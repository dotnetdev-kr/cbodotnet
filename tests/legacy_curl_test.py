"""Keep Core3's optional native HTTP ABI separate from SDK and SSL/ICU bytes."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import legacy_curl as CURL
import legacy_compat as BASE


def plan(version='3.1.426', arch='aarch64'):
    return dict(sdkVersion=version, variant='debian-13', architecture=dict(public=arch,
        deb='arm64' if arch == 'aarch64' else 'amd64', rpm='aarch64' if arch == 'aarch64' else 'x86_64'))


class NativeCurlTests(unittest.TestCase):
    def test_policy_keeps_exact_native_sdk_source_and_separate_vendor_identity(self):
        policy = CURL.load_policy()
        self.assertEqual('7051C470A929F454CEBE37B715AF5DAC6D745A60', policy['signingFingerprint'])
        self.assertNotEqual(BASE.FINGERPRINT, policy['signingFingerprint'])
        self.assertEqual(1, len(policy['sources']))
        self.assertEqual('rocky9-20261104', policy['baseProvider']['providerId'])
        self.assertEqual(hashlib.sha256(BASE.POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest(),
                         policy['baseProvider']['policySha256'])
        for version in ('3.0.103', '3.1.426'):
            for arch in ('x64', 'aarch64'):
                pins = CURL.runtime_pins(plan(version, arch))
                self.assertEqual(policy['nativeHttpComponents'][version][arch], pins['nativeHttp'])
                self.assertEqual('lib/libcurl.so.4.5.0', pins['curl']['path'])
                package = policy['architectures'][arch]['packages'][0]
                self.assertEqual(package['files'][0]['sha256'], pins['curl']['sha256'])
                self.assertIn('libssl.so.1.1', package['files'][0]['needed'])
                self.assertNotIn('libssl.so.3', package['files'][0]['needed'])
                self.assertEqual([], package['files'][0]['curlVersionDefinitions'])
                self.assertEqual('2.17', package['files'][0]['glibcMaximum'])

    def test_sdk5_and_modern_selection_have_no_addon_schema_or_environment_change(self):
        original = dict(LD_LIBRARY_PATH='/caller', SSL_CERT_FILE='/caller-ca')
        for version in ('5.0.214', '6.0.136', '7.0.120', '8.0.133', '9.0.123', '10.0.403'):
            with self.subTest(version=version):
                self.assertFalse(CURL.required(plan(version)))
                self.assertIsNone(CURL.plan_policy(plan(version)))
                self.assertIsNone(CURL.runtime_pins(plan(version)))
                self.assertEqual('', CURL.launcher_environment(plan(version)))
                self.assertEqual(original, CURL.runtime_environment(plan(version), None, base_environment=original))
        self.assertEqual('/caller', original['LD_LIBRARY_PATH'])
        with self.assertRaisesRegex(ValueError, 'Unreviewed Core3'):
            CURL.plan_policy(plan('3.1.999'))

    def test_missing_component_or_ambiguous_native_package_is_rejected_before_staging(self):
        original = CURL.load_policy()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'policy.json'
            for change in ('missing-sdk', 'multiple-packages', 'missing-elf'):
                value = copy.deepcopy(original)
                if change == 'missing-sdk':
                    value['nativeHttpComponents'].pop('3.0.103')
                elif change == 'multiple-packages':
                    value['architectures']['x64']['packages'] *= 2
                else:
                    value['architectures']['aarch64']['packages'][0]['files'] = []
                path.write_text(json.dumps(value))
                with self.subTest(change=change), mock.patch.object(CURL, 'POLICY', path), self.assertRaises(ValueError):
                    CURL.load_policy()

    def test_portable_environment_prefixes_addon_without_changing_caller_ca_or_base(self):
        base = dict(LD_LIBRARY_PATH='/portable ssl/lib', OPENSSL_CONF='/portable ssl/openssl.cnf', SSL_CERT_FILE='/user-ca')
        actual = CURL.environment(plan(), root='/portable curl', base_environment=base)
        self.assertEqual('/portable curl/lib:/portable ssl/lib', actual['LD_LIBRARY_PATH'])
        self.assertEqual('/user-ca', actual['SSL_CERT_FILE'])
        self.assertEqual('/portable ssl/lib', base['LD_LIBRARY_PATH'])
        for root in ('/', 'relative', '/a/../other'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                CURL.environment(plan(), root=root)

    @unittest.skipUnless(os.name == 'posix', 'POSIX wrapper scope execution required')
    def test_combined_scope_restores_both_private_prefixes_for_sdk5_and_modern_children(self):
        with tempfile.TemporaryDirectory(prefix='curl provider space-') as temporary:
            root = Path(temporary); base = root / 'base ssl'; curl = root / 'curl'
            for name in ['lib/libcrypto.so.1.1', 'lib/libssl.so.1.1', 'openssl.cnf', 'provider-manifest.json',
                         'lib/libicuuc.so.67', 'lib/libicui18n.so.67', 'lib/libicudata.so.67']:
                path = base / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture')
            for name in ['lib/libcurl.so.4.5.0', 'provider-manifest.json']:
                path = curl / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture')
            env = dict(os.environ, CBODOTNET_COMPAT_ROOT=str(base), CBODOTNET_CURL_COMPAT_ROOT=str(curl),
                       LD_LIBRARY_PATH='/caller', SSL_CERT_FILE='/user-ca')
            combined = BASE.launcher_environment(plan()) + CURL.launcher_environment(plan())
            result = subprocess.run(['sh', '-ec', combined + 'printf "%s\\n" "$LD_LIBRARY_PATH" "$SSL_CERT_FILE"'],
                                    env=env, capture_output=True, text=True, check=True)
            self.assertEqual([str(curl) + '/lib:' + str(base) + '/lib:/caller', '/user-ca'], result.stdout.splitlines())
            for version, expected in [('10.0.403', '/caller'), ('5.0.214', str(base) + '/lib:/caller')]:
                nested = combined + BASE.launcher_environment(plan(version)) + CURL.launcher_environment(plan(version))
                result = subprocess.run(['sh', '-ec', nested + 'printf "%s\\n" "$LD_LIBRARY_PATH" "$SSL_CERT_FILE"'],
                                        env=env, capture_output=True, text=True, check=True)
                self.assertEqual([expected, '/user-ca'], result.stdout.splitlines())
            (curl / 'lib/libcurl.so.4.5.0').unlink()
            self.assertEqual(70, subprocess.run(['sh', '-ec', combined], env=env, capture_output=True).returncode)

    def test_provider_installation_rejects_host_before_package_manager_or_source_fetch(self):
        with (mock.patch.object(CURL.os, 'geteuid', return_value=1000),
              mock.patch.object(CURL, 'build_provider') as build, mock.patch.object(CURL.subprocess, 'run') as run):
            with self.assertRaisesRegex(ValueError, 'disposable root container'):
                CURL.provision(plan(), Path('/forbidden-host-path'))
            build.assert_not_called(); run.assert_not_called()

    @unittest.skipUnless(os.environ.get('CBODOTNET_CURL_PROVIDER_CACHE') and all(shutil.which(tool) for tool in
        ('rpmdb', 'rpmkeys', 'rpm2cpio', 'gpg', 'readelf', 'dpkg-deb')), 'Opt-in actual curl vendor fixture cache/tools required')
    def test_actual_both_architecture_debs_and_companion_reject_corruption_and_forged_inventory(self):
        cache = Path(os.environ['CBODOTNET_CURL_PROVIDER_CACHE'])
        with tempfile.TemporaryDirectory(prefix='actual-curl-provider-') as temporary:
            for arch in ('x64', 'aarch64'):
                output = Path(temporary) / arch
                record = CURL.build_provider(arch, output, cache, variant='debian-13')
                CURL.verified_build(output / 'provider-build.json', plan(arch=arch), 'deb')
                extracted = Path(temporary) / (arch + '-extracted')
                subprocess.run(['dpkg-deb', '--extract', output / record['packages'][0]['path'], extracted], check=True)
                root = output / 'rootfs' / CURL.PROVIDER_ROOT.lstrip('/')
                self.assertEqual(CURL.tree_inventory(root), CURL.tree_inventory(extracted / CURL.PROVIDER_ROOT.lstrip('/')))
                elf = root / 'lib/libcurl.so.4.5.0'; original = elf.read_bytes()
                elf.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, 'ELF identity'):
                    CURL.verified_build(output / 'provider-build.json', plan(arch=arch), 'deb')
                elf.write_bytes(original)
                unexpected = output / 'rootfs/usr/bin'; unexpected.mkdir()
                (unexpected / 'unaccounted').write_bytes(b'outside the isolated provider')
                with self.assertRaisesRegex(ValueError, 'Unaccounted native HTTP provider rootfs'):
                    CURL.verified_build(output / 'provider-build.json', plan(arch=arch), 'deb')
                (unexpected / 'unaccounted').unlink(); unexpected.rmdir()
                companion = output / record['companion']['path']; modified = output / 'forged.tar.gz'
                with tarfile.open(companion) as source, tarfile.open(modified, 'w:gz') as target:
                    for entry in source:
                        target.addfile(entry, source.extractfile(entry) if entry.isfile() else None)
                    extra = tarfile.TarInfo('rootfs/../../unaccounted'); extra.size = 1; target.addfile(extra, io.BytesIO(b'x'))
                modified.replace(companion); record['companion'] = CURL.descriptor(companion)
                CURL.write_json(output / 'provider-build.json', record)
                with self.assertRaisesRegex(ValueError, 'unexpected member'):
                    CURL.verified_build(output / 'provider-build.json', plan(arch=arch), 'deb')


if __name__ == '__main__':
    unittest.main()
