"""Provider trust boundaries, scoped environment and optional real pinned RPM build."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import legacy_compat as COMPAT


def plan(version='3.1.426', variant='debian-13', arch='aarch64'):
    return {'sdkVersion': version, 'variant': variant, 'architecture': {'public': arch}}


def cpio_entry(name, content=b'', mode=stat.S_IFREG | 0o644):
    encoded = name.encode() + b'\0'
    values = [1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(encoded), 0]
    header = b'070701' + ''.join(f'{value:08x}' for value in values).encode()
    result = header + encoded
    result += b'\0' * (-len(result) % 4)
    result += content
    result += b'\0' * (-len(content) % 4)
    return result


class LegacyCompatTests(unittest.TestCase):
    def test_actual_rpm4_and_rpm6_statuses_require_exact_approved_signature_and_sha256(self):
        old = ('example.rpm:\n    Header V4 RSA/SHA256 Signature, key ID 350d275d: OK\n'
               '    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n    MD5 digest: OK\n')
        current = ('example.rpm:\n    Header OpenPGP V4 RSA/SHA256 signature, key fingerprint: '
                   '21cb256ae16fc54c6e652949702d426d350d275d: OK\n'
                   '    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n')
        for output in [old, current]:
            COMPAT.verify_rpm_signature_status(output)
        for output in [old.replace('350d275d', '01234567'), current.replace('21cb256a', '01234567'),
                       current.replace('signature,', 'digest,'), current.replace('Payload SHA256 digest: OK', ''),
                       current.replace('Header SHA256 digest: OK', ''), current + 'Payload SHA256 digest: BAD\n',
                       current.replace(': OK', ': NOKEY', 1), 'example.rpm: digests OK\n', old + old]:
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'approved valid signature'):
                COMPAT.verify_rpm_signature_status(output)

    def test_arch_image_build_stamp_is_not_treated_as_fixed_os_release(self):
        COMPAT.validate_operating_system({'ID': 'arch', 'BUILD_ID': 'rolling', 'VERSION_ID': '20261101.0.620205'}, 'arch-rolling')
        COMPAT.validate_operating_system({'ID': 'arch', 'BUILD_ID': 'rolling'}, 'arch-rolling')
        COMPAT.validate_operating_system({'ID': 'debian', 'VERSION_ID': '13'}, 'debian-13')
        for values, variant in [({'ID': 'arch', 'BUILD_ID': 'stable'}, 'arch-rolling'),
                                ({'ID': 'ubuntu', 'BUILD_ID': 'rolling'}, 'arch-rolling'),
                                ({'ID': 'debian', 'VERSION_ID': '12'}, 'debian-13')]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                COMPAT.validate_operating_system(values, variant)

    def test_policy_binds_both_native_binary_and_matching_source_packages(self):
        policy = COMPAT.load_policy()
        self.assertEqual(COMPAT.FINGERPRINT, policy['signingFingerprint'])
        self.assertEqual(2, len(policy['sources']))
        for arch, machine in [('x64', 62), ('aarch64', 183)]:
            record = policy['architectures'][arch]
            self.assertEqual(machine, record['elfMachine'])
            self.assertEqual(5, sum(len(item['files']) for item in record['packages']))
            self.assertEqual({'compat-openssl11', 'libicu'}, {item['packageName'] for item in record['packages']})
            for package in record['packages']:
                self.assertIn(package['sourcePackage'], {item['name'] for item in policy['sources']})
                self.assertTrue(package['licenses'])
        self.assertNotIn('.include', policy['opensslConfiguration']['content'])
        self.assertIn('MinProtocol = TLSv1.2', policy['opensslConfiguration']['content'])
        self.assertIn('SECLEVEL=2', policy['opensslConfiguration']['content'])

    def test_environment_is_legacy_only_and_uses_current_system_ca_store(self):
        for version in ['10.0.403', '9.0.123', '8.0.133', '7.0.120', '6.0.136']:
            self.assertFalse(COMPAT.required(plan(version)))
            self.assertEqual({}, COMPAT.environment(plan(version)))
            self.assertNotIn('export CBODOTNET_COMPAT_SCOPE=rocky9', COMPAT.launcher_environment(plan(version)))
        values = COMPAT.environment(plan())
        self.assertEqual('67', values['CLR_ICU_VERSION_OVERRIDE'])
        self.assertEqual('/etc/ssl/certs/ca-certificates.crt', values['SSL_CERT_FILE'])
        self.assertEqual('1.1', values['CLR_OPENSSL_VERSION_OVERRIDE'])
        self.assertNotIn('CLR_ICU_VERSION_OVERRIDE', COMPAT.environment(plan('5.0.214')))
        self.assertEqual('/etc/pki/tls/certs/ca-bundle.crt', COMPAT.environment(plan(variant='fedora-45'))['SSL_CERT_FILE'])
        with self.assertRaises(ValueError):
            COMPAT.environment(plan(variant='unreviewed-42'))
        for root in ['/', 'relative', '/path/../other']:
            with self.assertRaises(ValueError):
                COMPAT.environment(plan(), root=root)

    def test_x64_provider_requires_every_v2_cpu_feature_on_every_processor(self):
        flags = 'cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2'
        report = COMPAT.cpu_preflight('x64', 'flags\t: ' + flags + '\nflags : ' + flags + '\n')
        self.assertEqual(2, report['cpuFlagRowsChecked'])
        self.assertEqual('x86-64-v2', report['baseline'])
        self.assertEqual('passed', COMPAT.cpu_preflight('x64', 'flags : ' + flags.replace('pni', 'sse3'))['status'])
        for feature in flags.split():
            with self.subTest(feature=feature), self.assertRaisesRegex(ValueError, 'x86-64-v2'):
                COMPAT.cpu_preflight('x64', 'flags : ' + flags + '\nflags : ' + ' '.join(value for value in flags.split() if value != feature))
        with self.assertRaisesRegex(ValueError, 'Cannot establish'):
            COMPAT.cpu_preflight('x64', 'unavailable')
        self.assertEqual('armv8-a', COMPAT.cpu_preflight('aarch64')['baseline'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX CPU preflight execution required')
    def test_shell_cpu_preflight_rejects_partial_or_unavailable_feature_rows(self):
        flags = 'cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2'
        with tempfile.TemporaryDirectory() as temporary:
            cpuinfo = Path(temporary) / 'cpuinfo'
            script = COMPAT.cpu_launcher_preflight().replace('/proc/cpuinfo', str(cpuinfo))
            cpuinfo.write_text('flags\t: ' + flags + '\n')
            self.assertEqual(0, subprocess.run(['sh', '-c', script], capture_output=True).returncode)
            for body in ['flags : ' + flags.replace('cx16', '') + '\n',
                         'flags : ' + flags + '\nflags : ' + flags.replace('sse4_2', '') + '\n', 'no flags\n']:
                cpuinfo.write_text(body)
                result = subprocess.run(['sh', '-c', script], capture_output=True)
                self.assertEqual(70, result.returncode)
            cpuinfo.unlink()
            self.assertEqual(70, subprocess.run(['sh', '-c', script], capture_output=True).returncode)

    @unittest.skipUnless(os.name == 'posix', 'POSIX wrapper execution required')
    def test_relocatable_wrapper_scopes_provider_and_fails_when_missing(self):
        with tempfile.TemporaryDirectory(prefix='provider space-') as temporary:
            root = Path(temporary)
            for name in ['lib/libcrypto.so.1.1', 'lib/libssl.so.1.1', 'openssl.cnf', 'provider-manifest.json',
                         'lib/libicuuc.so.67', 'lib/libicui18n.so.67', 'lib/libicudata.so.67']:
                target = root / name
                target.parent.mkdir(exist_ok=True)
                target.write_text('fixture')
            environment = dict(os.environ, CBODOTNET_COMPAT_ROOT=str(root), LD_LIBRARY_PATH='/other', SSL_CERT_FILE='/custom-ca')
            script = COMPAT.launcher_environment(plan()) + 'printf "%s\\n" "$LD_LIBRARY_PATH" "$OPENSSL_CONF" "$CLR_ICU_VERSION_OVERRIDE" "$SSL_CERT_FILE"\n'
            result = subprocess.run(['sh', '-c', script], env=environment, capture_output=True, text=True, check=True)
            self.assertEqual([str(root) + '/lib:/other', str(root) + '/openssl.cnf', '67', '/custom-ca'], result.stdout.splitlines())
            nested = COMPAT.launcher_environment(plan()) + COMPAT.launcher_environment(plan('10.0.403'))
            nested += 'printf "%s\\n" "$LD_LIBRARY_PATH" "${OPENSSL_CONF+x}" "${CLR_ICU_VERSION_OVERRIDE+x}" "$SSL_CERT_FILE" "${CBODOTNET_COMPAT_SCOPE+x}"\n'
            result = subprocess.run(['sh', '-c', nested], env=environment, capture_output=True, text=True, check=True)
            self.assertEqual(['/other', '', '', '/custom-ca', ''], result.stdout.splitlines())
            nested = COMPAT.launcher_environment(plan()) + COMPAT.launcher_environment(plan('5.0.214'))
            nested += 'printf "%s\\n" "$LD_LIBRARY_PATH" "${CLR_ICU_VERSION_OVERRIDE+x}" "$SSL_CERT_FILE"\n'
            result = subprocess.run(['sh', '-c', nested], env=environment, capture_output=True, text=True, check=True)
            self.assertEqual([str(root) + '/lib:/other', '', '/custom-ca'], result.stdout.splitlines())
            (root / 'lib/libicuuc.so.67').unlink()
            result = subprocess.run(['sh', '-c', script], env=environment, capture_output=True, text=True)
            self.assertEqual(70, result.returncode)
            self.assertEqual('', result.stdout)

    def test_cpio_reader_rejects_path_escape_duplicates_and_truncated_contents(self):
        trailer = cpio_entry('TRAILER!!!')
        good = cpio_entry('./usr/lib64/example', b'original') + trailer
        self.assertEqual([('usr/lib64/example', stat.S_IFREG | 0o644, b'original')], list(COMPAT.cpio_members(good)))
        for bad in ['../escape', '/absolute', 'usr/../escape', 'usr//ambiguous', 'usr\\escape']:
            with self.subTest(name=bad), self.assertRaises(ValueError):
                list(COMPAT.cpio_members(cpio_entry(bad) + trailer))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            list(COMPAT.cpio_members(cpio_entry('same') + cpio_entry('same') + trailer))
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            list(COMPAT.cpio_members(cpio_entry('file', b'1234')[:-2]))
        with self.assertRaisesRegex(ValueError, 'trailer'):
            list(COMPAT.cpio_members(cpio_entry('file')))

    def test_fetch_never_promotes_wrong_length_or_hash_and_rejects_conflicting_cache(self):
        item = {'name': 'input.rpm', 'url': 'https://dl.rockylinux.org/pub/rocky/fixture.rpm',
                'size': 4, 'sha256': hashlib.sha256(b'good').hexdigest()}
        class Response(io.BytesIO):
            def geturl(self):
                return item['url']
        for content in [b'bad', b'toolong', b'evil']:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                with mock.patch.object(COMPAT.urllib.request, 'urlopen', return_value=Response(content)):
                    with self.assertRaises(ValueError):
                        COMPAT.fetch(item, temporary)
                self.assertEqual([], list(Path(temporary).iterdir()))
        with tempfile.TemporaryDirectory() as temporary:
            cached = Path(temporary) / item['name']
            cached.write_bytes(b'evil')
            with mock.patch.object(COMPAT.urllib.request, 'urlopen') as network:
                with self.assertRaisesRegex(ValueError, 'Retained'):
                    COMPAT.fetch(item, temporary)
                network.assert_not_called()
            self.assertEqual(b'evil', cached.read_bytes())

    def test_state_checks_every_byte_mode_link_owner_and_policy_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'provider'
            root.mkdir(); (root / 'library').write_bytes(b'original')
            (root / 'soname').symlink_to('library')
            inventory = COMPAT.tree_inventory(root, owners=True)
            state = {'required': True, 'providerRoot': str(root), 'architecture': 'aarch64',
                     'files': inventory, 'treeSha256': COMPAT.inventory_digest(inventory), 'policySha256': 'x',
                     'signingFingerprint': COMPAT.FINGERPRINT}
            with mock.patch.object(COMPAT, 'PROVIDER_ROOT', str(root)):
                self.assertEqual('passed', COMPAT.assert_unchanged(state)['status'])
                (root / 'library').write_bytes(b'modified')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    COMPAT.assert_unchanged(state)
        with self.assertRaisesRegex(ValueError, 'policy'):
            COMPAT.runtime_environment(plan(), {'providerRoot': COMPAT.PROVIDER_ROOT, 'architecture': 'aarch64', 'policySha256': 'x'})
        with self.assertRaisesRegex(ValueError, 'match SDK'):
            COMPAT.runtime_environment(plan(), {'providerRoot': COMPAT.PROVIDER_ROOT, 'architecture': 'x64'})

    def test_provision_cannot_install_on_the_host(self):
        with mock.patch.object(COMPAT.Path, 'is_file', return_value=False):
            with self.assertRaisesRegex(ValueError, 'disposable root container'):
                COMPAT.provision(plan(), '/unused')

    @unittest.skipUnless(os.environ.get('CBODOTNET_PROVIDER_CACHE') and os.name == 'posix',
                         'Opt-in actual pinned RPM fixture cache required')
    def test_real_pinned_both_architecture_provider_bytes_and_debian_payload(self):
        cache = Path(os.environ['CBODOTNET_PROVIDER_CACHE'])
        with tempfile.TemporaryDirectory(prefix='cbodotnet-real-provider-test-') as temporary:
            builds = []
            for architecture in ['x64', 'aarch64']:
                with self.subTest(architecture=architecture):
                    output = Path(temporary) / architecture
                    result = COMPAT.build_provider(architecture, output, cache, 'debian-13')
                    self.assertEqual(5, sum(len(item['files']) for item in result['manifest']['packages']))
                    self.assertTrue((output / result['companion']['path']).is_file())
                    package = output / result['packages'][0]['path']
                    extracted = Path(temporary) / (architecture + '-deb')
                    subprocess.run(['dpkg-deb', '-x', str(package), str(extracted)], check=True)
                    self.assertEqual(COMPAT.tree_inventory(output / 'rootfs'), COMPAT.tree_inventory(extracted))
                    control = subprocess.check_output(['dpkg-deb', '-f', str(package)], text=True)
                    self.assertIn('Package: cbodotnet-compat-rocky9\n', control)
                    self.assertNotIn('/opt/cbodotnet', '\n'.join(item['path'] for item in COMPAT.tree_inventory(extracted)))
                    native = {'x64': 'amd64', 'aarch64': 'arm64'}[architecture]
                    sdk_plan = plan(arch=architecture)
                    sdk_plan['architecture']['deb'] = native
                    COMPAT.verified_build(output / 'provider-build.json', sdk_plan, 'deb')
                    builds.append((output, result, sdk_plan))
            output, result, sdk_plan = builds[-1]
            # A modified report and matching artifact checksum do not authorize
            # extra members in the companion itself.
            companion = output / result['companion']['path']
            with tarfile.open(companion, 'w:gz') as archive:
                entry = tarfile.TarInfo('rootfs/etc/unsafe-extra')
                entry.size = 4
                archive.addfile(entry, io.BytesIO(b'evil'))
            result['companion'] = COMPAT.descriptor(companion)
            COMPAT.write_json(output / 'provider-build.json', result)
            with self.assertRaisesRegex(ValueError, 'unexpected member'):
                COMPAT.verified_build(output / 'provider-build.json', sdk_plan, 'deb')
            # Nor may a self-reported inventory substitute another ELF binary.
            root = output / 'rootfs' / COMPAT.PROVIDER_ROOT.lstrip('/')
            library = root / 'lib/libcrypto.so.1.1.1k'
            data = library.read_bytes()
            library.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'ELF identity'):
                COMPAT.verified_build(output / 'provider-build.json', sdk_plan, 'deb')


if __name__ == '__main__':
    unittest.main()
