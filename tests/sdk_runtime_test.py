import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import sdk_runtime as RUNTIME


class RuntimePolicyTests(unittest.TestCase):
    def test_public_verification_requires_every_provider_root_before_any_local_provisioning(self):
        import legacy_compat
        import legacy_curl
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / 'base'; addon = root / 'curl'
            with patch.object(legacy_compat, 'PROVIDER_ROOT', str(base)), patch.object(legacy_curl, 'PROVIDER_ROOT', str(addon)):
                RUNTIME.require_installed_provider_roots(dict(sdkVersion='10.0.403'))
                with self.assertRaisesRegex(ValueError, 'local repair is forbidden'):
                    RUNTIME.require_installed_provider_roots(dict(sdkVersion='5.0.214'))
                base.mkdir()
                RUNTIME.require_installed_provider_roots(dict(sdkVersion='5.0.214'))
                with self.assertRaisesRegex(ValueError, 'local repair is forbidden'):
                    RUNTIME.require_installed_provider_roots(dict(sdkVersion='3.1.426'))
                addon.mkdir()
                RUNTIME.require_installed_provider_roots(dict(sdkVersion='3.0.103'))
                addon.rmdir(); addon.symlink_to(base, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'ordinary managed provider roots'):
                    RUNTIME.require_installed_provider_roots(dict(sdkVersion='3.1.426'))
                addon.unlink(); base.rmdir(); base.write_bytes(b'not-a-directory')
                with self.assertRaisesRegex(ValueError, 'ordinary managed provider roots'):
                    RUNTIME.require_installed_provider_roots(dict(sdkVersion='5.0.214'))

    def test_core3_native_http_component_and_libcurl_must_actually_resolve(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'shared/Microsoft.NETCore.App/3.1.32/System.Net.Http.Native.so'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'qualified-native-http')
            scoped = {'LD_LIBRARY_PATH': '/usr/lib/cbodotnet/compat/rocky9/lib'}
            inspect = Mock(return_value='libcurl.so.4 => /lib64/libcurl.so.4 (0x123)\nlibc.so.6 => /lib64/libc.so.6 (0x456)\n')
            proof = RUNTIME.audit_core3_http_libraries('3.1.426', root, runtime_env=scoped, runner=inspect)
            self.assertEqual('/lib64/libcurl.so.4', proof[0]['libcurlProviderPath'])
            self.assertEqual(64, len(proof[0]['sha256']))
            self.assertEqual(scoped['LD_LIBRARY_PATH'], inspect.call_args.kwargs['env']['LD_LIBRARY_PATH'])
            for output in ('libcurl.so.4 => not found\n', 'libc.so.6 => /lib64/libc.so.6 (0x123)\n'):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'resolved stock libcurl'):
                    RUNTIME.audit_core3_http_libraries('3.1.426', root, runner=Mock(return_value=output))
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'Missing Core3'):
                RUNTIME.audit_core3_http_libraries('3.0.103', root, runner=inspect)

    def test_sdk5_and_modern_sdk_audits_do_not_gain_the_core3_optional_http_dependency(self):
        inspect = Mock()
        for version in ('5.0.214', '6.0.136', '7.0.120', '8.0.133', '9.0.123', '10.0.403'):
            self.assertEqual([], RUNTIME.audit_core3_http_libraries(version, '/not-an-installed-sdk', runner=inspect))
        inspect.assert_not_called()

    def test_all_reviewed_families_select_their_own_framework_root_and_abi(self):
        versions = ['10.0.403', '9.0.123', '8.0.133', '7.0.120', '6.0.136', '5.0.214', '3.1.426', '3.0.103']
        for version in versions:
            for arch in ('x64', 'aarch64'):
                with self.subTest(version=version, arch=arch):
                    value = RUNTIME.runtime_policy(version, arch)
                    family = '.'.join(version.split('.')[:2])
                    self.assertEqual('/opt/cbodotnet/' + family, value['sdkRoot'])
                    self.assertEqual(('netcoreapp' if family.startswith('3.') else 'net') + family, value['framework'])
                    self.assertEqual('linux-' + ('arm64' if arch == 'aarch64' else 'x64'), value['targetRid'])
                    self.assertEqual(family in {'3.0', '3.1', '5.0'}, value['legacy'])
                    if family != '10.0':
                        self.assertEqual(value['recordedMaximumRequiredVersions']['GLIBC'], value['maxGlibc'])

    def test_unreviewed_versions_and_architectures_are_rejected(self):
        for version in ('4.0.100', '10.0', '10.0.403-preview.1', '../10.0.403'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                RUNTIME.series(version)
        with self.assertRaises(ValueError):
            RUNTIME.runtime_policy('10.0.403', 'arm64')

    def test_legacy_reported_distro_rid_is_native_but_modern_host_must_be_portable(self):
        self.assertEqual('debian.13-arm64', RUNTIME.validate_host_rid('  RID: debian.13-arm64\n', '6.0.136', 'aarch64', 'debian-13'))
        self.assertEqual('linux-arm64', RUNTIME.validate_host_rid('  RID: linux-arm64\n', '9.0.123', 'aarch64', 'debian-13'))
        for rid in ('debian.13-x64', 'ubuntu.24.04-arm64', 'linux-musl-arm64'):
            with self.subTest(rid=rid), self.assertRaises(ValueError):
                RUNTIME.validate_host_rid(' RID: ' + rid + '\n', '6.0.136', 'aarch64', 'debian-13')
        with self.assertRaises(ValueError):
            RUNTIME.validate_host_rid(' RID: debian.13-arm64\n', '8.0.133', 'aarch64', 'debian-13')

    def test_rocky_native_major_only_rid_is_admitted_for_old_sdk_without_accepting_another_os_or_cpu(self):
        # Actual qualified SDK7 ARM --info on pinned Rocky9.8 reports rocky.9.
        for arch, suffix in (('x64', 'x64'), ('aarch64', 'arm64')):
            self.assertEqual('rocky.9-' + suffix, RUNTIME.validate_host_rid(' RID: rocky.9-' + suffix + '\n',
                '7.0.120', arch, 'rocky-9.8'))
        for rid in ('rocky.8-arm64', 'rocky.9-x64', 'rocky.10-arm64', 'rocky.9-musl-arm64'):
            with self.subTest(rid=rid), self.assertRaisesRegex(ValueError, rid):
                RUNTIME.validate_host_rid(' RID: ' + rid + '\n', '7.0.120', 'aarch64', 'rocky-9.8')

    def test_legacy_probe_uses_supported_apis_and_all_runtime_scenarios(self):
        script = RUNTIME.smoke_script('3.0.103', '/opt/cbodotnet/3.0', 'app', runtime_env={'SSL_CERT_FILE': '/etc/pki/tls/certs/ca-bundle.crt'})
        self.assertIn('<TargetFramework>netcoreapp3.0</TargetFramework>', script)
        self.assertNotIn('Environment.ProcessPath', script)
        self.assertNotIn('RandomNumberGenerator.GetBytes(32)', script)
        for text in ('SslProtocols.Tls12', 'VerifyData', 'RandomNumberGenerator.Create()', 'fr-FR', 'WebHost.CreateDefaultBuilder', 'Smoke.dll dll', 'Smoke apphost'):
            self.assertIn(text, script)
        self.assertIn('export SSL_CERT_FILE=', script)
        with self.assertRaises(ValueError):
            RUNTIME.smoke_script('3.0.103', '/opt/cbodotnet/3.0', 'app', runtime_env={'DOTNET_ROLL_FORWARD': 'LatestMajor'})

    def test_both_processes_must_finish_tls_and_complete_functional_probe(self):
        output = ''.join('published-tls12-passed\npublished-offline-' + mode + '-http-crypto-icu-passed\n' for mode in ('dll', 'apphost'))
        self.assertEqual(7, len(RUNTIME.validate_smoke_output(output)))
        with self.assertRaises(ValueError):
            RUNTIME.validate_smoke_output(output.replace('published-tls12-passed\n', '', 1))
        with self.assertRaises(ValueError):
            RUNTIME.validate_smoke_output(output.replace('published-offline-apphost-http-crypto-icu-passed', ''))


if __name__ == '__main__':
    unittest.main()
