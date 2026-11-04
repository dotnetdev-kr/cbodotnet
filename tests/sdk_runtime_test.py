import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import sdk_runtime as RUNTIME


class RuntimePolicyTests(unittest.TestCase):
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
