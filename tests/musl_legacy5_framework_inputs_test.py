import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_framework_test', ROOT / 'scripts/musl_legacy5_framework_inputs.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class SDK5FrameworkSourceTests(unittest.TestCase):
    def source_fixture(self):
        import hashlib
        def row(name, raw):
            return dict(path=name, **M.fingerprint(raw), gitBlob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
        il = {'implementation.il': b'// original preferred source\n'}
        sdk = {'eng/Versions.props': b'<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><PropertyGroup><NETStandardLibraryNETFrameworkVersion>2.0.1-servicing-26011-01</NETStandardLibraryNETFrameworkVersion></PropertyGroup></Project>'}
        policy = dict(preferredSource=dict(files={n: row(n, raw) for n, raw in il.items()}),
            sdkSourceFiles=[row(n, raw) for n, raw in sdk.items()], package=dict(version='2.0.1-servicing-26011-01'))
        return il, sdk, policy

    def test_original_namespaced_version_recipe(self):
        il, sdk, policy = self.source_fixture()
        with patch.object(M, 'policy', return_value=policy):
            M.source_chain(il, sdk)

    def test_rehashed_source_cannot_change_original_git_blob(self):
        il, sdk, policy = self.source_fixture()
        changed = b'// changed preferred source\n'
        il['implementation.il'] = changed
        policy['preferredSource']['files']['implementation.il'].update(M.fingerprint(changed))
        with patch.object(M, 'policy', return_value=policy), self.assertRaisesRegex(ValueError, 'original Git blob'):
            M.source_chain(il, sdk)

    def test_missing_preferred_source_rejects(self):
        il, sdk, policy = self.source_fixture()
        with patch.object(M, 'policy', return_value=policy), self.assertRaisesRegex(ValueError, 'Complete SDK5'):
            M.source_chain({}, sdk)

    def test_wrong_original_package_version_rejects(self):
        il, sdk, policy = self.source_fixture()
        policy['package']['version'] = '7.0.120-servicing.24272.7'
        with patch.object(M, 'policy', return_value=policy), self.assertRaisesRegex(ValueError, 'package version differs'):
            M.source_chain(il, sdk)

    def test_archive_path_escape_rejects(self):
        for name in ('../source', '/source', 'a//b', 'a\\b', 'a/./b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.portable(name)

    def test_sdk5_policy_uses_the_direct_canonical_package(self):
        policy = M.policy()
        self.assertEqual(policy['sdkVersion'], '5.0.214')
        self.assertEqual(M.SDK_COMMIT, '3fdf76c35026e311b7edc245d4b3d9e812fe532e')
        self.assertFalse(policy['sdk6PublisherPackageUsed'])
        self.assertEqual(policy['package']['fingerprint']['sha256'], M.PACKAGE_SHA)
        self.assertFalse(policy['sdk7PublisherPackageUsed'])
        self.assertEqual({r['kind'] for r in policy['layout']},
            {'derived-readable-type-forwarder-source-inputs', 'upstream-full-il-and-original-resource-inputs'})
        self.assertNotIn('6cf5b9719e6f7e2a078fe28db1f6d28fd7e2e48ecfa53c6d6d1c17b0cf3300ad', str(policy))


if __name__ == '__main__':
    unittest.main()
