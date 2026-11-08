"""Closed input boundaries for the old VSTest source graph."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('vstest5_worker', ROOT / 'scripts/musl-legacy5-vstest.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class OriginalInputs(unittest.TestCase):
    def test_policy_keeps_exact_source_version_and_separate_import_attribution(self):
        p = M.input_policy()
        self.assertEqual((p['sdkVersion'], p['sourceVersion']), ('5.0.214', '16.9.4-dev'))
        self.assertEqual(len(p['imports']), 38)
        self.assertEqual((p['managedPackageMembers'], p['sourceCommitAttributedMembers']), (339, 301))
        self.assertTrue(p['importedDependenciesRequireSeparateSourceAttribution'])
        self.assertFalse(p['localImportedDependencyBuildClaimed'])
        self.assertFalse(p['qualificationAllowed'])
        self.assertFalse(p['sourceAdmissionAllowed'])

    def test_changed_policy_is_rejected_before_json_parsing(self):
        with mock.patch.object(Path, 'read_bytes', return_value=b'changed'), \
                mock.patch.object(M.json, 'loads', side_effect=AssertionError('no parser')):
            with self.assertRaisesRegex(ValueError, 'policy changed'):
                M.input_policy()

    def test_reference_size_is_checked_before_package_read(self):
        policy = M.input_policy()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reference.nupkg'
            path.write_bytes(b'not the original reference package')
            with mock.patch.object(M, 'input_policy', return_value=policy), \
                    mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('no package read')):
                with self.assertRaisesRegex(ValueError, 'reference package size'):
                    M.check_reference_package(path)

    def test_same_size_reference_corruption_is_rejected(self):
        policy = M.input_policy()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reference.nupkg'
            path.write_bytes(b'X' * policy['compilerReferencePackage']['bytes'])
            with self.assertRaisesRegex(ValueError, 'reference package bytes'):
                M.check_reference_package(path)

    def test_missing_extra_or_changed_import_is_rejected(self):
        original = M.input_policy()['imports']
        M.check_imported_members(original)
        for change in ('missing', 'extra', 'changed'):
            actual = copy.deepcopy(original)
            first = next(iter(actual))
            if change == 'missing':
                del actual[first]
            elif change == 'extra':
                actual['contentFiles/any/netcoreapp2.1/Unexpected.dll'] = actual[first]
            else:
                actual[first]['sha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'member bytes differ'):
                M.check_imported_members(actual)


if __name__ == '__main__':
    unittest.main()
