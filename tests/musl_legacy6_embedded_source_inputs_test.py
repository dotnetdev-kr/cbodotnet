"""Closed original SDK6 package inputs must fail before untrusted parsing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_embedded_source_test', ROOT / 'scripts/musl_legacy6_embedded_source_inputs.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


class SDK6OriginalEmbeddedSourceInputs(unittest.TestCase):
    def manifest(self):
        return dict(roots=[dict(name='source-' + commit, kind='git', commit=commit,
            tree=row['tree']) for commit, row in B.policy()['sources'].items()] + [
                dict(name=B.ROOT_NAME, kind='tree', commit=None, role=B.ROLE)])

    def test_unlisted_package_is_not_a_missing_repository_fallback(self):
        self.assertIsNone(B.package_origin(ROOT / 'not-present.nupkg', '0' * 64))

    def test_changed_policy_rejects_before_json_parsing(self):
        with mock.patch.object(B.Path, 'read_bytes', return_value=b'{}'), \
             mock.patch.object(B.json, 'loads', side_effect=AssertionError('Unpinned policy reached parser')):
            with self.assertRaisesRegex(ValueError, 'policy bytes differ'):
                B.policy()

    def test_same_size_package_corruption_rejects_before_zip_parsing(self):
        sha, row = min(B.policy()['packages'].items(), key=lambda item: item[1]['fingerprint']['bytes'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'modified.nupkg'; path.write_bytes(b'X' * row['fingerprint']['bytes'])
            with mock.patch.object(B.zipfile, 'ZipFile', side_effect=AssertionError('Unpinned package reached ZIP parser')):
                with self.assertRaisesRegex(ValueError, 'raw bytes differ'):
                    B.inspect_package(path, sha)

    def test_unlisted_layout_member_or_changed_payload_cannot_reach_pe_parser(self):
        name, row = next(iter(B.policy()['products'].items())); pair = row['allowedPackageMembers'][0]
        for selected_name, sha, member in [('sdk/6.0.136/unreviewed.dll', pair['packageSha256'], pair['member']),
                                          (name, '0' * 64, pair['member']),
                                          (name, pair['packageSha256'], '../unreviewed.dll'),
                                          (name, pair['packageSha256'], pair['member'])]:
            with self.subTest(name=selected_name, sha=sha, member=member), \
                 mock.patch.object(B, 'module', side_effect=AssertionError('Unpinned input reached PE parser')):
                with self.assertRaisesRegex(ValueError, 'layout/package/member differs'):
                    B.declared_product(selected_name, sha, member, b'MZchanged')

    def test_missing_or_excluded_original_member_source_cannot_be_waived(self):
        for excluded in (False, True):
            manifest = self.manifest()
            if excluded: manifest['roots'][0]['exclude'] = ['src/actual-code.cs']
            else: manifest['roots'].pop(0)
            with self.subTest(excluded=excluded), self.assertRaisesRegex(ValueError, 'Complete pristine SDK6 per-member Git source'):
                B.validate(ROOT, manifest, {})

    def test_original_no_repository_package_data_cannot_claim_a_git_commit(self):
        manifest = self.manifest(); manifest['roots'][-1].update(kind='git', commit=next(iter(B.policy()['sources'])))
        with self.assertRaisesRegex(ValueError, 'non-Git role'):
            B.validate(ROOT, manifest, {})


if __name__ == '__main__': unittest.main()
