import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_attributed_test', ROOT / 'scripts/musl_legacy6_attributed_components.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class SDK6AttributedSourceTests(unittest.TestCase):
    def manifest(self):
        p = C.policy()
        roots = [dict(name=role, kind='git', commit=row['commit'], tree=row['tree'], submodules=[])
            for role, row in p['sources'].items()]
        by_name = {row['name']: row for row in roots}
        for parent, path, child in [('linker', 'external/cecil', 'cecil'), ('external', 'src/cssparser', 'css')]:
            by_name[parent]['submodules'].append(dict(path=path, commit=by_name[child]['commit'], root=child))
        roots.append(dict(name=C.ROOT_NAME, kind='tree', role=C.ROLE, commit=None))
        return dict(roots=roots)

    def test_unknown_path_is_not_a_generic_missing_commit_inference(self):
        self.assertIsNone(C.declared_product('sdk/6.0.136/unreviewed.dll', '0' * 64, 'lib/a.dll', b'MZ'))

    def test_mismatched_member_and_untrusted_payload_never_reach_metadata(self):
        name, row = next(iter(C.policy()['products'].items()))
        pair = row['allowedPackageMembers'][0]
        with mock.patch.object(C, 'module', side_effect=AssertionError('Untrusted PE reached metadata')):
            for sha, member in [('0' * 64, pair['packageMember']),
                                (pair['packageSha256'], '../another.dll'),
                                (pair['packageSha256'], pair['packageMember'])]:
                with self.subTest(sha=sha, member=member), self.assertRaisesRegex(ValueError, 'path/package/member'):
                    C.declared_product(name, sha, member, b'MZuntrusted')

    def test_corrupt_exact_size_package_rejects_before_zip(self):
        sha, row = min(C.policy()['packages'].items(), key=lambda item: item[1]['bytes'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'changed.nupkg'
            path.write_bytes(b'x' * row['bytes'])
            with mock.patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('Unpinned ZIP inspected')):
                with self.assertRaisesRegex(ValueError, 'package bytes differ'):
                    C.inspect_package(path, sha)

    def test_policy_change_rejects_before_json_parsing(self):
        with mock.patch.object(C.Path, 'read_bytes', return_value=b'{}'), \
             mock.patch.object(C.json, 'loads', side_effect=AssertionError('Unpinned policy parsed')):
            with self.assertRaisesRegex(ValueError, 'policy bytes differ'):
                C.policy()

    def test_missing_component_git_root_rejects(self):
        manifest = self.manifest()
        manifest['roots'] = [r for r in manifest['roots'] if r['name'] != 'runtime6']
        with mock.patch.object(C, 'data_bodies', return_value={}):
            with self.assertRaisesRegex(ValueError, 'Complete exact SDK6 component Git source'):
                C.validate(ROOT, manifest, {})

    def test_linker_cannot_select_sdk7_cecil_gitlink(self):
        manifest = self.manifest()
        linker = next(r for r in manifest['roots'] if r['name'] == 'linker')
        linker['submodules'][0]['commit'] = '1840b7410d37a613e684b6f9650e39e2d4950bbb'
        with mock.patch.object(C, 'data_bodies', return_value={}):
            with self.assertRaisesRegex(ValueError, 'original SDK6 publisher Gitlink'):
                C.validate(ROOT, manifest, {})

    def test_css_cannot_invent_git_provenance_for_package_data(self):
        manifest = self.manifest()
        root = next(r for r in manifest['roots'] if r['name'] == C.ROOT_NAME)
        root['commit'] = C.policy()['sources']['css']['commit']
        with mock.patch.object(C, 'data_bodies', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cannot invent Git provenance'):
                C.validate(ROOT, manifest, {})


if __name__ == '__main__':
    unittest.main()
