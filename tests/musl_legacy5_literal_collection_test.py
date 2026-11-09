import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_literal_collection as C


class LiteralCollection(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.old = self.root / 'compiler'; self.old.mkdir()
        (self.old / 'actual.cs').write_bytes(b'actual original compiler bytes\r\n')
        self.sources = {'compiler': dict(name='compiler', kind='git', path=str(self.old),
                                        expectedCommit='a' * 40, role='build-source')}
        self.original = copy.deepcopy(self.sources)
        self.expected = dict(name='literal-b', literalRole='test-role', repository='https://github.com/dotnet/example',
                             commit='b' * 40, tree='c' * 40, role=C.ROLE)
        self.report = self.root / 'reports' / 'literal.json'
        self.materialized = []
        self.identities = []
        self.enterContext(patch.object(C, 'required_sources', return_value=[self.expected]))
        self.enterContext(patch.object(C.COLLECTION, 'source_identity', side_effect=self.identity))
        utility = SimpleNamespace(exact_git_bytes=lambda row: self.materialized.append(copy.deepcopy(row)) or dict(name=row['name']))
        self.enterContext(patch.object(C.COLLECTION.PRIMARY, 'materializer', return_value=utility))

    def identity(self, row, expected):
        self.assertEqual(expected['commit'], row['expectedCommit'])
        self.identities.append(row['name'])
        return {key: expected[key] for key in ('repository', 'commit', 'tree')}

    def clone(self, name, repository, commit):
        path = self.root / name; path.mkdir()
        self.sources[name] = dict(name=name, kind='git', path=str(path), expectedCommit=commit)

    def run_registration(self, clone=None, expand=None, sdk='5.0.214'):
        return C.register(sdk, self.sources, clone or self.clone, expand or (lambda rows: rows), self.report)

    def test_new_corresponding_source_is_materialized_without_changing_compiler_bytes_or_role(self):
        result = self.run_registration()
        self.assertEqual(self.original['compiler'], self.sources['compiler'])
        self.assertEqual(b'actual original compiler bytes\r\n', (self.old / 'actual.cs').read_bytes())
        self.assertEqual(['literal-b'], [row['name'] for row in self.materialized])
        self.assertEqual(C.ROLE, self.sources['literal-b']['role'])
        self.assertFalse(result['sourceAdmissionAllowed'])

    def test_existing_same_commit_is_authenticated_without_recloning_materializing_or_relabelling(self):
        self.sources['compiler']['expectedCommit'] = self.expected['commit']
        before = copy.deepcopy(self.sources)
        clone = Mock(side_effect=AssertionError('Existing compiler may not be cloned'))
        result = self.run_registration(clone)
        self.assertEqual(before, self.sources); self.assertEqual([], self.materialized)
        self.assertEqual(['compiler'], self.identities)
        self.assertTrue(result['selectedSources'][0]['existingRolePreserved'])

    def test_ambiguous_physical_roots_with_same_commit_are_rejected(self):
        for name in ('first', 'second'):
            self.sources[name] = dict(self.sources['compiler'], name=name, expectedCommit=self.expected['commit'])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): self.run_registration()
        self.assertFalse(self.report.exists())

    def test_wrong_origin_or_tree_cannot_pass_an_existing_commit_match(self):
        self.sources['compiler']['expectedCommit'] = self.expected['commit']
        with patch.object(C.COLLECTION, 'source_identity', side_effect=ValueError('Exact original origin/tree required')):
            with self.assertRaisesRegex(ValueError, 'origin/tree'): self.run_registration()
        self.assertEqual([], self.materialized); self.assertFalse(self.report.exists())

    def test_clone_callback_cannot_replace_existing_compiler_worktree(self):
        def redirected(name, repository, commit):
            self.sources[name] = dict(name=name, kind='git', path=str(self.old), expectedCommit=commit)
        with self.assertRaisesRegex(ValueError, 'replace a compiler'): self.run_registration(redirected)
        self.assertEqual(b'actual original compiler bytes\r\n', (self.old / 'actual.cs').read_bytes())
        self.assertEqual([], self.materialized)

    def test_fresh_child_keeps_corresponding_source_role_and_is_materialized(self):
        def expand(rows):
            output = list(rows)
            for row in rows:
                if row['name'] == 'literal-b' and not any(r['name'] == 'literal-child' for r in rows):
                    path = Path(row['path']) / 'child'; path.mkdir(exist_ok=True)
                    output.append(dict(name='literal-child', kind='git', path=str(path), expectedCommit='d' * 40, role=row['role']))
            return output
        self.run_registration(expand=expand)
        self.assertEqual({'literal-b', 'literal-child'}, {row['name'] for row in self.materialized})

    def test_report_must_be_fresh_and_outside_compiler_tree(self):
        self.report = self.old / 'hidden.json'
        with self.assertRaisesRegex(ValueError, 'outside'): self.run_registration()
        self.report = self.root / 'existing.json'; self.report.write_bytes(b'original failure')
        with self.assertRaisesRegex(ValueError, 'fresh'): self.run_registration()
        self.assertEqual(b'original failure', self.report.read_bytes())

    def test_other_sdk_route_rejects_before_clone_or_materialization(self):
        clone = Mock()
        with self.assertRaisesRegex(ValueError, 'exact SDK5'): self.run_registration(clone, sdk='6.0.136')
        clone.assert_not_called(); self.assertEqual([], self.materialized)

    def test_report_under_future_cloned_root_rejects_before_materialization_or_write(self):
        self.report = self.root / 'literal-b' / 'captured.json'
        with self.assertRaisesRegex(ValueError, 'outside all collected Git'):
            self.run_registration()
        self.assertFalse(self.report.exists())
        self.assertEqual([], self.materialized)
        self.assertEqual(self.original['compiler'], self.sources['compiler'])

    def test_report_parent_traversal_into_existing_git_root_rejects_before_clone(self):
        self.report = self.root / 'reports' / '..' / 'compiler' / 'captured.json'
        clone = Mock()
        with self.assertRaisesRegex(ValueError, 'parent traversal'):
            self.run_registration(clone)
        clone.assert_not_called()
        self.assertEqual([], self.materialized)
        self.assertFalse((self.old / 'captured.json').exists())

    def test_report_parent_traversal_into_future_git_root_rejects_before_clone(self):
        self.report = self.root / 'reports' / '..' / 'literal-b' / 'captured.json'
        clone = Mock()
        with self.assertRaisesRegex(ValueError, 'parent traversal'):
            self.run_registration(clone)
        clone.assert_not_called()
        self.assertEqual([], self.materialized)
        self.assertFalse((self.root / 'literal-b').exists())

    def test_existing_source_parent_traversal_rejects_before_clone(self):
        self.sources['compiler']['path'] = str(self.root / 'reports' / '..' / 'compiler')
        clone = Mock()
        with self.assertRaisesRegex(ValueError, 'parent traversal'):
            self.run_registration(clone)
        clone.assert_not_called()
        self.assertEqual([], self.materialized)
        self.assertFalse(self.report.exists())

    def test_fresh_source_parent_traversal_rejects_before_identity_or_materialization(self):
        def clone(name, repository, commit):
            self.sources[name] = dict(name=name, kind='git',
                                     path=str(self.root / 'reports' / '..' / name), expectedCommit=commit)
        with self.assertRaisesRegex(ValueError, 'parent traversal'):
            self.run_registration(clone)
        self.assertEqual([], self.identities)
        self.assertEqual([], self.materialized)
        self.assertFalse(self.report.exists())

    @unittest.skipIf(sys.platform == 'win32', 'POSIX directory symlink fixture')
    def test_report_symlink_parent_still_rejects_before_clone(self):
        link = self.root / 'report-link'; link.symlink_to(self.old, target_is_directory=True)
        self.report = link / 'captured.json'
        clone = Mock()
        with self.assertRaisesRegex(ValueError, 'fresh ordinary'):
            self.run_registration(clone)
        clone.assert_not_called()
        self.assertEqual([], self.materialized)
        self.assertFalse((self.old / 'captured.json').exists())


class ClosedPolicy(unittest.TestCase):
    def test_seventeen_original_policy_identities_are_kept_distinct(self):
        rows = C.required_sources(); original = C.LITERAL.policy()['sources']
        self.assertEqual(17, len(rows))
        self.assertEqual({(r['repository'], r['commit'], r['tree']) for r in rows},
                         {(r['repository'], r['commit'], r['tree']) for r in original.values()})
        self.assertTrue(all(r['role'] == C.ROLE for r in rows))


if __name__ == '__main__': unittest.main()
