"""Fresh corresponding sources never rewrite a compiler worktree or infer Git markers."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_component_sources', ROOT / 'scripts/musl_legacy5_component_sources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class Sources(unittest.TestCase):
    def test_closed_sdk5_policy_rejects_versions_duplicates_mutable_refs_and_marker(self):
        rows = M.policy()
        self.assertEqual(40, len(rows))
        self.assertNotIn('b7f182415927d3b98445d043e1680c56b9d1f17c', {r['commit'] for r in rows})
        changes = [dict(schemaVersion=1, sdkVersion='6.0.136', sources=rows),
                   dict(schemaVersion=1, sdkVersion='5.0.214', sources=rows[:-1]),
                   dict(schemaVersion=1, sdkVersion='5.0.214', sources=rows[:-1] + [rows[0]]),
                   dict(schemaVersion=1, sdkVersion='5.0.214', sources=rows[:-1] + [dict(rows[-1], commit='main')]),
                   dict(schemaVersion=1, sdkVersion='5.0.214', sources=rows[:-1] + [dict(rows[-1], repository='file:///compiler')])]
        for incoming in changes:
            with self.subTest(incoming=incoming['sdkVersion']), mock.patch.object(M.Path, 'read_bytes', return_value=json.dumps(incoming).encode()), self.assertRaises(ValueError):
                M.policy()

    def test_only_fresh_clone_is_materialized_and_existing_compiler_tree_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'compiler'; original.mkdir()
            git = ['git', '-C', str(original)]
            subprocess.run(git + ['init', '-q'], check=True)
            (original / '.gitattributes').write_bytes(b'*.sln text eol=crlf\n')
            (original / 'Product.sln').write_bytes(b'original\n')
            subprocess.run(git + ['add', '.'], check=True, capture_output=True)
            subprocess.run(git + ['-c', 'user.name=Source fixture', '-c', 'user.email=source@example.invalid', 'commit', '-qm', 'original'], check=True)
            sha = subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip()
            (original / 'Product.sln').write_bytes(b'compiler worktree remains changed\r\n')
            pinned = dict(name='sdk5-fixture', repository='https://github.com/example/source', commit=sha, role=M.ROLE)
            roots = {}
            def clone(name, repository, commit):
                target = root / name
                subprocess.run(['git', 'clone', '-q', '--no-hardlinks', str(original), str(target)], check=True)
                roots[name] = dict(name=name, kind='git', path=str(target), expectedCommit=commit, repository=repository)
            with mock.patch.object(M, 'policy', return_value=[pinned]):
                reports = M.register('5.0.214', roots, clone, lambda rows: rows, root / 'report.json')
                self.assertEqual(b'original\n', (root / 'sdk5-fixture/Product.sln').read_bytes())
                self.assertEqual(b'compiler worktree remains changed\r\n', (original / 'Product.sln').read_bytes())
                self.assertEqual(['Product.sln'], [x['path'] for x in reports[0]['changedCheckoutFiles']])
                with mock.patch.object(M, 'materializer', side_effect=AssertionError('Another SDK selected materializer')), self.assertRaisesRegex(ValueError, 'exclusively SDK5'):
                    M.register('6.0.136', roots, clone, lambda rows: rows, root / 'wrong.json')
                with mock.patch.object(M, 'materializer') as materializer:
                    M.register('5.0.214', roots, mock.Mock(side_effect=AssertionError('Existing root cloned')), lambda rows: rows, root / 'reused.json')
                    materializer.return_value.exact_git_bytes.assert_not_called()

    def test_duplicate_existing_identity_and_wrong_clone_pin_reject(self):
        row = dict(name='sdk5-fixture', repository='https://github.com/example/source', commit='a' * 40, role=M.ROLE)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(M, 'policy', return_value=[row]):
            roots = {name: dict(name=name, kind='git', expectedCommit=row['commit']) for name in ('one', 'two')}
            with self.assertRaisesRegex(ValueError, 'Ambiguous SDK5'):
                M.register('5.0.214', roots, None, lambda rows: rows, Path(temporary) / 'ambiguous.json')
            roots = {}
            def wrong(name, repository, commit):
                roots[name] = dict(name=name, kind='git', path=temporary, expectedCommit='b' * 40)
            with self.assertRaisesRegex(ValueError, 'clone differs'):
                M.register('5.0.214', roots, wrong, lambda rows: rows, Path(temporary) / 'wrong.json')


if __name__ == '__main__': unittest.main()
