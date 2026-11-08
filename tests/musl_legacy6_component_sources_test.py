"""An acquired parent must supply its real Gitlinks before child selection."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_source_registry_tested', ROOT / 'scripts/musl_legacy6_component_sources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class CanonicalSourceGitlinks(unittest.TestCase):
    def row(self, name, commit):
        return dict(name=name, repository='https://github.com/example/' + name, commit=commit * 40, role=M.ROLE)

    def test_new_parent_is_expanded_before_later_child_clone_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); sources = dict(sdk=dict(name='sdk', kind='git', path=str(base / 'compiler'), expectedCommit='c' * 40))
            cloned, materialized = [], []
            def clone(name, repository, commit):
                cloned.append(name); sources[name] = dict(name=name, kind='git', path=str(base / name), expectedCommit=commit)
            def expand(rows):
                rows = list(rows)
                if any(r['name'] == 'parent' for r in rows) and not any(r['expectedCommit'] == 'b' * 40 for r in rows):
                    rows.append(dict(name='parent-sub-canonical', kind='git', path=str(base / 'parent/child'), expectedCommit='b' * 40, role=M.ROLE))
                return rows
            def literal(row): materialized.append(row['name']); return dict(name=row['name'])
            with mock.patch.object(M, 'policy', return_value=[self.row('parent', 'a'), self.row('child', 'b')]), \
                    mock.patch.object(M, 'materializer', return_value=SimpleNamespace(exact_git_bytes=literal)):
                M.register('6.0.136', sources, clone, expand, base / 'report.json')
            self.assertEqual(['parent'], cloned)
            self.assertEqual({'parent', 'parent-sub-canonical'}, set(materialized))
            self.assertNotIn('sdk', materialized)
            self.assertNotIn('child', sources)

    def test_localization_compiler_checkout_does_not_replace_pristine_import_source(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); sources = {'msbuild-localization': dict(name='msbuild-localization', kind='git',
                path=str(base / 'actual-compiler'), expectedCommit='a' * 40)}; cloned = []
            def clone(name, repository, commit):
                cloned.append(name); sources[name] = dict(name=name, kind='git', path=str(base / name), expectedCommit=commit)
            with mock.patch.object(M, 'policy', return_value=[self.row('import-msbuild', 'a')]), \
                    mock.patch.object(M, 'materializer', return_value=SimpleNamespace(exact_git_bytes=lambda r: dict(name=r['name']))):
                M.register('6.0.136', sources, clone, lambda r: r, base / 'report.json')
            self.assertEqual(['import-msbuild'], cloned)
            self.assertNotIn('role', sources['msbuild-localization'])

    def test_duplicate_independent_import_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = {name: dict(name=name, kind='git', expectedCommit='a' * 40, path=str(Path(directory) / name)) for name in ('one', 'two')}
            with mock.patch.object(M, 'policy', return_value=[self.row('import', 'a')]), mock.patch.object(M, 'materializer'), \
                    self.assertRaisesRegex(ValueError, 'Ambiguous SDK6 imported source commit'):
                M.register('6.0.136', sources, lambda *args: self.fail('must not clone'), lambda r: r, Path(directory) / 'report.json')


if __name__ == '__main__': unittest.main()
