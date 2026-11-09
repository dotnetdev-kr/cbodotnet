"""An acquired parent must supply its real Gitlinks before child selection."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_source_registry_tested', ROOT / 'scripts/musl_legacy6_component_sources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
spec = importlib.util.spec_from_file_location('sdk6_source_registry_packer_tested', ROOT / 'scripts/package-used-source.py')
PACKER = importlib.util.module_from_spec(spec); spec.loader.exec_module(PACKER)


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

    def test_untyped_compiler_checkout_is_never_materialized(self):
        with tempfile.TemporaryDirectory() as directory:
            source = dict(name='compiler', kind='git', path=str(Path(directory) / 'compiler'), expectedCommit='a' * 40)
            sources = {'compiler': source.copy()}
            with mock.patch.object(M, 'policy', return_value=[self.row('import', 'a')]), \
                    mock.patch.object(M, 'materializer', return_value=SimpleNamespace(
                        exact_git_bytes=lambda r: self.fail('An untyped compiler checkout cannot be rewritten'))):
                M.register('6.0.136', sources, lambda *args: self.fail('Existing compiler root must remain retained'),
                    lambda r: r, Path(directory) / 'report.json')
            self.assertEqual({'compiler': source}, sources)

    def test_typed_source_only_parent_and_gitlink_retain_original_bytes(self):
        def git(path, *args):
            return subprocess.check_output(['git', '-c', 'protocol.file.allow=always', '-C', str(path), *args],
                stderr=subprocess.PIPE)
        def repository(path, label, solution=True):
            path.mkdir(); git(path, 'init', '--quiet')
            (path / '.gitattributes').write_bytes(b'* text eol=lf\n' + (b'*.sln text eol=crlf\n' if solution else b''))
            (path / 'original.txt').write_bytes(label.encode() + b'\n')
            if solution: (path / 'Project.sln').write_bytes(b'original\nsolution\n')
            git(path, 'add', '.')
            git(path, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', label)
            return path
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = repository(base / 'child', 'Original child')
            parent = repository(base / 'parent', 'Original parent')
            git(parent, 'submodule', 'add', '--quiet', str(child), 'child')
            git(parent, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-am', 'Exact child Gitlink')
            imported = base / 'imported'
            git(base, 'clone', '--quiet', '--recurse-submodules', str(parent), str(imported))
            for path in (imported, imported / 'child'):
                self.assertEqual(b'original\r\nsolution\r\n', (path / 'Project.sln').read_bytes())
            compiler = repository(base / 'compiler', 'Actual compiler')
            (compiler / 'original.txt').write_bytes(b'actual compiler patch\n')
            before = (compiler / 'original.txt').read_bytes()
            commit = git(imported, 'rev-parse', 'HEAD').decode().strip()
            child_commit = git(child, 'rev-parse', 'HEAD').decode().strip()
            sources = dict(sdk=dict(name='sdk', kind='git', path=str(compiler),
                expectedCommit=git(compiler, 'rev-parse', 'HEAD').decode().strip()),
                imported=dict(name='imported', kind='git', path=str(imported), expectedCommit=commit,
                    role='source-for-reused-managed-input'))
            declared = [dict(name=name, repository='https://github.com/example/' + name, commit=sha, role=M.ROLE)
                for name, sha in [('publisher', commit), ('publisher-child', child_commit)]]
            report = base / 'materialization.json'
            with mock.patch.object(M, 'policy', return_value=declared):
                M.register('6.0.136', sources, lambda *args: self.fail('Reuse the actual source-only acquisition'),
                    PACKER.expand_submodules, report)
            source_only = [row for row in sources.values() if row['name'] != 'sdk']
            self.assertEqual(2, len(source_only))
            self.assertTrue(all(row['role'] == M.ROLE for row in source_only))
            for row in source_only:
                self.assertEqual(git(Path(row['path']), 'cat-file', 'blob', 'HEAD:Project.sln'),
                    (Path(row['path']) / 'Project.sln').read_bytes())
            self.assertEqual(before, (compiler / 'original.txt').read_bytes())
            self.assertNotIn('role', sources['sdk'])
            retained = json.loads(report.read_bytes())
            self.assertEqual(['imported'], retained['reusedSourceOnlyDependencyRoots'])
            self.assertFalse(retained['compilerWorktreesRewritten'])
            self.assertEqual(2, len(retained['roots']))
            self.assertTrue(all([r['path'] for r in row['changedCheckoutFiles']] == ['Project.sln'] for row in retained['roots']))
            project = repository(base / 'project', 'Clean orchestration', solution=False)
            project_commit = git(project, 'rev-parse', 'HEAD').decode().strip()
            root_file = base / 'roots.json'
            root_file.write_text(json.dumps(dict(schemaVersion=1, roots=list(sources.values()))))
            release = base / 'release'; (release / 'reports/ci').mkdir(parents=True)
            PACKER.pack(SimpleNamespace(project_root=project, project_commit=project_commit, output_dir=release / 'sources',
                roots_json=root_file, sdk_version='6.0.136', target_rid='linux-musl-arm64', run_id='111', run_attempt='1'))
            checked = PACKER.verify(SimpleNamespace(release_dir=release, expected_project_commit=project_commit,
                expected_run_id='111', expected_run_attempt='1', expected_target_rid='linux-musl-arm64'))
            publisher = next(row for row in checked['roots'] if row['name'] == 'imported')
            linked = next(row for row in checked['roots'] if row['name'] == publisher['submodules'][0]['root'])
            self.assertEqual(child_commit, linked['commit'])
            self.assertEqual(M.ROLE, linked['role'])


if __name__ == '__main__': unittest.main()
