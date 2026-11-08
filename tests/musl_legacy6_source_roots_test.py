"""Compiler and pristine publisher Gitlinks may share a commit, not a role."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


REGISTRY = module('sdk6_root_registry_tests', 'musl_legacy6_component_sources.py')
ATTRIBUTED = module('sdk6_root_attributed_tests', 'musl_legacy6_attributed_components.py')
EVIDENCE = module('sdk6_root_evidence_tests', 'musl_legacy6_evidence.py')
PACKER = module('sdk6_root_packer_tests', 'package-used-source.py')
ROLE = REGISTRY.ROLE


class ExactSourceRoles(unittest.TestCase):
    def root(self, name, role=None):
        row = dict(name=name, kind='git', commit='a' * 40, tree='b' * 40)
        if role: row['role'] = role
        return row

    def test_one_pristine_role_wins_without_removing_the_compiler_root(self):
        rows = [self.root('compiler-child'), self.root('publisher-child', ROLE)]
        original = copy.deepcopy(rows)
        selected = ATTRIBUTED.source_roots(dict(roots=rows), dict(component=dict(commit='a' * 40, tree='b' * 40)))
        self.assertEqual('publisher-child', selected['component']['name'])
        self.assertEqual({'a' * 40: ['publisher-child']}, EVIDENCE.source_commit_index({r['name']: r for r in rows}))
        self.assertEqual(original, rows)

    def test_two_pristine_candidates_are_still_ambiguous(self):
        rows = [self.root('one', ROLE), self.root('two', ROLE)]
        with self.assertRaisesRegex(ValueError, 'Complete exact SDK6 component Git source'):
            ATTRIBUTED.source_roots(dict(roots=rows), dict(component=dict(commit='a' * 40, tree='b' * 40)))
        with self.assertRaisesRegex(ValueError, 'Ambiguous SDK6 pristine imported source commit'):
            EVIDENCE.source_commit_index({r['name']: r for r in rows})

    def test_preferred_role_cannot_override_commit_tree_or_completeness(self):
        for field, value in [('commit', 'c' * 40), ('tree', 'd' * 40), ('exclude', ['actual.cs']), ('deleted', ['actual.cs'])]:
            row = dict(self.root('publisher', ROLE), **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Complete exact SDK6 component Git source'):
                ATTRIBUTED.source_roots(dict(roots=[row]), dict(component=dict(commit='a' * 40, tree='b' * 40)))

    def test_untyped_duplicate_roots_do_not_gain_an_arbitrary_winner(self):
        rows = [self.root('one'), self.root('two')]
        with self.assertRaisesRegex(ValueError, 'Complete exact SDK6 component Git source'):
            ATTRIBUTED.source_roots(dict(roots=rows), dict(component=dict(commit='a' * 40, tree='b' * 40)))

    def test_registry_still_rejects_two_pristine_import_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = {name: dict(self.root(name, ROLE), expectedCommit='a' * 40, path=str(Path(directory) / name))
                       for name in ('one', 'two')}
            row = dict(name='declared', repository='https://github.com/example/component', commit='a' * 40, role=ROLE)
            with mock.patch.object(REGISTRY, 'policy', return_value=[row]), \
                    self.assertRaisesRegex(ValueError, 'Ambiguous SDK6 imported source commit'):
                REGISTRY.register('6.0.136', sources, lambda *args: self.fail('must not clone'),
                    lambda values: values, Path(directory) / 'report.json')

    def test_pristine_role_still_requires_the_publishers_exact_parent_gitlink(self):
        declared = ATTRIBUTED.policy()['sources']
        roots = [dict(name=role, kind='git', commit=row['commit'], tree=row['tree'], submodules=[])
                 for role, row in declared.items()]
        by_name = {r['name']: r for r in roots}
        for parent, path, child in [('linker', 'external/cecil', 'cecil'), ('external', 'src/cssparser', 'css')]:
            by_name[parent]['submodules'].append(dict(path=path, commit=by_name[child]['commit'], root=child))
        roots.append(dict(by_name['css'], name='unrelated-css-copy', role=ROLE))
        with mock.patch.object(ATTRIBUTED, 'data_bodies', return_value={}), \
                self.assertRaisesRegex(ValueError, 'original SDK6 publisher Gitlink'):
            ATTRIBUTED.validate(ROOT, dict(roots=roots), {})

    def test_actual_two_parent_gitlinks_survive_full_source_pack_and_verify(self):
        def git(path, *args):
            return subprocess.check_output(['git', '-c', 'protocol.file.allow=always', '-C', str(path), *args],
                stderr=subprocess.DEVNULL, text=True).strip()
        def repository(path, label):
            path.mkdir(); git(path, 'init', '--quiet')
            (path / '.gitattributes').write_text('* text eol=lf\n', newline='\n')
            (path / 'original.txt').write_text(label + '\n', newline='\n')
            git(path, 'add', '--', '.gitattributes', 'original.txt')
            git(path, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', label)
            return path
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = repository(base / 'child', 'original preferred component')
            commit, tree = git(child, 'rev-parse', 'HEAD'), git(child, 'rev-parse', 'HEAD^{tree}')
            parents = [repository(base / name, name) for name in ('compiler', 'publisher')]
            for parent in parents:
                git(parent, 'submodule', 'add', '--quiet', str(child), 'child')
                git(parent, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-am', 'Exact child')
            originals = [(p / 'child/original.txt').read_bytes() for p in parents]
            sources = {p.name: dict(name=p.name, kind='git', path=str(p), expectedCommit=git(p, 'rev-parse', 'HEAD')) for p in parents}
            sources['publisher']['role'] = ROLE
            declared = dict(name='declared-component', repository='https://github.com/example/component', commit=commit, role=ROLE)
            with mock.patch.object(REGISTRY, 'policy', return_value=[declared]):
                REGISTRY.register('6.0.136', sources, lambda *args: self.fail('Existing exact publisher child must be reused'),
                    PACKER.expand_submodules, base / 'materialization.json')
            children = [r for r in sources.values() if r.get('expectedCommit') == commit]
            self.assertEqual(2, len(children))
            project = repository(base / 'project', 'Orchestration')
            root_file = base / 'roots.json'; root_file.write_text(json.dumps(dict(schemaVersion=1, roots=list(sources.values()))))
            release = base / 'release'; (release / 'reports/ci').mkdir(parents=True)
            project_commit = git(project, 'rev-parse', 'HEAD')
            PACKER.pack(SimpleNamespace(project_root=project, project_commit=project_commit, output_dir=release / 'sources',
                roots_json=root_file, sdk_version='6.0.136', target_rid='linux-musl-arm64', run_id='111', run_attempt='1'))
            manifest = PACKER.verify(SimpleNamespace(release_dir=release, expected_project_commit=project_commit,
                expected_run_id='111', expected_run_attempt='1', expected_target_rid='linux-musl-arm64'))
            selected = ATTRIBUTED.source_roots(manifest, dict(component=dict(commit=commit, tree=tree)))['component']
            self.assertEqual(ROLE, selected['role'])
            publisher = next(r for r in manifest['roots'] if r['name'] == 'publisher')
            self.assertEqual(selected['name'], publisher['submodules'][0]['root'])
            self.assertEqual(2, len([r for r in manifest['roots'] if r.get('commit') == commit]))
            self.assertEqual([selected['name']], EVIDENCE.source_commit_index({r['name']: r for r in manifest['roots']})[commit])
            self.assertEqual(originals, [(p / 'child/original.txt').read_bytes() for p in parents])


if __name__ == '__main__': unittest.main()
