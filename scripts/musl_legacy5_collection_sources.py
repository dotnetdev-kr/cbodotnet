"""SDK5 collection sources beyond the original forty-root registry.

Only newly cloned corresponding-source roots are materialized as raw Git.
Existing compiler/source worktrees and their declared roles are preserved.
"""
import copy
import json
from pathlib import Path
import subprocess

import musl_legacy5_component_sources as PRIMARY
import musl_legacy5_css_source_inputs as CSS
import musl_legacy5_framework_inputs as FRAMEWORK
import musl_legacy5_newtonsoft_source_inputs as NEWTONSOFT

require = PRIMARY.require
ROLE = PRIMARY.ROLE
EXTERNAL_COMMIT = '522d361e1cd703f1e8e526f5306e4ed18de1da41'
EXTERNAL_LINKS = {
    'src/MSBuildLocator': '47281c3de1c87a43ab946725d011b9dca4b6434a',
    'src/application-insights': '51c3ed8aa3f32209edf01168f9136a3ac8486c5d',
    'src/azure-activedirectory-identitymodel-extensions-for-dotnet': 'c94c7fc235501d478221e979062bd8837a55575b',
    'src/cssparser': 'd6d86bcd8c162b1ae22ef00955ff748d028dd0ee',
    'src/humanizer': '3ebc38de585fc641a04b0e78ed69468453b0f8a1',
    'src/newtonsoft-json': 'ae9fe44e1323e91bcbd185ca1a14099fba7c021f'}


def required_sources():
    css, newtonsoft, framework = CSS.policy(), NEWTONSOFT.policy(), FRAMEWORK.policy()
    require(css['sources']['external']['commit'] == EXTERNAL_COMMIT
            and css['sources']['css']['commit'] == EXTERNAL_LINKS['src/cssparser']
            and set(newtonsoft['sources']) == {'e5ac9a8473dfdefb8fe2cddae433a9aaa94a5b37', 'd50b912e9948472e122cfaf24ffeebbf77032806'}
            and framework['preferredSource']['commit'] == FRAMEWORK.ASSETS_COMMIT,
            'The distinct committed SDK5 imported-source leaf pins are required')
    rows = [dict(name='sdk5-source-build-externals-522d361e1cd7', repository='https://github.com/dotnet/source-build-externals',
                 commit=EXTERNAL_COMMIT, tree=css['sources']['external']['tree'], role=ROLE)]
    rows += [dict(name='sdk5-source-newtonsoft-publisher-' + commit[:12], repository='https://github.com/JamesNK/Newtonsoft.Json',
                  commit=commit, tree=row['tree'], role=ROLE) for commit, row in newtonsoft['sources'].items()]
    rows.append(dict(name='sdk5-source-framework-preferred-eccb08286828', repository='https://github.com/dotnet/source-build-assets',
                     commit=FRAMEWORK.ASSETS_COMMIT, tree=framework['preferredSource']['tree'], role=ROLE))
    return rows


def git(path, *arguments):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(path), '-C', str(path), *arguments])


def source_identity(row, expected):
    path = Path(row['path']).absolute()
    require(row.get('kind') == 'git' and row.get('expectedCommit') == expected['commit']
            and path.is_dir() and not any(parent.is_symlink() for parent in (path, *path.parents)),
            'Full ordinary original SDK5 extra Git source required')
    actual = dict(commit=git(path, 'rev-parse', 'HEAD').decode().strip(), tree=git(path, 'rev-parse', 'HEAD^{tree}').decode().strip(),
                  repository=git(path, 'config', '--get', 'remote.origin.url').decode().strip().removesuffix('.git'))
    require(all(actual[key] == expected[key] for key in ('commit', 'tree', 'repository')), 'Exact original SDK5 extra source origin/commit/tree required')
    return actual


def expand(sources, expand_submodules):
    expanded = expand_submodules(list(sources.values()))
    require(len(expanded) == len({row['name'] for row in expanded}), 'Unique SDK5 collection source names required')
    sources.clear(); sources.update({row['name']: row for row in expanded})


def register_extra(sdk, sources, clone, expand_submodules, report_path):
    """Add the four exact parents and all six real original Gitlinks."""
    require(sdk == '5.0.214', 'Only SDK5 collection corresponding sources may be selected')
    report_path = Path(report_path)
    require(not report_path.exists() and not any(path.is_symlink() for path in (report_path, *report_path.parents)), 'A fresh ordinary SDK5 extra-source report is required')
    protected = copy.deepcopy(sources); protected_paths = [Path(row['path']).absolute() for row in sources.values()]
    require(all(not report_path.absolute().is_relative_to(Path(row['path']).absolute()) for row in sources.values() if row.get('kind') == 'git'),
            'SDK5 materialization reports must not modify an existing Git source worktree')
    fresh, observations = [], []; expand(sources, expand_submodules)
    for expected in required_sources():
        matches = [row for row in sources.values() if row.get('kind') == 'git' and row.get('expectedCommit') == expected['commit']]
        require(len(matches) <= 1, 'Ambiguous original SDK5 extra source commit')
        if matches:
            row = matches[0]; newly_cloned = False
        else:
            require(expected['name'] not in sources, 'SDK5 extra source name is already in use')
            clone(expected['name'], expected['repository'], expected['commit'])
            require(expected['name'] in sources, 'Actual SDK5 extra clone must declare its source root')
            row = sources[expected['name']]; path = Path(row['path']).absolute()
            require(all(path != old and not path.is_relative_to(old) and not old.is_relative_to(path) for old in protected_paths),
                    'A new SDK5 corresponding source must not overwrite an existing compiler worktree')
            row['role'] = ROLE; fresh.append(path); newly_cloned = True
        identity = source_identity(row, expected)
        observations.append(dict(name=row['name'], path=row['path'], **identity, newlyCloned=newly_cloned,
                                 existingRolePreserved=not newly_cloned, role=row.get('role', 'build-source')))
        expand(sources, expand_submodules)
    parent = next(row for row in sources.values() if row.get('expectedCommit') == EXTERNAL_COMMIT)
    links = {}
    for entry in git(Path(parent['path']), 'ls-tree', '-rz', EXTERNAL_COMMIT).split(b'\0'):
        if not entry: continue
        header, path = entry.split(b'\t', 1); mode, kind, commit = header.decode().split()
        if kind == 'commit': links[path.decode()] = commit
    require(links == EXTERNAL_LINKS, 'All six original external-source Gitlinks are required without substitution')
    for relative, commit in links.items():
        expected_path = str(Path(parent['path']) / relative)
        matches = [row for row in sources.values() if row.get('kind') == 'git' and row.get('expectedCommit') == commit and str(Path(row['path'])) == expected_path]
        require(len(matches) == 1 and matches[0].get('role', 'build-source') == parent.get('role', 'build-source'),
                'Original SDK5 external Gitlink must retain its actual physical child and role')
    materialized = []; utility = PRIMARY.materializer()
    for row in sources.values():
        if row.get('kind') == 'git' and any(Path(row['path']).absolute() == path or Path(row['path']).absolute().is_relative_to(path) for path in fresh):
            require(row.get('role') == ROLE, 'New SDK5 extra corresponding sources require their explicit import role')
            materialized.append(utility.exact_git_bytes(row))
    require(all(sources[name] == value for name, value in protected.items()), 'Existing SDK5 source roots and compiler roles must remain unchanged')
    result = dict(schemaVersion=1, sdkVersion=sdk, kind='sdk5-extra-original-source-collection-materialization', requiredParents=observations,
                  originalExternalGitlinks=links, freshMaterialization=materialized, existingCompilerWorktreesRewritten=False,
                  existingSourceRootsRelabelled=False, policySelectedForSdk6=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open('x', encoding='utf-8') as stream: json.dump(result, stream, indent=2); stream.write('\n')
    return result


def register(sdk, sources, clone, expand_submodules, report_path):
    """The normal collection caller explicitly installs primary plus extra roots."""
    require(sdk == '5.0.214', 'Only SDK5 collection corresponding sources may be selected')
    report_path = Path(report_path)
    PRIMARY.register(sdk, sources, clone, expand_submodules, report_path.with_name(report_path.stem + '-primary.json'))
    return register_extra(sdk, sources, clone, expand_submodules, report_path)
