"""SDK5-only corresponding-source registry and fresh clone materialization."""
import importlib.util
import json
from pathlib import Path
import re

ROLE = 'source-for-serviced-imported-package'


def require(value, message):
    if not value: raise ValueError(message)


def policy():
    document = json.loads(Path(__file__).with_name('musl-legacy-sdk5-component-sources.json').read_bytes())
    require(document.get('schemaVersion') == 1 and document.get('sdkVersion') == '5.0.214' and len(document.get('sources', [])) == 40, 'Distinct SDK5 corresponding-source registry required')
    names, commits = set(), set()
    for row in document['sources']:
        require(set(row) == {'name', 'repository', 'commit', 'role'}
                and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]*', row['name'])
                and re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', row['repository'])
                and re.fullmatch('[a-f0-9]{40}', row['commit']) and row['role'] == ROLE
                and row['name'] not in names and row['commit'] not in commits, 'Unique exact SDK5 GitHub source pins required')
        names.add(row['name']); commits.add(row['commit'])
    require(names, 'Complete reviewed SDK5 source table is absent')
    return document['sources']


def materializer():
    spec = importlib.util.spec_from_file_location('sdk5_exact_git_blob_materializer', Path(__file__).with_name('musl_legacy_component_sources.py'))
    utility = importlib.util.module_from_spec(spec); spec.loader.exec_module(utility)
    return utility


def register(sdk, sources, clone, expand_submodules, report_path):
    require(sdk == '5.0.214', 'This source registry is exclusively SDK5')
    utility = materializer()
    fresh, reports = [], []
    expanded = expand_submodules(list(sources.values())); sources.clear(); sources.update({r['name']: r for r in expanded})
    require(len(sources) == len(expanded), 'Duplicate SDK5 canonical Gitlink source name')
    for row in policy():
        existing = [r for r in sources.values() if r.get('kind', 'git') in ('git', 'git-export')
                    and r.get('expectedCommit') == row['commit']]
        require(len(existing) <= 1, 'Ambiguous SDK5 imported source commit')
        if existing: continue
        require(row['name'] not in sources, 'SDK5 component source name conflicts with another root')
        clone(row['name'], row['repository'], row['commit'])
        require(sources[row['name']].get('expectedCommit') == row['commit'], 'Recorded SDK5 clone differs from its source pin')
        sources[row['name']]['role'] = ROLE
        fresh.append(Path(sources[row['name']]['path']).absolute())
        # A newly acquired parent can supply later registry entries through
        # exact Gitlinks. Expand it before deciding whether to clone a child.
        for child in expand_submodules([sources[row['name']]]):
            require(child['name'] not in sources or sources[child['name']] == child,
                    'SDK5 canonical parent/Gitlink source conflicts with an existing root')
            sources[child['name']] = child
    expanded = expand_submodules(list(sources.values())); require(len({r['name'] for r in expanded}) == len(expanded), 'Duplicate SDK5 expanded source name')
    sources.clear(); sources.update({r['name']: r for r in expanded})
    for row in expanded:
        if row.get('kind', 'git') == 'git' and any(Path(row['path']).absolute() == p or Path(row['path']).absolute().is_relative_to(p) for p in fresh):
            row['role'] = ROLE; reports.append(utility.exact_git_bytes(row))
    path = Path(report_path); require(not path.exists() and not any(p.is_symlink() for p in (path, *path.parents)), 'Fresh ordinary SDK5 source materialization report required')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(schemaVersion=1, kind='sdk5-fresh-corresponding-source-exact-Git-materialization',
        sdkVersion=sdk, roots=reports, compilerWorktreesRewritten=False), indent=2) + '\n')
    return reports
