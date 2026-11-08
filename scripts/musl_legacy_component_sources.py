"""Register exact corresponding sources before candidate evidence is emitted."""
import json
from pathlib import Path
import re

ROLE = 'source-for-serviced-imported-package'


def require(value, message):
    if not value: raise ValueError(message)


def policy():
    document = json.loads(Path(__file__).with_name('musl-legacy-sdk7-component-sources.json').read_bytes())
    require(document['schemaVersion'] == 1 and document['sdkVersion'] == '7.0.120'
            and len(document['sources']) == 20, 'Closed SDK7 component source registry required')
    names, commits = set(), set()
    for row in document['sources']:
        require(set(row) == {'name', 'repository', 'commit', 'role'}
                and isinstance(row['name'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]*', row['name'])
                and isinstance(row['repository'], str) and re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', row['repository'])
                and isinstance(row['commit'], str) and re.fullmatch(r'[a-f0-9]{40}', row['commit'])
                and row['role'] == ROLE and row['name'] not in names and row['commit'] not in commits,
                'Unique pinned ordinary GitHub component source required')
        names.add(row['name']); commits.add(row['commit'])
    return document['sources']


def register(sdk, sources, clone, expand_submodules):
    """Use the producer's recorded clone boundary and canonical Gitlink names.

    A container package does not establish every bundled component's source.
    These roots permit independent identity checks by the admission gate.
    """
    require(sdk == '7.0.120', 'Additional component source registry is reviewed only for SDK7')
    expanded = expand_submodules(list(sources.values()))
    require(len({r['name'] for r in expanded}) == len(expanded), 'Duplicate corresponding submodule names')
    sources.clear(); sources.update({r['name']: r for r in expanded})
    for row in policy():
        existing = [r for r in sources.values() if r.get('expectedCommit') == row['commit']
                    and r['kind'] in ('git', 'git-export')]
        require(len(existing) <= 1, 'Ambiguous existing component source commit')
        if not existing:
            require(row['name'] not in sources, 'Component source name conflicts with another root')
            clone(row['name'], row['repository'], row['commit'])
            require(sources[row['name']]['expectedCommit'] == row['commit'], 'Recorded component clone differs from its source pin')
            sources[row['name']]['role'] = row['role']
    expanded = expand_submodules(list(sources.values()))
    require(len({r['name'] for r in expanded}) == len(expanded), 'Duplicate corresponding submodule names')
    sources.clear(); sources.update({r['name']: r for r in expanded})
