"""Register the closed SDK5 literal-source trees in a fresh producer workspace."""
import copy
import json
from pathlib import Path

import musl_legacy5_collection_sources as COLLECTION
import musl_legacy5_literal_source_inputs as LITERAL

require = COLLECTION.require
ROLE = COLLECTION.ROLE


def _absolute_path(value):
    path = Path(value)
    require('..' not in path.parts, 'SDK5 literal paths must not contain parent traversal')
    return path.absolute()


def required_sources():
    return [dict(name='sdk5-literal-source-' + name + '-' + row['commit'][:12], literalRole=name,
                 repository=row['repository'], commit=row['commit'], tree=row['tree'], role=ROLE)
            for name, row in LITERAL.policy()['sources'].items()]


def register(sdk, sources, clone, expand_submodules, report_path):
    """Deduplicate by exact origin/commit without rewriting existing worktrees."""
    require(sdk == LITERAL.SDK, 'SDK5 literal corresponding sources require the exact SDK5 route')
    report_path = _absolute_path(report_path)
    require(not report_path.exists() and not any(p.is_symlink() for p in (report_path, *report_path.parents)),
            'A fresh ordinary SDK5 literal collection report is required')
    protected = copy.deepcopy(sources)
    protected_paths = [_absolute_path(row['path']) for row in sources.values()]
    require(all(not report_path.is_relative_to(_absolute_path(row['path'])) for row in sources.values()
                if row.get('kind') == 'git'), 'The SDK5 literal report must remain outside original Git worktrees')
    COLLECTION.expand(sources, expand_submodules)
    fresh, selected = [], []
    for expected in required_sources():
        matches = [row for row in sources.values() if row.get('kind') == 'git'
                   and row.get('expectedCommit') == expected['commit']]
        require(len(matches) <= 1, 'Ambiguous SDK5 literal source commit')
        if matches:
            row = matches[0]
            newly_cloned = False
        else:
            require(expected['name'] not in sources, 'SDK5 literal source name conflicts with another root')
            clone(expected['name'], expected['repository'], expected['commit'])
            require(expected['name'] in sources, 'An actual SDK5 literal clone must declare its source root')
            row = sources[expected['name']]
            path = _absolute_path(row['path'])
            require(all(path != old and not path.is_relative_to(old) and not old.is_relative_to(path)
                        for old in protected_paths), 'A fresh literal source must not replace a compiler worktree')
            row['role'] = ROLE
            fresh.append(path)
            newly_cloned = True
        _absolute_path(row['path'])
        identity = COLLECTION.source_identity(row, expected)
        selected.append(dict(name=row['name'], literalRole=expected['literalRole'], path=row['path'], **identity, newlyCloned=newly_cloned,
                             role=row.get('role', 'build-source'), existingRolePreserved=not newly_cloned))
        COLLECTION.expand(sources, expand_submodules)
    require(all(not report_path.is_relative_to(_absolute_path(row['path'])) for row in sources.values()
                if row.get('kind') == 'git'), 'The SDK5 literal report must remain outside all collected Git worktrees')
    utility = COLLECTION.PRIMARY.materializer()
    materialized = []
    for row in sources.values():
        path = _absolute_path(row['path'])
        if row.get('kind') == 'git' and any(path == parent or path.is_relative_to(parent) for parent in fresh):
            require(row.get('role') == ROLE, 'Fresh literal Gitlink sources must retain their explicit corresponding-source role')
            materialized.append(utility.exact_git_bytes(row))
    require(all(sources.get(name) == row for name, row in protected.items()),
            'Existing SDK5 compiler paths, source records and roles must remain unchanged')
    result = dict(schemaVersion=1, sdkVersion=sdk, kind='sdk5-literal-source-collection-materialization',
                  literalPolicySha256=LITERAL.POLICY_SHA256, selectedSources=selected,
                  freshMaterialization=materialized, existingCompilerWorktreesRewritten=False,
                  existingSourceRootsRelabelled=False, actualProducerExecutionClaimed=False,
                  qualificationAllowed=False, sourceAdmissionAllowed=False)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    return result
