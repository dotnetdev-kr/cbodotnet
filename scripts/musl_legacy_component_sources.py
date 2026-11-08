"""Register exact corresponding sources before candidate evidence is emitted."""
import json
import hashlib
from pathlib import Path
import re
import subprocess

ROLE = 'source-for-serviced-imported-package'


def require(value, message):
    if not value: raise ValueError(message)


def policy():
    document = json.loads(Path(__file__).with_name('musl-legacy-sdk7-component-sources.json').read_bytes())
    require(document['schemaVersion'] == 1 and document['sdkVersion'] == '7.0.120'
            and len(document['sources']) == 24, 'Closed SDK7 component source registry required')
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


def exact_git_bytes(root):
    """Materialize a fresh corresponding-source clone using original blobs.

    Checkout attributes may intentionally turn an original LF .sln into CRLF.
    Corresponding sources have never been compiler worktrees; retain the exact
    original Git bytes and report every changed checkout file separately.
    """
    path = Path(root['path']).absolute()
    require(root['kind'] == 'git' and root.get('role') == ROLE
            and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary fresh corresponding-source clone required')
    git = ['git', '-c', 'safe.directory=' + str(path), '-C', str(path)]
    commit = root['expectedCommit']
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == commit,
            'Fresh corresponding source differs from its exact commit')
    changed, files = [], 0
    for record in subprocess.check_output(git + ['ls-tree', '-rz', '--full-tree', commit]).split(b'\0'):
        if not record: continue
        header, encoded = record.split(b'\t', 1); mode, kind, blob = header.decode().split()
        if kind == 'commit' or mode == '120000': continue
        require(kind == 'blob' and mode in ('100644', '100755'), 'Unexpected corresponding-source Git tree entry')
        name = encoded.decode('utf-8'); relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,
                'Corresponding-source file escapes its fresh clone')
        target = path / relative
        require(target.is_file() and not any(p.is_symlink() for p in (target, *target.parents)),
                'Fresh corresponding-source checkout is missing or redirected')
        before = target.stat(); actual = hashlib.sha1(b'blob ' + str(before.st_size).encode() + b'\0')
        with target.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''): actual.update(block)
        require((before.st_size, before.st_mtime_ns) == (target.stat().st_size, target.stat().st_mtime_ns),
                'Fresh corresponding-source checkout changed during verification')
        files += 1
        if actual.hexdigest() == blob: continue
        old = target.read_bytes(); original = subprocess.check_output(git + ['cat-file', 'blob', blob])
        require(hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest() == blob,
                'Original corresponding-source Git blob identity differs')
        target.write_bytes(original)
        changed.append(dict(path=name, gitBlob=blob, checkoutBytes=len(old), checkoutSha256=hashlib.sha256(old).hexdigest(),
            retainedBytes=len(original), retainedSha256=hashlib.sha256(original).hexdigest()))
    return dict(name=root['name'], commit=commit, files=files, changedCheckoutFiles=changed,
                scope='Exact Git blobs in a fresh corresponding-source-only clone; no compiler worktree changes')


def register(sdk, sources, clone, expand_submodules, report_path=None):
    """Use the producer's recorded clone boundary and canonical Gitlink names.

    A container package does not establish every bundled component's source.
    These roots permit independent identity checks by the admission gate.
    """
    require(sdk == '7.0.120', 'Additional component source registry is reviewed only for SDK7')
    expanded = expand_submodules(list(sources.values()))
    require(len({r['name'] for r in expanded}) == len(expanded), 'Duplicate corresponding submodule names')
    sources.clear(); sources.update({r['name']: r for r in expanded})
    fresh = []
    for row in policy():
        existing = [r for r in sources.values() if r.get('expectedCommit') == row['commit']
                    and r['kind'] in ('git', 'git-export')]
        require(len(existing) <= 1, 'Ambiguous existing component source commit')
        if not existing:
            require(row['name'] not in sources, 'Component source name conflicts with another root')
            clone(row['name'], row['repository'], row['commit'])
            require(sources[row['name']]['expectedCommit'] == row['commit'], 'Recorded component clone differs from its source pin')
            sources[row['name']]['role'] = row['role']
            fresh.append(Path(sources[row['name']]['path']).absolute())
    expanded = expand_submodules(list(sources.values()))
    require(len({r['name'] for r in expanded}) == len(expanded), 'Duplicate corresponding submodule names')
    sources.clear(); sources.update({r['name']: r for r in expanded})
    reports = [exact_git_bytes(row) for row in expanded if row.get('role') == ROLE
               and any(Path(row['path']).absolute() == parent or Path(row['path']).absolute().is_relative_to(parent) for parent in fresh)]
    if report_path is not None:
        path = Path(report_path).absolute()
        require(not any(p.is_symlink() for p in (path, *path.parents)) and not path.exists(),
                'Fresh ordinary corresponding-source materialization report required')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(schemaVersion=1, kind='fresh-corresponding-source-exact-Git-materialization',
            sdkVersion=sdk, roots=reports), indent=2) + '\n')
    return reports
