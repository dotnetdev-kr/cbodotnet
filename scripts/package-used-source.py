#!/usr/bin/env python3
"""Archive the actual source inputs of a completed CI build, then verify delivery."""
import argparse
import base64
import datetime
import functools
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def portable(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name
            and not any(c in name for c in '\0\n\r') and not name.startswith('/')
            and posixpath.normpath(name) == name and '..' not in PurePosixPath(name).parts,
            'Unsafe source member: ' + str(name))
    return name


def ordinary_root(path):
    path = path.absolute()
    require(path.is_dir() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary absolute source directory is required: ' + str(path))
    return path


def fingerprint(path):
    before = path.stat(); hashes = {a: hashlib.new(a) for a in ('sha256', 'sha512')}
    require(path.is_file() and not path.is_symlink(), 'An ordinary source file is required')
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for h in hashes.values():
                h.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
            'Source changed while hashing: ' + str(path))
    return dict(bytes=after.st_size, **{a: h.hexdigest() for a, h in hashes.items()})


def git(root, *args):
    command = ['git', '--git-dir=' + root['gitDir']] if root.get('gitDir') else ['git', '-C', root['path']]
    return subprocess.check_output([*command, *args])


def git_identity(root):
    commit = root.get('expectedCommit') or git(root, 'rev-parse', 'HEAD').decode().strip()
    require(re.fullmatch('[a-f0-9]{40}', commit), 'A pinned Git commit is required')
    if root['kind'] == 'git':
        require(git(root, 'rev-parse', 'HEAD').decode().strip() == commit, 'Source HEAD differs from its pin')
    body = git(root, 'cat-file', 'commit', commit)
    actual = hashlib.sha1(b'commit ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    require(actual == commit, 'The source commit object differs')
    entries = {}; submodules = []
    for value in git(root, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not value:
            continue
        header, name = value.split(b'\t', 1); mode, kind, blob = header.decode().split()
        name = portable(name.decode('utf-8'))
        if kind == 'commit':
            submodules.append({'path': name, 'commit': blob}); continue
        require(mode in ('100644', '100755', '120000'), 'Unsupported Git source mode')
        entries[name] = {'mode': mode, 'blob': blob}
    return {'commit': commit, 'commitObjectBase64': base64.b64encode(body).decode(),
            'tree': body.splitlines()[0].decode().removeprefix('tree '), 'submodules': submodules}, entries


def baseline_tree(entries):
    tree = {}
    for name, row in entries.items():
        parts = PurePosixPath(portable(name)).parts; parent = tree
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
        require(parts[-1] not in parent, 'Duplicate Git baseline source entry')
        parent[parts[-1]] = (row['mode'], row['blob'])

    def digest(directory):
        data = b''
        for name, value in sorted(directory.items(), key=lambda item: item[0].encode() + (b'/' if isinstance(item[1], dict) else b'')):
            mode, object_id = ('40000', digest(value)) if isinstance(value, dict) else value
            data += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(object_id)
        return hashlib.sha1(b'tree ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    return digest(tree)


def tree_names(root):
    directory = Path(root['path']); exclusions = [portable(n).rstrip('/') for n in root.get('exclude', [])]
    result = []
    for current, directories, files in os.walk(directory, followlinks=False):
        parent = Path(current)
        for name in sorted(directories + files):
            path = parent / name; relative = path.relative_to(directory).as_posix()
            excluded = '.git' in PurePosixPath(relative).parts or any(
                relative == prefix or relative.startswith(prefix + '/') for prefix in exclusions)
            if excluded:
                if name in directories:
                    directories.remove(name)
                continue
            if path.is_symlink() or path.is_file():
                result.append(portable(relative))
                if name in directories:
                    directories.remove(name)
            else:
                require(path.is_dir(), 'Special source entries are not supported: ' + str(path))
    return sorted(result)


def selected(root):
    if root['kind'] == 'tree':
        return {'kind': 'tree', 'exclude': root.get('exclude', [])}, tree_names(root), {}
    identity, baseline = git_identity(root)
    names = set(baseline)
    if root['kind'] == 'git':
        names.update(portable(n.decode()) for n in git(root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0') if n)
    else:
        # Exported consumers lack an index. Capture their complete actual tree,
        # apart from explicitly reviewed build/cache paths and Git metadata.
        names.update(tree_names(root))
    names.update(portable(n) for n in root.get('include', []))
    identity.update(kind=root['kind'], exclude=root.get('exclude', []))
    return identity, sorted(names), baseline


def expand_submodules(roots):
    """Retain nested consumers, including valid empty submodule checkouts."""
    position = 0
    while position < len(roots):
        root = roots[position]; position += 1
        if root['kind'] == 'tree':
            continue
        identity, _ = git_identity(root)
        for submodule in identity.get('submodules', []):
            path = str(ordinary_root(Path(root['path']) / submodule['path']))
            present = [other for other in roots if other['path'] == path
                       and other.get('expectedCommit') == submodule['commit'] and other['kind'] in ('git', 'git-export')]
            if present:
                require(len(present) == 1, 'Ambiguous declared submodule consumer: ' + path)
                continue
            # Preserved generated checkouts have real Git directories/files.
            # Minimal legacy export markers must instead be declared with gitDir.
            name = root['name'] + '-sub-' + hashlib.sha256(submodule['path'].encode()).hexdigest()[:12]
            require(not any(other['name'] == name for other in roots), 'Duplicate automatic submodule name')
            child = {'name': name, 'path': path, 'kind': 'git', 'expectedCommit': submodule['commit']}
            git_identity(child)
            roots.append(child)
    return roots


def data_record(name, mode, data, baseline=None):
    record = {'path': name, 'mode': mode, 'bytes': len(data),
              **{a: hashlib.new(a, data).hexdigest() for a in ('sha256', 'sha512')}}
    if baseline:
        record['baseline'] = baseline
    return record


@functools.lru_cache(maxsize=1)
def shared_crlf_policy():
    """Load the exact reviewed attribute audit; a new pin requires re-auditing."""
    path = Path(__file__).with_name('net10-shared-source-crlf.json')
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'The pinned shared-source checkout policy must be ordinary')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == '9ac0fabdffed3e8fdaa037b52b9f62505b9710364b1268ce821a48bcb1218d65',
            'The reviewed shared-source checkout policy changed; re-audit required')
    policy = json.loads(data)
    require(policy['schemaVersion'] == 1 and policy['role'] == 'source-for-reused-shared-input'
            and policy['commit'] == '0427b9abbead3fa64c6655eb4290c537397131fa'
            and policy['tree'] == 'ed143c381dc0e4742aa1f9afd3652af5f21c15d6'
            and len(policy['paths']) == 987 and policy['paths'] == sorted(set(policy['paths']))
            and all(portable(name) == name for name in policy['paths']),
            'Unexpected pinned shared-source checkout policy')
    return policy, frozenset(policy['paths'])


def pristine_crlf_paths(root):
    """Permit audited paths only for the corresponding pinned source root."""
    if (root.get('role') != 'source-for-reused-shared-input'
            or root.get('commit') != '0427b9abbead3fa64c6655eb4290c537397131fa'
            or root.get('tree') != 'ed143c381dc0e4742aa1f9afd3652af5f21c15d6'):
        return frozenset()
    return shared_crlf_policy()[1]


def pristine_blob(row, actual_blob, windows_bytes, allow_audited_crlf=False):
    """Recognize uniform CRLF only when canonical bytes equal the Git blob."""
    baseline = row.get('baseline')
    if baseline == {'mode': row['mode'], 'blob': actual_blob}:
        return True
    if (row['mode'] not in ('100644', '100755')
            or not (row['path'].lower().endswith(('.cmd', '.bat')) or allow_audited_crlf)
            or windows_bytes is None
            or not baseline or baseline.get('mode') != row['mode']):
        return False
    canonical = windows_bytes.replace(b'\r\n', b'\n')
    if (allow_audited_crlf and b'\0' in canonical) or b'\r' in canonical or windows_bytes != canonical.replace(b'\n', b'\r\n'):
        return False
    return hashlib.sha1(b'blob ' + str(len(canonical)).encode() + b'\0' + canonical).hexdigest() == baseline['blob']


def pack(args):
    project = ordinary_root(args.project_root)
    require(subprocess.check_output(['git', '-C', str(project), 'rev-parse', 'HEAD']).decode().strip()
            == args.project_commit, 'The orchestration checkout differs from the requested commit')
    require(not subprocess.check_output(['git', '-C', str(project), 'status', '--porcelain', '--untracked-files=all']),
            'Source packaging requires a clean orchestration checkout')
    output = args.output_dir.absolute(); release = output.parent
    require(output.name == 'sources' and release.is_dir() and not output.exists() and not output.is_symlink(),
            'Source packaging requires a fresh release/sources directory')
    ordinary_root(release)
    roots_doc = json.loads(args.roots_json.read_text(encoding='utf-8-sig'))
    require(roots_doc.get('schemaVersion') == 1 and roots_doc.get('roots'), 'Actual build-source roots are required')
    roots = list(roots_doc['roots'])
    require(all(root.get('name') != 'orchestration' for root in roots), 'Reserved source root name')
    roots.append({'name': 'orchestration', 'kind': 'git', 'path': str(project), 'expectedCommit': args.project_commit,
                  'role': 'orchestration'})
    input_records = release / 'reports/ci-inputs'
    if input_records.is_dir():
        roots.append({'name': 'build-input-records', 'kind': 'tree', 'path': str(input_records), 'exclude': ['project']})
    require(len({root['name'] for root in roots}) == len(roots), 'Duplicate source root names')
    for root in roots:
        require(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]*', root['name']), 'Unsafe source root name')
        require(root['kind'] in ('git', 'git-export', 'tree'), 'Unsupported source root kind')
        root['path'] = str(ordinary_root(Path(root['path'])))
        if root['kind'] == 'git-export':
            root['gitDir'] = str(ordinary_root(Path(root['gitDir'])))
    expand_submodules(roots)
    output.mkdir()
    archive_name = 'cbodotnet-sources-{}-{}-build.{}.tar.gz'.format(args.sdk_version, args.target_rid, args.run_id)
    index_path = output / 'source-index.jsonl'; root_records = []; count = 0
    with index_path.open('x', encoding='utf-8', newline='\n') as index, tarfile.open(output / archive_name, 'w:gz', compresslevel=6) as archive:
        for root in sorted(roots, key=lambda value: value['name']):
            identity, names, baseline = selected(root)
            for submodule in identity.get('submodules', []):
                candidates = [other for other in roots if Path(other['path']) == Path(root['path']) / submodule['path']
                              and other.get('expectedCommit') == submodule['commit'] and other['kind'] in ('git', 'git-export')]
                require(len(candidates) == 1, 'Declare the actual pinned submodule consumer: ' + root['name'] + '/' + submodule['path'])
                submodule['root'] = candidates[0]['name']
            root_record = dict(name=root['name'], originalPath=root['path'], role=root.get('role', 'build-source'),
                               **identity, files=0, deleted=[])
            for relative in names:
                path = Path(root['path']) / relative
                require(not any(p.is_symlink() for p in path.parents if p != Path(root['path']).parent),
                        'A source member has a linked ancestor: ' + str(path))
                if not path.exists() and not path.is_symlink():
                    require(relative in baseline, 'Declared extra source is absent: ' + relative)
                    root_record['deleted'].append(dict(path=relative, **baseline[relative])); continue
                name = portable(root['name'] + '/' + relative)
                before = path.lstat(); info = tarfile.TarInfo(name)
                info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
                if stat.S_ISLNK(before.st_mode):
                    target = os.readlink(path)
                    require(not any(c in target for c in '\0\n\r') and not target.startswith('/')
                            and posixpath.normpath(posixpath.join(posixpath.dirname(name), target)).startswith(root['name'] + '/'),
                            'Source symlink escapes its archived root: ' + name)
                    raw = target.encode('utf-8'); info.type = tarfile.SYMTYPE; info.linkname = target; info.mode = 0o777
                    archive.addfile(info); row = data_record(name, '120000', raw, baseline.get(relative))
                else:
                    require(stat.S_ISREG(before.st_mode), 'Source member is not ordinary: ' + name)
                    mode = '100755' if before.st_mode & 0o111 else '100644'
                    values = fingerprint(path); info.mode = 0o755 if mode == '100755' else 0o644; info.size = values['bytes']
                    with path.open('rb') as stream:
                        archive.addfile(info, stream)
                    require(values == fingerprint(path), 'Source changed while archiving: ' + name)
                    row = dict(path=name, mode=mode, **values)
                    if relative in baseline:
                        row['baseline'] = baseline[relative]
                require((before.st_size, before.st_mtime_ns) == (path.lstat().st_size, path.lstat().st_mtime_ns),
                        'Source changed during archive capture: ' + name)
                index.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n')
                root_record['files'] += 1; count += 1
            root_records.append(root_record)
    manifest = {'schemaVersion': 1, 'status': 'captured-used-source', 'sdkVersion': args.sdk_version,
                'targetRid': args.target_rid, 'projectCommit': args.project_commit, 'runId': args.run_id,
                'runAttempt': args.run_attempt, 'capturedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'scope': 'Declared actual build sources, corresponding sources for reused inputs, applied changes, generated consumers and orchestration; root roles distinguish construction. Git object stores and declared build caches are excluded.',
                'roots': root_records, 'files': count,
                'archive': dict(path=archive_name, **fingerprint(output / archive_name)),
                'index': dict(path='source-index.jsonl', **fingerprint(index_path))}
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    (output / 'source-manifest.json').write_bytes(encoded)
    report = release / 'reports/ci/used-source.json'
    require(report.parent.is_dir() and not report.exists(), 'A fresh source report control is required')
    report.write_bytes(encoded)
    print(json.dumps({'status': 'passed', 'files': count, 'archive': manifest['archive']}))


def verify(args):
    release = ordinary_root(args.release_dir); source = ordinary_root(release / 'sources')
    manifest_path = source / 'source-manifest.json'
    require(manifest_path.read_bytes() == (release / 'reports/ci/used-source.json').read_bytes(),
            'Source manifest differs from the inventoried report control')
    manifest = json.loads(manifest_path.read_text())
    if getattr(args, 'expected_target_rid', None) is not None:
        require(manifest.get('targetRid') == args.expected_target_rid, 'Source delivery target RID differs')
    for key, value in [('projectCommit', args.expected_project_commit), ('runId', args.expected_run_id),
                       ('runAttempt', args.expected_run_attempt)]:
        require(manifest.get(key) == value, 'Source delivery identity differs: ' + key)
    require(manifest.get('schemaVersion') == 1 and manifest.get('status') == 'captured-used-source', 'Source capture did not pass')
    expected_files = {'source-manifest.json', manifest['archive']['path'], manifest['index']['path']}
    require({p.name for p in source.iterdir()} == expected_files, 'Unbound or missing source artifacts')
    for key in ('archive', 'index'):
        path = source / portable(manifest[key]['path'])
        require(path.parent == source and all(manifest[key].get(k) == v for k, v in fingerprint(path).items()),
                'Source artifact hash differs: ' + key)
    counts = {root['name']: 0 for root in manifest['roots']}; names = set(); total = 0
    allowed_crlf = {root['name']: pristine_crlf_paths(root) for root in manifest['roots']}
    baselines = {root['name']: {row['path']: {'mode': row['mode'], 'blob': row['blob']}
                              for row in root.get('deleted', [])} for root in manifest['roots']}
    require('orchestration' in counts and len(counts) == len(manifest['roots']), 'Missing or duplicate source roots')
    orchestration = next(root for root in manifest['roots'] if root['name'] == 'orchestration')
    require(orchestration.get('kind') == 'git' and orchestration.get('commit') == args.expected_project_commit,
            'Packaged orchestration sources belong to another commit')
    with (source / manifest['index']['path']).open(encoding='utf-8') as index, tarfile.open(source / manifest['archive']['path'], 'r|gz') as archive:
        for member in archive:
            line = index.readline(); require(bool(line), 'Source archive has an unindexed entry')
            row = json.loads(line); name = portable(member.name)
            require(row['path'] == name and name not in names and PurePosixPath(name).parts[0] in counts,
                    'Source member ordering, membership or root differs')
            names.add(name); hashes = {a: hashlib.new(a) for a in ('sha256', 'sha512')}; size = 0
            blob = hashlib.sha1(b'blob ' + str(row['bytes']).encode() + b'\0')
            root_name, relative = name.split('/', 1)
            audited_crlf = relative in allowed_crlf[root_name]
            windows_bytes = bytearray() if (name.lower().endswith(('.cmd', '.bat')) or audited_crlf) and row['bytes'] <= 8 * 1024**2 else None
            if row.get('baseline'):
                root, relative = name.split('/', 1)
                require(relative not in baselines[root], 'A deleted baseline also exists in the source archive')
                baselines[root][relative] = row['baseline']
            if row['mode'] == '120000':
                require(member.issym(), 'Source symlink type changed')
                raw = member.linkname.encode('utf-8'); size = len(raw)
                blob.update(raw)
                if windows_bytes is not None: windows_bytes.extend(raw)
                for digest in hashes.values():
                    digest.update(raw)
                root = PurePosixPath(name).parts[0]
                require(not member.linkname.startswith('/') and posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname)).startswith(root + '/'),
                        'Source symlink escapes its root')
            else:
                require(member.isfile() and row['mode'] in ('100644', '100755')
                        and (member.mode & 0o7777) == (0o755 if row['mode'] == '100755' else 0o644), 'Source file type/mode changed')
                stream = archive.extractfile(member)
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    size += len(block)
                    blob.update(block)
                    if windows_bytes is not None: windows_bytes.extend(block)
                    for digest in hashes.values():
                        digest.update(block)
            require(row.get('bytes') == size and all(row.get(a) == h.hexdigest() for a, h in hashes.items()),
                    'Source content differs: ' + name)
            root_info = next(root for root in manifest['roots'] if root['name'] == PurePosixPath(name).parts[0])
            if root_info['name'] == 'orchestration' or root_info.get('role') == 'source-for-reused-shared-input':
                require(pristine_blob(row, blob.hexdigest(), bytes(windows_bytes) if windows_bytes is not None else None, audited_crlf),
                        'Pristine corresponding source differs from its actual Git blob: ' + name)
            counts[PurePosixPath(name).parts[0]] += 1; total += 1
        require(not index.readline(), 'Source index contains absent archive members')
    require(total == manifest['files'] and all(counts[root['name']] == root['files'] for root in manifest['roots']),
            'Source root counts differ')
    for root in manifest['roots']:
        if root.get('kind') in ('git', 'git-export'):
            raw = base64.b64decode(root['commitObjectBase64'], validate=True)
            require(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == root['commit']
                    and raw.startswith(('tree ' + root['tree'] + '\n').encode()), 'Source Git origin control differs')
            for submodule in root.get('submodules', []):
                children = [child for child in manifest['roots'] if child['name'] == submodule['root']
                            and child.get('commit') == submodule['commit']]
                require(len(children) == 1, 'Pinned submodule source is missing')
                baselines[root['name']][submodule['path']] = {'mode': '160000', 'blob': submodule['commit']}
            require(baseline_tree(baselines[root['name']]) == root['tree'], 'Source baseline does not reconstruct its pinned Git tree')
    print(json.dumps({'status': 'passed', 'command': 'verify-source', 'files': total,
                      'sourceManifestSha256': fingerprint(manifest_path)['sha256']}))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command')
    packing = commands.add_parser('pack')
    for name in ('roots-json', 'output-dir', 'project-root'):
        packing.add_argument('--' + name, type=Path, required=True)
    for name in ('project-commit', 'sdk-version', 'target-rid', 'run-id', 'run-attempt'):
        packing.add_argument('--' + name, required=True)
    checking = commands.add_parser('verify')
    checking.add_argument('--release-dir', type=Path, required=True)
    for name in ('expected-project-commit', 'expected-run-id', 'expected-run-attempt'):
        checking.add_argument('--' + name, required=True)
    checking.add_argument('--expected-target-rid', choices=('linux-arm64', 'linux-x64'))
    import sys
    values = sys.argv[1:]
    # Packing remains compatible with the initially agreed flag-only interface.
    if values and values[0].startswith('--'):
        values.insert(0, 'pack')
    args = parser.parse_args(values)
    require(args.command in ('pack', 'verify'), 'Choose pack or verify')
    if args.command == 'pack':
        require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.sdk_version)
                and args.target_rid in ('linux-arm64', 'linux-x64')
                and re.fullmatch('[a-f0-9]{40}', args.project_commit)
                and all(re.fullmatch('[1-9][0-9]*', value) for value in (args.run_id, args.run_attempt)), 'Invalid build identity')
        pack(args)
    else:
        verify(args)


if __name__ == '__main__':
    main()
