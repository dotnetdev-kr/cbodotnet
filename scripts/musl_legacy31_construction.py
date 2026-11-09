"""Read-only Core3.1 source/bootstrap accounting; no producer or admission side effects."""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import tarfile
import zipfile

SDK = '3.1.426'
POLICY = Path(__file__).parent / 'musl-legacy31-construction-policy.json'
FIELDS = ('bytes', 'sha256', 'sha512')
ARCHITECTURES = {'x64': 'linux-musl-x64', 'aarch64': 'linux-musl-arm64'}
STAGES = ('sdk_tasks', 'cli', 'fsharp_proto', 'fsharp_release', 'toolset', 'core_sdk', 'collector')


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError('Core3.1: ' + message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def fingerprint(raw):
    require(isinstance(raw, bytes), 'bytes required for fingerprint')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def identity(value, *, nonempty=False):
    require(isinstance(value, dict) and set(value) == set(FIELDS), 'complete three-field fingerprint required')
    require(type(value.get('bytes')) is int and value['bytes'] >= (1 if nonempty else 0), 'invalid byte count')
    for name, length in (('sha256', 64), ('sha512', 128)):
        require(isinstance(value.get(name), str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value[name]), 'invalid ' + name)
    return value


def three_fields(value):
    require(isinstance(value, dict) and set(FIELDS) <= set(value), 'missing whole size/SHA256/SHA512')
    return identity({key: value[key] for key in FIELDS})


def document(raw, maximum=16 * 1024 ** 2):
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, 'bounded JSON bytes required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError('Core3.1: invalid JSON document') from error


def relative(name):
    require(isinstance(name, str) and 0 < len(name.encode()) <= 2048
            and not any(char in name for char in '\\:\0\r\n'), 'unsafe relative name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in ('', '.', '..') for part in name.split('/')), 'noncanonical relative name: ' + name)
    return name


def ordinary_file(value):
    path = Path(value).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents))
            and path.is_file() and stat.S_ISREG(path.stat().st_mode), 'ordinary nonlinked file required')
    return path


def file_identity(value, maximum):
    require(type(maximum) is int and 0 < maximum <= 8 * 1024 ** 3, 'invalid explicit file bound')
    path = ordinary_file(value)
    before = path.stat()
    require(before.st_size <= maximum, 'file exceeds declared bound')
    digests = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    size = 0
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1024 ** 2), b''):
            size += len(raw)
            require(size <= maximum, 'growing file exceeds declared bound')
            for digest in digests.values():
                digest.update(raw)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns), 'input changed while reading')
    return dict(bytes=size, **{name: digest.hexdigest() for name, digest in digests.items()})


def read_bounded(value, maximum):
    """Bound allocation before reading and reject changed ordinary raw inputs."""
    require(type(maximum) is int and 0 < maximum <= 512 * 1024 ** 2, 'explicit bounded raw-input limit required')
    path = ordinary_file(value)
    before = path.stat()
    require(before.st_size <= maximum, 'raw input exceeds declared bound')
    with path.open('rb') as stream:
        raw = stream.read(min(maximum + 1, before.st_size + 1))
    require(len(raw) == before.st_size and len(raw) <= maximum, 'raw input grew or truncated while reading')
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns), 'raw input changed while reading')
    return raw


def limits(value):
    fields = {'archiveBytes', 'members', 'memberBytes', 'expandedBytes'}
    require(isinstance(value, dict) and set(value) == fields
            and all(type(value[key]) is int and value[key] > 0 for key in fields), 'explicit complete archive limits required')
    require(value['archiveBytes'] <= 8 * 1024 ** 3 and value['expandedBytes'] <= 16 * 1024 ** 3
            and value['memberBytes'] <= value['expandedBytes'] and value['members'] <= 2000000, 'archive limits exceed accounting scope')
    return value


def _member_name(name, directory):
    if directory and name in ('.', './'):
        return None
    return relative(name.removeprefix('./').rstrip('/') if directory else name.removeprefix('./'))


def _stream_record(stream, size):
    hashes = {key: hashlib.new(key) for key in ('sha256', 'sha512')}
    blob = hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
    count, prefix = 0, b''
    while raw := stream.read(min(1024 ** 2, size - count + 1)):
        count += len(raw)
        require(count <= size, 'archive member exceeds declared size')
        prefix = (prefix + raw[:4])[:4]
        for value in hashes.values():
            value.update(raw)
        blob.update(raw)
    require(count == size, 'truncated archive member')
    return dict(bytes=count, **{key: value.hexdigest() for key, value in hashes.items()}, gitBlob=blob.hexdigest(),
                format='elf' if prefix == b'\x7fELF' else 'pe' if prefix.startswith(b'MZ') else 'data')


class _InflatedLimit:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.count = stream, maximum, 0

    def read(self, size=-1):
        remaining = self.maximum - self.count
        raw = self.stream.read(min(size, remaining + 1) if size >= 0 else remaining + 1)
        self.count += len(raw)
        require(self.count <= self.maximum, 'gzip inflation exceeds declared bound')
        return raw


def archive_inventory(value, expected, bounds, *, archive_type='tar.gz'):
    """Authenticate and inventory plain bytes; never extract, load or execute members."""
    bounds = limits(bounds)
    identity(expected, nonempty=True)
    path = ordinary_file(value)
    require(file_identity(path, bounds['archiveBytes']) == expected, 'whole archive fingerprint differs')
    rows, seen, total, count, root_mode = [], set(), 0, 0, None
    if archive_type == 'tar.gz':
        with gzip.open(path, 'rb') as compressed:
            inflated = _InflatedLimit(compressed, bounds['expandedBytes'])
            archive = tarfile.open(fileobj=inflated, mode='r|', ignore_zeros=True)
            with archive:
                for member in archive:
                    count += 1
                    require(count <= bounds['members'], 'too many TAR members')
                    require(not {'path', 'linkpath'} & set(member.pax_headers), 'PAX path redirection rejected')
                    require(0 <= member.size <= bounds['memberBytes'], 'oversized TAR declaration')
                    name = _member_name(member.name, member.isdir())
                    if name is None:
                        require(root_mode is None and member.isdir() and member.size == 0, 'duplicate or invalid TAR root directory')
                        root_mode = member.mode
                        continue
                    require(name not in seen, 'duplicate or aliased archive member')
                    seen.add(name)
                    row = dict(path=name, mode=member.mode)
                    if member.isdir():
                        require(member.size == 0, 'directory with hidden payload')
                        row['type'] = 'directory'
                    elif member.issym():
                        require(member.size == 0, 'symbolic link with hidden payload')
                        require(isinstance(member.linkname, str) and len(member.linkname.encode()) <= 2048
                                and not any(c in member.linkname for c in '\\:\0\r\n')
                                and not member.linkname.startswith('/'), 'unsafe symbolic link')
                        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                        relative(resolved)
                        row.update(type='symlink', target=member.linkname)
                    else:
                        require(member.isfile(), 'nonregular TAR member')
                        total += member.size
                        require(total <= bounds['expandedBytes'], 'expanded TAR exceeds declared bound')
                        with archive.extractfile(member) as stream:
                            row.update(type='file', **_stream_record(stream, member.size))
                    rows.append(row)
    elif archive_type == 'zip':
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                count += 1
                require(count <= bounds['members'] and not member.flag_bits & 1, 'too many or encrypted ZIP members')
                name = _member_name(member.filename, member.is_dir())
                require(name is not None and name not in seen, 'duplicate, root or aliased ZIP member')
                seen.add(name)
                mode = member.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG), 'ZIP special member rejected')
                row = dict(path=name, mode=stat.S_IMODE(mode), type='directory' if member.is_dir() else 'file')
                if not member.is_dir():
                    require(0 <= member.file_size <= bounds['memberBytes'], 'oversized ZIP member')
                    total += member.file_size
                    require(total <= bounds['expandedBytes'], 'expanded ZIP exceeds declared bound')
                    with archive.open(member) as stream:
                        row.update(_stream_record(stream, member.file_size))
                rows.append(row)
    else:
        raise ValidationError('Core3.1: unsupported archive format')
    require(file_identity(path, bounds['archiveBytes']) == expected, 'archive changed during inventory')
    return dict(archive=dict(expected), archiveType=archive_type, rootDirectoryMode=root_mode,
                members=sorted(rows, key=lambda row: row['path']), expandedBytes=total)


def nuget_package(value, expected, expected_content_hash, bounds):
    """Whole signed ZIP identity and NuGet unsigned-content identity are separate."""
    inventory = archive_inventory(value, expected, bounds, archive_type='zip')
    require(expected['bytes'] <= 512 * 1024 ** 2, 'NuGet helper bound exceeded')
    from musl_nuget_content_hash import content_hash
    raw = read_bounded(value, expected['bytes'])
    require(fingerprint(raw) == expected, 'NuGet input changed before content-hash verification')
    require(isinstance(expected_content_hash, str) and content_hash(raw) == expected_content_hash,
            'actual NuGet contentHash differs from asset/cache binding')
    return dict(inventory, nugetContentHash=expected_content_hash)


def verify_git_history(commit, tree, commit_objects, claimed_count):
    """Verify reachable history size, which is NOT the original GitCommitCount property."""
    require(re.fullmatch('[a-f0-9]{40}', commit or '') and re.fullmatch('[a-f0-9]{40}', tree or ''), 'exact Git commit/tree required')
    require(isinstance(commit_objects, dict) and 0 < len(commit_objects) <= 1000000, 'bounded commit-object graph required')
    visited, pending = set(), [commit]
    while pending:
        oid = pending.pop()
        if oid in visited:
            continue
        require(oid in commit_objects, 'missing Git ancestor; shallow or incomplete provenance')
        raw = commit_objects[oid]
        require(isinstance(raw, bytes) and len(raw) <= 1024 ** 2, 'bounded raw Git commit object required')
        require(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid, 'Git object identity differs')
        header = raw.split(b'\n\n', 1)[0]
        trees = re.findall(rb'^tree ([a-f0-9]{40})$', header, re.M)
        require(len(trees) == 1, 'one original Git tree required')
        if oid == commit:
            require(trees[0].decode() == tree, 'source tree differs from original commit')
        parents = re.findall(rb'^parent ([a-f0-9]{40})$', header, re.M)
        require(len(parents) == len(set(parents)), 'duplicate Git parent')
        visited.add(oid)
        pending.extend(parent.decode() for parent in parents)
    require(set(commit_objects) == visited, 'unreachable Git objects in provenance record')
    require(type(claimed_count) is int and claimed_count == len(visited) and claimed_count > 0,
            'synthetic or incorrect Git commit count')
    return dict(commit=commit, tree=tree, reachableCommitCount=len(visited), completeReachableHistory=True,
                originalVersionTargetDerivationStillRequired=True)


def verify_version_count(commit, tree, commit_objects, target_bytes, contract, derivation):
    """Recompute an explicitly approved original-target count from real Git objects.

    The policy must separately authenticate that target's algorithm; this function
    never guesses the Core3.1 algorithm or treats history size as version height.
    A proven first-parent distance of zero at the original base is valid.
    """
    require(isinstance(contract, dict) and set(contract) == {'targetIdentity', 'algorithm', 'baseCommit', 'property'},
            'original version target/count contract is unresolved')
    require(identity(contract['targetIdentity'], nonempty=True) == fingerprint(target_bytes)
            and contract['property'] == 'GitCommitCount', 'original version target identity/property differs')
    require(contract['algorithm'] in {'first-parent-distance', 'reachable-history-size'}, 'unreviewed original count algorithm')
    require(isinstance(derivation, dict) and set(derivation) == {'commit', 'tree', 'targetIdentity', 'algorithm', 'baseCommit', 'property', 'value'},
            'complete original version count witness required')
    require(derivation['commit'] == commit and derivation['tree'] == tree
            and all(derivation[key] == contract[key] for key in contract), 'version witness and approved original target differ')
    require(type(derivation['value']) is int and derivation['value'] >= 0, 'invalid original version count')
    history = verify_git_history(commit, tree, commit_objects, len(commit_objects))
    if contract['algorithm'] == 'reachable-history-size':
        require(contract['baseCommit'] is None, 'history-size algorithm has no inferred version base')
        actual = history['reachableCommitCount']
    else:
        base = contract['baseCommit']
        require(isinstance(base, str) and re.fullmatch('[a-f0-9]{40}', base), 'authenticated original version base required')
        actual, current, visited = 0, commit, set()
        while current != base:
            require(current not in visited, 'cyclic first-parent history')
            visited.add(current)
            parents = re.findall(rb'^parent ([a-f0-9]{40})$', commit_objects[current].split(b'\n\n', 1)[0], re.M)
            require(parents, 'original version base is not a first-parent ancestor')
            current = parents[0].decode()
            actual += 1
        require(base in commit_objects, 'original version base omitted from complete history')
    require(derivation['value'] == actual, 'synthetic or incorrect GitCommitCount; no fallback is permitted')
    return dict(commit=commit, tree=tree, reachableCommitCount=history['reachableCommitCount'],
                gitCommitCount=actual, derivationIdentity=fingerprint(encoded(derivation)),
                originalTargetIdentity=dict(contract['targetIdentity']),
                originalAlgorithmDeclaredByPinnedContract=True, normalAdmissionAllowed=False)


def directory_inventory(root, expected, bounds):
    """Re-read an ordinary layout against its canonical manifest, without extraction.

    Windows cannot qualify original POSIX modes. Such snapshots stay accounting
    evidence, never a POSIX/native producer or source admission proof.
    """
    bounds = limits(bounds)
    root = Path(root).absolute()
    require(root.is_dir() and not any(path.is_symlink() for path in (root, *root.parents)), 'ordinary layout root required')
    before = root.stat()
    rows, total, observed = [], 0, 0
    def walk(parent, prefix, depth):
        nonlocal total, observed
        require(depth <= 128, 'layout directory depth exceeds bound')
        children = []
        with os.scandir(parent) as stream:
            for child in stream:
                observed += 1
                require(observed <= bounds['members'], 'layout observed entry count exceeds bound')
                children.append(child)
        children.sort(key=lambda entry: entry.name)
        for child in children:
            name = relative(prefix + child.name)
            require(len(rows) < bounds['members'], 'layout member count exceeds bound')
            info = child.stat(follow_symlinks=False)
            row = dict(path=name, mode=stat.S_IMODE(info.st_mode))
            if stat.S_ISDIR(info.st_mode):
                rows.append(dict(row, type='directory'))
                walk(Path(child.path), name + '/', depth + 1)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                require(total <= bounds['expandedBytes'] and info.st_size <= bounds['memberBytes'], 'layout bytes exceed bound')
                with Path(child.path).open('rb') as source:
                    record = _stream_record(source, info.st_size)
                after = child.stat(follow_symlinks=False)
                require((info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)
                        == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns), 'layout file changed while reading')
                rows.append(dict(row, type='file', **record))
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(child.path)
                require(isinstance(target, str) and len(target.encode()) <= 2048 and not target.startswith('/')
                        and not any(c in target for c in '\\:\0\r\n'), 'unsafe layout symbolic link')
                relative(posixpath.normpath(posixpath.join(posixpath.dirname(name), target)))
                rows.append(dict(row, type='symlink', target=target))
            else:
                require(False, 'special layout member rejected')
    walk(root, '', 0)
    after = root.stat()
    require((before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns), 'layout root changed while reading')
    manifest = dict(kind='core31-layout-inventory', rootDirectoryMode=stat.S_IMODE(before.st_mode),
                    members=sorted(rows, key=lambda row: row['path']), expandedBytes=total)
    require(identity(expected, nonempty=True) == fingerprint(encoded(manifest)), 'actual layout differs from stage manifest')
    return manifest


def verify_git_tree(tree, tree_objects, entries, submodules):
    """Bind plain source blobs, modes, symbolic links and Gitlinks to actual tree objects."""
    require(isinstance(tree_objects, dict) and isinstance(entries, dict) and isinstance(submodules, dict), 'explicit Git tree/blob/Gitlink witnesses required')
    seen, witnessed, used_trees = set(), set(), set()
    def visit(oid, prefix, depth):
        require(depth <= 128 and oid in tree_objects, 'missing or excessive Git tree witness')
        raw = tree_objects[oid]
        require(isinstance(raw, bytes) and len(raw) <= 16 * 1024 ** 2
                and hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid, 'Git tree object identity differs')
        used_trees.add(oid)
        position, names = 0, set()
        while position < len(raw):
            space, end = raw.find(b' ', position), raw.find(b'\0', position)
            require(position < space < end and end + 21 <= len(raw), 'malformed Git tree entry')
            try:
                mode = raw[position:space].decode('ascii')
                name = raw[space+1:end].decode('utf-8')
            except UnicodeError as error:
                raise ValidationError('Core3.1: invalid Git tree entry encoding') from error
            relative(name)
            require('/' not in name and name not in names, 'duplicate or nonlocal Git tree name')
            names.add(name)
            child, path = raw[end+1:end+21].hex(), prefix + name
            position = end + 21
            if mode in ('40000', '040000'):
                visit(child, path + '/', depth + 1)
            elif mode == '160000':
                require(path in submodules and isinstance(submodules[path], dict)
                        and submodules[path].get('commit') == child, 'missing or changed original submodule Gitlink')
                identity(submodules[path]['manifestIdentity'], nonempty=True)
                witnessed.add(path)
            else:
                require(mode in ('100644', '100755', '120000') and path in entries and path not in seen, 'source tree/member universe differs')
                row = entries[path]
                require(row['gitBlob'] == child and (row['type'] == 'symlink') == (mode == '120000')
                        and (mode == '120000' or bool(row['mode'] & 0o111) == (mode == '100755')), 'source Git blob/mode/link differs')
                seen.add(path)
    visit(tree, '', 0)
    require(seen == set(entries) and witnessed == set(submodules) and used_trees == set(tree_objects), 'extra or omitted source/Git tree/submodule witness')
    return dict(sourceEntries=len(seen), submoduleGitlinks=len(witnessed), treeObjects=len(used_trees))


def validate_policy(policy):
    require(isinstance(policy, dict) and type(policy.get('schemaVersion')) is int and policy['schemaVersion'] == 1
            and policy.get('kind') == 'core31-musl-construction-policy' and policy.get('sdkVersion') == SDK,
            'own Core3.1 policy required; another SDK cannot be relabeled')
    require(policy.get('status') == 'unregistered-incomplete-source-contract'
            and all(policy.get(key) is False for key in ('normalAdmissionEnabled', 'sourceAdmissionAllowed', 'releaseAdmissionAllowed')),
            'first-slice policy must remain unregistered and closed')
    architectures = policy.get('architectures')
    require(isinstance(architectures, dict) and set(architectures) == set(ARCHITECTURES)
            and policy.get('stageOrder') == list(STAGES), 'exact Core3.1 CPU/RID/stage universe required')
    for name, rid in ARCHITECTURES.items():
        row = architectures[name]
        require(isinstance(row, dict) and row.get('rid') == rid and row.get('nativeOnly') is True
                and row.get('normalProducerProven') is False and row.get('normalConsumerProven') is False,
                'unproved native architecture cannot be promoted')
    repositories, stages = policy.get('sourceRepositories'), policy.get('stages')
    require(isinstance(repositories, dict) and repositories and isinstance(stages, dict) and set(stages) == set(STAGES), 'closed source/stage registry required')
    for name, row in repositories.items():
        relative(name)
        require(isinstance(row, dict) and isinstance(row.get('repository'), str)
                and row['repository'].startswith('https://github.com/dotnet/')
                and re.fullmatch('[a-f0-9]{40}', row.get('commit', '')), 'exact source repository/commit required')
        require(row.get('tree') is None or re.fullmatch('[a-f0-9]{40}', row['tree']), 'invalid recorded tree')
        require(isinstance(row.get('unresolved'), list), 'missing source proof gaps must be explicit')
    previous = set()
    output_roles = set()
    for stage in STAGES:
        row = stages[stage]
        require(isinstance(row, dict) and isinstance(row.get('requiredParents'), list)
                and len(set(row['requiredParents'])) == len(row['requiredParents'])
                and set(row['requiredParents']) <= previous, 'invalid stage parent graph')
        require(isinstance(row.get('sourceRepositories'), list) and set(row['sourceRepositories']) <= set(repositories)
                and isinstance(row.get('outputRoles'), list) and len(row['outputRoles']) == len(set(row['outputRoles'])), 'invalid stage source/output roles')
        require(not output_roles & set(row['outputRoles']), 'duplicate output role across stages')
        output_roles.update(row['outputRoles'])
        available = {role for parent in row['requiredParents'] for role in stages[parent]['outputRoles']}
        require(isinstance(row.get('requiredInputRoles'), list) and len(row['requiredInputRoles']) == len(set(row['requiredInputRoles']))
                and set(row['requiredInputRoles']) <= available, 'required consumed roles must be actual direct-parent outputs')
        previous.add(stage)
    require(isinstance(policy.get('importCandidates'), dict) and isinstance(policy.get('requiredOwnBuiltRoles'), list)
            and isinstance(policy.get('unresolvedGates'), list) and policy['unresolvedGates'], 'incomplete construction/import gates must stay explicit')
    for name, row in policy['importCandidates'].items():
        relative(name)
        require(isinstance(row, dict) and row.get('allowed') is False and isinstance(row.get('unresolved'), list), 'candidate import is not an admission allowlist')
    return policy


def load_policy(path=None):
    path = ordinary_file(POLICY if path is None else path)
    return validate_policy(document(read_bounded(path, 64 * 1024), 64 * 1024))


def readiness(policy):
    validate_policy(policy)
    gaps = list(policy['unresolvedGates'])
    for name, row in policy['sourceRepositories'].items():
        gaps.extend(dict(scope='source:' + name, reason=value) for value in row['unresolved'])
    for name, row in policy['importCandidates'].items():
        gaps.extend(dict(scope='import:' + name, reason=value) for value in row['unresolved'])
    for name, row in policy['stages'].items():
        gaps.extend(dict(scope='stage:' + name, reason=value) for value in row.get('unresolved', []))
    for row in policy['requiredOwnBuiltRoles']:
        gaps.extend(dict(scope='own-role:' + row['id'], reason=value) for value in row.get('unresolved', []))
    for name, row in policy['bootstrap']['architectures'].items():
        gaps.extend(dict(scope='bootstrap:' + name, reason=value) for value in row.get('unresolved', []))
    gaps.extend(dict(scope='bootstrap', reason=value) for value in policy['bootstrap'].get('unresolved', []))
    gaps.extend(dict(scope='version-tooling-reference', reason=value)
                for value in policy['bootstrap']['separateNativeVersionToolingReference'].get('unresolved', []))
    return dict(status='unregistered-incomplete-Core3.1-contract', unresolved=gaps,
                normalAdmissionAllowed=False, sourceAdmissionAllowed=False, releaseAdmissionAllowed=False)


def verify_bootstrap_sdk_selection(policy, architecture, sdk_archive, materialized_files, bounds):
    """Account actual private SDK PE/data selection; native/bootstrap qualification stays open."""
    validate_policy(policy)
    require(architecture in ARCHITECTURES, 'unknown bootstrap CPU')
    specification = policy['bootstrap']['architectures'][architecture]
    require(specification.get('sdkArchive') is not None, 'exact per-CPU bootstrap archive remains unresolved')
    inventory = archive_inventory(sdk_archive, three_fields(specification['sdkArchive']), bounds)
    wanted = {row['path']: row for row in inventory['members'] if row['type'] == 'file'
              and row['format'] != 'elf' and row['path'].startswith(('sdk/', 'packs/', 'templates/'))}
    excluded = [row['path'] for row in inventory['members'] if row['type'] == 'file' and row['format'] == 'elf']
    require(wanted and isinstance(materialized_files, dict) and set(materialized_files) == set(wanted),
            'private bootstrap must carry exactly selected SDK PE/data; every SDK ELF is excluded')
    adaptation = policy['bootstrap']['privateRidAdaptation']
    property_path = 'sdk/' + policy['bootstrap']['sdkVersion'] + '/Microsoft.NETCoreSdk.BundledVersions.props'
    actual, adapted = {}, []
    for name, row in wanted.items():
        observed = file_identity(materialized_files[name], bounds['memberBytes'])
        original = three_fields(row)
        if name == property_path and observed != original:
            require(row['sha256'] == adaptation['originalSha256'] and observed['sha256'] == adaptation['adaptedSha256'], 'private RID adaptation differs')
            adapted.append(name)
        else:
            require(observed == original, 'private bootstrap member changed: ' + name)
        actual[name] = observed
    return dict(status='byte-accounted-private-bootstrap-SDK-selection-unqualified', architecture=architecture,
                sdkArchive=inventory['archive'], selectedMembers=actual, excludedEverySdkElf=excluded,
                explicitPrivateRidAdaptations=adapted, product=False,
                privateNativeRuntimeAndCompilerSourceLicenseProofQualified=False,
                bootstrapAdmissionAllowed=False, normalAdmissionAllowed=False)


def verify_preferred_source(policy, repository_id, source_archive, manifest_raw, commit_objects, tree_objects, bounds):
    """Verify an explicitly pinned complete source/member/license manifest, never infer one."""
    validate_policy(policy)
    require(repository_id in policy['sourceRepositories'], 'unregistered preferred source repository')
    specification = policy['sourceRepositories'][repository_id]
    pin = specification.get('preferredSourceManifestPin')
    license_pin = specification.get('licenseInventoryPin')
    require(pin is not None and license_pin is not None and specification.get('tree') is not None,
            'preferred-source/tree/license registry remains unresolved')
    require(identity(pin, nonempty=True) == fingerprint(manifest_raw), 'preferred-source manifest identity differs')
    manifest = document(manifest_raw)
    fields = {'schemaVersion', 'kind', 'repositoryId', 'repository', 'commit', 'tree', 'archive', 'archivePrefix', 'gitEntries',
              'licenses', 'submoduleProofs', 'generatedInputProofs', 'sharedInputProofs'}
    require(isinstance(manifest, dict) and set(manifest) == fields and type(manifest['schemaVersion']) is int
            and manifest['schemaVersion'] == 1 and manifest['kind'] == 'core31-preferred-source-manifest'
            and manifest['repositoryId'] == repository_id and manifest['repository'] == specification['repository']
            and manifest['commit'] == specification['commit'] and manifest['tree'] == specification['tree'], 'source manifest original repository/commit/tree differs')
    inventory = archive_inventory(source_archive, identity(manifest['archive'], nonempty=True), bounds)
    files = {row['path']: row for row in inventory['members'] if row['type'] == 'file'}
    require(isinstance(manifest['gitEntries'], dict) and set(manifest['gitEntries']) == set(files), 'complete source file/Git entry universe differs')
    for name, row in files.items():
        require(manifest['gitEntries'][name] == dict(mode=row['mode'], gitBlob=row['gitBlob'], **three_fields(row)), 'source bytes/mode/Git blob differs: ' + name)
    licenses = manifest['licenses']
    require(isinstance(licenses, dict) and licenses and identity(license_pin, nonempty=True) == fingerprint(encoded(licenses)), 'exact source license inventory differs')
    require(set(specification.get('knownLicensePaths', [])) <= set(licenses), 'known original source license omitted')
    for name, row in licenses.items():
        relative(name)
        require(name in files and identity(row) == three_fields(files[name]), 'original license/notices member differs')
    for key in ('submoduleProofs', 'generatedInputProofs', 'sharedInputProofs'):
        require(isinstance(manifest[key], dict), 'explicit submodule/generated/shared source proof map required')
        for name, value in manifest[key].items():
            relative(name)
            if key == 'submoduleProofs':
                require(isinstance(value, dict) and set(value) == {'commit', 'manifestIdentity'}
                        and re.fullmatch('[a-f0-9]{40}', value['commit']), 'exact submodule source identity required')
                identity(value['manifestIdentity'], nonempty=True)
            else:
                identity(value, nonempty=True)
    prefix = manifest['archivePrefix']
    require(isinstance(prefix, str), 'explicit original archive root required')
    if prefix:
        relative(prefix)
    tree_entries = {}
    for row in inventory['members']:
        if row['type'] == 'directory':
            continue
        name = row['path']
        require(not prefix or name.startswith(prefix + '/'), 'source member outside original archive root')
        name = name[len(prefix)+1:] if prefix else name
        relative(name)
        value = dict(row)
        if row['type'] == 'symlink':
            target = row['target'].encode()
            value['gitBlob'] = hashlib.sha1(b'blob ' + str(len(target)).encode() + b'\0' + target).hexdigest()
        tree_entries[name] = value
    tree_proof = verify_git_tree(manifest['tree'], tree_objects, tree_entries, manifest['submoduleProofs'])
    history = verify_git_history(manifest['commit'], manifest['tree'], commit_objects, len(commit_objects))
    return dict(status='byte-accounted-preferred-source-unqualified', repositoryId=repository_id,
                sourceArchive=inventory['archive'], manifestIdentity=fingerprint(manifest_raw),
                sourceFileCount=len(files), history=history, treeWitness=tree_proof,
                dependentSubmoduleGeneratedAndSharedProofsStillRequireIndependentValidation=True,
                originalVersionTargetDerivationStillRequired=True, sourceAdmissionAllowed=False)
