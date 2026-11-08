"""Review visible historical-reference warnings without exempting runtime code.

The exact NET8 source-build-assets projects generate API signatures. Their
historical package identities must remain intact. NuGet audit stays enabled;
only their known warnings cease being build errors. Both native run logs agreed
on the closed graph below. Unknown diagnostics and runtime stub placements fail.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

from downstream_release import ordinary_file, require

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'scripts/musl-reference-audit-policy.json'
POLICY_SHA256 = 'a225d95dc15db8025320de1736a8d6ee68683894375168cca63057a28a9780ba'
PREFIX = '/vmr/src/source-build-assets/artifacts/source-build/self/src/'
MARKER = b'source-build-reference-packages'
DIAGNOSTIC = re.compile(r'\b(?:warning|error)\s+NU190[0-9]\s*:', re.IGNORECASE)
ROW = re.compile(re.escape(PREFIX) + r'(?P<project>src/referencePackages/[^:\r\n]+\.csproj) : '
    r'(?P<level>warning|error) (?P<code>NU190[1-4]): Package \'(?P<packageId>[^\']+)\' '
    r'(?P<packageVersion>[^ ]+) has a known (?P<severity>low|moderate|high|critical) severity vulnerability, '
    r'(?P<advisory>https://github\.com/advisories/GHSA-[a-z0-9-]+)')


def policy():
    raw = ordinary_file(POLICY).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Reference audit policy bytes differ')
    return json.loads(raw)


def key(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':'))


def warning_graph(text):
    expected = {key(row) for row in policy()['records']}
    observed = {}
    for line in text.splitlines():
        if not DIAGNOSTIC.search(line):
            continue
        match = ROW.search(line)
        require(match is not None, 'Audit diagnostic escaped the reviewed reference-only directory')
        row = match.groupdict()
        require(row.pop('level') == 'warning', 'Reference audit error cannot be accepted as a warning')
        require(key(row) in expected, 'Unknown reference package/advisory/project audit disposition')
        observed[key(row)] = row
    require(set(observed) == expected, 'Incomplete actual historical-reference audit graph')
    return [observed[k] for k in sorted(observed)]


def member_name(value):
    value = value.removeprefix('./')
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and '..' not in path.parts
            and not any(c in value for c in ('\\', '\0', '\n', '\r')),
            'Unsafe SDK reference inventory path')
    return value


def is_reference_path(name, *, nested=False):
    parts = PurePosixPath(name).parts
    if nested:
        return len(parts) >= 3 and parts[0] == 'ref'
    packs = {'Microsoft.NETCore.App.Ref': ('8.0.33', 'net8.0'),
             'Microsoft.AspNetCore.App.Ref': ('8.0.33', 'net8.0'),
             'NETStandard.Library.Ref': ('2.1.0', 'netstandard2.1')}
    return (len(parts) >= 6 and parts[0] == 'packs' and parts[1] in packs
            and (parts[2], parts[4]) == packs[parts[1]] and parts[3] == 'ref'
            or len(parts) >= 4 and parts[:3] == ('sdk', '8.0.133', 'ref'))


def sdk_payloads(archive, resolved_links):
    """Read regular payloads and archive-internal link bytes without extraction.

    Original SDK8 runtime packs link back to shared-framework files. Inspect
    those bytes under every alias as well as the original path: a reference
    stub cannot become an implementation by passing through a link.
    """
    suffixes = ('.dll', '.nupkg', '.zip')

    def name(value):
        result = member_name(value.rstrip('/'))
        require(result == PurePosixPath(result).as_posix() and ':' not in result,
                'Noncanonical SDK reference inventory path')
        return result

    nodes = {}
    with tarfile.open(ordinary_file(archive), 'r:gz') as source:
        for member in source:
            if member.isdir() and member.name in ('.', './'): continue
            key = name(member.name)
            require(key not in nodes and len(nodes) < 100000, 'Duplicate or oversized SDK reference inventory')
            require(member.isdir() or member.isfile() or member.issym() or member.islnk(), 'Special SDK archive member is forbidden')
            nodes[key] = member

    def parents(key):
        for parent in PurePosixPath(key).parents:
            if parent.as_posix() == '.': continue
            require(parent.as_posix() not in nodes or nodes[parent.as_posix()].isdir(),
                    'SDK reference payload has a redirected archive parent')

    directories = {parent.as_posix() for key in nodes for parent in PurePosixPath(key).parents}
    directories.update(key for key, member in nodes.items() if member.isdir())

    def link_path(key, member):
        target = member.linkname
        require(target and not target.startswith('/') and not target.endswith('/')
                and not any(c in target for c in ('\\', ':', '\0', '\r', '\n')),
                'SDK reference payload link escapes the archive')
        parts = list(PurePosixPath(key).parent.parts) if member.issym() else []
        segments = target.split('/')
        for index, segment in enumerate(segments):
            if segment in ('', '.'): continue
            if segment == '..':
                require(parts, 'SDK reference payload link escapes the archive')
                parts.pop()
            else:
                parts.append(segment)
                if index < len(segments) - 1:
                    prefix = '/'.join(parts)
                    # A later '..' cannot cancel traversal through a symlink,
                    # ordinary file or absent directory on the real filesystem.
                    require(prefix in directories and (prefix not in nodes or nodes[prefix].isdir()),
                            'SDK reference link traverses a redirected or absent target parent')
        return name('/'.join(parts))

    def resolve(key):
        visited = set()
        for _ in range(32):
            require(key in nodes and key not in visited, 'Dangling or cyclic SDK reference payload link')
            visited.add(key); parents(key); member = nodes[key]
            if member.isfile(): return key
            require(member.issym() or member.islnk(), 'SDK reference link must resolve to a regular archive file')
            key = link_path(key, member)
        raise ValueError('SDK reference payload link depth exceeds its limit')

    aliases, targets = [], set()
    for key, member in nodes.items():
        if not key.lower().endswith(suffixes): continue
        parents(key)
        if member.isfile():
            require(member.size <= 512 * 1024**2, 'Oversized SDK reference inventory input')
        else:
            target = resolve(key)
            require(nodes[target].size <= 512 * 1024**2, 'Oversized linked SDK reference inventory input')
            aliases.append((key, target, member)); targets.add(target)
    require(sum(nodes[target].size for target in targets) <= 512 * 1024**2,
            'SDK reference link target cache exceeds its limit')
    cached = {}
    with tarfile.open(ordinary_file(archive), 'r|gz') as source:
        for member in source:
            if not member.isfile(): continue
            key = name(member.name)
            if key not in targets and not key.lower().endswith(suffixes): continue
            require(member.size <= 512 * 1024**2, 'Oversized SDK reference inventory input')
            raw = source.extractfile(member).read(member.size + 1)
            require(len(raw) == member.size, 'Truncated SDK reference inventory input')
            if key in targets: cached[key] = raw
            if key.lower().endswith(suffixes): yield key, raw
    require(cached.keys() == targets, 'An SDK reference link target was not read from the actual archive')
    for key, target, member in aliases:
        raw = cached[target]
        resolved_links.append(dict(path=key, type='symlink' if member.issym() else 'hardlink',
            linkTarget=member.linkname, resolvedTarget=target, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        yield key, raw


def sdk_reference_inventory(archive, *, resolved_links=None):
    result = []
    budget = dict(entries=0, bytes=0)

    def inspect(name, raw, allowed):
        if MARKER not in raw:
            return
        require(raw[:2] == b'MZ' and allowed,
                'Historical signature stub is placed outside a compilation-reference path: ' + name)
        result.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           disposition='compilation-reference-api-only'))

    def inspect_package(raw, prefix, depth):
        require(depth <= 4, 'Nested reference archive depth exceeds its limit')
        with zipfile.ZipFile(io.BytesIO(raw)) as package:
            members = package.infolist()
            budget['entries'] += len(members)
            require(budget['entries'] <= 100000, 'Oversized nested reference inventory')
            require(len({item.filename for item in members}) == len(members), 'Duplicate nested reference member')
            for item in members:
                inner = member_name(item.filename)
                if item.is_dir() or not inner.lower().endswith(('.dll', '.nupkg', '.zip')):
                    continue
                budget['bytes'] += item.file_size
                require(item.file_size <= 128 * 1024 * 1024 and budget['bytes'] <= 2 * 1024**3
                        and (item.external_attr >> 16) & 0o170000 != 0o120000,
                        'Redirected or oversized nested reference payload')
                name = prefix + '!/' + inner
                contents = package.read(item)
                if inner.lower().endswith('.dll'):
                    inspect(name, contents, is_reference_path(inner, nested=True))
                else:
                    inspect_package(contents, name, depth + 1)

    for name, raw in sdk_payloads(archive, resolved_links if resolved_links is not None else []):
        if name.lower().endswith('.dll'):
            inspect(name, raw, is_reference_path(name))
        else:
            inspect_package(raw, name, 1)
    return sorted(result, key=lambda row: row['path'])


def fingerprint(path):
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    with ordinary_file(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for digest in hashes.values():
                digest.update(block)
    return dict(bytes=path.stat().st_size, **{name: digest.hexdigest() for name, digest in hashes.items()})


def report(release, archive):
    log = release / 'reports/build/reference-audit.log'
    links = []
    references = sdk_reference_inventory(archive, resolved_links=links)
    return dict(schemaVersion=1, kind='reviewed-reference-only-audit-proof', status='passed', sdkVersion='8.0.133',
        policy=dict(path='scripts/musl-reference-audit-policy.json', sha256=POLICY_SHA256),
        sdk=dict(name=archive.name, **fingerprint(archive)), log=dict(path='reports/build/reference-audit.log', **fingerprint(log)),
        nuGetAuditEnabled=True, warningsRemainVisible=True, runtimeImplementationExceptionAllowed=False,
        warnings=warning_graph(ordinary_file(log).read_text()), referenceApiFiles=references, resolvedPayloadLinks=links)


def validate(release, archive):
    actual = json.loads(ordinary_file(release / 'reports/build/reference-audit.json').read_bytes())
    require(actual == report(release, archive), 'Reference audit proof differs from actual log and SDK archive')
    return actual
