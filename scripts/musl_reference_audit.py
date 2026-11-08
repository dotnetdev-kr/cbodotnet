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


def sdk_reference_inventory(archive):
    result = []
    seen = set()
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

    with tarfile.open(ordinary_file(archive), 'r|gz') as source:
        for member in source:
            if member.isdir() and member.name in ('.', './'):
                continue
            name = member_name(member.name)
            if not member.isfile():
                require(not name.lower().endswith(('.dll', '.nupkg', '.zip')), 'Linked reference payload is forbidden')
                continue
            require(name not in seen, 'Duplicate SDK file in reference inventory')
            seen.add(name)
            if not name.lower().endswith(('.dll', '.nupkg', '.zip')):
                continue
            require(member.size <= 512 * 1024 * 1024, 'Oversized SDK reference inventory input')
            raw = source.extractfile(member).read()
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
    return dict(schemaVersion=1, kind='reviewed-reference-only-audit-proof', status='passed', sdkVersion='8.0.133',
        policy=dict(path='scripts/musl-reference-audit-policy.json', sha256=POLICY_SHA256),
        sdk=dict(name=archive.name, **fingerprint(archive)), log=dict(path='reports/build/reference-audit.log', **fingerprint(log)),
        nuGetAuditEnabled=True, warningsRemainVisible=True, runtimeImplementationExceptionAllowed=False,
        warnings=warning_graph(ordinary_file(log).read_text()), referenceApiFiles=sdk_reference_inventory(archive))


def validate(release, archive):
    actual = json.loads(ordinary_file(release / 'reports/build/reference-audit.json').read_bytes())
    require(actual == report(release, archive), 'Reference audit proof differs from actual log and SDK archive')
    return actual
