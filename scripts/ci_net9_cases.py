#!/usr/bin/env python3
"""Bind NET9 package comparison cases to the pinned graph and real baseline cache."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
CACHE = 'artifacts/TestResults/Release/Microsoft.DotNet.UnifiedBuild.Tests/DownloadCache/NugetPackageBaselines'
CONFIG = 'artifacts/bin/Microsoft.DotNet.UnifiedBuild.Tests/Release/Microsoft.DotNet.UnifiedBuild.Tests.runtimeconfig.json'
PREFIX = 'Microsoft.DotNet.UnifiedBuild.Tests.'


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]), 'Ordinary package test input required: ' + str(path))
    return path


def fingerprint(path):
    ordinary(path); before = path.stat(); hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in hashes.values(): value.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Package test input changed while hashing')
    return dict(bytes=after.st_size, **{name: value.hexdigest() for name, value in hashes.items()})


def policy():
    value = json.loads((HERE / 'ci-net9-test-cases.json').read_text())
    require(value['sourceCommit'] == '9f04b57d1366e21b3178648493d6edffeff2216e' and value['sdkVersion'] == '9.0.123'
            and len(value['shippingPackageIds']) == len(set(value['shippingPackageIds'])) == 262
            and set(value['unavailableBaselineIds']) == {'Microsoft.DotNet.Common.ProjectTemplates.9.0', 'Microsoft.EntityFrameworkCore.Tasks'},
            'Unexpected trusted NET9 package case policy')
    return value


def available_ids():
    p = policy()
    return set(p['shippingPackageIds']) - set(p['unavailableBaselineIds'])


def common_cases(results):
    p = policy(); available = available_ids()
    expected = {(method, name) for method in p['packageMethods'] for name in available}
    found = set(); facts = set()
    for row in results:
        name = row.get('testName', '')
        if name in p['factMethods']:
            require(name not in facts, 'Duplicate NET9 SDK fact result'); facts.add(name); continue
        matches = [method for method in p['packageMethods'] if name.startswith(method + '(packageName: "')]
        require(len(matches) == 1, 'Unexpected NET9 common test identity')
        method = matches[0]
        argument = name[len(method + '(packageName: "'):].split(', testNugetPackagePath: ', 1)
        require(len(argument) == 2 and ', baselineNugetPackagePath: ' in argument[1] and name.endswith(')'), 'Malformed NET9 package theory arguments')
        display = argument[0]
        candidates = [package for package in available if display == (package[:50] + '"···' if len(package) > 50 else package + '"')]
        require(len(candidates) == 1, 'Unexpected or ambiguous NET9 package theory identity')
        identity = (method, candidates[0])
        require(identity not in found, 'Duplicate NET9 package theory result'); found.add(identity)
    require(found == expected and facts == set(p['factMethods']), 'Incomplete exact NET9 package theory pairs or SDK facts')
    return dict(packageIdentities=len(available), packageTheoryResults=len(found), sdkFacts=len(facts),
                unavailableBaselineIds=p['unavailableBaselineIds'])


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def before_test(source, release):
    cache = source / CACHE
    require(not cache.exists() and not cache.is_symlink(), 'NET9 package baseline cache must be absent before the fresh test invocation')
    write(release / 'reports/test/package-cases-before.json', dict(status='passed', cacheInitiallyAbsent=True, cachePath='/vmr/' + CACHE,
          observedAtUtc=datetime.datetime.now(datetime.timezone.utc).isoformat()))


def manifest_rows(path):
    raw = ordinary(path).read_bytes()
    require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'Unsupported package manifest XML')
    rows = [node.attrib for node in ET.fromstring(raw).findall('./Package') if node.get('DotNetReleaseShipping') == 'true']
    p = policy()
    require(len(rows) == 262 and len({row['Id'] for row in rows}) == 262
            and {row['Id'] for row in rows} == set(p['shippingPackageIds']), 'Actual NET9 shipping package universe differs')
    require(all(re.fullmatch(r'[A-Za-z0-9.+-]+', row['Version']) and row.get('RepoOrigin') for row in rows), 'Invalid shipping package identity')
    return sorted(rows, key=lambda row: row['Id'])


def capture(source, release):
    p = policy(); directory = release / 'reports/test/package-cases'
    require(not directory.exists(), 'Package case evidence must be new')
    rows = manifest_rows(source / 'artifacts/VerticalManifest.xml')
    config_path = ordinary(source / CONFIG)
    config = json.loads(config_path.read_text())['runtimeOptions']['configProperties']
    require(config[PREFIX + 'AssetManifestPath'] == '/vmr/artifacts/VerticalManifest.xml'
            and config[PREFIX + 'LogsDirectory'].rstrip('/') == '/vmr/artifacts/TestResults/Release', 'Original test manifest/cache runtime wiring differs')
    paths = config[PREFIX + 'Packages'].split(';')
    directory.mkdir(parents=True)
    shutil.copyfile(source / 'artifacts/VerticalManifest.xml', directory / 'VerticalManifest.xml')
    shutil.copyfile(config_path, directory / 'runtimeconfig.json')
    source_rows = []
    for row in p['sourceFiles']:
        original = ordinary(source / row['path']); actual = fingerprint(original)
        require(all(actual[key] == row[key] for key in actual), 'Pinned NET9 package test source changed')
        target = directory / 'source' / Path(row['path']).name; target.parent.mkdir(exist_ok=True); shutil.copyfile(original, target)
        source_rows.append(dict(path=row['path'], copy=target.relative_to(release).as_posix(), **actual, gitBlobSha1=row['gitBlobSha1']))
    cache_rows = []
    for row in rows:
        filename = row['Id'] + '.' + row['Version'] + '.nupkg'
        candidates = [name for name in paths if Path(name).name == filename and Path(name).parent.name not in ('fsharp', 'command-line-api')]
        require(len(candidates) == 1, 'Original runtime package list must contain each shipping package exactly once')
        baseline = ordinary(source / CACHE / filename); fp = fingerprint(baseline)
        unavailable = row['Id'] in p['unavailableBaselineIds']
        require((fp['bytes'] == 0) == unavailable, 'Unexpected NET9 baseline absence or newly available excluded baseline')
        if unavailable:
            shutil.copyfile(baseline, directory / filename)
        else:
            with zipfile.ZipFile(baseline) as package:
                nuspecs = [item for item in package.infolist() if item.filename.endswith('.nuspec')]
                require(len(nuspecs) == 1 and nuspecs[0].file_size < 4 * 1024**2, 'Available package baseline has no ordinary bounded identity')
                raw = package.read(nuspecs[0]); require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'Unsupported baseline identity XML')
                metadata = ET.fromstring(raw); namespace = metadata.tag.partition('}')[0] + '}' if '}' in metadata.tag else ''
                identity = metadata.find(namespace + 'metadata')
                require(identity is not None and identity.findtext(namespace + 'id') == row['Id'] and identity.findtext(namespace + 'version') == row['Version'], 'Available baseline NuGet identity differs')
        cache_rows.append(dict(id=row['Id'], version=row['Version'], repoOrigin=row['RepoOrigin'], available=not unavailable,
                               packagePath=candidates[0], baselinePath='/vmr/' + CACHE + '/' + filename, **fp))
    record = dict(schemaVersion=1, status='passed', sourceCommit=p['sourceCommit'], cacheRows=cache_rows, sourceFiles=source_rows,
                  capturedAtUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  scope='Actual original downloader cache after this fresh test. Only the two fixed zero-byte cache entries lack comparisons; no independent HTTP-status or package equivalence claim.')
    write(directory / 'coverage.json', record)
    return validate(release, require_retained_cache=False)


def validate(release, require_retained_cache=True):
    p = policy(); directory = release / 'reports/test/package-cases'
    coverage = json.loads(ordinary(directory / 'coverage.json').read_text())
    before = json.loads(ordinary(release / 'reports/test/package-cases-before.json').read_text())
    require(before['status'] == 'passed' and before['cacheInitiallyAbsent'] is True and before['cachePath'] == '/vmr/' + CACHE,
            'Actual initially absent NET9 baseline cache proof required')
    require(coverage['schemaVersion'] == 1 and coverage['status'] == 'passed' and coverage['sourceCommit'] == p['sourceCommit'], 'Actual NET9 package coverage receipt required')
    rows = manifest_rows(directory / 'VerticalManifest.xml')
    config = json.loads(ordinary(directory / 'runtimeconfig.json').read_text())['runtimeOptions']['configProperties']
    require(config[PREFIX + 'AssetManifestPath'] == '/vmr/artifacts/VerticalManifest.xml'
            and config[PREFIX + 'LogsDirectory'].rstrip('/') == '/vmr/artifacts/TestResults/Release', 'Captured original test runtime wiring differs')
    require(len(coverage['sourceFiles']) == len(p['sourceFiles']), 'Complete original package comparison sources required')
    for actual, expected in zip(coverage['sourceFiles'], p['sourceFiles']):
        require(actual['path'] == expected['path'] and actual['gitBlobSha1'] == expected['gitBlobSha1'], 'Package comparison source identity differs')
        values = fingerprint(ordinary(directory / 'source' / Path(expected['path']).name))
        require(all(values[key] == expected[key] == actual[key] for key in values), 'Pinned package comparison source bytes differ')
    cache = coverage['cacheRows']; require(len(cache) == 262 and len({row['id'] for row in cache}) == 262, 'Complete current baseline cache inventory required')
    by_id = {row['id']: row for row in cache}
    retained = release / 'reports/test/upstream-results/Microsoft.DotNet.UnifiedBuild.Tests/DownloadCache/NugetPackageBaselines'
    if require_retained_cache:
        expected = {row['id'] + '.' + row['version'] + '.nupkg' for row in cache}
        require(retained.is_dir() and {path.name for path in retained.iterdir()} == expected,
                'Complete original retained NET9 baseline cache membership differs')
    for row in rows:
        actual = by_id[row['Id']]; unavailable = row['Id'] in p['unavailableBaselineIds']
        filename = row['Id'] + '.' + row['Version'] + '.nupkg'
        require(actual['version'] == row['Version'] and actual['repoOrigin'] == row['RepoOrigin'] and actual['available'] is not unavailable
                and (actual['bytes'] == 0) == unavailable and re.fullmatch('[a-f0-9]{64}', actual['sha256'])
                and re.fullmatch('[a-f0-9]{128}', actual['sha512']) and actual['baselinePath'] == '/vmr/' + CACHE + '/' + filename,
                'Current package baseline identity/absence differs')
        matches = [name for name in config[PREFIX + 'Packages'].split(';') if Path(name).name == filename and Path(name).parent.name not in ('fsharp', 'command-line-api')]
        require(matches == [actual['packagePath']], 'Captured original package list differs')
        if unavailable:
            require(fingerprint(directory / filename) == {key: actual[key] for key in ('bytes', 'sha256', 'sha512')}, 'Actual empty baseline receipt differs')
        if require_retained_cache:
            require(fingerprint(retained / filename) == {key: actual[key] for key in ('bytes', 'sha256', 'sha512')},
                    'Actual retained package baseline bytes differ from current coverage')
    return dict(shippingPackages=262, availableBaselines=260, unavailableBaselineIds=p['unavailableBaselineIds'])
