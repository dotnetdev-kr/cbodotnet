#!/usr/bin/env python3
"""Derive a constrained .NET 8 1xx source-build adapter from immutable VMR data.

PSB digests observe HTTPS content at the exact source-declared versioned URL.
Independent jobs repeat new observations; these are not publisher signatures.
The existing baseline PSB additionally retains its independently qualified hash.
"""
import argparse
import datetime as dt
import functools
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

BASELINE_SDK = '8.0.133'
BASELINE_SOURCE = '7d1bf90885cff22e7da72b27e9848e42fd3cb1ae'
BASELINE_RUNTIME = '8.0.33'
BASELINE_COMPONENTS = {'runtime': 'da7a9beabf4cccc624399d583f52f080a4c858c2',
                       'aspnetcore': '380bd0d498fbaa0a8ddd67c325aa748dd21f7596'}
BASELINE_PSB = {
    'url': 'https://builds.dotnet.microsoft.com/source-built-artifacts/assets/Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz',
    'bytes': 728976053,
    'sha256': 'e39d2656832923af11d00a2bd32a10326ab84a0dfd20307a8491d8af3f9e720c',
    'sha512': '07164022578785da51138e1201973163579da27fbe6e99645257ac39dcf68a1532a3646005b20e098e6fee90c8cb47c4a1b82dbc58ec73b6ca2a991e3a12c83a',
}
MAX_ARCHIVE_BYTES = 4 * 1024**3
BUILD_SDK_NAMES = {'Microsoft.Build.CentralPackageVersions', 'Microsoft.Build.Traversal',
                   'Microsoft.NET.Sdk.IL', 'Microsoft.DotNet.Arcade.Sdk', 'Yarn.MSBuild'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stable(value, major=8):
    require(isinstance(value, str) and re.fullmatch(str(major) + r'\.0\.[0-9]+', value),
            'pending-bootstrap: an exact stable SDK or runtime version is required')
    return value


def global_inputs(data):
    """Admit versions of the existing named build SDKs, never new packages or URIs."""
    value = json.loads(data)
    require(set(value) == {'tools', 'msbuild-sdks'} and set(value['tools']) == {'dotnet'}
            and set(value['msbuild-sdks']) == BUILD_SDK_NAMES,
            'pending-bootstrap: bootstrap tools or allowed build SDK names changed')
    bootstrap = stable(value['tools']['dotnet'])
    for version in value['msbuild-sdks'].values():
        require(isinstance(version, str) and len(version) <= 128
                and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?', version),
                'pending-bootstrap: an allowed build SDK has an unsupported version declaration')
    require(value['msbuild-sdks']['Microsoft.DotNet.Arcade.Sdk'].startswith('8.'),
            'pending-bootstrap: the bootstrap Arcade SDK crossed its .NET major version')
    return bootstrap, value['msbuild-sdks']


def official_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname == 'builds.dotnet.microsoft.com'
            and not parsed.username and not parsed.password and not parsed.port
            and not parsed.query and not parsed.fragment,
            'pending-bootstrap: only an exact official HTTPS archive URL is admitted')
    return url


def request(url):
    require(url.startswith('https://raw.githubusercontent.com/dotnet/core/main/release-notes/'),
            'Only official release metadata is admitted')
    try:
        response = urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise ValueError('pending-bootstrap: official bootstrap SDK release metadata is not published yet') from error
        raise
    with response:
        data = response.read(32 * 1024**2 + 1)
    require(len(data) <= 32 * 1024**2, 'Oversized official release metadata')
    return data


@functools.lru_cache(maxsize=32)
def bootstrap_sdk_files(version):
    """Obtain both official SDK archive SHA-512 values without executing an SDK."""
    require(isinstance(version, str) and re.fullmatch(r'[0-9]+\.0\.[0-9]+', version),
            'pending-bootstrap: unsupported bootstrap SDK version')
    channel = '.'.join(version.split('.')[:2])
    document = json.loads(request('https://raw.githubusercontent.com/dotnet/core/main/release-notes/' + channel + '/releases.json'))
    result = {}
    for release in document['releases']:
        for sdk in [(release.get('sdk') or {}), *(release.get('sdks') or [])]:
            if sdk.get('version') != version:
                continue
            for row in sdk.get('files', []):
                arch = {'linux-arm64': 'arm64', 'linux-x64': 'x64'}.get(row.get('rid'))
                expected = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + version + '/dotnet-sdk-' + version + '-linux-' + str(arch) + '.tar.gz'
                if arch is None or not row.get('url', '').endswith('.tar.gz'):
                    continue
                require(row['url'] == expected and re.fullmatch('[a-fA-F0-9]{128}', row.get('hash', '')),
                        'pending-bootstrap: exact official bootstrap SDK URL/SHA-512 is unavailable')
                value = dict(url=expected, sha512=row['hash'].lower())
                require(arch not in result or result[arch] == value, 'Conflicting official bootstrap SDK metadata')
                result[arch] = value
    require(set(result) == {'arm64', 'x64'}, 'pending-bootstrap: both exact native bootstrap SDK archives must be published')
    return result


@functools.lru_cache(maxsize=32)
def _observe_archive(url):
    official_url(url)
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}; size = 0
    try:
        response = urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise ValueError('pending-bootstrap: the exact source-declared PSB archive is not published yet') from error
        raise
    with response:
        official_url(response.geturl())
        require(response.status == 200 and response.headers.get('Content-Range') is None,
                'pending-bootstrap: an unsolicited partial PSB response is forbidden')
        length = response.headers.get('Content-Length')
        require(length is None or (length.isdecimal() and 0 < int(length) <= MAX_ARCHIVE_BYTES),
                'pending-bootstrap: invalid or oversized official PSB Content-Length')
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS); expanded = 0; tail = b''
        for block in iter(lambda: response.read(1024 * 1024), b''):
            size += len(block)
            require(size <= MAX_ARCHIVE_BYTES, 'pending-bootstrap: the observed PSB archive exceeds its size limit')
            for value in hashes.values():
                value.update(block)
            pending = block
            while pending:
                try:
                    output = decoder.decompress(pending, 1024 * 1024)
                except zlib.error as error:
                    raise ValueError('pending-bootstrap: the observed PSB gzip stream is corrupt') from error
                expanded += len(output); tail = (tail + output)[-1024:]
                require(expanded <= 32 * 1024**3, 'pending-bootstrap: the observed PSB expansion exceeds its size limit')
                pending = decoder.unconsumed_tail
    require(size > 0 and (length is None or size == int(length)),
            'pending-bootstrap: the observed PSB archive is empty or truncated')
    require(decoder.eof and not decoder.unused_data and expanded >= 1024 and expanded % 512 == 0
            and tail == bytes(1024), 'pending-bootstrap: a complete gzip stream and tar end records are required')
    return dict(url=url, bytes=size, **{name: value.hexdigest() for name, value in hashes.items()})


def observe_archive(url, expected=None):
    """Observe once per process; an optional retained pin forbids content drift."""
    value = dict(_observe_archive(url))
    if url == BASELINE_PSB['url']:
        require(value == BASELINE_PSB, 'pending-bootstrap: official archive bytes changed at the retained versioned URL')
    if expected is not None:
        require(value == expected, 'pending-bootstrap: official archive bytes changed at the retained versioned URL')
    return value


def xml_values(data):
    require(b'<!DOCTYPE' not in data and b'<!ENTITY' not in data, 'Unsupported bootstrap declaration XML')
    root = ET.fromstring(data); values = {}
    for node in root.iter():
        name = node.tag.rsplit('}', 1)[-1]
        if name in ('PrivateSourceBuiltArtifactsUrl', 'PrivateSourceBuiltSdkUrl', 'PrivateSourceBuiltPrebuiltsUrl'):
            require(name not in values, 'Ambiguous original bootstrap declaration')
            values[name] = node.text or ''
    require(not values.get('PrivateSourceBuiltPrebuiltsUrl'), 'pending-bootstrap: additional prebuilt archive inputs require a qualified policy')
    return root, values


def manifest_values(sdk, commit, read):
    stable(sdk)
    require(100 <= int(sdk.split('.')[2]) < 200 and re.fullmatch('[a-f0-9]{40}', commit),
            'Only an exact .NET 8 1xx VMR source pin is admitted')
    bootstrap, build_sdks = global_inputs(read('global.json'))
    _, declarations = xml_values(read('eng/Versions.props'))
    url = official_url(declarations['PrivateSourceBuiltArtifactsUrl'])
    prefix = 'https://builds.dotnet.microsoft.com/source-built-artifacts/assets/Private.SourceBuilt.Artifacts.'
    match = re.fullmatch(re.escape(prefix) + r'(8\.0\.[0-9]+-servicing\.[0-9]+\.[0-9]+)\.centos\.9-x64\.tar\.gz', url)
    require(match and match[1].split('-')[0] == bootstrap, 'pending-bootstrap: unsupported or incoherent exact PSB version/RID')
    expected_sdk = 'https://builds.dotnet.microsoft.com/source-built-artifacts/sdks/dotnet-sdk-' + bootstrap + '-centos.9-x64.tar.gz'
    require(declarations.get('PrivateSourceBuiltSdkUrl') == expected_sdk,
            'pending-bootstrap: the source-built SDK declaration differs from the selected bootstrap')
    rows = json.loads(read('src/source-manifest.json'))['repositories']; components = {}; versions = {}
    for row in rows:
        if row.get('path') not in ('runtime', 'aspnetcore'):
            continue
        name = row['path']; pin = row.get('commitSha', '')
        require(name not in components and re.fullmatch('[a-f0-9]{40}', pin), 'Ambiguous or invalid component source revision')
        package = row.get('packageVersion', '')
        release = re.fullmatch(r'(8\.0\.[0-9]+)(?:-servicing\.[0-9]+\.[0-9]+)?', package)
        require(release, 'Unsupported component package version')
        components[name] = pin; versions[name] = release[1]
    require(set(components) == {'runtime', 'aspnetcore'} and len(set(versions.values())) == 1,
            'Runtime and ASP.NET component sources must identify the same stable runtime release')
    # Existing immutable URLs use their qualified retained fingerprints. New
    # URLs are observed independently by discovery and each generation job.
    psb = dict(BASELINE_PSB) if url == BASELINE_PSB['url'] else observe_archive(url)
    return dict(bootstrapSdk=bootstrap, sourceBuiltArtifacts=match[1], sourceBuiltArtifactsRid='centos.9-x64',
                runtime=versions['runtime'], components=components, psbArchive=psb,
                bootstrapSdkFiles=bootstrap_sdk_files(bootstrap), buildSdkVersions=build_sdks)


def compatibility(root, policy, candidate, helpers):
    adapter = policy['adapter']; old = adapter['baselineSource']; new = candidate['sourceCommit']
    unchanged = {}
    for path in adapter['requiredUnchangedFiles']:
        before = helpers.tree_entries(root, old, path); after = helpers.tree_entries(root, new, path)
        require(set(before) == set(after) == {path} and before[path] == after[path]
                and before[path]['mode'] in ('100644', '100755') and before[path]['type'] == 'blob',
                'pending-adapter: original compatibility input changed: ' + path)
        unchanged[path] = before[path]['blob']
    inventories = {}
    for path in adapter['requiredUnchangedRoots']:
        before = helpers.tree_entries(root, old, path); after = helpers.tree_entries(root, new, path)
        require(before and before == after, 'pending-adapter: original bootstrap, sysroot or test inventory changed: ' + path)
        inventories[path] = dict(files=len(before), sha256=helpers.digest(before))
    for commit in (old, new):
        global_inputs(helpers.git(root, 'show', commit + ':global.json'))
    require(set(adapter.get('allowedBuildSdkNames', BUILD_SDK_NAMES)) == BUILD_SDK_NAMES,
            'The allowed NET8 build SDK name policy changed')
    roots = []
    for commit in (old, new):
        tree, _ = xml_values(helpers.git(root, 'show', commit + ':eng/Versions.props'))
        for node in tree.iter():
            if node.tag.rsplit('}', 1)[-1] in ('PrivateSourceBuiltArtifactsUrl', 'PrivateSourceBuiltSdkUrl'):
                node.text = '<admitted-versioned-bootstrap-archive>'
        roots.append(ET.tostring(tree))
    require(roots[0] == roots[1], 'pending-bootstrap: unrelated source-build bootstrap declarations changed')
    inputs = candidate['upstreamInputs']
    require(inputs['runtime'] == candidate['runtimeVersion'], 'Published and source-declared runtime versions differ')
    return dict(unchangedFiles=unchanged, unchangedInventories=inventories,
                bootstrapSdk=inputs['bootstrapSdk'], psbArchive=inputs['psbArchive'],
                bootstrapTrust='Official SDK SHA-512 metadata; source-pinned PSB URI with retained or independently repeated HTTPS content digests, not a publisher signature.')


def transform(root, policy, candidate, helpers):
    adapter = policy['adapter']; inputs = candidate['upstreamInputs']; baseline = adapter['baselineSdk']
    profiles = sorted((root / 'profiles').glob('dotnet-' + baseline + '-linux-*.json'))
    require(len(profiles) == 2, 'Both baseline native profiles are required')
    original = helpers.load(profiles[0])
    require(original['source']['commit'] == adapter['baselineSource'], 'The NET8 adapter baseline differs')
    replacements = {baseline: candidate['sdkVersion'], adapter['baselineSource']: candidate['sourceCommit'],
                    original['upstreamInputs']['bootstrapSdk']: inputs['bootstrapSdk'],
                    original['upstreamInputs']['sourceBuiltArtifacts']: inputs['sourceBuiltArtifacts'],
                    BASELINE_RUNTIME: inputs['runtime'],
                    **{pin: inputs['components'][name] for name, pin in BASELINE_COMPONENTS.items()}}
    for name in adapter['generatedFiles']:
        path = root / name; data = path.read_text(encoding='utf-8')
        # Apply replacements once to original tokens, preventing cascades when
        # a new bootstrap SDK equals the previous product SDK version.
        pattern = re.compile('|'.join(re.escape(value) for value in sorted(replacements, key=len, reverse=True)))
        data = pattern.sub(lambda match: replacements[match[0]], data)
        if name == 'scripts/ci_vmr89_support.py':
            data = helpers.replace_exact(data, 'dotnetdev-kr/cbodotnet/.github/workflows/sdk-x64.yml@refs/heads/main', helpers.WORKFLOW, required=True)
            anchor = "        bootstrap = load(reports / 'prepare/bootstrap/bootstrap-inputs.json')\n"
            check = ("        expected_bootstrap = manifest['profile']['contents']['upstreamInputs']\n"
                     "        require(bootstrap['originalUrl'] == expected_bootstrap['psbArchive']['url']\n"
                     "                and all(bootstrap['originalArchive'][key] == expected_bootstrap['psbArchive'][key]\n"
                     "                        for key in ('bytes', 'sha256', 'sha512')), 'Actual original PSB differs from admitted immutable input')\n"
                     "        import upstream_vmr8 as bootstrap_evidence\n"
                     "        bootstrap_evidence.validate_bootstrap(release, manifest['profile']['contents'], arch, stages['prepare']['commands'])\n")
            require(data.count(anchor) == 1, 'The exact NET8 bootstrap evidence hook changed')
            data = data.replace(anchor, anchor + check, 1)
        if name == 'scripts/ci-vmr89.py':
            anchor = "            self.container(['bash', '/inputs/ci-tools/scripts/build-vmr8.sh',"
            hook = ("            self.container(['python3', '/delivery/reports/ci-inputs/project/scripts/upstream_vmr8.py', 'prepare-bootstrap',\n"
                    "                            '--profile', '/delivery/reports/ci-inputs/effective-profile.json', '--source-dir', '/vmr',\n"
                    "                            '--inputs-dir', '/inputs', '--arch', self.arch,\n"
                    "                            '--report', '/delivery/reports/prepare/bootstrap-sdk-input.json'])\n")
            require(data.count(anchor) == 1, 'The exact original NET8 preparation hook changed')
            data = data.replace(anchor, hook + anchor, 1)
            anchor = "                            '--reports-dir', '/delivery/reports/prepare/bootstrap', '--action', 'prepare'])\n"
            after = hook.replace("'prepare-bootstrap'", "'verify-bootstrap'")
            require(data.count(anchor) == 1, 'The exact original NET8 preparation completion hook changed')
            data = data.replace(anchor, anchor + after, 1)
        if name == 'scripts/watch-bootstrap8.py':
            declaration = '\nEXPECTED_ORIGINAL = ' + repr(inputs['psbArchive']) + '\n'
            require(data.count('\ndef main():') == 1, 'The original bootstrap watcher entry point changed')
            verifier = ("\ndef verify_generated_original(record):\n"
                        "    if (record['originalUrl'] != EXPECTED_ORIGINAL['url'] or\n"
                        "            any(record['originalArchive'][key] != EXPECTED_ORIGINAL[key]\n"
                        "                for key in ('bytes', 'sha256', 'sha512'))):\n"
                        "        raise ValueError('Original PSB bytes differ from admitted immutable source input')\n")
            data = data.replace('\ndef main():', declaration + verifier + '\ndef main():', 1)
            anchor = "        if args.arch != 'arm64':\n"
            require(data.count(anchor) == 1, 'The original bootstrap finalization hook changed')
            data = data.replace(anchor, '        verify_generated_original(record)\n' + anchor, 1)
            anchor = '        record = json.loads(marker.read_text())\n'
            require(data.count(anchor) == 1, 'The original bootstrap verification hook changed')
            data = data.replace(anchor, anchor + '        verify_generated_original(record)\n', 1)
        path.write_text(data, encoding='utf-8', newline='\n')
    for path in profiles:
        profile = helpers.load(path)
        profile.update(sdkVersion=candidate['sdkVersion'], selectedAt=candidate['releaseDate'])
        profile['source'].update(tag=candidate['sourceTag'], commit=candidate['sourceCommit'])
        profile['upstreamInputs'].update(inputs)
        profile['build']['sharedComponents'] = 'Both shared frameworks require current-run local producer, consumed archive and complete SDK byte-identity proof.'
        profile['construction']['note'] = 'An admitted candidate requires fresh original upstream tests, actual used sources and both native architecture qualifications. Bootstrap and package inputs remain external; no Stage 2 or zero-prebuilt claim.'
        if 'selection' in profile:
            profile['selection'].update(latestPublishedSdk=candidate['sdkVersion'], latestPublishedRuntime=inputs['runtime'],
                                        releaseDate=candidate['releaseDate'], reason='Exact published 1xx SDK VMR tag admitted by the constrained source-build adapter.')
        destination = path.with_name(path.name.replace(baseline, candidate['sdkVersion']))
        if destination != path:
            require(not destination.exists(), 'Generated NET8 profile already exists')
            path.unlink()
        destination.write_bytes(helpers.encode(profile))


def ordinary(path):
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'An ordinary absolute bootstrap path is required')
    return path


def fingerprint(path):
    ordinary(path); require(path.is_file(), 'A regular bootstrap evidence file is required')
    before = path.stat(); hashes = {key: hashlib.new(key) for key in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in hashes.values(): value.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Bootstrap evidence changed while hashing')
    return dict(bytes=after.st_size, **{key: value.hexdigest() for key, value in hashes.items()})


def record(path, root):
    return dict(path=path.relative_to(root).as_posix(), **fingerprint(path))


def member(root, name):
    require(isinstance(name, str), 'A relative bootstrap evidence path is required')
    value = PurePosixPath(name)
    require(value.parts and not value.is_absolute() and '..' not in value.parts and value.as_posix() == name
            and not any(character in name for character in '\\:\0\n\r'), 'Unsafe bootstrap evidence member')
    return ordinary(root.joinpath(*value.parts))


def sdk_identity(source, sdk, arch):
    host = ordinary(source / '.dotnet/dotnet'); dll = ordinary(source / '.dotnet/sdk' / sdk / 'dotnet.dll')
    with host.open('rb') as stream: header = stream.read(20)
    require(len(header) == 20 and header[:6] == b'\x7fELF\x02\x01'
            and int.from_bytes(header[18:20], 'little') == (183 if arch == 'arm64' else 62), 'The bootstrap host ELF architecture differs')
    versions = {path.name for path in (source / '.dotnet/sdk').iterdir()
                if path.is_dir() and re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', path.name)}
    require(versions == {sdk}, 'An unexpected bootstrap SDK version was installed')
    return dict(dotnetHost=record(host, source), sdkDll=record(dll, source))


def archive_identity(path, sdk, arch):
    expected = {'dotnet': 'dotnetHost', 'sdk/' + sdk + '/dotnet.dll': 'sdkDll'}; found = {}; versions = set()
    with tarfile.open(path, 'r|gz') as archive:
        for row in archive:
            name = row.name.removeprefix('./')
            parts = PurePosixPath(name).parts
            if len(parts) >= 2 and parts[0] == 'sdk' and re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', parts[1]):
                versions.add(parts[1])
            if name not in expected:
                continue
            require(row.isfile() and expected[name] not in found, 'Duplicate or nonregular bootstrap SDK identity member')
            hashes = {key: hashlib.new(key) for key in ('sha256', 'sha512')}; size = 0; header = b''
            with archive.extractfile(row) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    if size < 20: header += block[:20 - size]
                    size += len(block)
                    for value in hashes.values(): value.update(block)
            require(size == row.size, 'Truncated bootstrap SDK identity member')
            if name == 'dotnet':
                require(len(header) == 20 and header[:6] == b'\x7fELF\x02\x01'
                        and int.from_bytes(header[18:20], 'little') == (183 if arch == 'arm64' else 62),
                        'The retained bootstrap archive has another native architecture')
            found[expected[name]] = dict(path='.dotnet/' + name, bytes=size,
                                         **{key: value.hexdigest() for key, value in hashes.items()})
    require(set(found) == set(expected.values()) and versions == {sdk}, 'The retained bootstrap archive SDK identity differs')
    return found


def bootstrap_command(command, arch):
    return ['python3', '/delivery/reports/ci-inputs/project/scripts/upstream_vmr8.py', command,
            '--profile', '/delivery/reports/ci-inputs/effective-profile.json', '--source-dir', '/vmr',
            '--inputs-dir', '/inputs', '--arch', arch, '--report', '/delivery/reports/prepare/bootstrap-sdk-input.json']


def validate_bootstrap(release, profile, arch, commands):
    """Rehash retained official bytes and bind unchanged SDK identities to actual prep."""
    arch = 'arm64' if arch == 'aarch64' else arch
    require(arch in ('arm64', 'x64'), 'Unsupported bootstrap proof architecture')
    declared = profile['upstreamInputs']; sdk = stable(declared['bootstrapSdk']); pin = declared['bootstrapSdkFiles'][arch]
    receipt = json.loads(member(release, 'reports/prepare/bootstrap-sdk-input.json').read_text())
    require(receipt.get('schemaVersion') == 2 and receipt.get('status') == 'passed'
            and receipt['sdkVersion'] == sdk and receipt['targetRid'] == 'linux-' + arch
            and receipt['sourceCommit'] == profile['source']['commit'] and receipt['url'] == pin['url'],
            'Actual matching native bootstrap preparation proof is required')
    name = 'reports/prepare/bootstrap-sdk-inputs/dotnet-sdk-' + sdk + '-linux-' + arch + '.tar.gz'
    require(receipt['archive']['path'] == name, 'The complete official bootstrap archive must be retained')
    archive = member(release, name); actual = record(archive, release)
    require(actual == receipt['archive'] and actual['sha512'] == pin['sha512'],
            'The retained official bootstrap SDK archive differs from its observed or official metadata digest')
    identity = archive_identity(archive, sdk, arch)
    require(receipt['beforeOriginalPrep'] == receipt['afterOriginalPrep'] == identity,
            'The official bootstrap SDK host or SDK DLL was replaced during original prep')
    status_path = member(release, 'reports/prepare/bootstrap/prepare-status.json')
    status = json.loads(status_path.read_text())
    require(receipt['originalPrepStatus'] == record(status_path, release)
            and status.get('action') == 'prepare' and status.get('exitCode') == 0
            and status.get('sourceCommit') == profile['source']['commit']
            and status.get('sourceOnly') is True and status.get('targetRid') == 'linux-' + arch,
            'The unchanged SDK must bracket the actual successful original upstream preparation')
    log = member(release, 'reports/prepare/bootstrap/prepare.log')
    require(log.stat().st_size <= 128 * 1024**2, 'Oversized original bootstrap log')
    text = log.read_text(errors='replace')
    require('  ./.dotnet SDK directory exists...it will not be installed' in text
            and '  Building bootstrap previously source-built in ' in text,
            'Actual original prep must reuse the admitted SDK and run its normal PSB transformation')
    original = ['bash', '/inputs/ci-tools/scripts/build-vmr8.sh', '--arch', arch, '--source-dir', '/vmr',
                '--sysroot', '/inputs/' + arch + '-xenial', '--reports-dir', '/delivery/reports/prepare/bootstrap', '--action', 'prepare']
    positions = []
    for tail in (bootstrap_command('prepare-bootstrap', arch), original, bootstrap_command('verify-bootstrap', arch)):
        indices = [index for index, command in enumerate(commands) if command[-len(tail):] == tail]
        require(len(indices) == 1, 'Exactly one actual bootstrap preparation, original prep and completion invocation is required')
        positions.append(indices[0])
    require(positions == sorted(positions), 'Verified bootstrap SDK must be prepared before original prep and checked afterward')
    return receipt


def prepare_bootstrap(args):
    source = ordinary(args.source_dir); inputs = ordinary(args.inputs_dir); report = ordinary(args.report)
    profile = json.loads(ordinary(args.profile).read_text()); declarations = profile['upstreamInputs']
    arch = 'arm64' if args.arch == 'aarch64' else args.arch
    require(arch in ('arm64', 'x64') and profile['target']['rid'] == 'linux-' + arch, 'The explicit bootstrap architecture differs')
    sdk = stable(declarations['bootstrapSdk']); pin = declarations['bootstrapSdkFiles'][arch]
    require(pin['url'] == 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + sdk + '/dotnet-sdk-' + sdk + '-linux-' + arch + '.tar.gz'
            and re.fullmatch('[a-f0-9]{128}', pin['sha512']), 'Invalid exact official bootstrap SDK pin')
    delivery = report.parents[2]
    require(report.relative_to(delivery).as_posix() == 'reports/prepare/bootstrap-sdk-input.json',
            'Use the exact bootstrap report path under the delivery')
    destination = source / '.dotnet'; retained = report.parent / 'bootstrap-sdk-inputs'
    require(source.is_dir() and inputs.is_dir() and not destination.exists() and not report.exists()
            and not retained.exists(), 'Bootstrap preparation requires fresh inputs and SDK paths')
    retained.mkdir(parents=True); archive_path = retained / Path(pin['url']).name
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}; size = 0
    with urllib.request.urlopen(official_url(pin['url']), timeout=120) as response, archive_path.open('xb') as output:
        official_url(response.geturl())
        for block in iter(lambda: response.read(1024 * 1024), b''):
            size += len(block); require(size <= MAX_ARCHIVE_BYTES, 'The official bootstrap SDK archive exceeds its size limit')
            output.write(block)
            for value in hashes.values(): value.update(block)
    require(size > 0 and hashes['sha512'].hexdigest() == pin['sha512'], 'Official bootstrap SDK SHA-512 mismatch')
    require(hasattr(tarfile, 'data_filter'), 'Safe bootstrap extraction requires Python tarfile.data_filter')
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries = archive.getmembers(); seen = set(); total = 0
        for entry in entries:
            name = entry.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and entry.isdir(): continue
            value = PurePosixPath(name)
            require(name and not value.is_absolute() and '..' not in value.parts and '\\' not in name
                    and name not in seen and (entry.isdir() or entry.isfile() or entry.issym() or entry.islnk()),
                    'Unsafe or duplicate official bootstrap SDK archive member')
            seen.add(name); total += entry.size
        require(len(entries) <= 200000 and total <= MAX_ARCHIVE_BYTES
                and shutil.disk_usage(source).free >= total + 128 * 1024**2, 'Insufficient bounded bootstrap extraction capacity')
        destination.mkdir(mode=0o700)
        archive.extractall(destination, filter='data')
    identity = sdk_identity(source, sdk, arch)
    require(identity == archive_identity(archive_path, sdk, arch), 'The extracted bootstrap SDK differs from its official archive')
    receipt = dict(schemaVersion=2, status='prepared', sdkVersion=sdk, targetRid='linux-' + arch, url=pin['url'],
                   sourceCommit=profile['source']['commit'], preparedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(),
                   archive=record(archive_path, delivery), beforeOriginalPrep=identity,
                   scope='Retained official SDK archive and byte-identical native host/SDK DLL prepared before original prep. Successful actual original prep and a second unchanged identity observation are required before qualification.')
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open('x') as output: json.dump(receipt, output, indent=2); output.write('\n')


def verify_bootstrap(args):
    """Observe the same host and SDK DLL after the unmodified upstream prep exits."""
    source = ordinary(args.source_dir); report = ordinary(args.report); delivery = report.parents[2]
    profile = json.loads(ordinary(args.profile).read_text()); arch = 'arm64' if args.arch == 'aarch64' else args.arch
    require(report.relative_to(delivery).as_posix() == 'reports/prepare/bootstrap-sdk-input.json', 'Use the exact bootstrap completion report path')
    sdk = stable(profile['upstreamInputs']['bootstrapSdk']); pin = profile['upstreamInputs']['bootstrapSdkFiles'][arch]
    receipt = json.loads(report.read_text())
    require(receipt.get('schemaVersion') == 2 and receipt.get('status') == 'prepared'
            and receipt['sdkVersion'] == sdk and receipt['sourceCommit'] == profile['source']['commit']
            and receipt['targetRid'] == profile['target']['rid'] == 'linux-' + arch,
            'A matching newly prepared bootstrap SDK observation is required')
    archive = member(delivery, receipt['archive']['path'])
    require(record(archive, delivery) == receipt['archive'] and receipt['archive']['sha512'] == pin['sha512'],
            'The admitted bootstrap archive changed before original prep completed')
    identity = sdk_identity(source, sdk, arch)
    require(identity == receipt['beforeOriginalPrep'] == archive_identity(archive, sdk, arch),
            'The official bootstrap host or SDK DLL was replaced during original prep')
    status_path = member(delivery, 'reports/prepare/bootstrap/prepare-status.json'); status = json.loads(status_path.read_text())
    require(status.get('action') == 'prepare' and status.get('exitCode') == 0 and status.get('sourceOnly') is True
            and status.get('sourceCommit') == profile['source']['commit'] and status.get('targetRid') == 'linux-' + arch,
            'Actual successful original upstream preparation is required before the second SDK observation')
    receipt.update(status='passed', afterOriginalPrep=identity, originalPrepStatus=record(status_path, delivery),
                   verifiedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat())
    with report.open('w') as output: json.dump(receipt, output, indent=2); output.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare-bootstrap', 'verify-bootstrap'))
    for name in ('profile', 'source-dir', 'inputs-dir', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--arch', choices=('aarch64', 'arm64', 'x64'), required=True)
    args = parser.parse_args()
    (prepare_bootstrap if args.command == 'prepare-bootstrap' else verify_bootstrap)(args)


if __name__ == '__main__':
    main()
