"""Retain one historical Globbing binary's preferred sources and real license.

The old VSTest package is comparison-only license evidence. It is never a
layout origin, an executable tool or a claimed locally compiled product.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'globbing-binary-source-inputs'
ROLE = 'original-globbing-source-and-publisher-license-inputs'
KIND = 'reviewed-legacy-globbing-source-chain'
COMMIT = '96bf83a6c1ab6f6801130150c27282c49030c8e1'
COMMON_COMMIT = 'fab8d45f6be307ae0b96b1860e516f8a7aa903b0'
VSTEST_COMMIT = '79d56b02b69a582cd90428878a5e9411ab7538f5'
PACKAGE_SHA = '16600b068e1ff2072da4691db7cba75bf8795a91ab3ea0fbd084e9b3ec232646'
PUBLISHER_SHA = '12a6be3700ac802727aa8a1308230e0cfa4a6cb59ac66c3a9423da4270d8a475'
PUBLISHER_URL = ('https://pkgs.dev.azure.com/dnceng/public/_packaging/test-tools/nuget/v3/flat2/'
    'microsoft.testplatform.cli/17.4.1-release-20230405-06/'
    'microsoft.testplatform.cli.17.4.1-release-20230405-06.nupkg')
MEMBER = 'lib/netstandard1.3/Microsoft.Extensions.FileSystemGlobbing.dll'
PUBLISHER_MEMBER = 'contentFiles/any/netcoreapp3.1/Microsoft.Extensions.FileSystemGlobbing.dll'
SOURCE_LICENSE = 'src/package/licenses/LICENSE_NET.txt'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n')
            and not PurePosixPath(value).is_absolute() and all(p not in ('', '.', '..') for p in value.split('/')),
            'An ordinary relative source member is required')
    return value


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'A redirected source input is forbidden')
    return path


def policy():
    result = json.loads(Path(__file__).with_name('musl-legacy-globbing-policy.json').read_bytes())
    require(result.get('schemaVersion') == 1 and result.get('sdkVersion') == '7.0.120'
            and result.get('kind') == 'legacy-globbing-binary-preferred-source-and-license-policy'
            and result['package']['sha256'] == PACKAGE_SHA and result['publisherPackage']['sha256'] == PUBLISHER_SHA
            and result['sources']['primary']['commit'] == COMMIT and result['sources']['shared']['commit'] == COMMON_COMMIT
            and result['sources']['vstest']['commit'] == VSTEST_COMMIT
            and [len(result['sources'][k]['files']) for k in ('primary', 'shared', 'vstest')] == [3, 3, 1]
            and result['allowedLayoutPaths'] == ['sdk/7.0.120/Microsoft.Extensions.FileSystemGlobbing.dll']
            and all(result.get(k) is False for k in ('localBuildClaimed', 'byteIdenticalCompilationClaimed', 'sharedSourcePackageArtifactRecovered')),
            'The closed historical Globbing input/source/license policy is required')
    return result


def pinned(path, identity):
    path = ordinary(path)
    require(path.is_file() and path.stat().st_size == identity['bytes'], 'An ordinary exact pinned Globbing input is required')
    raw = path.read_bytes()
    require(fingerprint(raw) == identity, 'Pinned Globbing input bytes differ')
    return raw


def fetch_publisher(destination):
    """Fetch only the immutable comparison input; never called by validation."""
    destination = ordinary(destination); identity = policy()['publisherPackage']
    if destination.exists(): pinned(destination, identity); return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(PUBLISHER_URL, timeout=90) as response:
        raw = response.read(identity['bytes'] + 1)
    require(fingerprint(raw) == identity, 'Original publisher license-reference download differs')
    with destination.open('xb') as stream: stream.write(raw)
    return destination


def metadata():
    spec = importlib.util.spec_from_file_location('globbing_literal_metadata', Path(__file__).with_name('musl_managed_metadata.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def origin():
    p = policy()
    return dict(schemaVersion=1, kind=KIND, primaryPackage=p['package'],
        publisherLicenseComparisonPackage=p['publisherPackage'], comparisonPackageUsedForLayout=False,
        comparisonPackageExecuted=False, principalSourceCommit=COMMIT,
        principalSourceBasis='actual-assembly-metadata-CommitHash-and-original-project',
        sharedSourceCommit=COMMON_COMMIT, sharedSourceBasis=p['sharedSourceBasis'], sharedSourcePackageVersion='1.1.1',
        sharedSourcePackageArtifactRecovered=False, sharedCommitNotClaimedAsEmbeddedBinaryIdentity=True,
        publisherLicenseMember='LICENSE_NET.txt', publisherBinaryMember=PUBLISHER_MEMBER,
        originalSourceLicenseCommit=VSTEST_COMMIT, originalSourceLicensePath=SOURCE_LICENSE,
        originalLicenseUrl=p['originalLicenseUrl'], requireLicenseAcceptance=True,
        sourceApacheLicenseNotSubstitutedForPublisherBinaryLicense=True,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False)


def origin_bytes():
    return (json.dumps(origin(), indent=2) + '\n').encode()


def inspect_package(package):
    p = policy(); pinned(package, p['package'])
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        require(len(names) < 1000 and len(names) == len(set(names)), 'Original Globbing ZIP member identities differ')
        specs = [name for name in names if name.endswith('.nuspec')]
        require(len(specs) == 1, 'One original Globbing nuspec is required')
        raw = archive.read(specs[0])
        require(fingerprint(raw) == p['nuspec'] and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
                'Original Globbing nuspec bytes differ')
        node = ET.fromstring(raw).find('{*}metadata')
        require(node.findtext('{*}id') == 'Microsoft.Extensions.FileSystemGlobbing'
                and node.findtext('{*}version') == '1.1.1' and node.find('{*}repository') is None
                and node.findtext('{*}licenseUrl') == p['originalLicenseUrl']
                and node.findtext('{*}requireLicenseAcceptance') == 'true', 'Original historical metadata/license declaration differs')
        binary = archive.read(MEMBER)
        require(fingerprint(binary) == p['binary'], 'Original exact Globbing managed member differs')
        identity = metadata().inspect(binary)
        attrs = identity['attributes'].get('System.Reflection.AssemblyMetadataAttribute', [])
        require(len(attrs) % 2 == 0 and [attrs[i + 1] for i in range(0, len(attrs), 2) if attrs[i] == 'CommitHash'] == [COMMIT]
                and identity['assemblyName'] == 'Microsoft.Extensions.FileSystemGlobbing'
                and identity['cliFlags'] & 1 and not identity['cliFlags'] & 16
                and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0,
                'Original Globbing assembly CommitHash or managed identity differs')
    return raw, binary


def data_bodies(package, publisher, source_license):
    p = policy(); nuspec, binary = inspect_package(package)
    package_raw = pinned(package, p['package']); publisher_raw = pinned(publisher, p['publisherPackage'])
    require(fingerprint(source_license) == p['sourceLicense'], 'Original VSTest source publisher-license text differs')
    with zipfile.ZipFile(publisher) as archive:
        require(archive.read(PUBLISHER_MEMBER) == binary, 'License comparison package does not contain the identical original binary')
        license_raw = archive.read('LICENSE_NET.txt')
        require(fingerprint(license_raw) == p['publisherLicense'], 'Actual publisher bundled license bytes differ')
    require(license_raw.decode('utf-8-sig').replace('\r\n', '\n') == source_license.decode('utf-8-sig').replace('\r\n', '\n'),
            'Publisher/source license texts must match after CRLF-only translation')
    return {'packages/' + PACKAGE_SHA + '.nupkg': package_raw,
        'publisher-license-comparison/' + PUBLISHER_SHA + '.nupkg': publisher_raw,
        'licenses/publisher-LICENSE_NET.txt': license_raw,
        'licenses/original-source-LICENSE_NET.txt': source_license,
        'original-globbing.nuspec': nuspec, 'origin.json': origin_bytes()}


def prepare(package, publisher, vstest_source, destination):
    """Retain actual binary, comparison-only publisher input and legal texts."""
    source, destination = ordinary(vstest_source), ordinary(destination)
    require(subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'],
                                   text=True).strip() == VSTEST_COMMIT, 'Original exact VSTest license source commit required')
    raw = (source / SOURCE_LICENSE).read_bytes()
    require(raw == subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source),
            'show', VSTEST_COMMIT + ':' + SOURCE_LICENSE]), 'The source license must retain its pristine original Git blob')
    bodies = data_bodies(package, publisher, raw)
    require(not destination.exists(), 'A fresh historical source/license data tree is required')
    destination.mkdir(parents=True)
    for name, raw in bodies.items():
        path = destination / portable(name); path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def check_source_chain(sources):
    primary = json.loads(sources['primary']['src/Microsoft.Extensions.FileSystemGlobbing/project.json'])
    shared = json.loads(sources['shared']['src/Microsoft.Extensions.HashCodeCombiner.Sources/project.json'])
    require(primary['version'] == '1.1.1' and primary['packOptions']['repository']['url'] == 'git://github.com/aspnet/filesystem'
            and primary['dependencies']['Microsoft.Extensions.HashCodeCombiner.Sources'] == {'version': '1.1.1', 'type': 'build'}
            and set(primary['frameworks']) == {'net45', 'netstandard1.3'}
            and shared['version'] == '1.1.1' and shared['shared'] == '*.cs' and set(shared['frameworks']) == {'netstandard1.0'},
            'Original principal/shared source-package version chain differs')
    require(b'HashCodeCombiner.Start()' in sources['primary']['src/Microsoft.Extensions.FileSystemGlobbing/FilePatternMatch.cs']
            and b'internal struct HashCodeCombiner' in sources['shared']['src/Microsoft.Extensions.HashCodeCombiner.Sources/HashCodeCombiner.cs']
            and all(b'Apache License, Version 2.0' in sources[k]['LICENSE.txt'] for k in ('primary', 'shared')),
            'Complete original preferred shared source and Apache source notices are required')


def validate(release, manifest, package):
    """Recheck full pinned source/archive/index/legal-data correspondence."""
    release = ordinary(release); p = policy(); inspect_package(package)
    roots, expected, source_names = {}, {}, {}
    for key, row in p['sources'].items():
        matches = [r for r in manifest['roots'] if r.get('commit') == row['commit'] and r['kind'] in ('git', 'git-export')]
        require(len(matches) == 1 and not matches[0].get('deleted'), 'Complete original Globbing/Common/VSTest source root required')
        roots[key] = matches[0]
        for name, identity in row['files'].items():
            full = portable(matches[0]['name']) + '/' + portable(name)
            expected[full] = {field: identity[field] for field in FP}; source_names[full] = (key, name, identity['gitBlob'])
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'License/comparison inputs may not claim Git provenance')
    data = {'packages/' + PACKAGE_SHA + '.nupkg': p['package'],
        'publisher-license-comparison/' + PUBLISHER_SHA + '.nupkg': p['publisherPackage'],
        'licenses/publisher-LICENSE_NET.txt': p['publisherLicense'],
        'licenses/original-source-LICENSE_NET.txt': p['sourceLicense'], 'original-globbing.nuspec': p['nuspec'],
        'origin.json': fingerprint(origin_bytes())}
    expected.update({ROOT_NAME + '/' + name: identity for name, identity in data.items()})
    index = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected or row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in index, 'Duplicate historical source/license index entry')
                index[row['path']] = row
    require(index.keys() == expected.keys() and all(all(index[name].get(k) == identity[k] for k in FP)
            for name, identity in expected.items()), 'Complete exact Globbing sources and raw legal data required in the source index')
    sources = {key: {} for key in roots}; actual, bodies = set(), {}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.isfile() and entry.size == expected[entry.name]['bytes'] and entry.size <= 16 * 1024**2
                    and entry.name not in actual, 'Ordinary exact bounded Globbing source/license archive member required')
            raw = archive.extractfile(entry).read()
            require(fingerprint(raw) == expected[entry.name], 'Archived historical source/license bytes differ')
            actual.add(entry.name)
            if entry.name in source_names:
                key, name, blob = source_names[entry.name]
                require(index[entry.name].get('baseline', {}).get('blob') == blob,
                        'Preferred source/license must retain the exact original pristine Git blob')
                sources[key][name] = raw
            else: bodies[entry.name[len(ROOT_NAME) + 1:]] = raw
    require(actual == expected.keys(), 'Archived original Globbing/source/license evidence is incomplete')
    check_source_chain(sources)
    # Recompute the two immutable ZIP relationships without loading any DLL.
    import io
    with zipfile.ZipFile(io.BytesIO(bodies['packages/' + PACKAGE_SHA + '.nupkg'])) as original, \
            zipfile.ZipFile(io.BytesIO(bodies['publisher-license-comparison/' + PUBLISHER_SHA + '.nupkg'])) as publisher:
        require(original.read(MEMBER) == publisher.read(PUBLISHER_MEMBER), 'Archived license comparison binary differs')
        require(publisher.read('LICENSE_NET.txt') == bodies['licenses/publisher-LICENSE_NET.txt'],
                'Archived publisher license did not come from its original pinned package')
    require(bodies['licenses/original-source-LICENSE_NET.txt'] == sources['vstest'][SOURCE_LICENSE]
            and bodies['licenses/publisher-LICENSE_NET.txt'].decode('utf-8-sig').replace('\r\n', '\n') ==
                sources['vstest'][SOURCE_LICENSE].decode('utf-8-sig').replace('\r\n', '\n'),
            'Archived license must preserve the original source and publisher texts')
    return dict(kind=KIND, basis='pinned-binary-CommitHash-and-version-declared-preferred-shared-source',
        sourceRoot=roots['primary']['name'], sourceCommit=COMMIT, sharedSourceRoot=roots['shared']['name'],
        sharedSourceCommit=COMMON_COMMIT, allowedLayoutPaths=p['allowedLayoutPaths'],
        products={name: p['binary'] for name in p['allowedLayoutPaths']}, publisherBinaryLicensePreserved=True,
        sourceApacheLicenseNotSubstitutedForPublisherBinaryLicense=True, localBuildClaimed=False,
        byteIdenticalCompilationClaimed=False)
