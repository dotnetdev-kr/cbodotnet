"""SDK6 Globbing preferred sources and its actual consumer's license.

The binary keeps its real CommitHash. Common is explicitly version-matched
preferred source, without an invented embedded Common commit or compilation
claim. The genuine VSTest source package supplies the unchanged upstream
license; its compilation and actual consumption require the independent gate.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'sdk6-globbing-source-inputs'
ROLE = 'sdk6-globbing-preferred-source-and-consumed-license-inputs'
KIND = 'reviewed-sdk6-globbing-source-chain'
POLICY_SHA = 'b557b33b03562168100e1b655a3c854d5fd3d066e9ffb4751722576af71b306f'
COMMIT = '96bf83a6c1ab6f6801130150c27282c49030c8e1'
COMMON_COMMIT = 'fab8d45f6be307ae0b96b1860e516f8a7aa903b0'
VSTEST_COMMIT = 'cc7fb0593127e24f55ce016fb3ac85b5b2857fec'
PACKAGE_SHA = '16600b068e1ff2072da4691db7cba75bf8795a91ab3ea0fbd084e9b3ec232646'
SOURCE_LICENSE = 'src/package/licenses/LICENSE_NET.txt'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 Globbing source/data path required')
    return path


def portable(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n') and
            not PurePosixPath(value).is_absolute() and all(p not in ('', '.', '..') for p in value.split('/')),
            'Ordinary SDK6 Globbing source member required')
    return value


def policy():
    raw = Path(__file__).with_name('musl-legacy6-globbing-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK6 Globbing policy bytes differ')
    p = json.loads(raw)
    require(p['schemaVersion'] == 1 and p['sdkVersion'] == '6.0.136'
            and p['package']['sha256'] == PACKAGE_SHA
            and [p['sources'][k]['commit'] for k in ('primary', 'shared', 'vstest')] == [COMMIT, COMMON_COMMIT, VSTEST_COMMIT]
            and p['consumer']['version'] == '17.0.3-dev' and p['consumer']['sourceCommit'] == VSTEST_COMMIT
            and all(p[k] is False for k in ('localBuildClaimed', 'byteIdenticalCompilationClaimed',
                'originalCommonBinaryCommitClaimed', 'sourceApacheLicenseSubstitutedForBinaryLicense')),
            'Only the original SDK6 Globbing/source/license relationship is reviewed')
    return p


def metadata():
    spec = importlib.util.spec_from_file_location('sdk6_globbing_literal_metadata', Path(__file__).with_name('musl_managed_metadata.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def inspect_package(package):
    p = policy(); package = ordinary(package)
    require(package.is_file() and package.stat().st_size == p['package']['bytes'],
            'Exact original SDK6 Globbing package size required')
    raw = package.read_bytes()
    require(fingerprint(raw) == p['package'], 'Exact original SDK6 Globbing package required')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist(); specs = [n for n in names if n.endswith('.nuspec')]
        require(len(names) == len(set(names)) and len(specs) == 1, 'Unique original SDK6 Globbing ZIP/nuspec members required')
        spec = archive.read(specs[0]); binary = archive.read(p['member'])
    require(fingerprint(spec) == p['nuspec'] and b'<!DOCTYPE' not in spec.upper() and b'<!ENTITY' not in spec.upper()
            and fingerprint(binary) == p['binary'], 'Original SDK6 Globbing package metadata/member bytes differ')
    node = ET.fromstring(spec).find('{*}metadata')
    require(node.findtext('{*}id') == 'Microsoft.Extensions.FileSystemGlobbing' and node.findtext('{*}version') == '1.1.1'
            and node.find('{*}repository') is None and node.findtext('{*}licenseUrl') == p['originalLicenseUrl']
            and node.findtext('{*}requireLicenseAcceptance') == 'true', 'Original binary license/nuspec declaration differs')
    identity = metadata().inspect(binary); attrs = identity['attributes'].get('System.Reflection.AssemblyMetadataAttribute', [])
    require(len(attrs) % 2 == 0 and [attrs[i + 1] for i in range(0, len(attrs), 2) if attrs[i] == 'CommitHash'] == [COMMIT]
            and identity['assemblyName'] == 'Microsoft.Extensions.FileSystemGlobbing'
            and identity['cliFlags'] & 1 and not identity['cliFlags'] & 16
            and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0,
            'Actual SDK6 Globbing binary CommitHash/managed identity differs')
    return spec, binary


def inspect_consumer(raw, binary):
    p = policy(); require(len(raw) <= 32 * 1024**2, 'Bounded genuine SDK6 VSTest source package required')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist(); specs = [n for n in names if n.endswith('.nuspec')]
        require(len(names) == len(set(names)) and len(specs) == 1, 'Unique genuine consumer package members required')
        node = ET.fromstring(archive.read(specs[0])).find('{*}metadata'); repository = node.find('{*}repository')
        require(node.findtext('{*}id') == p['consumer']['id'] and node.findtext('{*}version') == p['consumer']['version']
                and repository is not None and repository.get('commit') == VSTEST_COMMIT,
                'Genuine original VSTest source package version/repository differs')
        require(archive.read(p['consumer']['binaryMember']) == binary, 'Actual consumer does not carry the identical original Globbing binary')
        license_raw = archive.read(p['consumer']['licenseMember'])
        require(fingerprint(license_raw) == p['sourceLicense'], 'Actual consumer original binary license bytes differ')
    return license_raw


def bodies(package_raw, consumer_raw, source_license):
    p = policy()
    with zipfile.ZipFile(io.BytesIO(package_raw)) as archive:
        spec = archive.read(next(n for n in archive.namelist() if n.endswith('.nuspec'))); binary = archive.read(p['member'])
    license_raw = inspect_consumer(consumer_raw, binary)
    require(fingerprint(source_license) == p['sourceLicense'] and license_raw == source_license,
            'Actual consumed license must equal the pristine original SDK6 VSTest Git source')
    origin = dict(schemaVersion=1, kind=KIND, policySha256=POLICY_SHA, primaryPackage=p['package'],
        consumerPackage=fingerprint(consumer_raw), consumerVersion='17.0.3-dev', consumerSourceCommit=VSTEST_COMMIT,
        consumerSourceBuildAndConsumptionRequireIndependentGate=True, licenseMember=p['consumer']['licenseMember'],
        preferredSourceCommit=COMMIT, preferredSharedSourceCommit=COMMON_COMMIT,
        originalCommonBinaryCommitClaimed=False, localGlobbingBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        sourceApacheLicenseSubstitutedForBinaryLicense=False)
    return {'packages/' + PACKAGE_SHA + '.nupkg': package_raw, 'consumer/vstest-source-package.nupkg': consumer_raw,
            'licenses/consumed-CLI-LICENSE_NET.txt': license_raw, 'licenses/original-source-LICENSE_NET.txt': source_license,
            'original-globbing.nuspec': spec, 'origin.json': (json.dumps(origin, indent=2) + '\n').encode()}


def prepare(package, consumer, vstest_source, destination):
    inspect_package(package); p = policy(); source = ordinary(vstest_source); destination = ordinary(destination)
    require(subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'],
            text=True).strip() == VSTEST_COMMIT, 'Exact original SDK6 VSTest license source required')
    license_raw = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source),
                                         'show', VSTEST_COMMIT + ':' + SOURCE_LICENSE])
    require((source / SOURCE_LICENSE).read_bytes() == license_raw, 'Original consumer license source was modified')
    data = bodies(ordinary(package).read_bytes(), ordinary(consumer).read_bytes(), license_raw)
    require(not destination.exists(), 'Fresh SDK6 Globbing source/data tree required')
    destination.mkdir(parents=True)
    for name, raw in data.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def source_chain(sources):
    primary = json.loads(sources['primary']['src/Microsoft.Extensions.FileSystemGlobbing/project.json'])
    shared = json.loads(sources['shared']['src/Microsoft.Extensions.HashCodeCombiner.Sources/project.json'])
    require(primary['version'] == shared['version'] == '1.1.1'
            and primary['packOptions']['repository']['url'] == 'git://github.com/aspnet/filesystem'
            and primary['dependencies']['Microsoft.Extensions.HashCodeCombiner.Sources'] == {'version': '1.1.1', 'type': 'build'}
            and set(primary['frameworks']) == {'net45', 'netstandard1.3'} and shared['shared'] == '*.cs'
            and set(shared['frameworks']) == {'netstandard1.0'}, 'Original versioned principal/shared source relationship differs')
    require(b'HashCodeCombiner.Start()' in sources['primary']['src/Microsoft.Extensions.FileSystemGlobbing/FilePatternMatch.cs']
            and b'internal struct HashCodeCombiner' in sources['shared']['src/Microsoft.Extensions.HashCodeCombiner.Sources/HashCodeCombiner.cs']
            and all(b'Apache License, Version 2.0' in sources[k]['LICENSE.txt'] for k in ('primary', 'shared')),
            'Complete original shared source and separate Apache source notices required')


def validate(release, manifest, package):
    import importlib.util
    spec = importlib.util.spec_from_file_location('sdk6_globbing_archive_primitives', Path(__file__).with_name('package-used-source.py'))
    packer = importlib.util.module_from_spec(spec); spec.loader.exec_module(packer)
    release = ordinary(release); p = policy(); inspect_package(package); roots = {}
    for key, expected in p['sources'].items():
        found = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and
                 r.get('commit') == expected['commit'] and r.get('tree') == expected['tree'] and not r.get('deleted')]
        require(len(found) == 1, 'Complete exact SDK6 Globbing/Common/VSTest Git root required: ' + key); roots[key] = found[0]
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'Consumed license data must keep its separate non-Git source role')
    prefixes = {r['name'] + '/': key for key, r in roots.items()}; indexed = {}; baselines = {key: {} for key in roots}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = portable(row['path'])
            selected = next(((prefix, key) for prefix, key in prefixes.items() if name.startswith(prefix)), None)
            if selected:
                prefix, key = selected; relative = name[len(prefix):]
                require(name not in indexed and row.get('baseline'), 'Unique original source baseline required')
                baselines[key][relative] = row['baseline']; indexed[name] = (key, relative, row)
            elif name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate source/license data index entry'); indexed[name] = (None, name[len(ROOT_NAME) + 1:], row)
    for key, baseline in baselines.items():
        for sub in roots[key].get('submodules', []): baseline[sub['path']] = dict(mode='160000', blob=sub['commit'])
        require(packer.baseline_tree(baseline) == p['sources'][key]['tree'], 'Full original SDK6 Globbing source tree differs')
    seen, data, sources = set(), {}, {key: {} for key in roots}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            key, name, expected = indexed[entry.name]
            require(entry.name not in seen and entry.isfile() and entry.size <= 32 * 1024**2,
                    'Unique ordinary bounded SDK6 Globbing source/data archive entry required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k: expected[k] for k in FP}, 'Archived source/license bytes differ')
            if key:
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                if key != 'vstest':
                    require(packer.pristine_blob(expected, blob, raw if name.lower().endswith(('.cmd', '.bat')) else None),
                            'Original SDK6 Globbing source differs from its pristine Git blob')
                if name in p['sources'][key]['files']:
                    anchor = p['sources'][key]['files'][name]
                    require(fingerprint(raw) == {k: anchor[k] for k in FP} and expected['baseline']['blob'] == anchor['gitBlob'],
                            'Original SDK6 source/project/license anchor differs'); sources[key][name] = raw
            else: data[name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and all(sources[k].keys() == p['sources'][k]['files'].keys() for k in roots),
            'Complete original source/license archive coverage required')
    source_chain(sources)
    require(set(data) == {'packages/' + PACKAGE_SHA + '.nupkg', 'consumer/vstest-source-package.nupkg',
        'licenses/consumed-CLI-LICENSE_NET.txt', 'licenses/original-source-LICENSE_NET.txt', 'original-globbing.nuspec', 'origin.json'},
        'Closed SDK6 Globbing source/data tree required')
    require(data['packages/' + PACKAGE_SHA + '.nupkg'] == ordinary(package).read_bytes(), 'Actual primary raw package differs from source-retained input')
    require(data == bodies(data['packages/' + PACKAGE_SHA + '.nupkg'], data['consumer/vstest-source-package.nupkg'],
                           sources['vstest'][SOURCE_LICENSE]), 'Consumed license and source data relationships differ')
    return dict(kind=KIND, basis='actual-CommitHash-and-versioned-preferred-shared-source', sourceRoot=roots['primary']['name'],
        sourceCommit=COMMIT, sharedSourceRoot=roots['shared']['name'], sharedSourceCommit=COMMON_COMMIT,
        licenseSourceRoot=roots['vstest']['name'], licenseSourceCommit=VSTEST_COMMIT, dataRoot=ROOT_NAME,
        consumerPackageFingerprint=fingerprint(data['consumer/vstest-source-package.nupkg']),
        consumerSourceBuildAndConsumptionRequireIndependentGate=True, usedVstestSourceRequiresIndependentCompilerGate=True,
        allowedLayoutPaths=p['allowedLayoutPaths'],
        products={name: p['binary'] for name in p['allowedLayoutPaths']}, actualConsumerBinaryLicensePreserved=True,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False, originalCommonBinaryCommitClaimed=False)
