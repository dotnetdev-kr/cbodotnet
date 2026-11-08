"""SDK5's direct canonical framework copy and complete corresponding inputs.

The original SDK5 graph copies the targeting package itself. Its byte origin
is distinct from SDK7's published Build.Extensions package. Shared decoders
only inspect metadata and original IL; SDK7 package policies are never used.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'sdk5-framework-corresponding-inputs'
ROLE = 'sdk5-direct-canonical-framework-source-inputs'
KIND = 'sdk5-direct-canonical-framework-correspondence'
SDK_COMMIT = '3fdf76c35026e311b7edc245d4b3d9e812fe532e'
ASSETS_COMMIT = 'eccb0828682858d8daa029ba29adce07fd70d9a7'
PACKAGE_SHA = '218dd4c63d3f800de697bca41178827a52df0a9ec7a9b47520327d91ebc7051c'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(name):
    require(isinstance(name, str) and name and not any(c in name for c in '\\\0\r\n')
            and not PurePosixPath(name).is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
            'An ordinary relative SDK5 framework input path is required')
    return name


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Redirected SDK5 framework source is forbidden')
    return path


def module(name):
    spec = importlib.util.spec_from_file_location('sdk5_framework_' + name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def policy():
    p = json.loads(Path(__file__).with_name('musl-legacy5-framework-policy.json').read_bytes())
    require(p.get('schemaVersion') == 1 and p.get('kind') == 'sdk5-direct-canonical-framework-source-policy'
            and p.get('sdkVersion') == '5.0.214' and p.get('sdkSourceCommit') == SDK_COMMIT
            and p['package']['fingerprint']['sha256'] == PACKAGE_SHA
            and p['package']['id'] == 'NETStandard.Library.NETFramework' and p.get('sdk6PublisherPackageUsed') is False
            and p['package']['version'] == '2.0.1-servicing-26011-01'
            and p['preferredSource']['commit'] == ASSETS_COMMIT
            and p['preferredSource']['tree'] == 'cb4ed080b55039760f9b7fce7410be0d63ed2fe0'
            and len(p['preferredSource']['files']) == 137 and len(p['sdkSourceFiles']) == 3
            and len(p['layout']) == len({row['path'] for row in p['layout']}) == 114
            and p['totals'] == dict(layoutFiles=114, literalForwarders=87, realImplementations=27,
                methodBodies=5289, resourceBlobs=22, resourceStrings=1410)
            and all(p.get(k) is False for k in ('originalCSharpSourceRecovered', 'localBuildClaimed',
                'byteIdenticalCompilationClaimed', 'sdk7PublisherPackageUsed')),
            'The distinct closed SDK5 canonical framework policy is required')
    return p


def source_chain(sources, sdk):
    p = policy()
    for actual, declared in ((sources, p['preferredSource']['files']),
                              (sdk, {row['path']: row for row in p['sdkSourceFiles']})):
        require(actual.keys() == declared.keys(), 'Complete SDK5 preferred source and copy recipe are required')
        for name, row in declared.items():
            raw = actual[name]
            require(all(fingerprint(raw)[key] == row[key] for key in FP)
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['gitBlob'],
                    'SDK5 framework source differs from its exact original Git blob')
    versions = ET.fromstring(sdk['eng/Versions.props'])
    require([node.text for node in versions.iter() if node.tag.rsplit('}', 1)[-1] == 'NETStandardLibraryNETFrameworkVersion']
            == [p['package']['version']], 'Original SDK5 canonical package version differs')


def package_bodies(package, sources, sdk):
    """Derive every literal declaration and original implementation resource."""
    p = policy()
    source_chain(sources, sdk)
    path = ordinary(package)
    require(path.is_file() and path.stat().st_size == p['package']['fingerprint']['bytes'],
            'Exact original SDK5 targeting package is required')
    raw = path.read_bytes()
    require(fingerprint(raw) == p['package']['fingerprint'], 'Canonical SDK5 targeting package bytes differ')
    F = module('musl_legacy_facade_inputs')
    I = module('musl_legacy_framework_il_inputs')
    bodies = {'packages/' + PACKAGE_SHA + '.nupkg': raw, 'policy.json': json_bytes(p),
        'origin.json': json_bytes(dict(kind=KIND, package=p['package'], sdkSourceCommit=SDK_COMMIT,
            preferredSourceCommit=ASSETS_COMMIT, directCanonicalPackageCopy=True,
            originalCSharpSourceRecovered=False, localBuildClaimed=False, byteIdenticalCompilationClaimed=False))}
    for row in p['sdkSourceFiles']:
        bodies['original-sdk-recipe/' + row['path']] = sdk[row['path']]
    products, kinds = {}, {}
    counts = dict(layoutFiles=0, literalForwarders=0, realImplementations=0, methodBodies=0,
        resourceBlobs=0, resourceStrings=0)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) < 1000 and len({entry.filename for entry in entries}) == len(entries)
                and all(entry.file_size < 16 * 1024**2 and entry.external_attr >> 16 & 0o170000 != 0o120000 for entry in entries),
                'Only ordinary bounded SDK5 canonical package members are admitted')
        require({name for name in archive.namelist() if name.startswith('build/') and name.endswith('.dll')}
                == {row['packageMember'] for row in p['layout']}, 'Complete 114-member canonical SDK5 set is required')
        for row in p['layout']:
            binary = archive.read(portable(row['packageMember']))
            require(fingerprint(binary) == row['fingerprint'], 'An exact SDK5 canonical framework product is required')
            sha = row['fingerprint']['sha256']
            if row['kind'] == 'derived-readable-type-forwarder-source-inputs':
                declaration = F.inspect(binary)
                require(len(declaration['exportedTypes']) == row['exportedTypes'], 'SDK5 literal type-forwarding declarations differ')
                bodies['literal-products/' + sha + '.dll'] = binary
                bodies['metadata/' + sha + '.bin'] = bytes.fromhex(declaration['metadataBytes'])
                bodies['readable/' + sha + '.json'] = json_bytes(declaration)
                bodies['declarations/' + sha + '.il'] = declaration['readableIL'].encode()
                counts['literalForwarders'] += 1
            else:
                require(row['kind'] == 'upstream-full-il-and-original-resource-inputs', 'Unreviewed SDK5 framework source kind')
                il = sources[portable(row['ilSourcePath'])]
                proof = I.correspondence(binary, il)
                require(proof['mvid'] == row['mvid'] and len(proof['methodBodies']) == row['methodBodies']
                        and proof['noRvaMethods'] == row['noRvaMethods'], 'SDK5 original implementation identity or method set differs')
                resources, directives, il_directives = [], [], []
                for number, resource in enumerate(proof.pop('resources')):
                    resources.append(dict(name=resource['name'], flags=resource['flags'], bytes=len(resource['raw']),
                        sha256=hashlib.sha256(resource['raw']).hexdigest(), kind=resource['readable']['kind']))
                    stem = 'resources/' + sha + '/' + f'{number:02d}'
                    bodies[stem + '.bin'] = resource['raw']
                    bodies[stem + '.json'] = json_bytes(resource['readable'])
                    if resource['readable']['kind'] == 'xml':
                        bodies[stem + '.xml'] = resource['raw']
                    directives.append(dict(manifestName=resource['name'], flags=resource['flags'],
                        rawInput=stem + '.bin', readableInput=stem + '.json', originalResourceOffset=resource['offset']))
                    # Resource names are exact pinned metadata from the canonical package.
                    il_directives.append('.mresource ' + ('public' if resource['flags'] == 1 else 'private')
                        + " '" + resource['name'] + "' as '" + stem + ".bin' {}")
                    counts['resourceStrings'] += len(resource['readable'].get('values', {}))
                require(resources == row['resources'], 'Complete original SDK5 resource source is required')
                proof.update(resources=directives, preferredILSource=row['ilSourcePath'])
                bodies['correspondence/' + sha + '.json'] = json_bytes(proof)
                reconstructed, adjustments = I.reconstruction_il(binary, il, il_directives)
                bodies['reconstruction/' + sha + '.il'] = reconstructed
                bodies['reconstruction/' + sha + '.json'] = json_bytes(adjustments)
                counts['realImplementations'] += 1
                counts['methodBodies'] += len(proof['methodBodies'])
                counts['resourceBlobs'] += len(resources)
            name = 'sdk/5.0.214/' + portable(row['path'])
            products[name] = row['fingerprint']
            kinds[name] = row['kind']
            counts['layoutFiles'] += 1
        for name in archive.namelist():
            if name.lower().endswith(('.nuspec', 'license.txt', 'third-party-notices.txt', '.props', '.targets')):
                bodies['original-package-metadata/' + portable(name)] = archive.read(name)
    require(counts == p['totals'], 'Complete original SDK5 framework source totals differ')
    bodies['correspondence-summary.json'] = json_bytes(counts)
    return bodies, products, kinds


def prepare(package, sdk_source, assets_source, destination):
    p = policy()
    sources = {name: ordinary(Path(assets_source) / portable(name)).read_bytes() for name in p['preferredSource']['files']}
    sdk = {row['path']: ordinary(Path(sdk_source) / portable(row['path'])).read_bytes() for row in p['sdkSourceFiles']}
    bodies, products, kinds = package_bodies(package, sources, sdk)
    destination = ordinary(destination)
    require(not destination.exists(), 'Fresh SDK5 framework corresponding input directory required')
    destination.mkdir(parents=True)
    for name, raw in bodies.items():
        target = destination / portable(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', role=ROLE, path=str(destination),
        products=products, productKinds=kinds, sourceAdmissionAllowed=False)


def validate(release, manifest, package):
    """Recompute all derived data from exact original archived Git inputs."""
    p = policy()
    release = ordinary(release)
    expected, git_paths, names = {}, {}, {}
    for key, commit, files in [('assets', ASSETS_COMMIT, p['preferredSource']['files']),
                              ('sdk', SDK_COMMIT, {r['path']: r for r in p['sdkSourceFiles']})]:
        roots = [r for r in manifest['roots'] if r.get('commit') == commit and r['kind'] in ('git', 'git-export')]
        require(len(roots) == 1 and not roots[0].get('deleted'), 'Complete original SDK5 recipe and preferred-source Git roots required')
        names[key] = portable(roots[0]['name'])
        if key == 'assets':
            require(roots[0].get('tree') == p['preferredSource']['tree'], 'Preferred-source complete Git tree differs')
        for name, row in files.items():
            path = names[key] + '/' + portable(name)
            expected[path] = {k: row[k] for k in FP}
            git_paths[path] = (key, name, row['gitBlob'])
    roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0].get('role') == ROLE
            and roots[0].get('commit') is None, 'SDK5 corresponding declarations require a distinct data-only root')
    index = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected or row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in index, 'Duplicate SDK5 framework corresponding-source entry')
                index[row['path']] = row
    require(expected.keys() <= index.keys() and all(all(index[name].get(k) == row[k] for k in FP) for name, row in expected.items()),
            'All original SDK5 recipe, license and preferred IL inputs must be indexed')
    found, sources, sdk, data = set(), {}, {}, {}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in index:
                continue
            require(entry.isfile() and entry.name not in found and entry.size == index[entry.name]['bytes']
                    and entry.size <= 16 * 1024**2, 'Ordinary bounded SDK5 framework corresponding source required')
            raw = archive.extractfile(entry).read()
            require(all(index[entry.name].get(k) == fingerprint(raw)[k] for k in FP), 'Archived SDK5 framework source bytes differ')
            found.add(entry.name)
            if entry.name in git_paths:
                key, name, blob = git_paths[entry.name]
                require(index[entry.name].get('baseline', {}).get('blob') == blob
                        and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob,
                        'Original SDK5 framework source Git blob differs')
                (sources if key == 'assets' else sdk)[name] = raw
            else:
                data[entry.name[len(ROOT_NAME) + 1:]] = raw
    require(found == index.keys(), 'Complete archived SDK5 framework source required')
    bodies, products, kinds = package_bodies(package, sources, sdk)
    require(data == bodies, 'All SDK5 declarations, preferred source complements and original resources must match')
    return dict(kind=KIND, sourceRoot=names['assets'], sourceCommit=ASSETS_COMMIT, dataRoot=ROOT_NAME,
        sdkSourceRoot=names['sdk'], sdkSourceCommit=SDK_COMMIT, canonicalPackage=p['package'],
        products=products, productKinds=kinds, allowedLayoutPaths=sorted(products),
        originalCSharpSourceRecovered=False, localBuildClaimed=False, byteIdenticalCompilationClaimed=False)
