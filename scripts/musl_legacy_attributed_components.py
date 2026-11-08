"""Attribute eight fixed SDK7 imports to reviewed publisher source chains.

No general missing-commit inference is provided. Cecil comes from Linker's
declared source Gitlink, not the different public Cecil package. Unsafe is
byte-identical to its exact original package; Locator's short embedded hash
is bound to the full commit in its exact original package. Elfie's source
association is separately reviewed by a complete code/metadata comparison;
its binary does not contain a source commit and is never claimed to do so.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'attributed-component-inputs'
ROLE = 'original-package-component-source-correspondence-inputs'
KIND = 'reviewed-closed-original-component-source-chain'
POLICY_SHA = '46349d2bbccd46eedae3b8e3c4cd23faf10bf3ac4d67a108aab73b40166e73f4'
VARIANTS_SHA = '1cad689f5aaa4b8a4c457f5efdc3f26e65b535b6ec750d028b028fddcd6de5ae'
ILLINK_CANONICAL = '4ebaac39fd6f96593fd368dffdaf811690c84a05bf58bc3913674770c7edd025'
ILLINK_SIGNED = '4b057a2e0807ba2c0265ed709886b848fe1fd4b17b379c3ab838f313883b7fb1'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def policy():
    raw = Path(__file__).with_name('musl-legacy-attributed-components.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed component source policy bytes differ')
    result = json.loads(raw)
    require(result['schemaVersion'] == 1 and result['sdkVersion'] == '7.0.120'
            and len(result['products']) == 8 and set(result['sources']) == {'linker', 'cecil', 'locator', 'runtime', 'elfie'}
            and result['localBuildClaimed'] is result['byteIdenticalCompilationClaimed'] is False
            and result['publicCecilPackageUsedAsBinaryOrigin'] is False, 'Closed eight-component source policy required')
    return result


def portable(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n')
            and not PurePosixPath(value).is_absolute() and all(p not in ('', '.', '..') for p in value.split('/')),
            'Ordinary relative component source member required')
    return value


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Redirected component input forbidden')
    return path


def pinned(path, identity):
    path = ordinary(path)
    require(path.is_file() and path.stat().st_size == identity['bytes'] and identity['bytes'] <= 32 * 1024**2,
            'Ordinary bounded exact component package required')
    raw = path.read_bytes()
    require(fingerprint(raw) == {k: identity[k] for k in FP}, 'Pinned component package bytes differ')
    return raw


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def container_variants():
    raw = Path(__file__).with_name('musl-legacy-illink-container-variants.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == VARIANTS_SHA, 'Closed ILLink container variant policy bytes differ')
    result = json.loads(raw)
    require(result['schemaVersion'] == 1 and result['sdkVersion'] == '7.0.120'
            and result['kind'] == 'closed-illink-package-container-variants'
            and result['sourcePolicySha256'] == POLICY_SHA and result['canonicalPackageSha256'] == ILLINK_CANONICAL
            and set(result['acceptedPackages']) == set(result['signatureMembers']) == {ILLINK_CANONICAL, ILLINK_SIGNED}
            and result['acceptedPackages'][ILLINK_CANONICAL] == policy()['packages'][ILLINK_CANONICAL]
            and result['acceptedPackages'][ILLINK_SIGNED]['nuspec'] == result['acceptedPackages'][ILLINK_CANONICAL]['nuspec']
            and len(result['unchangedNonSignatureMembers']) == 24 and result['signatureMember'] == '.signature.p7s'
            and all(result[key] is False for key in ('productSourceLicenseBindingsChanged', 'rawInputCanonicalized',
                                                    'signatureCryptographicTrustClaimed')),
            'Only the two fully pinned original ILLink containers are reviewed')
    return result


def package_policy(sha):
    p = policy()
    if sha in p['packages']: return p['packages'][sha]
    variants = container_variants()
    require(sha == ILLINK_SIGNED, 'Unreviewed original component package container')
    return variants['acceptedPackages'][sha]


def selected_packages(available):
    """Select one actual raw container per closed original package identity."""
    available = set(available); selected = {}
    for canonical in policy()['packages']:
        allowed = set(container_variants()['acceptedPackages']) if canonical == ILLINK_CANONICAL else {canonical}
        present = sorted(allowed & available)
        require(len(present) == 1, 'A unique exact actual restored component and one unambiguous actual container required: ' + canonical)
        selected[canonical] = present[0]
    return selected


def declared_product(name, package_sha256, member, data):
    """Construct a candidate attribution; complete validation remains separate."""
    p = policy(); row = p['products'].get(name)
    if row is None: return None
    allowed = set(container_variants()['acceptedPackages']) if row['packageSha256'] == ILLINK_CANONICAL else {row['packageSha256']}
    require(package_sha256 in allowed and row['packageMember'] == member
            and fingerprint(data) == row['fingerprint'], 'Closed imported component path/package/member bytes differ')
    identity = module('attributed_component_metadata', 'musl_managed_metadata.py').inspect(data)
    require(identity == row['metadata'], 'Closed imported component actual metadata differs')
    return dict(row, packageSha256=package_sha256, sourceCommit=p['sources'][row['source']]['commit'])


def inspect_package(path, sha):
    p = policy(); expected = package_policy(sha); pinned(path, expected)
    with zipfile.ZipFile(path) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), 'Duplicate component ZIP members forbidden')
        if sha in {ILLINK_CANONICAL, ILLINK_SIGNED}:
            variants = container_variants()
            members = dict(variants['unchangedNonSignatureMembers'])
            members[variants['signatureMember']] = variants['signatureMembers'][sha]
            require(set(archive.namelist()) == set(members) and all(fingerprint(archive.read(name)) == identity
                    for name, identity in members.items()), 'Exact ILLink payload and signature members required')
        require(fingerprint(archive.read(expected['nuspec']['path'])) == {k: expected['nuspec'][k] for k in FP},
                'Original component package nuspec differs')
        for name, row in p['products'].items():
            if row['packageSha256'] == sha or row['packageSha256'] == ILLINK_CANONICAL and sha == ILLINK_SIGNED:
                declared_product(name, sha, row['packageMember'], archive.read(row['packageMember']))


def package_source_commit(path):
    """A single closed missing-nuspec-repository exception, never inference."""
    p = policy(); sha = fingerprint(ordinary(path).read_bytes())['sha256']
    row = p['packageSourceExceptions'].get(sha)
    if row is None: return None
    inspect_package(path, sha)
    return p['sources'][row['source']]['commit']


def inspect_canonical_unsafe(raw):
    import io
    p = policy(); expected = p['unsafeCanonicalPackage']
    require(fingerprint(raw) == {k: expected[k] for k in FP}, 'Exact original Unsafe package required')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        spec = archive.read(expected['nuspec']['path'])
        require(fingerprint(spec) == {k: expected['nuspec'][k] for k in FP}, 'Original Unsafe nuspec differs')
        metadata = ET.fromstring(spec).find('{*}metadata'); repository = metadata.find('{*}repository')
        license = metadata.find('{*}license')
        require(metadata.findtext('{*}id') == 'System.Runtime.CompilerServices.Unsafe'
                and metadata.findtext('{*}version') == '5.0.0'
                and repository is not None and repository.get('url') == 'git://github.com/dotnet/runtime'
                and repository.get('commit') == p['sources']['runtime']['commit']
                and license is not None and license.get('type') == 'expression' and license.text == 'MIT',
                'Original Unsafe publisher full source/license declaration differs')
        row = next(v for k, v in p['products'].items() if k.endswith('/System.Runtime.CompilerServices.Unsafe.dll'))
        require(fingerprint(archive.read(expected['member'])) == row['fingerprint'],
                'Bundled Unsafe is not the identical canonical publisher member')


def data_bodies(unsafe_package):
    p = policy(); raw = pinned(unsafe_package, p['unsafeCanonicalPackage']); inspect_canonical_unsafe(raw)
    origin = dict(schemaVersion=1, kind=KIND, policySha256=POLICY_SHA, canonicalUnsafePackage=p['unsafeCanonicalPackage'],
        canonicalPackageUsedAsLayoutOrigin=False, canonicalPackageExecuted=False,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False, publicCecilPackageUsedAsBinaryOrigin=False)
    return {'packages/' + p['unsafeCanonicalPackage']['sha256'] + '.nupkg': raw,
            'origin.json': (json.dumps(origin, indent=2) + '\n').encode(),
            'elfie-source-correspondence-review.json': (json.dumps(p['elfieCorrespondenceReview'], indent=2) + '\n').encode()}


def prepare(unsafe_package, destination):
    destination = ordinary(destination); bodies = data_bodies(unsafe_package)
    require(not destination.exists(), 'Fresh component source input tree required')
    destination.mkdir(parents=True)
    for name, raw in bodies.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, packages):
    """Independently validate exact packages and complete original Git trees."""
    release = ordinary(release); p = policy(); roots = {}
    selected_containers = selected_packages(packages)
    for sha in selected_containers.values():
        inspect_package(packages[sha], sha)
    for role, expected in p['sources'].items():
        matches = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export')
                   and r.get('commit') == expected['commit'] and r.get('tree') == expected['tree']]
        require(len(matches) == 1 and not matches[0].get('deleted'), 'Complete exact component Git source required: ' + role)
        roots[role] = matches[0]
    require(any(s.get('path') == 'external/cecil' and s.get('commit') == p['sources']['cecil']['commit']
                and s.get('root') == roots['cecil']['name'] for s in roots['linker'].get('submodules', [])),
            'Original Linker Cecil project Gitlink must connect its complete preferred source')
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'Canonical comparison inputs may not invent Git provenance')
    prefixes = {r['name'] + '/': key for key, r in roots.items()}; indexed = {}; baselines = {key: {} for key in roots}
    data = {}; sources = {key: {} for key in roots}; seen = set()
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = portable(row['path'])
            selected = next(((prefix, role) for prefix, role in prefixes.items() if name.startswith(prefix)), None)
            if selected:
                prefix, role = selected; relative = name[len(prefix):]
                require(name not in indexed and row.get('baseline') is not None, 'Original component Git member required')
                baselines[role][relative] = row['baseline']; indexed[name] = (role, relative, row)
            elif name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate component data source entry'); indexed[name] = (None, name[len(ROOT_NAME) + 1:], row)
    packer = module('attributed_component_source_tree', 'package-used-source.py')
    for role, baseline in baselines.items():
        for sub in roots[role].get('submodules', []):
            require(sub['path'] not in baseline, 'Gitlink cannot also be an ordinary component source')
            baseline[sub['path']] = dict(mode='160000', blob=sub['commit'])
        require(packer.baseline_tree(baseline) == p['sources'][role]['tree'], 'Complete original component Git tree differs')
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            role, relative, row = indexed[entry.name]
            require(entry.name not in seen and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2,
                    'Ordinary bounded original component source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            require(fingerprint(raw) == {k: row[k] for k in FP}, 'Archived component source/index bytes differ')
            if role:
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                require(packer.pristine_blob(row, blob, raw if relative.lower().endswith(('.cmd', '.bat')) else None),
                        'Component preferred source differs from its original Git blob')
                expected = p['sources'][role]['files'].get(relative)
                if expected:
                    require(fingerprint(raw) == {k: expected[k] for k in FP} and row['baseline']['blob'] == expected['gitBlob'],
                            'Reviewed original source/project/license bytes differ')
                    sources[role][relative] = raw
            else:
                require(entry.isfile(), 'Canonical package evidence must be an ordinary file'); data[relative] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and all(sources[k].keys() == p['sources'][k]['files'].keys() for k in roots),
            'Complete original component source/project/license archive required')
    canonical = 'packages/' + p['unsafeCanonicalPackage']['sha256'] + '.nupkg'
    require(set(data) == {canonical, 'origin.json', 'elfie-source-correspondence-review.json'},
            'Closed canonical component evidence tree required')
    inspect_canonical_unsafe(data[canonical])
    require(data['elfie-source-correspondence-review.json'] ==
            (json.dumps(p['elfieCorrespondenceReview'], indent=2) + '\n').encode(),
            'Independently reviewed original Elfie source correspondence differs')
    # Recompute deterministic origin without creating or executing any SDK/tool.
    origin = json.loads(data['origin.json'])
    require(origin == dict(schemaVersion=1, kind=KIND, policySha256=POLICY_SHA,
        canonicalUnsafePackage=p['unsafeCanonicalPackage'], canonicalPackageUsedAsLayoutOrigin=False,
        canonicalPackageExecuted=False, localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        publicCecilPackageUsedAsBinaryOrigin=False), 'Original component evidence scope differs')
    products = {name: dict(row, packageSha256=selected_containers[row['packageSha256']],
                          sourceRoot=roots[row['source']]['name'], sourceCommit=p['sources'][row['source']]['commit'])
                for name, row in p['products'].items()}
    return dict(kind=KIND, products=products, localBuildClaimed=False, byteIdenticalCompilationClaimed=False)
