"""Closed SDK6 package members and their complete preferred source chains.

Only ten pinned imported members are covered. Canonical Unsafe/Locator inputs
are compared with their actual distributor packages. Cecil follows its own
SDK6 Linker Gitlink; CSS uses the original SDK recipe and publisher Gitlink.
No missing repository metadata or local compilation is invented.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'sdk6-attributed-component-inputs'
ROLE = 'sdk6-original-package-component-source-correspondence-inputs'
KIND = 'sdk6-reviewed-closed-component-source-chain'
POLICY_SHA = '72cc5158deb9aff3fdb1ef8c16003abf22251aeeba0f68a06fbfe3c67d01fea0'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(name):
    require(isinstance(name, str) and name and not any(c in name for c in '\\\0\r\n')
            and not PurePosixPath(name).is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
            'Ordinary relative SDK6 attributed-source member required')
    return name


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Redirected SDK6 attributed input is forbidden')
    return path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def policy():
    raw = Path(__file__).with_name('musl-legacy6-attributed-components.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK6 attributed source policy bytes differ')
    p = json.loads(raw)
    require(p['schemaVersion'] == 1 and p['sdkVersion'] == '6.0.136'
            and p['kind'] == 'sdk6-closed-attributed-component-source-policy'
            and len(p['products']) == 10 and len(p['packages']) == 7 and len(p['sources']) == 10
            and all(p[key] is False for key in ('localBuildClaimed', 'byteIdenticalCompilationClaimed',
                'publicCecilPackageUsedAsBinaryOrigin', 'packageRepositoryMetadataFabricated')),
            'The distinct closed ten-member SDK6 source policy is required')
    return p


def declared_product(name, package_sha256, member, data):
    """Emit a candidate binding; independent full source validation is required."""
    p = policy()
    row = p['products'].get(name)
    if row is None:
        return None
    require(dict(packageSha256=package_sha256, packageMember=member) in row['allowedPackageMembers']
            and fingerprint(data) == row['fingerprint'], 'Closed SDK6 product path/package/member bytes differ')
    reader = module('sdk6_attributed_metadata', 'musl_managed_metadata.py')
    require(reader.inspect(data) == row['metadata'], 'Original SDK6 attributed product metadata differs')
    source = row['canonical']['source']
    return dict(row, packageSha256=package_sha256, packageMember=member,
        source=source, sourceCommit=p['sources'][source]['commit'])


def inspect_package(path, sha):
    p = policy()
    require(sha in p['packages'], 'Unreviewed SDK6 attributed package')
    expected = p['packages'][sha]
    path = ordinary(path)
    require(path.is_file() and path.stat().st_size == expected['bytes'] and expected['bytes'] <= 32 * 1024**2,
            'Ordinary bounded exact SDK6 package required')
    raw = path.read_bytes()
    require(fingerprint(raw) == {key: expected[key] for key in FP}, 'Exact SDK6 attributed package bytes differ')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == len({e.filename for e in entries}) and len(entries) < 20000
                and all(e.file_size <= 64 * 1024**2 and e.external_attr >> 16 & 0o170000 != 0o120000 for e in entries),
                'Only ordinary bounded SDK6 package members are admitted')
        nuspec = archive.read(portable(expected['nuspec']['path']))
        require(fingerprint(nuspec) == {key: expected['nuspec'][key] for key in FP}, 'Original SDK6 package nuspec differs')
        metadata = ET.fromstring(nuspec).find('{*}metadata')
        repository = metadata.find('{*}repository')
        actual_repository = dict(repository.attrib) if repository is not None else None
        require(metadata.findtext('{*}id') == expected['id'] and metadata.findtext('{*}version') == expected['version']
                and actual_repository == expected['repository'], 'Original SDK6 publisher metadata differs')
        for name, product in p['products'].items():
            for pair in product['allowedPackageMembers']:
                if pair['packageSha256'] == sha:
                    declared_product(name, sha, pair['packageMember'], archive.read(pair['packageMember']))
        return raw, nuspec


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def data_bodies(packages):
    p = policy()
    require(p['packages'].keys() <= packages.keys(), 'All seven actual SDK6 component package inputs are required')
    bodies = {'policy.json': json_bytes(p), 'origin.json': json_bytes(dict(kind=KIND,
        sourcePolicySha256=POLICY_SHA, products=10, packages=7, localBuildClaimed=False,
        byteIdenticalCompilationClaimed=False, packageRepositoryMetadataFabricated=False))}
    for sha in p['packages']:
        raw, nuspec = inspect_package(packages[sha], sha)
        bodies['packages/' + sha + '.nupkg'] = raw
        bodies['original-package-metadata/' + sha + '/' + portable(p['packages'][sha]['nuspec']['path'])] = nuspec
    return bodies


def prepare(packages, destination):
    bodies = data_bodies(packages)
    destination = ordinary(destination)
    require(not destination.exists(), 'A fresh SDK6 attributed input directory is required')
    destination.mkdir(parents=True)
    for name, raw in bodies.items():
        target = destination / portable(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return dict(name=ROOT_NAME, path=str(destination), kind='tree', role=ROLE,
        sourceAdmissionAllowed=False, qualificationAllowed=False)


def source_roots(manifest, declared):
    """Select the one pristine source role while retaining compiler Gitlinks."""
    roots = {}
    for role, expected in declared.items():
        matches = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export')
            and r.get('commit') == expected['commit'] and r.get('tree') == expected['tree']]
        preferred = [r for r in matches if r.get('role') == 'source-for-serviced-imported-package']
        if preferred:
            matches = preferred
        require(len(matches) == 1 and not matches[0].get('deleted') and not matches[0].get('exclude'),
                'Complete exact SDK6 component Git source required: ' + role)
        roots[role] = matches[0]
    return roots


def validate(release, manifest, packages):
    """Authenticate complete source trees, original blobs and exact raw packages."""
    release = ordinary(release)
    p = policy()
    expected_bodies = data_bodies(packages)
    roots = source_roots(manifest, p['sources'])
    for parent, child_path, child in [('linker', 'external/cecil', 'cecil'), ('external', 'src/cssparser', 'css')]:
        require(any(s.get('path') == child_path and s.get('commit') == p['sources'][child]['commit']
            and s.get('root') == roots[child]['name'] for s in roots[parent].get('submodules', [])),
            'The original SDK6 publisher Gitlink must connect its complete component source')
    derived = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(derived) == 1 and derived[0]['kind'] == 'tree' and derived[0].get('role') == ROLE
            and derived[0].get('commit') is None, 'SDK6 attributed comparison inputs cannot invent Git provenance')
    prefixes = {portable(row['name']) + '/': role for role, row in roots.items()}
    indexed, baselines = {}, {role: {} for role in roots}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            name = portable(row['path'])
            selected = next(((prefix, role) for prefix, role in prefixes.items() if name.startswith(prefix)), None)
            if selected:
                prefix, role = selected
                relative = name[len(prefix):]
                require(name not in indexed and (row.get('baseline') is not None or role == 'sdk'),
                        'Original SDK6 imported component Git member required')
                if row.get('baseline') is not None:
                    baselines[role][relative] = row['baseline']
                indexed[name] = (role, relative, row)
            elif name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate SDK6 attributed data member')
                indexed[name] = (None, name[len(ROOT_NAME) + 1:], row)
    packer = module('sdk6_attributed_full_source_tree', 'package-used-source.py')
    for role, baseline in baselines.items():
        for sub in roots[role].get('submodules', []):
            require(sub['path'] not in baseline, 'SDK6 Gitlink cannot be an ordinary source file')
            baseline[sub['path']] = dict(mode='160000', blob=sub['commit'])
        require(packer.baseline_tree(baseline) == p['sources'][role]['tree'], 'Complete original SDK6 component Git tree differs')
    found, data, sources = set(), {}, {role: {} for role in roots}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed:
                continue
            role, relative, row = indexed[entry.name]
            require(entry.name not in found and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2,
                    'Ordinary bounded original SDK6 component source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            require(fingerprint(raw) == {key: row[key] for key in FP}, 'Archived SDK6 component source bytes differ')
            found.add(entry.name)
            if role is None:
                data[relative] = raw
                continue
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            # The SDK is the actual patched compiler worktree. Its complete
            # original baseline is reconstructed above; its used-source/Csc
            # validator separately binds the recorded product patches. All
            # imported component roots must remain entirely pristine.
            if role != 'sdk':
                require(packer.pristine_blob(row, blob, raw if relative.lower().endswith(('.cmd', '.bat')) else None),
                        'SDK6 imported component source differs from its original Git blob')
            expected = p['sources'][role]['files'].get(relative)
            if expected is not None:
                require(fingerprint(raw) == {key: expected[key] for key in FP}
                        and blob == expected['gitBlob'], 'Exact original SDK6 dependency recipe or license differs')
                sources[role][relative] = raw
    require(found == indexed.keys() and data == expected_bodies, 'Complete original SDK6 attributed source/data archive required')
    require(all(sources[role].keys() == expected['files'].keys() for role, expected in p['sources'].items()),
            'All original SDK6 dependency recipes, preferred IL and licenses must remain retained')
    products = {name: dict(row, sourceRoot=roots[row['canonical']['source']]['name'],
        sourceCommit=p['sources'][row['canonical']['source']]['commit']) for name, row in p['products'].items()}
    return dict(kind=KIND, products=products, localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        packageRepositoryMetadataFabricated=False, publicCecilPackageUsedAsBinaryOrigin=False)
