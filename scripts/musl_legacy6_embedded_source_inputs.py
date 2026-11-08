"""Closed SDK6 package inputs with real per-member embedded source identities.

The fifteen original nuspecs have no repository element. The package input
therefore retains a non-Git role; every admitted member separately names its
full original Git source. In particular, System.Drawing's reference and runtime
members retain their different commits. No repository or local build is invented.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'sdk6-embedded-origin-package-inputs'
ROLE = 'sdk6-original-packages-and-per-member-embedded-source-inputs'
KIND = 'reviewed-sdk6-embedded-source-package'
POLICY_SHA = '0f36f3be66a92fd47afeaabea2164b82fe6501941b73849c86989efff27df07c'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 embedded-origin input path required')
    return path


def policy():
    raw = Path(__file__).with_name('musl-legacy6-embedded-source-packages.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK6 embedded-origin policy bytes differ')
    p = json.loads(raw)
    require(p['schemaVersion'] == 1 and p['sdkVersion'] == '6.0.136'
            and p['kind'] == 'sdk6-closed-original-package-embedded-source-policy'
            and len(p['packages']) == 15 and len(p['products']) == 38 and len(p['sources']) == 8
            and all(p[k] is False for k in ('packageRepositoryMetadataSynthesized', 'localBuildClaimed',
                'byteIdenticalCompilationClaimed', 'sourceLicenseSubstitutedForOriginalBinaryLicense')),
            'Only the original closed SDK6 package/member/source set is reviewed')
    return p


def member_identity(sha, member, raw):
    p = policy(); expected = p['packages'][sha]['members'].get(member)
    require(expected is not None and fingerprint(raw) == expected['fingerprint'], 'Original SDK6 embedded-origin package member differs')
    B = module('sdk6_embedded_origin_literal_pe', 'musl_legacy_admission.py'); actual = B.MANAGED.inspect(raw)
    require(B.embedded_component_source(actual) == expected['embeddedSource']
            and actual['assemblyName'] == expected['assemblyName'] and actual['assemblyVersion'] == expected['assemblyVersion']
            and actual['cliFlags'] & 1 and actual['entryPoint'] == actual['managedNativeHeaderBytes'] == 0,
            'Actual full SDK6 member source identity or managed IL metadata differs')
    return expected['embeddedSource']


def inspect_package(path, sha):
    p = policy(); expected = p['packages'].get(sha); path = ordinary(path)
    require(expected is not None and path.is_file() and path.stat().st_size == expected['fingerprint']['bytes']
            and path.stat().st_size <= 4 * 1024**2, 'Exact bounded SDK6 original embedded-origin package required')
    raw = path.read_bytes(); require(fingerprint(raw) == expected['fingerprint'], 'Original SDK6 package raw bytes differ')
    B = module('sdk6_embedded_origin_archive_names', 'musl_legacy_admission.py')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist(); require(len(names) == len(set(names)), 'Unique original SDK6 package members required')
        for entry in archive.infolist():
            if entry.is_dir(): continue
            B.portable(entry.filename); require((entry.external_attr >> 16) & 0o170000 != 0o120000, 'Redirected original package member')
        spec = archive.read(expected['nuspec']['path'])
        require(fingerprint(spec) == {k: expected['nuspec'][k] for k in FP}
                and b'<!DOCTYPE' not in spec.upper() and b'<!ENTITY' not in spec.upper(), 'Original SDK6 nuspec differs')
        node = ET.fromstring(spec).find('{*}metadata')
        require(node.findtext('{*}id') == expected['id'] and node.findtext('{*}version') == expected['version']
                and node.find('{*}repository') is None and {n: node.findtext('{*}' + n) for n in ('license', 'licenseUrl', 'requireLicenseAcceptance')}
                == expected['originalLicenseDeclaration'], 'Original absent repository and licensing declarations must remain unchanged')
        for name, fp in expected['notices'].items(): require(fingerprint(archive.read(name)) == fp, 'Original package license/notice changed')
        for name in expected['members']: member_identity(sha, name, archive.read(name))
    return raw


def package_origin(path, sha):
    if sha not in policy()['packages']: return None
    inspect_package(path, sha)
    return dict(kind=KIND, sourceRoot=ROOT_NAME, sourceCommit=None, sourceBasis='closed-original-package-with-per-member-embedded-Git-identities')


def declared_product(name, sha, member, raw):
    p = policy(); row = p['products'].get(name)
    require(row is not None and dict(packageSha256=sha, member=member) in row['allowedPackageMembers']
            and fingerprint(raw) == row['fingerprint'], 'Closed SDK6 embedded-origin layout/package/member differs')
    identity = member_identity(sha, member, raw)
    require(identity['sourceCommit'] == row['sourceCommit'], 'Underlying SDK6 member Git identity differs')
    return dict(row, basis=identity['basis'])


def bodies(packages, license_reference):
    p = policy(); require(set(packages) == set(p['packages']), 'All fifteen original package inputs required')
    require(fingerprint(license_reference) == p['licenseReference']['fingerprint'], 'Original upstream .NET Library license reference differs')
    result = {'licenses/original-upstream-NET-LIBRARY-EULA.txt': license_reference}
    for sha, raw in packages.items():
        require(fingerprint(raw) == p['packages'][sha]['fingerprint'], 'Source-retained original package differs')
        result['packages/' + sha + '.nupkg'] = raw
    origin = dict(schemaVersion=1, sdkVersion='6.0.136', kind=KIND, policySha256=POLICY_SHA,
        packageRepositoryMetadataSynthesized=False, packageGitCommitClaimed=False, localBuildClaimed=False,
        sourceLicenseSubstitutedForOriginalBinaryLicense=False, vstestConsumptionOfCommandLineUtilsClaimed=False,
        licenseReferenceBasis='Unchanged common original license URL; original upstream reference retained without a new consumption claim')
    result['origin.json'] = (json.dumps(origin, indent=2) + '\n').encode()
    return result


def prepare(packages_by_sha, vstest_source, destination):
    p = policy(); packages = {sha: inspect_package(packages_by_sha[sha], sha) for sha in p['packages']}
    source = ordinary(vstest_source); ref = p['licenseReference']; git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == ref['sourceCommit'], 'Exact original upstream license reference source required')
    license_raw = subprocess.check_output(git + ['show', ref['sourceCommit'] + ':' + ref['sourcePath']])
    require((source / ref['sourcePath']).read_bytes() == license_raw, 'Original upstream license reference was modified')
    data = bodies(packages, license_raw); destination = ordinary(destination); require(not destination.exists(), 'Fresh SDK6 embedded-source input tree required')
    destination.mkdir(parents=True)
    for name, raw in data.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, packages_by_sha):
    p = policy(); release = ordinary(release); P = module('sdk6_embedded_source_archive', 'package-used-source.py')
    roots = {}
    for commit, expected in p['sources'].items():
        found = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and r.get('commit') == commit
                 and r.get('tree') == expected['tree'] and not r.get('deleted') and not r.get('exclude')]
        require(len(found) == 1, 'Complete pristine SDK6 per-member Git source required: ' + commit); roots[commit] = found[0]
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0].get('kind') == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'Original package container inputs must retain their non-Git role')
    ref = p['licenseReference']; vcs = [r for r in manifest['roots'] if r.get('commit') == ref['sourceCommit'] and r.get('tree') == ref['sourceTree']]
    require(len(vcs) == 1, 'Exact complete upstream license reference source required'); license_path = vcs[0]['name'] + '/' + ref['sourcePath']
    prefixes = {r['name'] + '/': c for c, r in roots.items()}; indexed, baselines = {}, {c: {} for c in roots}
    with (release / 'sources' / manifest['index']['path']).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = row['path']; selected = next(((pre, c) for pre, c in prefixes.items() if name.startswith(pre)), None)
            if selected:
                prefix, commit = selected; relative = name[len(prefix):]
                require(name not in indexed and row.get('baseline'), 'Unique original SDK6 source baseline required')
                baselines[commit][relative] = row['baseline']; indexed[name] = (commit, relative, row)
            elif name.startswith(ROOT_NAME + '/') or name == license_path:
                require(name not in indexed, 'Duplicate SDK6 embedded-origin source/data member'); indexed[name] = (None, name, row)
    for commit, baseline in baselines.items():
        for child in roots[commit].get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
        require(P.baseline_tree(baseline) == p['sources'][commit]['tree'], 'Full original SDK6 member source tree differs')
    seen, data, licenses, license_reference = set(), {}, {}, None
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            commit, name, expected = indexed[entry.name]
            require(entry.name not in seen and entry.isfile() and entry.size == expected['bytes'] and entry.size <= 32 * 1024**2,
                    'Unique ordinary bounded SDK6 member source/data required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k: expected[k] for k in FP}, 'Archived SDK6 source/input bytes differ')
            if commit:
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                require(P.pristine_blob(expected, blob, raw if name.lower().endswith(('.cmd', '.bat')) else None), 'SDK6 preferred imported source was changed')
                if name in p['sources'][commit]['licenses']:
                    anchor = p['sources'][commit]['licenses'][name]
                    require(fingerprint(raw) == {k: anchor[k] for k in FP} and expected['baseline']['blob'] == anchor['gitBlob'], 'Original source license changed')
                    licenses[(commit, name)] = raw
            elif entry.name == license_path:
                require(fingerprint(raw) == ref['fingerprint'] and expected['baseline']['blob'] == ref['gitBlob'], 'Original upstream binary license reference differs')
                license_reference = raw
            else: data[name[len(ROOT_NAME) + 1:]] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and len(licenses) == sum(len(s['licenses']) for s in p['sources'].values()), 'Complete original SDK6 source/license coverage required')
    packages = {sha: inspect_package(packages_by_sha[sha], sha) for sha in p['packages']}
    require(license_reference is not None and data == bodies(packages, license_reference),
            'Exact raw original SDK6 packages, metadata and license reference must be retained')
    products = {name: dict(row, sourceRoot=roots[row['sourceCommit']]['name']) for name, row in p['products'].items()}
    return dict(kind=KIND, dataRoot=ROOT_NAME, products=products, packageRepositoryMetadataSynthesized=False,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False)
