"""Three SDK5 Json.NET products and their original publisher source ZIPs.

Publisher-generated version/signing metadata remains original publisher data,
separate from pristine Git source. No publisher binary or source is rewritten.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
POLICY_SHA256 = 'dbae1c394c84c3bc2f9d8077459db6a5829e8e47d711456d5fa9cc79e36545fa'
ROOT_NAME = 'sdk5-original-newtonsoft-publisher-sources'
ROLE = 'sdk5-original-publisher-source-distributions-and-package-inputs'
KIND = 'reviewed-sdk5-original-publisher-source-package'
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
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK5 publisher-source path required')
    return path


def policy():
    raw = Path(__file__).with_name('musl-legacy5-newtonsoft-publisher-source-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed original SDK5 publisher-source policy differs')
    p = json.loads(raw)
    require(p['kind'] == 'sdk5-original-newtonsoft-publisher-source-policy' and p['sdkVersion'] == SDK
            and len(p['packages']) == len(p['distributions']) == len(p['sources']) == 2 and len(p['products']) == 3
            and set(p['distributions']) == {'9.0.1', '11.0.1'}
            and all(p[k] is False for k in ('packageGitCommitClaimed', 'localBuildClaimed', 'byteIdenticalCompilationClaimed',
                'originalPublisherSourceModified', 'originalPublisherMetadataCalledPristineGit')), 'Distinct SDK5 original publisher identities required')
    return p


def inspect_package(path, sha, p=None):
    p = p or policy(); expected = p['packages'].get(sha); path = ordinary(path)
    require(expected is not None and path.is_file() and path.stat().st_size == expected['fingerprint']['bytes'], 'Exact original SDK5 Json.NET NPK required')
    raw = path.read_bytes(); require(fingerprint(raw) == expected['fingerprint'], 'Original SDK5 Json.NET NPK bytes differ')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        spec = archive.read(expected['nuspec']['path'])
        require(fingerprint(spec) == {k:expected['nuspec'][k] for k in FP}
                and b'<!DOCTYPE' not in spec.upper() and b'<!ENTITY' not in spec.upper(), 'Original Json.NET nuspec differs')
        metadata = ET.fromstring(spec).find('{*}metadata')
        require(metadata.findtext('{*}id') == 'Newtonsoft.Json' and metadata.findtext('{*}version') == expected['version'], 'Original Json.NET package identity differs')
    return raw


def publisher_metadata(version, name, original, publisher):
    """Only five exact upstream build outputs differ from original Git text."""
    if version == '9.0.1' and name in {'Src/Newtonsoft.Json/Properties/AssemblyInfo.cs',
            'Src/Newtonsoft.Json.Tests/Properties/AssemblyInfo.cs', 'Src/Newtonsoft.Json.TestConsole/Properties/AssemblyInfo.cs'}:
        require(original.count(b'AssemblyVersion("7.0.0.0")') == original.count(b'AssemblyFileVersion("7.0.2.18802")') == 1,
                'Original Json.NET9 version recipe input differs')
        expected = original.replace(b'AssemblyVersion("7.0.0.0")', b'AssemblyVersion("9.0.0.0")').replace(
            b'AssemblyFileVersion("7.0.2.18802")', b'AssemblyFileVersion("9.0.1.19813")')
        require(not expected.endswith(b'\n') and publisher.replace(b'\r\n', b'\n') == expected + b'\n',
                'Original publisher Json.NET9 assembly-version output differs')
        return
    if version == '9.0.1' and name == 'Src/Newtonsoft.Json/project.json':
        expected, actual = json.loads(original.decode('utf-8-sig')), json.loads(publisher.decode('utf-8-sig'))
        require(expected['version'] == '1.0.0-*' and 'buildOptions' not in expected, 'Original Json.NET9 project recipe input differs')
        expected.update(version='9.0.1', buildOptions=dict(keyFile='C:\\Development\\Releases\\newtonsoft.snk',
            define=['CODE_ANALYSIS', 'TRACE', 'dotnet', 'SIGNED'], xmlDoc=True, warningsAsErrors=True))
        require(actual == expected, 'Original publisher Json.NET9 version/signing project output differs')
        return
    if version == '11.0.1' and name == 'Src/Newtonsoft.Json/Newtonsoft.Json.csproj':
        require(all(b'<!DOCTYPE' not in v.upper() and b'<!ENTITY' not in v.upper() for v in (original, publisher)), 'Unsafe original Json.NET project XML')
        before, after = ET.fromstring(original), ET.fromstring(publisher)
        file_version, suffix = before.findall('./PropertyGroup/FileVersion'), before.findall('./PropertyGroup/VersionSuffix')
        require(len(file_version) == len(suffix) == 1 and file_version[0].text == '11.0.1' and suffix[0].text == 'beta2', 'Original Json.NET11 project version inputs differ')
        file_version[0].text = '11.0.1.21818'; suffix[0].text = ''
        def shape(node):
            return (node.tag, tuple(sorted(node.attrib.items())), '' if not node.text or node.text.isspace() else node.text, tuple(shape(c) for c in node))
        require(shape(before) == shape(after), 'Original publisher Json.NET11 version project output differs')
        return
    raise ValueError('Unreviewed original publisher source difference')


def distribution_sources(raw, version, originals, p):
    expected = p['distributions'][version]
    require(fingerprint(raw) == expected['fingerprint'], 'Original publisher Json.NET ZIP bytes differ')
    B = module('sdk5_publisher_archive_bytes', 'musl_legacy_admission.py'); result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist(); require(len(names) == len(set(names)) and len(names) < 2000, 'Unique bounded original publisher ZIP required')
        # The pinned 2018 publisher ZIP uses literal Windows member separators.
        # This is a comparison map only; the original ZIP is never extracted.
        selected = {n for n in names if n.replace('\\', '/').startswith('Source/') and not n.replace('\\', '/').endswith('/')}
        require(selected == expected['sourceMembers'].keys(), 'Complete original publisher source member set differs')
        paths = set()
        for member, row in expected['sourceMembers'].items():
            path = B.portable(row['path']); require(path not in paths, 'Original publisher source comparison path collides'); paths.add(path)
            info = archive.getinfo(member)
            require(info.file_size <= 16 * 1024**2 and ((info.external_attr >> 16) & 0o170000) != 0o120000, 'Ordinary bounded publisher source member required')
            data = archive.read(member); require(fingerprint(data) == row['fingerprint'], 'Original publisher source bytes differ')
            original = originals[path]
            require(fingerprint(original) == row['originalGit']['fingerprint']
                    and hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest() == row['originalGit']['blob'], 'Original corresponding Json.NET Git source differs')
            if row['correspondence'] == 'exact': require(data == original, 'Literal publisher/Git source bytes differ')
            elif row['correspondence'] == 'publisher-crlf-original-git-lf':
                require(b'\r\n' not in original and b'\r\n' in data and data.replace(b'\r\n', b'\n') == original, 'Original publisher CRLF representation differs')
            else:
                require(row['correspondence'] == 'original-publisher-build-version-and-signing-metadata', 'Unknown original publisher source correspondence')
                publisher_metadata(version, path, original, data)
            result[path] = data
        require(set(expected['productionPaths']) <= paths and len(expected['productionPaths']) == expected['productionFiles'], 'Complete original Json.NET production C# and project inputs required')
        for product in p['products'].values():
            if product['publisherVersion'] == version:
                require(fingerprint(archive.read(product['publisherBinaryMember'])) == product['fingerprint'], 'Original publisher binary differs from its actual NPK product')
    return result


def bodies(packages, distributions, originals):
    p = policy(); require(packages.keys() == p['packages'].keys() and distributions.keys() == p['distributions'].keys(), 'Both complete original Json.NET package and publisher inputs required')
    result = {}
    for sha, raw in packages.items():
        require(fingerprint(raw) == p['packages'][sha]['fingerprint'], 'Retained original Json.NET package differs')
        result['packages/' + sha + '.nupkg'] = raw
    for version, raw in distributions.items():
        files = distribution_sources(raw, version, originals[p['distributions'][version]['sourceCommit']], p)
        result['publisher-distributions/' + p['distributions'][version]['name']] = raw
        result.update({'original-publisher-source/' + version + '/' + path:data for path,data in files.items()})
    for name, row in p['products'].items():
        pair = row['allowedPackageMembers'][0]
        with zipfile.ZipFile(io.BytesIO(packages[pair['packageSha256']])) as archive: raw = archive.read(pair['member'])
        require(fingerprint(raw) == row['fingerprint'], 'Original Json.NET layout/package/member bytes differ')
    result['origin.json'] = (json.dumps(dict(schemaVersion=1, sdkVersion=SDK, kind=KIND, policySha256=POLICY_SHA256,
        packageGitCommitClaimed=False, localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        originalPublisherSourceModified=False, originalPublisherMetadataCalledPristineGit=False), indent=2) + '\n').encode()
    return result


def prepare(package_paths, distribution_paths, source_paths, destination):
    p = policy(); originals = {}
    for commit, row in p['sources'].items():
        source = ordinary(source_paths[commit]); git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
        require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == commit, 'Exact original Json.NET source checkout required')
        distribution = p['distributions'][row['version']]
        originals[commit] = {r['path']:ordinary(source / r['path']).read_bytes() for r in distribution['sourceMembers'].values()}
    packages = {sha:inspect_package(package_paths[sha], sha, p) for sha in p['packages']}
    distributions = {version:ordinary(distribution_paths[version]).read_bytes() for version in p['distributions']}
    data = bodies(packages, distributions, originals); destination = ordinary(destination)
    require(not destination.exists(), 'Fresh original publisher source input tree required'); destination.mkdir(parents=True)
    for name, raw in data.items():
        path = ordinary(destination / name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def package_origin(path, sha):
    if sha not in policy()['packages']: return None
    inspect_package(path, sha)
    return dict(kind=KIND, sourceRoot=ROOT_NAME, sourceCommit=None, sourceBasis='closed-original-publisher-source-and-byte-identical-product-distribution')


def validate(release, manifest, package_paths, distribution_paths):
    p = policy(); release = ordinary(release); B = module('sdk5_publisher_source_bytes', 'musl_legacy_admission.py'); P = module('sdk5_publisher_source_tree', 'package-used-source.py')
    require(manifest.get('sdkVersion') == SDK and manifest.get('targetRid') in ('linux-musl-arm64', 'linux-musl-x64'), 'Independent SDK5 publisher-source delivery required')
    index_path = B.checked(release / 'sources', manifest['index']); archive_path = B.checked(release / 'sources', manifest['archive']); roots = {}
    for commit, row in p['sources'].items():
        found = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and r.get('commit') == commit and r.get('tree') == row['tree'] and not r.get('exclude') and not r.get('deleted')]
        require(len(found) == 1, 'Complete pristine original Json.NET Git tree required'); roots[commit] = found[0]
    data_root = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_root) == 1 and data_root[0]['kind'] == 'tree' and data_root[0].get('role') == ROLE and data_root[0].get('commit') is None, 'Original publisher source distribution must retain its non-Git role')
    prefixes = {r['name'] + '/':c for c,r in roots.items()}; indexed = {}; baselines = {c:{} for c in roots}
    with index_path.open() as stream:
        for line in stream:
            row = json.loads(line); selected = next(((pre,c) for pre,c in prefixes.items() if row['path'].startswith(pre)), None)
            if selected:
                prefix, commit = selected; name = row['path'][len(prefix):]
                require(row['path'] not in indexed and row.get('baseline'), 'Unique original Json.NET source baseline required')
                indexed[row['path']] = (commit,name,row); baselines[commit][name] = row['baseline']
            elif row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in indexed, 'Duplicate original publisher source data member'); indexed[row['path']] = (None,row['path'][len(ROOT_NAME)+1:],row)
    for commit, baseline in baselines.items(): require(P.baseline_tree(baseline) == p['sources'][commit]['tree'], 'Complete original Json.NET Git baseline differs')
    originals, actual, seen = {c:{} for c in roots}, {}, set()
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            commit, name, expected = indexed[entry.name]
            require(entry.isfile() and entry.name not in seen and entry.size == expected['bytes'] and entry.size <= 16 * 1024**2, 'Ordinary bounded original Json.NET source member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k:expected[k] for k in FP}, 'Archived original Json.NET source bytes differ')
            if commit:
                require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['baseline']['blob'], 'Pristine original Json.NET source Git blob differs')
                originals[commit][name] = raw
            else: actual[name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys(), 'Complete original Json.NET source archive required')
    packages = {sha:inspect_package(package_paths[sha], sha, p) for sha in p['packages']}
    distributions = {version:ordinary(distribution_paths[version]).read_bytes() for version in p['distributions']}
    require(actual == bodies(packages, distributions, originals), 'Complete original publisher package, ZIP and source bytes differ')
    products = {name:dict(row, sourceRoot=ROOT_NAME, sourceCommit=None, gitSourceRoot=roots[p['distributions'][row['publisherVersion']]['sourceCommit']]['name'],
        gitSourceCommit=p['distributions'][row['publisherVersion']]['sourceCommit'], sourceBasis='original-publisher-source-distribution-with-byte-identical-original-NPK-product') for name,row in p['products'].items()}
    return dict(kind=KIND, dataRoot=ROOT_NAME, products=products, originalPublisherSourceModified=False,
        originalPublisherMetadataCalledPristineGit=False, localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
