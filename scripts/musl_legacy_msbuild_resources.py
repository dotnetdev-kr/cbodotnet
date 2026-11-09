"""Authenticate one resource-only MSBuild package against its original XLF.

No assembly is loaded. The original package, satellite bytes and decoded text
remain retained; only CRLF/LF translation is accepted when comparing XLF text.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
from musl_source_archive import open_source_archive
import xml.etree.ElementTree as ET
import zipfile

COMMIT = '6918b863aa37ad0699f98482fbab9f7a52e65a92'
KIND = 'resource-only-msbuild-localization'
ROOT_NAME = 'msbuild-localization-data'
ROLE = 'imported-msbuild-resource-data-and-readable-source'
PACKAGE = dict(bytes=1735520,
    sha256='33b7c312e18d4ded2824039dc8b93703bae0883dd6803171ceaad36e9a40b593',
    sha512='42e76e1e05c18c4b5984eee29c84146568d0fe26ca8d8d7dff60298c53cca3209dd0fe6d7a6d502c848ba4cc4c584f9cae318033f946658a75f0ae956e9f068d')
CULTURES = ('cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant')
PROJECTS = {'MSBuild': 'MSBuild', 'Microsoft.Build': 'Build',
            'Microsoft.Build.Tasks.Core': 'Tasks', 'Microsoft.Build.Utilities.Core': 'Utilities'}
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def contract():
    # Lazy loading avoids a cycle when the admission gate imports this policy.
    spec = importlib.util.spec_from_file_location('msbuild_resource_primitives', Path(__file__).with_name('musl_legacy_admission.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def xml(raw):
    require(len(raw) <= 2 * 1024**2 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
            'Bounded XML without external entities required')
    return ET.fromstring(raw)


def source_policy():
    policy = json.loads(Path(__file__).with_name('musl-legacy-msbuild-xlf-policy.json').read_bytes())
    require(policy['schemaVersion'] == 1 and policy['sourceCommit'] == COMMIT and len(policy['files']) == 79,
            'Exact original 78-XLF and MIT source policy required')
    return policy['files']


def source_path(base, resource, culture):
    require(base in PROJECTS and culture in CULTURES and resource.startswith(base + '.')
            and resource.endswith('.' + culture + '.resources'), 'Unexpected satellite resource identity')
    suffix = resource[len(base) + 1:-(len(culture) + len('.resources') + 1)]
    if suffix == 'Strings.shared': prefix = 'src/Shared/Resources/xlf/Strings.shared.'
    elif suffix == 'Strings.ManifestUtilities' and base == 'Microsoft.Build.Tasks.Core':
        prefix = 'src/Tasks/ManifestUtil/Resources/xlf/Strings.ManifestUtilities.'
    elif suffix == 'Strings': prefix = 'src/' + PROJECTS[base] + '/Resources/xlf/Strings.'
    else: raise ValueError('Unreviewed resource-to-source mapping')
    return prefix + culture + '.xlf'


def inspect(package):
    package = Path(package).absolute()
    require(package.is_file() and not any(p.is_symlink() for p in (package, *package.parents))
            and package.stat().st_size == PACKAGE['bytes'], 'Ordinary pinned localization input required')
    raw = package.read_bytes(); require(fingerprint(raw) == PACKAGE, 'Unreviewed localization package bytes')
    reader = contract(); products, readable, bodies = {}, [], {'packages/' + PACKAGE['sha256'] + '.nupkg': raw}
    expected = {f'lib/netstandard1.3/{culture}/{base}.resources.dll'
                for culture in CULTURES for base in PROJECTS}
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        require(len({e.filename for e in entries}) == len(entries) and len(entries) < 80,
                'Duplicate or oversized localization ZIP entries')
        nuspecs = [e.filename for e in entries if e.filename.endswith('.nuspec')]
        require(len(nuspecs) == 1, 'One original localization nuspec required')
        nuspec = archive.read(nuspecs[0]); metadata = xml(nuspec).find('{*}metadata')
        license_node = metadata.find('{*}license')
        require(metadata.findtext('{*}id') == 'Microsoft.Build.Localization'
                and metadata.findtext('{*}version') == '17.4.8-preview-23319-01'
                and metadata.find('{*}repository') is None and license_node is not None
                and license_node.get('type') == 'expression' and license_node.text == 'MIT',
                'Exact original package identity/license required')
        bodies['original.nuspec'] = nuspec
        actual = {e.filename for e in entries if e.filename.lower().endswith(('.dll', '.exe'))}
        require(actual == expected, 'Exactly the reviewed 52 resource satellites required')
        for member in sorted(expected):
            require(archive.getinfo(member).file_size <= 1024**2, 'Bounded satellite required')
            data = archive.read(member); information = reader.MANAGED.inspect(data)
            satellite = reader.resource_only_pe(data)
            base = satellite['assemblyName'].removesuffix('.resources'); culture = satellite['culture']
            require(member == f'lib/netstandard1.3/{culture}/{base}.resources.dll'
                    and satellite['assemblyVersion'] == '15.1.0.0' and satellite['publicKeyToken'] == 'b03f5f7f11d50a3a'
                    and reader.embedded_component_commit(information) == COMMIT,
                    'Satellite ABI, culture or own source identity differs')
            strings = []
            for resource in satellite['resources']:
                path = source_path(base, resource['name'], culture)
                for key, value in reader.resource_strings(resource['data']).items():
                    strings.append(dict(resource=resource['name'], key=key, sourceXlf=path, **value))
            relative = culture + '/' + base + '.resources.dll'
            bodies['resources/' + relative] = data
            products['sdk/7.0.120/' + relative] = fingerprint(data)
            readable.append(dict(member=member, strings=strings))
    require(sum(len(row['strings']) for row in readable) == 20280, 'Complete 20,280 original translation strings required')
    bodies['readable-resources.json'] = (json.dumps(readable, indent=2, ensure_ascii=False) + '\n').encode()
    bodies['origin.json'] = (json.dumps(dict(schemaVersion=1, package=PACKAGE, sourceCommit=COMMIT,
        kind=KIND, localBuildClaimed=False, byteIdenticalCompilationClaimed=False), indent=2) + '\n').encode()
    return bodies, readable, products


def compare_xlf(readable, sources):
    values = {}
    for path, raw in sources.items():
        if not path.endswith('.xlf'): continue
        root = xml(raw); files = root.findall('{*}file')
        culture = path.rsplit('.', 2)[1]
        require(len(files) == 1 and files[0].get('target-language') == culture, 'Original XLF target culture differs')
        strings = {}; ids = set()
        for unit in root.iter():
            if unit.tag.rsplit('}', 1)[-1] != 'trans-unit': continue
            key = unit.get('id'); require(key and key not in ids, 'Duplicate or missing XLF resource identity'); ids.add(key)
            targets = unit.findall('{*}target'); require(len(targets) <= 1, 'Ambiguous XLF target')
            if targets: strings[key] = ''.join(targets[0].itertext())
        values[path] = strings
    exact = normalized = 0
    for row in readable:
        for item in row['strings']:
            original = values[item['sourceXlf']].get(item['key'])
            require(original is not None and original.replace('\r\n', '\n') == item['value'].replace('\r\n', '\n'),
                    'Translation differs from its own original XLF target')
            exact += original == item['value']; normalized += original != item['value']
    require(exact == 19591 and normalized == 689, 'Original exact/CRLF-only translation counts differ')


def prepare(package, source, destination):
    """Retain complete actual resource input plus readable text before packing."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    require(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == COMMIT,
            'Exact original MSBuild source commit required')
    sources = {}
    for name, expected in source_policy().items():
        path = source / name
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary original XLF source required')
        raw = path.read_bytes()
        require(all(fingerprint(raw)[key] == expected[key] for key in FP)
                and raw == subprocess.check_output(['git', '-C', str(source), 'show', COMMIT + ':' + name]),
                'Original XLF/license differs from its pinned source blob')
        sources[name] = raw
    bodies, readable, products = inspect(package); compare_xlf(readable, sources)
    for name, raw in bodies.items():
        target = destination / name; target.parent.mkdir(parents=True, exist_ok=True)
        require(not any(p.is_symlink() for p in (target, *target.parents))
                and (not target.exists() or target.read_bytes() == raw), 'Refusing redirected or different resource source output')
        if not target.exists(): target.write_bytes(raw)
    require({p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()} == bodies.keys(),
            'Unexpected resource source tree files')
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, package):
    """Independently verify retained resource data and exact archived Git XLF."""
    release = Path(release); bodies, readable, products = inspect(package)
    roots = [r for r in manifest['roots'] if r.get('commit') == COMMIT and r['kind'] in ('git', 'git-export')]
    require(len(roots) == 1 and not roots[0].get('deleted'), 'Complete original MSBuild Git source root required')
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0]['role'] == ROLE
            and data_roots[0].get('commit') is None, 'Retained resource data must not claim Git provenance')
    source_files = source_policy(); expected = {ROOT_NAME + '/' + name: fingerprint(raw) for name, raw in bodies.items()}
    expected.update({roots[0]['name'] + '/' + name: {key: row[key] for key in FP} for name, row in source_files.items()})
    reader = contract(); index = {}
    with (release / 'sources' / reader.portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected or row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in index, 'Duplicate resource source index member'); index[row['path']] = row
    require(index.keys() == expected.keys() and all(all(index[name].get(key) == fp[key] for key in FP)
            for name, fp in expected.items()), 'Complete original input/resource/readable/XLF bytes required in source index')
    sources, actual = {}, set()
    with open_source_archive(release, manifest) as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.isfile() and entry.size == expected[entry.name]['bytes'] and entry.size <= 16 * 1024**2
                    and entry.name not in actual, 'Ordinary bounded resource source member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == expected[entry.name], 'Archived resource source bytes differ')
            actual.add(entry.name)
            prefix = roots[0]['name'] + '/'
            if entry.name.startswith(prefix):
                name = entry.name[len(prefix):]; policy = source_files[name]
                require(index[entry.name].get('baseline', {}).get('blob') == policy['gitBlob'],
                        'Original XLF/license must retain its exact pristine Git blob')
                sources[name] = raw
    require(actual == expected.keys(), 'Archived original resource/source data is incomplete')
    compare_xlf(readable, sources)
    return dict(kind=KIND, basis='pinned-resource-only-pe-and-original-xlf', sourceRoot=roots[0]['name'], sourceCommit=COMMIT,
        allowedLayoutPaths=sorted(products), products=products, localBuildClaimed=False, byteIdenticalCompilationClaimed=False)
