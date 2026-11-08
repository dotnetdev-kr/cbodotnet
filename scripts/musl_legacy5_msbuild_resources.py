"""SDK5's original resource-only localization and exact XLF/RESX source.

No assembly is loaded. Imported bytes keep their original identity; this is
readable resource provenance, never a claim of local binary compilation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
COMMIT = '5e4b48a27efce55a613664b58d353ab4c8d1f6c1'
POLICY_SHA256 = 'c1d3223c7911016aa999007739aba9098fa7963cd0bc2048065201864faf2c98'
ROOT_NAME = 'sdk5-msbuild-localization-data'
ROLE = 'sdk5-imported-resource-only-msbuild-localization-and-readable-source'
KIND = 'sdk5-resource-only-msbuild-localization'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def contract():
    spec = importlib.util.spec_from_file_location('sdk5_localization_byte_primitives', Path(__file__).with_name('musl_legacy_admission.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def policy():
    raw = Path(__file__).with_name('musl-legacy5-msbuild-localization-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Exact distinct SDK5 localization policy required')
    result = json.loads(raw)
    require(result['sdkVersion'] == SDK and result['sourceCommit'] == COMMIT and result['resourceAssemblies'] == 56
            and result['resourceStreams'] == 126 and len(result['sourceFiles']) == 93 and len(result['resources']) == 56,
            'Independent SDK5 localization identities required')
    return result


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK5 localization evidence required')
    return path


def xml(raw):
    require(len(raw) <= 2 * 1024**2 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
            'Bounded original SDK5 XML without entities required')
    return ET.fromstring(raw)


def compare_resource(values, xlf_raw, resx_raw, culture):
    root = xml(xlf_raw); files = root.findall('{*}file')
    language = {'zh-Hans': 'zh-HANS', 'zh-Hant': 'zh-HANT'}.get(culture, culture)
    require(len(files) == 1 and files[0].get('target-language') == language, 'Original SDK5 XLF culture differs')
    units = {}
    for unit in root.iter():
        if unit.tag.rsplit('}', 1)[-1] != 'trans-unit': continue
        key = unit.get('id')
        require(key and key not in units, 'Duplicate original SDK5 XLF resource key')
        sources, targets = unit.findall('{*}source'), unit.findall('{*}target')
        require(len(sources) == len(targets) == 1, 'Complete unambiguous SDK5 XLF source and target required')
        units[key] = (''.join(sources[0].itertext()), ''.join(targets[0].itertext()))
    neutral = {}
    for item in xml(resx_raw).findall('data'):
        key = item.get('name'); value = item.findall('value')
        require(key and key not in neutral and len(value) == 1, 'Unique original SDK5 neutral resource required')
        neutral[key] = ''.join(value[0].itertext())
    require(values.keys() == units.keys() == neutral.keys(), 'Complete original SDK5 resource key sets differ')
    exact = normalized = 0
    for key, row in values.items():
        source, target = units[key]
        require(source == neutral[key], 'SDK5 XLF source differs from its original neutral RESX')
        require(target.replace('\r\n', '\n') == row['value'].replace('\r\n', '\n'), 'SDK5 translation differs from its original XLF target')
        exact += target == row['value']; normalized += target != row['value']
    return exact, normalized


def inspect(package):
    p = policy(); reader = contract(); package = ordinary(package)
    require(package.is_file() and package.stat().st_size == p['package']['bytes'], 'Exact original SDK5 localization package required')
    raw = package.read_bytes(); require(fingerprint(raw) == p['package'], 'Original SDK5 localization package fingerprints differ')
    bodies = {'packages/' + p['package']['sha256'] + '.nupkg': raw}; readable, products = [], {}
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist(); names = [e.filename for e in entries]
        require(len(names) == len(set(names)) and len(names) < 90, 'Unique bounded original SDK5 localization ZIP required')
        for name in names: reader.portable(name)
        specs = [n for n in names if '/' not in n and n.lower().endswith('.nuspec')]
        require(len(specs) == 1, 'One original SDK5 localization root definition required')
        nuspec = archive.read(specs[0]); metadata = xml(nuspec).find('{*}metadata'); license_node = metadata.find('{*}license')
        require(metadata.findtext('{*}id') == p['packageId'] and metadata.findtext('{*}version') == p['packageVersion']
                and metadata.find('{*}repository') is None and license_node is not None
                and license_node.get('type') == 'expression' and license_node.text == 'MIT', 'Original SDK5 package identity and license differ')
        bodies['original.nuspec'] = nuspec
        actual = {n for n in names if n.lower().endswith(('.dll', '.exe'))}
        require(actual == p['resources'].keys(), 'All56 original SDK5 localization satellites required')
        for member in sorted(actual):
            require(archive.getinfo(member).file_size <= 1024**2, 'Bounded SDK5 localization satellite required')
            data = archive.read(member); identity = reader.MANAGED.inspect(data); satellite = reader.resource_only_pe(data)
            culture, assembly = satellite['culture'], satellite['assemblyName']
            require(member == 'lib/netstandard1.3/' + culture + '/' + assembly + '.dll'
                    and culture in p['cultures'] and satellite['assemblyVersion'] == '15.1.0.0'
                    and satellite['publicKeyToken'] == 'b03f5f7f11d50a3a'
                    and reader.embedded_component_commit(identity) == COMMIT, 'Original SDK5 resource-only ABI and embedded source differ')
            streams = {r['name']: r for r in satellite['resources']}
            require(len(streams) == len(satellite['resources']) and streams.keys() == p['resources'][member].keys(),
                    'Complete original SDK5 resource stream set required')
            for name, resource in sorted(streams.items()):
                values = reader.resource_strings(resource['data']); source = p['resources'][member][name]
                require(len(values) == source['keyCount'], 'Complete original SDK5 resource string count required')
                readable.append(dict(member=member, resource=name, culture=culture, sourceXlf=source['sourceXlf'], sourceResx=source['sourceResx'], values=values))
            relative = culture + '/' + assembly + '.dll'; bodies['resources/' + relative] = data
            products['sdk/' + SDK + '/' + relative] = fingerprint(data)
    require(len(readable) == 126 and sum(len(r['values']) for r in readable) == 21098, 'All126 SDK5 streams and21098 strings required')
    bodies['readable-resources.json'] = (json.dumps(readable, indent=2, ensure_ascii=False) + '\n').encode()
    bodies['origin.json'] = (json.dumps(dict(schemaVersion=1, sdkVersion=SDK, kind=KIND, sourceCommit=COMMIT,
        policySha256=POLICY_SHA256, package=p['package'], localBuildClaimed=False, byteIdenticalCompilationClaimed=False), indent=2) + '\n').encode()
    return bodies, readable, products


def compare_sources(readable, sources):
    exact = normalized = 0
    for row in readable:
        left, right = compare_resource(row['values'], sources[row['sourceXlf']], sources[row['sourceResx']], row['culture'])
        exact += left; normalized += right
    require((exact, normalized) == (20384, 714), 'Original SDK5 exact and CRLF-only translation totals differ')


def prepare(package, source, destination):
    source, destination = ordinary(source), ordinary(destination); p = policy(); sources = {}
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == COMMIT, 'Exact original SDK5 MSBuild source checkout required')
    for name, expected in p['sourceFiles'].items():
        path = ordinary(source / name); raw = path.read_bytes()
        require(fingerprint(raw) == {k:expected[k] for k in FP}
                and raw == subprocess.check_output(git + ['show', COMMIT + ':' + name]), 'Original SDK5 XLF, RESX or notice source differs')
        sources[name] = raw
    bodies, readable, _ = inspect(package); compare_sources(readable, sources)
    for name, raw in bodies.items():
        target = ordinary(destination / name); target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists() or target.read_bytes() == raw, 'Refusing to overwrite different SDK5 resource data')
        if not target.exists(): target.write_bytes(raw)
    require({p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()} == bodies.keys(), 'Unexpected SDK5 localization data files')
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, package):
    release = ordinary(release); p = policy(); reader = contract(); bodies, readable, products = inspect(package)
    require(manifest.get('sdkVersion') == SDK and manifest.get('targetRid') in ('linux-musl-arm64', 'linux-musl-x64'), 'SDK5 localization source delivery identity differs')
    roots = [r for r in manifest['roots'] if r.get('commit') == COMMIT and r['kind'] in ('git', 'git-export')]
    require(len(roots) == 1 and not roots[0].get('deleted') and not roots[0].get('exclude'), 'Complete original SDK5 MSBuild Git source root required')
    data = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data) == 1 and data[0]['kind'] == 'tree' and data[0]['role'] == ROLE and data[0].get('commit') is None,
            'SDK5 imported resource data cannot claim Git provenance')
    expected = {ROOT_NAME + '/' + name: fingerprint(raw) for name,raw in bodies.items()}
    expected.update({roots[0]['name'] + '/' + name:{k:row[k] for k in FP} for name,row in p['sourceFiles'].items()})
    index_path = reader.checked(release / 'sources', manifest['index'])
    archive_path = reader.checked(release / 'sources', manifest['archive'])
    index = {}
    with index_path.open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected or row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in index, 'Duplicate SDK5 resource source index member'); index[row['path']] = row
    require(index.keys() == expected.keys() and all(all(index[n].get(k) == fp[k] for k in FP) for n,fp in expected.items()),
            'Complete SDK5 original package, resources, readable data and93 source files required')
    actual, sources = set(), {}
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.isfile() and entry.name not in actual and entry.size == expected[entry.name]['bytes'] and entry.size <= 16 * 1024**2,
                    'Ordinary bounded SDK5 resource source archive member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == expected[entry.name], 'Archived SDK5 resource or source bytes differ')
            actual.add(entry.name); prefix = roots[0]['name'] + '/'
            if entry.name.startswith(prefix):
                name = entry.name[len(prefix):]
                require(index[entry.name].get('baseline', {}).get('blob') == p['sourceFiles'][name]['gitBlob'], 'Pristine original SDK5 resource source Git blob required')
                sources[name] = raw
    require(actual == expected.keys(), 'Archived original SDK5 resource and readable source data incomplete')
    compare_sources(readable, sources)
    return dict(kind=KIND, basis='original-sdk5-resource-only-pe-and-exact-xlf-resx', sourceRoot=roots[0]['name'], sourceCommit=COMMIT,
        allowedLayoutPaths=sorted(products), products=products, localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
