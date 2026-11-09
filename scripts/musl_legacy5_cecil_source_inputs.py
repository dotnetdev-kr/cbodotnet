"""SDK5 Cecil provenance declared by its original Linker package/source graph.

The source basis is the publisher's repository, Gitlink and project recipe.
Publisher compiler execution and local rebuilding are not claimed.
"""
import configparser
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
POLICY_SHA256 = 'e82f2c75a426bddf3c5900b725e4da58aff350bb7f4a81aa4760e17bb415fe88'
ROOT_NAME = 'sdk5-original-linker-cecil-declared-inputs'
ROLE = 'sdk5-original-linker-package-and-declared-cecil-source-recipe'
KIND = 'reviewed-sdk5-publisher-declared-cecil-source'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK5 Cecil source input required')
    return path


def policy():
    raw = Path(__file__).with_name('musl-legacy5-cecil-declared-source-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed SDK5 Cecil source policy differs')
    p = json.loads(raw)
    require(p['sdkVersion'] == SDK and p['kind'] == 'sdk5-publisher-declared-linker-cecil-source-policy'
            and p['linker']['commit'] == 'a3cca7a168d83444e833eceac61e721f97d5cfb2'
            and p['cecil']['commit'] == p['gitlink']['commit'] == '75fc419764f239dcdd679657316e6eae31e04dc2'
            and p['sourceBasis'] == 'publisher-declared-repository-gitlink-project-recipe' and len(p['products']) == 3
            and all(p[k] is False for k in ('publisherCompilerExecutionClaimed', 'localBuildClaimed', 'byteIdenticalCompilationClaimed')),
            'Distinct publisher-declared SDK5 Cecil identities required')
    return p


def xml(raw):
    require(len(raw) <= 2 * 1024**2 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Bounded original Cecil project XML without entities required')
    return ET.fromstring(raw)


def source_recipe(sources, p=None):
    p = p or policy()
    for role in ('linker', 'cecil'):
        require(sources[role].keys() == p[role]['files'].keys(), 'Complete original Cecil source recipe files required')
        for name, expected in p[role]['files'].items():
            raw = sources[role][name]
            require(fingerprint(raw) == {k:expected[k] for k in FP}
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['gitBlob'],
                    'Original Cecil source recipe or license Git bytes differ')
    gitmodules = configparser.ConfigParser(interpolation=None, strict=True)
    gitmodules.read_string(sources['linker']['.gitmodules'].decode('utf-8-sig'))
    require(gitmodules.sections() == ['submodule "cecil"'] and gitmodules['submodule "cecil"']['path'] == p['gitlink']['path']
            and gitmodules['submodule "cecil"']['url'] == p['gitlink']['repository'], 'Original publisher Cecil Gitlink declaration differs')
    defaults = list(xml(sources['linker']['Directory.Build.props']).iter('UseCecilPackage'))
    require(len(defaults) == 1 and defaults[0].text == 'false' and defaults[0].get('Condition') == "'$(UseCecilPackage)' == ''",
            'Original publisher source-project default must remain false')
    versions = [x for x in xml(sources['linker']['eng/Versions.props']).iter() if x.tag.rsplit('}', 1)[-1] == 'MonoCecilVersion']
    require(len(versions) == 1 and versions[0].text == '0.11.2', 'Original publisher Cecil version declaration differs')
    tasks = xml(sources['linker']['src/ILLink.Tasks/ILLink.Tasks.csproj'])
    require([x.text for x in tasks.iter('PackageId')] == ['Microsoft.NET.ILLink.Tasks']
            and [x.text for x in tasks.iter('TargetFrameworks')] == ['netcoreapp3.0;net472'], 'Original publisher Linker package and targets differ')
    references = [x for x in tasks.iter('ProjectReference') if x.get('Include') == '../../external/cecil/Mono.Cecil.csproj']
    require(len(references) == 1 and references[0].get('Condition') == "'$(UseCecilPackage)' != 'true'", 'Original Linker tasks must retain its Cecil project reference')
    linker = xml(sources['linker']['src/linker/Mono.Linker.csproj'])
    wanted = {'../../external/cecil/Mono.Cecil.csproj', '../../external/cecil/symbols/pdb/Mono.Cecil.Pdb.csproj'}
    refs = {x.get('Include').replace('\\', '/'):x for x in linker.iter('ProjectReference') if x.get('Include').replace('\\', '/') in wanted}
    require(refs.keys() == wanted and all(x.get('Condition') == "'$(UseCecilPackage)' != 'true'" for x in refs.values()), 'Both original Linker Cecil source projects required')
    for name in ('Mono.Cecil.csproj', 'symbols/pdb/Mono.Cecil.Pdb.csproj'):
        require([x.text for x in xml(sources['cecil'][name]).iter('TargetFrameworks')] == ['netstandard2.0;net40'], 'Original Cecil target frameworks differ')
    information = sources['cecil']['ProjectInfo.cs']
    require(re.findall(rb'AssemblyVersion\s*\(\s*"([^"]+)"\s*\)', information) == [b'0.11.2.0']
            and re.findall(rb'AssemblyFileVersion\s*\(\s*"([^"]+)"\s*\)', information) == [b'0.11.2.0'], 'Original Cecil assembly version source differs')
    return dict(sourceBasis=p['sourceBasis'], linkerCommit=p['linker']['commit'], cecilCommit=p['cecil']['commit'],
        gitlinkPath=p['gitlink']['path'], useCecilPackageDefault=False, linkerTargetFrameworks=['netcoreapp3.0', 'net472'],
        cecilTargetFrameworks=['netstandard2.0', 'net40'], publisherCompilerExecutionClaimed=False, localBuildClaimed=False)


def inspect_package(path, p=None):
    p = p or policy(); path = ordinary(path)
    require(path.is_file() and path.stat().st_size == p['package']['fingerprint']['bytes'], 'Exact original SDK5 Linker NPK required')
    raw = path.read_bytes(); require(fingerprint(raw) == p['package']['fingerprint'], 'Original SDK5 Linker NPK bytes differ')
    B = module('sdk5_cecil_metadata_bytes', 'musl_legacy_admission.py')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        node = p['package']['nuspec']; spec = archive.read(node['path']); require(fingerprint(spec) == {k:node[k] for k in FP}, 'Original publisher Linker nuspec differs')
        metadata = xml(spec).find('{*}metadata'); repository = metadata.find('{*}repository')
        require(metadata.findtext('{*}id') == p['package']['id'] and metadata.findtext('{*}version') == p['package']['version']
                and repository is not None and dict(repository.attrib) == dict(type='git', url='https://github.com/dotnet/linker', commit=p['linker']['commit']),
                'Original publisher Linker repository declaration required')
        for name, fp in p['package']['notices'].items(): require(fingerprint(archive.read(name)) == fp, 'Original publisher Linker notice bytes differ')
        for product in p['products'].values():
            data = archive.read(product['member']); require(fingerprint(data) == product['fingerprint'], 'Actual original SDK5 Cecil package member differs')
            identity = B.MANAGED.inspect(data)
            require(all(identity[k] == product[k] for k in ('assemblyName', 'assemblyVersion', 'publicKeyToken'))
                    and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0 and identity['cliFlags'] & 1,
                    'Actual original SDK5 Cecil managed identity differs')
    return raw


def bodies(raw, recipe):
    p = policy(); require(fingerprint(raw) == p['package']['fingerprint'], 'Retained original Linker package differs')
    return {'packages/' + p['package']['fingerprint']['sha256'] + '.nupkg':raw,
        'declared-source-recipe.json':(json.dumps(recipe, indent=2) + '\n').encode(),
        'origin.json':(json.dumps(dict(schemaVersion=1, sdkVersion=SDK, kind=KIND, policySha256=POLICY_SHA256,
            sourceBasis=p['sourceBasis'], publisherCompilerExecutionClaimed=False, localBuildClaimed=False,
            byteIdenticalCompilationClaimed=False), indent=2) + '\n').encode()}


def prepare(package, linker_source, cecil_source, destination):
    p = policy(); sources = {}
    for role, path in [('linker', linker_source), ('cecil', cecil_source)]:
        path = ordinary(path); git = ['git', '-c', 'safe.directory=' + str(path), '-C', str(path)]
        require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == p[role]['commit'], 'Exact original declared Cecil source checkout required')
        sources[role] = {name:ordinary(path / name).read_bytes() for name in p[role]['files']}
    data = bodies(inspect_package(package, p), source_recipe(sources, p)); destination = ordinary(destination)
    require(not destination.exists(), 'Fresh declared Cecil source input tree required'); destination.mkdir(parents=True)
    for name, raw in data.items():
        path = ordinary(destination / name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, package):
    p = policy(); release = ordinary(release); B = module('sdk5_cecil_source_bytes', 'musl_legacy_admission.py'); P = module('sdk5_cecil_source_tree', 'package-used-source.py')
    require(manifest.get('sdkVersion') == SDK and manifest.get('targetRid') in ('linux-musl-arm64', 'linux-musl-x64'), 'Independent SDK5 Cecil source delivery required')
    index_path = B.checked(release / 'sources', manifest['index']); archive_path = B.checked(release / 'sources', manifest['archive']); roots = {}
    for role in ('linker', 'cecil'):
        selected = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and r.get('commit') == p[role]['commit'] and r.get('tree') == p[role]['tree'] and not r.get('exclude') and not r.get('deleted')]
        require(len(selected) == 1, 'Complete pristine declared Cecil Git source required'); roots[role] = selected[0]
    require(roots['linker'].get('submodules') == [dict(path=p['gitlink']['path'], commit=p['cecil']['commit'], root=roots['cecil']['name'])], 'Original parent package source must bind its actual full Cecil Gitlink root')
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE and data_roots[0].get('commit') is None, 'Original Linker package data must retain its non-Git role')
    indexed, baselines = {}, {role:{} for role in roots}; prefixes = {r['name'] + '/':role for role,r in roots.items()}
    with index_path.open() as stream:
        for line in stream:
            row = json.loads(line); selected = next(((pre,role) for pre,role in prefixes.items() if row['path'].startswith(pre)), None)
            if selected:
                prefix, role = selected; name = row['path'][len(prefix):]
                require(row['path'] not in indexed and row.get('baseline'), 'Unique original Cecil source baseline required')
                indexed[row['path']] = (role,name,row); baselines[role][name] = row['baseline']
            elif row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in indexed, 'Duplicate original Cecil source data member'); indexed[row['path']] = (None,row['path'][len(ROOT_NAME)+1:],row)
    for role, baseline in baselines.items():
        for child in roots[role].get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
        require(P.baseline_tree(baseline) == p[role]['tree'], 'Complete original Cecil source tree baseline differs')
    sources, actual, seen = {r:{} for r in roots}, {}, set()
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            role, name, expected = indexed[entry.name]
            require(entry.isfile() and entry.name not in seen and entry.size == expected['bytes'] and entry.size <= 32 * 1024**2, 'Ordinary bounded original Cecil source member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k:expected[k] for k in FP}, 'Archived original Cecil source bytes differ')
            if role:
                require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['baseline']['blob'] and expected['mode'] == expected['baseline']['mode'], 'Pristine original Cecil source Git blob or mode differs')
                if name in p[role]['files']: sources[role][name] = raw
            else: actual[name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys(), 'Complete original Cecil source archive required')
    recipe = source_recipe(sources, p); require(actual == bodies(inspect_package(package, p), recipe), 'Original package and declared Cecil source recipe bytes differ')
    products = {name:dict(row, allowedPackageMembers=[dict(packageSha256=row['packageSha256'], member=row['member'])], sourceRoot=roots['cecil']['name'],
        sourceCommit=p['cecil']['commit'], publisherDeclaredParentRoot=roots['linker']['name'], publisherDeclaredParentCommit=p['linker']['commit'], sourceBasis=p['sourceBasis']) for name,row in p['products'].items()}
    return dict(kind=KIND, dataRoot=ROOT_NAME, products=products, sourceBasis=p['sourceBasis'], publisherCompilerExecutionClaimed=False,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
