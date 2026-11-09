"""Four SDK5 original data transforms and copied task-provider identities.

These are partial byte/source-file checks. No entry executes tools, obtains
sources, changes raw observations, or authenticates a task's actual CLR loads.
Full source/normal construction and admission remain separate required gates.
"""
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile

import musl_legacy5_component_evidence as CE
import musl_legacy5_newtonsoft_source_inputs as J

POLICY_SHA256='b2591d55209ab086a8a15bea8c38c90251d5f0b54aa41b28ff33135ce7c41970'
FP=('bytes','sha256','sha512')
MAX_INPUT=16*1024**2
MAX_TOTAL=64*1024**2
PENDING=('actual-archive-backed-source-trees-and-objects-modes',
 'actual-original-installer-Csc-and-provider-load-binding',
 'original-task-parameters-chronology-Copy-final-archive-binding','actual-both-CPU-normal-SDK-consumers')
require=CE.require


def fingerprint(raw):
    require(type(raw)is bytes,'Actual byte body required; descriptors are insufficient')
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def ordinary(value,*,directory=False):
    require(isinstance(value,(str,Path)),'Actual ordinary file path required; descriptors are insufficient')
    path=Path(value)
    require(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),
        'Ordinary absolute generated-data input path required')
    require(path.exists(),'Actual generated-data input is absent')
    mode=path.lstat().st_mode
    require(not mode&0o7000 and (stat.S_ISDIR(mode)if directory else stat.S_ISREG(mode)),
        'Ordinary generated-data input with safe mode required')
    return path


def body(value,*,allow_bytes=False):
    if allow_bytes and type(value)is bytes:raw=value
    else:
        path=ordinary(value);require(path.stat().st_size<=MAX_INPUT,'Bounded original generated-data file required')
        with path.open('rb')as stream:raw=stream.read(MAX_INPUT+1)
    require(len(raw)<=MAX_INPUT,'Bounded actual generated-data bytes required')
    return raw


def unique_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate original JSON property is forbidden');result[key]=value
        return result
    require(type(raw)is bytes and len(raw)<=MAX_INPUT,'Bounded original JSON bytes required')
    return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs)


def policy():
    raw=body(Path(__file__).with_name('musl-legacy5-generated-data-policy.json'))
    require(fingerprint(raw)['sha256']==POLICY_SHA256,'Immutable four-data/provider partial policy differs')
    p=unique_json(raw)
    require(p['schemaVersion']==1 and p['sdkVersion']=='5.0.214'
        and p['kind']=='sdk5-exact-four-data-and-copied-task-provider-partial-policy'
        and p['observedArchitecture']=='aarch64'and p['observedRid']=='linux-musl-arm64'
        and (len(p['sourceFiles']),len(p['dataPackages']),len(p['dataOutputs']),len(p['providerPackages']),
             len(p['providerMembers']),len(p['ownedTaskFiles']))==(13,3,4,11,13,3)
        and tuple(p['pendingFullConstruction'])==PENDING
        and all(p[k]is False for k in('referenceBootstrapPolicyBroadened','rawUnknownObservationsChanged',
            'rawCorrespondenceChanged','publisherCompilerExecutionClaimed','actualRuntimeLoadsAuthenticated',
            'fullProviderSourceClosure','wholeSourceClosure','qualificationAllowed','sourceAdmissionAllowed')),
        'Closed original four-data/provider scope required')
    return p


def _package(path,want,member):
    raw=body(path);require(fingerprint(raw)==want['fingerprint'],'Exact original whole package bytes required')
    with zipfile.ZipFile(io.BytesIO(raw))as archive:
        entries=archive.infolist();names=[r.filename for r in entries]
        require(len(names)==len(set(names))and len(names)<=8192,'Unique bounded original package members required')
        for row in entries:
            mode=row.external_attr>>16
            require(not row.filename.startswith('/')and '\\'not in row.filename and '..'not in PurePosixPath(row.filename).parts
                and not row.flag_bits&1 and row.file_size<=MAX_INPUT and not mode&0o7000
                and stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR),'Ordinary bounded original package member required')
        require(names.count(member)==1 and names.count(want['nuspec']['path'])==1,'Exact unique original package member/nuspec required')
        spec=archive.read(want['nuspec']['path'])
        require(fingerprint(spec)==want['nuspec']['fingerprint']and b'<!DOCTYPE'not in spec.upper()and b'<!ENTITY'not in spec.upper(),
            'Exact original package metadata without XML entities required')
        metadata=ET.fromstring(spec).find('{*}metadata');repo=metadata.find('{*}repository')
        require(metadata.findtext('{*}id')==want['id']and metadata.findtext('{*}version')==want['version']
            and (dict(repo.attrib)if repo is not None else None)==want['repository'],
            'Original package identity and repository metadata must remain unchanged')
        return archive.read(member)


def source_file_correspondence(source_files):
    p=policy();require(type(source_files)is dict and set(source_files)==set(p['sourceFiles']),
        'All exact original data recipe source files required')
    result={};total=0
    for key,want in p['sourceFiles'].items():
        raw=body(source_files[key],allow_bytes=True);total+=len(raw)
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        require(total<=MAX_TOTAL and fingerprint(raw)==want['fingerprint']and blob==want['gitBlob'],
            'Exact original authored source file bytes and Git blob required: '+key)
        result[key]=raw
    return result


def expand_runtime_graph(raw,rid):
    graph=unique_json(raw);require(type(graph)is dict and type(graph.get('runtimes'))is dict,'Original runtime graph required')
    require(isinstance(rid,str)and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',rid)
        and rid in graph['runtimes'],'Declared original runtime identifier required')
    queue=[rid];seen=set();ordered=[]
    while queue:
        current=queue.pop(0)
        if current in seen:continue
        seen.add(current);ordered.append(current)
        require(len(ordered)<=4096,'Bounded original runtime graph expansion required')
        row=graph['runtimes'].get(current,{})
        require(type(row)is dict and type(row.get('#import',[]))is list,'Original runtime import array required')
        for parent in row.get('#import',[]):
            require(isinstance(parent,str)and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',parent),
                'Ordinary original runtime import required')
            queue.append(parent)
    return '\n'.join(ordered).encode()


def replace_tool_runtime_version(raw):
    value=unique_json(raw)
    require(type(value)is dict and value.get('runtimeOptions')==dict(tfm='net5.0',
        framework=dict(name='Microsoft.NETCore.App',version='5.0.0')),
        'Exact original tool runtime options required')
    require(raw.count(b'"version": "5.0.0"')==1 and b'Microsoft.AspNetCore.App'not in raw,
        'One original .NET runtime version replacement required')
    result,count=re.subn(rb'"version": ".*"',b'"version": "5.0.17"',raw)
    require(count==1,'One exact original ReplaceFileContents match required')
    return result


def reconstruct(source_files,packages,*,rid):
    p=policy();sources=source_file_correspondence(source_files)
    require(rid==p['observedRid'],'Only the actually observed aarch64 data construction is established')
    require(type(packages)is dict and set(packages)==set(p['dataPackages']),'All three exact original data packages required')
    graph_source=sources[p['graphSourceKey']]
    require(b'\r'not in graph_source and graph_source.count(b'\n')==3198,'Exact original LF graph source required')
    outputs={};graph=None
    for name,want in p['dataOutputs'].items():
        if want['kind']=='original-runtime-graph-expansion':continue
        sha=want['packageSha256'];original=_package(packages[sha],p['dataPackages'][sha],want['member'])
        require(fingerprint(original)==want['originalInput'],'Exact original data member bytes required')
        if want['kind']=='original-package-copy':
            require(original==graph_source.replace(b'\n',b'\r\n'),'Only the exact original graph LF-to-CRLF byte bridge is allowed')
            result=graph=original
        else:
            require(want['kind']=='exact-original-runtime-version-replacement','Unreviewed generated-data transform')
            result=replace_tool_runtime_version(original)
        require(fingerprint(result)==want['fingerprint'],'Exact original transformed data bytes required');outputs[name]=result
    require(graph is not None,'Actual original graph package member required')
    for name,want in p['dataOutputs'].items():
        if want['kind']=='original-runtime-graph-expansion':
            result=expand_runtime_graph(graph,rid);require(fingerprint(result)==want['fingerprint'],'Exact observed original runtime chain required');outputs[name]=result
    require(set(outputs)==set(p['dataOutputs']),'Only the four closed original data outputs are permitted')
    return dict(kind='partial-original-SDK5-four-data-byte-reconstruction',outputs=outputs,sourceFilesMatched=len(sources),
        sourceArchiveValidated=False,publisherCompilerExecutionClaimed=False,actualRuntimeLoadsAuthenticated=False,
        fullProviderSourceClosure=False,wholeSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def validate_reconstruction(source_files,packages,actual_outputs,*,rid):
    result=reconstruct(source_files,packages,rid=rid)
    require(type(actual_outputs)is dict and set(actual_outputs)==set(result['outputs']),'All four actual original data output files required')
    correspondences={}
    for name,expected in result.pop('outputs').items():
        actual=body(actual_outputs[name]);require(actual==expected,'Actual original final data output differs: '+name)
        correspondences[name]=fingerprint(actual)
    return dict(**result,correspondences=correspondences,finalArchiveBindingAuthenticated=False,
        actualTaskChronologyAuthenticated=False)


def _provider_source(metadata,want,package):
    require(metadata['assemblyName']==want['assemblyName']and metadata['assemblyVersion']==want['assemblyVersion']
        and metadata['references']==want['assemblyReferences']
        and metadata['attributes'].get('System.Reflection.AssemblyInformationalVersionAttribute',[])==want['assemblyInformationalVersions']
        and CE.B.embedded_component_source(metadata)==want['originalEmbeddedSource'],
        'Exact original provider assembly identity and dependency metadata required')
    source=want['sourceRequirement']
    if source['kind']=='original-full-assembly-informational-Git-identity':
        require(want['originalEmbeddedSource']==dict(sourceCommit=source['commit'],basis='assembly-informational-version'),
            'Original full provider Git identity required')
        if package['repository']is not None:
            require(package['repository'].get('commit')==source['commit']
                and package['repository'].get('url','').lower()==source['repository'].lower(),
                'Original provider nuspec and assembly source identity must agree')
    elif source['kind']=='original-short-Git-prefix-and-official-unique-commit-resolution':
        require(want['originalEmbeddedSource']is None and source['prefix']=='ac19036b0d'
            and source['commit']=='ac19036b0de4f1b58c3be76d51000df8db98560c'
            and want['assemblyInformationalVersions']==['15.7.179+g'+source['prefix']],
            'Distinct original short Git prefix provenance required; no invented full embedded SHA')
    else:
        require(source['kind']=='original-Json9-publisher-source-policy-required'and package['id']=='Newtonsoft.Json'
            and package['version']=='9.0.1'and want['originalEmbeddedSource']is None
            and J.POLICY_SHA256==source['sourcePolicySha256'],
            'Original Json9 publisher policy required without invented embedded metadata')
        J.policy()
    return source


def provider_identities(actual_output_root,packages):
    p=policy();root=ordinary(actual_output_root,directory=True)
    require(type(packages)is dict and set(packages)==set(p['providerPackages']),'All eleven exact original provider packages required')
    expected={**{name:row['fingerprint']for name,row in p['providerMembers'].items()},**p['ownedTaskFiles']}
    candidates=set();total=0
    for path in root.rglob('*'):
        if path.is_dir():ordinary(path,directory=True);continue
        ordinary(path);total+=path.stat().st_size;require(total<=MAX_TOTAL,'Bounded actual task output tree required')
        with path.open('rb')as stream:prefix=stream.read(2)
        if path.suffix.lower()in('.dll','.json')or prefix==b'MZ':candidates.add(path.relative_to(root).as_posix())
    require(candidates==set(expected),'Complete original copied provider/task/deps set required; no omitted or extra PE')
    actual={name:body(root/name)for name in expected}
    require(all(fingerprint(raw)==expected[name]for name,raw in actual.items()),'Exact original task/deps/provider bytes required')
    deps=unique_json(actual['core-sdk-tasks.deps.json']);target=deps['targets'][deps['runtimeTarget']['name']]
    identities={};requirements={};all_references=set()
    for name,want in p['providerMembers'].items():
        package=p['providerPackages'][want['packageSha256']]
        original=_package(packages[want['packageSha256']],package,want['member'])
        require(actual[name]==original,'Actual copied provider must equal its exact original package member')
        matches=[]
        for key,lib in target.items():
            for role in('runtime','runtimeTargets'):
                for member in lib.get(role,{}):
                    if (role=='runtime'and Path(member).name==name)or(role=='runtimeTargets'and member==name):matches.append((key,member,role))
        require(len(matches)==1,'One original declared runtime asset for each actual copied provider required')
        key,member,role=matches[0];pkg_id,pkg_version=key.split('/',1)
        require(member==want['member']and role==want['declaredAssetRole']and pkg_id.lower()==package['id'].lower()
            and pkg_version==package['version'].split('+',1)[0]and deps['libraries'][key]['type']=='package',
            'Exact original deps library/runtime-or-Windows asset identity required')
        metadata=CE.B.MANAGED.inspect(actual[name]);source=_provider_source(metadata,want,package)
        source_key=(source.get('repository','publisher-policy'),source.get('commit',source.get('sourcePolicySha256')))
        require(source_key not in requirements or requirements[source_key]['source']==source,'Conflicting source requirements for one origin')
        group=requirements.setdefault(source_key,dict(source=source,providers=[]));group['providers'].append(name)
        all_references.update((row['name'],row['version'])for row in metadata['references'])
        identities[name]=dict(fingerprint=fingerprint(actual[name]),packageSha256=want['packageSha256'],member=member,
            declaredAssetRole=role,sourceRequirement=source,actualRuntimeLoadAuthenticated=False)
    require(all(fingerprint(body(root/name))==want for name,want in expected.items()),'Original task output changed during read-only validation')
    return dict(kind='partial-original-SDK5-copied-task-provider-identities',copiedProviderCount=len(identities),
        uniqueOriginalPackages=len(packages),providers=identities,sourceRequirements=list(requirements.values()),
        declaredAssemblyReferences=[dict(name=name,version=version)for name,version in sorted(all_references)],
        sourceArchiveValidated=False,actualTaskSourceCompilationAuthenticated=False,actualRuntimeLoadsAuthenticated=False,
        allRuntimeDependenciesClosed=False,fullProviderSourceClosure=False,wholeSourceClosure=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)


def validate_full(**inputs):
    raise ValueError('Full four-data construction pending: '+', '.join(PENDING)+
        '; byte hashes, deps, descriptors and callbacks cannot establish full source or runtime use')
