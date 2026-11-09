"""One isolated genuine SDK5 AppInsights PCL derivation; no SDK admission route."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import shlex
import shutil
import stat
import subprocess
import time
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET
import zipfile

SDK='5.0.214'
POLICY_SHA256='91980fa1ed93367e346050ca2db3528bdbe86af359ba2c7fb69372bd87819b25'
POLICY_FILE='musl-legacy5-appinsights-build-policy.json'
SOURCE_COMMIT='9b5b49f2a7697a2bf38f09ca2f2c97326c49d93b'
NS={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}


def require(value,message):
    if not value:raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def ordinary(path):
    path=Path(path).absolute();require(not any(p.is_symlink()for p in(path,*path.parents)),'Ordinary isolated App5 path required');return path


def file_fingerprint(path):
    path=ordinary(path);require(path.is_file(),'Ordinary App5 input file required');a=hashlib.sha256();b=hashlib.sha512();length=0
    with path.open('rb')as stream:
        while block:=stream.read(65536):a.update(block);b.update(block);length+=len(block)
    return dict(bytes=length,sha256=a.hexdigest(),sha512=b.hexdigest())


def write_json(path,value):
    path=ordinary(path);require(not path.exists(),'Fresh App5 evidence record required');path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n')


def api_module():
    spec=importlib.util.spec_from_file_location('sdk5_app_api_bytes',Path(__file__).with_name('musl_legacy5_appinsights_api.py'));api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api);return api


def policy():
    raw=ordinary(Path(__file__).with_name(POLICY_FILE)).read_bytes();require(hashlib.sha256(raw).hexdigest()==POLICY_SHA256,'Closed genuine App5 input policy differs');p=json.loads(raw)
    require(p['kind']=='sdk5-genuine-appinsights-pcl-build-policy'and p['sdkVersion']==SDK and p['source']['commit']==SOURCE_COMMIT
        and len(p['source']['files'])==437 and len(p['source']['compileItems'])==112 and p['referenceZip']['dllCount']==len(p['referenceZip']['assemblies'])==65
        and p['referenceZip']['supportFiles'].keys()=={'v4.5/RedistList/FrameworkList.xml'}
        and p['assembly']['targetFramework']=='.NETPortable,Version=v4.5,Profile=Profile7'and p['assembly']['delaySign']is True
        and p['assembly']['publicRelease']is True and p['assembly']['fileVersion']=='2.0.0.30671'
        and p['assembly']['defines']==['CORE_PCL','TRACE','CODE_ANALYSIS']
        and p['localPackage']['version']=='2.0.0-cbodotnet.1'and p['oldBinarySourceAttributed']is False
        and p['publisherSigningClaimed']is p['qualificationAllowed']is p['sourceAdmissionAllowed']is False,'Distinct original App5 PCL source/target/signing boundary required')
    return p


def copy_exact(source,target,expected):
    source,target=ordinary(source),ordinary(target);require(file_fingerprint(source)==expected,'Exact original App5 input bytes required');require(not target.exists(),'Fresh App5 retained input required');target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb')as first,target.open('xb')as second:shutil.copyfileobj(first,second,65536)
    require(file_fingerprint(target)==expected,'Retained App5 input copy differs')


def validate_reference_zip(path,p=None):
    p=p or policy();expected=p['referenceZip'];require(file_fingerprint(path)==expected['fingerprint'],'Exact original Profile7 reference ZIP required');bodies={};api=api_module()
    with zipfile.ZipFile(path)as archive:
        entries=archive.infolist();names=[e.filename for e in entries];require(len(names)==len(set(names))and len(names)<10000,'Unique bounded original reference ZIP required')
        licenses=[n for n in names if any(t in Path(n).name.lower()for t in('license','eula','copying'))]
        require(licenses==expected['embeddedLicenseFiles']==[] and expected['licenseAbsenceRetained']is True,'Original reference ZIP license absence must remain distinct')
        selected={e.filename[len(expected['prefix']):]:e for e in entries if e.filename.startswith(expected['prefix'])and not e.is_dir()}
        require(selected.keys()==expected['files'].keys(),'Complete exact original Profile7 member set required')
        for name,entry in selected.items():
            require(entry.file_size==expected['files'][name]['bytes']and entry.file_size<=4*1024**2 and entry.external_attr>>16&0o170000!=0o120000,'Ordinary bounded original Profile7 member required')
            raw=archive.read(entry);require(fingerprint(raw)==expected['files'][name],'Original Profile7 reference member bytes differ')
            if name.endswith('.dll'):require(name in expected['assemblies']and api.assembly_identity(raw)==expected['assemblies'][name],'Exact original Profile7 assembly contract identity required')
            bodies[name]=raw
    require(sum(n.endswith('.dll')for n in bodies)==65,'Complete 65-DLL Profile7 reference closure required');return bodies


def validate_targets(root,p=None):
    p=p or policy();root=ordinary(root);result={}
    for name,row in p['portableTargets']['files'].items():
        raw=ordinary(root/name).read_bytes();require(fingerprint(raw)=={k:row[k]for k in('bytes','sha256','sha512')}
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['gitBlob'],'Exact published Portable target source Git bytes required');result[name]=raw
    return result


def reference_support(path,p=None):
    p=p or policy();require(file_fingerprint(path)==p['referenceZip']['fingerprint'],'Exact original reference ZIP support input required');result={}
    with zipfile.ZipFile(path)as archive:
        for name,expected in p['referenceZip']['supportFiles'].items():
            entry=archive.getinfo('PortableReferenceAssemblies-2014-04-14/'+name);require(entry.file_size==expected['bytes']and entry.file_size<=65536 and entry.external_attr>>16&0o170000!=0o120000,'Ordinary original base framework metadata required')
            raw=archive.read(entry);require(fingerprint(raw)==expected,'Exact original base FrameworkList bytes required');result[name]=raw
    return result


def project_bytes(p=None):
    p=p or policy();sources='\n'.join('    <Compile Include="/inputs/source/'+escape(n,{'"':'&quot;'})+'" />'for n in p['source']['compileItems'])
    return ('''<Project ToolsVersion="Current" DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><BaseIntermediateOutputPath>/output/obj/</BaseIntermediateOutputPath><MSBuildProjectExtensionsPath>/output/obj/</MSBuildProjectExtensionsPath></PropertyGroup>
  <Import Project="$(MSBuildToolsPath)/Current/Microsoft.Common.props" />
  <Import Project="/inputs/source/GlobalStaticVersion.props" />
  <PropertyGroup>
    <OutputType>Library</OutputType><AssemblyName>Microsoft.ApplicationInsights</AssemblyName><RootNamespace>Microsoft.ApplicationInsights</RootNamespace>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion><TargetFrameworkProfile>Profile7</TargetFrameworkProfile>
    <TargetFrameworkRootPath>/inputs/reference-root/</TargetFrameworkRootPath><EnlistmentRoot>/inputs/source</EnlistmentRoot>
    <OutputPath>/output/app/</OutputPath><BaseIntermediateOutputPath>/output/obj/</BaseIntermediateOutputPath><IntermediateOutputPath>/output/obj/</IntermediateOutputPath>
    <LangVersion>6</LangVersion><DefineConstants>CORE_PCL;TRACE;CODE_ANALYSIS</DefineConstants><PlatformTarget>AnyCPU</PlatformTarget>
    <Optimize>true</Optimize><DebugSymbols>true</DebugSymbols><DebugType>portable</DebugType><WarningLevel>4</WarningLevel><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <NoStdLib>true</NoStdLib><NoConfig>true</NoConfig><UseSharedCompilation>false</UseSharedCompilation><Deterministic>true</Deterministic>
    <DocumentationFile>/output/app/Microsoft.ApplicationInsights.xml</DocumentationFile><AssemblyAttributesPath>/output/obj/AssemblyInfo.g.cs</AssemblyAttributesPath>
  </PropertyGroup>
  <Import Project="/inputs/source/Signing.targets" />
  <ItemGroup>
'''+sources+'''
    <Compile Include="$(AssemblyAttributesPath)" />
    <AssemblyAttributes Include="System.Reflection.AssemblyVersionAttribute"><_Parameter1>$(SemanticVersionMajor).$(SemanticVersionMinor).$(SemanticVersionPatch).0</_Parameter1></AssemblyAttributes>
    <AssemblyAttributes Include="System.Reflection.AssemblyFileVersionAttribute"><_Parameter1>$(SemanticVersionMajor).$(SemanticVersionMinor).$(SemanticVersionPatch).$(PreReleaseVersion)</_Parameter1></AssemblyAttributes>
  </ItemGroup>
  <Target Name="GenerateOriginalVersionAttributes" BeforeTargets="CoreCompile">
    <WriteCodeFragment Language="C#" AssemblyAttributes="@(AssemblyAttributes)" OutputFile="$(AssemblyAttributesPath)" />
  </Target>
  <Import Project="/inputs/portable/v4.5/Microsoft.Portable.CSharp.targets" />
</Project>
''').encode()


def prepare(source,reference_zip,targets,original_package,reader_source,destination):
    p=policy();destination=ordinary(destination);require(not destination.exists(),'Fresh isolated App5 workspace required');destination.mkdir(parents=True);inputs=destination/'inputs';inputs.mkdir();source=ordinary(source)
    git=['git','-c','safe.directory='+str(source),'-C',str(source)];require(subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()==SOURCE_COMMIT,'Exact original AppInsights source checkout required')
    commit=p['source']['commitObject'].encode();require(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==SOURCE_COMMIT
        and commit.startswith(('tree '+p['source']['tree']+'\n').encode()),'Authenticated original AppInsights commit object required')
    for name,row in p['source']['files'].items():
        fp={k:row[k]for k in('bytes','sha256','sha512')};copy_exact(source/name,inputs/'source'/name,fp);raw=ordinary(inputs/'source'/name).read_bytes();require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['gitBlob'],'Original App5 source Git blob differs');(inputs/'source'/name).chmod(0o755 if row['mode']=='100755'else 0o644)
    bodies=validate_reference_zip(reference_zip,p);copy_exact(reference_zip,inputs/'reference.zip',p['referenceZip']['fingerprint'])
    for name,raw in bodies.items():
        target=inputs/'reference-root/.NETPortable/v4.5/Profile/Profile7'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    for name,raw in reference_support(reference_zip,p).items():
        target=inputs/'reference-root/.NETPortable'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    prefix='mcs/tools/xbuild/data/Portable/Targets/'
    for name,raw in validate_targets(targets,p).items():
        target=inputs/('portable/'+name[len(prefix):]if name.startswith(prefix)else'licenses/Mono-target-LICENSE');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    copy_exact(original_package,inputs/'original.nupkg',p['originalPackage']['officialPackage'])
    reader_source=ordinary(reader_source)
    for name,fp in p['reader']['sourceFiles'].items():copy_exact(reader_source/name,inputs/'reader'/name,fp)
    (inputs/'recipe').mkdir();(inputs/'recipe/App.PCL.proj').write_bytes(project_bytes(p));(inputs/'NuGet.Config').write_bytes(b'<configuration><packageSources><clear /></packageSources></configuration>\n')
    for name in('musl_legacy5_appinsights.py','musl_legacy5_appinsights_api.py',POLICY_FILE):
        original=Path(__file__).with_name(name);copy_exact(original,inputs/'execution'/name,file_fingerprint(original))
    manifest={}
    for path in sorted(inputs.rglob('*')):
        if path.is_file():manifest[path.relative_to(inputs).as_posix()]=dict(**file_fingerprint(path),mode=stat.S_IMODE(path.stat().st_mode))
    write_json(destination/'input-manifest.json',dict(schemaVersion=1,kind='typed-pinned-app5-inputs',policySha256=POLICY_SHA256,files=manifest,originalSourceCommit=SOURCE_COMMIT,
        referenceLicenseEmbedded=False,portableTargetsSourceRepository=p['portableTargets']['repository'],portableTargetsSourceCommit=p['portableTargets']['commit'],
        originalPublisherCompilerInputsClaimed=False,oldBinarySourceAttributed=False,publisherSigningClaimed=False))
    (destination/'output').mkdir();(destination/'home').mkdir();return dict(workspace=str(destination),inputs=str(inputs),inputManifest=str(destination/'input-manifest.json'),sourceGitDir=str(source/'.git'),
        sdkVersion=SDK,sourceMountRoot='/inputs/source',automaticAppBuildRetry=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def run_record(command,log,env=None):
    started=time.time();log=ordinary(log);require(not log.exists(),'Fresh actual App5 process log required')
    with log.open('xb')as stream:process=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,env=env,check=False)
    return dict(command=command,exitCode=process.returncode,seconds=time.time()-started,log=dict(path=str(log),**file_fingerprint(log)))


def bound_host(environment,role):
    require(role in('/bootstrap','/inspector'),'Explicit App5 host role required');expected=role+':/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    require(environment.get('PATH')==expected and environment.get('DOTNET_ROOT')==role and environment.get('DOTNET_HOST_PATH')==role+'/dotnet','Exact controlled compiler host PATH/root required')
    path=shutil.which('dotnet',path=environment['PATH']);require(path==role+'/dotnet'and ordinary(path).is_file(),'Ordinary resolved compiler host must be exact bootstrap dotnet')
    return dict(PATH=expected,DOTNET_ROOT=role,DOTNET_HOST_PATH=role+'/dotnet',resolvedHost=dict(path=path,**file_fingerprint(path)))


def worker():
    require(os.getuid()!=0 and Path('/etc/alpine-release').read_text().strip()=='3.24.4','Native non-root original App5 worker environment required')
    p=policy();output=Path('/output');require(not any(output.iterdir()),'Fresh App5 output directory required');env=dict(os.environ,DOTNET_ROOT='/bootstrap',DOTNET_HOST_PATH='/bootstrap/dotnet',PATH='/bootstrap:/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',DOTNET_PROCESSOR_COUNT='1',MSBUILDDISABLENODEREUSE='1')
    app_command=['/bootstrap/dotnet','/bootstrap/sdk/5.0.401/MSBuild.dll','/inputs/recipe/App.PCL.proj','/t:Build','/m:1','/nr:false','/v:normal','/p:Configuration=Release','/p:PublicRelease=True','/p:PreReleaseVersion=30671','/p:AssemblyOriginatorKeyFile=/inputs/source/35MSSharedLib1024.snk','/p:UseSharedCompilation=false','/bl:/output/app.binlog']
    host=bound_host(env,'/bootstrap');app=run_record(app_command,output/'app-build.log',env);require(host==bound_host(env,'/bootstrap'),'Actual App5 host changed during compilation');app['hostBinding']=host;write_json(output/'actual-app-process.json',app)
    inspector_env=dict(env,DOTNET_ROOT='/inspector',DOTNET_HOST_PATH='/inspector/dotnet',PATH='/inspector:/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');reader_command=['/inspector/dotnet','/inspector/sdk/6.0.135/MSBuild.dll','/inputs/reader/Reader.csproj','/restore','/t:Build','/m:1','/nr:false','/v:normal','/p:BootstrapMajor=6','/p:BootstrapSdkDir=/inspector/sdk/6.0.135','/p:BaseIntermediateOutputPath=/output/reader-obj/','/p:OutputPath=/output/reader/','/p:RestoreConfigFile=/inputs/NuGet.Config','/p:UseSharedCompilation=false','/bl:/output/reader-build.binlog']
    host=bound_host(inspector_env,'/inspector');reader=run_record(reader_command,output/'reader-build.log',inspector_env);require(host==bound_host(inspector_env,'/inspector'),'Actual Reader build host changed');reader['hostBinding']=host;write_json(output/'actual-reader-build-process.json',reader)
    require(reader['exitCode']==0,'Actual frozen Reader build failed')
    replays=[]
    for name,sdk in [('app','/bootstrap/sdk/5.0.401'),('reader-build','/inspector/sdk/6.0.135')]:
        executable=file_fingerprint(output/'reader/Reader.dll');original_binlog=file_fingerprint(output/(name+'.binlog'))
        replay=run_record(['/inspector/dotnet','/output/reader/Reader.dll','/output/'+name+'.binlog',sdk,'/output/replay/'+name],output/(name+'-reader.log'),inspector_env)
        require(executable==file_fingerprint(output/'reader/Reader.dll')and original_binlog==file_fingerprint(output/(name+'.binlog')),'Reader executable or original binlog changed during actual replay')
        replay.update(readerExecutable=executable,originalBinlog=original_binlog);replays.append(replay)
    write_json(output/'actual-reader-processes.json',replays);require(all(r['exitCode']==0 for r in replays),'Actual frozen Reader replay failed');require(app['exitCode']==0,'Actual App5 compiler process failed')
    write_json(output/'worker-completed.json',dict(status='one-genuine-offline-app5-build-completed',appBuilds=1,readerBuiltFromFrozenSources=True,readerActuallyExecuted=True,network='none',publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False))


def verify_inputs(workspace):
    p=policy();workspace=ordinary(workspace);inputs=workspace/'inputs';manifest=json.loads((workspace/'input-manifest.json').read_bytes())
    require(manifest['kind']=='typed-pinned-app5-inputs'and manifest['policySha256']==POLICY_SHA256 and manifest['referenceLicenseEmbedded']is False
        and manifest['oldBinarySourceAttributed']is manifest['publisherSigningClaimed']is False,'Closed typed App5 reference/source/license roles required')
    actual={path.relative_to(inputs).as_posix():dict(**file_fingerprint(path),mode=stat.S_IMODE(path.stat().st_mode))for path in inputs.rglob('*')if path.is_file()}
    require(actual==manifest['files'],'Actual isolated App5 input bytes or file modes differ')
    prefix='mcs/tools/xbuild/data/Portable/Targets/'
    expected_names={'source/'+n for n in p['source']['files']}|{'reference-root/.NETPortable/v4.5/Profile/Profile7/'+n for n in p['referenceZip']['files']}
    expected_names|={'reference-root/.NETPortable/'+n for n in p['referenceZip']['supportFiles']}
    expected_names|={('portable/'+n[len(prefix):]if n.startswith(prefix)else'licenses/Mono-target-LICENSE')for n in p['portableTargets']['files']}
    expected_names|={'reader/'+n for n in p['reader']['sourceFiles']}|{'execution/'+n for n in('musl_legacy5_appinsights.py','musl_legacy5_appinsights_api.py',POLICY_FILE)}|{'reference.zip','original.nupkg','recipe/App.PCL.proj','NuGet.Config'}
    require(actual.keys()==expected_names,'Closed exact App5 input members required; optional target injections reject')
    for name,row in p['source']['files'].items():
        raw=ordinary(inputs/'source'/name).read_bytes();require(fingerprint(raw)=={k:row[k]for k in('bytes','sha256','sha512')}
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['gitBlob']
            and bool((inputs/'source'/name).stat().st_mode&0o111)==(row['mode']=='100755'),'Pristine original App5 source Git bytes or executable mode differ')
    validate_reference_zip(inputs/'reference.zip',p)
    for name,expected in p['referenceZip']['files'].items():require(file_fingerprint(inputs/'reference-root/.NETPortable/v4.5/Profile/Profile7'/name)==expected,'Actual complete Profile7 reference bytes differ')
    for name,expected in p['referenceZip']['supportFiles'].items():require(file_fingerprint(inputs/'reference-root/.NETPortable'/name)==expected,'Actual original base FrameworkList bytes differ')
    prefix='mcs/tools/xbuild/data/Portable/Targets/'
    for name,row in p['portableTargets']['files'].items():
        target=inputs/('portable/'+name[len(prefix):]if name.startswith(prefix)else'licenses/Mono-target-LICENSE');require(file_fingerprint(target)=={k:row[k]for k in('bytes','sha256','sha512')},'Actual original Portable target/source license differs')
    require((inputs/'recipe/App.PCL.proj').read_bytes()==project_bytes(p),'Plain App5 PCL adjunct recipe differs')
    for name,fp in p['reader']['sourceFiles'].items():require(file_fingerprint(inputs/'reader'/name)==fp,'Actual frozen Reader source bytes differ')
    for name in('musl_legacy5_appinsights.py','musl_legacy5_appinsights_api.py',POLICY_FILE):require(file_fingerprint(inputs/'execution'/name)==file_fingerprint(Path(__file__).with_name(name)),'Actual App5 execution source snapshot differs')
    require(file_fingerprint(inputs/'original.nupkg')==p['originalPackage']['officialPackage'],'Original publisher AppInsights package differs');return manifest


def _tasks(output,name):
    status=json.loads((output/'replay'/(name+'-status.json')).read_bytes());binlog=output/(name+'.binlog')
    require(status.get('schemaVersion')==1 and status.get('completedReplay')is True and status.get('buildSucceeded')is True and status.get('unfinishedTasks')==status.get('unfinishedSelectedTasks')==0
        and status.get('failure')is None and status.get('inputSha256')==file_fingerprint(binlog)['sha256'],'Actual complete Reader status must bind the original binary log')
    path=output/'replay'/(name+'-tasks.jsonl');require(path.stat().st_size<=32*1024**2,'Bounded actual App5 task stream required');tasks=[];contexts=set()
    with path.open(encoding='utf-8')as stream:
        for line in stream:
            require(len(line)<=8*1024**2,'Bounded actual App5 task record required');task=json.loads(line);events=task.get('events',[])
            require(task.get('context')not in contexts and len(events)>=2 and events[0]['kind']=='task-started'and events[-1]['kind']=='task-finished'
                and events[-1]['succeeded']==task.get('succeeded')and all(a['eventNumber']<=b['eventNumber']for a,b in zip(events,events[1:])),'Original unique completed App5 task context required');contexts.add(task['context']);tasks.append(task)
    require(len(tasks)==status['completedSelectedTasks'],'Actual Reader selected-task count differs');return tasks


def task_values(task,key):
    values={e['text']for e in task['events']if e['kind']=='task-parameter'and e['field']==key}
    for event in task['events']:
        if event['kind']!='message'or not isinstance(event.get('text'),str):continue
        message=event['text'];scalar='Task Parameter:'+key+'='
        if message.startswith(scalar):values.add(message[len(scalar):]);continue
        prefix='Task Parameter:\n    '+key+'=\n'
        if not message.startswith(prefix):continue
        item_seen=False
        for line in message[len(prefix):].splitlines():
            if not line.strip():continue
            if line.startswith('                '):
                require(item_seen and '='in line[16:],'Legacy Csc item metadata must follow its actual item');continue
            require(line.startswith('        ')and not line[8:].startswith(' '),'Exact legacy Csc parameter item indentation required');values.add(line[8:]);item_seen=True
    return values


def compiler_record(workspace,name,host_roots):
    workspace=ordinary(workspace);output=workspace/'output';tasks=_tasks(output,name);selected=[t for t in tasks if t['taskName']=='Csc'];require(len(selected)==1 and selected[0]['succeeded']is True,'One actual successful compiler task required: '+name);task=selected[0]
    values=lambda key:task_values(task,key)
    require(values('SkipCompilerExecution')<={'False','false'},'Actual compiler execution cannot be skipped');commands=list(dict.fromkeys(e['text']for e in task['events']if e['kind']=='command-line'and e.get('text')));require(len(commands)==1,'One actual compiler command line required');argv=shlex.split(commands[0]);bootstrap='/bootstrap'if name=='app'else'/inspector';version='5.0.401'if name=='app'else'6.0.135'
    process=json.loads((output/('actual-app-process.json'if name=='app'else'actual-reader-build-process.json')).read_bytes());binding=process.get('hostBinding',{});expected_path=bootstrap+':/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    require(binding.get('PATH')==expected_path and binding.get('DOTNET_ROOT')==bootstrap and binding.get('DOTNET_HOST_PATH')==bootstrap+'/dotnet'
        and binding.get('resolvedHost')==dict(path=bootstrap+'/dotnet',**file_fingerprint(ordinary(host_roots[bootstrap])/'dotnet')),'Actual ordinary resolved compiler host must bind controlled PATH and bootstrap bytes')
    require(argv[0]in(bootstrap+'/dotnet','dotnet')and argv[1:3]==['exec',bootstrap+'/sdk/'+version+'/Roslyn/bincore/csc.dll']and task['taskFile']==bootstrap+'/sdk/'+version+'/Roslyn/Microsoft.CSharp.Core.targets'
        and not values('EnvironmentVariables'),'Actual compiler must use its exact bound host/tool/targets without task environment overrides')
    project='/inputs/recipe/App.PCL.proj'if name=='app'else'/inputs/reader/Reader.csproj';require(task['projectFile']==project,'Actual compiler project differs')
    def absolute(value):
        require(isinstance(value,str)and value and '\\'not in value and not any(c in value for c in'\0\r\n'),'Ordinary original compiler input path required');return posixpath.normpath(value if value.startswith('/')else posixpath.join(posixpath.dirname(project),value))
    def host(value):
        value=absolute(value);matches=[ordinary(root)/value[len(prefix)+1:]for prefix,root in host_roots.items()if value.startswith(prefix+'/')];require(len(matches)==1,'Actual compiler file escapes its explicit mounts');return ordinary(matches[0])
    sources={absolute(v)for v in values('Sources')};references={absolute(v)for v in values('References')};require(sources and references,'Actual Csc source and reference task parameters required')
    command_sources={absolute(a)for a in argv[3:]if a.endswith('.cs')and ':'not in a and not a.startswith('-')}
    command_references=set()
    for a in argv[3:]:
        if a.lower().startswith(('/reference:','-reference:','/r:','-r:')):
            for value in a.split(':',1)[1].split(','):
                require('='not in value,'Unreviewed compiler reference alias');command_references.add(absolute(value))
    require(command_sources==sources and command_references==references and not any(a.startswith('@')for a in argv),'Actual Csc command sources/references must equal task parameters without hidden response files')
    source_fps={n:file_fingerprint(host(n))for n in sorted(sources)};reference_fps={n:file_fingerprint(host(n))for n in sorted(references)}
    if name=='app':
        p=policy();original={'/inputs/source/'+n for n in p['source']['compileItems']};expected_references={'/inputs/reference-root/.NETPortable/v4.5/Profile/Profile7/'+n for n in p['referenceZip']['files']if n.endswith('.dll')}
        require(original<=sources and len(sources-original)==2 and all(n.startswith('/output/obj/')and n.endswith('.cs')for n in sources-original),'Exactly 112 original C# inputs plus two controlled generated metadata sources required')
        require(references==expected_references,'Actual Csc must consume all and only the 65 original Profile7 references')
        for name_in_source in original:require(source_fps[name_in_source]=={k:p['source']['files'][name_in_source[len('/inputs/source/'):]][k]for k in('bytes','sha256','sha512')},'Actual Csc original source fingerprint differs')
        require(values('DelaySign')=={'True'}and values('KeyFile')=={'/inputs/source/35MSSharedLib1024.snk'}and values('DefineConstants')=={'CORE_PCL;TRACE;CODE_ANALYSIS'}and values('LangVersion')=={'6'},'Original public-only DelaySign/CORE_PCL/release-analysis/compiler language contract required')
        require('/delaysign+'in argv and '/keyfile:/inputs/source/35MSSharedLib1024.snk'in argv and '/nostdlib+'in argv and '/noconfig'in argv
            and not any(a.lower().startswith(('/publicsign','/analyzer:'))for a in argv),'Actual App5 compiler must use only original public-key DelaySign and closed references')
    else:
        p=policy();original={absolute(n)for n in p['reader']['sourceFiles']if n.endswith('.cs')};require(original<=sources,'Actual frozen Reader C# source consumption required')
        for n in original:require(source_fps[n]==p['reader']['sourceFiles'][posixpath.basename(n)],'Actually compiled frozen Reader source differs')
    outputs={absolute(v)for v in values('OutputAssembly')};command_outputs=[absolute(a.split(':',1)[1])for a in argv if a.lower().startswith('/out:')];require(len(outputs)==1 and command_outputs==list(outputs),'Actual Csc OutputAssembly and command differ');compiled=next(iter(outputs));final=output/('app/Microsoft.ApplicationInsights.dll'if name=='app'else'reader/Reader.dll');require(file_fingerprint(host(compiled))==file_fingerprint(final),'Actual compiler output and delivered local DLL differ')
    return dict(replayName=name,context=task['context'],projectFile=project,taskFile=task['taskFile'],commandLine=commands[0],compiler=dict(path=argv[2],**file_fingerprint(host(argv[2]))),sources=source_fps,references=reference_fps,compiledOutput=dict(path=compiled,**file_fingerprint(host(compiled))),finalOutput=dict(path=str(final),**file_fingerprint(final)))


def api_proof(workspace):
    workspace=ordinary(workspace);api=api_module()
    with zipfile.ZipFile(workspace/'inputs/original.nupkg')as package:original=package.read('lib/dotnet5.4/Microsoft.ApplicationInsights.dll')
    rebuilt=(workspace/'output/app/Microsoft.ApplicationInsights.dll').read_bytes();expected,actual=api.public_api(original),api.public_api(rebuilt)
    if expected!=actual:
        write_json(workspace/'output/original-public-api.json',expected);write_json(workspace/'output/rebuilt-public-api.json',actual)
    return api.compare(original,rebuilt)


def container_command(context):
    workspace=ordinary(context['workspace']);require(context['uid']>0 and context['gid']>0 and len(context['image'])==64
        and all(c in'0123456789abcdef'for c in context['image'])and context['sdkVersion']==SDK and context['sourceMountRoot']=='/inputs/source','Explicit original isolated App5 worker identity required')
    command=['podman','run','--rm','--network=none','--read-only','--user',str(context['uid'])+':'+str(context['gid']),'--cap-drop=all','--security-opt=no-new-privileges',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=128m']
    for name,value in dict(HOME='/home/build',DOTNET_CLI_HOME='/home/build',DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_MULTILEVEL_LOOKUP='0',DOTNET_PROCESSOR_COUNT='1',PYTHONDONTWRITEBYTECODE='1',NUGET_PACKAGES='/home/build/.nuget/packages').items():command+=['--env',name+'='+value]
    for source,target,mode in[(workspace/'inputs','/inputs','ro'),(workspace/'output','/output','rw'),(workspace/'home','/home/build','rw'),(ordinary(context['bootstrap5']),'/bootstrap','ro'),(ordinary(context['inspector6']),'/inspector','ro')]:command+=['--volume',str(source)+':'+target+':'+mode]
    return command+['--workdir','/output',context['image'],'python3','/inputs/execution/musl_legacy5_appinsights.py','--worker']


def execute(context,window_record):
    """One explicit call after Native grants the compiler window; no retry."""
    workspace=ordinary(context['workspace']);verify_inputs(workspace);require(isinstance(window_record,str)and len(window_record)>=20,'Explicit Native compiler window record required')
    require(not(workspace/'container-invocation.json').exists()and not any((workspace/'output').iterdir()),'Exactly one fresh App5 compiler attempt required')
    command=container_command(context);snapshot={n:file_fingerprint(Path(__file__).with_name(n))for n in('musl_legacy5_appinsights.py','musl_legacy5_appinsights_api.py',POLICY_FILE)}
    invocation=dict(kind='one-authorized-offline-private-app5-compiler-attempt',command=command,context=context,nativeWindow=window_record,executionSources=snapshot,automaticRetry=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    write_json(workspace/'container-invocation.json',invocation);result=run_record(command,workspace/'container.log');write_json(workspace/'container-result.json',result);verify_inputs(workspace)
    require(result['exitCode']==0,'Genuine App5 isolated compiler/Reader worker failed; evidence preserved without retry');return result


def local_nuspec(workspace):
    p=policy();source=ordinary(workspace)/'inputs/source/src/Core/NuGet/Core/Package.nuspec';original=ET.fromstring(source.read_bytes());groups=[x for x in original.iter('group')if x.get('targetFramework')=='dotnet5.4'];require(len(groups)==1 and len(groups[0])==19,'Original PCL dependency group required');dependencies=ET.tostring(groups[0],encoding='unicode').strip()
    return ('<?xml version="1.0" encoding="utf-8"?>\n<package><metadata><id>Microsoft.ApplicationInsights</id><version>'+p['localPackage']['version']+'</version><authors>cbodotnet local derivation of Microsoft source</authors><description>Genuine local PCL-only source build; not a Microsoft publisher binary.</description><license type="file">LICENSE</license><requireLicenseAcceptance>false</requireLicenseAcceptance><repository type="git" url="'+p['source']['repository']+'" commit="'+SOURCE_COMMIT+'"/><dependencies>'+dependencies+'</dependencies></metadata></package>\n').encode()


def verify_execution(workspace,host_roots):
    workspace=ordinary(workspace);output=workspace/'output';verify_inputs(workspace)
    require(host_roots.keys()=={'/inputs','/output','/bootstrap','/inspector'}and ordinary(host_roots['/inputs'])==workspace/'inputs'and ordinary(host_roots['/output'])==output,'Exact original App5 worker mount map required')
    invocation=json.loads((workspace/'container-invocation.json').read_bytes());container=json.loads((workspace/'container-result.json').read_bytes());require(invocation['command']==container_command(invocation['context'])==container['command']
        and container['exitCode']==0 and invocation['automaticRetry']is False and invocation['context']['workspace']==str(workspace),'Actual successful single offline App5 container invocation required')
    require(ordinary(host_roots['/bootstrap'])==ordinary(invocation['context']['bootstrap5'])and ordinary(host_roots['/inspector'])==ordinary(invocation['context']['inspector6']),'Actual compiler bootstrap mount origins must match execution')
    for name,fp in invocation['executionSources'].items():require(file_fingerprint(workspace/'inputs/execution'/name)==fp,'Actually executed App5 source snapshot differs')
    require(file_fingerprint(workspace/'container.log')=={k:container['log'][k]for k in('bytes','sha256','sha512')},'Actual App5 container log differs')
    done=json.loads((output/'worker-completed.json').read_bytes());require(done.get('status')=='one-genuine-offline-app5-build-completed'and done.get('appBuilds')==1
        and done.get('readerBuiltFromFrozenSources')is done.get('readerActuallyExecuted')is True and done.get('network')=='none'and done.get('publisherSigningClaimed')is False,'One actual offline source build and actual frozen Reader execution required')
    app=json.loads((output/'actual-app-process.json').read_bytes());reader=json.loads((output/'actual-reader-build-process.json').read_bytes());replays=json.loads((output/'actual-reader-processes.json').read_bytes())
    require(app['exitCode']==reader['exitCode']==0 and len(replays)==2 and all(r['exitCode']==0 for r in replays),'Successful original App5/Reader processes required')
    require(app['command'][:4]==['/bootstrap/dotnet','/bootstrap/sdk/5.0.401/MSBuild.dll','/inputs/recipe/App.PCL.proj','/t:Build']
        and '/p:PublicRelease=True'in app['command']and '/p:PreReleaseVersion=30671'in app['command']and '/m:1'in app['command']and '/nr:false'in app['command'], 'Original bounded deterministic App5 process command required')
    require(reader['command'][:3]==['/inspector/dotnet','/inspector/sdk/6.0.135/MSBuild.dll','/inputs/reader/Reader.csproj']and '/p:RestoreConfigFile=/inputs/NuGet.Config'in reader['command'],'Actual isolated frozen Reader source build command required')
    for record in[app,reader,*replays]:
        name=posixpath.basename(record['log']['path']);require(file_fingerprint(output/name)=={k:record['log'][k]for k in('bytes','sha256','sha512')},'Original actual App5 process log bytes differ')
    executable=file_fingerprint(output/'reader/Reader.dll')
    for record,(name,sdk)in zip(replays,[('app','/bootstrap/sdk/5.0.401'),('reader-build','/inspector/sdk/6.0.135')]):
        require(record['command']==['/inspector/dotnet','/output/reader/Reader.dll','/output/'+name+'.binlog',sdk,'/output/replay/'+name]
            and record['readerExecutable']==executable and record['originalBinlog']==file_fingerprint(output/(name+'.binlog')),'Actual frozen Reader executable/process must bind each original binary log')
    app_compiler=compiler_record(workspace,'app',host_roots);reader_compiler=compiler_record(workspace,'reader-build',host_roots)
    return dict(kind='actual-offline-app5-and-frozen-reader-execution',appCompiler=app_compiler,readerCompiler=reader_compiler,
        rawAppBinlog=file_fingerprint(output/'app.binlog'),rawReaderBuildBinlog=file_fingerprint(output/'reader-build.binlog'),readerExecutable=executable,
        actualSourceProcesses=[app,reader],actualBinaryReaderProcesses=replays,readerActuallyExecuted=True,oldBinarySourceAttributed=False,publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def package_local(workspace,host_roots):
    workspace=ordinary(workspace);execution=verify_execution(workspace,host_roots);api=api_proof(workspace);target=workspace/'output/microsoft.applicationinsights.2.0.0-cbodotnet.1.nupkg';require(not target.exists(),'Fresh genuine local App5 package required');bodies={'Microsoft.ApplicationInsights.nuspec':local_nuspec(workspace),'LICENSE':(workspace/'inputs/source/LICENSE').read_bytes()}
    for suffix in('dll','pdb','xml'):
        path=workspace/'output/app'/('Microsoft.ApplicationInsights.'+suffix);require(path.is_file()and path.stat().st_size>0,'All genuine PCL DLL/PDB/XML outputs required');bodies['lib/dotnet5.4/'+path.name]=path.read_bytes()
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as archive:
        for name,raw in sorted(bodies.items()):
            info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,raw)
    return dict(package=dict(path=str(target),**file_fingerprint(target)),members={n:fingerprint(raw)for n,raw in bodies.items()},api=api,execution=execution,originalPublisherPackageUnchanged=True,oldBinarySourceAttributed=False,publisherSigningClaimed=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',action='store_true');args=parser.parse_args();require(args.worker,'Explicit isolated worker mode required');worker()
