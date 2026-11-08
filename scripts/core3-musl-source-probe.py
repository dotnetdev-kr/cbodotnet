#!/usr/bin/env python3
"""Reproduce bounded Core3.1 source components and default certificate validation.

The input SDK supplies private bootstrap PE/data only. This helper never emits a
complete SDK, releases an archive, or changes source global.json/version pins.
"""
import argparse,hashlib,json,os,pathlib,platform,resource,shutil,subprocess,tarfile,tempfile,time,zipfile
import musl_archive as MUSL

ROOT=pathlib.Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mode',choices=('source-components','source-package','negative','negative-consumer'),required=True)
p.add_argument('--inputs-dir',type=pathlib.Path)
p.add_argument('--bootstrap-inputs-dir',type=pathlib.Path)
p.add_argument('--native-evidence',type=pathlib.Path)
p.add_argument('--trace-evidence',type=pathlib.Path)
p.add_argument('--runtime-dir',type=pathlib.Path)
p.add_argument('--application-dir',type=pathlib.Path)
p.add_argument('--output-dir',type=pathlib.Path,required=True)
args=p.parse_args();profile=json.loads((ROOT/'profiles/experimental/core3-musl-source.json').read_text())
if platform.system()!='Linux' or platform.machine()!=profile['nativeArchitecture'] or os.geteuid()==0 or pathlib.Path('/etc/alpine-release').read_text().strip()!=profile['alpine'] or shutil.which('dotnet'):
 raise SystemExit('Exact native ARM64, non-root, SDK-free Alpine probe environment required')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def ordinary(path):
 if path is None:raise SystemExit('Required input directory is absent')
 path=path.absolute()
 if path==pathlib.Path(path.anchor) or '..' in path.parts or any(q.is_symlink() for q in (path,*path.parents)):raise SystemExit('Ordinary absolute control paths required')
 return path
out=ordinary(args.output_dir);out.mkdir(parents=True,exist_ok=True)
if any(out.iterdir()):raise SystemExit('A new empty output directory is required')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(name,value):
 target=out/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(value,indent=2)+'\n')
def pinned(path,pin):
 raw=path.read_bytes()
 if len(raw)!=pin['bytes'] or sha(raw)!=pin['sha256'] or 'sha512' in pin and hashlib.sha512(raw).hexdigest()!=pin['sha512']:raise SystemExit('Pinned input differs: '+str(path))
 return raw
temporary=tempfile.TemporaryDirectory(prefix='cbodotnet-core31-source-');work=pathlib.Path(temporary.name)
env=dict(os.environ,HOME=str(work/'home'),DOTNET_CLI_HOME=str(work/'home'),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_NOLOGO='1',DOTNET_MULTILEVEL_LOOKUP='0',DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='false',DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER='1',DOTNET_PROCESSOR_COUNT='2',MSBUILDDISABLENODEREUSE='1')
records=[]
def run(name,command,cwd=None,timeout=360):
 log=out/(name+'.log');start=time.monotonic()
 with log.open('x') as stream:
  stream.write(json.dumps(command)+'\n');stream.flush();child=subprocess.Popen(command,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
  try:code=child.wait(timeout=timeout)
  except subprocess.TimeoutExpired:os.killpg(child.pid,15);child.wait(timeout=5);code=124
 records.append(dict(name=name,command=command,cwd=str(cwd) if cwd else None,exitCode=code,seconds=round(time.monotonic()-start,2),log=log.name,sha256=sha(log.read_bytes())))
 return code
fixture=ROOT/profile['negativeFixture']['path']
if sha(fixture.read_bytes())!=profile['negativeFixture']['sha256']:raise SystemExit('Shared reviewed certificate fixture differs')
if args.mode=='negative-consumer':
 boot=ordinary(args.runtime_dir);application=ordinary(args.application_dir)
 if (boot/'sdk').exists() or shutil.which('cc') or shutil.which('clang'):raise SystemExit('Runtime-only certificate probe requires no SDK/compiler')
 if sha((application/'Negative.cs').read_bytes())!=profile['negativeFixture']['sha256']:raise SystemExit('Compiled application fixture source differs')
 env.update(DOTNET_ROOT=str(boot),COMPlus_ReadyToRun='1')
 run('runtime-info',[str(boot/'dotnet'),'--info'],timeout=90)
 run('negative-certificates',[str(boot/'dotnet'),str(application/'Negative.dll')],timeout=120)
 write('application-inputs.json',[dict(path=q.name,bytes=q.stat().st_size,sha256=sha(q.read_bytes())) for q in sorted(application.iterdir()) if q.is_file()])
else:
 inputs=ordinary(args.inputs_dir);bootstrap_inputs=ordinary(args.bootstrap_inputs_dir);native=ordinary(args.native_evidence);trace=ordinary(args.trace_evidence)
 boot=work/'bootstrap';boot.mkdir();pinned(inputs/profile['bootstrapRuntime']['name'],profile['bootstrapRuntime']);pinned(bootstrap_inputs/profile['bootstrapSdk']['name'],profile['bootstrapSdk'])
 with tarfile.open(inputs/profile['bootstrapRuntime']['name']) as archive:archive.extractall(boot,filter='data')
 imported=[];excluded=[]
 with tarfile.open(bootstrap_inputs/profile['bootstrapSdk']['name'],mode='r|gz') as archive:
  for member in archive:
   name=str(pathlib.PurePosixPath(member.name));assert not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts
   if not member.isfile():continue
   raw=archive.extractfile(member).read();row=dict(path=name,bytes=len(raw),sha256=sha(raw))
   if raw[:4]==b'\x7fELF':excluded.append(row);continue
   if name.startswith(('sdk/','packs/','templates/')):
    target=boot/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(member.mode&0o755);imported.append(row)
 framework=boot/'shared/Microsoft.NETCore.App/3.1.32'
 for kind,root,target in [('crypto',native,'System.Security.Cryptography.Native.OpenSsl.so'),('trace',trace,'libcoreclrtraceptprovider.so')]:
  pin=profile['nativeCandidates'][kind];raw=pinned(root/pin['relativePath'],pin);(framework/target).write_bytes(raw)
 bundled=boot/'sdk/3.1.425/Microsoft.NETCoreSdk.BundledVersions.props';raw=bundled.read_bytes();pin=profile['privateBootstrapRidMetadata']
 if sha(raw)!=pin['originalSha256']:raise SystemExit('Original bootstrap RID metadata differs')
 adapted=raw.replace(b'<NETCoreSdkRuntimeIdentifier>linux-arm64</NETCoreSdkRuntimeIdentifier>',b'<NETCoreSdkRuntimeIdentifier>linux-musl-arm64</NETCoreSdkRuntimeIdentifier>')
 if sha(adapted)!=pin['adaptedSha256']:raise SystemExit('Private bootstrap RID metadata adaptation differs')
 bundled.write_bytes(adapted);write('private-bootstrap.json',dict(inputSdk=profile['bootstrapSdk'],inputRuntime=profile['bootstrapRuntime'],importedPeData=imported,excludedEverySdkElf=excluded,ridMetadata=pin,product=False,readyToRunDisabledOnlyPrivateBootstrap=True))
 env.update(DOTNET_ROOT=str(boot),DOTNET_INSTALL_DIR=str(boot),COMPlus_ReadyToRun='0',PATH=str(boot)+':'+env['PATH'])
 run('bootstrap-info',[str(boot/'dotnet'),'--info'],timeout=90)
 if args.mode=='negative':
  app=work/'negative';app.mkdir();(app/'Negative.cs').write_bytes(fixture.read_bytes());refs=next((boot/'packs/Microsoft.NETCore.App.Ref').glob('*/ref/netcoreapp3.1'))
  (app/'compile.rsp').write_text('/noconfig\n/nostdlib+\n/target:exe\n/out:'+str(app/'Negative.dll')+'\n'+'\n'.join('/r:'+str(q) for q in sorted(refs.glob('*.dll')))+'\n'+str(app/'Negative.cs')+'\n')
  (app/'Negative.runtimeconfig.json').write_text(json.dumps(dict(runtimeOptions=dict(tfm='netcoreapp3.1',framework=dict(name='Microsoft.NETCore.App',version='3.1.32')))))
  if run('compile-negative',[str(boot/'dotnet'),str(boot/'sdk/3.1.425/Roslyn/bincore/csc.dll'),'@'+str(app/'compile.rsp')])==0:
   for q in app.iterdir():target=out/'application'/q.name;target.parent.mkdir(exist_ok=True);target.write_bytes(q.read_bytes())
   run('negative-worker-execution',[str(boot/'dotnet'),str(app/'Negative.dll')],timeout=120)
 else:
  sources={}
  for pin in profile['sourceInputs']:
   archive_path=inputs/(pin['name']+'.tar.gz');pinned(archive_path,pin);dest=work/pin['name'];dest.mkdir()
   with tarfile.open(archive_path) as archive:archive.extractall(dest,filter='data')
   source=next(dest.iterdir());sources[pin['name']]=source;global_json=json.loads((source/'global.json').read_text())
   if global_json['tools']['dotnet']!='3.1.425' or global_json['msbuild-sdks']['Microsoft.DotNet.Arcade.Sdk']!='1.0.0-beta.22558.6':raise SystemExit('Original component global pin differs')
   for relative in ['global.json','NuGet.config','Directory.Build.props','Directory.Build.targets','eng/Versions.props','eng/Version.Details.xml']:
    q=source/relative
    if q.is_file():target=out/'original-source-files'/pin['name']/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(q.read_bytes())
  props=out/'record-properties.targets';props.write_text('<Project><Target Name="RecordMuslProperties" BeforeTargets="BeforeBuild"><WriteLinesToFile File="'+str(out/'evaluated-properties.txt')+'" Lines="NETCoreSdkRuntimeIdentifier=$(NETCoreSdkRuntimeIdentifier);ToolsRID=$(ToolsRID);RuntimeIdentifier=$(RuntimeIdentifier);ProductMonikerRid=$(ProductMonikerRid);TargetFramework=$(TargetFramework);RepositoryCommit=$(RepositoryCommit)" Overwrite="false" /></Target></Project>')
  common=['/p:Configuration=Release','/p:NETCoreSdkRuntimeIdentifier=linux-musl-arm64','/p:ToolsRID=linux-musl-arm64','/p:DotNetBuildFromSource=true','/p:EnableSourceLink=false','/p:EnableSourceControlManagerQueries=false','/p:DeterministicSourcePaths=false','/p:UseSharedCompilation=false','/p:DisableSourceLink=true','/p:CustomAfterMicrosoftCommonTargets='+str(props),'/m:2','/nologo']
  package_mode=args.mode=='source-package'
  projects=[('sdk31','src/Tasks/Microsoft.NET.Build.Tasks/Microsoft.NET.Build.Tasks.csproj',None if package_mode else 'netcoreapp2.1','Build;Pack' if package_mode else 'Build'),('core-sdk31','src/redist/redist.csproj' if package_mode else 'src/core-sdk-tasks/core-sdk-tasks.csproj','netcoreapp3.1','BuildCoreSdkTasks;GenerateBundledVersionsProps' if package_mode else 'Build')]
  for name,relative,tfm,target in projects:
   source=sources[name];pin=next(q for q in profile['sourceInputs'] if q['name']==name)
   command=[str(boot/'dotnet'),'msbuild',str(source/relative),*common,'/p:RepositoryCommit='+pin['commit'],*(['/p:TargetFramework='+tfm] if tfm else [])]
   if package_mode:
    command+=['/p:Rid=linux-musl-arm64','/p:Architecture=arm64','/p:OSName=linux','/p:ProductMonikerRid=linux-musl-arm64','/p:CoreSetupRid=linux-musl-arm64','/p:UsePortableLinuxSharedFramework=false','/p:GitCommitHash='+pin['commit'],'/p:GitCommitCount=0','/p:NuGetPackagesDir='+str(work/'home/.nuget/packages')]
    if name=='sdk31':command+=['/p:VersionSuffix=servicing.22566.17']
   if run(name+'-restore',command+['/t:Restore','/bl:'+str(out/(name+'-restore.binlog'))],cwd=source)==0:run(name+'-source-build',command+['/t:'+target,'/bl:'+str(out/(name+'-build.binlog'))],cwd=source)
  imported_hashes={q['sha256']:q['path'] for q in imported};outputs=[]
  for name,source in sources.items():
   for q in source.rglob('*'):
    if not q.is_file() or '/artifacts/' not in str(q):continue
    if not (q.suffix=='.nupkg' or q.name=='Microsoft.NETCoreSdk.BundledVersions.props' or q.name in ('Microsoft.NET.Build.Tasks.dll','core-sdk-tasks.dll')):continue
    raw=q.read_bytes();relative=pathlib.Path(name)/q.relative_to(source);target=out/'source-outputs'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    row=dict(path=str(target.relative_to(out)),bytes=len(raw),sha256=sha(raw),identicalBootstrapPath=imported_hashes.get(sha(raw)))
    if q.suffix=='.nupkg':
     with zipfile.ZipFile(q) as archive:row['entries']=[dict(path=item,bytes=len(archive.read(item)),sha256=sha(archive.read(item)),elf=archive.read(item)[:4]==b'\x7fELF') for item in archive.namelist() if not item.endswith('/')]
    outputs.append(row)
  write('source-outputs.json',dict(outputs=outputs,scope='Component outputs only. Original SDK outer build creates bootstrap performance-test SDK siblings outside its package; those siblings are excluded from retained source outputs. GitCommitCount=0 is diagnostic archive metadata, not final release version provenance.'))
 cache=work/'home/.nuget/packages';packages=[];native_assets=[]
 if cache.exists():
  for q in cache.rglob('*.nupkg'):
   raw=q.read_bytes();relative=q.relative_to(cache);target=out/'restored-packages'/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);metadata=q.parent/'.nupkg.metadata'
   packages.append(dict(path=str(relative),bytes=len(raw),sha256=sha(raw),metadata=json.loads(metadata.read_text()) if metadata.is_file() else {}))
  for q in cache.rglob('*'):
   if q.is_file():
    with q.open('rb') as stream:header=stream.read(20)
    if header[:4]==b'\x7fELF':native_assets.append(dict(path=str(q.relative_to(cache)),bytes=q.stat().st_size,sha256=sha(q.read_bytes()),elfMachine=int.from_bytes(header[18:20],'little'),classification='Restored input inventory; not a claim that this foreign native asset was executed or shipped.'))
 write('source-package-byte-hashes.json',dict(packages=packages,restoredNativeAssets=native_assets,usedSourceAuditComplete=False))
try:closure=MUSL.audit_elf(boot,'aarch64')
except ValueError as error:closure=dict(status='not-qualified',reason=str(error))
write('elf-closure.json',closure)
write('results.json',dict(schemaVersion=1,qualification=False,releaseAdmission=False,mode=args.mode,architecture='aarch64',normalReadyToRunEnabled=args.mode=='negative-consumer',privateBootstrapOnly=args.mode!='negative-consumer',records=records,allRequestedCommandsPassed=all(q['exitCode']==0 for q in records),nativeClosureStatus=closure['status'],sourceSdkProduct=False,completeUsedSourceAudit=False,scope=profile['scope']))
print(json.dumps(dict(mode=args.mode,targetExitCodes={q['name']:q['exitCode'] for q in records},qualification=False,nativeClosureStatus=closure['status'])))
temporary.cleanup()
