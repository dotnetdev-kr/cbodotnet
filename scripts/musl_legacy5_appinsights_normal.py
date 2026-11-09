"""Explicit normal Docker adapter for the unchanged genuine App5 worker.

This additive module does not select a backend implicitly or admit an SDK.
The original worker and strengthened private validator remain byte-for-byte
unchanged. Execution is a separate explicit entry; validation never runs tools.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

import musl_legacy5_component_evidence as CE

P=CE.B.P
require=P.require
FP=('bytes','sha256','sha512')
SDK='5.0.214'
SOURCE='9b5b49f2a7697a2bf38f09ca2f2c97326c49d93b'
PACKAGE='microsoft.applicationinsights.2.0.0-cbodotnet.1.nupkg'
KIND='explicit-normal-docker-genuine-App5-worker'
STAGE='build-appinsights-source'
STRONG_SOURCE=dict(bytes=9953,sha256='5704e0ed8b172a2b6fd28e4bbc667ab3debe72e06dfc7f0f573c9fa1c9374034',
    sha512='f789f3c9664dc2ac8ed1f971c6335b30b82c6afff38959ca70406465cf29490d8efe2e73baeb640ddf163918b5060e690c6580ea9d3d1223bc37cc9f7bf2f7fb')
INNER=['python3','/inputs/execution/musl_legacy5_appinsights.py','--worker']
ENV=dict(HOME='/home/build',DOTNET_CLI_HOME='/home/build',DOTNET_CLI_TELEMETRY_OPTOUT='1',
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_MULTILEVEL_LOOKUP='0',DOTNET_PROCESSOR_COUNT='1',
    PYTHONDONTWRITEBYTECODE='1',NUGET_PACKAGES='/home/build/.nuget/packages',
    MSBUILDDEBUGPATH='/diag',MSBUILDDEBUGCOMM='1')
CONTEXT_KEYS={'schemaVersion','kind','sdkVersion','architecture','targetRid','runId','runAttempt','buildId',
    'projectCommit','sourceCommit','imageId','uid','gid','paths','sources','recordIdentity','prepareIdentity'}
PATH_KEYS={'workspace','delivery','project','attempt','source','bootstrap','inspector','diagnostics'}
IDENTITY=('sdkVersion','architecture','targetRid','runId','runAttempt','buildId','projectCommit')


def ordinary(value,*,file=False,directory=False):
    path=Path(value)
    require(path.is_absolute() and '..' not in path.parts and path!=Path(path.anchor)
        and not any(p.is_symlink()for p in(path,*path.parents)), 'Ordinary absolute normal App5 path required')
    if path.exists():
        mode=path.lstat().st_mode
        require(not mode&0o7000 and (stat.S_ISREG(mode)or stat.S_ISDIR(mode)),
                'Normal App5 special entries and special mode bits are forbidden')
    if file:require(path.is_file(),'Ordinary normal App5 file required')
    if directory:require(path.is_dir(),'Ordinary normal App5 directory required')
    return path


def fingerprint(path):
    path=ordinary(path,file=True);a=hashlib.sha256();b=hashlib.sha512();length=0
    with path.open('rb')as stream:
        while raw:=stream.read(65536):length+=len(raw);a.update(raw);b.update(raw)
    return dict(bytes=length,sha256=a.hexdigest(),sha512=b.hexdigest())


def descriptor(path):return dict(path=str(ordinary(path,file=True)),**fingerprint(path))
def read(path):return json.loads(ordinary(path,file=True).read_bytes())
def write(path,value):
    path=ordinary(path);require(not path.exists(),'Fresh exclusive normal App5 record required')
    with path.open('x',encoding='utf-8',newline='\n')as stream:json.dump(value,stream,indent=2);stream.write('\n')


def checked(path,want):
    require(set(want)=={'path',*FP} and want['path']==str(ordinary(path,file=True))
        and fingerprint(path)=={k:want[k]for k in FP},'Exact normal App5 retained file descriptor required')
    return Path(path)


def original_validators():
    path=Path(__file__).with_name('musl_legacy5_appinsights_validator.py')
    require(fingerprint(path)==STRONG_SOURCE,'Original strengthened App5 validator bytes differ')
    spec=importlib.util.spec_from_file_location('normal_app5_original_strong_validator',path)
    strong=importlib.util.module_from_spec(spec);spec.loader.exec_module(strong)
    return strong,strong.original_worker()


def tree_files(root):
    root=ordinary(root,directory=True);rows={}
    for parent,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:ordinary(Path(parent)/name,directory=True)
        for name in files:
            path=ordinary(Path(parent)/name,file=True)
            rows[path.relative_to(root).as_posix()]=dict(**fingerprint(path),mode=stat.S_IMODE(path.stat().st_mode))
    return rows


def execution_sources(reference_bootstrap=None):
    strong,worker=original_validators()
    names=[*strong.WORKER_SOURCES,'musl_legacy5_appinsights_validator.py',Path(__file__).name,'musl-sdk.py']
    if reference_bootstrap is not None:
        import musl_legacy5_appinsights_reference_bootstrap as reference
        reference.validate_role(reference_bootstrap)
        names+=['musl_legacy5_appinsights_reference_bootstrap.py',reference.POLICY_FILE]
    return {name:fingerprint(Path(__file__).with_name(name))for name in names}


def _identity(value):
    require(all(key in value for key in IDENTITY),'Complete actual normal SDK5 run identity required')
    return {key:value[key]for key in IDENTITY}


def normal_context(record,prepare,*,workspace,delivery,project,diagnostics,uid,gid,reference_bootstrap=None):
    """Build from caller-authenticated normal records and physical producer roots.

    A5 must supply its authenticated record/prepare/stages again at validation;
    this module never treats a self-reported context as aggregate admission.
    """
    identity=_identity(record);require(identity==_identity(prepare),'Normal App5 record/prepare identity differs')
    arch=identity['architecture'];require(arch in('aarch64','x64'),'Explicit normal App5 native CPU required')
    require(identity['sdkVersion']==SDK and identity['targetRid']==P.identity(arch)['rid']
        and re.fullmatch('[0-9a-f]{40}',identity['projectCommit']) and
        all(isinstance(identity[k],str)and re.fullmatch('[A-Za-z0-9_.-]{1,128}',identity[k])for k in('runId','runAttempt','buildId')),
        'Exact normal App5 SDK/CPU/run/build/project identity required')
    require(prepare.get('emulation')is False and prepare.get('diagnosticPodman')is False
        and prepare.get('diagnosticPtrace')is False and prepare.get('previousPrivateSdkArchiveUsed')is False
        and re.fullmatch('sha256:[0-9a-f]{64}',prepare.get('imageId','')),
        'Normal App5 requires the real normal Docker image and no diagnostic/private producer mode')
    require(type(uid)is int and type(gid)is int and uid>0 and gid>0,'Exact non-root normal App5 UID/GID required')
    W,D,J=[ordinary(p)for p in(workspace,delivery,project)]
    require(all(a!=b and a not in b.parents and b not in a.parents for i,a in enumerate((W,D,J))for b in(W,D,J)[i+1:]),
        'Distinct normal App5 workspace, delivery and orchestration roots required')
    diag=ordinary(diagnostics);require(diag.parent==D/'reports/diagnostics'and re.fullmatch('container-[0-9]{4,}',diag.name),
        'One exact normal App5 diagnostic directory required')
    paths=dict(workspace=str(W),delivery=str(D),project=str(J),attempt=str(D/'reports/build/appinsights'),
        source=str(W/'work/appinsights'),bootstrap=str(W/'inputs/bootstrap5'),inspector=str(W/'inputs/bootstrap6'),diagnostics=str(diag))
    result=dict(schemaVersion=1,kind=KIND,**identity,sourceCommit=SOURCE,imageId=prepare['imageId'],uid=uid,gid=gid,
        paths=paths,sources=execution_sources(reference_bootstrap),recordIdentity=identity,prepareIdentity=_identity(prepare))
    if reference_bootstrap is not None:
        import musl_legacy5_appinsights_reference_bootstrap as reference
        reference.validate_role(reference_bootstrap)
        result.update(schemaVersion=2,kind=reference.KIND,referenceBootstrap=reference_bootstrap)
        result['paths']['attempt']=str(W/'private/appinsights')
    return result


def validate_context(context):
    finite='referenceBootstrap'in context
    if finite:
        import musl_legacy5_appinsights_reference_bootstrap as reference
        reference.validate_role(context['referenceBootstrap'])
    require(set(context)==CONTEXT_KEYS|({'referenceBootstrap'}if finite else set())
        and context['kind']==(reference.KIND if finite else KIND)and context['schemaVersion']==(2 if finite else 1),
        'Closed explicit normal App5 context required; private records are not normal evidence')
    require(set(context['paths'])==PATH_KEYS,'Closed normal App5 physical path roles required')
    prepare=dict(context['prepareIdentity'],imageId=context['imageId'],emulation=False,diagnosticPodman=False,
        diagnosticPtrace=False,previousPrivateSdkArchiveUsed=False)
    expected=normal_context(context['recordIdentity'],prepare,
        **{key:context['paths'][key]for key in('workspace','delivery','project','diagnostics')},uid=context['uid'],gid=context['gid'],
        reference_bootstrap=context.get('referenceBootstrap'))
    require(context==expected,'Exact original normal App5 context/source/path identities required')
    return context


def normal_container_command(context):
    context=validate_context(context);paths=context['paths'];attempt=Path(paths['attempt'])
    command=P.DOCKER_ENGINE+['run','--rm','--network=none','--read-only','--user',str(context['uid'])+':'+str(context['gid']),
        '--cap-drop=all','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,size=128m']
    for key,value in ENV.items():command+=['--env',key+'='+value]
    mounts=[(attempt/'inputs','/inputs','ro'),(attempt/'output','/output','rw'),(attempt/'home','/home/build','rw'),
        (Path(paths['bootstrap']),'/bootstrap','ro'),(Path(paths['inspector']),'/inspector','ro'),
        (Path(paths['project']),'/project','ro')]
    for source,target,mode in mounts:command+=['--volume',str(source)+':'+target+':'+mode]
    command+=['--volume',paths['diagnostics']+':/diag','--workdir','/output',context['imageId']]
    return command+P.Producer.observed_command(INNER)


def verify_project(context):
    J=ordinary(context['paths']['project'],directory=True)
    require(P.git(J,'rev-parse','HEAD')==context['projectCommit']
        and not P.git(J,'status','--porcelain','--untracked-files=all'),'Clean actual normal App5 orchestration commit required')
    for name,want in context['sources'].items():
        path=J/'scripts'/name;require(fingerprint(path)==want,'Normal App5 executed orchestration source differs: '+name)
        row=P.git(J,'ls-tree',context['projectCommit'],'--','scripts/'+name).split()
        raw=ordinary(path,file=True).read_bytes()
        require(len(row)==4 and row[0]in('100644','100755')and row[1]=='blob'
            and row[2]==hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            and bool(path.stat().st_mode&0o111)==(row[0]=='100755'),
            'Normal App5 worker-critical source must equal original Git blob and executable mode')


def input_inventory(source,reference_zip,targets,original_package,reader_source):
    """Read-only pin check and copy-size estimate; no normal execution proof."""
    strong,worker=original_validators();policy=worker.policy();source=ordinary(source,directory=True)
    require(P.git(source,'rev-parse','HEAD')==SOURCE and not P.git(source,'status','--porcelain','--untracked-files=all'),
        'Pristine exact original App5 source checkout required for typed preparation')
    rows={}
    for name,row in policy['source']['files'].items():
        path=ordinary(source/name,file=True);raw=path.read_bytes()
        require(fingerprint(path)=={k:row[k]for k in FP}
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['gitBlob']
            and bool(path.stat().st_mode&0o111)==(row['mode']=='100755'),
            'Exact original App5 source blob and executable mode required before normal preparation')
        rows[name]=dict(**fingerprint(path),gitBlob=row['gitBlob'],gitMode=row['mode'])
    references=worker.validate_reference_zip(reference_zip,policy);support=worker.reference_support(reference_zip,policy)
    portable=worker.validate_targets(targets,policy)
    require(fingerprint(original_package)==policy['originalPackage']['officialPackage'],
        'Exact original comparison-only App5 package required before normal preparation')
    readers={name:descriptor(Path(reader_source)/name)for name in policy['reader']['sourceFiles']}
    require(all({k:row[k]for k in FP}==policy['reader']['sourceFiles'][name]for name,row in readers.items()),
        'Exact original frozen Reader input source required before normal preparation')
    size=sum(row['bytes']for row in rows.values())+fingerprint(reference_zip)['bytes']+sum(map(len,references.values()))
    size+=sum(map(len,support.values()))+sum(map(len,portable.values()))+fingerprint(original_package)['bytes']
    size+=sum(row['bytes']for row in readers.values())+sum(row['bytes']for row in strong.WORKER_SOURCES.values())
    size+=len(worker.project_bytes(policy))+len(b'<configuration><packageSources><clear /></packageSources></configuration>\n')
    return dict(kind='read-only-pinned-normal-App5-input-inventory',sourceCommit=SOURCE,sourceFiles=rows,
        referenceArchive=descriptor(reference_zip),profileMembers=len(references),referenceAssemblies=65,
        baseFrameworkMetadata={name:worker.fingerprint(raw)for name,raw in support.items()},
        portableTargetAndLicenseFiles={name:worker.fingerprint(raw)for name,raw in portable.items()},
        comparisonOnlyPublisherPackage=descriptor(original_package),readerSources=readers,estimatedTypedCopyBytes=size,
        originalZipEmbeddedLicenseFiles=[],referenceZipRedistributedIfWholeTypedTreePublished=True,
        referencePreferredSourceAndLicenseClosure=False,completeMonoProviderImportClosure=False,
        normalAppWorkerBoundaryValidated=False,compilerExecuted=False,binaryReaderExecuted=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def prepare_normal(source,reference_zip,targets,original_package,reader_source,*,context):
    context=validate_context(context);strong,worker=original_validators();paths=context['paths']
    require(ordinary(source,directory=True)==Path(paths['source']),'Normal App5 source must be this physical producer checkout')
    verify_project(context);inventory=input_inventory(source,reference_zip,targets,original_package,reader_source);destination=Path(paths['attempt'])
    # Immutable prepare checks the original commit object, all 437 Git blobs,
    # 112 compile items, 70 selected Profile7 members/baseXML and typed roles.
    prepared=worker.prepare(source,reference_zip,targets,original_package,reader_source,destination)
    manifest=worker.verify_inputs(destination);require(tree_files(destination/'inputs')==manifest['files'],
        'Complete ordinary normal App5 typed inputs required')
    require(not any((destination/'output').iterdir())and not any((destination/'home').iterdir()),'Fresh normal App5 output/home required')
    write(destination/'normal-context.json',context)
    write(destination/'normal-prepared.json',dict(kind='fresh-typed-normal-App5-inputs',context=context,
        inputManifest=descriptor(destination/'input-manifest.json'),inputFiles=manifest['files'],
        pinnedInputInventory=inventory,
        originalWorkerSources=strong.WORKER_SOURCES,originalStrongValidator=STRONG_SOURCE,
        referencePreferredSourceAndLicenseClosure=False,wholeProducerSourceClosure=False))
    return dict(**prepared,normalContext=context,normalWorkerOnly=True,qualificationAllowed=False,sourceAdmissionAllowed=False)


def _host_roots(workspace,context,host_roots):
    expected={'/inputs':workspace/'inputs','/output':workspace/'output','/bootstrap':Path(context['paths']['bootstrap']),'/inspector':Path(context['paths']['inspector'])}
    require(set(host_roots)==set(expected)and all(ordinary(host_roots[k],directory=True)==v for k,v in expected.items()),
        'Exact normal App5 bootstrap/inspector/input/output mount origins required')


def preflight_engine_evidence(release,stages):
    """Reject special/unbounded evidence before any shared validator reads it."""
    release=ordinary(release,directory=True);wanted={
        release/'reports/prepare/container-engine-version.json':4*1024**2,
        release/'reports/prepare/container-engine-info.json':4*1024**2}
    for stage in stages.values():
        for command in stage['commands']:
            if command[:len(P.DOCKER_ENGINE)+1]!=P.DOCKER_ENGINE+['run']:continue
            mounts=[value for value in command if isinstance(value,str)and value.endswith(':/diag')]
            require(len(mounts)==1,'One exact actual normal App5 inspected-stage diagnostic mount required')
            directory=ordinary(mounts[0][:-len(':/diag')],directory=True)
            require(re.fullmatch('container-[0-9]{4,}',directory.name)
                and directory.parent==release/'reports/diagnostics',
                'Every inspected normal Docker stage must use its exact delivery diagnostic directory')
            for name,limit in [('process-status.txt',65536),('apparmor-current.txt',4096),('exit-code.txt',65536)]:
                wanted[directory/name]=limit
    for path,limit in wanted.items():
        ordinary(path,file=True)
        require(0<path.stat().st_size<=limit,'Bounded ordinary normal App5 engine/security/exit evidence required')
    return {str(path):fingerprint(path)for path in wanted}


def execute_normal(context,*,producer):
    """Run once in the actual normal producer; never retry or select Podman."""
    context=validate_context(context);strong,worker=original_validators();paths=context['paths'];workspace=Path(paths['attempt'])
    require(producer.engine==P.DOCKER_ENGINE and producer.diagnostic is False and producer.diagnostic_ptrace is False
        and producer.image==context['imageId']and producer.uid==context['uid']and producer.gid==context['gid']
        and ordinary(producer.workspace)==Path(paths['workspace'])and ordinary(producer.output)==Path(paths['delivery'])
        and producer.project==context['projectCommit'], 'Actual normal Docker producer object must match the bound App5 context')
    require(read(workspace/'normal-context.json')==context,'Actual normal App5 prepared context differs')
    prepare=read(Path(paths['delivery'])/'reports/prepare/identity.json')
    expected=normal_context(context['recordIdentity'],prepare,**{k:paths[k]for k in('workspace','delivery','project','diagnostics')},uid=context['uid'],gid=context['gid'],reference_bootstrap=context.get('referenceBootstrap'))
    require(expected==context,'Actual retained normal SDK5 prepare identity differs before App5 execution')
    prepare_stage=read(Path(paths['delivery'])/'reports/stages/prepare.json')
    require(prepare_stage['status']=='passed','Normal SDK5 preparation must complete before App5 execution')
    prior_stages=dict(prepare=prepare_stage,build=dict(commands=producer.commands))
    preflight_engine_evidence(Path(paths['delivery']),prior_stages)
    P.validate_container_engine(Path(paths['delivery']),prepare,prior_stages,P.identity(context['architecture']))
    verify_project(context);manifest=worker.verify_inputs(workspace);before=tree_files(workspace/'inputs')
    require(before==manifest['files']and not any((workspace/'output').iterdir())and not any((workspace/'home').iterdir()),
        'One fresh normal App5 physical output/home and original typed inputs required')
    require(not any((workspace/n).exists()for n in('normal-container-invocation.json','normal-container-result.json','normal-app-stage.json','container-invocation.json','container-result.json')),
        'Normal App5 cannot reuse any normal or private attempt record')
    diag=ordinary(paths['diagnostics']);require(not diag.exists(),'Fresh exclusive normal App5 diagnostics required');diag.mkdir()
    if os.getuid()==0:
        for path in(workspace/'output',workspace/'home',diag):os.chown(path,context['uid'],context['gid'])
    command=normal_container_command(context)
    write(workspace/'normal-container-invocation.json',dict(kind=context['kind'],context=context,command=command,
        inputManifest=descriptor(workspace/'input-manifest.json'),inputFiles=before,automaticRetry=False))
    require(command not in producer.commands,'Only one actual normal App5 stage invocation permitted')
    producer.commands.append(command)
    result=worker.run_record(command,workspace/'normal-container.log')
    after=tree_files(workspace/'inputs')
    write(workspace/'normal-container-result.json',dict(**result,inputFilesAfter=after))
    write(workspace/'normal-app-stage.json',dict(stage=STAGE,status='passed'if result['exitCode']==0 and after==before else'failed',commands=[command],
        result=descriptor(workspace/'normal-container-result.json'),automaticRetry=False))
    worker.verify_inputs(workspace);require(after==before,'Normal App5 readonly typed inputs changed')
    preflight_engine_evidence(Path(paths['delivery']),{STAGE:dict(commands=[command])})
    P.validate_default_container_policy(Path(paths['delivery']),command)
    require((diag/'exit-code.txt').read_text().strip()==str(result['exitCode'])=='0','Normal App5 container/observed worker failed; original evidence retained without retry')
    return result


def validate_normal_boundary(workspace,host_roots,*,normal_context,require_parent_build=False):
    """Authenticate against actual caller-bound prepare/stages, never an App-only claim."""
    bound=normal_context
    require(set(bound)=={'context','record','prepare','stages'},'Explicit caller-authenticated normal App5 context/record/prepare/stages required')
    context=validate_context(bound['context']);paths=context['paths'];workspace=ordinary(workspace,directory=True)
    require(workspace==Path(paths['attempt']),'Current normal App5 attempt workspace required')
    expected=globals()['normal_context'](bound['record'],bound['prepare'],**{k:paths[k]for k in('workspace','delivery','project','diagnostics')},uid=context['uid'],gid=context['gid'],reference_bootstrap=context.get('referenceBootstrap'))
    require(context==expected==read(workspace/'normal-context.json'),'Normal App5 context differs from actual authenticated producer identity')
    _host_roots(workspace,context,host_roots);verify_project(context)
    invocation=read(workspace/'normal-container-invocation.json');result=read(workspace/'normal-container-result.json');stage=read(workspace/'normal-app-stage.json')
    require(set(invocation)=={'kind','context','command','inputManifest','inputFiles','automaticRetry'}
        and invocation['kind']==context['kind'] and invocation['context']==context and invocation['automaticRetry']is False,
        'Closed actual normal App5 invocation required')
    command=normal_container_command(context)
    require(invocation['command']==result['command']==command and result['exitCode']==0,
        'Actual normal App5 complete Docker argv and zero exit status required')
    checked(workspace/'input-manifest.json',invocation['inputManifest']);checked(workspace/'normal-container.log',result['log'])
    checked(workspace/'normal-container-result.json',stage['result'])
    require(stage==dict(stage=STAGE,status='passed',commands=[command],result=stage['result'],automaticRetry=False),
        'One actual successful normal App5 source substage required')
    require(invocation['inputFiles']==result['inputFilesAfter']==tree_files(workspace/'inputs'),
        'Original normal App5 typed input content/modes must remain unchanged across execution')
    require(not any((workspace/n).exists()for n in('container-invocation.json','container-result.json')),
        'Private App5 records must not be presented as normal evidence')
    stages=bound['stages'];D=Path(paths['delivery'])
    require(bound['prepare']==read(D/'reports/prepare/identity.json')and stages['prepare']==read(D/'reports/stages/prepare.json')
        and stages['prepare']['status']=='passed','Actual retained normal SDK5 preparation must match the authenticated records and have passed')
    if require_parent_build:
        require(stages['build']==read(D/'reports/stages/build.json')and stages['build']['status']=='passed'and stages['build']['commands'].count(command)==1,
            'Actual current successful normal SDK5 build stage must contain this App5 source process once')
    inspected_stages=dict(stages,**{STAGE:stage})
    evidence=preflight_engine_evidence(Path(paths['delivery']),inspected_stages)
    P.validate_container_engine(Path(paths['delivery']),bound['prepare'],inspected_stages,P.identity(context['architecture']))
    P.validate_default_container_policy(Path(paths['delivery']),command)
    diag=ordinary(paths['diagnostics'],directory=True)
    require(ordinary(diag/'exit-code.txt',file=True).read_text().strip()=='0','Actual observed normal App5 worker exit status required')
    return dict(kind='normal-App5-Docker-boundary',context=context,invocation=descriptor(workspace/'normal-container-invocation.json'),
        result=descriptor(workspace/'normal-container-result.json'),stage=descriptor(workspace/'normal-app-stage.json'),
        securityReports={n:descriptor(diag/n)for n in('process-status.txt','apparmor-current.txt','exit-code.txt')},
        # Later parent SDK processes add diagnostic reports after packaging.
        # Preflight all of them, but this component receipt binds only its
        # stable two engine reports and its own three process reports.
        preflightOrdinaryEngineSecurityEvidence={name:fp for name,fp in evidence.items()
            if Path(name).parent in(diag,Path(paths['delivery'])/'reports/prepare')},
        allInspectedStageEvidenceCheckedBeforeReads=True,
        parentSdkBuildValidated=require_parent_build,normalAppWorkerBoundaryValidated=True)


def process_commands():
    app=['/bootstrap/dotnet','/bootstrap/sdk/5.0.401/MSBuild.dll','/inputs/recipe/App.PCL.proj','/t:Build','/m:1','/nr:false','/v:normal',
        '/p:Configuration=Release','/p:PublicRelease=True','/p:PreReleaseVersion=30671','/p:AssemblyOriginatorKeyFile=/inputs/source/35MSSharedLib1024.snk',
        '/p:UseSharedCompilation=false','/bl:/output/app.binlog']
    reader=['/inspector/dotnet','/inspector/sdk/6.0.135/MSBuild.dll','/inputs/reader/Reader.csproj','/restore','/t:Build','/m:1','/nr:false','/v:normal',
        '/p:BootstrapMajor=6','/p:BootstrapSdkDir=/inspector/sdk/6.0.135','/p:BaseIntermediateOutputPath=/output/reader-obj/',
        '/p:OutputPath=/output/reader/','/p:RestoreConfigFile=/inputs/NuGet.Config','/p:UseSharedCompilation=false','/bl:/output/reader-build.binlog']
    replays=[['/inspector/dotnet','/output/reader/Reader.dll','/output/'+name+'.binlog',sdk,'/output/replay/'+name]
        for name,sdk in[('app','/bootstrap/sdk/5.0.401'),('reader-build','/inspector/sdk/6.0.135')]]
    return [app,reader,*replays]


def validate_process_records(output):
    output=ordinary(output,directory=True)
    done=read(output/'worker-completed.json')
    require(done==dict(status='one-genuine-offline-app5-build-completed',appBuilds=1,readerBuiltFromFrozenSources=True,
        readerActuallyExecuted=True,network='none',publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False),
        'Exact unchanged normal App5 worker completion required')
    app=read(output/'actual-app-process.json');reader=read(output/'actual-reader-build-process.json');replays=read(output/'actual-reader-processes.json')
    require(type(replays)is list and len(replays)==2,'Exactly two separate actual normal App5 Reader invocations required')
    records=[app,reader,*replays];logs=['app-build.log','reader-build.log','app-reader.log','reader-build-reader.log']
    for record,command,log in zip(records,process_commands(),logs):
        require(record['command']==command and record['exitCode']==0 and record['log']['path']=='/output/'+log,
            'Exact complete ordered original App5/Reader command, output log path and successful exit required')
        require(fingerprint(output/log)=={k:record['log'][k]for k in FP},'Actual normal App5/Reader process log bytes differ')
    executable=fingerprint(output/'reader/Reader.dll')
    statuses=[]
    for record,name in zip(replays,('app','reader-build')):
        require(record['readerExecutable']==executable and record['originalBinlog']==fingerprint(output/(name+'.binlog')),
            'Actual normal App5 Reader executable and each original binary log must bind consumed bytes')
        statuses.append({field:fingerprint(output/('replay/'+name+'-'+field))for field in('status.json','tasks.jsonl')})
    require(all(statuses[0][field]!=statuses[1][field]for field in('status.json','tasks.jsonl'))
        and fingerprint(output/'app.binlog')!=fingerprint(output/'reader-build.binlog'),
        'Normal App5 App/Reader status, tasks and binary logs must have distinct original content')
    return dict(actualSourceProcesses=[app,reader],actualBinaryReaderProcesses=replays,readerExecutable=executable,
        rawAppBinlog=fingerprint(output/'app.binlog'),rawReaderBuildBinlog=fingerprint(output/'reader-build.binlog'))


def verify_normal_execution(workspace,host_roots,*,normal_context,require_parent_build=False):
    boundary=validate_normal_boundary(workspace,host_roots,normal_context=normal_context,require_parent_build=require_parent_build)
    strong,worker=original_validators();workspace=ordinary(workspace,directory=True);output=workspace/'output'
    manifest=worker.verify_inputs(workspace);require(tree_files(workspace/'inputs')==manifest['files'],'Complete normal App5 input tree required')
    processes=validate_process_records(output)
    app_compiler=strong.compiler_record(workspace,'app',host_roots);reader_compiler=strong.compiler_record(workspace,'reader-build',host_roots)
    return dict(kind='actual-normal-offline-App5-and-frozen-reader-execution',boundary=boundary,appCompiler=app_compiler,
        readerCompiler=reader_compiler,**processes,
        originalStrongValidator=STRONG_SOURCE,immutableOriginalWorkerSources=strong.WORKER_SOURCES,
        readerActuallyExecuted=True,referenceInputPreferredSourceAndLicenseClosure=False,wholeProducerSourceClosure=False,
        oldBinarySourceAttributed=False,publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def package_bodies(workspace,worker):
    workspace=ordinary(workspace,directory=True)
    bodies={'Microsoft.ApplicationInsights.nuspec':worker.local_nuspec(workspace),'LICENSE':ordinary(workspace/'inputs/source/LICENSE',file=True).read_bytes()}
    for suffix in('dll','pdb','xml'):
        path=ordinary(workspace/'output/app'/('Microsoft.ApplicationInsights.'+suffix),file=True)
        require(path.stat().st_size>0,'Complete actual normal App5 DLL/PDB/XML required');bodies['lib/dotnet5.4/'+path.name]=path.read_bytes()
    return bodies


def validate_api(workspace,worker):
    """Use the unchanged exact decoder without the old helper's error writes."""
    workspace=ordinary(workspace,directory=True)
    with zipfile.ZipFile(ordinary(workspace/'inputs/original.nupkg',file=True))as archive:
        original=archive.read('lib/dotnet5.4/Microsoft.ApplicationInsights.dll')
    rebuilt=ordinary(workspace/'output/app/Microsoft.ApplicationInsights.dll',file=True).read_bytes()
    return worker.api_module().compare(original,rebuilt)


def package_normal(workspace,host_roots,*,normal_context):
    execution=verify_normal_execution(workspace,host_roots,normal_context=normal_context)
    strong,worker=original_validators();api=validate_api(workspace,worker);workspace=ordinary(workspace,directory=True)
    target=workspace/'output'/PACKAGE;receipt=workspace/'output/genuine-normal-package.json'
    require(not target.exists()and not receipt.exists(),'Fresh actual normal App5 package and receipt required')
    bodies=package_bodies(workspace,worker)
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as archive:
        for name,raw in sorted(bodies.items()):
            entry=zipfile.ZipInfo(name,(1980,1,1,0,0,0));entry.create_system=3;entry.external_attr=0o100644<<16;entry.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(entry,raw)
    result=dict(kind='actual-normal-genuine-App5-package',package=descriptor(target),members={n:worker.fingerprint(raw)for n,raw in bodies.items()},
        api=api,execution=execution,oldBinarySourceAttributed=False,publisherSigningClaimed=False,wholeProducerSourceClosure=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)
    write(receipt,result);return result


def validate(workspace,host_roots,*,normal_context):
    """Strong normal-only entry for a later fully authenticated SDK consumer."""
    execution=verify_normal_execution(workspace,host_roots,normal_context=normal_context,require_parent_build=True)
    strong,worker=original_validators();workspace=ordinary(workspace,directory=True);api=validate_api(workspace,worker)
    receipt=read(workspace/'output/genuine-normal-package.json');package=workspace/'output'/PACKAGE
    checked(package,receipt['package']);bodies=package_bodies(workspace,worker)
    with zipfile.ZipFile(package)as archive:
        require(archive.namelist()==sorted(bodies)and len(archive.infolist())==5,'Exact five original PCL-only normal App5 package members required')
        for entry in archive.infolist():
            require(entry.date_time==(1980,1,1,0,0,0)and entry.create_system==3 and entry.external_attr>>16==0o100644
                and entry.compress_type==zipfile.ZIP_DEFLATED and not entry.extra and not entry.comment
                and entry.file_size==len(bodies[entry.filename])and archive.read(entry)==bodies[entry.filename],
                'Exact actual normal App5 package member bytes, modes and metadata required')
        require(not archive.comment,'Normal App5 package archive comments are forbidden')
    members={n:worker.fingerprint(raw)for n,raw in bodies.items()}
    require(receipt['kind']=='actual-normal-genuine-App5-package'and receipt['members']==members and receipt['api']==api,
        'Actual normal App5 package receipt/API/member identities differ')
    # The package receipt was written before the parent SDK build could finish;
    # its retained App proof must otherwise reproduce exactly at admission.
    expected_execution=dict(execution,boundary=dict(execution['boundary'],parentSdkBuildValidated=False))
    require(receipt['execution']==expected_execution,'Actual normal App5 package must bind this source execution, not preseeded/private outputs')
    return dict(kind='strong-normal-genuine-App5-execution-api-package-validation',execution=execution,api=api,
        package=descriptor(package),members=members,normalAppWorkerBoundaryValidated=True,
        referenceInputPreferredSourceAndLicenseClosure=False,wholeProducerSourceClosure=False,
        oldBinarySourceAttributed=False,publisherSigningClaimed=False,sdkConsumerReplacementPerformed=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)
