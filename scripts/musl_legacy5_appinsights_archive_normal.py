"""Archived App5 normal/consumer predicates over concrete immutable core views.

Original logical records are never rewritten or treated as relocated live W.
Pure field helpers do not prove source, execution, construction or admission.
"""
import math
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

import musl_legacy5_appinsights_archive as A
import musl_legacy5_appinsights_capture as C
import musl_legacy5_appinsights_consumption as M
import musl_legacy5_appinsights_normal as N

P=N.P
require=A.require
FP=set(N.FP)
_SCOPED=dict(archivedConstructionValidated=False,wholeProducerSourceClosure=False,
    qualificationAllowed=False,sourceAdmissionAllowed=False)


def require_posix():
    require(os.name=='posix','Full archived normal validation requires POSIX original-path semantics')


def _descriptor(value,path):
    require(type(value)is dict and set(value)=={'path',*FP}and value['path']==path,
        'Exact unchanged original archived descriptor path required')
    return A.identity({key:value[key]for key in FP},empty=True)


def bound_fields(bound):
    """Cross-platform field checks only; no saved normal boolean is consumed."""
    require(type(bound)is dict and set(bound)=={'context','record','prepare','stages'},
        'Closed actual archived normal context/record/prepare/stages required')
    context=bound['context'];record=bound['record'];prepare=bound['prepare'];stages=bound['stages']
    require(type(context)is dict and type(record)is dict and type(prepare)is dict and type(stages)is dict
        and {'prepare','build'}<=set(stages),'Actual normal bound objects and both parent stages required')
    require(all(key in record and key in prepare and key in context for key in N.IDENTITY),
        'Complete original normal SDK5 run identity required')
    expected={key:record[key]for key in N.IDENTITY}
    require(expected=={key:prepare[key]for key in N.IDENTITY}=={key:context[key]for key in N.IDENTITY}
        and context.get('recordIdentity')==expected and context.get('prepareIdentity')==expected,
        'Original normal context/record/prepare identity differs')
    require(context['sdkVersion']==N.SDK and context['architecture']in('aarch64','x64')
        and context['targetRid']=='linux-musl-'+('arm64'if context['architecture']=='aarch64'else'x64')
        and all(isinstance(expected[key],str)and re.fullmatch('[A-Za-z0-9_.-]{1,128}',expected[key])for key in('runId','runAttempt','buildId'))
        and re.fullmatch('[0-9a-f]{40}',context['projectCommit']),
        'Exact original normal SDK/CPU/RID/run/attempt/build/project fields required')
    logical_paths(context)
    return expected


def logical_paths(context):
    """Check original POSIX strings without the verifier platform's Path rules."""
    paths=context.get('paths')
    require(type(paths)is dict and set(paths)==N.PATH_KEYS,'Closed original normal path roles required')
    for value in paths.values():A.logical(value)
    W,D,J=(PurePosixPath(paths[key])for key in('workspace','delivery','project'))
    require(all(x!=y and x not in y.parents and y not in x.parents for i,x in enumerate((W,D,J))for y in(W,D,J)[i+1:]),
        'Distinct original workspace/delivery/project roots required')
    require(paths['attempt']==str(W/'private/appinsights')and paths['source']==str(W/'work/appinsights')
        and paths['bootstrap']==str(W/'inputs/bootstrap5')and paths['inspector']==str(W/'inputs/bootstrap6'),
        'Exact finite original private App/BOOT physical roles required')
    diag=PurePosixPath(paths['diagnostics'])
    require(diag.parent==D/'reports/diagnostics'and re.fullmatch('container-[0-9]{4,}',diag.name),
        'Exact original delivery diagnostic directory required')
    return paths


def normal_record_fields(context,command,invocation,result,stage):
    """Original invocation/result/stage relationships, before physical opens."""
    paths=logical_paths(context);attempt=paths['attempt']
    require(type(invocation)is dict and set(invocation)=={'kind','context','command','inputManifest','inputFiles','automaticRetry'}
        and invocation['kind']==context['kind']and invocation['context']==context and invocation['automaticRetry']is False,
        'Closed original normal invocation without automatic retry required')
    require(type(result)is dict and set(result)=={'command','exitCode','seconds','log','inputFilesAfter'}
        and type(result['exitCode'])is int and result['exitCode']==0
        and type(result['seconds'])in(int,float)and math.isfinite(result['seconds'])and result['seconds']>=0,
        'One original successful bounded-field normal process result required')
    require(type(command)is list and command and all(isinstance(value,str)for value in command)
        and invocation['command']==result['command']==command,'Original normal complete Docker argv differs')
    _descriptor(invocation['inputManifest'],attempt+'/input-manifest.json')
    _descriptor(result['log'],attempt+'/normal-container.log')
    require(type(stage)is dict and set(stage)=={'stage','status','commands','result','automaticRetry'}
        and stage['stage']==N.STAGE and stage['status']=='passed'and stage['commands']==[command]
        and stage['automaticRetry']is False,'Exactly one original passed normal App source substage required')
    _descriptor(stage['result'],attempt+'/normal-container-result.json')
    require(type(invocation['inputFiles'])is dict and invocation['inputFiles']
        and invocation['inputFiles']==result['inputFilesAfter'],'Original before/after typed input inventories differ')
    for name,row in invocation['inputFiles'].items():
        A.portable(name)
        require(type(row)is dict and set(row)=={*FP,'mode'}and row['mode']in(0o644,0o755),
            'Original ordinary typed input fingerprint/mode required')
        A.identity({key:row[key]for key in FP},empty=True)
    return dict(originalInputManifest=invocation['inputManifest'],originalLog=result['log'],originalResult=stage['result'])


def parent_record_fields(bound,actual_prepare,actual_stages,command):
    """Never accept a caller stage object in place of its retained original."""
    bound_fields(bound)
    require(bound['prepare']==actual_prepare and type(actual_stages)is dict and bound['stages']==actual_stages,
        'Caller normal identity/stages differ from authenticated archived records')
    for name in('prepare','build'):
        require(type(actual_stages[name])is dict and actual_stages[name].get('stage')==name
            and actual_stages[name].get('status')=='passed','Both actual original parent prepare/build stages must pass')
    require(isinstance(actual_stages['build'].get('commands'),list)and actual_stages['build']['commands'].count(command)==1,
        'Actual original successful parent build must contain the App process exactly once')
    return True


def diagnostic_plan(original_delivery,stages):
    """Map exact original diagnostic mounts; no physical-directory fallback."""
    D=PurePosixPath(A.logical(original_delivery))
    wanted={str(D/'reports/prepare/container-engine-version.json'):4*1024**2,
        str(D/'reports/prepare/container-engine-info.json'):4*1024**2}
    require(type(stages)is dict and stages,'Actual inspected original stages required')
    for stage in stages.values():
        require(type(stage)is dict and isinstance(stage.get('commands'),list),'Original inspected command list required')
        for command in stage['commands']:
            require(type(command)is list and all(isinstance(value,str)for value in command),'Original inspected argv strings required')
            if command[:len(P.DOCKER_ENGINE)+1]!=P.DOCKER_ENGINE+['run']:continue
            mounts=[value[:-len(':/diag')]for value in command if value.endswith(':/diag')]
            require(len(mounts)==1,'One exact original Docker diagnostic mount required')
            directory=PurePosixPath(A.logical(mounts[0]))
            require(directory.parent==D/'reports/diagnostics'and re.fullmatch('container-[0-9]{4,}',directory.name),
                'Every original Docker diagnostic mount must belong to this original delivery')
            for name,limit in(('process-status.txt',65536),('apparmor-current.txt',4096),('exit-code.txt',65536)):
                wanted[str(directory/name)]=limit
    return wanted


def _source_body(view,source,original,public_root,suffix,limit):
    """Only a core-minted member of this actual public App root may supply it."""
    origin=view.require_origin(original)
    root=public_root['name'];member=root+'/'+A.portable(suffix)
    archived=public_root['originalPath']+'/'+suffix
    require(origin['root']==root and origin['member']==member and origin['role']==A.APP_PUBLIC_ROLE
        and origin['originalLogicalPath']==original and origin['originalArchivedPath']==archived
        and origin['archive']==source.archive.fingerprint and origin['index']==source.index.fingerprint,
        'Actual same-session public App source-index origin required')
    raw=view.read(original,limit)
    require(A.fingerprint(raw)==origin['fingerprint'],'Actual archived App record differs from its original indexed body')
    return raw,origin


def _delivery_body(view,record,original_delivery,relative,limit):
    relative=A.portable(relative);original=original_delivery+'/'+relative
    origin=view.require_origin(original)
    require(origin['member']==relative and origin['originalLogicalPath']==original
        and origin['originalArchivedPath']==original
        and origin['recordFingerprint']==A.fingerprint(A.canonical(record)),
        'Actual captured sealed-D inventory origin required')
    require(view.path(original)==view.release_root/relative,
        'Shared validators must read the same captured D-relative physical record')
    raw=view.read(original,limit)
    require(A.fingerprint(raw)==origin['fingerprint'],'Actual sealed-D body differs from its captured inventory')
    return raw,origin


def _typed_policy():
    return C.R.policy()


def _typed_origins(view,source,public_root,workspace,attempt,inputs):
    policy=_typed_policy();public=set(policy['publicInputNames']);private=policy['privateInputFiles']
    require(set(inputs)==public|private.keys()and not(public&private.keys()),
        'Complete closed original public449/private73 input namespace required')
    for name,row in inputs.items():
        original=attempt+'/inputs/'+name;origin=view.require_origin(original)
        require(view.path(original)==workspace/'inputs'/name and origin['originalLogicalPath']==original
            and origin['fingerprint']=={key:row[key]for key in FP}and origin['mode']==row['mode']
            and origin['archive']==source.archive.fingerprint and origin['index']==source.index.fingerprint,
            'Every actual reconstructed typed input needs its same-session original file origin')
        if name in public:
            require(origin['kind']=='source'and origin['root']==public_root['name']and origin['role']==A.APP_PUBLIC_ROLE
                and origin['member']==public_root['name']+'/product-source/'+name
                and origin['originalArchivedPath']==public_root['originalPath']+'/product-source/'+name,
                'Actual public449 typed input must come from its exact indexed product-source member')
        else:
            require(origin['kind']=='external'and origin['role']==C.R.ROLE and origin['member']==name
                and origin['mode']==0o644 and origin['fingerprint']==private[name],
                'Only exact core-verified finite private73 external reference/comparison inputs are permitted')


def validate_archived_normal_boundary(view,bound,source):
    """Revalidate original normal/parent fields using concrete indexed origins.

    This scoped entry does not perform compiler, Reader, package or SDK consumer
    validation. A source proof and frozen view alone cannot replace file origins.
    """
    require_posix()
    require(type(view)is A.FrozenView and type(source)is A.SourceSession
        and view.frozen and source.verified and view.source is source,
        'Actual frozen core view bound to its exact verified source session required')
    expected=bound_fields(bound);context=N.validate_context(bound['context']);paths=logical_paths(context)
    require('referenceBootstrap'in context,'Only the explicit finite reference-bootstrap normal context may enter archived construction')
    require(source.expected=={key:expected[key]for key in('sdkVersion','projectCommit','runId','runAttempt','targetRid')},
        'Actual source session and original normal run/attempt/CPU/RID identity differ')
    physical=A.ordinary(view.root,directory=True)
    for value in paths.values():
        original=Path(value)
        require(physical!=original and physical not in original.parents and original not in physical.parents,
            'Reconstructed physical view must not recreate or overlap an original host root')
    require(view.logical_root('delivery')==paths['delivery'],
        'Captured delivery role must retain this exact original delivery path')
    public_root=source.root_for(paths['delivery']+'/reports/build/appinsights',kind='tree',role=A.APP_PUBLIC_ROLE)
    require(type(public_root)is dict and public_root['originalPath']==paths['delivery']+'/reports/build/appinsights',
        'Actual named public App source/evidence root required')
    attempt=paths['attempt'];D=paths['delivery']
    with view.guard():
        orchestration=source.require_orchestration(context)
        expected_context=N.normal_context(bound['record'],bound['prepare'],
            **{key:paths[key]for key in('workspace','delivery','project','diagnostics')},
            uid=context['uid'],gid=context['gid'],reference_bootstrap=context['referenceBootstrap'])
        require(expected_context==context,'Original archived normal context differs from authenticated parent identity')
        records={};origins={}
        for name in('normal-context.json','normal-container-invocation.json','normal-container-result.json','normal-app-stage.json'):
            raw,origin=_source_body(view,source,attempt+'/'+name,public_root,'evidence/'+name,1024**2)
            records[name]=A.unique_json(raw);origins[name]=origin
        require(records['normal-context.json']==context,'Original actual normal-context body differs')
        workspace=view.path(attempt+'/normal-context.json').parent
        for name in records:
            require(view.path(attempt+'/'+name)==workspace/name,
                'Original App record mapping must preserve one explicit verification workspace')
        invocation=records['normal-container-invocation.json'];result=records['normal-container-result.json'];stage=records['normal-app-stage.json']
        command=N.normal_container_command(context)
        descriptors=normal_record_fields(context,command,invocation,result,stage)
        raw,manifest_origin=_source_body(view,source,attempt+'/input-manifest.json',public_root,
            'original-private-input-manifest.json',8*1024**2)
        manifest=A.unique_json(raw)
        view.checked(attempt+'/input-manifest.json',invocation['inputManifest'])
        view.checked(attempt+'/normal-container-result.json',stage['result'])
        log,log_origin=_source_body(view,source,attempt+'/normal-container.log',public_root,'evidence/normal-container.log',8*1024**2)
        view.checked(attempt+'/normal-container.log',result['log'])
        require(view.path(attempt+'/input-manifest.json')==workspace/'input-manifest.json'
            and view.path(attempt+'/normal-container.log')==workspace/'normal-container.log',
            'Original manifest/container log must belong to the same reconstructed workspace')
        inputs=N.tree_files(A.ordinary(workspace/'inputs',directory=True))
        require(manifest.get('files')==invocation['inputFiles']==result['inputFilesAfter']==inputs,
            'Original complete input manifest/before/after must equal actual reconstructed typed bytes/modes')
        _typed_origins(view,source,public_root,workspace,attempt,inputs)
        forbidden={'container-invocation.json','container-result.json','evidence/container-invocation.json','evidence/container-result.json'}
        absence=source.assert_absent_members(public_root['name'],forbidden)
        require(not any(view.contains(attempt+'/'+name)for name in('container-invocation.json','container-result.json')),
            'Old private Podman records cannot be presented as archived normal evidence')
        raw,prepare_origin=_delivery_body(view,bound['record'],D,'reports/prepare/identity.json',1024**2)
        actual_prepare=A.unique_json(raw);actual_stages={};stage_origins={}
        for name in bound['stages']:
            require(isinstance(name,str)and re.fullmatch('[a-z][a-z0-9-]{0,63}',name),'Canonical original parent stage name required')
            raw,origin=_delivery_body(view,bound['record'],D,'reports/stages/'+name+'.json',8*1024**2)
            actual_stages[name]=A.unique_json(raw);stage_origins[name]=origin
        parent_record_fields(bound,actual_prepare,actual_stages,command)
        inspected=dict(actual_stages,**{N.STAGE:stage});security={}
        for original,limit in diagnostic_plan(D,inspected).items():
            relative=PurePosixPath(original).relative_to(D).as_posix()
            raw,origin=_delivery_body(view,bound['record'],D,relative,limit)
            require(0<len(raw)<=limit,'Bounded ordinary original engine/security/exit evidence required before shared reads')
            security[original]=origin
        P.validate_container_engine(view.release_root,actual_prepare,inspected,P.identity(context['architecture']))
        P.validate_default_container_policy(view.release_root,command)
        exit_raw,_=_delivery_body(view,bound['record'],D,
            PurePosixPath(paths['diagnostics']).relative_to(D).as_posix()+'/exit-code.txt',65536)
        require(exit_raw.decode('utf-8').strip()=='0','Original observed normal App worker must exit successfully')
        return dict(kind='archived-normal-App5-Docker-boundary',context=context,
            originalNormalDescriptors=descriptors,originalRecordOrigins=origins,originalInputManifestOrigin=manifest_origin,
            originalContainerLogOrigin=log_origin,actualVerificationWorkspace=str(workspace),
            actualVerificationDelivery=str(view.release_root),parentPrepareOrigin=prepare_origin,parentStageOrigins=stage_origins,
            engineSecurityOrigins=security,orchestration=orchestration,originalPrivateRecordAbsence=absence,
            originalLogicalPathsRewritten=False,normalAppWorkerBoundaryValidated=True,parentSdkBuildValidated=True,
            archivedNormalEnvelopeValidated=True,compilerOrReaderExecuted=False,**_SCOPED)


def capture_link_fields(index,proof,compiler,toolset):
    """Link original captured descriptors; saved normal flags are not verdicts."""
    require(index['existingFinalArchive']==proof['sdkArchive']and index['existingToolset']==toolset
        and index['originalCompilerProof']==proof['componentCompilerProofs']['sdk']
        and index['originalConsumerReplays']==compiler['proof']['replays'],
        'Actual capture must bind this same original final/toolset/SDK proof and both consumer replays')
    return True


def _all_delivery_origins(view,record,D):
    """Shared path-opening predicates may read only the captured sealed packet."""
    count=0;record_fp=A.fingerprint(A.canonical(record))
    for parent,dirs,names in os.walk(view.release_root,followlinks=False):
        for name in names:
            path=A.ordinary(Path(parent)/name,file=True);relative=path.relative_to(view.release_root).as_posix()
            original=D+'/'+relative;origin=view.require_origin(original)
            require(origin['member']==relative and origin['originalLogicalPath']==original
                and origin['originalArchivedPath']==original and origin['recordFingerprint']==record_fp
                and view.path(original)==path,'Every shared consumer file must have its actual captured delivery origin')
            count+=1;require(count<=view.budget.file_limit,'Bounded consumer delivery physical file set required')
    require(count>0,'Actual captured consumer delivery is empty')
    return count


def _delivery_json(view,record,D,relative,descriptor=None):
    raw,origin=_delivery_body(view,record,D,relative,8*1024**2)
    if descriptor is not None:
        require(type(descriptor)is dict and set(descriptor)=={'path',*FP}and descriptor['path']==relative
            and {key:descriptor[key]for key in FP}==A.fingerprint(raw),
            'Explicit consumer descriptor differs from actual captured delivery bytes')
    return A.unique_json(raw),origin


def _capture_origins(app,capture_source_root):
    source,view=app.source,app.view
    require(isinstance(capture_source_root,str)and capture_source_root==app.capture_source_root,
        'Exact core-selected actual capture source root required')
    root=source.root_for(view.logical_root('consumption-capture'),kind='tree',role=C.KIND)
    require(root['name']==capture_source_root,'Actual capture root role/original path differs')
    physical=view.root_path('consumption-capture');original=root['originalPath']
    C.validate_data(physical)
    raw=view.read(original+'/capture-index.json',C.MAX_FILE);index=A.unique_json(raw,limit=C.MAX_FILE)
    members={'capture-index.json',*(row['member']for row in index['originalLogicalPaths'].values())}
    source.assert_closed_root(capture_source_root,members,kind='tree',role=C.KIND)
    for member in members:
        origin=view.require_origin(original+'/'+member)
        require(origin['root']==capture_source_root and origin['member']==capture_source_root+'/'+member
            and origin['role']==C.KIND and origin['originalLogicalPath']==original+'/'+member
            and origin['originalArchivedPath']==original+'/'+member
            and origin['archive']==source.archive.fingerprint and origin['index']==source.index.fingerprint
            and origin['mode']==0o644 and view.path(original+'/'+member)==physical/member,
            'Actual immutable indexed capture data origin required')
    require(view.logical_root('consumer-sdk')==C.MOUNT
        and view.logical_root('consumer-feed')=='/work/inputs/bootstrap-feed',
        'Exact original SDK/cache/feed consumer logical roots required')
    sdk=view.root_path('consumer-sdk');feed=view.root_path('consumer-feed')
    for logical,row in index['originalLogicalPaths'].items():
        origin=view.require_origin(logical,namespace='consumer')
        require(origin['root']==capture_source_root and origin['member']==capture_source_root+'/'+row['member']
            and origin['role']==C.KIND and origin['originalLogicalPath']==logical
            and origin['originalArchivedPath']==original+'/'+row['member']
            and origin['fingerprint']=={key:row[key]for key in FP}and origin['mode']==0o644,
            'Actual SDK/feed/Copy physical view must come solely from its original captured observation')
        expected=feed/M.PACKAGE if logical=='/work/inputs/bootstrap-feed/'+M.PACKAGE else sdk/C._logical(logical)
        require(view.path(logical,namespace='consumer')==expected,
            'Captured consumer observation must preserve its exact SDK-relative physical layout')
    code=C.code_pins()
    require(index['captureCode']==code,'Captured validator source identities differ from reviewed current code')
    selected=source.select({'orchestration/scripts/'+name for name in code},max_total=16*1024**2,max_file=8*1024**2)
    for name,expected in code.items():
        require(A.fingerprint(selected['orchestration/scripts/'+name]['raw'])==expected,
            'Actual archived capture/consumer validator source bytes differ')
    return index,sdk,feed


def final_sdk_record_fields(record,producer):
    """Keep the authenticated caller SDK identity at the original M boundary."""
    require(type(record.get('sdk'))is dict and producer.get('sdk')==record['sdk'],
        'Actual final producer SDK descriptor differs from authenticated parent SDK')


def validate_archived_sdk_consumption(app,*,sdk_proof_descriptor,tooling_descriptor,capture_source_root):
    """Recompute actual captured consumption only after the genuine core factory.

    The live M supplier selector is not patched or called. Saved capture normal
    flags and caller-authored supplier dictionaries cannot supply this entry.
    """
    require_posix();app=A.require_reconstructed(app)
    require(type(app.source)is A.SourceSession and type(app.view)is A.FrozenView and app.view.source is app.source
        and app.view.frozen and app.source.verified,'Actual reconstructed supplier/session/frozen view required')
    view,source=app.view,app.source;bound=app.normal_context;record=app.record;D=bound['context']['paths']['delivery']
    require(bound['record']==record and A.fingerprint(A.canonical(app.delivery.record))==A.fingerprint(A.canonical(record)),
        'Concrete reconstructed supplier must retain this same captured parent inventory')
    boundary=validate_archived_normal_boundary(view,bound,source)
    application=app.application
    require(type(application)is dict and 'package'in application and 'members'in application and M.MEMBER in application['members'],
        'Independently recomputed genuine core application/package facts required')
    package=A.fields(application['package']);product=A.identity(application['members'][M.MEMBER])
    with view.guard():
        checked_files=_all_delivery_origins(view,record,D)
        proof,_=_delivery_json(view,record,D,'reports/legacy-construction.json')
        require(type(sdk_proof_descriptor)is dict and sdk_proof_descriptor==proof['componentCompilerProofs']['sdk'],
            'Actual SDK proof descriptor must equal the original E5 compiler proof role')
        require(type(tooling_descriptor)is dict and tooling_descriptor.get('path')=='reports/build/sdk/results.json',
            'Exact original tooling result descriptor required')
        tooling,_=_delivery_json(view,record,D,tooling_descriptor['path'],tooling_descriptor)
        producer,_=_delivery_json(view,record,D,'producer-sdk.json')
        for key in('sdkVersion','architecture','targetRid','projectCommit','runId','runAttempt'):
            require(producer.get(key)==record.get(key),'Actual final producer identity differs from captured parent')
        final_sdk_record_fields(record,producer)
        final=M.CONSTRUCTION.validate_final_sdk_archive(record,proof)
        final_path=M.B.checked(view.release_root,final)
        roots={row['name']:dict(path=row['originalPath'],kind=row['kind'],commit=row.get('commit'),role=row.get('role'))
            for row in source.manifest['roots']}
        require(len(roots)==len(source.manifest['roots']),'Unique actual archived source root identities required')
        artifact=proof['artifacts'].get('package-'+package['sha256'])
        require(type(artifact)is dict and artifact.get('kind')=='managed-package'and artifact.get('sourceCommit')==M.SOURCE_COMMIT
            and artifact.get('sourceRoot')in roots and roots[artifact['sourceRoot']]['commit']==M.SOURCE_COMMIT
            and all(artifact.get(key)==package[key]for key in FP)
            and artifact.get('path')=='imported-inputs/'+package['sha256']+'.nupkg',
            'Actual genuine App package/source/canonical artifact role required')
        M.B.checked(view.release_root,{key:artifact[key]for key in('path',*N.FP)})
        toolset=M.validate_toolset_member(view.release_root,proof,product)
        compiler=M.CE.validate(view.release_root,sdk_proof_descriptor,roots)
        require(len(compiler['proof']['packages'])==1
            and all(compiler['proof']['packages'][0][key]==toolset[key]for key in FP),
            'App must be in the actual independently validated SDK compiler-produced toolset')
        index,sdk,feed=_capture_origins(app,capture_source_root)
        capture_link_fields(index,proof,compiler,toolset)
        M.validate_tooling(tooling,package)
        cache=M.validate_cache(sdk,feed,package,product)
        consumers=M.validate_sdk_tasks(view.release_root,sdk,compiler,product)
        installer_path=M.B.checked(view.release_root,proof['installerBuildReplay'])
        installer=A.unique_json(installer_path.read_bytes(),limit=8*1024**2)
        transformations=[row for row in installer['transformations']if row['archivePath']==M.LAYOUT]
        require(len(transformations)<=1,'One final original SDK App Crossgen transformation at most')
        final_product=None
        with tarfile.open(final_path,'r|gz')as archive:
            for entry in archive:
                if entry.name.removeprefix('./')!=M.LAYOUT:continue
                require(entry.isfile()and final_product is None and 0<entry.size<=8*1024**2,
                    'One bounded ordinary actual final App SDK member required')
                raw=archive.extractfile(entry).read(8*1024**2+1)
                require(len(raw)==entry.size,'Complete actual final App SDK member required')
                final_product=A.fingerprint(raw)
        require(final_product is not None,'Actual final SDK App member missing')
        if transformations:
            row=transformations[0]
            require(row['input']=='toolset'and row['member']=='Microsoft.ApplicationInsights.dll'
                and row['inputSha256']==product['sha256']and row['outputSha256']==final_product['sha256'],
                'Final original Crossgen must bind actual genuine pre-Crossgen App bytes')
            replay=installer['replay'];tasks=M.B.read_tasks(M.B.checked(view.release_root,replay['tasks']))
            crossgen=M.CE.validate_crossgen_task(row,replay,tasks,installer['sourceCrossgenRecord'])
        else:
            require(final_product==product,'Actual final App bytes changed without original Crossgen task');crossgen=None
        return dict(kind='sdk5-archived-genuine-App-actual-sdk-consumption',package=package,product=product,cache=cache,
            toolset=toolset,sdkConsumers=consumers,finalProduct=final_product,crossgen=crossgen,normalBoundary=boundary,
            originalCaptureIndexValidated=True,actualCapturedConsumptionRecomputed=True,checkedDeliveryFiles=checked_files,
            sourceDisposition=dict(path=M.LAYOUT,sourceRoot=artifact['sourceRoot'],sourceCommit=M.SOURCE_COMMIT,
                fingerprint=product,allowedPackageMembers=[dict(packageSha256=package['sha256'],member=M.MEMBER)],
                sourceBasis='genuine-archived-App5-source-build-and-actual-captured-sdk-consumption'),
            savedNormalBooleansUsedAsProof=False,originalLogicalPathsRewritten=False,compilerOrReaderExecuted=False,**_SCOPED)
