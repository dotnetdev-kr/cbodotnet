"""One finite, nonshipping external Profile7 reference-bootstrap boundary.

The original full522 constructor and strong validator are unchanged. Public
product-source validation is partial. Full archived construction fails closed
until the original Mono import decoder and genuine normal positive are closed.
No entry in this module acquires inputs, launches tools or admits an SDK.
"""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import shutil
import stat
import tarfile
import zipfile

import musl_legacy5_appinsights_normal as N
import musl_legacy5_appinsights_imports as IMPORTS

require=N.require
ROLE='sdk5-app-profile7-reference-bootstrap'
KIND='explicit-normal-docker-App5-finite-reference-bootstrap'
POLICY_FILE='musl-legacy5-appinsights-reference-bootstrap-policy.json'
POLICY_SHA256='e25c59d269f84ce84d7b3a1a4122d05dd35ddb061d80d4149dca34ffd8bc1ed5'
FP=N.FP
MAX_EXPORT=64*1024**2
MAX_ENTRIES=4096
MAX_DEPTH=4
PENDING=('original-mono-bootstrap-import-graph',
    'genuine-normal-archive-backed-construction-positive','actual-sdk-consumer-source-and-copy-binding')


def policy():
    path=Path(__file__).with_name(POLICY_FILE);raw=N.ordinary(path,file=True).read_bytes()
    require(hashlib.sha256(raw).hexdigest()==POLICY_SHA256,'Immutable finite Profile7 role policy differs')
    p=json.loads(raw);strong,worker=N.original_validators()
    require(N.fingerprint(Path(__file__).with_name('musl-legacy5-appinsights-build-policy.json'))==p['originalPolicy']
        and p['role']==ROLE and p['sdkVersion']==N.SDK and p['schemaVersion']==1
        and p['fullPrivateInputCount']==522 and len(p['privateInputFiles'])==73
        and p['publicInputCount']==len(p['publicInputNames'])==449
        and len(set(p['publicInputNames']))==449 and not(set(p['publicInputNames'])&p['privateInputFiles'].keys())
        and p['referenceAssemblyCount']==65 and p['profileMemberCount']==70
        and p['referenceArchive']==worker.policy()['referenceZip']['fingerprint']
        and all(p[key]is False for key in ('payloadRole','referencePreferredSourceEstablished',
            'licenseCoverageClaimed','binaryRedistributionApproved','rawArtifactKindsChanged',
            'wholeProducerSourceClosure','qualificationAllowed','sourceAdmissionAllowed'))
        and p['compilerReferenceOnly']is True and tuple(p['pendingConstructionGates'])==PENDING,
        'Only one finite unchanged external reference role is permitted')
    return p


def role_record():
    policy();return dict(role=ROLE,policy=N.fingerprint(Path(__file__).with_name(POLICY_FILE)))


def validate_role(value):
    require(value==role_record(),'Exact finite external reference role and policy identity required')
    return value


def normal_context(record,prepare,**paths):
    return N.normal_context(record,prepare,reference_bootstrap=role_record(),**paths)


def finite_context(context):
    N.validate_context(context)
    require(context['kind']==KIND and context['schemaVersion']==2
        and context['referenceBootstrap']==role_record()
        and Path(context['paths']['attempt'])==Path(context['paths']['workspace'])/'private/appinsights',
        'Explicit finite normal context outside the delivery tree required')
    return context


def _mode(name,source_files):
    if name.startswith('source/'):
        return 0o755 if source_files[name[len('source/'):]]['mode']=='100755'else 0o644
    return 0o644


def public_input_fingerprints():
    strong,worker=N.original_validators();p=worker.policy();rows={}
    rows.update({'source/'+name:{key:row[key]for key in FP}for name,row in p['source']['files'].items()})
    prefix='mcs/tools/xbuild/data/Portable/Targets/'
    rows.update({('portable/'+name[len(prefix):]if name.startswith(prefix)else'licenses/Mono-target-LICENSE'):
        {key:row[key]for key in FP}for name,row in p['portableTargets']['files'].items()})
    rows.update({'reader/'+name:row for name,row in p['reader']['sourceFiles'].items()})
    rows.update({'execution/'+name:row for name,row in strong.WORKER_SOURCES.items()})
    rows['recipe/App.PCL.proj']=worker.fingerprint(worker.project_bytes(p))
    rows['NuGet.Config']=worker.fingerprint(b'<configuration><packageSources><clear /></packageSources></configuration>\n')
    require(set(rows)==set(policy()['publicInputNames']),'Closed original public449 source input identities required')
    return rows


def verify_private_inputs(workspace):
    p=policy();strong,worker=N.original_validators();workspace=N.ordinary(workspace,directory=True)
    N.ordinary(workspace/'input-manifest.json',file=True);actual=N.tree_files(workspace/'inputs')
    manifest=worker.verify_inputs(workspace)
    require(set(actual)==set(p['publicInputNames'])|p['privateInputFiles'].keys()
        and len(actual)==522 and actual==manifest['files'],'Actual complete original522 input tree required')
    source_files=worker.policy()['source']['files']
    for name,row in actual.items():
        require(row['mode']==_mode(name,source_files),'Exact original finite-reference input permission required: '+name)
    for name,want in p['privateInputFiles'].items():
        require({key:actual[name][key]for key in FP}==want,'Exact original private reference/comparison bytes required')
    return dict(inputManifest=N.descriptor(workspace/'input-manifest.json'),inputFiles=actual,
        privateInputFiles={name:actual[name]for name in p['privateInputFiles']},fullPrivateInputCount=522)


def _notice(path):
    p=policy();path=N.ordinary(path,file=True);raw=path.read_bytes();expected=p['referenceOrigin']
    require(len(raw)==expected['notice']['bytes'] and hashlib.sha256(raw).hexdigest()==expected['notice']['sha256']
        and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected['noticeGitBlob'],
        'Exact original historical reference-distribution notice required')
    return raw


def prepare_normal(source,reference_zip,targets,original_package,reader_source,*,context,historical_notice):
    context=finite_context(context);notice=_notice(historical_notice)
    result=N.prepare_normal(source,reference_zip,targets,original_package,reader_source,context=context)
    workspace=Path(context['paths']['attempt']);(workspace/'origin').mkdir()
    (workspace/'origin/historical-reference-notice.txt').write_bytes(notice)
    (workspace/'origin/historical-reference-notice.txt').chmod(0o644)
    N.write(workspace/'finite-reference-prepared.json',dict(kind=KIND,role=role_record(),
        fullPrivateInputs=verify_private_inputs(workspace),historicalNotice=N.descriptor(workspace/'origin/historical-reference-notice.txt'),
        payloadRole=False,referencePreferredSourceEstablished=False,sourceAdmissionAllowed=False))
    return dict(**result,finiteReferenceRole=role_record(),publicExportPerformed=False)


def execute_normal(context,*,producer):
    context=finite_context(context);workspace=Path(context['paths']['attempt'])
    _notice(workspace/'origin/historical-reference-notice.txt');verify_private_inputs(workspace)
    return N.execute_normal(context,producer=producer)


def _copy(source,target,expected,mode):
    source=N.ordinary(source,file=True);target=N.ordinary(target)
    require(not target.exists()and N.fingerprint(source)==expected,'Fresh mode-preserving exact public source copy required')
    target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb')as src,target.open('xb')as dst:shutil.copyfileobj(src,dst,65536)
    target.chmod(mode);require(N.fingerprint(target)==expected and stat.S_IMODE(target.stat().st_mode)==mode,
        'Copied public App source bytes or original permissions differ')


def _forbidden(workspace):
    p=policy();inputs=Path(workspace)/'inputs'
    result={name:N.ordinary(inputs/name,file=True).read_bytes()for name in p['privateInputFiles']}
    # The whole old comparison NPK is separate from the original comparison PE.
    with zipfile.ZipFile(io.BytesIO(result['original.nupkg']))as archive:
        result['comparison-publisher-dll']=archive.read('lib/dotnet5.4/Microsoft.ApplicationInsights.dll')
    require(all(raw for raw in result.values()),'Nonempty exact private exclusion bodies required')
    return result


def _scan_body(raw,forbidden,*,depth,budget):
    require(depth<=MAX_DEPTH,'Public App container nesting limit exceeded')
    budget['bytes']+=len(raw);budget['entries']+=1
    require(budget['bytes']<=MAX_EXPORT and budget['entries']<=MAX_ENTRIES,'Public App expanded content budget exceeded')
    for role,body in forbidden.items():
        require(body and (len(body)>len(raw)or body not in raw),'Private reference/comparison bytes cannot be published: '+role)
        if (len(body)+2)//3*4<=len(raw):
            require(base64.b64encode(body)not in raw,'Encoded private reference/comparison bodies cannot be published: '+role)


def scan_content(raw,forbidden,*,name='public',depth=0,budget=None):
    """Check real byte bodies, including bounded compressed/container members."""
    if budget is None:budget={'bytes':0,'entries':0}
    _scan_body(raw,forbidden,depth=depth,budget=budget)
    if raw.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(raw))as stream:expanded=stream.read(MAX_EXPORT+1)
        require(len(expanded)<=MAX_EXPORT,'Bounded public gzip stream required')
        return scan_content(expanded,forbidden,name=name+'!gzip',depth=depth+1,budget=budget)
    if len(raw)>262 and raw[257:262]==b'ustar':
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
            seen=set()
            for entry in archive:
                require(entry.name not in seen and not entry.name.startswith('/')and '\\'not in entry.name and '..'not in PurePosixPath(entry.name).parts
                    and not entry.mode&0o7000 and (entry.isdir()or entry.isreg()),'Ordinary unique bounded public TAR member required')
                seen.add(entry.name)
                if entry.isdir():continue
                require(entry.size<=MAX_EXPORT,'Bounded public TAR member required')
                scan_content(archive.extractfile(entry).read(MAX_EXPORT+1),forbidden,name=entry.name,depth=depth+1,budget=budget)
        return budget
    # MSBuild binary logs may contain an embedded project-import ZIP. Inspect
    # each complete ZIP envelope rather than assuming the .binlog suffix is safe.
    start=0
    while(start:=raw.find(b'PK\x03\x04',start))!=-1:
        end=raw.find(b'PK\x05\x06',start)
        require(end>=0 and end+22<=len(raw),'Unclosed public ZIP envelope is forbidden')
        end+=22+int.from_bytes(raw[end+20:end+22],'little')
        require(end<=len(raw),'Bounded complete public ZIP envelope required')
        with zipfile.ZipFile(io.BytesIO(raw[start:end]))as archive:
            entries=archive.infolist();names=[row.filename for row in entries]
            require(len(names)==len(set(names))and len(entries)<=MAX_ENTRIES,'Unique bounded public ZIP members required')
            for entry in entries:
                mode=entry.external_attr>>16
                require(not entry.filename.startswith('/')and '\\'not in entry.filename and '..'not in PurePosixPath(entry.filename).parts
                    and not mode&0o7000 and stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR)
                    and not entry.flag_bits&1 and entry.file_size<=MAX_EXPORT,'Ordinary bounded unencrypted public ZIP member required')
                if not entry.is_dir():
                    scan_content(archive.read(entry),forbidden,name=entry.filename,depth=depth+1,budget=budget)
        start=end
    return budget


def _scan_original_binlog(raw,forbidden,*,role,expected,budget):
    """A parsed, policy-bound import ZIP is the only logical-name exception."""
    p=IMPORTS.policy();require(role in p['logs'],'One exact original binlog role required')
    decoded=IMPORTS.decode_binlog(raw,expected,expected_format=p['logs'][role]['format'])
    members=IMPORTS.import_members(decoded,p['logs'][role]['originalMembers'])
    _scan_body(raw,forbidden,depth=0,budget=budget)
    _scan_body(decoded['expanded'],forbidden,depth=1,budget=budget)
    archive=decoded['archive']
    scan_content(decoded['expanded'][:archive['offset']],forbidden,depth=2,budget=budget)
    scan_content(decoded['expanded'][archive['end']:],forbidden,depth=2,budget=budget)
    for logical,row in members.items():scan_content(row['raw'],forbidden,name=logical,depth=2,budget=budget)


def _normal_binlog_specs(value):
    if value is None:return{}
    require(type(value)is dict and value.get('kind')=='scoped-normal-App-original-import-provenance'
        and set(value.get('logs',{}))=={'app','reader-build'}and value.get('actualOriginalInputsAndProcessesRead')is True,
        'Current actual normal import provenance required for narrow binlog publication')
    specs={}
    for role,row in value['logs'].items():
        require(row.get('kind')=='scoped-actual-original-App-import-bindings'and row.get('role')==role
            and row.get('actualMountedInputBytesCompared')is True and set(row['binlog'])==set(FP),
            'Exact actual normal binlog role and complete bytes identity required')
        specs['evidence/output/'+role+'.binlog']=dict(role=role,expected=row['binlog'])
    return specs


def scan_public_tree(root,*,private_workspace,normal_imports=None):
    rows=N.tree_files(root);require(len(rows)<=MAX_ENTRIES,'Bounded public App tree required')
    forbidden=_forbidden(private_workspace);budget={'bytes':0,'entries':0};binlogs=_normal_binlog_specs(normal_imports)
    require(set(binlogs)<=set(rows),'Both bound original binlogs must exist in the scanned public tree')
    for name in rows:
        raw=(Path(root)/name).read_bytes()
        if name in binlogs:_scan_original_binlog(raw,forbidden,budget=budget,**binlogs[name])
        else:scan_content(raw,forbidden,name=name,budget=budget)
    return dict(kind='actual-public-App-content-exclusion',files=len(rows),expandedScanBytes=budget['bytes'],
        excludedPrivateInputs=73,excludedOriginalComparisonDll=True,allActualBodiesChecked=True)


def _checked_public_buffers(root,*,private_workspace,normal_imports=None):
    """Read and scan every candidate before a delivery target can be opened."""
    rows=N.tree_files(root)
    require(len(rows)<=MAX_ENTRIES and sum(row['bytes']for row in rows.values())<=MAX_EXPORT,
        'Bounded complete public App publication required')
    forbidden=_forbidden(private_workspace);budget={'bytes':0,'entries':0};buffers={};binlogs=_normal_binlog_specs(normal_imports)
    require(set(binlogs)<=set(rows),'Both actual normal original binlog files must be staged for publication')
    for name,row in rows.items():
        path=N.ordinary(Path(root)/name,file=True)
        with path.open('rb')as stream:raw=stream.read(row['bytes']+1)
        actual=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())
        require(actual=={key:row[key]for key in FP},'Public App candidate changed before publication')
        if name in binlogs:_scan_original_binlog(raw,forbidden,budget=budget,**binlogs[name])
        else:scan_content(raw,forbidden,name=name,budget=budget)
        buffers[name]=dict(raw=raw,mode=row['mode'],fingerprint=actual)
    require(N.tree_files(root)==rows,'Public App candidate tree changed before publication')
    return buffers


def _publish_checked_public_tree(root,destination,*,private_workspace,normal_imports=None):
    """Publish exactly the checked immutable buffers, never reopen staged input."""
    root=N.ordinary(root,directory=True);destination=N.ordinary(destination)
    require(not destination.exists()and root not in destination.parents and destination not in root.parents,
        'Fresh distinct checked public App delivery root required')
    buffers=_checked_public_buffers(root,private_workspace=private_workspace,normal_imports=normal_imports)
    destination.mkdir(parents=True)
    for name,row in buffers.items():
        target=N.ordinary(destination/name);target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb')as stream:stream.write(row['raw'])
        target.chmod(row['mode'])
        require(N.fingerprint(target)==row['fingerprint']and stat.S_IMODE(target.stat().st_mode)==row['mode'],
            'Published checked public App bytes or permissions differ')
    return dict(files=len(buffers),bytes=sum(len(row['raw'])for row in buffers.values()),
        allCandidatesScannedBeforeFirstDeliveryWrite=True,deliveryWrittenFromCheckedBuffers=True)


def _export_source(workspace,destination,proof,*,private_control):
    p=policy();workspace=N.ordinary(workspace,directory=True);destination=N.ordinary(destination)
    require(not destination.exists()and destination not in workspace.parents and workspace not in destination.parents,
        'Fresh distinct App source export root required')
    inputs=verify_private_inputs(workspace);destination.mkdir(parents=True)
    source=destination/'product-source';source.mkdir();rows={}
    for name in p['publicInputNames']:
        original=workspace/'inputs'/name;target=source/name;row=inputs['inputFiles'][name]
        _copy(original,target,{key:row[key]for key in FP},row['mode'])
        rows[name]=dict(originalInputPath='/inputs/'+name,**row)
    require(len(rows)==449 and sum(row['bytes']for row in rows.values())==p['publicInputBytes'],
        'Exact original449 public source files and byte count required')
    _copy(workspace/'input-manifest.json',destination/'original-private-input-manifest.json',
        {key:inputs['inputManifest'][key]for key in FP},0o644)
    record=dict(schemaVersion=1,kind='finite-App5-public-product-source',role=role_record(),publicFiles=rows,
        originalPrivateInputManifest=inputs['inputManifest'],privateInputs=inputs['privateInputFiles'],
        sourceProof=proof,retainedPrivateControlOnly=private_control,
        oldComparisonInputRole=p['originalComparisonRole'],payloadRole=False,
        referencePreferredSourceEstablished=False,constructionValidated=False,
        pendingConstructionGates=list(PENDING),wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    N.write(destination/'export-record.json',record)
    scan=scan_public_tree(destination,private_workspace=workspace)
    N.write(destination/'content-exclusion.json',scan)
    return dict(sourceTree=str(source),publicExport=N.descriptor(destination/'export-record.json'),
        privateInputManifest=inputs['inputManifest'],contentExclusion=scan,constructionValidated=False,sourceAdmissionAllowed=False)


def export_retained_private_control(workspace,host_roots,destination):
    """Read-only old private positive/control; never a genuine normal result."""
    verify_private_inputs(workspace);strong,worker=N.original_validators();proof=strong.validate(workspace,host_roots)
    return _export_source(workspace,destination,proof,private_control=True)


def compiler_output_origins(workspace,genuine,imports):
    """Retain actual Csc intermediates/generated sources, never reconstruct them."""
    workspace=N.ordinary(workspace,directory=True);execution=genuine['execution'];boundary=execution['boundary']
    context=finite_context(boundary['context'])
    require(genuine['kind']=='actual-normal-genuine-App5-package'
        and execution['kind']=='actual-normal-offline-App5-and-frozen-reader-execution'
        and boundary['kind']=='normal-App5-Docker-boundary'and boundary['normalAppWorkerBoundaryValidated']is True
        and boundary['parentSdkBuildValidated']is False and workspace==Path(context['paths']['attempt'])
        and imports['kind']=='scoped-normal-App-original-import-provenance'and imports['normalBoundary']==boundary
        and imports['actualOriginalInputsAndProcessesRead']is True
        and imports['normalParentBuildRequiredAtAdmission']is True,
        'Actual matching finite normal compiler and import boundaries required for output origins')
    normal_file=N.ordinary(workspace/'normal-context.json',file=True)
    require(normal_file.stat().st_size<=1024**2 and N.read(normal_file)==context,
        'Actual unchanged normal context required for compiler output origins')
    for key,name in(('invocation','normal-container-invocation.json'),('result','normal-container-result.json'),('stage','normal-app-stage.json')):
        require(boundary[key]==N.descriptor(workspace/name),'Actual original normal boundary descriptor differs')
    generated=('reader-obj/Debug/net6.0/.NETCoreApp,Version=v6.0.AssemblyAttributes.cs',
        'reader-obj/Debug/net6.0/Reader.AssemblyInfo.cs','reader-obj/Debug/net6.0/Reader.GlobalUsings.g.cs')
    specifications=(('app','appCompiler','rawAppBinlog','obj/Microsoft.ApplicationInsights.dll',()),
        ('reader-build','readerCompiler','rawReaderBuildBinlog','reader-obj/Debug/net6.0/Reader.dll',generated))
    rows={};total=0;import_policy=IMPORTS.policy()
    for role,compiler,key,compiled,source_names in specifications:
        record=execution[compiler];log=imports['logs'][role]
        expected_import=import_policy['logs'][role]
        require(record['projectFile']==expected_import['project']and record['taskFile']==expected_import['compilerTarget']
            and log['role']==role and log['actualMountedInputBytesCompared']is True
            and log['binlog']==execution[key]==N.fingerprint(workspace/'output'/(role+'.binlog')),
            'Actual original compiler raw-log identity required for output origins')
        compiled_row=record['compiledOutput']
        require(set(compiled_row)=={'path',*FP}and compiled_row['path']=='/output/'+compiled,
            'One exact original Csc intermediate output path required')
        if source_names:
            require({name for name in record['sources']if name.startswith('/output/')}=={'/output/'+name for name in source_names},
                'Exactly three original Reader generated Csc source paths required')
        csc=record['context'];parts=csc.split(':')if isinstance(csc,str)else[]
        require(len(parts)==4 and len(csc)<=128 and all(str(int(part))==part for part in parts),
            'Original Csc context required for output origins')
        command=record['commandLine'];require(isinstance(command,str)and 0<len(command)<=1024**2,
            'Bounded original Csc argv required for output origins')
        command_fp=IMPORTS.fingerprint(command.encode('utf-8'))
        for name in(compiled,*source_names):
            expected=({key:compiled_row[key]for key in FP}if name==compiled else record['sources']['/output/'+name])
            require(set(expected)==set(FP)and type(expected['bytes'])is int and 0<expected['bytes']<=8*1024**2,
                'Exact bounded original compiler output/source fingerprint required')
            path=N.ordinary(workspace/'output'/name,file=True)
            require(N.fingerprint(path)==expected,'Actual original compiler output/source bytes differ')
            total+=expected['bytes'];require(total<=16*1024**2,'Five compiler output/source origin budget exceeded')
            rows[name]=dict(originalLogicalPath='/output/'+name,originalPhysicalPath=str(path),fingerprint=expected,
                originalMode=stat.S_IMODE(path.stat().st_mode),role='compiled-output'if name==compiled else'generated-reader-source',
                compilerRole=role,cscContext=csc,projectFile=record['projectFile'],taskFile=record['taskFile'],
                commandLineFingerprint=command_fp,rawBinlog=dict(path='/output/'+role+'.binlog',**log['binlog']))
    require(len(rows)==5,'Exactly five actual compiler output/source origins required')
    return dict(kind='scoped-actual-normal-App-compiler-output-origins',normalContext=N.descriptor(normal_file),
        normalSourceBoundary={key:boundary[key]for key in('invocation','result','stage')},files=rows,
        actualCurrentFilesCompared=True,originalReportPathsRewritten=False,parentSdkBuildValidated=False,
        archivedConstructionValidated=False,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def package_normal(workspace,host_roots,*,normal_context):
    context=finite_context(normal_context['context']);require(Path(workspace)==Path(context['paths']['attempt']),
        'Exact current finite normal App attempt required')
    verify_private_inputs(workspace);_notice(Path(workspace)/'origin/historical-reference-notice.txt')
    genuine=N.package_normal(workspace,host_roots,normal_context=normal_context)
    imports=IMPORTS.validate_normal_logs(workspace,host_roots,normal_context=normal_context)
    compiler_origins=compiler_output_origins(workspace,genuine,imports)
    destination=Path(context['paths']['delivery'])/'reports/build/appinsights'
    # The workflow archives all D even on failure. Assemble and check outside D,
    # including all dynamic logs/binlogs, before any delivery file is created.
    staging=Path(workspace).parent/'appinsights-public'
    exported=_export_source(workspace,staging,genuine,private_control=False)
    validate_public_source(staging)
    _copy(Path(workspace)/'origin/historical-reference-notice.txt',staging/'origin/historical-reference-notice.txt',
        N.fingerprint(Path(workspace)/'origin/historical-reference-notice.txt'),0o644)
    output=Path(workspace)/'output';evidence=staging/'evidence'
    # Explicit names only: inputs, HOME/cache and arbitrary worker outputs are
    # never recursively copied into the workflow's all-delivery upload tree.
    names=['normal-context.json','normal-prepared.json','normal-container-invocation.json','normal-container-result.json',
        'normal-app-stage.json','normal-container.log','finite-reference-prepared.json']
    for name in names:_copy(Path(workspace)/name,evidence/name,N.fingerprint(Path(workspace)/name),0o644)
    output_names=['actual-app-process.json','actual-reader-build-process.json','actual-reader-processes.json',
        'app-build.log','reader-build.log','app-reader.log','reader-build-reader.log','app.binlog','reader-build.binlog',
        'worker-completed.json','genuine-normal-package.json','reader/Reader.dll',
        'replay/app-status.json','replay/app-tasks.jsonl','replay/reader-build-status.json','replay/reader-build-tasks.jsonl',
        'app/Microsoft.ApplicationInsights.dll','app/Microsoft.ApplicationInsights.pdb','app/Microsoft.ApplicationInsights.xml']
    output_names+=list(IMPORTS.GENERATED)
    output_names+=sorted(compiler_origins['files'])
    strong,worker=N.original_validators()
    output_names += [name[len('/output/'):]for name in strong.generated_metadata(worker.policy())]
    for name in output_names:
        expected=(imports['logs'][name[:-len('.binlog')]]['binlog']if name in('app.binlog','reader-build.binlog')
            else imports['generatedReaderFiles'][name]if name in IMPORTS.GENERATED
            else compiler_origins['files'][name]['fingerprint']if name in compiler_origins['files']else N.fingerprint(output/name))
        _copy(output/name,evidence/'output'/name,expected,0o644)
    product=staging/'product'/N.PACKAGE;_copy(output/N.PACKAGE,product,N.fingerprint(output/N.PACKAGE),0o644)
    N.write(staging/'finite-reference-use.json',dict(kind=KIND,role=role_record(),context=context,
        genuineNormalProof=genuine,privateInputManifest=exported['privateInputManifest'],
        payloadRole=False,referencePreferredSourceEstablished=False,wholeProducerSourceClosure=False,sourceAdmissionAllowed=False))
    N.write(staging/'original-import-bindings.json',imports)
    N.write(staging/'compiler-output-origins.json',compiler_origins)
    publication=_publish_checked_public_tree(staging,destination,private_workspace=workspace,normal_imports=imports)
    exported.update(sourceTree=str(destination/'product-source'),publicExport=N.descriptor(destination/'export-record.json'))
    return dict(**exported,supplierPackage=N.descriptor(destination/'product'/N.PACKAGE),
        finiteBootstrapUse=N.descriptor(destination/'finite-reference-use.json'),publicContentPublication=publication,
        finiteReferenceRole=role_record(),wholeProducerSourceClosure=False,qualificationAllowed=False)


def validate_public_source(root):
    """Public449 source correspondence only: always a partial result."""
    root=N.ordinary(root,directory=True);p=policy();record=N.read(root/'export-record.json')
    require(set(record)=={'schemaVersion','kind','role','publicFiles','originalPrivateInputManifest','privateInputs',
        'sourceProof','retainedPrivateControlOnly','oldComparisonInputRole','payloadRole','referencePreferredSourceEstablished',
        'constructionValidated','pendingConstructionGates','wholeProducerSourceClosure','qualificationAllowed','sourceAdmissionAllowed'}
        and record['schemaVersion']==1 and record['kind']=='finite-App5-public-product-source'
        and record['role']==role_record()and record['constructionValidated']is False
        and record['sourceAdmissionAllowed']is record['qualificationAllowed']is record['wholeProducerSourceClosure']is False
        and record['referencePreferredSourceEstablished']is record['payloadRole']is False
        and record['oldComparisonInputRole']==p['originalComparisonRole']
        and record['pendingConstructionGates']==list(PENDING),'Closed scoped public App source record required')
    source=N.tree_files(root/'product-source');require(set(source)==set(p['publicInputNames']),
        'Exactly449 original public source files required; no private payload or extra file')
    manifest=N.read(root/'original-private-input-manifest.json');require(len(manifest['files'])==522
        and set(manifest['files'])==set(p['publicInputNames'])|p['privateInputFiles'].keys()
        and {key:record['originalPrivateInputManifest'][key]for key in FP}==N.fingerprint(root/'original-private-input-manifest.json')
        and set(record['publicFiles'])==set(p['publicInputNames']),
        'Original complete private input manifest must remain public evidence')
    expected=public_input_fingerprints();strong,worker=N.original_validators();source_files=worker.policy()['source']['files']
    for name,row in source.items():
        require(row==manifest['files'][name]and record['publicFiles'][name]==dict(originalInputPath='/inputs/'+name,**row)
            and row['mode']==_mode(name,source_files),'Exact public source bytes/modes/original mapping required')
        require({key:row[key]for key in FP}==expected[name],'Exact original App/Mono/Reader/worker/adjunct public source bytes required')
    require(record['privateInputs']=={name:manifest['files'][name]for name in p['privateInputFiles']}
        and all(record['privateInputs'][name]==dict(**want,mode=0o644)for name,want in p['privateInputFiles'].items()),
        'Original exact73 omitted private input descriptors required')
    return dict(kind='partial-finite-App5-public-product-source-validation',publicFiles=449,
        publicInputBytes=sum(row['bytes']for row in source.values()),constructionValidated=False,
        actualNormalConstructionValidated=False,referencePreferredSourceEstablished=False,
        pendingConstructionGates=list(PENDING),wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def validate_public_construction(root,*,external_inputs=None,verification_root=None,**context):
    """Never replace missing private bytes or normal proof with descriptors.

    Full archived source/view and Mono import decoding are intentionally not
    implemented by this finite input-role leaf. Even correct acquired inputs
    cannot yield construction/admission success until those gates are reviewed.
    """
    validate_public_source(root)
    require(type(external_inputs)is dict and set(external_inputs)=={'referenceZip','comparisonPackage','compilerArchives'},
        'Full construction requires actual reacquired reference/comparison inputs and all3 compiler originals')
    for key in('referenceZip','comparisonPackage'):
        require(isinstance(external_inputs[key],(str,Path)),'Actual external input path required; descriptors alone are insufficient')
        N.ordinary(external_inputs[key],file=True)
    archives=external_inputs['compilerArchives']
    require(type(archives)is dict and set(archives)=={'legacy5','runtime','vstest'},'All3 distinct original compiler archive roles required')
    for path in archives.values():
        require(isinstance(path,(str,Path)),'Actual compiler original file path required')
        N.ordinary(path,file=True)
    strong,worker=N.original_validators();p=worker.policy()
    worker.validate_reference_zip(external_inputs['referenceZip'],p)
    worker.reference_support(external_inputs['referenceZip'],p)
    require(N.fingerprint(external_inputs['comparisonPackage'])==p['originalPackage']['officialPackage'],
        'Actual exact original comparison input required for full construction')
    require(False,'Full construction pending: original Mono import decoder, real normal archive-backed full522/3compiler/65Csc/process proof and actual SDK consumer validation')
