"""Pure archived-normal field fixtures; no actual App/SDK/source positive."""
import copy
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_archive_normal as M


def fixture():
    identity=dict(sdkVersion='5.0.214',architecture='aarch64',targetRid='linux-musl-arm64',
        runId='fixture123',runAttempt='1',buildId='fixture.123',projectCommit='a'*40)
    paths=dict(workspace='/original/work',delivery='/original/delivery',project='/original/project',
        attempt='/original/work/private/appinsights',source='/original/work/work/appinsights',
        bootstrap='/original/work/inputs/bootstrap5',inspector='/original/work/inputs/bootstrap6',
        diagnostics='/original/delivery/reports/diagnostics/container-0007')
    context=dict(identity,kind='fixture-fields-only',paths=paths,recordIdentity=copy.deepcopy(identity),prepareIdentity=copy.deepcopy(identity))
    command=M.P.DOCKER_ENGINE+['run','--volume',paths['diagnostics']+':/diag','fixture-image','fixture-worker']
    pin=M.A.fingerprint(b'tiny original field fixture; no actual execution evidence')
    desc=lambda name:dict(path=paths['attempt']+'/'+name,**pin)
    files={'fixture.txt':dict(mode=0o644,**pin)}
    invocation=dict(kind=context['kind'],context=copy.deepcopy(context),command=command,inputManifest=desc('input-manifest.json'),inputFiles=files,automaticRetry=False)
    result=dict(command=command,exitCode=0,seconds=1.0,log=desc('normal-container.log'),inputFilesAfter=copy.deepcopy(files))
    stage=dict(stage=M.N.STAGE,status='passed',commands=[command],result=desc('normal-container-result.json'),automaticRetry=False)
    stages=dict(prepare=dict(stage='prepare',status='passed',commands=[]),build=dict(stage='build',status='passed',commands=[command]))
    bound=dict(context=context,record=copy.deepcopy(identity),prepare=copy.deepcopy(identity),stages=stages)
    return bound,command,invocation,result,stage


class OriginalFieldPredicates(unittest.TestCase):
    def test_pure_fields_preserve_original_posix_paths_and_json(self):
        bound,command,invocation,result,stage=fixture()
        before=json.dumps([bound,invocation,result,stage],sort_keys=True)
        self.assertEqual(M.bound_fields(bound),bound['record'])
        observed=M.normal_record_fields(bound['context'],command,invocation,result,stage)
        self.assertEqual(observed['originalLog']['path'],'/original/work/private/appinsights/normal-container.log')
        self.assertEqual(json.dumps([bound,invocation,result,stage],sort_keys=True),before)

    def test_source_attempt_or_cpu_identity_cannot_hide_behind_same_commit(self):
        for key,value in(('runAttempt','2'),('runId','different'),('architecture','x64'),('targetRid','linux-musl-x64')):
            bound,*_=fixture();bound['prepare'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'identity differs'):
                M.bound_fields(bound)

    def test_aliased_logical_host_roots_and_wrong_private_attempt_reject(self):
        for value in('/original/work//private/appinsights','/original/work/../work/private/appinsights',
                '/original/delivery/reports/build/appinsights','relative/path'):
            bound,*_=fixture();bound['context']['paths']['attempt']=value
            with self.subTest(value=value),self.assertRaises(ValueError):M.logical_paths(bound['context'])

    def test_overlapping_original_project_or_delivery_rejects(self):
        for field,value in(('project','/original/work/project'),('delivery','/original/work')):
            bound,*_=fixture();bound['context']['paths'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'Distinct original'):
                M.logical_paths(bound['context'])

    def test_result_duration_schema_and_terminal_failure_cannot_relabel_normal(self):
        for field,value in(('exitCode',1),('exitCode',False),('seconds',float('nan')),('seconds',float('inf')),('seconds',-1)):
            bound,command,invocation,result,stage=fixture();result[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                M.normal_record_fields(bound['context'],command,invocation,result,stage)
        bound,command,invocation,result,stage=fixture();result['savedNormalSuccess']=True
        with self.assertRaises(ValueError):M.normal_record_fields(bound['context'],command,invocation,result,stage)

    def test_descriptor_logical_alias_cannot_be_rewritten_to_verification_path(self):
        bound,command,invocation,result,stage=fixture()
        for path in('/verification/private/normal-container.log','normal-container.log','/original/work/private/appinsights/./normal-container.log'):
            changed=copy.deepcopy(result);changed['log']['path']=path
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'unchanged original'):
                M.normal_record_fields(bound['context'],command,invocation,changed,stage)

    def test_changed_complete_command_or_retry_and_second_substage_reject(self):
        for change in('command','retry','stage'):
            bound,command,invocation,result,stage=fixture()
            if change=='command':result['command']=command+['unobserved-override']
            elif change=='retry':invocation['automaticRetry']=True
            else:stage['commands']=[command,command]
            with self.subTest(change=change),self.assertRaises(ValueError):
                M.normal_record_fields(bound['context'],command,invocation,result,stage)

    def test_changed_before_after_inventory_or_input_mode_reject(self):
        for change in('after','mode','alias'):
            bound,command,invocation,result,stage=fixture()
            if change=='after':result['inputFilesAfter']={}
            elif change=='mode':
                invocation['inputFiles']['fixture.txt']['mode']=0o4755
                result['inputFilesAfter']=copy.deepcopy(invocation['inputFiles'])
            else:
                row=invocation['inputFiles'].pop('fixture.txt');invocation['inputFiles']['../fixture.txt']=row
                result['inputFilesAfter']=copy.deepcopy(invocation['inputFiles'])
            with self.subTest(change=change),self.assertRaises(ValueError):
                M.normal_record_fields(bound['context'],command,invocation,result,stage)

    def test_actual_parent_build_must_contain_original_app_once(self):
        for count in(0,2):
            bound,command,*_=fixture();bound['stages']['build']['commands']=[command]*count
            with self.subTest(count=count),self.assertRaisesRegex(ValueError,'exactly once'):
                M.parent_record_fields(bound,copy.deepcopy(bound['prepare']),copy.deepcopy(bound['stages']),command)

    def test_saved_parent_objects_do_not_replace_authenticated_retained_records(self):
        bound,command,*_=fixture();actual=copy.deepcopy(bound['stages']);actual['build']['status']='failed'
        with self.assertRaisesRegex(ValueError,'authenticated archived'):
            M.parent_record_fields(bound,bound['prepare'],actual,command)

    def test_all_parent_diagnostics_use_original_root_and_bounded_report_roles(self):
        bound,command,*_=fixture();stages=copy.deepcopy(bound['stages'])
        other=command.copy();other[other.index('--volume')+1]='/original/delivery/reports/diagnostics/container-0011:/diag'
        stages['test']=dict(commands=[other])
        plan=M.diagnostic_plan('/original/delivery',stages)
        self.assertEqual(len(plan),8)
        self.assertEqual(plan['/original/delivery/reports/diagnostics/container-0011/apparmor-current.txt'],4096)
        self.assertEqual(plan['/original/delivery/reports/prepare/container-engine-info.json'],4*1024**2)

    def test_foreign_or_aliased_parent_diagnostic_root_rejects_before_reads(self):
        for path in('/different/reports/diagnostics/container-0007','/original/delivery/reports/diagnostics//container-0007',
                '/original/delivery/reports/diagnostics/../diagnostics/container-0007'):
            bound,command,*_=fixture();command=command.copy();command[command.index('--volume')+1]=path+':/diag'
            with self.subTest(path=path),self.assertRaises(ValueError):
                M.diagnostic_plan('/original/delivery',{'build':{'commands':[command]}})

    def test_full_entry_platform_guard_is_explicit(self):
        with mock.patch.object(M.os,'name','nt'),self.assertRaisesRegex(ValueError,'requires POSIX'):
            M.require_posix()

    def test_saved_dictionary_or_duck_type_cannot_supply_verified_core_capability(self):
        from types import SimpleNamespace
        for value in({},SimpleNamespace(frozen=True,verified=True,source=None)):
            with self.subTest(value=type(value).__name__),mock.patch.object(M,'require_posix'),self.assertRaisesRegex(ValueError,'exact verified source session'):
                M.validate_archived_normal_boundary(value,{},value)

    def test_saved_supplier_dictionary_never_enters_consumer_predicates(self):
        with mock.patch.object(M,'require_posix'),self.assertRaisesRegex(ValueError,'actual completed|Actual completed'):
            M.validate_archived_sdk_consumption({'source':{'verified':True}},sdk_proof_descriptor={},tooling_descriptor={},capture_source_root='saved')

    def test_capture_descriptors_must_bind_actual_original_sdk_and_both_replays(self):
        proof=dict(sdkArchive={'path':'actual-sdk.tar.gz'},componentCompilerProofs={'sdk':{'path':'actual-sdk-proof.json'}})
        compiler=dict(proof={'replays':[{'name':'sdk'},{'name':'redist'}]});toolset={'path':'actual-toolset.zip'}
        index=dict(existingFinalArchive=copy.deepcopy(proof['sdkArchive']),existingToolset=copy.deepcopy(toolset),
            originalCompilerProof=copy.deepcopy(proof['componentCompilerProofs']['sdk']),originalConsumerReplays=copy.deepcopy(compiler['proof']['replays']),
            actualNormalConsumption={'savedNormalSuccess':True})
        self.assertTrue(M.capture_link_fields(index,proof,compiler,toolset))
        for key in('existingFinalArchive','existingToolset','originalCompilerProof','originalConsumerReplays'):
            changed=copy.deepcopy(index);changed[key]={}
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'same original'):
                M.capture_link_fields(changed,proof,compiler,toolset)

    def test_final_sdk_descriptor_matches_without_changing_authenticated_parent(self):
        sdk=dict(name='actual-sdk.tar.gz',**M.A.fingerprint(b'tiny descriptor fixture only'))
        record=dict(sdk=copy.deepcopy(sdk),files=[]);producer=dict(sdk=copy.deepcopy(sdk))
        before=copy.deepcopy(record)
        self.assertIsNone(M.final_sdk_record_fields(record,producer))
        self.assertEqual(record,before)
        self.assertIsNot(record['sdk'],producer['sdk'])

    def test_final_sdk_descriptor_missing_or_mismatched_rejects_without_enrichment(self):
        sdk=dict(name='actual-sdk.tar.gz',**M.A.fingerprint(b'tiny descriptor fixture only'))
        for field,value in(('name','different-sdk.tar.gz'),('bytes',sdk['bytes']+1),
                ('sha256','a'*64),('sha512','b'*128),('extra','unreviewed')):
            record=dict(sdk=copy.deepcopy(sdk));record['sdk'][field]=value
            before=copy.deepcopy(record)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'descriptor differs'):
                M.final_sdk_record_fields(record,dict(sdk=copy.deepcopy(sdk)))
            self.assertEqual(record,before)
        for record,producer in(({},dict(sdk=sdk)),(dict(sdk=sdk),{}),
                ({},{}),(dict(sdk=None),dict(sdk=None))):
            before=copy.deepcopy(record)
            with self.subTest(record=record,producer=producer),self.assertRaisesRegex(ValueError,'descriptor differs'):
                M.final_sdk_record_fields(record,producer)
            self.assertEqual(record,before)


@unittest.skipUnless(os.name=='posix','Concrete frozen physical views require POSIX modes/witnesses')
class ArchivedNormalOrigins(unittest.TestCase):
    """Tiny actual sessions with a mocked one-public-input policy, never full522."""
    def validate_boundary(self,view,bound,source):
        # Isolate normal-envelope origin/field correctness. Production always
        # uses real R.policy449+73; no external success/App capability is faked.
        with mock.patch.object(M,'_typed_policy',return_value=dict(publicInputNames=['fixture.txt'],privateInputFiles={})):
            return M.validate_archived_normal_boundary(view,bound,source)

    def snapshot(self,raw,budget):
        value=M.A.Snapshot.from_bytes(raw,M.A.fingerprint(raw),budget=budget,category='source')
        self.addCleanup(value.close);return value

    def fixture(self,mutate=None):
        temporary=tempfile.TemporaryDirectory(prefix='sdk5-archive-normal-unit-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);A=M.A
        budget=A.Budget(private_bytes=64*1024**2,source_bytes=64*1024**2,public_bytes=64*1024**2,files=4096)
        sources=M.N.execution_sources(__import__('musl_legacy5_appinsights_reference_bootstrap').role_record())
        files={};modes={};baseline={}
        for name in sources:
            path=ROOT/'scripts'/name;member='orchestration/scripts/'+name;raw=path.read_bytes()
            mode='100755'if path.stat().st_mode&0o111 else'100644'
            files[member]=raw;modes[member]=mode
            baseline['scripts/'+name]=dict(mode=mode,blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
        tree=A.packer().baseline_tree(baseline)
        commit_body=('tree '+tree+'\nauthor Unit <unit@invalid> 0 +0000\ncommitter Unit <unit@invalid> 0 +0000\n\nPure archived boundary fixture\n').encode()
        commit=hashlib.sha1(b'commit '+str(len(commit_body)).encode()+b'\0'+commit_body).hexdigest()
        identity=dict(sdkVersion='5.0.214',architecture='aarch64',targetRid='linux-musl-arm64',runId='fixture',runAttempt='1',buildId='fixture.1',projectCommit=commit)
        version=dict(Client=dict(Version='unit-fixture'),Server=dict(Version='unit-fixture'))
        info=dict(ServerVersion='unit-fixture',Architecture='aarch64',KernelVersion='unit-kernel',Driver='overlay2',CgroupDriver='systemd',
            OSType='linux',DockerRootDir='/var/lib/docker',SecurityOptions=['name=apparmor','name=seccomp,profile=builtin'])
        encode=lambda value:(json.dumps(value,sort_keys=True)+'\n').encode()
        delivery_files={}
        engine={}
        for field,value in(('version',version),('info',info)):
            relative='reports/prepare/container-engine-'+field+'.json';raw=encode(value)
            delivery_files[relative]=raw;engine[field+'Report']=dict(path=relative,**A.fingerprint(raw))
        prepare=dict(identity,imageId='sha256:'+'a'*64,emulation=False,diagnosticPodman=False,diagnosticPtrace=False,previousPrivateSdkArchiveUsed=False,
            nativeKernelVersion='unit-kernel',sourceAppArmorPolicy='engine-default',consumerAppArmorPolicy='engine-default',
            sourceSeccompPolicy='engine-default',consumerSeccompPolicy='engine-default',
            containerEngine=dict(M.P.engine_identity('docker',version,info,M.P.identity('aarch64')),commandPrefix=M.P.DOCKER_ENGINE,**engine))
        reference=__import__('musl_legacy5_appinsights_reference_bootstrap')
        context=reference.normal_context(identity,prepare,workspace='/original/work',delivery='/original/delivery',project='/original/project',
            diagnostics='/original/delivery/reports/diagnostics/container-0007',uid=1000,gid=1000)
        command=M.N.normal_container_command(context);attempt=context['paths']['attempt'];D=context['paths']['delivery']
        input_body=b'One tiny indexed input; not real App/full522 evidence.\n'
        manifest={'files':{'fixture.txt':dict(mode=0o644,**A.fingerprint(input_body))}}
        app_bodies={'normal-context.json':encode(context),'input-manifest.json':encode(manifest),'normal-container.log':b'Tiny recorded unit invocation, no actual Docker execution.\n'}
        descriptor=lambda name:dict(path=attempt+'/'+name,**A.fingerprint(app_bodies[name]))
        invocation=dict(kind=context['kind'],context=context,command=command,inputManifest=descriptor('input-manifest.json'),inputFiles=manifest['files'],automaticRetry=False)
        result=dict(command=command,exitCode=0,seconds=1.0,log=descriptor('normal-container.log'),inputFilesAfter=copy.deepcopy(manifest['files']))
        app_bodies['normal-container-invocation.json']=encode(invocation);app_bodies['normal-container-result.json']=encode(result)
        stage=dict(stage=M.N.STAGE,status='passed',commands=[command],result=descriptor('normal-container-result.json'),automaticRetry=False)
        app_bodies['normal-app-stage.json']=encode(stage)
        stages=dict(prepare=dict(stage='prepare',status='passed',commands=[M.P.DOCKER_ENGINE+['version','--format',M.P.ENGINE_JSON_FORMAT],
            M.P.DOCKER_ENGINE+['info','--format',M.P.DOCKER_INFO_FORMAT]]),build=dict(stage='build',status='passed',commands=[command]))
        status='Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
        status+=''.join(name+':\t0000000000000000\n'for name in('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        for name,raw in(('process-status.txt',status.encode()),('apparmor-current.txt',b'docker-default (enforce)\n'),('exit-code.txt',b'0\n')):
            delivery_files['reports/diagnostics/container-0007/'+name]=raw
        state=dict(identity=identity,prepare=prepare,context=context,command=command,stages=stages,app=app_bodies,delivery=delivery_files,
            extra_public={},input_body=input_body)
        if mutate:mutate(state)
        delivery_files['reports/prepare/identity.json']=encode(prepare)
        for name,value in stages.items():delivery_files['reports/stages/'+name+'.json']=encode(value)
        public='app-public'
        for name,raw in app_bodies.items():
            member=public+('/original-private-input-manifest.json'if name=='input-manifest.json'else'/evidence/'+name)
            files[member]=raw;modes[member]='100644'
        input_member=public+'/product-source/fixture.txt';files[input_member]=input_body;modes[input_member]='100644'
        for name,raw in state['extra_public'].items():files[public+'/'+name]=raw;modes[public+'/'+name]='100644'
        rows=[]
        for name,raw in sorted(files.items()):
            row=dict(path=name,mode=modes[name],**A.fingerprint(raw))
            if name.startswith('orchestration/'):row['baseline']=baseline[name[len('orchestration/'):]]
            rows.append(row)
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz',format=tarfile.PAX_FORMAT)as archive:
            for row in rows:
                raw=files[row['path']];entry=tarfile.TarInfo(row['path']);entry.size=len(raw);entry.mode=0o755 if row['mode']=='100755'else 0o644
                entry.uid=entry.gid=entry.mtime=0;archive.addfile(entry,io.BytesIO(raw))
        archive_raw=output.getvalue();index_raw=b''.join(encode(row)for row in rows)
        roots=[dict(name='orchestration',kind='git',role='orchestration',originalPath='/original/project',files=len(baseline),deleted=[],
            commit=commit,tree=tree,commitObjectBase64=base64.b64encode(commit_body).decode(),submodules=[]),
            dict(name=public,kind='tree',role=A.APP_PUBLIC_ROLE,originalPath=D+'/reports/build/appinsights',
                files=len(rows)-len(baseline),deleted=[])]
        expected={key:identity[key]for key in('sdkVersion','projectCommit','runId','runAttempt','targetRid')}
        source_manifest=dict(schemaVersion=1,status='captured-used-source',**expected,roots=roots,files=len(rows),
            archive=dict(path='source.tar.gz',**A.fingerprint(archive_raw)),index=dict(path='source-index.jsonl',**A.fingerprint(index_raw)))
        manifest_raw=encode(source_manifest)
        source=A.SourceSession(self.snapshot(archive_raw,budget),self.snapshot(index_raw,budget),manifest_raw,expected,
            manifest_identity=A.fingerprint(manifest_raw),budget=budget,private_root=root)
        self.addCleanup(source.close);source.verify()
        delivery_files.update({'sources/source.tar.gz':archive_raw,'sources/source-index.jsonl':index_raw,
            'sources/source-manifest.json':manifest_raw,'reports/ci/used-source.json':manifest_raw})
        actual=root/'incoming-delivery';actual.mkdir();private=root/'snapshots';private.mkdir()
        for name,raw in delivery_files.items():
            path=actual/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
        record=dict(identity,files=[dict(path=name,**A.fingerprint(raw))for name,raw in sorted(delivery_files.items())])
        delivery=A.DeliverySession.capture(actual,record,source,D,budget=budget,private_root=private);self.addCleanup(delivery.close)
        view=A.FrozenView(root/'view',budget=budget,forbidden_roots=(actual,));self.addCleanup(view.close)
        view.declare_root(D,'delivery',role='delivery')
        origins=source.mint_members({public+('/original-private-input-manifest.json'if name=='input-manifest.json'else'/evidence/'+name)for name in app_bodies}|{input_member},budget=budget)
        for origin in origins.values():self.addCleanup(origin.snapshot.close)
        for name in app_bodies:
            member=public+('/original-private-input-manifest.json'if name=='input-manifest.json'else'/evidence/'+name)
            view.bind_origin(attempt+'/'+name,'app/'+name,origins[member])
        view.bind_origin(attempt+'/inputs/fixture.txt','app/inputs/fixture.txt',origins[input_member])
        for name in delivery_files:view.bind_origin(D+'/'+name,'delivery/'+name,delivery.mint(name),category='public')
        view.freeze();bound=dict(context=context,record=record,prepare=prepare,stages=stages)
        return view,bound,source

    def test_actual_indexed_frozen_views_validate_scoped_normal_envelope(self):
        view,bound,source=self.fixture();result=self.validate_boundary(view,bound,source)
        self.assertTrue(result['archivedNormalEnvelopeValidated']);self.assertTrue(result['parentSdkBuildValidated'])
        self.assertFalse(result['archivedConstructionValidated']);self.assertFalse(result['qualificationAllowed'])
        self.assertFalse(result['sourceAdmissionAllowed']);self.assertFalse(result['originalLogicalPathsRewritten'])

    def test_original_private_record_in_index_rejects_even_when_unmapped(self):
        def change(state):state['extra_public']['evidence/container-result.json']=b'{}\n'
        view,bound,source=self.fixture(change)
        self.assertFalse(view.contains(bound['context']['paths']['attempt']+'/container-result.json'))
        with self.assertRaisesRegex(ValueError,'Forbidden original member'):
            self.validate_boundary(view,bound,source)

    def test_original_parent_duplicate_app_command_rejects_with_real_origins(self):
        def change(state):state['stages']['build']['commands'].append(state['command'])
        view,bound,source=self.fixture(change)
        with self.assertRaisesRegex(ValueError,'exactly once'):self.validate_boundary(view,bound,source)

    def test_foreign_parent_diag_rejects_before_shared_engine_reads(self):
        def change(state):
            state['stages']['build']['commands'].append(M.P.DOCKER_ENGINE+['run','--volume','/foreign/reports/diagnostics/container-0033:/diag','image','worker'])
        view,bound,source=self.fixture(change)
        with (mock.patch.object(M.P,'validate_container_engine',side_effect=AssertionError('must reject before delegate')),
                self.assertRaisesRegex(ValueError,'original delivery')):
            self.validate_boundary(view,bound,source)

    def test_observed_default_security_cannot_be_replaced_with_command_intent(self):
        def change(state):
            key='reports/diagnostics/container-0007/apparmor-current.txt';state['delivery'][key]=b'unconfined\n'
        view,bound,source=self.fixture(change)
        with self.assertRaisesRegex(ValueError,'default enforced AppArmor'):
            self.validate_boundary(view,bound,source)

    def test_frozen_engine_report_mutation_and_restore_is_terminal(self):
        view,bound,source=self.fixture();original=M.P.validate_container_engine
        path=view.release_root/'reports/diagnostics/container-0007/process-status.txt'
        def changed(*args):
            result=original(*args);raw=path.read_bytes();path.write_bytes(b'changed');path.write_bytes(raw);return result
        with mock.patch.object(M.P,'validate_container_engine',side_effect=changed),self.assertRaisesRegex(ValueError,'changed during delegated'):
            self.validate_boundary(view,bound,source)

    def test_actual_source_session_attempt_is_checked_beyond_project_commit(self):
        view,bound,source=self.fixture();source.expected['runAttempt']='2'
        with self.assertRaisesRegex(ValueError,'source session.*run/attempt'):
            self.validate_boundary(view,bound,source)

    def test_production_policy_does_not_accept_tiny_unit_namespace_as_full522(self):
        view,bound,source=self.fixture()
        with self.assertRaisesRegex(ValueError,'public449/private73'):
            M.validate_archived_normal_boundary(view,bound,source)

    def test_indexed_public_file_cannot_be_relabelled_as_finite_external_reference(self):
        view,bound,source=self.fixture();attempt=bound['context']['paths']['attempt']
        inputs=M.N.tree_files(view.path(attempt+'/input-manifest.json').parent/'inputs')
        private={'fixture.txt':{key:inputs['fixture.txt'][key]for key in M.FP}}
        public_root=source.root_for(bound['context']['paths']['delivery']+'/reports/build/appinsights',kind='tree',role=M.A.APP_PUBLIC_ROLE)
        with (mock.patch.object(M,'_typed_policy',return_value=dict(publicInputNames=[],privateInputFiles=private)),
                self.assertRaisesRegex(ValueError,'private73 external')):
            M._typed_origins(view,source,public_root,view.path(attempt+'/input-manifest.json').parent,attempt,inputs)


if __name__=='__main__':unittest.main()
