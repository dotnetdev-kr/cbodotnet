"""Pure normal-envelope/process fixtures; never execute App, Reader or Docker."""
import copy
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_normal as M


def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


class NormalAppEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_temp=tempfile.TemporaryDirectory(prefix='sdk5-normal-app-project-')
        cls.project=Path(cls.project_temp.name)/'project';cls.project.mkdir()
        # This is independent temporary Git metadata, never the shared index.
        (cls.project/'.gitattributes').write_text('* -text\n',encoding='utf-8')
        for name in M.execution_sources():
            path=cls.project/'scripts'/name;path.parent.mkdir(exist_ok=True);shutil.copyfile(ROOT/'scripts'/name,path);path.chmod(0o644)
        def git(*args):
            return subprocess.check_output(['git','-c','core.autocrlf=false','-c','user.name=SDK5 normal fixture',
                '-c','user.email=sdk5-fixture@invalid','-C',str(cls.project),*args],stderr=subprocess.PIPE,text=True).strip()
        git('init');git('add','--','.gitattributes','scripts');git('commit','-m','Isolated normal App envelope fixture')
        cls.commit=git('rev-parse','HEAD')

    @classmethod
    def tearDownClass(cls):cls.project_temp.cleanup()

    def fixture(self):
        temp=tempfile.TemporaryDirectory(prefix='sdk5-normal-app-boundary-');self.addCleanup(temp.cleanup)
        root=Path(temp.name);W=root/'work';D=root/'delivery';W.mkdir();D.mkdir()
        diag=D/'reports/diagnostics/container-0007';diag.mkdir(parents=True)
        identity=dict(sdkVersion=M.SDK,architecture='aarch64',targetRid='linux-musl-arm64',runId='fixture970',runAttempt='1',buildId='fixture.970',projectCommit=self.commit)
        version=dict(Client=dict(Version='1.0-fixture'),Server=dict(Version='1.0-fixture'))
        info=dict(ServerVersion='1.0-fixture',Architecture='aarch64',KernelVersion='fixture-kernel',Driver='overlay2',CgroupDriver='systemd',
            OSType='linux',DockerRootDir='/var/lib/docker',SecurityOptions=['name=apparmor','name=seccomp,profile=builtin'])
        reports={}
        for field,value in [('version',version),('info',info)]:
            relative='reports/prepare/container-engine-'+field+'.json';put(D/relative,value)
            reports[field+'Report']=dict(path=relative,**M.fingerprint(D/relative))
        prepare=dict(identity,imageId='sha256:'+'a'*64,emulation=False,diagnosticPodman=False,diagnosticPtrace=False,previousPrivateSdkArchiveUsed=False,
            nativeKernelVersion='fixture-kernel',sourceAppArmorPolicy='engine-default',consumerAppArmorPolicy='engine-default',
            sourceSeccompPolicy='engine-default',consumerSeccompPolicy='engine-default',
            containerEngine=dict(M.P.engine_identity('docker',version,info,M.P.identity('aarch64')),commandPrefix=M.P.DOCKER_ENGINE,**reports))
        context=M.normal_context(identity,prepare,workspace=W,delivery=D,project=self.project,diagnostics=diag,uid=1000,gid=1000)
        paths=context['paths'];attempt=Path(paths['attempt'])
        for path in[attempt/'inputs',attempt/'output',attempt/'home',Path(paths['bootstrap']),Path(paths['inspector']),Path(paths['source'])]:path.mkdir(parents=True)
        (attempt/'inputs/synthetic-boundary-only.txt').write_bytes(b'Not a typed App source/compiler positive.\n')
        manifest=dict(files=M.tree_files(attempt/'inputs'));put(attempt/'input-manifest.json',manifest)
        put(attempt/'normal-context.json',context);command=M.normal_container_command(context)
        invocation=dict(kind=M.KIND,context=context,command=command,inputManifest=M.descriptor(attempt/'input-manifest.json'),
            inputFiles=manifest['files'],automaticRetry=False)
        put(attempt/'normal-container-invocation.json',invocation);(attempt/'normal-container.log').write_bytes(b'synthetic normal-envelope fixture\n')
        result=dict(command=command,exitCode=0,seconds=1.0,log=M.descriptor(attempt/'normal-container.log'),inputFilesAfter=manifest['files'])
        put(attempt/'normal-container-result.json',result)
        stage=dict(stage=M.STAGE,status='passed',commands=[command],result=M.descriptor(attempt/'normal-container-result.json'),automaticRetry=False)
        put(attempt/'normal-app-stage.json',stage)
        prepare_stage=dict(stage='prepare',status='passed',commands=[M.P.DOCKER_ENGINE+['version','--format',M.P.ENGINE_JSON_FORMAT],
            M.P.DOCKER_ENGINE+['info','--format',M.P.DOCKER_INFO_FORMAT]])
        stages=dict(prepare=prepare_stage,build=dict(stage='build',status='passed',commands=[command]))
        put(D/'reports/prepare/identity.json',prepare);put(D/'reports/stages/prepare.json',prepare_stage);put(D/'reports/stages/build.json',stages['build'])
        status='Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
        status+=''.join(key+':\t0000000000000000\n'for key in('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        (diag/'process-status.txt').write_text(status,encoding='utf-8');(diag/'apparmor-current.txt').write_text('docker-default (enforce)\n',encoding='utf-8');(diag/'exit-code.txt').write_text('0\n',encoding='utf-8')
        bound=dict(context=context,record=identity,prepare=prepare,stages=stages)
        hosts={'/inputs':attempt/'inputs','/output':attempt/'output','/bootstrap':Path(paths['bootstrap']),'/inspector':Path(paths['inspector'])}
        state=dict(context=context,bound=bound,attempt=attempt,hosts=hosts,diag=diag,command=command,D=D)
        self.assertTrue(M.validate_normal_boundary(attempt,hosts,normal_context=bound,require_parent_build=True)['normalAppWorkerBoundaryValidated'])
        return state

    def reject(self,state,regex=None):
        error=self.assertRaisesRegex(ValueError,regex)if regex else self.assertRaises(ValueError)
        with error:M.validate_normal_boundary(state['attempt'],state['hosts'],normal_context=state['bound'],require_parent_build=True)

    def reseal_command(self,state,command):
        attempt=state['attempt'];invocation=M.read(attempt/'normal-container-invocation.json');invocation['command']=command;put(attempt/'normal-container-invocation.json',invocation)
        result=M.read(attempt/'normal-container-result.json');result['command']=command;put(attempt/'normal-container-result.json',result)
        stage=M.read(attempt/'normal-app-stage.json');stage.update(commands=[command],result=M.descriptor(attempt/'normal-container-result.json'));put(attempt/'normal-app-stage.json',stage)
        state['bound']['stages']['build']['commands']=[command];put(state['D']/'reports/stages/build.json',state['bound']['stages']['build'])

    def test_complete_normal_envelope_fixture(self):self.fixture()

    def test_finite_reference_context_is_explicit_and_outside_all_delivery(self):
        import musl_legacy5_appinsights_reference_bootstrap as reference
        state=self.fixture();old=state['context'];paths=old['paths']
        context=reference.normal_context(old['recordIdentity'],state['bound']['prepare'],
            **{key:paths[key]for key in('workspace','delivery','project','diagnostics')},uid=old['uid'],gid=old['gid'])
        reference.finite_context(context)
        self.assertEqual(context['schemaVersion'],2)
        self.assertEqual(Path(context['paths']['attempt']),Path(paths['workspace'])/'private/appinsights')
        self.assertNotIn(Path(paths['delivery']),Path(context['paths']['attempt']).parents)
        self.assertEqual(old['schemaVersion'],1);self.assertNotIn('referenceBootstrap',old)
        command=M.normal_container_command(context)
        self.assertIn(str(Path(context['paths']['attempt'])/'inputs')+':/inputs:ro',command)

    def test_finite_reference_context_cannot_relabel_delivery_attempt(self):
        import musl_legacy5_appinsights_reference_bootstrap as reference
        state=self.fixture();old=state['context'];context=copy.deepcopy(old)
        context.update(schemaVersion=2,kind=reference.KIND,referenceBootstrap=reference.role_record())
        with self.assertRaises(ValueError):M.validate_context(context)

    def test_default_context_cannot_carry_implicit_reference_role(self):
        state=self.fixture();context=copy.deepcopy(state['context']);context['referenceBootstrap']={'role':'arbitrary-reference'}
        with self.assertRaises(ValueError):M.validate_context(context)

    def test_private_record_cannot_satisfy_normal_context(self):
        state=self.fixture();state['bound']['context']['kind']='one-authorized-offline-private-app5-compiler-attempt';self.reject(state,'Closed explicit normal')

    def test_changed_run_identity_rejected(self):
        state=self.fixture();state['bound']['record']['runId']='another-attempt';self.reject(state)

    def test_changed_bootstrap_mount_origin_rejected(self):
        state=self.fixture();state['hosts']['/bootstrap']=state['hosts']['/inspector'];self.reject(state,'mount origins')

    def test_all_extra_unsafe_or_shadow_command_options_reject(self):
        for extra in[['--network=host'],['--privileged'],['--security-opt=seccomp=unconfined'],['--user','0:0'],
                     ['--volume','/another:/bootstrap:ro'],['--env','PATH=/unbound'],['--env','DOTNET_ROOT=/another'],['--cap-add=SYS_PTRACE']]:
            with self.subTest(extra=extra):
                state=self.fixture();command=copy.deepcopy(state['command']);command[5:5]=extra;self.reseal_command(state,command);self.reject(state,'complete Docker argv')

    def test_replaced_image_backend_and_observed_wrapper_reject(self):
        for mode in('image','backend','wrapper'):
            with self.subTest(mode=mode):
                state=self.fixture();command=copy.deepcopy(state['command'])
                if mode=='image':command[command.index(state['context']['imageId'])]='sha256:'+'b'*64
                elif mode=='backend':command[3]='podman'
                else:command[command.index('sh')+2]+='; true'
                self.reseal_command(state,command);self.reject(state,'complete Docker argv')

    def test_duplicated_parent_build_process_rejected(self):
        state=self.fixture();state['bound']['stages']['build']['commands']*=2;put(state['D']/'reports/stages/build.json',state['bound']['stages']['build']);self.reject(state,'contain this App5 source process once')

    def test_failed_or_absent_parent_build_cannot_be_normal_consumer(self):
        state=self.fixture();state['bound']['stages']['build']['status']='failed';put(state['D']/'reports/stages/build.json',state['bound']['stages']['build']);self.reject(state,'successful normal SDK5 build')

    def test_process_security_and_exit_reports_are_required(self):
        for name,body in[('exit-code.txt','1\n'),('apparmor-current.txt','unconfined\n'),('process-status.txt','Uid:\t0 0 0 0\n')]:
            with self.subTest(name=name):
                state=self.fixture();(state['diag']/name).write_text(body,encoding='utf-8');self.reject(state)

    def test_missing_or_changed_actual_engine_report_rejected(self):
        state=self.fixture();path=state['D']/'reports/prepare/container-engine-info.json';info=M.read(path);info['SecurityOptions'].append('name=rootless');put(path,info)
        # Keep the raw report descriptor self-consistent; actual rootful/default
        # engine semantics still reject independently of a stale hash.
        prepare=state['bound']['prepare'];prepare['containerEngine']['infoReport']=dict(path=path.relative_to(state['D']).as_posix(),**M.fingerprint(path))
        put(state['D']/'reports/prepare/identity.json',prepare);self.reject(state,'rootful daemon')

    def test_readonly_typed_input_mutation_rejected(self):
        state=self.fixture();(state['attempt']/'inputs/synthetic-boundary-only.txt').write_bytes(b'changed');self.reject(state,'must remain unchanged')

    def test_private_invocation_files_cannot_be_fabricated_alongside_normal(self):
        state=self.fixture();put(state['attempt']/'container-invocation.json',{});self.reject(state,'Private App5 records')

    @unittest.skipIf(os.name=='nt','POSIX FIFO and fork semantics required')
    def test_fifo_evidence_rejects_before_shared_blocking_reads(self):
        for relative in('reports/prepare/container-engine-version.json','reports/prepare/container-engine-info.json',
                         'reports/diagnostics/container-0007/process-status.txt','reports/diagnostics/container-0007/apparmor-current.txt',
                         'reports/diagnostics/container-0007/exit-code.txt'):
            with self.subTest(relative=relative):
                state=self.fixture();path=state['D']/relative;path.unlink();os.mkfifo(path)
                self.prompt_rejection(state)

    def prompt_rejection(self,state):
        context=multiprocessing.get_context('fork');queue=context.Queue()
        def check():
            try:M.validate_normal_boundary(state['attempt'],state['hosts'],normal_context=state['bound'],require_parent_build=True)
            except ValueError as error:queue.put(dict(rejected=True,reason=str(error)))
            else:queue.put(dict(rejected=False))
        process=context.Process(target=check);started=time.monotonic();process.start();process.join(timeout=2)
        if process.is_alive():
            process.terminate();process.join(timeout=2);self.fail('Special evidence blocked before ordinary-file rejection')
        result=queue.get(timeout=1);self.assertEqual(result['rejected'],True);self.assertLess(time.monotonic()-started,2)
        self.assertRegex(result['reason'],'special|ordinary')

    @unittest.skipIf(os.name=='nt','POSIX FIFO and fork semantics required')
    def test_fifo_in_another_inspected_docker_stage_rejects_before_shared_read(self):
        state=self.fixture();other=state['diag'].parent/'container-0008';other.mkdir()
        before=M.validate_normal_boundary(state['attempt'],state['hosts'],normal_context=state['bound'],require_parent_build=True)
        for name in('process-status.txt','apparmor-current.txt','exit-code.txt'):shutil.copyfile(state['diag']/name,other/name)
        call=state['command'][:state['command'].index(state['context']['imageId'])+1]
        call=[str(other)+':/diag'if value==str(state['diag'])+':/diag'else value for value in call]
        call+=M.P.Producer.observed_command(['sh','-ec','true'])
        state['bound']['stages']['build']['commands'].append(call);put(state['D']/'reports/stages/build.json',state['bound']['stages']['build'])
        after=M.validate_normal_boundary(state['attempt'],state['hosts'],normal_context=state['bound'],require_parent_build=True)
        self.assertEqual(before['preflightOrdinaryEngineSecurityEvidence'],after['preflightOrdinaryEngineSecurityEvidence'])
        (other/'process-status.txt').unlink();os.mkfifo(other/'process-status.txt');self.prompt_rejection(state)

    @unittest.skipIf(os.name=='nt','POSIX executable/special-mode semantics required')
    def test_special_mode_and_fifo_are_rejected(self):
        for mode in('setuid','fifo'):
            with self.subTest(mode=mode):
                state=self.fixture();path=state['attempt']/'inputs/extra'
                if mode=='setuid':path.write_bytes(b'x');path.chmod(0o4755)
                else:os.mkfifo(path)
                self.reject(state,'special')


class NormalAppProcessRecords(unittest.TestCase):
    def fixture(self):
        temp=tempfile.TemporaryDirectory(prefix='sdk5-normal-app-process-');self.addCleanup(temp.cleanup);output=Path(temp.name)
        (output/'reader').mkdir();(output/'reader/Reader.dll').write_bytes(b'fixture Reader executable')
        done=dict(status='one-genuine-offline-app5-build-completed',appBuilds=1,readerBuiltFromFrozenSources=True,
            readerActuallyExecuted=True,network='none',publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
        put(output/'worker-completed.json',done);records=[]
        for command,name in zip(M.process_commands(),('app-build','reader-build','app-reader','reader-build-reader')):
            path=output/(name+'.log');path.write_bytes(('fixture '+name).encode())
            records.append(dict(command=command,exitCode=0,seconds=0.1,log=dict(path='/output/'+path.name,**M.fingerprint(path))))
        for record,name in zip(records[2:],('app','reader-build')):
            path=output/(name+'.binlog');path.write_bytes(('fixture binary log '+name).encode())
            record.update(readerExecutable=M.fingerprint(output/'reader/Reader.dll'),originalBinlog=M.fingerprint(path))
            for suffix in('status.json','tasks.jsonl'):
                target=output/'replay'/(name+'-'+suffix);target.parent.mkdir(exist_ok=True);target.write_bytes(('fixture '+name+'-'+suffix).encode())
        put(output/'actual-app-process.json',records[0]);put(output/'actual-reader-build-process.json',records[1]);put(output/'actual-reader-processes.json',records[2:])
        M.validate_process_records(output);return output

    def test_full_process_command_fixture(self):self.fixture()

    def test_each_extra_msb_property_response_or_compiler_process_option_rejects(self):
        for extra in('/p:DefineConstants=UNBOUND','-property:PublicRelease=False','@override.rsp','/p:UseSharedCompilation=true'):
            with self.subTest(extra=extra):
                output=self.fixture();path=output/'actual-app-process.json';record=M.read(path);record['command'].append(extra);put(path,record)
                with self.assertRaisesRegex(ValueError,'complete ordered'):M.validate_process_records(output)

    def test_missing_failed_or_swapped_reader_process_rejected(self):
        for mode in('failed','swapped','missing'):
            with self.subTest(mode=mode):
                output=self.fixture();path=output/'actual-reader-processes.json';records=M.read(path)
                if mode=='failed':records[0]['exitCode']=1
                elif mode=='swapped':records.reverse()
                else:records.pop()
                put(path,records)
                with self.assertRaises(ValueError):M.validate_process_records(output)

    def test_reused_reader_status_or_task_content_is_not_two_replays(self):
        for suffix in('status.json','tasks.jsonl'):
            with self.subTest(suffix=suffix):
                output=self.fixture();shutil.copyfile(output/'replay'/('app-'+suffix),output/'replay'/('reader-build-'+suffix))
                with self.assertRaisesRegex(ValueError,'distinct original content'):M.validate_process_records(output)

    def test_reader_executable_and_original_binlog_must_match_actual_process(self):
        for name in('reader/Reader.dll','app.binlog'):
            with self.subTest(name=name):
                output=self.fixture();(output/name).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'consumed bytes'):M.validate_process_records(output)


if __name__=='__main__':unittest.main()
