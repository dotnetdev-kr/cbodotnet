"""Tiny capacity/transport fixtures and fake children, never native qualification."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_release as R
import musl_source_archive as SA

def fp(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())

def source_fixture(root, arch='x64', version='6.0.136'):
    tree = root / arch; (tree / 'sources').mkdir(parents=True)
    expected = dict(projectCommit='a'*40, runId=123, runAttempt=2)
    identity = dict(sdkVersion=version, architecture=arch, targetRid=R.ARCHITECTURES[arch]['rid'],
                    libc='musl', projectCommit=expected['projectCommit'], runId='123', runAttempt='2')
    (tree/'producer-validation.json').write_bytes(R.encoded(identity))
    rows = [dict(path='orchestration/a.cs', mode='100644', bytes=4),
            dict(path='source/'+('b'*200), mode='120000', bytes=7),
            dict(path='source/executable', mode='100755', bytes=0)]
    index = b''.join(R.encoded(row).replace(b'\n', b'') + b'\n' for row in rows)
    (tree/'sources/source-index.jsonl').write_bytes(index)
    raw = b'ordinary capacity bytes, not an SDK source gzip'
    (tree/'sources/used.tar.gz').write_bytes(raw)
    manifest = dict(sdkVersion=version, projectCommit=expected['projectCommit'], runId='123', runAttempt='2',
                    targetRid=identity['targetRid'], files=len(rows),
                    archive=dict(path='used.tar.gz', **fp(raw)), index=dict(path='source-index.jsonl', **fp(index)))
    (tree/'sources/source-manifest.json').write_bytes(R.encoded(manifest))
    return tree, expected, manifest, rows

class Capacity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.tree,self.expected,self.manifest,self.rows=source_fixture(self.root)
    def write_manifest(self, value):
        (self.tree/'sources/source-manifest.json').write_bytes(R.encoded(value))
    def test_exact_bound_matches_original_source_arithmetic(self):
        expected=SA.expansion_bound(self.tree,self.manifest)+self.manifest['archive']['bytes']+SA.RESERVE_BYTES
        self.assertEqual(R._sdk6_source_requirement(self.tree,'x64',self.expected),expected)
    def test_index_hash_count_and_identity_changes_are_terminal(self):
        for field,value in [('sha256','b'*64),('sha512','b'*128)]:
            bad=copy.deepcopy(self.manifest);bad['index'][field]=value
            self.write_manifest(bad)
            with self.subTest(field=field),self.assertRaises(ValueError):R._sdk6_source_requirement(self.tree,'x64',self.expected)
        bad=copy.deepcopy(self.manifest);bad['files']+=1;self.write_manifest(bad)
        with self.assertRaises(ValueError):R._sdk6_source_requirement(self.tree,'x64',self.expected)
        bad=copy.deepcopy(self.manifest);bad['runAttempt']='3';self.write_manifest(bad)
        with self.assertRaises(ValueError):R._sdk6_source_requirement(self.tree,'x64',self.expected)
    def test_malformed_row_is_terminal_even_with_matching_hash(self):
        for change in ({'bytes':-1},{'mode':'100600'},{'path':'../escape'}):
            rows=copy.deepcopy(self.rows);rows[0].update(change)
            raw=b''.join(json.dumps(row).encode()+b'\n'for row in rows)
            (self.tree/'sources/source-index.jsonl').write_bytes(raw)
            bad=copy.deepcopy(self.manifest);bad['index'].update(fp(raw));self.write_manifest(bad)
            with self.subTest(change=change),self.assertRaises(ValueError):R._sdk6_source_requirement(self.tree,'x64',self.expected)
    def test_metadata_size_checked_before_open_and_raw_json_is_not_normalized(self):
        path=self.root/'ordinary.json';raw=b'{ "original" : null }\n';path.write_bytes(raw)
        self.assertEqual(R._pair_source_bytes(path,128),raw)
        with mock.patch.object(Path,'open',side_effect=AssertionError('oversized body opened')):
            with self.assertRaises(ValueError):R._pair_source_bytes(path,1)
        for bad in (b'{"a":1,"a":2}',b'[]'):
            with self.assertRaises(ValueError):R._pair_json(bad)
    def test_scheduling_envelope_overflow_selects_serial_without_unbounded_read(self):
        for name,value in [('SDK6_PAIR_MANIFEST',1),('SDK6_PAIR_INDEX',1),('SDK6_PAIR_LINE',1),('SDK6_PAIR_ROWS',1)]:
            with self.subTest(name=name),mock.patch.object(R,name,value):
                self.assertIsNone(R._sdk6_source_requirement(self.tree,'x64',self.expected))
    def test_growing_overlong_index_is_terminal_before_envelope_fallback(self):
        target=self.tree/'sources/source-index.jsonl';original=Path.open;injected=False
        def opening(path,*args,**kwargs):
            nonlocal injected
            if path==target and args and args[0]=='rb' and not injected:
                injected=True
                with original(path,'ab')as stream:stream.write(b'X'*(R.SDK6_PAIR_LINE+1))
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,'open',opening):
            with self.assertRaisesRegex(ValueError,'grew while scheduling'):R._sdk6_source_requirement(self.tree,'x64',self.expected)
    def test_changed_over_envelope_index_witness_is_terminal_below_declared_total(self):
        target=self.tree/'sources/source-index.jsonl';original=Path.open
        class ChangedRead:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def fileno(self):return self.stream.fileno()
            def readline(self,maximum):
                raw=self.stream.readline(maximum)
                with original(target,'ab')as outgoing:outgoing.write(b'X')
                return raw
        def opening(path,*args,**kwargs):
            stream=original(path,*args,**kwargs)
            return ChangedRead(stream)if path==target and args and args[0]=='rb'else stream
        with mock.patch.object(R,'SDK6_PAIR_LINE',1),mock.patch.object(Path,'open',opening):
            with self.assertRaisesRegex(ValueError,'changed before scheduling fallback'):R._sdk6_source_requirement(self.tree,'x64',self.expected)
    def test_combined_capacity_must_fit_not_just_each_child(self):
        trees={arch:self.tree for arch in R.ARCHITECTURES}
        with mock.patch.object(SA,'supported',return_value=True),mock.patch.object(R,'_sdk6_host_capacity',return_value=dict(cpus=4,availableMemoryBytes=R.SDK6_PAIR_MEMORY)),mock.patch.object(R,'_sdk6_source_requirement',side_effect=[100,100]),mock.patch.object(R.shutil,'disk_usage',return_value=SimpleNamespace(free=200+1024**3-1)):
            self.assertEqual(R._sdk6_pair_capacity(trees,self.expected)['workers'],1)
        with mock.patch.object(SA,'supported',return_value=True),mock.patch.object(R,'_sdk6_host_capacity',return_value=dict(cpus=4,availableMemoryBytes=R.SDK6_PAIR_MEMORY)),mock.patch.object(R,'_sdk6_source_requirement',side_effect=[100,100]),mock.patch.object(R.shutil,'disk_usage',return_value=SimpleNamespace(free=200+1024**3)):
            self.assertEqual(R._sdk6_pair_capacity(trees,self.expected)['workers'],2)
    def test_unknown_cpu_memory_or_nonmain_thread_stays_serial(self):
        trees={arch:self.tree for arch in R.ARCHITECTURES}
        for host in (None,dict(cpus=3,availableMemoryBytes=2*R.SDK6_PAIR_MEMORY),dict(cpus=4,availableMemoryBytes=R.SDK6_PAIR_MEMORY-1)):
            with self.subTest(host=host),mock.patch.object(SA,'supported',return_value=True),mock.patch.object(R,'_sdk6_host_capacity',return_value=host),mock.patch.object(R,'_sdk6_source_requirement',side_effect=AssertionError('source planning without capacity')):
                self.assertEqual(R._sdk6_pair_capacity(trees,self.expected)['workers'],1)
        with mock.patch.object(R.threading,'current_thread',return_value=object()):
            self.assertEqual(R._sdk6_pair_capacity(trees,self.expected)['workers'],1)

class HostLimits(unittest.TestCase):
    def test_visible_ancestor_limits_clamp_affinity_memory_and_quota(self):
        with tempfile.TemporaryDirectory()as temporary:
            mount=Path(temporary)/'cgroup';current=mount/'a/b';current.mkdir(parents=True)
            (mount/'cgroup.controllers').write_text('cpu memory')
            for parent in (mount/'a',current):
                (parent/'cpu.max').write_text('max 100000')
                (parent/'memory.max').write_text('max');(parent/'memory.high').write_text('max')
                (parent/'memory.current').write_text('0')
            (mount/'a/cpu.max').write_text('200000 100000')
            (mount/'a/memory.max').write_text(str(10*1024**3));(mount/'a/memory.current').write_text(str(3*1024**3))
            original=R._pair_host_bytes
            values={'/proc/meminfo':'MemAvailable: 16777216 kB\n','/proc/self/cgroup':'0::/a/b\n',
                    '/proc/self/mountinfo':'1 0 0:1 / '+mount.as_posix()+' rw - cgroup2 cgroup rw\n'}
            def read(path,maximum):return values[str(path)] if str(path)in values else original(path,maximum)
            with mock.patch.object(R.sys,'platform','linux'),mock.patch.object(R.os,'sched_getaffinity',return_value=set(range(8)),create=True),mock.patch.object(R,'_pair_host_bytes',side_effect=read):
                host=R._sdk6_host_capacity();self.assertEqual(host['cpus'],2);self.assertEqual(host['availableMemoryBytes'],7*1024**3)
                self.assertEqual(host['hostObservation']['quotaCpus'],2);self.assertEqual(host['hostObservation']['cgroupAncestorsChecked'],3)
    def test_unaccounted_or_malformed_host_hierarchy_is_unknown(self):
        with mock.patch.object(R.sys,'platform','linux'),mock.patch.object(R.os,'sched_getaffinity',return_value=set(range(4)),create=True),mock.patch.object(R,'_pair_host_bytes',side_effect=['MemAvailable: 16777216 kB\n','1:cpu:/unaccounted\n']):
            self.assertEqual(R._sdk6_host_capacity()['hostReason'],'unaccounted-host-capacity')

    def probe(self,mount,group='/',denied=None):
        original=R._pair_host_bytes
        values={'/proc/meminfo':'MemAvailable: 16777216 kB\n','/proc/self/cgroup':'0::'+group+'\n',
                '/proc/self/mountinfo':'1 0 0:1 / '+mount.as_posix()+' rw - cgroup2 cgroup rw\n'}
        def read(path,maximum):
            if denied and Path(path)==mount/denied:raise PermissionError('ordinary inaccessible marker')
            return values[str(path)] if str(path)in values else original(path,maximum)
        with mock.patch.object(R.sys,'platform','linux'),mock.patch.object(R.os,'sched_getaffinity',return_value=set(range(4)),create=True),mock.patch.object(R,'_pair_host_bytes',side_effect=read):
            return R._sdk6_host_capacity()
    def test_real_root_accepts_documented_absence_of_nonroot_limit_interfaces(self):
        with tempfile.TemporaryDirectory()as temporary:
            mount=Path(temporary);(mount/'cgroup.controllers').write_text('cpu memory io')
            host=self.probe(mount)
            self.assertEqual(host['cpus'],4);self.assertEqual(host['hostReason'],'observed')
            self.assertEqual(host['hostObservation']['rootWitness']['missingNonrootMarkers'],['cgroup.type','cgroup.events'])
            self.assertEqual(host['hostObservation']['cgroupAncestorsChecked'],1)
    def test_hidden_root_markers_and_inaccessible_marker_never_prove_real_root(self):
        with tempfile.TemporaryDirectory()as temporary:
            mount=Path(temporary);(mount/'cgroup.controllers').write_text('cpu memory')
            for name in ('cgroup.type','cgroup.events'):
                (mount/name).write_text('ordinary nonroot marker')
                self.assertEqual(self.probe(mount)['hostReason'],'unaccounted-host-capacity')
                (mount/name).unlink()
            self.assertEqual(self.probe(mount,denied='cgroup.type')['hostReason'],'unaccounted-host-capacity')
    def test_missing_visible_nonroot_interfaces_select_unknown_capacity(self):
        with tempfile.TemporaryDirectory()as temporary:
            mount=Path(temporary);(mount/'cgroup.controllers').write_text('cpu memory');(mount/'a').mkdir()
            self.assertEqual(self.probe(mount,'/a')['hostReason'],'unaccounted-host-capacity')

class RealLinuxObservation(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Read-only real Linux host observation')
    def test_bounded_real_host_capacity_observation_without_native_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);trees={}
            for arch in R.ARCHITECTURES:
                tree,expected,_,_=source_fixture(root,arch);trees[arch]=tree
            capacity=R._sdk6_pair_capacity(trees,expected)
            self.assertIn(capacity['workers'],(1,2));self.assertIsInstance(capacity['reason'],str)
            print(json.dumps(dict(kind='sdk6-real-linux-host-capacity-observation',capacity=capacity,
                tinyIndexFixturesOnly=True,actualFullValidatorExecuted=False),sort_keys=True),file=sys.stderr,flush=True)

class FakeProcess:
    def __init__(self,pid,events,codes=(0,),timeouts=0):
        self.pid,self.events,self.codes,self.returncode,self.timeouts=pid,events,list(codes),None,timeouts
    def poll(self):
        self.events.append(('poll',self.pid))
        if self.returncode is None and self.codes:
            value=self.codes.pop(0)
            if isinstance(value,BaseException):raise value
            self.returncode=value
        return self.returncode
    def wait(self,timeout=None):
        self.events.append(('wait',self.pid,timeout))
        if self.timeouts:self.timeouts-=1;raise subprocess.TimeoutExpired('ordinary fake',timeout)
        if self.returncode is None:self.returncode=0
        return self.returncode

class Pair(unittest.TestCase):
    def setUp(self):
        self.events=[];self.children=[];self.old={R.signal.SIGTERM:object(),R.signal.SIGINT:object()};self.handlers=dict(self.old)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.trees={}
        for arch in R.ARCHITECTURES:
            tree,self.expected,_,_=source_fixture(Path(self.temp.name),arch);self.trees[arch]=tree
    def context(self,popen):
        from contextlib import ExitStack
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(R,'_sdk6_pair_capacity',return_value={'workers':2}))
        stack.enter_context(mock.patch.object(R.subprocess,'Popen',side_effect=popen))
        stack.enter_context(mock.patch.object(R.signal,'SIGKILL',9,create=True))
        stack.enter_context(mock.patch.object(R.signal,'getsignal',side_effect=lambda value:self.handlers[value]))
        stack.enter_context(mock.patch.object(R.signal,'signal',side_effect=lambda value,handler:self.handlers.__setitem__(value,handler)))
        def kill(pid,signum):
            self.events.append(('kill',pid,signum))
            child=next(child for child in self.children if child.pid==pid)
            if signum==R.signal.SIGKILL or child.timeouts==0:child.returncode=-signum
        stack.enter_context(mock.patch.object(R.os,'killpg',side_effect=kill,create=True))
        return stack
    def test_both_exact_children_start_before_poll_and_restore_handlers(self):
        def spawn(command,**kwargs):
            self.events.append(('spawn',command,kwargs));child=FakeProcess(100+len(self.children),self.events,(None,0));self.children.append(child);return child
        self.context(spawn);R._validate_sdk6_pair(self.trees,self.expected,phase='receive')
        self.assertEqual([event[0]for event in self.events[:2]],['spawn','spawn'])
        for index,arch in enumerate(R.ARCHITECTURES):
            self.assertEqual(self.events[index][1],[sys.executable,str(R.ROOT/'scripts/musl-sdk-expand.py'),'validate','--release-dir',str(self.trees[arch])])
            self.assertEqual(self.events[index][2],{'start_new_session':True})
        self.assertEqual(self.handlers,self.old);self.assertEqual(len([e for e in self.events if e[0]=='wait']),2)
    def test_nonzero_waits_for_both_before_raising(self):
        def spawn(command,**kwargs):
            child=FakeProcess(100+len(self.children),self.events,(7,)if not self.children else(None,0));self.children.append(child);return child
        self.context(spawn)
        with self.assertRaises(subprocess.CalledProcessError):R._validate_sdk6_pair(self.trees,self.expected,phase='stage')
        self.assertEqual(len([e for e in self.events if e[0]=='wait']),2);self.assertFalse(any(e[0]=='kill'for e in self.events));self.assertEqual(self.handlers,self.old)
    def test_second_launch_failure_reaps_first(self):
        def spawn(command,**kwargs):
            if self.children:raise OSError('ordinary second launch failure')
            child=FakeProcess(101,self.events,(None,));self.children.append(child);return child
        self.context(spawn)
        with self.assertRaises(OSError):R._validate_sdk6_pair(self.trees,self.expected,phase='receive')
        self.assertIn(('kill',101,R.signal.SIGTERM),self.events);self.assertEqual(self.handlers,self.old)
    def test_signal_during_launch_is_deferred_until_handle_is_owned(self):
        def spawn(command,**kwargs):
            child=FakeProcess(101,self.events,(None,));self.children.append(child)
            self.handlers[R.signal.SIGTERM](R.signal.SIGTERM,None)
            self.handlers[R.signal.SIGTERM](R.signal.SIGTERM,None)
            return child
        self.context(spawn)
        with self.assertRaises(KeyboardInterrupt):R._validate_sdk6_pair(self.trees,self.expected,phase='receive')
        self.assertEqual(len(self.children),1);self.assertIn(('kill',101,R.signal.SIGTERM),self.events);self.assertEqual(self.handlers,self.old)
    def test_interrupt_escalates_timeout_and_reaps_owned_groups(self):
        def spawn(command,**kwargs):
            child=FakeProcess(100+len(self.children),self.events,(None,),timeouts=1 if not self.children else 0);self.children.append(child);return child
        self.context(spawn)
        with mock.patch.object(R.time,'sleep',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):R._validate_sdk6_pair(self.trees,self.expected,phase='stage')
        self.assertIn(('kill',100,R.signal.SIGKILL),self.events);self.assertTrue(all(child.returncode is not None for child in self.children));self.assertEqual(self.handlers,self.old)
    def test_repeated_signal_at_cleanup_is_recorded_and_remains_terminal(self):
        def spawn(command,**kwargs):
            child=FakeProcess(100+len(self.children),self.events);self.children.append(child)
            original=child.wait
            def waiting(timeout=None):
                handler=self.handlers[R.signal.SIGTERM]
                if callable(handler):handler(R.signal.SIGTERM,None);handler(R.signal.SIGTERM,None)
                return original(timeout=timeout)
            child.wait=waiting
            return child
        self.context(spawn)
        with self.assertRaises(KeyboardInterrupt):R._validate_sdk6_pair(self.trees,self.expected,phase='stage')
        self.assertEqual(self.handlers,self.old);self.assertEqual(len([e for e in self.events if e[0]=='wait']),2)
    def test_bad_serial_pair_identity_is_rejected_before_any_child_dispatch(self):
        path=self.trees['aarch64']/'producer-validation.json';value=json.loads(path.read_bytes());value['sdkVersion']='7.0.120';path.write_bytes(R.encoded(value))
        with mock.patch.object(R,'_sdk6_pair_capacity',return_value={'workers':1})as capacity,mock.patch.object(R.subprocess,'run')as run,mock.patch.object(R.subprocess,'Popen')as popen:
            with self.assertRaises(ValueError):R._validate_sdk6_pair(self.trees,self.expected,phase='receive')
        capacity.assert_not_called();run.assert_not_called();popen.assert_not_called()
    def test_serial_fallback_runs_same_two_full_commands_without_popen(self):
        with mock.patch.object(R,'_sdk6_pair_capacity',return_value={'workers':1}),mock.patch.object(R.subprocess,'run')as run,mock.patch.object(R.subprocess,'Popen',side_effect=AssertionError('parallel process')):
            R._validate_sdk6_pair(self.trees,self.expected,phase='receive')
        self.assertEqual(run.call_count,2)
        self.assertTrue(all(call.kwargs=={'check':True}for call in run.call_args_list))

class Orchestration(unittest.TestCase):
    def test_four_full_calls_two_extra_verifies_and_closed_cpu_order(self):
        self.exercise()
    def test_non_sdk6_keeps_original_serial_calls(self):
        self.exercise('7.0.120')
    def test_receive_failure_writes_no_received_success(self):
        self.exercise(fail='receive')
    def test_stage_failure_packs_nothing(self):
        self.exercise(fail='stage')
    def exercise(self,version='6.0.136',fail=None):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);events=[];payloads={};artifacts=[]
            run=dict(id=123,run_attempt=2,path='.github/workflows/musl-sdk-expand.yml',head_sha='a'*40,head_branch='main',event='workflow_dispatch',repository={'full_name':R.REPOSITORY},head_repository={'full_name':R.REPOSITORY},status='completed',conclusion='success')
            for index,arch in enumerate(R.ARCHITECTURES):
                tree,_,manifest,_=source_fixture(root,arch,version)
                sdk=b'ordinary orchestration bytes, never a genuine SDK'
                sdkname='cbodotnet-sdk-'+version+'-linux-musl-'+arch+'-build.123.tar.gz';(tree/sdkname).write_bytes(sdk)
                record=json.loads((tree/'producer-validation.json').read_bytes());record['sdk']=dict(name=sdkname,**fp(sdk));(tree/'producer-sdk.json').write_bytes(R.encoded(record))
                tar=io.BytesIO()
                with tarfile.open(fileobj=tar,mode='w:gz')as archive:
                    for path in sorted(tree.rglob('*')):
                        if path.is_file():archive.add(path,arcname='delivery/'+path.relative_to(tree).as_posix(),recursive=False)
                bundle=tar.getvalue();transport=dict(kind='musl-sdk-producer-transport',status='passed',sdkVersion=version,workflow=run['path'],architecture=arch,projectCommit=run['head_sha'],repository=R.REPOSITORY,libc='musl',runId='123',runAttempt='2',bundle=dict(name='delivery.tar.gz',size=len(bundle),sha256=hashlib.sha256(bundle).hexdigest()))
                zipped=io.BytesIO()
                with zipfile.ZipFile(zipped,'w')as archive:
                    archive.writestr('delivery.tar.gz',bundle);archive.writestr('delivery.tar.gz.sha256',hashlib.sha256(bundle).hexdigest()+'  delivery.tar.gz\n');archive.writestr('delivery.json',R.encoded(transport))
                payloads[456+index]=zipped.getvalue();artifacts.append(dict(id=456+index,name=R.producer_artifact_name(version,arch,123,2),expired=False,size_in_bytes=len(zipped.getvalue()),digest='sha256:'+hashlib.sha256(zipped.getvalue()).hexdigest(),workflow_run=dict(id=123,head_sha=run['head_sha'],head_branch='main',repository_id=10,head_repository_id=10)))
            def api(path):return {'artifacts':artifacts}if'/artifacts?'in path else run
            def command(argv,**kwargs):
                if argv[0]=='gh':
                    identity=int(argv[-1].split('/')[-2]);kwargs['stdout'].write(payloads[identity]);events.append(('download',identity))
                else:events.append(('serial',argv))
                return SimpleNamespace(returncode=0)
            children=[]
            def spawn(argv,**kwargs):
                events.append(('full',argv));phase='receive'if len(children)<2 else'stage';child=FakeProcess(100+len(children),events,(9 if fail==phase and len(children)%2==0 else 0,));children.append(child);return child
            def verify(args):events.append(('extra-source-verify',args.expected_target_rid))
            handlers={R.signal.SIGTERM:object(),R.signal.SIGINT:object()}
            with mock.patch.object(R,'GitHubReleases',return_value=SimpleNamespace(api=api)),mock.patch.object(R.subprocess,'run',side_effect=command),mock.patch.object(R.subprocess,'Popen',side_effect=spawn),mock.patch.object(R,'_sdk6_pair_capacity',return_value={'workers':2}),mock.patch.object(R,'_source_module',return_value=SimpleNamespace(verify=verify)),mock.patch.object(R.signal,'getsignal',side_effect=lambda value:handlers[value]),mock.patch.object(R.signal,'signal',side_effect=lambda value,handler:handlers.__setitem__(value,handler)):
                received=root/'received';stage=root/'stage'
                if fail=='receive':
                    with self.assertRaises(subprocess.CalledProcessError):R.receive_producer(123,2,received,sdk_version=version)
                    self.assertFalse((received/'received.json').exists());return
                result=R.receive_producer(123,2,received,sdk_version=version)
                self.assertEqual(list(result['architectures']),list(R.ARCHITECTURES))
                if fail=='stage':
                    with self.assertRaises(subprocess.CalledProcessError):R.stage_producer(received,stage)
                    self.assertEqual(list(stage.iterdir()),[]);self.assertFalse(any(e[0]=='extra-source-verify'for e in events));return
                manifest=R.stage_producer(received,stage)
            self.assertEqual(list(manifest['architectures']),list(R.ARCHITECTURES))
            self.assertEqual((stage/'SHA256SUMS').read_bytes(),R.producer_checksum_bytes(manifest))
            self.assertEqual(len([e for e in events if e[0]=='extra-source-verify']),2)
            full=[e for e in events if e[0]==('full'if version=='6.0.136'else'serial')];self.assertEqual(len(full),4)
            if version=='6.0.136':self.assertEqual([e[0]for e in events[:4]],['download','download','full','full'])
            else:self.assertEqual([e[0]for e in events[:4]],['download','serial','download','serial']);self.assertEqual(children,[])

if __name__=='__main__':unittest.main()
