"""Ordinary tiny archive/snapshot fixtures only; no retained SDK data or tools."""
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_archive as A


def budget(**changes):
    values=dict(private_bytes=64*1024**2,source_bytes=64*1024**2,public_bytes=64*1024**2,files=4096)
    values.update(changes);return A.Budget(**values)


def source_fixture(files=None,*,pax=None,modes=None):
    files=files or{'orchestration/scripts/example.py':b'print("tiny original source")\n'}
    p=A.packer();baseline={};rows=[]
    for name,raw in sorted(files.items()):
        mode='100755'if(modes or{}).get(name)==0o755 else'100644'
        row=dict(path=name,mode=mode,**A.fingerprint(raw))
        if name.startswith('orchestration/'):
            blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            row['baseline']=dict(mode=mode,blob=blob);baseline[name[len('orchestration/'):]]=row['baseline']
        rows.append(row)
    tree=p.baseline_tree(baseline)
    commit_body=('tree '+tree+'\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nordinary fixture\n').encode()
    commit=hashlib.sha1(b'commit '+str(len(commit_body)).encode()+b'\0'+commit_body).hexdigest()
    roots=[]
    for name in sorted({name.split('/',1)[0]for name in files}):
        row=dict(name=name,kind='git'if name=='orchestration'else'tree',files=sum(path.startswith(name+'/')for path in files),deleted=[])
        if name=='orchestration':row.update(commit=commit,tree=tree,commitObjectBase64=base64.b64encode(commit_body).decode(),submodules=[])
        roots.append(row)
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz',format=tarfile.PAX_FORMAT)as archive:
        for name,raw in sorted(files.items()):
            entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=(modes or{}).get(name,0o644);entry.uid=entry.gid=entry.mtime=0
            if pax:entry.pax_headers=dict(pax)
            archive.addfile(entry,io.BytesIO(raw))
    archive=output.getvalue();index=b''.join((json.dumps(row,sort_keys=True)+'\n').encode()for row in rows)
    expected=dict(sdkVersion='5.0.214',targetRid='linux-musl-arm64',projectCommit=commit,runId='fixture',runAttempt='1')
    manifest=dict(schemaVersion=1,status='captured-used-source',**expected,roots=roots,files=len(rows),
        archive=dict(path='source.tar.gz',**A.fingerprint(archive)),index=dict(path='source-index.jsonl',**A.fingerprint(index)))
    return archive,index,manifest,expected


class FixtureCase(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.budget=budget()

    def snapshot(self,raw,*,category='source'):
        value=A.Snapshot.from_bytes(raw,A.fingerprint(raw),budget=self.budget,category=category)
        self.addCleanup(value.close);return value

    def session(self,archive,index,manifest,expected):
        raw=(json.dumps(manifest,sort_keys=True)+'\n').encode()
        value=A.SourceSession(self.snapshot(archive),self.snapshot(index),raw,expected,
            manifest_identity=A.fingerprint(raw),budget=self.budget,private_root=self.root)
        self.addCleanup(value.close);return value


class ImmutableSnapshots(FixtureCase):
    def test_actual_captured_bytes_survive_later_incoming_path_mutation(self):
        path=self.root/'incoming';path.write_bytes(b'original captured bytes')
        snapshot=A.Snapshot.capture(path,A.fingerprint(path.read_bytes()),budget=self.budget,category='private',private_root=self.root)
        self.addCleanup(snapshot.close);path.write_bytes(b'later different caller bytes')
        self.assertEqual(snapshot.bytes(),b'original captured bytes')

    def test_budget_exhaustion_happens_before_source_body_open(self):
        path=self.root/'incoming';path.write_bytes(b'abcd');small=budget(private_bytes=3)
        with mock.patch.object(Path,'open',side_effect=AssertionError('body must not open')):
            with self.assertRaisesRegex(ValueError,'before allocation'):
                A.Snapshot.capture(path,A.fingerprint(b'abcd'),budget=small,category='private',private_root=self.root)

    def test_changed_captured_body_does_not_match_declared_fingerprint(self):
        path=self.root/'incoming';path.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError,'identity'):
            A.Snapshot.capture(path,A.fingerprint(b'original'),budget=self.budget,category='private',private_root=self.root)

    def test_boolean_size_arbitrary_callback_and_mutated_snapshot_reject(self):
        wrong=A.fingerprint(b'a');wrong['bytes']=True
        with self.assertRaises(ValueError):A.identity(wrong)
        with self.assertRaises(ValueError):A.SourceSession(lambda:None,{},b'{}',{},manifest_identity=A.fingerprint(b'{}'),budget=self.budget,private_root=self.root)
        snapshot=self.snapshot(b'original');snapshot.raw=b'mutated'
        with self.assertRaisesRegex(ValueError,'identity changed'):snapshot.bytes()

    def test_raw_parent_component_is_rejected_before_normalization(self):
        with self.assertRaisesRegex(ValueError,'before normalization'):A.ordinary(self.root/'missing/../input')

    @unittest.skipUnless(A.SA.supported(),'Owned unlinked POSIX descriptor semantics')
    def test_disk_snapshot_uses_one_unlinked_readonly_descriptor(self):
        raw=b'a'*1024;path=self.root/'incoming';path.write_bytes(raw)
        with mock.patch.object(A,'MEMORY_FILE',64):
            snapshot=A.Snapshot.capture(path,A.fingerprint(raw),budget=self.budget,category='private',private_root=self.root)
        self.addCleanup(snapshot.close);self.assertIsNone(snapshot.raw)
        self.assertEqual(os.fstat(snapshot.fd).st_nlink,0)
        self.assertEqual(snapshot.bytes(2048),raw)
        self.assertEqual({p.name for p in self.root.iterdir()},{'incoming'})


class OriginalSourceStreams(FixtureCase):
    def test_complete_source_Git_tree_and_selected_actual_body(self):
        files={'orchestration/scripts/example.py':b'original source\n','data/notice.txt':b'actual data\n'}
        session=self.session(*source_fixture(files));result=session.verify()
        self.assertEqual(result['files'],2);self.assertTrue(session.verified)
        selected=session.select(set(files));self.assertEqual({name:row['raw']for name,row in selected.items()},files)
        self.assertFalse(result['wholeProducerSourceClosure']);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_mismatched_source_bytes_reject_even_with_new_compressed_fingerprint(self):
        archive,index,manifest,expected=source_fixture()
        expanded=gzip.decompress(archive);expanded=expanded.replace(b'print("tiny original source")',b'print("tiny replaced source")')
        changed=gzip.compress(expanded);manifest['archive'].update(A.fingerprint(changed))
        with self.assertRaises(ValueError):self.session(changed,index,manifest,expected).verify()

    def test_wrong_run_or_caller_manifest_identity_rejects(self):
        archive,index,manifest,expected=source_fixture();wrong=dict(expected,runAttempt='2')
        with self.assertRaisesRegex(ValueError,'identity'):self.session(archive,index,manifest,wrong)
        with self.assertRaisesRegex(ValueError,'sealed identity'):
            A.SourceSession(self.snapshot(archive),self.snapshot(index),b'{}',expected,
                manifest_identity=A.fingerprint(b'{"different":true}'),budget=self.budget,private_root=self.root)

    def test_source_index_order_and_extra_rows_reject(self):
        archive,index,manifest,expected=source_fixture({'orchestration/a.py':b'a','orchestration/b.py':b'b'})
        changed=b''.join(reversed(index.splitlines(keepends=True)));manifest['index'].update(A.fingerprint(changed))
        with self.assertRaisesRegex(ValueError,'order'):self.session(archive,changed,manifest,expected).verify()
        extra=index+index.splitlines(keepends=True)[0];manifest['index'].update(A.fingerprint(extra))
        with self.assertRaisesRegex(ValueError,'count'):self.session(archive,extra,manifest,expected)

    def test_source_Git_baseline_and_mode_reject(self):
        archive,index,manifest,expected=source_fixture();rows=[json.loads(line)for line in index.splitlines()]
        rows[0]['baseline']['blob']='0'*40;changed=(json.dumps(rows[0])+'\n').encode();manifest['index'].update(A.fingerprint(changed))
        with self.assertRaisesRegex(ValueError,'Git blob'):self.session(archive,changed,manifest,expected).verify()
        archive,index,manifest,expected=source_fixture();rows=[json.loads(line)for line in index.splitlines()]
        rows[0]['mode']='100755';changed=(json.dumps(rows[0])+'\n').encode();manifest['index'].update(A.fingerprint(changed))
        with self.assertRaisesRegex(ValueError,'mode'):self.session(archive,changed,manifest,expected).verify()

    def test_unknown_PAX_metadata_padding_and_concatenated_archive_reject(self):
        with self.assertRaisesRegex(ValueError,'PAX metadata'):
            self.session(*source_fixture(pax={'comment':'hidden container bytes'}))
        archive,index,manifest,expected=source_fixture();raw=bytearray(gzip.decompress(archive));raw[-100]=ord('X')
        changed=gzip.compress(raw);manifest['archive'].update(A.fingerprint(changed))
        with self.assertRaisesRegex(ValueError,'termination'):self.session(changed,index,manifest,expected)
        archive,index,manifest,expected=source_fixture();changed=archive+archive;manifest['archive'].update(A.fingerprint(changed))
        with self.assertRaises(ValueError):self.session(changed,index,manifest,expected)

    def test_long_original_PAX_path_is_consumed_exactly(self):
        name='orchestration/'+('long-name-'*20)+'.py';session=self.session(*source_fixture({name:b'ordinary long path\n'}))
        session.verify();self.assertEqual(session.select({name})[name]['raw'],b'ordinary long path\n')

    def test_original_tarfile_record_boundary_can_have_10752_zero_tail_bytes(self):
        name='orchestration/boundary.bin';archive,index,manifest,expected=source_fixture({name:b'x'*9216})
        raw=gzip.decompress(archive)
        self.assertEqual(len(raw),20480);self.assertEqual(raw[9728:],b'\0'*10752)
        session=self.session(archive,index,manifest,expected);session.verify()
        self.assertEqual(session.select({name})[name]['raw'],b'x'*9216)

    def test_mutable_manifest_or_unverified_selection_never_becomes_source_proof(self):
        session=self.session(*source_fixture())
        with self.assertRaisesRegex(ValueError,'Verified closed'):session.select({'orchestration/scripts/example.py'})
        session.verify()
        with self.assertRaises(TypeError):session.manifest['runId']='replaced'
        session.manifest=dict(session.manifest,runId='replaced')
        with self.assertRaisesRegex(ValueError,'identity/manifest changed'):session.select({'orchestration/scripts/example.py'})

    def test_capture_reads_actual_manifest_control_archive_and_index_once(self):
        archive,index,manifest,expected=source_fixture();release=self.root/'delivery';(release/'sources').mkdir(parents=True)
        (release/'reports/ci').mkdir(parents=True);private=self.root/'private';private.mkdir()
        raw=(json.dumps(manifest)+'\n').encode()
        for name,body in(('source-manifest.json',raw),('source.tar.gz',archive),('source-index.jsonl',index)):(release/'sources'/name).write_bytes(body)
        (release/'reports/ci/used-source.json').write_bytes(raw)
        session=A.SourceSession.capture(release,expected,A.fingerprint(raw),budget=self.budget,private_root=private)
        self.addCleanup(session.close);(release/'sources/source-index.jsonl').write_bytes(b'changed after capture')
        self.assertEqual(session.select({'orchestration/scripts/example.py'})['orchestration/scripts/example.py']['raw'],b'print("tiny original source")\n')

    def test_failed_complete_verification_closes_its_owned_expanded_source_session(self):
        archive,index,manifest,expected=source_fixture();release=self.root/'D';private=self.root/'private';private.mkdir()
        raw=(json.dumps(manifest)+'\n').encode();bodies={'sources/source-manifest.json':raw,'sources/source.tar.gz':archive,
            'sources/source-index.jsonl':index,'reports/ci/used-source.json':raw}
        for name,body in bodies.items():
            path=release/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
        captured=[]
        def failed(session):captured.append(session);raise ValueError('ordinary verification failure')
        with mock.patch.object(A.SourceSession,'verify',new=failed),self.assertRaisesRegex(ValueError,'ordinary verification failure'):
            A.SourceSession.capture(release,expected,A.fingerprint(raw),budget=self.budget,private_root=private)
        self.assertEqual(len(captured),1);self.assertTrue(captured[0].raw.closed)
        self.assertTrue(captured[0].archive.closed);self.assertTrue(captured[0].index.closed)

    def test_absence_and_closed_root_use_complete_immutable_index_not_missing_mappings(self):
        files={'orchestration/scripts/example.py':b'code','app/evidence/normal-context.json':b'{}',
            'app/evidence/container-invocation.json':b'private process marker'}
        session=self.session(*source_fixture(files));session.verify()
        with self.assertRaisesRegex(ValueError,'Forbidden original member'):
            session.assert_absent_members('app',{'evidence/container-invocation.json'})
        with self.assertRaisesRegex(ValueError,'missing or extra'):
            session.assert_closed_root('app',{'evidence/normal-context.json'},kind='tree',role=None)
        members={'evidence/normal-context.json','evidence/container-invocation.json'}
        self.assertEqual(set(session.assert_closed_root('app',members,kind='tree',role=None)),members)
        result=session.assert_absent_members('app',{'evidence/container-result.json'})
        self.assertTrue(result['absenceCheckedAgainstCompleteImmutableIndex'])
        self.assertEqual(result['actualIndexedFiles'],2)


class AuthenticatedViews(FixtureCase):
    def view(self):
        value=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(value.close);return value

    def test_original_host_container_and_capture_namespaces_are_distinct(self):
        view=self.view();view.declare_root('/original/delivery','delivery',role='delivery')
        one=self.snapshot(b'host',category='private');two=self.snapshot(b'container',category='private')
        view.add('/inputs/file','host/file',one)
        view.add('/inputs/file','container/file',two,namespace='container')
        if os.name=='posix':
            view.freeze()
            with view.guard():self.assertEqual(view.read('/inputs/file'),b'host')
        self.assertEqual(view.read('/inputs/file'),b'host')
        self.assertEqual(view.read('/inputs/file',namespace='container'),b'container')
        self.assertEqual(view.release_root,view.root/'delivery')
        self.assertEqual(view.logical_root('delivery'),'/original/delivery')

    def test_descriptors_require_original_path_and_complete_actual_identity(self):
        view=self.view();raw=b'actual bytes';view.add('/original/report','delivery/report',self.snapshot(raw))
        descriptor=dict(path='/original/report',**A.fingerprint(raw))
        if os.name=='posix':
            view.freeze()
            with view.guard():self.assertEqual(view.checked('/original/report',descriptor),view.root/'delivery/report')
        else:self.assertEqual(view.checked('/original/report',descriptor),view.root/'delivery/report')
        with self.assertRaises(ValueError):view.checked('/original/report',dict(descriptor,path='/new/report'))
        with self.assertRaises(ValueError):view.checked('/original/report',dict(descriptor,sha256='0'*64))

    def test_only_exact_recorded_consumer_double_slash_is_allowed(self):
        view=self.view();name='/work/work/sdk/artifacts/bin/redist/Release/dotnet//sdk/5.0.214-ci/Microsoft.ApplicationInsights.dll'
        view.add(name,'capture/file',self.snapshot(b'product'),namespace='consumer')
        self.assertEqual(view.read(name,namespace='consumer'),b'product')
        with self.assertRaises(ValueError):view.path(name)
        with self.assertRaises(ValueError):view.path(name.replace('dotnet//','dotnet///'),namespace='consumer')

    @unittest.skipUnless(os.name=='posix','POSIX physical delegated view semantics')
    def test_changed_body_before_freeze_extra_file_and_new_binding_reject(self):
        view=self.view();path=view.add('/actual','data/actual',self.snapshot(b'original'));path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'before view freeze'):view.freeze()
        path.write_bytes(b'original');(view.root/'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'extra/unmapped'):view.freeze()
        (view.root/'extra').unlink();view.freeze()
        with self.assertRaises(ValueError):view.add('/new','data/new',self.snapshot(b'new'))

    def test_unsupported_physical_view_never_claims_a_frozen_delegate(self):
        view=self.view();view.add('/actual','data/actual',self.snapshot(b'actual'))
        if os.name!='posix':
            with self.assertRaisesRegex(ValueError,'require POSIX'):view.freeze()
            self.assertFalse(view.frozen)
        else:self.assertTrue(A.SA.supported())

    @unittest.skipUnless(os.name=='posix','POSIX ctime/witness semantics')
    def test_write_and_restore_bytes_and_mtime_cannot_hide_delegated_mutation(self):
        view=self.view();path=view.add('/actual','data/actual',self.snapshot(b'original'));view.freeze();info=path.stat()
        with self.assertRaisesRegex(ValueError,'during delegated reads'):
            with view.guard():
                path.write_bytes(b'changed!');path.write_bytes(b'original');os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))

    @unittest.skipUnless(os.name=='posix','POSIX symlink semantics')
    def test_symlinked_destination_or_missing_logical_mapping_rejects(self):
        view=self.view();outside=self.root/'outside';outside.mkdir();(view.root/'linked').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(ValueError):view.add('/actual','linked/file',self.snapshot(b'actual'))
        with self.assertRaisesRegex(ValueError,'no authenticated mapping'):view.path('/not/mapped')


class ConcreteProvenance(FixtureCase):
    def source(self):
        archive,index,manifest,expected=source_fixture()
        manifest['roots'][0].update(originalPath='/original/project',role='orchestration')
        session=self.session(archive,index,manifest,expected);session.verify();return session

    def test_actual_source_member_mints_same_session_index_provenance(self):
        source=self.source();name='orchestration/scripts/example.py'
        origin=source.mint_members({name},budget=self.budget)[name];self.addCleanup(origin.snapshot.close)
        view=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(view.close)
        view.bind_origin('/original/project/scripts/example.py','project/scripts/example.py',origin)
        result=view.require_origin('/original/project/scripts/example.py')
        self.assertIs(view.source,source);self.assertEqual(result['member'],name)
        self.assertEqual(result['role'],'orchestration');self.assertEqual(result['archive'],source.archive.fingerprint)
        self.assertEqual(result['index'],source.index.fingerprint)
        self.assertEqual(source.root_for('/original/project',kind='git',role='orchestration')['name'],'orchestration')

    def test_arbitrary_snapshot_and_another_session_never_supply_accepted_origins(self):
        source=self.source();view=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(view.close)
        view.add('/fabricated','data/file',self.snapshot(b'fake'));view.source=source
        with self.assertRaisesRegex(ValueError,'Arbitrary captured bytes'):view.require_origin('/fabricated')
        other=self.source();name='orchestration/scripts/example.py';origin=other.mint_members({name},budget=self.budget)[name]
        self.addCleanup(origin.snapshot.close)
        with self.assertRaisesRegex(ValueError,'One actual source session'):view.bind_origin('/other','data/other',origin)

    def test_closing_source_session_invalidates_live_origin_capability(self):
        source=self.source();name='orchestration/scripts/example.py';origin=source.mint_members({name},budget=self.budget)[name]
        self.addCleanup(origin.snapshot.close);source.close();self.assertFalse(source.verified)
        with self.assertRaisesRegex(ValueError,'Live actual archived'):origin.metadata()
        with self.assertRaises(ValueError):A.require_reconstructed({'constructionValidated':True})

    def test_complete_delivery_captures_bind_caller_record_and_reuse_source_bytes(self):
        source=self.source();release=self.root/'delivery';(release/'sources').mkdir(parents=True);(release/'reports/ci').mkdir(parents=True)
        bodies={'sources/source-manifest.json':source.manifest_raw,'reports/ci/used-source.json':source.manifest_raw,
            'sources/source.tar.gz':source.archive.bytes(),'sources/source-index.jsonl':source.index.bytes(),
            'reports/stage.json':b'{"status":"passed"}\n'}
        for name,raw in bodies.items():
            path=release/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        record=dict(source.expected,files=[dict(path=name,**A.fingerprint(raw))for name,raw in sorted(bodies.items())])
        private=self.root/'snapshots';private.mkdir()
        delivery=A.DeliverySession.capture(release,record,source,'/original/delivery',budget=self.budget,private_root=private)
        self.addCleanup(delivery.close);origin=delivery.mint('reports/stage.json')
        view=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(view.close)
        view.bind_origin('/original/delivery/reports/stage.json','delivery/reports/stage.json',origin,category='public')
        result=view.require_origin('/original/delivery/reports/stage.json')
        self.assertEqual(result['member'],'reports/stage.json')
        self.assertEqual(result['recordFingerprint'],A.fingerprint(A.canonical(record)))
        (release/'reports/stage.json').write_bytes(b'changed after immutable capture')
        self.assertEqual(view.read('/original/delivery/reports/stage.json'),b'{"status":"passed"}\n')
        with self.assertRaises(TypeError):delivery.record['runAttempt']='different'
        delivery.record=dict(delivery.record,runAttempt='different')
        with self.assertRaisesRegex(ValueError,'record changed'):view.require_origin('/original/delivery/reports/stage.json')


def compiler_archive_fixture(entries):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz')as archive:
        for name,raw,mode,kind in entries:
            entry=tarfile.TarInfo(name);entry.type=kind;entry.mode=mode
            if kind in(tarfile.REGTYPE,tarfile.AREGTYPE):entry.size=len(raw);archive.addfile(entry,io.BytesIO(raw))
            else:entry.linkname='target';archive.addfile(entry)
    raw=output.getvalue();pin=dict(version='fixture',rid='linux-musl-arm64',url='https://example.invalid/original',sha512=A.fingerprint(raw)['sha512'])
    return raw,pin,dict(pin,**A.fingerprint(raw))


class CompilerArchiveStreams(FixtureCase):
    def test_complete_original_stream_inventory_and_official_pin(self):
        raw,pin,receipt=compiler_archive_fixture([('dotnet',b'host',0o755,tarfile.REGTYPE),('sdk/targets',b'original target',0o644,tarfile.REGTYPE)])
        snapshot=self.snapshot(raw,category='private')
        with mock.patch.object(A.BYTE.C,'pin',return_value=pin):
            actual,inventory=A.inventory_original_stream(snapshot,receipt,'legacy5','aarch64')
            self.assertEqual(actual,receipt);self.assertEqual(set(inventory),{'dotnet','sdk/targets'})
            wrong=dict(receipt,sha512='0'*128)
            with self.assertRaisesRegex(ValueError,'pin/receipt'):A.inventory_original_stream(snapshot,wrong,'legacy5','aarch64')

    def test_unselected_matching_runtime_archive_entries_still_receive_type_guards(self):
        raw,pin,receipt=compiler_archive_fixture([(A.BYTE.PREFIX+'libcoreclr.so',b'core',0o755,tarfile.REGTYPE),
            ('unselected/link',b'',0o777,tarfile.SYMTYPE)])
        with mock.patch.object(A.BYTE.C,'pin',return_value=pin),self.assertRaisesRegex(ValueError,'links/devices'):
            A.inventory_original_stream(self.snapshot(raw),receipt,'runtime','aarch64',prefix=A.BYTE.PREFIX)

    def test_original_duplicate_parent_special_mode_and_empty_selection_reject(self):
        controls=[ [('same',b'a',0o644,tarfile.REGTYPE),('same',b'b',0o644,tarfile.REGTYPE)],
            [('../escape',b'a',0o644,tarfile.REGTYPE)],[('special',b'a',0o4755,tarfile.REGTYPE)] ]
        for entries in controls:
            raw,pin,receipt=compiler_archive_fixture(entries)
            with self.subTest(entries=entries),mock.patch.object(A.BYTE.C,'pin',return_value=pin),self.assertRaises(ValueError):
                A.inventory_original_stream(self.snapshot(raw),receipt,'legacy5','aarch64')
        raw,pin,receipt=compiler_archive_fixture([('other/file',b'a',0o644,tarfile.REGTYPE)])
        with mock.patch.object(A.BYTE.C,'pin',return_value=pin),self.assertRaisesRegex(ValueError,'inventory is empty'):
            A.inventory_original_stream(self.snapshot(raw),receipt,'runtime','aarch64',prefix=A.BYTE.PREFIX)

    @unittest.skipUnless(os.name=='posix','Actual compiler reconstruction POSIX modes')
    def test_materialization_checks_inventory_and_whole_budget_before_first_write(self):
        raw,pin,receipt=compiler_archive_fixture([('dotnet',b'host',0o755,tarfile.REGTYPE)])
        snapshot=self.snapshot(raw)
        with mock.patch.object(A.BYTE.C,'pin',return_value=pin):
            _,inventory=A.inventory_original_stream(snapshot,receipt,'legacy5','aarch64')
            denied=self.root/'denied'
            with self.assertRaisesRegex(ValueError,'before allocation'):
                A.materialize_inventory(snapshot,receipt,'legacy5','aarch64',inventory,denied,budget=budget(private_bytes=3))
            self.assertFalse(denied.exists())
            destination=self.root/'actual'
            result=A.materialize_inventory(snapshot,receipt,'legacy5','aarch64',inventory,destination,budget=self.budget)
            self.assertEqual((destination/'dotnet').read_bytes(),b'host');self.assertEqual(result['files'],1)
            self.assertEqual(stat.S_IMODE((destination/'dotnet').stat().st_mode),0o755)

    @unittest.skipUnless(os.name=='posix','Actual compiler reconstruction POSIX modes')
    def test_matching_framework_merges_once_only_into_exact_disjoint_sdk_inventory(self):
        raw,pin,receipt=compiler_archive_fixture([('dotnet',b'host',0o755,tarfile.REGTYPE)])
        runtime,runtime_pin,runtime_receipt=compiler_archive_fixture([(A.BYTE.PREFIX+'libcoreclr.so',b'clr',0o755,tarfile.REGTYPE)])
        first=self.snapshot(raw);second=self.snapshot(runtime);destination=self.root/'compiler'
        with mock.patch.object(A.BYTE.C,'pin',return_value=pin):
            _,sdk=A.inventory_original_stream(first,receipt,'legacy5','aarch64')
            A.materialize_inventory(first,receipt,'legacy5','aarch64',sdk,destination,budget=self.budget)
        with mock.patch.object(A.BYTE.C,'pin',return_value=runtime_pin):
            _,framework=A.inventory_original_stream(second,runtime_receipt,'runtime','aarch64',prefix=A.BYTE.PREFIX)
            with self.assertRaisesRegex(ValueError,'existing compiler inventory'):
                A.materialize_inventory(second,runtime_receipt,'runtime','aarch64',framework,destination,budget=self.budget,
                    prefix=A.BYTE.PREFIX,existing_inventory={})
            A.materialize_inventory(second,runtime_receipt,'runtime','aarch64',framework,destination,budget=self.budget,
                prefix=A.BYTE.PREFIX,existing_inventory=sdk)
            self.assertEqual(A.BYTE.actual_tree(destination),dict(sdk,**framework))
            with self.assertRaises(ValueError):A.materialize_inventory(second,runtime_receipt,'runtime','aarch64',framework,
                destination,budget=self.budget,prefix=A.BYTE.PREFIX,existing_inventory=dict(sdk,**framework))


class ArchiveFactoryPredicates(FixtureCase):
    def delivery_fixture(self,*,different=False):
        files={'orchestration/scripts/example.py':b'print("fixture")\n','app/script.sh':b'#!/bin/sh\nexit 0\n'}
        archive,index,manifest,expected=source_fixture(files,modes={'app/script.sh':0o755})
        for root in manifest['roots']:
            root.update(originalPath='/original/project'if root['name']=='orchestration'else'/original/delivery/reports/app',
                role='orchestration'if root['name']=='orchestration'else A.APP_PUBLIC_ROLE)
        source=self.session(archive,index,manifest,expected);source.verify()
        release=self.root/'D';release.mkdir();private=self.root/'snapshot-private';private.mkdir()
        bodies={'sources/source-manifest.json':source.manifest_raw,'reports/ci/used-source.json':source.manifest_raw,
            'sources/source.tar.gz':archive,'sources/source-index.jsonl':index,
            'reports/app/script.sh':b'foreign bytes'if different else files['app/script.sh']}
        for name,raw in bodies.items():
            path=release/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            if os.name=='posix':path.chmod(0o644)
        record=dict(expected,files=[dict(path=name,**A.fingerprint(raw))for name,raw in sorted(bodies.items())])
        delivery=A.DeliverySession.capture(release,record,source,'/original/delivery',budget=self.budget,private_root=private)
        self.addCleanup(delivery.close);return source,delivery

    def test_source_index_couples_actual_captured_delivery_bytes_and_original_mode(self):
        source,delivery=self.delivery_fixture();origins=source.mint_delivery_root(delivery,'app')
        origin=origins['script.sh'];self.assertIs(origin.snapshot,delivery.snapshots['reports/app/script.sh'])
        self.assertEqual(origin.metadata()['mode'],0o755)
        delivery._couple_source_modes({'reports/app/script.sh':origin})
        minted=delivery.mint('reports/app/script.sh');self.assertEqual(minted.metadata()['mode'],0o755)
        with self.assertRaisesRegex(ValueError,'before first delivery'):delivery._couple_source_modes({'reports/app/script.sh':origin})

    def test_self_consistent_delivery_record_cannot_replace_real_source_index_body(self):
        source,delivery=self.delivery_fixture(different=True)
        with self.assertRaisesRegex(ValueError,'differs from captured'):source.mint_delivery_root(delivery,'app')

    def test_provenance_mutation_and_snapshot_relabeling_reject(self):
        source,delivery=self.delivery_fixture();origin=delivery.mint('reports/app/script.sh')
        origin.member='sources/source-manifest.json'
        with self.assertRaisesRegex(ValueError,'binding changed'):origin.metadata()
        snapshot=delivery.snapshots['reports/app/script.sh'];snapshot.fingerprint=A.fingerprint(b'forged')
        with self.assertRaisesRegex(ValueError,'caller inventory'):delivery.mint('reports/app/script.sh')

    def test_authenticated_nested_source_and_delivery_metadata_cannot_mutate(self):
        source,delivery=self.delivery_fixture()
        with self.assertRaises(TypeError):source.manifest['roots'].append({})
        with self.assertRaises(TypeError):source.result['identity']['runId']='other'
        with self.assertRaises(TypeError):delivery.record['files'][0]['sha256']='0'*64
        with self.assertRaises(TypeError):delivery.snapshots.clear()

    def test_closed_real_public_output_names_include_every_intermediate_and_generated_origin(self):
        members,outputs=A.public_app_members();self.assertEqual((len(members),len(outputs)),(493,29))
        self.assertTrue(set(A.COMPILER_FILES)<=outputs)
        self.assertFalse(any(name.startswith(('inputs/','reference-root/'))for name in members))
        self.assertTrue({'original-import-bindings.json','compiler-output-origins.json'}<=members)

    def test_original_compiler_path_fields_have_distinct_fixed_physical_witness(self):
        workspace=self.root/'app';physical=workspace/'output/app/Microsoft.ApplicationInsights.dll'
        physical.parent.mkdir(parents=True);physical.write_bytes(b'tiny helper fixture, never compiled')
        record=dict(finalOutput=dict(path=str(physical),**A.N.fingerprint(physical)),other='preserved')
        result=A._compiler_original_fields(record,workspace,'/original/attempt','app')
        self.assertEqual(result['finalOutput']['path'],'/original/attempt/output/app/Microsoft.ApplicationInsights.dll')
        self.assertEqual(record['finalOutput']['path'],str(physical));self.assertEqual(result['other'],'preserved')
        with self.assertRaisesRegex(ValueError,'fixed reconstructed'):A._compiler_original_fields(dict(record,finalOutput=dict(record['finalOutput'],path='/forged')),
            workspace,'/original/attempt','app')

    @unittest.skipUnless(os.name=='posix','Actual adopted compiler view POSIX modes')
    def test_owned_compiler_adoption_hashes_actual_bytes_and_cannot_accept_foreign_inventory(self):
        view=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(view.close)
        compiler=view.root/'compiler';compiler.mkdir();(compiler/'dotnet').write_bytes(b'tiny host');(compiler/'dotnet').chmod(0o755)
        inventory=A.BYTE.actual_tree(compiler);view.declare_root('/bootstrap','compiler',namespace='container')
        with self.assertRaisesRegex(ValueError,'differs before mapping'):view.adopt_inventory('/bootstrap','compiler',{'dotnet':dict(inventory['dotnet'],sha256='0'*64)})
        view.adopt_inventory('/bootstrap','compiler',inventory);view.freeze()
        with view.guard():self.assertEqual(view.path('/bootstrap/dotnet',namespace='container'),compiler/'dotnet')

    @unittest.skipUnless(os.name=='posix','POSIX descriptor budget preflight')
    def test_descriptor_budget_rejects_before_any_owned_file_open(self):
        import resource
        view=A.FrozenView(self.root/'view',budget=self.budget);self.addCleanup(view.close)
        view.add('/tiny','tiny',self.snapshot(b'body'))
        with mock.patch.object(resource,'getrlimit',return_value=(1,1)),mock.patch.object(A.os,'open',side_effect=AssertionError('no opens')):
            with self.assertRaisesRegex(ValueError,'before frozen-view opens'):view.freeze()


class CompletePackageContainer(FixtureCase):
    def fixture(self):
        bodies={'Microsoft.ApplicationInsights.nuspec':b'<package/>','LICENSE':b'ordinary fixture license',
            **{'lib/dotnet5.4/Microsoft.ApplicationInsights.'+suffix:b'fixture '+suffix.encode()for suffix in('dll','pdb','xml')}}
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as archive:
            for name,body in sorted(bodies.items()):
                row=zipfile.ZipInfo(name,(1980,1,1,0,0,0));row.create_system=3;row.external_attr=0o100644<<16;row.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(row,body)
        return raw.getvalue(),bodies

    def test_exact_complete_container_and_all_five_actual_bodies(self):
        raw,bodies=self.fixture();self.assertEqual(A.validate_package_bytes(raw,bodies),{name:A.fingerprint(body)for name,body in bodies.items()})

    def test_unchanged_members_cannot_hide_comment_padding_extra_or_metadata(self):
        raw,bodies=self.fixture();mutations=[raw+b'private trailing body',raw[:-2]+b'\x07\0comment']
        for extra,comment,mode in((b'\xfe\xca\x04\0body',b'',0o100644),(b'',b'private',0o100644),(b'',b'',0o100755)):
            out=io.BytesIO()
            with zipfile.ZipFile(out,'w')as archive:
                for name,body in sorted(bodies.items()):
                    row=zipfile.ZipInfo(name,(1980,1,1,0,0,0));row.create_system=3;row.external_attr=mode<<16;row.compress_type=zipfile.ZIP_DEFLATED
                    row.extra=extra;row.comment=comment;archive.writestr(row,body)
            mutations.append(out.getvalue())
        for value in mutations:
            with self.subTest(length=len(value)),self.assertRaisesRegex(ValueError,'Whole actual'):A.validate_package_bytes(value,bodies)

    def test_missing_or_changed_expected_member_and_arbitrary_descriptor_reject(self):
        raw,bodies=self.fixture()
        with self.assertRaises(ValueError):A.validate_package_bytes(raw,{name:body for name,body in bodies.items()if name!='LICENSE'})
        with self.assertRaises(ValueError):A.validate_package_bytes(raw,dict(bodies,LICENSE=b'changed'))
        with self.assertRaises(ValueError):A.validate_package_bytes(A.fingerprint(raw),bodies)


if __name__=='__main__':unittest.main()
