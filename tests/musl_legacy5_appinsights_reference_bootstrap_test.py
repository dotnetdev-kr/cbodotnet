"""Small byte/role/exclusion fixtures; no App, CLR, Reader or container."""
import base64
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_reference_bootstrap as M


class FiniteReferenceRole(unittest.TestCase):
    def test_one_finite_original_role(self):
        p=M.policy();self.assertEqual(p['role'],M.ROLE)
        self.assertEqual(p['referenceArchive']['bytes'],13539095)
        self.assertEqual((len(p['publicInputNames']),len(p['privateInputFiles'])),(449,73))
        self.assertFalse(p['payloadRole']);self.assertFalse(p['referencePreferredSourceEstablished'])
        self.assertFalse(p['binaryRedistributionApproved'])

    def test_original_worker_three_and_strong_pins_unchanged(self):
        strong,worker=M.N.original_validators()
        self.assertEqual(M.N.fingerprint(Path(strong.__file__)),M.N.STRONG_SOURCE)
        for name,want in strong.WORKER_SOURCES.items():self.assertEqual(M.N.fingerprint(ROOT/'scripts'/name),want)

    def test_alternate_extra_or_descriptor_only_role_rejects(self):
        for value in ({},dict(role=M.ROLE),dict(M.role_record(),payloadRole=True),
                      dict(M.role_record(),role='generic-binary-bootstrap')):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'Exact finite'):M.validate_role(value)

    def test_original449_full_fingerprints_and_exact_byte_budget(self):
        rows=M.public_input_fingerprints();p=M.policy()
        self.assertEqual(len(rows),449);self.assertEqual(sum(row['bytes']for row in rows.values()),5635690)
        self.assertFalse(set(rows)&set(p['privateInputFiles']))
        self.assertNotIn('original.nupkg',rows);self.assertNotIn('reference.zip',rows)
        self.assertEqual(sum(name.startswith('source/')for name in rows),437)

    def test_all65_pe_and_selected71_binaries_are_private(self):
        p=M.policy();rows=p['privateInputFiles']
        self.assertEqual(sum(name.endswith('.dll')for name in rows),65)
        self.assertEqual(sum(name.startswith('reference-root/')for name in rows),71)
        self.assertEqual(rows['original.nupkg']['sha256'],'19d894ac4051087ebb81f81e4a072327cfb7deac826502148061c6584ae8bf61')

    def test_original_git_mode_intent_remains_strict(self):
        files={'a':{'mode':'100644'},'b':{'mode':'100755'}}
        self.assertEqual(M._mode('source/a',files),0o644);self.assertEqual(M._mode('source/b',files),0o755)
        self.assertEqual(M._mode('reference.zip',files),0o644)

    @unittest.skipIf(os.name=='nt','POSIX source copy mode semantics')
    def test_fresh_source_copy_retains_original_executable_mode(self):
        with tempfile.TemporaryDirectory()as temp:
            source=Path(temp)/'source';target=Path(temp)/'export/source';source.write_bytes(b'original source\n')
            M._copy(source,target,M.N.fingerprint(source),0o755)
            self.assertEqual(target.stat().st_mode&0o7777,0o755)

    def test_missing_external_inputs_never_become_full_construction(self):
        with tempfile.TemporaryDirectory()as temp:
            with self.assertRaises(ValueError):M.validate_public_construction(Path(temp),external_inputs={})

    def test_altered_historical_notice_rejects(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/'notice';path.write_bytes(b'Not the original historical notice')
            with self.assertRaisesRegex(ValueError,'historical'):M._notice(path)


class ContentExclusion(unittest.TestCase):
    SECRET=b'MZ\x00PRIVATE-FINITE-REFERENCE-CONTENT\xff'

    def check(self,raw):return M.scan_content(raw,{'reference':self.SECRET})

    def test_authored_source_positive(self):self.assertGreater(self.check(b'// original authored source\n')['bytes'],0)

    def test_renamed_and_embedded_complete_reference_reject(self):
        for raw in (self.SECRET,b'prefix'+self.SECRET+b'suffix'):
            with self.assertRaisesRegex(ValueError,'cannot be published'):self.check(raw)

    def test_encoded_reference_json_body_rejects(self):
        with self.assertRaisesRegex(ValueError,'Encoded private'):
            self.check(json.dumps({'blob':base64.b64encode(self.SECRET).decode()}).encode())

    def test_npk_and_embedded_import_zip_reject(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED)as z:z.writestr('renamed/member.dat',self.SECRET)
        for payload in (raw.getvalue(),b'binlog-record-prefix'+raw.getvalue()+b'record-suffix'):
            with self.assertRaisesRegex(ValueError,'cannot be published'):self.check(payload)

    def test_gzip_binlog_and_tar_members_reject(self):
        with self.assertRaisesRegex(ValueError,'cannot be published'):self.check(gzip.compress(b'events'+self.SECRET))
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w')as archive:
            row=tarfile.TarInfo('data/file');row.size=len(self.SECRET);archive.addfile(row,io.BytesIO(self.SECRET))
        with self.assertRaisesRegex(ValueError,'cannot be published'):self.check(gzip.compress(raw.getvalue()))

    def test_unique_ordinary_zip_members_required(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w')as archive:
            member=zipfile.ZipInfo('symlink');member.create_system=3;member.external_attr=0o120777<<16;archive.writestr(member,b'target')
        with self.assertRaisesRegex(ValueError,'Ordinary'):self.check(raw.getvalue())

    def test_unclosed_zip_and_expansion_cap_reject(self):
        with self.assertRaisesRegex(ValueError,'Unclosed'):self.check(b'PK\x03\x04truncated')
        with self.assertRaisesRegex(ValueError,'budget'):
            M.scan_content(b'x',{'ref':self.SECRET},budget={'bytes':M.MAX_EXPORT,'entries':0})

    def test_small_clean_nested_archive_positive(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w')as z:z.writestr('source/Original.cs',b'class Original {}\n')
        self.assertGreater(self.check(gzip.compress(raw.getvalue()))['entries'],2)

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO')
    def test_fifo_rejected_before_read(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/'fifo';os.mkfifo(path);start=time.monotonic()
            with self.assertRaises(ValueError):M.N.tree_files(Path(temp))
            self.assertLess(time.monotonic()-start,1)

    @unittest.skipIf(os.name=='nt','POSIX special permission')
    def test_special_permissions_rejected(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/'source';path.write_bytes(b'data');path.chmod(0o4755)
            with self.assertRaises(ValueError):M.N.tree_files(Path(temp))


class CheckedDeliveryPublication(unittest.TestCase):
    SECRET=b'MZ\0PRIVATE-LATE-REFERENCE-BODY\xff'

    def roots(self,temp):
        stage=Path(temp)/'private/public-staging';stage.mkdir(parents=True)
        return stage,Path(temp)/'delivery/appinsights'

    def test_late_forbidden_candidate_rejects_before_first_delivery_write(self):
        with tempfile.TemporaryDirectory()as temp:
            stage,delivery=self.roots(temp)
            (stage/'01-clean.cs').write_bytes(b'// clean authored source\n')
            (stage/'99-late.binlog').write_bytes(self.SECRET)
            with mock.patch.object(M,'_forbidden',return_value={'reference':self.SECRET}):
                with self.assertRaisesRegex(ValueError,'cannot be published'):
                    M._publish_checked_public_tree(stage,delivery,private_workspace=Path(temp)/'private')
            self.assertFalse(delivery.exists());self.assertFalse(delivery.parent.exists())

    def test_changed_source_after_inventory_rejects_before_delivery_open(self):
        with tempfile.TemporaryDirectory()as temp:
            stage,delivery=self.roots(temp);source=stage/'candidate';source.write_bytes(b'clean original bytes\n')
            original_tree=M.N.tree_files
            def swap_after_inventory(root):
                result=original_tree(root);source.write_bytes(self.SECRET);return result
            with mock.patch.object(M.N,'tree_files',side_effect=swap_after_inventory),\
                    mock.patch.object(M,'_forbidden',return_value={'reference':self.SECRET}):
                with self.assertRaisesRegex(ValueError,'candidate changed'):
                    M._publish_checked_public_tree(stage,delivery,private_workspace=Path(temp)/'private')
            self.assertFalse(delivery.exists());self.assertFalse(delivery.parent.exists())

    def test_changed_source_after_complete_preflight_cannot_change_published_bytes(self):
        with tempfile.TemporaryDirectory()as temp:
            stage,delivery=self.roots(temp);source=stage/'candidate';clean=b'clean checked authored bytes\n';source.write_bytes(clean)
            original_buffers=M._checked_public_buffers
            def swap_after_preflight(*args,**kwargs):
                result=original_buffers(*args,**kwargs);source.write_bytes(self.SECRET);return result
            with mock.patch.object(M,'_checked_public_buffers',side_effect=swap_after_preflight),\
                    mock.patch.object(M,'_forbidden',return_value={'reference':self.SECRET}):
                result=M._publish_checked_public_tree(stage,delivery,private_workspace=Path(temp)/'private')
            self.assertEqual((delivery/'candidate').read_bytes(),clean)
            self.assertEqual(source.read_bytes(),self.SECRET)
            self.assertTrue(result['allCandidatesScannedBeforeFirstDeliveryWrite'])
            self.assertTrue(result['deliveryWrittenFromCheckedBuffers'])

    def test_over_budget_candidates_reject_before_delivery_write(self):
        with tempfile.TemporaryDirectory()as temp:
            stage,delivery=self.roots(temp);(stage/'candidate').write_bytes(b'clean authored bytes over the tiny cap')
            with mock.patch.object(M,'MAX_EXPORT',16):
                with self.assertRaisesRegex(ValueError,'Bounded complete'):
                    M._publish_checked_public_tree(stage,delivery,private_workspace=Path(temp)/'private')
            self.assertFalse(delivery.exists());self.assertFalse(delivery.parent.exists())


class OriginalBinlogPublication(unittest.TestCase):
    """Synthetic framing/payload controls; no retained original log is read."""
    SECRET=b'MZ\0SYNTHETIC-REFERENCE-FORBIDDEN-BODY\xff'

    def fixture(self,role='app',secret=None):
        spec=importlib.util.spec_from_file_location('synthetic_import_wire_fixture',ROOT/'tests/musl_legacy5_appinsights_imports_test.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module.fixture(role,secret=secret)

    def test_generic_zip_guards_still_reject_original_logical_backslash_names(self):
        raw,_,_,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'Ordinary bounded unencrypted'):
            M.scan_content(raw,{'private':self.SECRET})

    def test_only_complete_framed_policy_members_receive_narrow_content_scan(self):
        raw,p,_,_=self.fixture();budget={'bytes':0,'entries':0}
        with mock.patch.object(M.IMPORTS,'policy',return_value=p):
            M._scan_original_binlog(raw,{'private':self.SECRET},role='app',expected=M.IMPORTS.fingerprint(raw),budget=budget)
        self.assertGreater(budget['entries'],4)

    def test_foreign_member_or_changed_whole_log_rejects_narrow_route(self):
        raw,p,_,_=self.fixture()
        with mock.patch.object(M.IMPORTS,'policy',return_value=p):
            with self.assertRaisesRegex(ValueError,'fingerprint'):
                M._scan_original_binlog(raw,{'private':self.SECRET},role='app',expected=dict(M.IMPORTS.fingerprint(raw),bytes=1),budget={'bytes':0,'entries':0})
            changed=copy.deepcopy(p);changed['logs']['app']['originalMembers']={}
            with mock.patch.object(M.IMPORTS,'policy',return_value=changed),self.assertRaisesRegex(ValueError,'Unknown'):
                M._scan_original_binlog(raw,{'private':self.SECRET},role='app',expected=M.IMPORTS.fingerprint(raw),budget={'bytes':0,'entries':0})

    def test_private_body_inside_authenticated_import_zip_still_rejects(self):
        raw,p,_,_=self.fixture(secret=self.SECRET)
        with mock.patch.object(M.IMPORTS,'policy',return_value=p),self.assertRaisesRegex(ValueError,'cannot be published'):
            M._scan_original_binlog(raw,{'private':self.SECRET},role='app',expected=M.IMPORTS.fingerprint(raw),budget={'bytes':0,'entries':0})

    def test_binlog_filename_alone_cannot_bypass_generic_publication_guard(self):
        raw,_,_,_=self.fixture()
        with tempfile.TemporaryDirectory()as temp:
            stage=Path(temp)/'private/stage';source=stage/'evidence/output/app.binlog';source.parent.mkdir(parents=True);source.write_bytes(raw)
            target=Path(temp)/'delivery/app'
            with mock.patch.object(M,'_forbidden',return_value={'private':self.SECRET}),self.assertRaisesRegex(ValueError,'Ordinary bounded unencrypted'):
                M._publish_checked_public_tree(stage,target,private_workspace=Path(temp)/'private')
            self.assertFalse(target.exists())

    def test_two_explicit_bound_logs_publish_only_checked_original_buffers(self):
        app,pa,_,_=self.fixture();reader,pr,_,_=self.fixture('reader-build')
        policy=dict(logs={**pa['logs'],**pr['logs']});bindings=dict(kind='scoped-normal-App-original-import-provenance',
            actualOriginalInputsAndProcessesRead=True,logs={role:dict(kind='scoped-actual-original-App-import-bindings',role=role,
                actualMountedInputBytesCompared=True,binlog=M.IMPORTS.fingerprint(raw))for role,raw in [('app',app),('reader-build',reader)]})
        with tempfile.TemporaryDirectory()as temp:
            stage=Path(temp)/'private/stage';stage.mkdir(parents=True);target=Path(temp)/'delivery/app'
            for role,raw in [('app',app),('reader-build',reader)]:
                path=stage/'evidence/output'/(role+'.binlog');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            with mock.patch.object(M.IMPORTS,'policy',return_value=policy),mock.patch.object(M,'_forbidden',return_value={'private':self.SECRET}):
                result=M._publish_checked_public_tree(stage,target,private_workspace=Path(temp)/'private',normal_imports=bindings)
            self.assertEqual((target/'evidence/output/app.binlog').read_bytes(),app)
            self.assertEqual((target/'evidence/output/reader-build.binlog').read_bytes(),reader)
            self.assertTrue(result['deliveryWrittenFromCheckedBuffers'])

    def test_extra_comment_padding_and_local_metadata_fail_before_first_delivery_write(self):
        spec=importlib.util.spec_from_file_location('synthetic_import_metadata_fixture',ROOT/'tests/musl_legacy5_appinsights_imports_test.py')
        wire=importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)
        app,pa,_,bodies=wire.fixture();reader,pr,_,_=wire.fixture('reader-build')
        secret=gzip.compress(self.SECRET);extra=wire.struct.pack('<HH',0xcafe,len(secret))+secret
        def padding(blob):
            offset=wire.struct.unpack_from('<I',blob,len(blob)-6)[0]
            data=bytearray(blob[:offset]+secret+blob[offset:]);wire.struct.pack_into('<I',data,len(data)-6,offset+len(secret));return bytes(data)
        def mismatch(blob):
            data=bytearray(blob);data[30]=ord('X');return bytes(data)
        originals={'\\'+name[1:].replace('/','\\'):body for name,body in bodies.items()}
        mutations=[wire.Wire().finish(originals,entry_extra=extra),wire.Wire().finish(originals,entry_comment=secret),
            wire.replace_archive(app,padding),wire.replace_archive(app,mismatch)]
        for bad in mutations:
            bindings=dict(kind='scoped-normal-App-original-import-provenance',actualOriginalInputsAndProcessesRead=True,
                logs={role:dict(kind='scoped-actual-original-App-import-bindings',role=role,actualMountedInputBytesCompared=True,
                    binlog=M.IMPORTS.fingerprint(raw))for role,raw in [('app',bad),('reader-build',reader)]})
            with tempfile.TemporaryDirectory()as temp:
                stage=Path(temp)/'private/stage';stage.mkdir(parents=True);target=Path(temp)/'delivery/app'
                for role,raw in [('app',bad),('reader-build',reader)]:
                    path=stage/'evidence/output'/(role+'.binlog');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
                with mock.patch.object(M.IMPORTS,'policy',return_value=dict(logs={**pa['logs'],**pr['logs']})),\
                        mock.patch.object(M,'_forbidden',return_value={'private':self.SECRET}),self.assertRaises(ValueError):
                    M._publish_checked_public_tree(stage,target,private_workspace=Path(temp)/'private',normal_imports=bindings)
                self.assertFalse(target.exists());self.assertFalse(target.parent.exists())


if __name__=='__main__':unittest.main()
