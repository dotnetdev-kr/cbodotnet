"""Tiny task-derived fixtures; these never establish a genuine normal producer."""
import copy,io,json,os
from pathlib import Path
import struct,sys,tempfile,unittest,zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_capture as C


class TinyTaskDerivedFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sdk5-app-capture-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.sdk=self.root/'sdk';self.feed=self.root/'feed'
        self.release=self.root/'release';self.app=self.root/'app';self.other=self.root/'other-source';self.destination=self.root/'captured'
        for p in(self.sdk,self.feed,self.release,self.app,self.other):p.mkdir()
        self.product=b'tiny task-derived new local product; not actual App evidence'
        self.package=self.npk(self.product);self.package_pin=C.fingerprint(self.package);self.product_pin=C.fingerprint(self.product)
        self.cache=self.sdk/'.packages'/C.M.ID.lower()/C.M.VERSION
        self.put(self.cache/C.M.PACKAGE,self.package);self.put(self.cache/C.M.MEMBER,self.product);self.put(self.feed/C.M.PACKAGE,self.package)
        import base64
        content=base64.b64encode(bytes.fromhex(self.package_pin['sha512'])).decode()
        self.metadata={'source':'/work/inputs/bootstrap-feed','contentHash':content,'version':2}
        self.put(self.cache/'.nupkg.metadata',json.dumps(self.metadata).encode());self.put(self.cache/(C.M.PACKAGE+'.sha512'),content.encode())
        cache=C.MOUNT+'/.packages/'+C.M.ID.lower()+'/'+C.M.VERSION+'/'+C.M.MEMBER
        cli=C.MOUNT+'/artifacts/bin/dotnet/Release/net5.0/Microsoft.ApplicationInsights.dll'
        redist=C.MOUNT+'/artifacts/bin/redist/Release/net5.0/Microsoft.ApplicationInsights.dll'
        layout=C.MOUNT+'/artifacts/bin/redist/Release/layouts/dotnet-toolset-internal/Microsoft.ApplicationInsights.dll'
        final=C.MOUNT+'/artifacts/bin/redist/Release/dotnet//sdk/5.0.214-ci/Microsoft.ApplicationInsights.dll'
        edges=[(cache,cli),(cache,redist),(redist,layout),(redist,final)]
        for edge in edges:
            for value in edge:self.put(self.sdk/C._logical(value),self.product)
        self.validated=dict(kind='sdk5-genuine-local-App-actual-sdk-consumption',package=self.package_pin,product=self.product_pin,
            cache=dict(originalNugetMetadata=self.metadata),toolset={'path':'already-retained-toolset.zip'},
            sdkConsumers=[dict(replayName=name,actualCscContexts=['fixture-'+name],actualCopies=[
                dict(context=name+'-'+str(i),source=a,destination=b)for i,(a,b)in enumerate(edges)])for name in('sdk','redist')],
            normalSourceWorkerEnvelopeValidatedByThisPart=True,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
        self.compiler={'replays':[{'name':'sdk'},{'name':'redist'}]};raw=json.dumps(self.compiler).encode();self.put(self.release/'compiler.json',raw)
        self.proof={'componentCompilerProofs':{'sdk':dict(path='compiler.json',**C.fingerprint(raw))},'sdkArchive':{'path':'already-retained-final.tar.gz'}}
        original=self.npk(b'original comparison fixture, never a local product');self.forbidden={'original.nupkg':original,
            'comparison-publisher-dll':b'original comparison fixture, never a local product','private-reference':b'private reference fixture body'}
        self.private=dict(privateInputFiles={k:C.fingerprint(v)for k,v in self.forbidden.items()if k!='comparison-publisher-dll'},
            inputManifest={'fixture':True},fullPrivateInputCount=522)
        self.args=dict(app_workspace=self.app,app_host_roots={},sdk_source=self.sdk,feed=self.feed,normal_context={'fixtureOnly':True},destination=self.destination)

    @staticmethod
    def npk(product,extra=None):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED)as archive:
            archive.writestr(C.M.MEMBER,product)
            if extra is not None:archive.writestr('hidden.bin',extra)
        return buffer.getvalue()

    @staticmethod
    def put(path,raw):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)

    def run_capture(self,**kwargs):
        args=dict(self.args,**kwargs)
        with patch.object(C.M,'validate',return_value=self.validated)as validator,patch.object(C.R,'verify_private_inputs',return_value=self.private),\
                patch.object(C.R,'_forbidden',return_value=self.forbidden):
            result=C.capture(self.release,{},self.proof,{'other':{'path':str(self.other)}},{},**args)
            validator.assert_called_once();self.assertEqual(validator.call_args.kwargs['normal_context'],args['normal_context'])
            return result

    @unittest.skipIf(os.name=='nt','POSIX data0644 publication')
    def test_checked_capture_retains_nine_paths_and_original_double_slash(self):
        result=self.run_capture();self.assertEqual(result['logicalPaths'],9);self.assertEqual(result['contentFiles'],4)
        checked=C.validate_data(self.destination);self.assertTrue(checked['retainedDataBytesValidated']);self.assertFalse(checked['actualNormalExecutionRevalidated'])
        index=json.loads((self.destination/'capture-index.json').read_bytes())
        self.assertIn('/work/work/sdk/artifacts/bin/redist/Release/dotnet//sdk/5.0.214-ci/Microsoft.ApplicationInsights.dll',index['originalLogicalPaths'])
        self.assertTrue(index['rawNugetSidecarFingerprintsAreNewCaptureObservations']);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_explicit_normal_is_required_before_supplier(self):
        with patch.object(C.M,'validate',side_effect=AssertionError('must not call private fallback')):
            with self.assertRaisesRegex(ValueError,'Explicit genuine normal'):self.run_capture(normal_context=None)
        self.assertFalse(self.destination.exists())

    def test_actual_normal_validation_failure_stops_before_capture(self):
        with patch.object(C.M,'validate',side_effect=ValueError('actual normal rejection')):
            with self.assertRaisesRegex(ValueError,'actual normal rejection'):
                C.capture(self.release,{},self.proof,{}, {},**self.args)
        self.assertFalse(self.destination.exists())

    def test_private_supplier_scope_is_not_accepted(self):
        self.validated['normalSourceWorkerEnvelopeValidatedByThisPart']=False
        with self.assertRaisesRegex(ValueError,'strict normal'):self.run_capture()

    def test_other_collected_source_destination_rejects_before_validator(self):
        with self.assertRaisesRegex(ValueError,'separate'):self.run_capture(destination=self.other/'poisoned')
        self.assertFalse((self.other/'poisoned').exists())

    def test_source_and_report_ancestor_destinations_reject(self):
        for dest in(self.root,self.sdk/'data',self.release/'data',self.feed/'data',self.app/'data'):
            with self.subTest(dest=dest),self.assertRaises(ValueError):self.run_capture(destination=dest)

    def test_changed_cache_or_feed_bytes_reject(self):
        for path in(self.cache/C.M.PACKAGE,self.feed/C.M.PACKAGE):
            old=path.read_bytes();path.write_bytes(b'changed same package ID')
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'capture bytes differ'):self.run_capture()
            path.write_bytes(old)
        self.assertFalse(self.destination.exists())

    def test_changed_copy_destination_rejects(self):
        logical=self.validated['sdkConsumers'][0]['actualCopies'][0]['destination'];self.put(self.sdk/C._logical(logical),b'changed copied DLL')
        with self.assertRaisesRegex(ValueError,'capture bytes differ'):self.run_capture()

    def test_missing_copy_edge_or_second_process_rejects(self):
        self.validated['sdkConsumers'][1]['actualCopies'].pop()
        with self.assertRaisesRegex(ValueError,'four actually'):self.run_capture()
        self.validated['sdkConsumers'].pop()
        with self.assertRaisesRegex(ValueError,'Two original'):self.run_capture()

    def test_unbound_path_alias_and_traversal_reject(self):
        for value in('/work/work/sdk/../escape','/work/work/sdk/./file','/work/work/sdk/a//b','/other/root/file'):
            with self.subTest(value=value),self.assertRaises(ValueError):C._logical(value)

    def test_metadata_mismatch_and_duplicate_key_reject(self):
        path=self.cache/'.nupkg.metadata';path.write_bytes(b'{"source":"changed"}')
        with self.assertRaisesRegex(ValueError,'metadata/hash'):self.run_capture()
        path.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError,'Duplicate'):self.run_capture()

    def test_actual_sha512_sidecar_mismatch_reject(self):
        (self.cache/(C.M.PACKAGE+'.sha512')).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'metadata/hash'):self.run_capture()

    def test_per_file_and_total_publication_bounds_reject(self):
        with patch.object(C,'MAX_FILE',16):
            with self.assertRaisesRegex(ValueError,'Bounded actual capture'):self.run_capture()
        with patch.object(C,'MAX_TOTAL',16):
            with self.assertRaisesRegex(ValueError,'budget exceeded'):self.run_capture()

    @unittest.skipIf(os.name=='nt','POSIX symlink and FIFO')
    def test_special_or_redirected_cache_file_rejects_without_open(self):
        path=self.cache/C.M.PACKAGE;path.unlink();path.symlink_to(self.feed/C.M.PACKAGE)
        with self.assertRaisesRegex(ValueError,'unredirected'):self.run_capture()
        path.unlink();os.mkfifo(path)
        with self.assertRaisesRegex(ValueError,'Ordinary capture'):self.run_capture()

    def test_nested_private_body_rejects_before_destination(self):
        bad=self.npk(self.product,extra=self.forbidden['private-reference']);pin=C.fingerprint(bad)
        self.put(self.cache/C.M.PACKAGE,bad);self.put(self.feed/C.M.PACKAGE,bad);self.validated['package']=pin
        import base64
        content=base64.b64encode(bytes.fromhex(pin['sha512'])).decode();self.metadata['contentHash']=content
        self.put(self.cache/'.nupkg.metadata',json.dumps(self.metadata).encode());self.put(self.cache/(C.M.PACKAGE+'.sha512'),content.encode())
        with self.assertRaisesRegex(ValueError,'Private reference'):self.run_capture()
        self.assertFalse(self.destination.exists())

    def test_changed_original_input_during_scan_rejects(self):
        scan=C.R.scan_content
        def changed(*args,**kwargs):
            result=scan(*args,**kwargs);(self.cache/C.M.PACKAGE).write_bytes(b'late changed');return result
        with patch.object(C.R,'scan_content',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'changed before publication'):self.run_capture()
        self.assertFalse(self.destination.exists())

    def test_changed_exclusion_body_rejects(self):
        self.forbidden['private-reference']=b'different private reference'
        with self.assertRaisesRegex(ValueError,'private exclusion body changed'):self.run_capture()

    def test_changed_private_manifest_after_scan_rejects(self):
        count=0
        def changed(_):
            nonlocal count
            count+=1;result=copy.deepcopy(self.private)
            if count>1:result['inputManifest']={'changed':True}
            return result
        with patch.object(C.M,'validate',return_value=self.validated),patch.object(C.R,'verify_private_inputs',side_effect=changed),patch.object(C.R,'_forbidden',return_value=self.forbidden):
            with self.assertRaisesRegex(ValueError,'private inputs changed'):C.capture(self.release,{},self.proof,{}, {},**self.args)
        self.assertFalse(self.destination.exists())

    def test_changed_validator_code_rejects_before_publication(self):
        with patch.object(C,'code_pins',side_effect=[{'fixture':'before'},{'fixture':'after'}]):
            with self.assertRaisesRegex(ValueError,'validator code changed'):self.run_capture()
        self.assertFalse(self.destination.exists())

    def test_actual_captured_npk_member_and_product_must_agree(self):
        with self.assertRaisesRegex(ValueError,'package member must equal'):
            C._package_product(self.npk(bytes([self.product[0]^1])+self.product[1:]),self.product_pin)

    def test_package_entry_count_bound_is_checked_before_zip_allocation(self):
        raw=bytearray(self.package);struct.pack_into('<HH',raw,len(raw)-14,65535,65535)
        with patch.object(C.zipfile,'ZipFile',side_effect=AssertionError('Must reject before directory allocation')):
            with self.assertRaisesRegex(ValueError,'Bounded single-disk'):C._package_product(bytes(raw),self.product_pin)

    def test_forged_small_count_cannot_hide_more_central_entries_before_zip_allocation(self):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w')as archive:
            archive.writestr(C.M.MEMBER,self.product)
            for number in range(16):archive.writestr('other-'+str(number),b'x')
        raw=bytearray(buffer.getvalue());struct.pack_into('<HH',raw,len(raw)-14,1,1)
        with patch.object(C.zipfile,'ZipFile',side_effect=AssertionError('Must reject before directory allocation')):
            with self.assertRaisesRegex(ValueError,'directory count'):C._package_product(bytes(raw),self.product_pin)

    def test_truncated_central_name_rejects_before_zip_allocation(self):
        raw=bytearray(self.package);offset=struct.unpack_from('<I',raw,len(raw)-6)[0]
        struct.pack_into('<H',raw,offset+28,65535)
        with patch.object(C.zipfile,'ZipFile',side_effect=AssertionError('Must reject before directory allocation')):
            with self.assertRaisesRegex(ValueError,'central entry'):C._package_product(bytes(raw),self.product_pin)

    def test_redirected_central_product_rejects_before_zip_allocation(self):
        raw=bytearray(self.package);offset=struct.unpack_from('<I',raw,len(raw)-6)[0]
        struct.pack_into('<I',raw,offset+38,0o120777<<16)
        with patch.object(C.zipfile,'ZipFile',side_effect=AssertionError('Must reject before directory allocation')):
            with self.assertRaisesRegex(ValueError,'ordinary captured'):C._package_product(bytes(raw),self.product_pin)

    @unittest.skipIf(os.name=='nt','POSIX retained-data counterexample')
    def test_self_consistent_package_and_sidecar_rebinding_cannot_hide_different_member(self):
        self.run_capture();path=self.destination/'capture-index.json';index=json.loads(path.read_bytes())
        changed=bytes([self.product[0]^1])+self.product[1:];package=self.npk(changed);package_pin=C.fingerprint(package)
        import base64
        content=base64.b64encode(bytes.fromhex(package_pin['sha512'])).decode()
        metadata=dict(self.metadata,contentHash=content)
        def rebind(logicals,raw):
            pin=C.fingerprint(raw);member='content/'+pin['sha256'];self.put(self.destination/member,raw)
            prior=set()
            for logical in logicals:
                row=index['originalLogicalPaths'][logical];prior.add(row['member']);row.update(member=member,**pin)
            used={r['member']for r in index['originalLogicalPaths'].values()}
            for old in prior-used:(self.destination/old).unlink()
        prefix=C.MOUNT+'/.packages/'+C.M.ID.lower()+'/'+C.M.VERSION+'/'
        rebind([prefix+C.M.PACKAGE,'/work/inputs/bootstrap-feed/'+C.M.PACKAGE],package)
        rebind([prefix+'.nupkg.metadata'],json.dumps(metadata).encode());rebind([prefix+C.M.PACKAGE+'.sha512'],content.encode())
        index['actualNormalConsumption']['package']=package_pin;index['actualNormalConsumption']['cache']['originalNugetMetadata']=metadata
        path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError,'package member must equal'):C.validate_data(self.destination)

    @unittest.skipIf(os.name=='nt','POSIX checked-buffer publication')
    def test_publication_does_not_reopen_original_files_after_final_check(self):
        original=Path.mkdir
        def changed(path,*args,**kwargs):
            if path==self.destination:(self.cache/C.M.PACKAGE).write_bytes(b'changed after all input checks')
            return original(path,*args,**kwargs)
        with patch.object(Path,'mkdir',new=changed):self.run_capture()
        checked=C.validate_data(self.destination);self.assertTrue(checked['retainedDataBytesValidated'])
        self.assertNotEqual((self.cache/C.M.PACKAGE).read_bytes(),self.package)
        self.assertEqual((self.destination/'content'/self.package_pin['sha256']).read_bytes(),self.package)

    @unittest.skipIf(os.name=='nt','POSIX data0644 replay')
    def test_altered_data_or_omitted_mapping_rejects(self):
        self.run_capture();index_path=self.destination/'capture-index.json';index=json.loads(index_path.read_bytes())
        first=next(iter(index['originalLogicalPaths']));index['originalLogicalPaths'].pop(first);index_path.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError,'inventory|mappings'):C.validate_data(self.destination)

    @unittest.skipIf(os.name=='nt','POSIX data0644 replay')
    def test_extra_file_and_altered_content_reject(self):
        self.run_capture();extra=self.destination/'extra.bin';extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'inventory'):C.validate_data(self.destination)
        extra.unlink();p=next((self.destination/'content').iterdir());p.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'bytes differ'):C.validate_data(self.destination)


if __name__=='__main__':unittest.main()
