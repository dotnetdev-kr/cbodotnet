import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_source_audit as M
from musl_release import validate_run


class SourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.run=dict(id=123,run_attempt=1,path=M.PRODUCER_WORKFLOW,head_sha='a'*40,head_branch='main',event='workflow_dispatch',
                      repository=dict(full_name=M.REPOSITORY),head_repository=dict(full_name=M.REPOSITORY),status='completed',conclusion='failure')

    def test_development_origin_never_relaxes_production_success(self):
        self.assertEqual(M.validate_origin(self.run,123,1),'a'*40)
        with self.assertRaises(ValueError):validate_run(self.run,workflow=M.PRODUCER_WORKFLOW,run_id=123,attempt=1)
        for field,value in [('conclusion','success'),('status','in_progress'),('event','pull_request'),('head_branch','feature'),('path',M.WORKFLOW),('run_attempt',2)]:
            with self.subTest(field=field),self.assertRaises(ValueError):M.validate_origin(dict(self.run,**{field:value}),123,1)

    def test_current_audit_can_be_queued_without_relaxing_failed_source_origin(self):
        current=dict(self.run,path=M.WORKFLOW,conclusion=None)
        for status in ['queued','in_progress']:
            run=dict(current,status=status)
            self.assertEqual(M.validate_origin(run,123,1,workflow=M.WORKFLOW,failed=False,commit='a'*40),'a'*40)
            with self.assertRaises(ValueError):M.validate_origin(run,123,1)
        for status,conclusion in [('completed','failure'),('completed','success'),('queued','failure'),('waiting',None)]:
            with self.subTest(status=status,conclusion=conclusion),self.assertRaises(ValueError) as caught:
                M.validate_origin(dict(current,status=status,conclusion=conclusion),123,1,workflow=M.WORKFLOW,failed=False)
            self.assertIn('actual status=',str(caught.exception))
            self.assertEqual(caught.exception.api_context['actualStatus'],status)
            self.assertEqual(caught.exception.api_context['actualConclusion'],conclusion)

    def test_both_failed_real_native_cpu_jobs_required(self):
        jobs=[]
        for i,(arch,label) in enumerate(M.RUNNERS.items()):
            jobs.append(dict(id=i+1,run_id=123,name='Native Alpine 3.24.4 '+arch,head_sha='a'*40,status='completed',conclusion='failure',
                runner_id=i+100,runner_name='GitHub Actions '+str(i+100),runner_group_name='GitHub Actions',labels=[label],
                started_at='2026-11-07T01:00:00Z',completed_at='2026-11-07T02:00:00Z'))
        self.assertEqual(set(M.native_jobs(self.run,jobs)),set(M.RUNNERS))
        for field,value in [('conclusion','success'),('labels',['self-hosted']),('head_sha','b'*40),('runner_name','other')]:
            bad=copy.deepcopy(jobs);bad[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):M.native_jobs(self.run,bad)
        with self.assertRaises(ValueError):M.native_jobs(self.run,jobs[:1])

    def test_current_workflow_permissions_must_be_read_only_without_overrides_or_secrets(self):
        valid=b'name: Audit\npermissions:\n  contents: read\n  actions: read\njobs:\n  audit:\n    runs-on: ubuntu-24.04\n'
        M.workflow_policy(valid)
        for bad in [valid.replace(b'contents: read',b'contents: write'),valid+b'    permissions:\n      packages: write\n',
                    valid+b'    environment: downstream-release\n',valid+b'    env:\n      KEY: ${{ secrets.KEY }}\n',valid.replace(b'  actions: read',b'  packages: read')]:
            with self.subTest(raw=bad),self.assertRaises(ValueError):M.workflow_policy(bad)

    def test_read_only_api_surface_cannot_send_mutations_or_foreign_endpoints(self):
        api=M.ReadOnlyAPI()
        self.assertFalse(hasattr(api,'publish'));self.assertFalse(hasattr(api,'delete'))
        for endpoint in ['repos/other/repo/actions/runs/1','repos/'+M.REPOSITORY+'/../actions','https://api.github.com/x','repos/'+M.REPOSITORY+'/a\nPOST']:
            with self.assertRaises(ValueError):api.endpoint(endpoint)
        with mock.patch.object(M.subprocess,'run',return_value=mock.Mock(stdout=b'{}')) as run:
            api.api('repos/'+M.REPOSITORY+'/actions/runs/123')
        self.assertEqual(run.call_args.args[0][-2:],['--method','GET'])

    def fixture(self,root):
        original=root/'original';original.mkdir()
        files={'reports/prepare/identity.json':dict(diagnosticPtrace=False,projectCommit='a'*40),'producer-sdk.json':dict(projectCommit='a'*40)}
        files.update({'reports/stages/'+x+'.json':dict(stage=x,status='passed') for x in M.STAGES})
        for name,data in files.items():
            p=original/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(data))
        validator=M.sdk_module();rows=[dict(path=p.relative_to(original).as_posix(),**validator.fingerprint(p)) for p in original.rglob('*') if p.is_file()]
        seal=dict(schemaVersion=1,status='passed',kind='musl-sdk-producer-validation',diagnosticPtrace=False,architecture='x64',
            targetRid='linux-musl-x64',libc='musl',projectCommit='a'*40,runId='123',runAttempt='1',allRequiredStages=M.STAGES,files=rows)
        (original/'producer-validation.json').write_text(json.dumps(seal))
        extra=original/'reports/diagnostics/unqualified-sdk/x.tar.gz';extra.parent.mkdir(parents=True);extra.write_bytes(b'unqualified extra')
        return original,seal

    def test_sealed_subset_preserves_original_excludes_postfailure_extras_and_closes_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);original,seal=self.fixture(root);before={p.relative_to(original).as_posix():p.read_bytes() for p in original.rglob('*') if p.is_file()}
            subset,proof=M.sealed_subset(original,root/'subset',self.run,'x64')
            self.assertEqual(proof['excludedFileCount'],1);self.assertFalse((subset/'reports/diagnostics').exists())
            self.assertEqual((subset/'producer-validation.json').read_bytes(),(original/'producer-validation.json').read_bytes())
            self.assertEqual(before,{p.relative_to(original).as_posix():p.read_bytes() for p in original.rglob('*') if p.is_file()})
            M.sdk_module().delivery_index(subset,seal['files'])

    def test_subset_rejects_changed_missing_duplicate_or_escaping_declared_bytes(self):
        for mutation in ['changed','missing','duplicate','escape','diagnostic','project','failedstage']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);original,seal=self.fixture(root)
                if mutation=='changed':(original/'producer-sdk.json').write_text('{}')
                elif mutation=='missing':(original/'producer-sdk.json').unlink()
                elif mutation=='duplicate':seal['files'].append(seal['files'][0])
                elif mutation=='escape':seal['files'][0]['path']='../escape'
                elif mutation=='diagnostic':seal['diagnosticPtrace']=True
                elif mutation=='project':seal['projectCommit']='b'*40
                elif mutation=='failedstage':
                    p=original/'reports/stages/test.json';p.write_text(json.dumps(dict(stage='test',status='failed')))
                    next(x for x in seal['files'] if x['path']=='reports/stages/test.json').update(M.sdk_module().fingerprint(p))
                (original/'producer-validation.json').write_text(json.dumps(seal))
                with self.assertRaises((ValueError,OSError)):M.sealed_subset(original,root/'subset',self.run,'x64')

    def test_subset_rejects_symlink_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);original,seal=self.fixture(root)
            p=original/'producer-sdk.json';body=p.read_bytes();p.unlink();external=root/'external.json';external.write_bytes(body);p.symlink_to(external)
            with self.assertRaises(ValueError):M.sealed_subset(original,root/'subset',self.run,'x64')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);original,seal=self.fixture(root);p=original/'producer-validation.json';p.write_text('{"status":"passed","status":"passed"}')
            with self.assertRaises(ValueError):M.sealed_subset(original,root/'subset',self.run,'x64')

    def test_bounded_listing_rejects_runaway_or_malformed_pages(self):
        api=mock.Mock();api.api.return_value=dict(jobs=[{}]*100)
        with self.assertRaisesRegex(ValueError,'ten pages'):M.pages(api,'repos/'+M.REPOSITORY+'/x','jobs')
        self.assertEqual(api.api.call_count,10)
        api.api.return_value={}
        with self.assertRaises(ValueError):M.pages(api,'repos/'+M.REPOSITORY+'/x','jobs')

    def test_early_failures_are_reported_without_overwriting_complete_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'result.json';args=SimpleNamespace(arch='x64',run_id=123,attempt=1)
            M.failure_report(output,args,ValueError('Actual API origin rejected'))
            data=json.loads(output.read_text());self.assertEqual(data['status'],'dev-only-fail')
            self.assertIs(data['sourceAdmission'],False);self.assertIs(data['productionQualification'],False)
            self.assertIs(data['originValidationCompleted'],False)
            self.assertEqual(data['error']['reason'],'Actual API origin rejected')
            before=output.read_bytes();M.failure_report(output,args,ValueError('later'))
            self.assertEqual(output.read_bytes(),before)

    def test_current_lifecycle_failure_report_preserves_actual_api_state(self):
        run=dict(self.run,path=M.WORKFLOW,status='waiting',conclusion=None)
        with self.assertRaises(ValueError) as caught:
            M.validate_origin(run,123,1,workflow=M.WORKFLOW,failed=False)
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'result.json';args=SimpleNamespace(arch='x64',run_id=123,attempt=1)
            M.failure_report(output,args,caught.exception)
            data=json.loads(output.read_text())
            self.assertEqual(data['apiContext']['actualRun'],run)
            self.assertEqual(data['apiContext']['actualStatus'],'waiting')
            self.assertIsNone(data['apiContext']['actualConclusion'])
            self.assertEqual(data['apiContext']['role'],'current-audit')


if __name__=='__main__':unittest.main()
