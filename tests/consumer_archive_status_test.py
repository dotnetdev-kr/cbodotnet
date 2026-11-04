"""Status activation checks both actual public ZIPs and uses a content-SHA lease."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive_status as STATUS


class Api:
    def __init__(self):
        self.calls=[];self.fail_write=False
        self.status=dict(schemaVersion=1,repository=STATUS.REPOSITORY,publications=[])
        self.run=dict(id=42,run_attempt=1,status='in_progress',conclusion=None,
            repository=dict(full_name=STATUS.REPOSITORY),head_repository=dict(full_name=STATUS.REPOSITORY),
            head_branch='main',event='workflow_dispatch',path=STATUS.WORKFLOW,head_sha='a'*40)
        self.jobs=[dict(name=name,status='completed',conclusion='success',run_id=42,run_attempt=1,head_sha='a'*40) for name in ['Sign and publish branded consumer archives',
            'Verify public branded consumer archive on native x64','Verify public branded consumer archive on native aarch64']]
        self.artifacts=[];self.run_responses=[];self.job_responses=[];self.artifact_responses=[]

    def api(self,endpoint,method='GET',body=None):
        self.calls.append((endpoint,method,body))
        if endpoint.endswith('/actions/runs/42'):
            return self.run_responses.pop(0) if self.run_responses else self.run
        if '/jobs?' in endpoint:return dict(jobs=self.job_responses.pop(0) if self.job_responses else self.jobs)
        if '/artifacts?' in endpoint:return dict(artifacts=self.artifact_responses.pop(0) if self.artifact_responses else self.artifacts)
        if '/contents/' in endpoint and method=='GET':
            raw=STATUS.encoded(self.status)
            return dict(type='file',path=STATUS.STATUS_PATH,encoding='base64',size=len(raw),
                sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),content=base64.b64encode(raw).decode())
        if '/contents/' in endpoint and method=='PUT':
            if self.fail_write:raise RuntimeError('SHA lease conflict')
            self.status=json.loads(base64.b64decode(body['content']));return dict(commit=dict(sha='c'*40))
        if endpoint.endswith('pages.yml/dispatches'):return None
        raise AssertionError(endpoint)


class ConsumerArchiveStatusTests(unittest.TestCase):
    def source(self):return dict(repository=STATUS.REPOSITORY,workflow=STATUS.WORKFLOW,commit='a'*40,runId='42',runAttempt='1')

    def reports(self):
        return [dict(architecture=arch,report=dict(orchestration=self.source()),rawJsonSha256='',rawJsonSize=0) for arch in ('x64','aarch64')]

    def artifact_fixture(self):
        api=Api();reports=self.reports();data={}
        for index,record in enumerate(reports,1):
            arch=record['architecture'];raw=STATUS.encoded(record['report'])
            record.update(rawJsonSha256=hashlib.sha256(raw).hexdigest(),rawJsonSize=len(raw))
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w') as zip:zip.writestr('published-'+arch+'.json',raw)
            data[index]=buffer.getvalue()
            api.artifacts.append(dict(id=index,name='downstream-archive-postverify-'+arch+'-42-1',expired=False,
                size_in_bytes=len(data[index]),digest='sha256:'+hashlib.sha256(data[index]).hexdigest(),
                workflow_run=dict(id=42,head_sha='a'*40)))
        return api,reports,data

    def test_exact_both_architecture_zip_members_must_match_supplied_raw_reports(self):
        api,reports,data=self.artifact_fixture()
        proof=STATUS.verify_artifacts(api,self.source(),reports,fetch_artifact=lambda artifact:data[artifact['id']])
        self.assertEqual({'x64','aarch64'},{item['architecture'] for item in proof})
        changed=copy.deepcopy(reports);changed[1]['report']['forged']=True
        changed[1]['rawJsonSize']=len(STATUS.encoded(changed[1]['report']))
        changed[1]['rawJsonSha256']=hashlib.sha256(STATUS.encoded(changed[1]['report'])).hexdigest()
        with self.assertRaisesRegex(ValueError,'actual workflow artifact'):
            STATUS.verify_artifacts(api,self.source(),changed,fetch_artifact=lambda artifact:data[artifact['id']])
        with self.assertRaisesRegex(ValueError,'ZIP digest'):
            STATUS.verify_artifacts(api,self.source(),reports,fetch_artifact=lambda artifact:data[artifact['id']]+b'changed')

    def test_failed_public_job_prevents_status_activation(self):
        api=Api();self.assertEqual(self.source(),STATUS.validate_run(api,'42','1'))
        api.jobs[-1]['conclusion']='failure'
        with self.assertRaisesRegex(ValueError,'did not pass'):STATUS.validate_run(api,'42','1')
        self.assertFalse(any(method=='PUT' for endpoint,method,body in api.calls))

    def test_null_job_conclusion_retries_until_actual_success_not_successful_steps(self):
        api=Api();pending=copy.deepcopy(api.jobs)
        pending[1].update(status='in_progress',conclusion=None,steps=[dict(name='Complete job',status='completed',conclusion='success')])
        api.job_responses=[pending];sleep=mock.Mock()
        self.assertEqual(self.source(),STATUS.validate_run(api,'42','1',retry_delays=(2,),sleep=sleep))
        sleep.assert_called_once_with(2)
        self.assertEqual(2,sum('/jobs?' in endpoint for endpoint,method,body in api.calls))

    def test_missing_jobs_retry_but_persistent_null_conclusion_reaches_deadline(self):
        api=Api();api.job_responses=[api.jobs[:1]];sleep=mock.Mock()
        self.assertEqual(self.source(),STATUS.validate_run(api,'42','1',retry_delays=(2,),sleep=sleep))
        sleep.assert_called_once_with(2)
        api=Api();api.jobs[1].update(status='in_progress',conclusion=None);sleep=mock.Mock()
        with self.assertRaisesRegex(ValueError,'consistency deadline'):
            STATUS.validate_run(api,'42','1',retry_delays=(2,4),sleep=sleep)
        self.assertEqual([mock.call(2),mock.call(4)],sleep.call_args_list)
        self.assertFalse(any(method=='PUT' for endpoint,method,body in api.calls))

    def test_default_pending_budget_is_finite_and_each_wait_is_at_most_twenty_seconds(self):
        api=Api();api.jobs[1].update(status='in_progress',conclusion=None);sleep=mock.Mock()
        with self.assertRaisesRegex(ValueError,'consistency deadline'):
            STATUS.validate_run(api,'42','1',sleep=sleep)
        self.assertEqual(1500,sum(call.args[0] for call in sleep.call_args_list))
        self.assertLessEqual(max(call.args[0] for call in sleep.call_args_list),20)
        for delays in ((21,), (20,)*76, (-1,), (True,)):
            api=Api();sleep=mock.Mock()
            with self.subTest(delays=delays),self.assertRaisesRegex(ValueError,'bounded to 25 minutes'):
                STATUS.validate_run(api,'42','1',retry_delays=delays,sleep=sleep)
            self.assertEqual([],api.calls);sleep.assert_not_called()

    def test_job_and_artifact_waits_share_one_elapsed_budget_during_update(self):
        api=Api();pending=copy.deepcopy(api.jobs);pending[1].update(status='in_progress',conclusion=None)
        api.job_responses=[pending];clock=[0];original=api.api;first=[True]
        def call(endpoint,method='GET',body=None):
            if '/jobs?' in endpoint and first[0]:clock[0]=1490;first[0]=False
            return original(endpoint,method,body)
        api.api=call
        def sleep(seconds):clock[0]+=seconds
        with mock.patch.object(STATUS.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(STATUS.time,'sleep',side_effect=sleep):
            with self.assertRaisesRegex(ValueError,'artifact.*consistency deadline'):
                STATUS.update({},self.reports(),'42','1',api=api)
        self.assertEqual(1498,clock[0])
        self.assertFalse(any(method=='PUT' for endpoint,method,body in api.calls))

    def test_terminal_job_failures_and_duplicate_jobs_never_retry(self):
        for conclusion in ('failure','cancelled','timed_out','skipped','neutral'):
            with self.subTest(conclusion=conclusion):
                api=Api();api.jobs[1]['conclusion']=conclusion;sleep=mock.Mock()
                with self.assertRaisesRegex(ValueError,'did not pass'):STATUS.validate_run(api,'42','1',sleep=sleep)
                sleep.assert_not_called()
        api=Api();api.jobs.append(copy.deepcopy(api.jobs[1]));sleep=mock.Mock()
        with self.assertRaisesRegex(ValueError,'ambiguous'):STATUS.validate_run(api,'42','1',sleep=sleep)
        sleep.assert_not_called()

    def test_run_and_job_provenance_mismatches_never_retry(self):
        for field,value in [('repository',dict(full_name='foreign/repository')),('head_branch','feature'),
                ('event','pull_request'),('path','other.yml'),('id',43),('run_attempt',2),('head_sha','invalid')]:
            with self.subTest(field=field):
                api=Api();api.run[field]=value;sleep=mock.Mock()
                with self.assertRaisesRegex(ValueError,'trusted main'):STATUS.validate_run(api,'42','1',sleep=sleep)
                sleep.assert_not_called()
        api=Api();api.jobs[1]['head_sha']='b'*40;sleep=mock.Mock()
        with self.assertRaisesRegex(ValueError,'another source run'):STATUS.validate_run(api,'42','1',sleep=sleep)
        sleep.assert_not_called()
        api=Api();api.jobs[1].update(status='in_progress',conclusion=None)
        changed=copy.deepcopy(api.run);changed['head_sha']='b'*40;api.run_responses=[api.run,changed];sleep=mock.Mock()
        with self.assertRaisesRegex(ValueError,'identity changed'):
            STATUS.validate_run(api,'42','1',retry_delays=(2,),sleep=sleep)
        sleep.assert_called_once_with(2)

    def test_missing_or_pending_digest_artifacts_require_complete_api_and_exact_zip_proof(self):
        api,reports,data=self.artifact_fixture();pending=copy.deepcopy(api.artifacts)
        pending[0]['digest']=None;api.artifact_responses=[[],pending];sleep=mock.Mock()
        fetched=[]
        def fetch(artifact):
            fetched.append(artifact['id']);return data[artifact['id']]
        proof=STATUS.verify_artifacts(api,self.source(),reports,fetch_artifact=fetch,retry_delays=(2,4),sleep=sleep)
        self.assertEqual(2,len(proof));self.assertEqual([1,2],fetched)
        self.assertEqual([mock.call(2),mock.call(4)],sleep.call_args_list)
        api.artifacts[0]['digest']=None;sleep=mock.Mock();fetch=mock.Mock()
        with self.assertRaisesRegex(ValueError,'consistency deadline'):
            STATUS.verify_artifacts(api,self.source(),reports,fetch_artifact=fetch,retry_delays=(2,),sleep=sleep)
        sleep.assert_called_once_with(2);fetch.assert_not_called()

    def test_artifact_duplicates_bad_provenance_and_malformed_digest_fail_without_retry(self):
        for failure in ('duplicate','head','digest','expired','size'):
            with self.subTest(failure=failure):
                api,reports,data=self.artifact_fixture();sleep=mock.Mock();fetch=mock.Mock()
                if failure=='duplicate':api.artifacts.append(copy.deepcopy(api.artifacts[0]))
                elif failure=='head':api.artifacts[0]['workflow_run']['head_sha']='b'*40
                elif failure=='digest':api.artifacts[0]['digest']='sha256:invalid'
                elif failure=='expired':api.artifacts[0]['expired']=True
                else:api.artifacts[0]['size_in_bytes']=0
                with self.assertRaises(ValueError):
                    STATUS.verify_artifacts(api,self.source(),reports,fetch_artifact=fetch,sleep=sleep)
                sleep.assert_not_called();fetch.assert_not_called()

    def test_repository_write_uses_exact_observed_sha_and_refreshes_pages_only_after_success(self):
        api=Api();receipt=dict(identity=dict(sdkVersion='10.0.403',packageRevision=1))
        activated=dict(schemaVersion=1,repository=STATUS.REPOSITORY,publications=[dict(identity=receipt['identity'],postVerification=dict(reports=[]))])
        with mock.patch.object(STATUS,'activate',return_value=activated),mock.patch.object(STATUS,'verify_artifacts',return_value=[]):
            result=STATUS.update(receipt,self.reports(),'42','1',api=api)
        self.assertEqual('c'*40,result['commit'])
        writes=[body for endpoint,method,body in api.calls if method=='PUT']
        raw=STATUS.encoded(dict(schemaVersion=1,repository=STATUS.REPOSITORY,publications=[]))
        self.assertEqual(1,len(writes));self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),writes[0]['sha'])
        self.assertTrue(api.calls[-1][0].endswith('pages.yml/dispatches'))
        api=Api();api.fail_write=True
        with mock.patch.object(STATUS,'activate',return_value=copy.deepcopy(activated)),mock.patch.object(STATUS,'verify_artifacts',return_value=[]):
            with self.assertRaisesRegex(RuntimeError,'lease conflict'):STATUS.update(receipt,self.reports(),'42','1',api=api)
        self.assertFalse(any(endpoint.endswith('pages.yml/dispatches') for endpoint,method,body in api.calls))


if __name__=='__main__':unittest.main()
