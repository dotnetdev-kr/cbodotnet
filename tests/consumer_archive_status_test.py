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
        self.jobs=[dict(name=name,conclusion='success') for name in ['Sign and publish branded consumer archives',
            'Verify public branded consumer archive on native x64','Verify public branded consumer archive on native aarch64']]
        self.artifacts=[]

    def api(self,endpoint,method='GET',body=None):
        self.calls.append((endpoint,method,body))
        if endpoint.endswith('/actions/runs/42'):
            return dict(repository=dict(full_name=STATUS.REPOSITORY),head_repository=dict(full_name=STATUS.REPOSITORY),
                head_branch='main',event='workflow_dispatch',path=STATUS.WORKFLOW,head_sha='a'*40)
        if '/jobs?' in endpoint:return dict(jobs=self.jobs)
        if '/artifacts?' in endpoint:return dict(artifacts=self.artifacts)
        if '/contents/' in endpoint and method=='GET':
            return dict(type='file',path=STATUS.STATUS_PATH,encoding='base64',sha='b'*40,content=base64.b64encode(STATUS.encoded(self.status)).decode())
        if '/contents/' in endpoint and method=='PUT':
            if self.fail_write:raise RuntimeError('SHA lease conflict')
            self.status=json.loads(base64.b64decode(body['content']));return dict(commit=dict(sha='c'*40))
        if endpoint.endswith('pages.yml/dispatches'):return None
        raise AssertionError(endpoint)


class ConsumerArchiveStatusTests(unittest.TestCase):
    def source(self):return dict(repository=STATUS.REPOSITORY,workflow=STATUS.WORKFLOW,commit='a'*40,runId='42',runAttempt='1')

    def reports(self):
        return [dict(architecture=arch,report=dict(orchestration=self.source()),rawJsonSha256='',rawJsonSize=0) for arch in ('x64','aarch64')]

    def test_exact_both_architecture_zip_members_must_match_supplied_raw_reports(self):
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

    def test_repository_write_uses_exact_observed_sha_and_refreshes_pages_only_after_success(self):
        api=Api();receipt=dict(identity=dict(sdkVersion='10.0.403',packageRevision=1))
        activated=dict(schemaVersion=1,repository=STATUS.REPOSITORY,publications=[dict(identity=receipt['identity'],postVerification=dict(reports=[]))])
        with mock.patch.object(STATUS,'activate',return_value=activated),mock.patch.object(STATUS,'verify_artifacts',return_value=[]):
            result=STATUS.update(receipt,self.reports(),'42','1',api=api)
        self.assertEqual('c'*40,result['commit'])
        writes=[body for endpoint,method,body in api.calls if method=='PUT']
        self.assertEqual(1,len(writes));self.assertEqual('b'*40,writes[0]['sha'])
        self.assertTrue(api.calls[-1][0].endswith('pages.yml/dispatches'))
        api=Api();api.fail_write=True
        with mock.patch.object(STATUS,'activate',return_value=copy.deepcopy(activated)),mock.patch.object(STATUS,'verify_artifacts',return_value=[]):
            with self.assertRaisesRegex(RuntimeError,'lease conflict'):STATUS.update(receipt,self.reports(),'42','1',api=api)
        self.assertFalse(any(endpoint.endswith('pages.yml/dispatches') for endpoint,method,body in api.calls))


if __name__=='__main__':unittest.main()
