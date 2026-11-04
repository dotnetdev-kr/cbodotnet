"""Activate consumer availability only after exact native public artifact proof."""
import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile

from consumer_archive import ARCHITECTURES,REPOSITORY,WORKFLOW,encoded,require
from consumer_archive_release import workflow_identity
from consumer_archive_site import authenticate_receipt,archive_rows,load_archive_status,postverified_receipt
from downstream_publish import GitHubReleases

STATUS_PATH='releases/archive-status.json'


def validate_run(api,run_id,attempt):
    require(re.fullmatch(r'[1-9][0-9]*',str(run_id)) and re.fullmatch(r'[1-9][0-9]*',str(attempt)),
        'Exact consumer publication run and attempt required')
    run=api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}')
    require(run and run.get('repository',{}).get('full_name')==run.get('head_repository',{}).get('full_name')==REPOSITORY
        and run.get('head_branch')=='main' and run.get('event')=='workflow_dispatch' and run.get('path')==WORKFLOW,
        'Consumer status requires the trusted main publication workflow')
    jobs=api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')['jobs']
    for name in ['Sign and publish branded consumer archives',*['Verify public branded consumer archive on native '+arch for arch in ARCHITECTURES]]:
        selected=[item for item in jobs if item.get('name')==name]
        require(len(selected)==1 and selected[0].get('conclusion')=='success','Consumer publication or native public verification did not pass: '+name)
    return workflow_identity(dict(repository=REPOSITORY,workflow=WORKFLOW,commit=run['head_sha'],runId=str(run_id),runAttempt=str(attempt)))


def download_artifact(artifact,gh='gh'):
    require(type(artifact.get('id')) is int and artifact['id']>0 and not artifact.get('expired')
        and 0<artifact.get('size_in_bytes',0)<4*1024**2 and re.fullmatch(r'sha256:[a-f0-9]{64}',artifact.get('digest','')),
        'Consumer public report artifact is absent or unbounded')
    with tempfile.TemporaryFile() as output:
        result=subprocess.run([gh,'api',f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'],stdout=output,stderr=subprocess.PIPE,timeout=120)
        require(result.returncode==0,'Consumer public report artifact download failed');output.seek(0);data=output.read(4*1024**2+1)
    require(len(data)==artifact['size_in_bytes'] and 'sha256:'+hashlib.sha256(data).hexdigest()==artifact['digest'],
        'Consumer public artifact differs from its exact API ZIP size/SHA-256')
    return data


def verify_artifacts(api,source,reports,*,fetch_artifact=None,gh='gh'):
    artifacts=api.api(f'repos/{REPOSITORY}/actions/runs/{source["runId"]}/artifacts?per_page=100')['artifacts']
    fetch_artifact=fetch_artifact or (lambda artifact:download_artifact(artifact,gh))
    require(len(reports)==2 and {item['architecture'] for item in reports}==set(ARCHITECTURES),'Both native public consumer reports required')
    proof=[]
    for record in reports:
        arch=record['architecture'];name=f'downstream-archive-postverify-{arch}-{source["runId"]}-{source["runAttempt"]}'
        selected=[item for item in artifacts if item.get('name')==name]
        require(len(selected)==1,'Exact public consumer artifact is missing or ambiguous');artifact=selected[0]
        require(artifact.get('workflow_run',{}).get('head_sha')==source['commit']
            and str(artifact['workflow_run'].get('id'))==source['runId'],'Consumer report artifact belongs to another source run')
        data=fetch_artifact(artifact)
        require(len(data)==artifact['size_in_bytes'] and 'sha256:'+hashlib.sha256(data).hexdigest()==artifact['digest'],
            'Public consumer report ZIP digest changed')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries=archive.infolist()
            require(len(entries)==1 and entries[0].filename=='published-'+arch+'.json' and 0<entries[0].file_size<2*1024**2
                and stat.S_IFMT(entries[0].external_attr>>16) in {0,stat.S_IFREG} and not (entries[0].external_attr>>16)&0o7000,
                'Unexpected public consumer report ZIP member')
            raw=archive.read(entries[0])
        require(raw==encoded(record['report']) and len(raw)==record['rawJsonSize']
            and hashlib.sha256(raw).hexdigest()==record['rawJsonSha256'],'Supplied public consumer report differs from actual workflow artifact bytes')
        proof.append(dict(architecture=arch,id=str(artifact['id']),name=name,zipSha256=artifact['digest'][7:],size=artifact['size_in_bytes'],
            url=f'https://github.com/{REPOSITORY}/actions/runs/{source["runId"]}/artifacts/{artifact["id"]}',exactRawReportBytes='passed'))
    return proof


def activate(status,receipt,reports,*,source=None,policy=None,keyring=None,fetch=None,verifier=None):
    require(status.get('schemaVersion')==1 and status.get('repository')==REPOSITORY and isinstance(status.get('publications'),list),
        'Invalid existing consumer availability status')
    manifest=authenticate_receipt(receipt,policy=policy,keyring=keyring,fetch=fetch)
    record=postverified_receipt(receipt,reports,manifest,source=source)
    result=copy.deepcopy(status);key=lambda item:(item['identity']['sdkVersion'],item['identity']['packageRevision'])
    previous=[item for item in result['publications'] if key(item)==key(record)]
    require(len(previous)<=1,'Existing consumer publication identity is ambiguous')
    if previous:
        immutable=lambda item:{name:value for name,value in item.items() if name!='postVerification'}
        require(immutable(previous[0])==immutable(record),'Consumer SDK/revision conflicts with an immutable published receipt')
    else:result['publications'].append(record)
    result['publications'].sort(key=lambda item:(tuple(map(int,item['identity']['sdkVersion'].split('.'))),item['identity']['packageRevision']))
    (verifier or archive_rows)(status=result,policy=policy,keyring=keyring,fetch=fetch)
    return result


def update(receipt,reports,run_id,attempt,*,gh='gh',api=None,keyring=None,policy=None,fetch=None,fetch_artifact=None):
    api=api or GitHubReleases(gh);source=validate_run(api,run_id,attempt)
    artifacts=verify_artifacts(api,source,reports,fetch_artifact=fetch_artifact,gh=gh)
    content=api.api(f'repos/{REPOSITORY}/contents/{STATUS_PATH}?ref=main')
    require(content and content.get('type')=='file' and content.get('path')==STATUS_PATH and content.get('encoding')=='base64'
        and re.fullmatch(r'[a-f0-9]{40}',content.get('sha','')),'Invalid current consumer status content metadata')
    status=json.loads(base64.b64decode(content['content']))
    for record in reports:
        require(record['report']['orchestration']==source,'Consumer post-verification report source differs from API workflow identity')
    activated=activate(status,receipt,reports,source=source,policy=policy,keyring=keyring,fetch=fetch)
    key=(receipt['identity']['sdkVersion'],receipt['identity']['packageRevision'])
    entry=next(item for item in activated['publications'] if (item['identity']['sdkVersion'],item['identity']['packageRevision'])==key)
    # Preserve the first complete proof on an idempotent frozen-release recheck.
    if entry['postVerification'].get('workflow') is None:
        entry['postVerification'].update(workflow=source,artifacts=artifacts)
    changed=activated!=status;commit=None
    if changed:
        response=api.api(f'repos/{REPOSITORY}/contents/{STATUS_PATH}','PUT',dict(message='Publish verified branded consumer SDK archives',branch='main',
            sha=content['sha'],content=base64.b64encode(encoded(activated)).decode()))
        require(response and re.fullmatch(r'[a-f0-9]{40}',response.get('commit',{}).get('sha','')),'Consumer status commit was not acknowledged')
        commit=response['commit']['sha']
    api.api(f'repos/{REPOSITORY}/actions/workflows/pages.yml/dispatches','POST',dict(ref='main'))
    return dict(status='availability-updated' if changed else 'availability-already-current',commit=commit,
        sdkVersion=receipt['identity']['sdkVersion'],packageRevision=receipt['identity']['packageRevision'],pagesDispatched=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--reports-dir',type=Path,required=True);parser.add_argument('--keyring',type=Path)
    parser.add_argument('--run-id',default=os.environ.get('GITHUB_RUN_ID'));parser.add_argument('--run-attempt',default=os.environ.get('GITHUB_RUN_ATTEMPT','1'))
    parser.add_argument('--write',action='store_true');args=parser.parse_args()
    receipt=json.loads(args.receipt.read_bytes());reports=[]
    for arch in ARCHITECTURES:
        path=args.reports_dir/('published-'+arch+'.json');raw=path.read_bytes();report=json.loads(raw)
        require(encoded(report)==raw,'Public consumer report JSON encoding changed')
        reports.append(dict(architecture=arch,rawJsonSha256=hashlib.sha256(raw).hexdigest(),rawJsonSize=len(raw),report=report))
    result=update(receipt,reports,args.run_id,args.run_attempt,keyring=args.keyring) if args.write else activate(load_archive_status(),receipt,reports,keyring=args.keyring)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
