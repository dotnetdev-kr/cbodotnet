"""Protected consumer archive staging and recovery of exact frozen signatures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

from consumer_archive import ROOT,REPOSITORY,WORKFLOW,encoded,fresh_directory,ordinary_file,require,sdk_tools
from consumer_archive_ci import run
from consumer_archive_release import create_bundle,publish_bundle,validate_bundle

PUBLISH_JOB='Sign and publish branded consumer archives'
FREEZE_STEP='Freeze signed consumer archive bytes before publication'


def protected():
    require(os.environ.get('GITHUB_REPOSITORY')==REPOSITORY and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and os.environ.get('GITHUB_WORKFLOW_REF')==REPOSITORY+'/'+WORKFLOW+'@refs/heads/main',
        'Only the approved protected main distribution workflow may sign or publish consumer archives')


def source_identity(run_id,attempt):
    require(re.fullmatch(r'[1-9][0-9]*',str(run_id)) and re.fullmatch(r'[1-9][0-9]*',str(attempt)),
        'Exact native source run and attempt required')
    metadata=json.loads(run(['gh','api',f'repos/{REPOSITORY}/actions/runs/{run_id}']))
    require(metadata.get('repository',{}).get('full_name')==metadata.get('head_repository',{}).get('full_name')==REPOSITORY
        and metadata.get('head_branch')=='main' and metadata.get('event')=='workflow_dispatch' and metadata.get('path')==WORKFLOW
        and re.fullmatch(r'[a-f0-9]{40}',metadata.get('head_sha','')),'Consumer native source must be a trusted main workflow run')
    jobs=json.loads(run(['gh','api',f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100']))['jobs']
    for arch in ('x64','aarch64'):
        selected=[item for item in jobs if item.get('name')=='Build branded consumer archive on native '+arch]
        require(len(selected)==1 and selected[0].get('conclusion')=='success'
            and any(step.get('name')=='Retain successful native consumer archive bytes' and step.get('conclusion')=='success'
                for step in selected[0].get('steps',[])),'Both exact native consumer build and artifact uploads must have passed')
    return dict(repository=REPOSITORY,workflow=WORKFLOW,commit=metadata['head_sha'],runId=str(run_id),runAttempt=str(attempt))


def stage(args):
    protected();source=source_identity(args.source_run,args.source_attempt)
    received=Path(args.received).absolute()
    expected={'native-archive-'+arch+'.tar.gz' for arch in ('x64','aarch64')}
    require({item.name for item in received.iterdir()}==expected,'Exact two native archive transports required')
    output=fresh_directory(args.output)
    with tempfile.TemporaryDirectory(prefix='cbodotnet-archive-native-') as temporary:
        builds=[];reports=[];inputs=[];providers=[]
        for arch in ('x64','aarch64'):
            transport=ordinary_file(received/('native-archive-'+arch+'.tar.gz'))
            destination=Path(temporary)/arch;sdk_tools().extract_sdk(transport,destination)
            name='delivery-archive-'+arch
            require({item.name for item in destination.iterdir()}=={name},'Unexpected native archive transport root')
            workspace=destination/name
            build=ordinary_file(workspace/'build/package-build.json')
            plan=json.loads(build.read_bytes())['plan']
            require(plan['architecture']==arch and 'sdk-'+plan['sdkVersion']==args.tag and plan['packageRevision']==args.revision,
                'Native consumer transport differs from the requested SDK/architecture/revision')
            builds.append(build);reports.append(ordinary_file(workspace/'report.json'));inputs.append(workspace/'inputs')
            if plan['compatibility']['required']:providers.append(ordinary_file(workspace/'compat/provider-build.json'))
        manifest=create_bundle(builds,reports,inputs,output/'bundle-archive',args.signing_key,args.keyring,source,
            gnupg_home=args.gnupg_home,compatibility_files=providers)
    metadata=dict(schemaVersion=1,status='signed-and-frozen',channel='archive',tag=manifest['tag'],
        sourceOrchestration=source,publisherCommit=os.environ['GITHUB_SHA'])
    (output/'promotion.json').write_bytes(encoded(metadata))
    return metadata


def receive_frozen(run_id,attempt,destination):
    spec=importlib.util.spec_from_file_location('consumer_archive_frozen_transport',ROOT/'scripts/distribution-ci.py')
    core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
    core.receive_frozen(run_id,attempt,destination,channels=('archive',),publisher_job=PUBLISH_JOB,
        freeze_step=FREEZE_STEP,artifact_prefix='downstream-archive-frozen')


def publish(args):
    protected()
    if args.frozen_run:receive_frozen(args.frozen_run,args.frozen_attempt,args.promotion)
    promotion=Path(args.promotion).absolute()
    require(promotion.is_dir() and not any(path.is_symlink() for path in [promotion,*promotion.parents]),'Ordinary frozen consumer promotion required')
    require({item.name for item in promotion.iterdir()} in ({'bundle-archive','promotion.json'},
        {'bundle-archive','promotion.json','archive-publication.json'}),'Unexpected frozen consumer promotion members')
    metadata=json.loads(ordinary_file(promotion/'promotion.json').read_bytes())
    manifest=validate_bundle(promotion/'bundle-archive',args.keyring)
    require(metadata.get('schemaVersion')==1 and metadata.get('status')=='signed-and-frozen' and metadata.get('channel')=='archive'
        and metadata.get('tag')==manifest['tag'] and metadata.get('sourceOrchestration')==manifest['sourceOrchestration'],
        'Frozen consumer metadata differs from its signed source identity')
    receipt=publish_bundle(promotion/'bundle-archive',args.keyring)
    (promotion/'archive-publication.json').write_bytes(encoded(receipt))
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('stage');command.add_argument('--received',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    command.add_argument('--tag',required=True);command.add_argument('--revision',type=int,required=True)
    command.add_argument('--signing-key',required=True);command.add_argument('--keyring',type=Path,required=True);command.add_argument('--gnupg-home',type=Path)
    command.add_argument('--source-run',required=True);command.add_argument('--source-attempt',required=True)
    command=commands.add_parser('publish');command.add_argument('--promotion',type=Path,required=True);command.add_argument('--keyring',type=Path,required=True)
    command.add_argument('--frozen-run',default='');command.add_argument('--frozen-attempt',default='1')
    args=parser.parse_args();print(json.dumps({'stage':stage,'publish':publish}[args.command](args),sort_keys=True))


if __name__=='__main__':main()
