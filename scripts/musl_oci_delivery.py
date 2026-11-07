"""Native OCI candidates, independently frozen two-CPU delivery and public proof.

Only the existing public cbodotnet-sdk GHCR package is used. Native images are
staged under unique run/attempt tags after passing the full native gate. The
canonical Alpine/musl tag is immutable and never aliases a glibc image.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_distribution as DISTRIBUTION
import musl_package_native as NATIVE
import musl_packages as PACKAGES
import musl_promotion as PROMOTION
from downstream_publish import GitHubReleases, verify_remote_assets
from downstream_release import descriptor, encoded, ordinary_file, require, verify_report_signature
from musl_release import WORKFLOW, extract_artifact, load_signing_policy, validate_artifact, verify_release_tag
from musl_verification import listed, timestamp, artifact_provenance
from release_catalog import get_bytes, release_assets, validate_api_asset

ROOT=CONTRACT.ROOT
REPOSITORY=CONTRACT.REPOSITORY
IMAGE_REPOSITORY='ghcr.io/'+REPOSITORY+'-sdk'
REGISTRY_NAME=REPOSITORY+'-sdk'
MANIFEST=PROMOTION.MANIFEST
SIGNATURE=PROMOTION.SIGNATURE
NATIVE_FILES={'oci-candidate.json','package-build.json','qualification-report.json',
              'payload-inventory.json','command-inventory.json'}
RUNNER_LABELS={'x64':'ubuntu-24.04','aarch64':'ubuntu-24.04-arm'}
IMAGE_TYPES={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
INDEX_TYPES={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}
MAX_REGISTRY_JSON=8*1024**2
OCI_CHECKS=(NATIVE.APK_CHECKS-{'package-signature','index-signature','package-index-binding','negative-signature-tests'}) \
    |{'oci-config','native-image-loader','native-stock-provider-ownership','root-owned-sdk','no-source-build-tools','clean-runtime-environment'}


def json_bytes(raw):
    require(isinstance(raw,bytes) and 0<len(raw)<=MAX_REGISTRY_JSON,'Registry JSON exceeds its explicit bound')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'Duplicate registry JSON key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)


class StripAuthorizationRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        target=urllib.parse.urlparse(newurl)
        require(target.scheme=='https' and target.hostname and target.username is None and target.password is None
            and target.port in {None,443},'Registry redirect attempted an unsafe origin or HTTPS downgrade')
        redirected=super().redirect_request(request,fp,code,message,headers,newurl)
        if redirected is not None and target.hostname!='ghcr.io':
            redirected.remove_header('Authorization')
        return redirected


class Registry:
    """Anonymous registry reads bind actual response bytes, not re-encoded JSON."""
    def __init__(self,opener=None,runner=None):
        self.open=opener or urllib.request.build_opener(StripAuthorizationRedirect()).open
        self.runner=runner or ARCHIVE.run
        self.token=None

    def _token(self):
        if self.token is None:
            request=urllib.request.Request('https://ghcr.io/token?service=ghcr.io&scope=repository:'+REGISTRY_NAME+':pull')
            with self.open(request,timeout=120) as response:
                value=json_bytes(response.read(64*1024+1))
            token=value.get('token') or value.get('access_token')
            require(isinstance(token,str) and 0<len(token)<=16384,'Anonymous GHCR pull token is absent')
            self.token=token
        return self.token

    def _get(self,path,*,accept=None,missing=False,expected=None,digest_header=False):
        headers={'Authorization':'Bearer '+self._token()}
        if accept:
            headers['Accept']=accept
        for attempt in range(4):
            request=urllib.request.Request('https://ghcr.io/v2/'+REGISTRY_NAME+'/'+path,headers=headers)
            try:
                with self.open(request,timeout=120) as response:
                    raw=response.read(MAX_REGISTRY_JSON+1)
                    observed={key.lower():value for key,value in response.headers.items()}
                break
            except urllib.error.HTTPError as error:
                if error.code==404 and missing:
                    return None
                if error.code not in {404,429,500,502,503,504} or attempt==3:
                    raise ValueError('Anonymous GHCR read failed with HTTP '+str(error.code)) from error
                time.sleep(0.5*(attempt+1))
        value=json_bytes(raw)
        digest='sha256:'+hashlib.sha256(raw).hexdigest()
        require(expected is None or digest==expected,'Registry actual bytes differ from requested digest')
        if digest_header:
            require(observed.get('docker-content-digest')==digest,'Registry digest header differs from actual response bytes')
        return dict(digest=digest,size=len(raw),raw=raw,document=value,
            mediaType=value.get('mediaType') or observed.get('content-type','').split(';')[0])

    def manifest(self,reference,*,missing=False):
        require(reference.startswith(IMAGE_REPOSITORY+':') or reference.startswith(IMAGE_REPOSITORY+'@'),
                'OCI read escaped the reviewed existing GHCR package')
        selector=reference[len(IMAGE_REPOSITORY)+1:]
        require(re.fullmatch(r'(?:sha256:[a-f0-9]{64}|[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})',selector),
                'Unsafe OCI manifest selector')
        value=self._get('manifests/'+selector,accept=', '.join(sorted(IMAGE_TYPES|INDEX_TYPES)),missing=missing,
            expected=selector if reference.startswith(IMAGE_REPOSITORY+'@') else None,digest_header=True)
        if value is not None:
            require(value['document'].get('schemaVersion')==2 and value['mediaType'] in IMAGE_TYPES|INDEX_TYPES,
                    'Unsupported registry manifest format')
        return value

    def config(self,digest):
        require(re.fullmatch(r'sha256:[a-f0-9]{64}',digest),'Exact OCI config digest required')
        return self._get('blobs/'+digest,expected=digest)

    def login(self):
        token=os.environ.get('GITHUB_TOKEN')
        actor=os.environ.get('GITHUB_ACTOR')
        require(token and actor and '\n' not in actor,'Scoped workflow GITHUB_TOKEN/actor required for GHCR write')
        result=subprocess.run(['docker','login','ghcr.io','--username',actor,'--password-stdin'],
            input=token+'\n',text=True,capture_output=True)
        require(result.returncode==0,'GHCR login failed without exposing credential diagnostics')

    def push(self,local,reference,expected_config):
        previous=self.manifest(reference,missing=True)
        if previous is None:
            self.login()
            self.runner(['docker','tag',local,reference])
            self.runner(['docker','push',reference])
        actual=self.manifest(reference)
        require(actual['mediaType'] in IMAGE_TYPES and actual['document'].get('config',{}).get('digest')==expected_config,
                'Refusing a conflicting immutable native staging tag')
        return actual

    def create_index(self,reference,platforms,*,version='10.0.403',revision=1):
        require(reference==IMAGE_REPOSITORY+':'+CONTRACT.oci_tag(version,revision),
                'Canonical OCI write escaped the exact musl SDK/revision tag')
        raw=canonical_index_bytes(platforms)
        expected_digest='sha256:'+hashlib.sha256(raw).hexdigest()
        actual=self.manifest(reference,missing=True)
        if actual is None:
            token=os.environ.get('GITHUB_TOKEN');actor=os.environ.get('GITHUB_ACTOR')
            require(token and actor,'Scoped GITHUB_TOKEN/actor required for canonical OCI index publication')
            credentials=base64.b64encode((actor+':'+token).encode()).decode()
            request=urllib.request.Request('https://ghcr.io/token?service=ghcr.io&scope=repository:'+REGISTRY_NAME+':pull,push',
                headers={'Authorization':'Basic '+credentials})
            with self.open(request,timeout=120) as response:
                authentication=json_bytes(response.read(64*1024+1))
            write_token=authentication.get('token') or authentication.get('access_token')
            require(isinstance(write_token,str) and 0<len(write_token)<=16384,'Scoped GHCR push token is absent')
            tag=reference[len(IMAGE_REPOSITORY)+1:]
            # GHCR does not promise tag compare-and-swap. Main-workflow OCI-channel
            # concurrency serializes our publishers; absence + exact raw-byte
            # pre/post checks remain mandatory. This header is only extra defense.
            request=urllib.request.Request('https://ghcr.io/v2/'+REGISTRY_NAME+'/manifests/'+tag,data=raw,method='PUT',
                headers={'Authorization':'Bearer '+write_token,'Content-Type':'application/vnd.oci.image.index.v1+json',
                    'If-None-Match':'*'})
            with self.open(request,timeout=120) as response:
                require(response.status==201,'Registry did not acknowledge canonical index creation')
            actual=self.manifest(reference)
        require(actual['digest']==expected_digest and actual['raw']==raw,
                'Refusing a canonical OCI tag with different immutable bytes')
        validate_registry_index(actual,platforms)
        return actual


def staging_tag(version,revision,architecture,origin):
    CONTRACT.version_revision(version,revision)
    require(architecture in CONTRACT.ARCHITECTURES and all(re.fullmatch(r'[1-9][0-9]*',str(origin[key]))
        for key in ('runId','runAttempt')),'Exact native staging CPU/run identity required')
    return f'musl-candidate-{version}-r{revision}-{architecture}-{origin["runId"]}-{origin["runAttempt"]}'


def protected(jobs):
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_REPOSITORY')==REPOSITORY
        and os.environ.get('GITHUB_WORKFLOW_REF')==REPOSITORY+'/'+WORKFLOW+'@refs/heads/main'
        and os.environ.get('GITHUB_WORKFLOW_SHA')==os.environ.get('GITHUB_SHA') and os.environ.get('GITHUB_JOB') in jobs,
        'OCI write/signing is limited to its exact reviewed main-branch workflow job')
    return DISTRIBUTION.orchestration()


def registry_platform(registry,reference,architecture,config_digest):
    actual=registry.manifest(reference)
    require(actual['mediaType'] in IMAGE_TYPES,'A native candidate must be a single-platform image manifest')
    config=actual['document'].get('config',{})
    require(config.get('digest')==config_digest and type(config.get('size')) is int and config['size']>0
        and config.get('mediaType') in {'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json'},
            'Pushed native image differs from qualified local config')
    blob=registry.config(config_digest)
    require(blob['size']==config['size'] and blob['document'].get('os')=='linux'
        and blob['document'].get('architecture')==('amd64' if architecture=='x64' else 'arm64'),
        'Actual registry config has another native OS/CPU/size')
    layers=actual['document'].get('layers',[])
    require(isinstance(layers,list) and 0<len(layers)<=128 and all(type(row.get('size')) is int and row['size']>0
        and re.fullmatch(r'sha256:[a-f0-9]{64}',row.get('digest','')) for row in layers),'Invalid OCI layer descriptors')
    diff_ids=blob['document'].get('rootfs',{}).get('diff_ids',[])
    require(blob['document'].get('rootfs',{}).get('type')=='layers' and isinstance(diff_ids,list)
        and len(diff_ids)==len(layers) and all(isinstance(value,str) and re.fullmatch(r'sha256:[a-f0-9]{64}',value)
        for value in diff_ids),'OCI config/layer graph differs')
    return dict(platform=CONTRACT.ARCHITECTURES[architecture]['oci'],digest=actual['digest'],
        configDigest=config_digest,manifestSize=actual['size'],manifestMediaType=actual['mediaType'],configSize=blob['size']),blob['document']


def validate_registry_index(actual,platforms):
    require(actual is not None and actual['mediaType'] in INDEX_TYPES and set(platforms)==set(CONTRACT.ARCHITECTURES),
            'Both native platforms and an actual registry index are required')
    rows=actual['document'].get('manifests',[])
    expected={(item['platform'].split('/')[0],item['platform'].split('/')[1],item['digest'],
               item['manifestSize'],item['manifestMediaType']) for item in platforms.values()}
    observed={(row.get('platform',{}).get('os'),row.get('platform',{}).get('architecture'),row.get('digest'),
               row.get('size'),row.get('mediaType')) for row in rows}
    require(len(rows)==2 and observed==expected,'Refusing a partial, duplicate or conflicting canonical musl OCI index')
    return actual


def canonical_index_bytes(platforms):
    require(set(platforms)==set(CONTRACT.ARCHITECTURES),'Both qualified native OCI platforms required')
    rows=[]
    for arch in sorted(platforms):
        row=platforms[arch]
        require(row['platform']==CONTRACT.ARCHITECTURES[arch]['oci']
            and re.fullmatch(r'sha256:[a-f0-9]{64}',row.get('digest',''))
            and type(row.get('manifestSize')) is int and row['manifestSize']>0 and row.get('manifestMediaType') in IMAGE_TYPES,
            'Invalid immutable child manifest descriptor')
        rows.append(dict(mediaType=row['manifestMediaType'],digest=row['digest'],size=row['manifestSize'],
            platform=dict(os='linux',architecture='amd64' if arch=='x64' else 'arm64')))
    return encoded(dict(schemaVersion=2,mediaType='application/vnd.oci.image.index.v1+json',manifests=rows))


def validate_config(config,build):
    plan=build['plan']
    body=config.get('config',{})
    values=body.get('Env',[])
    require(isinstance(values,list) and len(values)==5 and all(isinstance(value,str) and '=' in value for value in values),
            'Registry image contains duplicate or unreviewed build/signing environment entries')
    environment=dict(value.split('=',1) for value in values)
    require(config.get('os')=='linux' and config.get('architecture')==('amd64' if plan['architecture']['public']=='x64' else 'arm64')
        and body.get('User')=='app' and body.get('WorkingDir')=='/work' and body.get('Cmd')==['cbodotnet','--info']
        and not body.get('Entrypoint'),'Actual registry image execution configuration differs')
    require(environment==dict(PATH='/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
        DOTNET_ROOT=plan['package']['root'],DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_NOLOGO='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'),
        'Registry image contains unreviewed build/signing environment')
    require(body.get('Labels')==build['labels'],
            'Registry image source/license/SDK labels differ from independently reconstructed inputs')


def validate_native_report(report,build,origin,*,payload_inventory=None):
    plan=build['plan'];arch=plan['architecture']['public']
    require(report.get('schemaVersion')==1 and report.get('scope')=='musl-oci-installation'
        and report.get('status')=='passed' and report.get('native') is True and report.get('architecture')==arch
        and report.get('libc')=='musl' and report.get('targetRid')==plan['targetRid']
        and report.get('identity')==ARCHIVE.identity(plan) and report.get('networkForBuild')=='none'
        and report.get('orchestration')==origin and re.fullmatch(r'sha256:[a-f0-9]{64}',report.get('imageId',''))
        and report.get('productionQualification') is not False and not report.get('sourceAdmissionBypassedForDevelopment'),
        'An exact actual source-qualified native OCI report is required')
    for name,required in [('checks',OCI_CHECKS),('functionalChecks',ARCHIVE.FUNCTIONAL_CHECKS)]:
        observed=report.get(name,{})
        require(isinstance(observed,dict) and required<=set(observed) and all(observed[key]=='passed' for key in required),
                'Native OCI report lacks a mandatory complete runtime check')
    spaces=report.get('userSpaces',[])
    require(isinstance(spaces,list) and len(spaces)==1,'Exactly one actual native Alpine OCI user space required')
    space=spaces[0]
    require(space.get('variant')=='alpine-3.24' and space.get('alpineVersion')=='3.24.4' and space.get('status')=='passed'
        and space.get('base')==ARCHIVE.BASES[arch] and space.get('uid')==space.get('gid')==1654,
        'Native OCI report did not use the reviewed base/default non-root user')
    elf=space.get('elfAudit',{})
    require(elf.get('status')=='passed' and elf.get('native') is False and elf.get('architecture')==arch
        and elf.get('libc')=='musl' and elf.get('targetRid')==plan['targetRid']
        and type(elf.get('hostElfCount')) is int and elf['hostElfCount']>0 and elf.get('nonHostElfCount')==0,
        'Complete static OCI ELF audit is absent or has unreviewed foreign targets')
    rows=elf.get('elfFiles',[])
    require(len(rows)==elf['hostElfCount'] and len({row.get('path') for row in rows})==len(rows),
            'OCI ELF audit has duplicate, missing or extra host records')
    if payload_inventory is not None:
        for row in rows:
            item=payload_inventory.get(row.get('path'),[])
            require(len(item)==3 and item[0]=='file' and item[2]==row.get('sha256'),
                    'Native OCI ELF bytes differ from source payload inventory')
    for row in rows:
        require(row.get('disposition')=='host-runtime-or-tool' and row.get('machine')==CONTRACT.ARCHITECTURES[arch]['elfMachine']
            and row.get('elfClass')=='ELF64' and row.get('elfType') in {'DYN','EXEC','REL'}
            and row.get('interpreter') in {None,CONTRACT.ARCHITECTURES[arch]['interpreter']}
            and ARCHIVE.reviewed_gcc_abi_labels(row)==row.get('reviewedAbiVersionLabels'),
            'Native OCI ELF CPU/loader/ABI provider attribution differs')
    require(any(row.get('path')=='dotnet' and row.get('elfType') in {'DYN','EXEC'}
        and row.get('interpreter')==CONTRACT.ARCHITECTURES[arch]['interpreter'] for row in rows),
        'Native OCI proof lacks its actual matching musl dotnet host')
    execution=space.get('nativeImageExecution',{})
    require(execution.get('status')=='passed' and execution.get('native') is True and execution.get('architecture')==arch
        and execution.get('targetRid')==plan['targetRid'] and execution.get('imageId')==report['imageId']
        and execution.get('loader')==CONTRACT.ARCHITECTURES[arch]['interpreter']
        and execution.get('dynamicElfCount')==sum(row.get('elfType') in {'DYN','EXEC'} for row in rows)
        and re.fullmatch(r'[a-f0-9]{64}',execution.get('loaderOutputSha256','')),
        'Actual same-CPU OCI loader execution is absent')
    providers=execution.get('stockLibraries',[])
    static=elf.get('stockLibraries',[])
    require(isinstance(providers,list) and providers and isinstance(static,list) and static
        and all(isinstance(row,dict) and isinstance(row.get('path'),str) and '/image-rootfs/' in row['path'] for row in static),
        'Native OCI static stock closure lacks anchored exported library paths')
    static_paths={'/'+row['path'].rsplit('/image-rootfs/',1)[1]:row.get('sha256') for row in static}
    require(len(static_paths)==len(static) and len({row.get('path') for row in providers})==len(providers)
        and {row.get('path'):row.get('sha256') for row in providers}==static_paths
        and all(re.fullmatch(r'/(?:lib|usr/lib|usr/local/lib)/[A-Za-z0-9._+/-]+',row.get('path',''))
                and re.fullmatch(r'[a-f0-9]{64}',row.get('sha256',''))
                and row.get('apkOwner','') in {row['path']+' is owned by '+name+'-'+version
                    for name,version in ARCHIVE.RUNTIME_PACKAGES.items()} for row in providers),
        'Actual native OCI stock library bytes/APK ownership do not cover static closure')
    for row in static:
        require(row.get('machine')==CONTRACT.ARCHITECTURES[arch]['elfMachine']
            and row.get('elfClass')=='ELF64' and ARCHIVE.reviewed_gcc_abi_labels(row)==row.get('reviewedAbiVersionLabels'),
            'Static OCI stock ELF ABI/provider attribution differs')
        if 'GLIBC_2.0' in row.get('versionDefinitions',[]):
            path='/'+row['path'].rsplit('/image-rootfs/',1)[1]
            require(any(provider['path']==path and provider['apkOwner']==path+' is owned by libgcc-'
                +ARCHIVE.RUNTIME_PACKAGES['libgcc'] for provider in providers),'Reviewed GCC unwind ABI needs exact stock libgcc')
    validate_report_closure(rows,static,plan['package']['root'])
    ownership=space.get('ownership',{})
    require(ownership.get('status')=='passed' and ownership.get('uid')==ownership.get('gid')==0
        and ownership.get('sdkEntries',0)>0 and ownership.get('launcherEntries')==len(build['commandInventory'])
        and ownership.get('setIdOrWorldWritableEntries')==0,'Actual complete OCI root ownership proof is absent')
    require(set(name+'-'+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items())<=set(space.get('dependencies',[])),
            'Native OCI stock package versions differ')
    trust=space.get('systemTrustHttps',{})
    require(trust.get('status')=='passed' and trust.get('url')==ARCHIVE.trust_url(arch)
        and re.fullmatch(r'[a-f0-9]{64}',trust.get('outputSha256','')),'OCI actual system-CA HTTPS proof is absent')
    return report


def validate_report_closure(rows,stock,sdk_root):
    """Bind every reported DT_NEEDED edge to the complete payload/stock graph."""
    payload={sdk_root+'/'+row['path']:row['sha256'] for row in rows}
    system={'/'+row['path'].rsplit('/image-rootfs/',1)[1]:row['sha256'] for row in stock}
    referenced=set()
    for row in [*rows,*stock]:
        dependencies=row.get('dependencies',[])
        require(isinstance(dependencies,list) and len(dependencies)==len(row.get('needed',[]))
            and [edge.get('needed') for edge in dependencies]==row.get('needed',[]),
            'Native OCI closure omits a DT_NEEDED dependency edge')
        for edge in dependencies:
            resolved=edge.get('resolved','')
            require(isinstance(resolved,str) and '/image-rootfs/' in resolved,
                    'Native OCI dependency escaped the reviewed exported image root')
            path='/'+resolved.rsplit('/image-rootfs/',1)[1]
            if edge.get('provider')=='payload':
                require(path in payload and payload[path]==edge.get('sha256'),
                        'Native OCI payload dependency bytes are absent from the complete ELF set')
            else:
                require(edge.get('provider')=='stock-system' and path in system and system[path]==edge.get('sha256'),
                        'Native OCI stock dependency bytes are absent from the actual APK closure')
                referenced.add(path)
    require(referenced==set(system),'Native OCI closure contains unreferenced or missing stock providers')


def native_candidate(architecture,revision,workspace,output,*,push_staging=False,registry=None):
    origin=protected({'native_oci'})
    DISTRIBUTION._docker_architecture(architecture)
    workspace=ARCHIVE.fresh_directory(workspace)
    inputs=DISTRIBUTION.receive_source(architecture,workspace/'inputs')
    plan,sdk=DISTRIBUTION.intake_plan(inputs,architecture,'oci',revision)
    context=workspace/'context'
    build=PACKAGES.build_oci_context(plan,sdk,context,ARCHIVE.BASES[architecture])
    local='cbodotnet-musl-native:'+staging_tag(plan['sdkVersion'],revision,architecture,origin)
    command=['docker','build','--pull=false','--provenance=false','-f',context/'Containerfile','-t',local]
    for key,value in build['buildArgs'].items():command.extend(['--build-arg',key+'='+value])
    for key,value in build['labels'].items():command.extend(['--label',key+'='+value])
    ARCHIVE.run([*command,context])
    report=NATIVE.native_oci(context,architecture,workspace/'qualification',local)
    report['orchestration']=origin
    inventory=PROMOTION.load_json(context/'payload-inventory.json')
    validate_native_report(report,build,origin,payload_inventory=inventory)
    staged=None
    if push_staging:
        registry=registry or Registry()
        tag=staging_tag(plan['sdkVersion'],revision,architecture,origin)
        reference=IMAGE_REPOSITORY+':'+tag
        registry.push(local,reference,report['imageId'])
        platform,config=registry_platform(registry,reference,architecture,report['imageId'])
        validate_config(config,build)
        staged=dict(repository=IMAGE_REPOSITORY,tag=tag,reference=reference,**platform)
    output=ARCHIVE.fresh_directory(output)
    for name in ('package-build.json','payload-inventory.json','command-inventory.json'):
        shutil.copyfile(ordinary_file(context/name),output/name)
    (output/'qualification-report.json').write_bytes(encoded(report))
    candidate=dict(schemaVersion=1,kind='musl-oci-native-candidate',status='validated-staged' if staged else 'validated-unpublished',
        architecture=architecture,libc='musl',targetRid=plan['targetRid'],orchestration=origin,
        identity=ARCHIVE.identity(plan),localImage=local,configDigest=report['imageId'],registry=staged,
        build=descriptor(output/'package-build.json'),report=descriptor(output/'qualification-report.json'),
        payloadInventory=descriptor(output/'payload-inventory.json'),commandInventory=descriptor(output/'command-inventory.json'))
    (output/'oci-candidate.json').write_bytes(encoded(candidate))
    return candidate


def native_identity(api,run_id,attempt,*,current=None):
    require(type(run_id) is int and run_id>0 and type(attempt) is int and attempt>0,'Exact positive native OCI run/attempt required')
    run=api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    require(isinstance(run,dict),'Native OCI run is absent')
    commit=PROMOTION.validate_native_run(run,run_id,attempt,current=current)
    jobs=listed(api,f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs','jobs')
    selected={}
    for arch,label in RUNNER_LABELS.items():
        matches=[job for job in jobs if job.get('name')=='Qualify musl OCI native '+arch]
        require(len(matches)==1,'Exactly one actual native OCI job required per CPU')
        job=matches[0]
        require(job.get('status')=='completed' and job.get('conclusion')=='success' and job.get('head_sha')==commit
            and type(job.get('id')) is int and job['id']>0 and type(job.get('runner_id')) is int and job['runner_id']>0
            and job.get('runner_group_name')=='GitHub Actions' and job.get('runner_name')=='GitHub Actions '+str(job['runner_id'])
            and isinstance(job.get('labels'),list) and label in job['labels'] and 'self-hosted' not in job['labels']
            and timestamp(job['started_at'])<=timestamp(job['completed_at']),
            'Native OCI job did not use the successful exact GitHub-hosted CPU runner')
        selected[arch]=job
    return run,dict(repository=REPOSITORY,workflow=WORKFLOW,commit=commit,runId=str(run_id),runAttempt=str(attempt)),selected


def receive_candidates(api,run_id,attempt,output,*,current=None,downloader=None):
    run,origin,jobs=native_identity(api,run_id,attempt,current=current)
    artifacts=listed(api,f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts','artifacts')
    output=ARCHIVE.fresh_directory(output)
    received={}
    for arch in CONTRACT.ARCHITECTURES:
        name=f'musl-native-oci-{arch}-{run_id}-{attempt}'
        matches=[row for row in artifacts if row.get('name')==name]
        require(len(matches)==1,'One unique closed native OCI artifact required per CPU')
        artifact=validate_artifact(matches[0],run,name)
        require(artifact['size_in_bytes']<=64*1024**2,'Native OCI JSON transport exceeds size bound')
        archive=output/(arch+'.zip')
        if downloader is None:
            with archive.open('xb') as stream:
                subprocess.run([api.gh,'api',f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'],stdout=stream,check=True)
        else:
            downloader(artifact,archive)
        directory=extract_artifact(archive,output/arch,NATIVE_FILES,api_artifact=artifact)
        received[arch]=dict(directory=directory,transport=artifact_provenance(artifact,archive,origin,job=jobs[arch]))
    return origin,received


def validate_complete_elf(report,payload,architecture):
    """Independently cover all actual source ELF bytes, headers and version needs."""
    elf=report['userSpaces'][0]['elfAudit']
    actual={}
    for path in Path(payload).rglob('*'):
        if path.is_symlink() or not path.is_file():continue
        with path.open('rb') as stream:
            if stream.read(4)!=b'\x7fELF':continue
        actual[path.relative_to(payload).as_posix()]=descriptor(path)['sha256']
    rows=elf.get('elfFiles',[])
    require(actual and {row.get('path'):row.get('sha256') for row in rows}==actual
        and len(rows)==len(actual),'Native OCI report omits or substitutes a qualified source ELF')
    for row in rows:
        observed=ARCHIVE.inspect_elf(Path(payload)/row['path'])
        require(all(row.get(key)==value for key,value in observed.items()),
                'Native OCI ELF headers/needed/RPATH/version requirements differ from independent source inspection')


def verify_candidate(directory,architecture,origin,source_inputs,revision,registry):
    directory=Path(directory)
    require({path.name for path in directory.iterdir()}==NATIVE_FILES,'Native OCI candidate must be a closed five-JSON set')
    candidate=PROMOTION.load_json(directory/'oci-candidate.json')
    build=PROMOTION.load_json(directory/'package-build.json')
    report=PROMOTION.load_json(directory/'qualification-report.json')
    require(candidate.get('schemaVersion')==1 and candidate.get('kind')=='musl-oci-native-candidate'
        and candidate.get('status')=='validated-staged' and candidate.get('architecture')==architecture
        and candidate.get('libc')=='musl' and candidate.get('orchestration')==origin,
        'An actual staged source-qualified native OCI candidate is required')
    for field,name in [('build','package-build.json'),('report','qualification-report.json'),
        ('payloadInventory','payload-inventory.json'),('commandInventory','command-inventory.json')]:
        require(candidate.get(field)==descriptor(directory/name),'Native OCI metadata bytes changed after qualification')
    plan,sdk=DISTRIBUTION.intake_plan(source_inputs,architecture,'oci',revision)
    require(candidate.get('identity')==ARCHIVE.identity(plan) and candidate.get('targetRid')==plan['targetRid']
        and candidate.get('localImage')=='cbodotnet-musl-native:'+staging_tag(plan['sdkVersion'],revision,architecture,origin),
        'Native OCI candidate source/root/orchestration identity differs')
    with tempfile.TemporaryDirectory(prefix='musl-oci-independent-context-') as temporary:
        context=Path(temporary)/'canonical'
        canonical=PACKAGES.build_oci_context(plan,sdk,context,ARCHIVE.BASES[architecture])
        require(build==canonical,'Native OCI build/labels differ from independently reconstructed qualified source')
        payload=PROMOTION.load_json(context/'payload-inventory.json')
        require(PROMOTION.load_json(directory/'payload-inventory.json')==payload
            and PROMOTION.load_json(directory/'command-inventory.json')==PROMOTION.load_json(context/'command-inventory.json'),
            'Native OCI payload/command inventories differ from source reconstruction')
        validate_native_report(report,build,origin,payload_inventory=payload)
        validate_complete_elf(report,context/'rootfs'/plan['package']['root'].lstrip('/'),architecture)
    require(candidate.get('configDigest')==report['imageId'],'Native OCI config changed after actual execution')
    staged=candidate.get('registry',{})
    tag=staging_tag(plan['sdkVersion'],revision,architecture,origin)
    require(staged.get('repository')==IMAGE_REPOSITORY and staged.get('tag')==tag
        and staged.get('reference')==IMAGE_REPOSITORY+':'+tag and re.fullmatch(r'sha256:[a-f0-9]{64}',staged.get('digest','')),
        'Native OCI registry staging identity differs')
    # Never follow the mutable staging tag during freeze. The report-bound digest
    # is the sole source even if an unrelated writer moves that staging tag.
    platform,config=registry_platform(registry,IMAGE_REPOSITORY+'@'+staged['digest'],architecture,report['imageId'])
    require(staged==dict(repository=IMAGE_REPOSITORY,tag=tag,reference=IMAGE_REPOSITORY+':'+tag,**platform),
            'Actual immutable native registry bytes differ from staged proof')
    validate_config(config,build)
    return build,report,platform


def publication_index(platforms,version,revision,actual):
    validate_registry_index(actual,platforms)
    return dict(schemaVersion=1,repository=IMAGE_REPOSITORY,tag=CONTRACT.oci_tag(version,revision),
        digest=actual['digest'],rawManifestSize=actual['size'],mediaType=actual['mediaType'],
        platforms=copy.deepcopy(platforms))


def create_bundle(candidates,origin,output,*,revision=1,keyring,signing_key=None,gnupg_home=None,
                  target_commit,registry=None,source_receiver=None,policy=None):
    require(set(candidates)==set(CONTRACT.ARCHITECTURES),'Both native OCI candidates required before any canonical write')
    require(re.fullmatch(r'[a-f0-9]{40}',target_commit),'Exact protected OCI publication commit required')
    policy=policy or load_signing_policy(); signing_key=signing_key or PROMOTION.active_signer(policy)
    require(signing_key==PROMOTION.active_signer(policy),'Unreviewed OCI publication signing fingerprint')
    source_receiver=source_receiver or DISTRIBUTION.receive_source
    registry=registry or Registry()
    output=ARCHIVE.fresh_directory(output)
    records=[];platforms={};assets={};common=None
    with tempfile.TemporaryDirectory(prefix='musl-oci-source-recheck-') as temporary:
        for arch in sorted(candidates):
            item=candidates[arch];directory=Path(item['directory'])
            inputs=source_receiver(arch,Path(temporary)/arch)
            build,report,platform=verify_candidate(directory,arch,origin,inputs,revision,registry)
            identity=PROMOTION.publication_identity(build['plan'])
            require(identity['channel']=='oci' and (common is None or common==identity),'Mixed OCI source/version/revision matrix')
            common=identity;platforms[arch]=platform
            name='qualification-'+arch+'.json'
            shutil.copyfile(ordinary_file(directory/'qualification-report.json'),output/name)
            assets[name]=descriptor(output/name)
            records.append(dict(architecture=arch,targetRid=build['plan']['targetRid'],artifactAsset='oci-index.json',
                qualificationReportAsset=name,build=build,orchestration=origin,transport=item['transport']))
    # All independent source/GHA/native proofs have passed before this write.
    reference=IMAGE_REPOSITORY+':'+CONTRACT.oci_tag(common['sdkVersion'],revision)
    actual=registry.create_index(reference,platforms,version=common['sdkVersion'],revision=revision)
    index=publication_index(platforms,common['sdkVersion'],revision,actual)
    (output/'oci-index.json').write_bytes(encoded(index))
    assets['oci-index.json']=descriptor(output/'oci-index.json')
    manifest=dict(schemaVersion=1,kind='musl-distribution-publication',repository=REPOSITORY,
        contractVersion=CONTRACT.load_contract()['schemaVersion'],tag=CONTRACT.distribution_tag('oci',common['sdkVersion'],revision),
        identity=common,targetCommit=target_commit,sourceOrchestration=origin,signingFingerprint=signing_key,
        status='validated-complete-matrix',ociIndex=index,records=records,assets=[assets[key] for key in sorted(assets)])
    (output/MANIFEST).write_bytes(encoded(manifest))
    command=['gpg']+(['--homedir',str(gnupg_home)] if gnupg_home is not None else [])
    subprocess.run([*command,'--batch','--yes','--armor','--local-user',signing_key,
        '--output',str(output/SIGNATURE),'--detach-sign',str(output/MANIFEST)],check=True)
    validate_bundle(output,keyring,policy=policy,registry=registry)
    return manifest


def validate_bundle(directory,keyring,*,policy=None,registry=None):
    directory=Path(directory).absolute()
    require(directory.is_dir() and not any(path.is_symlink() for path in [directory,*directory.parents]),'Ordinary frozen OCI bundle required')
    policy=policy or load_signing_policy()
    manifest=PROMOTION.load_json(directory/MANIFEST)
    signer=verify_report_signature(directory/MANIFEST,directory/SIGNATURE,keyring,policy,WORKFLOW)
    identity=manifest.get('identity',{})
    require(manifest.get('schemaVersion')==1 and manifest.get('kind')=='musl-distribution-publication'
        and manifest.get('repository')==REPOSITORY and manifest.get('signingFingerprint')==signer
        and manifest.get('status')=='validated-complete-matrix' and identity.get('channel')=='oci' and identity.get('libc')=='musl'
        and manifest.get('tag')==CONTRACT.distribution_tag('oci',identity.get('sdkVersion'),identity.get('packageRevision'))
        and re.fullmatch(r'[a-f0-9]{40}',manifest.get('targetCommit','')),'Frozen OCI manifest identity/signer differs')
    assets=manifest.get('assets',[])
    expected={row.get('name'):row for row in assets}
    required={'oci-index.json',*['qualification-'+arch+'.json' for arch in CONTRACT.ARCHITECTURES]}
    require(len(expected)==len(assets) and set(expected)==required
        and {path.name for path in directory.iterdir()}==required|{MANIFEST,SIGNATURE},'Frozen OCI bundle is not a closed complete asset set')
    for name,row in expected.items():require(descriptor(directory/name)==row,'Frozen OCI asset bytes changed: '+name)
    index=PROMOTION.load_json(directory/'oci-index.json')
    require(index==manifest.get('ociIndex') and index.get('schemaVersion')==1 and index.get('repository')==IMAGE_REPOSITORY
        and index.get('tag')==CONTRACT.oci_tag(identity['sdkVersion'],identity['packageRevision'])
        and set(index.get('platforms',{}))==set(CONTRACT.ARCHITECTURES),'Signed OCI descriptor matrix differs')
    registry=registry or Registry()
    actual=registry.manifest(IMAGE_REPOSITORY+'@'+index['digest'])
    require(actual['raw']==canonical_index_bytes(index['platforms']) and actual['size']==index['rawManifestSize']
        and actual['mediaType']==index['mediaType'],'Actual canonical index bytes differ from frozen descriptor')
    validate_registry_index(actual,index['platforms'])
    records=manifest.get('records',[])
    require(len(records)==2 and {row.get('architecture') for row in records}==set(CONTRACT.ARCHITECTURES),'Incomplete frozen OCI record matrix')
    for row in records:
        arch=row['architecture'];build=row['build'];plan=build['plan']
        PACKAGES.validate_plan(plan,'oci');NATIVE.qualified_plan_source(plan)
        require(PROMOTION.publication_identity(plan)==identity and row.get('targetRid')==plan['targetRid']
            and row.get('artifactAsset')=='oci-index.json' and row.get('qualificationReportAsset')=='qualification-'+arch+'.json'
            and row.get('orchestration')==manifest['sourceOrchestration'],'Frozen OCI source/build identity differs')
        report=PROMOTION.load_json(directory/row['qualificationReportAsset'])
        validate_native_report(report,build,manifest['sourceOrchestration'])
        platform,config=registry_platform(registry,IMAGE_REPOSITORY+'@'+index['platforms'][arch]['digest'],arch,report['imageId'])
        require(platform==index['platforms'][arch],'Actual child manifest/config differs from frozen platform')
        validate_config(config,build)
    return manifest


def freeze_oci(run_id,attempt,revision,output,*,keyring,signing_key=None,gnupg_home=None,api=None,registry=None):
    current=protected({'freeze_oci'})
    api=api or GitHubReleases()
    with tempfile.TemporaryDirectory(prefix='musl-oci-receive-') as temporary:
        origin,candidates=receive_candidates(api,run_id,attempt,Path(temporary)/'received',current=current)
        return create_bundle(candidates,origin,output,revision=revision,keyring=keyring,signing_key=signing_key,
            gnupg_home=gnupg_home,target_commit=current['commit'],registry=registry)


def publish_oci(directory,keyring,*,api=None,registry=None,policy=None):
    current=protected({'publish_oci'})
    api=api or GitHubReleases();registry=registry or Registry()
    directory=Path(directory).absolute()
    manifest=validate_bundle(directory,keyring,policy=policy,registry=registry)
    source=manifest['sourceOrchestration']
    _,origin,_=native_identity(api,int(source['runId']),int(source['runAttempt']),current=current)
    require(origin==source,'Frozen native OCI origin changed before publication')
    index=manifest['ociIndex']
    tagged=registry.manifest(IMAGE_REPOSITORY+':'+index['tag'])
    require(tagged['digest']==index['digest'] and tagged['raw']==canonical_index_bytes(index['platforms']),
            'Canonical OCI tag moved after protected freeze')
    expected={row['name']:row for row in manifest['assets']}
    expected.update({name:descriptor(directory/name) for name in (MANIFEST,SIGNATURE)})
    tag=manifest['tag'];title,body=PROMOTION.publication_metadata(manifest)
    release=api.find(tag)
    if release is None:
        require(api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}') is None,'Refusing an unrelated existing musl OCI release tag')
        release=api.api(f'repos/{REPOSITORY}/releases','POST',dict(tag_name=tag,target_commitish=manifest['targetCommit'],
            name=title,body=body,draft=True,prerelease=False,make_latest='false'))
    require(release.get('tag_name')==tag and release.get('name')==title and release.get('body')==body
        and release.get('target_commitish')==manifest['targetCommit'] and release.get('prerelease') is False,
        'Existing OCI release has another immutable identity')
    verify_release_tag(api,tag,manifest['targetCommit'],allow_pending_draft=release.get('draft') is True)
    remote={row.get('name'):row for row in release.get('assets',[])}
    require(len(remote)==len(release.get('assets',[])) and set(remote)<=set(expected),'Unexpected or duplicate remote OCI release assets')
    for name,wanted in expected.items():
        if name in remote:
            require(remote[name].get('size')==wanted['size'] and remote[name].get('digest')=='sha256:'+wanted['sha256'],
                    'Refusing to replace conflicting immutable musl OCI release bytes')
        else:
            require(release.get('draft') is True,'Public OCI release cannot gain or replace assets')
            api.upload(release,directory/name)
    release=api.get(release)
    verify_remote_assets(release,expected,api,public=False)
    if release['draft']:release=api.publish(release)
    release=api.get(release)
    verify_release_tag(api,tag,manifest['targetCommit'])
    verify_remote_assets(release,expected,api,public=True)
    base=f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    return dict(schemaVersion=1,kind='musl-distribution-publication-receipt',status='published-public-bytes-verified',
        identity=manifest['identity'],tag=tag,releaseUrl=release['html_url'],releaseId=release['id'],
        manifestUrl=base+MANIFEST,signatureUrl=base+SIGNATURE,manifestSha256=expected[MANIFEST]['sha256'],
        signingFingerprint=manifest['signingFingerprint'],ociIndex=index,
        assets=[dict(row,url=base+row['name']) for row in manifest['assets']])


def public_oci(architecture,revision,workspace,output,*,registry=None):
    origin=DISTRIBUTION.orchestration()
    require(architecture in CONTRACT.ARCHITECTURES,'Exact native public OCI CPU required')
    CONTRACT.version_revision('10.0.403',revision)
    DISTRIBUTION._docker_architecture(architecture)
    workspace=ARCHIVE.fresh_directory(workspace)
    bundle=ARCHIVE.fresh_directory(workspace/'public-bundle')
    tag=CONTRACT.distribution_tag('oci','10.0.403',revision)
    base=f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    release=json.loads(get_bytes(f'https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}',8*1024**2,api=True))
    require(release.get('tag_name')==tag and release.get('draft') is False and release.get('prerelease') is False,
            'A public stable exact musl OCI distribution release is required')
    remote=release_assets(release)
    manifest_raw=get_bytes(base+MANIFEST,16*1024**2)
    signature_raw=get_bytes(base+SIGNATURE,1024**2)
    for name,raw in ((MANIFEST,manifest_raw),(SIGNATURE,signature_raw)):
        validate_api_asset(remote.get(name),name,REPOSITORY,tag,content=raw)
        (bundle/name).write_bytes(raw)
    keyring=workspace/'trusted.gpg'
    subprocess.run(['gpg','--batch','--dearmor','--output',str(keyring),str(ROOT/'releases/downstream-signing-key.asc')],check=True)
    from musl_release import verify_publication_signature
    signer=verify_publication_signature(bundle/MANIFEST,bundle/SIGNATURE,keyring)
    manifest=PROMOTION.load_json(bundle/MANIFEST)
    require(manifest.get('tag')==tag and manifest.get('identity',{}).get('channel')=='oci'
        and manifest.get('signingFingerprint')==signer,'Anonymous OCI manifest signature/identity differs')
    assets=manifest.get('assets',[])
    expected={'oci-index.json','qualification-x64.json','qualification-aarch64.json'}
    require(len(assets)==3 and {row.get('name') for row in assets}==expected,'Public signed OCI asset set differs')
    for row in assets:
        require(type(row.get('size')) is int and 0<row['size']<=32*1024**2
            and re.fullmatch(r'[a-f0-9]{64}',row.get('sha256','')),'Unsafe public OCI asset descriptor')
        validate_api_asset(remote.get(row['name']),row['name'],REPOSITORY,tag,descriptor=row)
        DISTRIBUTION.download_asset(base+row['name'],bundle/row['name'],row)
    require(set(remote)==expected|{MANIFEST,SIGNATURE},'Public OCI release has missing or extra assets')
    validate_bundle(bundle,keyring,registry=registry)
    verify_release_tag(DISTRIBUTION.AnonymousGitHubAPI(),tag,manifest['targetCommit'])
    records=[row for row in manifest['records'] if row['architecture']==architecture]
    require(len(records)==1,'A unique actual native public OCI record required')
    record=records[0]
    inputs=DISTRIBUTION.receive_source(architecture,workspace/'source',anonymous=True)
    plan,sdk=DISTRIBUTION.intake_plan(inputs,architecture,'oci',revision)
    context=workspace/'context'
    build=PACKAGES.build_oci_context(plan,sdk,context,ARCHIVE.BASES[architecture])
    require(build==record['build'],'Public OCI descriptor source/build differs from independent source reconstruction')
    index=manifest['ociIndex'];platform=index['platforms'][architecture]
    index_asset=next(row for row in manifest['assets'] if row['name']=='oci-index.json')
    public=dict(architecture=architecture,digest=platform['digest'],url=base+'oci-index.json',artifactSha256=index_asset['sha256'])
    report=NATIVE.native_oci(context,architecture,workspace/'qualification',IMAGE_REPOSITORY+'@'+platform['digest'],public_descriptor=public)
    report['orchestration']=origin
    report['publicVerification'].update(manifestUrl=base+MANIFEST,manifestSha256=hashlib.sha256(manifest_raw).hexdigest(),
        signingFingerprint=signer)
    validate_native_report(report,build,origin,payload_inventory=PROMOTION.load_json(context/'payload-inventory.json'))
    output=ARCHIVE.fresh_directory(output)
    (output/'public-report.json').write_bytes(encoded(report))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    for name in ('native-candidate','public-oci'):
        child=commands.add_parser(name)
        child.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
        child.add_argument('--revision',type=int,default=1)
        child.add_argument('--workspace',type=Path,required=True)
        child.add_argument('--output',type=Path,required=True)
        if name=='native-candidate':child.add_argument('--push-staging',action='store_true')
    child=commands.add_parser('freeze-oci')
    child.add_argument('--run-id',type=int,required=True)
    child.add_argument('--attempt',type=int,default=1)
    child.add_argument('--revision',type=int,default=1)
    child.add_argument('--output',type=Path,required=True)
    child.add_argument('--keyring',type=Path,required=True)
    child.add_argument('--signing-key')
    child.add_argument('--gnupg-home',type=Path)
    child=commands.add_parser('publish-oci')
    child.add_argument('--bundle',type=Path,required=True)
    child.add_argument('--keyring',type=Path,required=True)
    child.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='native-candidate':
        result=native_candidate(args.arch,args.revision,args.workspace,args.output,push_staging=args.push_staging)
    elif args.command=='freeze-oci':
        result=freeze_oci(args.run_id,args.attempt,args.revision,args.output,keyring=args.keyring,
            signing_key=args.signing_key,gnupg_home=args.gnupg_home)
    elif args.command=='publish-oci':
        require(args.output.parent.is_dir() and not args.output.exists(),'Fresh OCI publication receipt path required')
        result=publish_oci(args.bundle,args.keyring)
        args.output.write_bytes(encoded(result))
    else:
        result=public_oci(args.arch,args.revision,args.workspace,args.output)
    print(json.dumps(dict(status=result.get('status'),tag=result.get('tag'),architecture=result.get('architecture'))))


if __name__=='__main__':
    main()
