"""Real ephemeral OpenPGP over API-authenticated six-report verification fixtures."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_release as RELEASE
from musl_package_native import APK_CHECKS
import musl_site as SITE
import musl_verification as VERIFY
from downstream_release import encoded
from musl_contract_test import fixture as source_fixture

ENVIRONMENT = dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=CONTRACT.REPOSITORY,GITHUB_REF='refs/heads/main',
    GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_WORKFLOW_REF=CONTRACT.REPOSITORY+'/'+VERIFY.WORKFLOW+'@refs/heads/main',
    GITHUB_SHA='f'*40,GITHUB_WORKFLOW_SHA='f'*40,GITHUB_JOB='freeze_verification',GITHUB_RUN_ID='900',GITHUB_RUN_ATTEMPT='1')


class FixtureAPI:
    """Synthetic native executions; actual ZIP bytes, hashes and GPG are exercised."""
    gh = 'fixture-gh'
    def __init__(self, signer, sign):
        _, source, source_raw, _, self.catalog, _ = source_fixture()
        self.runs,self.jobs,self.artifacts,self.zips,self.releases,self.objects = {},{},{},{},{},{}
        self.sources,self.posts,self.uploads,self.downloads = {},[],[],[]
        artifact_id = 100
        for index,channel in enumerate(VERIFY.CHANNELS):
            run_id,commit = (index+1)*111,chr(ord('a')+index)*40
            self.sources[channel] = (run_id,1)
            run = dict(id=run_id,run_attempt=1,path=VERIFY.WORKFLOW,head_sha=commit,head_branch='main',
                event='workflow_dispatch',repository=dict(full_name=CONTRACT.REPOSITORY),
                head_repository=dict(full_name=CONTRACT.REPOSITORY),status='completed',conclusion='success')
            self.runs[run_id] = run
            origin = dict(repository=CONTRACT.REPOSITORY,workflow=VERIFY.WORKFLOW,commit=commit,runId=str(run_id),runAttempt='1')
            self.jobs[run_id] = [dict(id=run_id*10+offset,name=f'Verify public musl {channel} native {arch}',
                status='completed',conclusion='success',head_sha=commit,labels=[VERIFY.RUNNER_LABELS[arch]],
                runner_id=10000+run_id*10+offset,runner_name='GitHub Actions '+str(10000+run_id*10+offset),
                runner_group_name='GitHub Actions',started_at='2026-11-07T02:00:00Z',completed_at='2026-11-07T02:00:10Z')
                for offset,arch in enumerate(CONTRACT.ARCHITECTURES)]
            self.artifacts[run_id] = []
            identity = dict(sdkVersion='10.0.403',producerRevision=1,packageRevision=1,libc='musl',channel=channel,
                sourceReleaseTag=source['tag'],sourceManifestSha256=hashlib.sha256(source_raw).hexdigest())
            tag = CONTRACT.distribution_tag(channel,'10.0.403',1)
            manifest = dict(schemaVersion=1,kind='musl-distribution-publication',repository=CONTRACT.REPOSITORY,
                identity=identity,tag=tag,targetCommit=commit,sourceOrchestration=origin,signingFingerprint=signer,assets=[],records=[])
            payloads={}
            index_object = dict(repository='ghcr.io/'+CONTRACT.REPOSITORY+'-sdk',tag=CONTRACT.oci_tag('10.0.403'),
                digest='sha256:'+'d'*64,platforms={arch:dict(digest='sha256:'+str(offset+1)*64,
                    configDigest='sha256:'+str(offset+3)*64,platform=target['oci'])
                    for offset,(arch,target) in enumerate(CONTRACT.ARCHITECTURES.items())})
            if channel == 'oci':
                manifest['ociIndex'] = index_object
                payloads['oci-index.json'] = encoded(index_object)
            for arch,target in CONTRACT.ARCHITECTURES.items():
                name = (CONTRACT.archive_name('10.0.403',arch) if channel == 'archive' else
                        'apk-'+arch+'-sdk.apk' if channel == 'apk' else 'oci-index.json')
                if channel != 'oci':
                    payloads[name] = (channel+' native SDK '+arch).encode()
                pre_report='qualification-'+arch+'.json'
                payloads[pre_report]=b'{"status":"passed"}'
                record = dict(architecture=arch,targetRid=target['rid'],artifactAsset=name,qualificationReportAsset=pre_report,
                    build=dict(plan=dict(identity,targetRid=target['rid'],producer=source['architectures'][arch]['provenance'])))
                if channel == 'apk':
                    repo_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/musl-apk-repo-10.0.403-alpine324-{arch}-r1/'
                    sdk_raw=payloads[name];host_raw=b'shared-host'
                    record['repository'] = dict(url=repo_url,indexSha256='9'*64,packages=[
                        dict(name=name,size=len(sdk_raw),sha256=hashlib.sha256(sdk_raw).hexdigest(),url=repo_url+name),
                        dict(name='cbodotnet-host-1.0.0-r1.apk',size=len(host_raw),sha256=hashlib.sha256(host_raw).hexdigest(),
                             url=repo_url+'cbodotnet-host-1.0.0-r1.apk')])
                manifest['records'].append(record)
            manifest['assets']=[dict(name=name,size=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for name,raw in payloads.items()]
            for record in manifest['records']:
                record['build']['artifact']=next(item for item in manifest['assets'] if item['name']==record['artifactAsset'])
            manifest_raw=encoded(manifest)
            payloads['distribution-manifest.json']=manifest_raw
            payloads['distribution-manifest.json.asc']=sign(manifest_raw)
            release = dict(id=5000+run_id,tag_name=tag,target_commitish=commit,draft=False,prerelease=False,
                html_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/tag/{tag}',assets=[])
            for name,raw in payloads.items():
                url=VERIFY.asset_url(tag,name)
                self.objects[url]=raw
                release['assets'].append(dict(name=name,size=len(raw),digest='sha256:'+hashlib.sha256(raw).hexdigest(),
                    state='uploaded',browser_download_url=url))
            self.releases[tag]=release
            receipt = dict(schemaVersion=1,kind='musl-distribution-publication-receipt',status='published-public-bytes-verified',
                identity=identity,tag=tag,releaseId=release['id'],releaseUrl=release['html_url'],
                manifestUrl=VERIFY.asset_url(tag,'distribution-manifest.json'),signatureUrl=VERIFY.asset_url(tag,'distribution-manifest.json.asc'),
                manifestSha256=hashlib.sha256(manifest_raw).hexdigest(),signingFingerprint=signer,
                assets=[dict(row,url=VERIFY.asset_url(tag,row['name'])) for row in manifest['assets']])
            self.add_artifact(artifact_id,run_id,f'musl-{channel}-publication-{run_id}-1',f'musl-{channel}-publication.json',encoded(receipt))
            artifact_id+=1
            for record in manifest['records']:
                arch,target=record['architecture'],CONTRACT.ARCHITECTURES[record['architecture']]
                artifact=next(row for row in manifest['assets'] if row['name']==record['artifactAsset'])
                report_identity={key:value for key,value in identity.items() if key!='channel'}
                report = dict(schemaVersion=1,scope={'archive':'musl-consumer-archive-installation','apk':'musl-apk-installation',
                    'oci':'musl-oci-installation'}[channel],status='passed',native=True,architecture=arch,libc='musl',
                    targetRid=target['rid'],networkForBuild='none',orchestration=origin,
                    identity=dict(report_identity,targetRid=target['rid']),
                    artifact=copy.deepcopy(artifact),checks=dict.fromkeys(ARCHIVE.REPORT_CHECKS|APK_CHECKS|{
                        'oci-config','native-image-loader','native-stock-provider-ownership','root-owned-sdk','no-source-build-tools',
                        'clean-runtime-environment'},'passed'),functionalChecks=dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS,'passed'),
                    userSpaces=[dict(variant='alpine-3.24',alpineVersion='3.24.4',status='passed',uid=1654 if channel=='oci' else 10001,
                        gid=1654 if channel=='oci' else 10001,elfAudit=dict(status='passed',native=True,libc='musl',architecture=arch,
                            targetRid=target['rid'],hostElfCount=31,stockLibraries=[dict(name='musl',sha256='e'*64)]),
                        systemTrustHttps=dict(status='passed'))],
                    publicVerification=dict(status='passed',anonymous=True,artifactSha256=artifact['sha256'],
                        manifestUrl=receipt['manifestUrl'],manifestSha256=receipt['manifestSha256'],signingFingerprint=signer,
                        url=VERIFY.asset_url(tag,record['artifactAsset'])))
                if channel == 'oci':
                    space=report['userSpaces'][0]
                    space['elfAudit'].update(native=False,elfFiles=[dict(path='dotnet',disposition='host-runtime-or-tool',elfType='DYN')])
                    report.update(imageDigest=index_object['platforms'][arch]['digest'],imageId=index_object['platforms'][arch]['configDigest'])
                    provider=dict(path=target['interpreter'],sha256='e'*64,apkOwner=target['interpreter']+' is owned by musl-1.2.6-r3')
                    space.update(nativeImageExecution=dict(status='passed',native=True,architecture=arch,targetRid=target['rid'],
                        loader=target['interpreter'],imageId=report['imageId'],loaderOutputSha256='8'*64,dynamicElfCount=1,stockLibraries=[provider]),
                        ownership=dict(status='passed',uid=0,gid=0,setIdOrWorldWritableEntries=0,sdkEntries=1234))
                    report['publicVerification'].update(imageDigest=index_object['platforms'][arch]['digest'],
                        imageConfigDigest=index_object['platforms'][arch]['configDigest'],indexDigest=index_object['digest'],
                        descriptorUrl=VERIFY.asset_url(tag,'oci-index.json'))
                elif channel == 'apk':
                    repository=record['repository']
                    report['publicBytes']=dict(packages=copy.deepcopy(repository['packages']))
                    report['publicVerification'].update(indexUrl=repository['url']+'APKINDEX.tar.gz',indexSha256=repository['indexSha256'],
                        sourceUrl=repository['url']+artifact['name'])
                self.add_artifact(artifact_id,run_id,f'musl-public-{channel}-{arch}-{run_id}-1','public-report.json',encoded(report))
                artifact_id+=1

    def add_artifact(self,artifact_id,run_id,name,filename,raw):
        content=io.BytesIO()
        with zipfile.ZipFile(content,'w',compression=zipfile.ZIP_STORED) as stream:
            stream.writestr(filename,raw)
        blob=content.getvalue()
        self.zips[artifact_id]=blob
        self.artifacts[run_id].append(dict(id=artifact_id,name=name,size_in_bytes=len(blob),digest='sha256:'+hashlib.sha256(blob).hexdigest(),
            expired=False,created_at='2026-11-07T02:00:05Z',workflow_run=dict(id=run_id,head_sha=self.runs[run_id]['head_sha'],
                head_branch='main',repository_id=10,head_repository_id=10)))

    def api(self,endpoint,method='GET',body=None):
        parts=endpoint.split('/')
        if '/actions/runs/' in endpoint:
            run_id=int(parts[5])
            if '/jobs?' in endpoint:return dict(jobs=copy.deepcopy(self.jobs[run_id]))
            if '/artifacts?' in endpoint:return dict(artifacts=copy.deepcopy(self.artifacts[run_id]))
            return copy.deepcopy(self.runs[run_id])
        if '/releases/tags/' in endpoint:
            return copy.deepcopy(self.releases.get(endpoint.rsplit('/',1)[1]))
        if '/git/ref/tags/' in endpoint:
            tag=endpoint.rsplit('/',1)[1];release=self.releases.get(tag)
            if release is not None and not release['draft']:
                return dict(ref='refs/tags/'+tag,object=dict(type='commit',sha=release['target_commitish']))
            return None
        if method=='POST':
            self.posts.append(copy.deepcopy(body));tag=body['tag_name']
            self.releases[tag]=dict(body,id=9999,html_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/tag/{tag}',assets=[])
            return copy.deepcopy(self.releases[tag])
        raise AssertionError('Unexpected API call '+endpoint)

    def find(self,tag):return copy.deepcopy(self.releases.get(tag))
    def get(self,release):return copy.deepcopy(self.releases[release['tag_name']])
    def upload(self,release,path):
        raw=path.read_bytes();tag=release['tag_name'];url=VERIFY.asset_url(tag,path.name)
        self.uploads.append(path.name);self.objects[url]=raw
        self.releases[tag]['assets'].append(dict(name=path.name,size=len(raw),digest='sha256:'+hashlib.sha256(raw).hexdigest(),
            state='uploaded',browser_download_url=url))
    def publish(self,release):
        self.releases[release['tag_name']]['draft']=False
        return self.get(release)
    def download(self,asset,path,public=False):
        self.downloads.append(dict(name=asset['name'],public=public))
        path.write_bytes(self.objects[asset['browser_download_url']])
    def fetch(self,url,maximum):
        raw=self.objects[url]
        if len(raw)>maximum:raise ValueError('fixture anonymous response exceeds actual bound')
        return raw
    def artifact_download(self,artifact,path):path.write_bytes(self.zips[artifact['id']])

    def rewrite_json_artifact(self,artifact,change,*,canonical=True):
        with zipfile.ZipFile(io.BytesIO(self.zips[artifact['id']])) as stream:
            filename=stream.infolist()[0].filename
            value=json.loads(stream.read(filename))
        change(value)
        raw=encoded(value) if canonical else json.dumps(value).encode()
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_STORED) as stream:
            stream.writestr(filename,raw)
        blob=buffer.getvalue();self.zips[artifact['id']]=blob
        artifact.update(size_in_bytes=len(blob),digest='sha256:'+hashlib.sha256(blob).hexdigest())


@unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgv'),'Ephemeral OpenPGP fixture requires GnuPG')
class MuslVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto_temp=tempfile.TemporaryDirectory()
        cls.crypto=Path(cls.crypto_temp.name)
        cls.home=cls.crypto/'gnupg';cls.home.mkdir(mode=0o700)
        subprocess.run(['gpg','--homedir',str(cls.home),'--batch','--pinentry-mode','loopback','--passphrase','',
            '--quick-generate-key','cbodotnet ephemeral test <test@example.invalid>','ed25519','sign','1d'],
            check=True,capture_output=True)
        listed=subprocess.check_output(['gpg','--homedir',str(cls.home),'--batch','--with-colons','--list-keys'],text=True)
        cls.signer=next(line.split(':')[9] for line in listed.splitlines() if line.startswith('fpr:'))
        cls.keyring=cls.crypto/'trusted.gpg'
        cls.keyring.write_bytes(subprocess.check_output(['gpg','--homedir',str(cls.home),'--batch','--export',cls.signer]))
        now=datetime.now(timezone.utc)
        cls.policy=copy.deepcopy(RELEASE.load_signing_policy())
        cls.policy['evidenceSigners']={cls.signer:dict(state='active',workflow=VERIFY.WORKFLOW,
            notBefore=(now-timedelta(days=1)).isoformat(),notAfter=(now+timedelta(days=1)).isoformat())}

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf','--homedir',str(cls.home),'--kill','all'],capture_output=True)
        cls.crypto_temp.cleanup()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.counter=0
        self.api=FixtureAPI(self.signer,self.sign)
        patches=[mock.patch.object(VERIFY,'load_signing_policy',return_value=self.policy),
                 mock.patch.object(RELEASE,'load_signing_policy',return_value=self.policy),
                 mock.patch.object(RELEASE,'load_qualification_catalog',return_value=self.api.catalog),
                 mock.patch.dict(VERIFY.os.environ,ENVIRONMENT,clear=True)]
        for patch in patches:
            patch.start();self.addCleanup(patch.stop)

    def sign(self,raw):
        self.counter+=1
        source=self.root/f'metadata-{self.counter}.json';source.write_bytes(raw)
        target=self.root/f'metadata-{self.counter}.asc'
        subprocess.run(['gpg','--homedir',str(self.home),'--batch','--yes','--armor','--local-user',self.signer,
            '--output',str(target),'--detach-sign',str(source)],check=True,capture_output=True)
        return target.read_bytes()

    def freeze(self):
        return VERIFY.freeze(self.api.sources,1,self.root/'bundle',self.keyring,gnupg_home=self.home,
            api=self.api,fetch=self.api.fetch,downloader=self.api.artifact_download)

    def test_real_gpg_freeze_publish_and_site_authenticate_all_six_report_bytes(self):
        document=self.freeze()
        self.assertEqual(6,len(document['assets']));self.assertEqual(3,len(document['entries']))
        self.assertEqual(8,len(list((self.root/'bundle').iterdir())))
        with mock.patch.dict(VERIFY.os.environ,dict(ENVIRONMENT,GITHUB_JOB='publish_verification'),clear=True):
            status=VERIFY.publish(self.root/'bundle',self.root/'status.json',self.keyring,api=self.api,fetch=self.api.fetch)
        self.assertEqual('published-postverified',status['status'])
        self.assertEqual('false',self.api.posts[0]['make_latest'])
        self.assertEqual(8,len([row for row in self.api.downloads if row['public']]))
        self.assertEqual(8,len(self.api.uploads))
        for receipt in status['publications']:
            manifest=SITE.authenticate_receipt(receipt,fetch=self.api.fetch,keyring=self.keyring)
            self.assertEqual(receipt['identity'],manifest['identity'])
            self.assertEqual(2,len(receipt['postVerification']['reports']))
            self.assertNotIn('verification',next(entry for entry in document['entries'] if entry['identity']==receipt['identity']))

    def test_native_host_labels_failed_jobs_and_wrong_artifact_origin_are_rejected(self):
        run_id,_=self.api.sources['archive']
        for key,value in (('labels',['ubuntu-24.04-arm']),('conclusion','failure'),('runner_group_name','self-hosted')):
            saved=copy.deepcopy(self.api.jobs[run_id][0]);self.api.jobs[run_id][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                VERIFY.receive_channel(self.api,'archive',run_id,1,1,self.root/key,downloader=self.api.artifact_download)
            self.api.jobs[run_id][0]=saved
        self.api.artifacts[run_id][-1]['workflow_run']['head_sha']='0'*40
        with self.assertRaisesRegex(ValueError,'artifact origin differs'):
            VERIFY.receive_channel(self.api,'archive',run_id,1,1,self.root/'origin',downloader=self.api.artifact_download)

    def test_api_digest_and_timestamp_must_bind_the_actual_native_report_transport(self):
        run_id,_=self.api.sources['archive']
        artifact=self.api.artifacts[run_id][1]
        original=self.api.zips[artifact['id']]
        self.api.zips[artifact['id']]=original+b'changed transport'
        with self.assertRaisesRegex(ValueError,'actual GitHub API digest'):
            VERIFY.receive_channel(self.api,'archive',run_id,1,1,self.root/'digest',downloader=self.api.artifact_download)
        self.api.zips[artifact['id']]=original
        artifact['created_at']='2026-11-07T01:59:00Z'
        with self.assertRaisesRegex(ValueError,'not created during'):
            VERIFY.receive_channel(self.api,'archive',run_id,1,1,self.root/'timestamp',downloader=self.api.artifact_download)

    def test_partial_matrix_and_changed_public_manifest_cannot_be_signed(self):
        run_id,_=self.api.sources['apk']
        self.api.artifacts[run_id].pop()
        with self.assertRaisesRegex(ValueError,'exact unique public musl artifact'):
            self.freeze()
        self.assertFalse((self.root/'bundle').exists())

    def test_rehashed_native_report_from_another_orchestration_is_rejected(self):
        run_id,_=self.api.sources['archive']
        artifact=self.api.artifacts[run_id][1]
        self.api.rewrite_json_artifact(artifact,lambda value:value['orchestration'].update(commit='0'*40))
        with self.assertRaisesRegex(ValueError,'another workflow/CPU/native scope'):
            self.freeze()
        self.assertFalse((self.root/'bundle').exists())

    def test_valid_transport_hash_cannot_admit_failed_full_icu_evidence(self):
        run_id,_=self.api.sources['archive']
        artifact=self.api.artifacts[run_id][1]
        self.api.rewrite_json_artifact(artifact,lambda value:value['functionalChecks'].update(fullIcuCulturesAndCalendars='failed'))
        with self.assertRaisesRegex(ValueError,'full offline runtime'):
            self.freeze()
        self.assertFalse((self.root/'bundle').exists())

    def test_actual_gpg_rejects_a_replaced_channel_signature_with_matching_api_digest(self):
        tag=CONTRACT.distribution_tag('archive','10.0.403',1)
        url=VERIFY.asset_url(tag,'distribution-manifest.json.asc')
        raw=b'not an OpenPGP signature\n';self.api.objects[url]=raw
        item=next(row for row in self.api.releases[tag]['assets'] if row['name']=='distribution-manifest.json.asc')
        item.update(size=len(raw),digest='sha256:'+hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError,'signature did not independently verify'):
            self.freeze()

    def test_original_receipt_wire_format_can_change_without_changing_bound_fields(self):
        run_id,_=self.api.sources['archive']
        self.api.rewrite_json_artifact(self.api.artifacts[run_id][0],lambda value:None,canonical=False)
        document=self.freeze()
        original=document['entries'][0]['postVerification']['publication']
        self.assertRegex(original['receiptCanonicalSha256'],r'^[a-f0-9]{64}$')
        self.assertNotEqual(original['receipt']['sha256'],original['receiptCanonicalSha256'])

    def test_oci_tag_commit_is_bound_separately_from_native_workflow_and_receipt_extra_fields(self):
        run_id,_=self.api.sources['oci']
        tag=CONTRACT.distribution_tag('oci','10.0.403',1)
        manifest_url=VERIFY.asset_url(tag,'distribution-manifest.json')
        signature_url=VERIFY.asset_url(tag,'distribution-manifest.json.asc')
        manifest=json.loads(self.api.objects[manifest_url])
        self.assertNotEqual('d'*40,manifest['sourceOrchestration']['commit'])
        manifest['targetCommit']='d'*40
        raw=encoded(manifest);sha=hashlib.sha256(raw).hexdigest()
        self.api.objects[manifest_url]=raw
        self.api.objects[signature_url]=self.sign(raw)
        release=self.api.releases[tag]
        release['target_commitish']='d'*40
        for asset in release['assets']:
            if asset['browser_download_url'] in {manifest_url,signature_url}:
                actual=self.api.objects[asset['browser_download_url']]
                asset.update(size=len(actual),digest='sha256:'+hashlib.sha256(actual).hexdigest())
        self.api.rewrite_json_artifact(self.api.artifacts[run_id][0],
            lambda receipt:receipt.update(manifestSha256=sha,ociIndex=copy.deepcopy(manifest['ociIndex'])))
        for artifact in self.api.artifacts[run_id][1:]:
            self.api.rewrite_json_artifact(artifact,
                lambda report:report['publicVerification'].update(manifestSha256=sha))
        document=self.freeze()
        entry=next(row for row in document['entries'] if row['identity']['channel']=='oci')
        self.assertEqual(manifest['ociIndex'],entry['ociIndex'])
        self.assertEqual(manifest['sourceOrchestration'],entry['postVerification']['publication']['orchestration'])
        self.assertNotEqual(manifest['targetCommit'],entry['postVerification']['publication']['orchestration']['commit'])
        release['target_commitish']='0'*40
        with self.assertRaisesRegex(ValueError,'tag ref points to another commit'):
            VERIFY.authenticate_channel(entry,self.keyring,api=self.api,fetch=self.api.fetch)

    def test_frozen_report_mutation_and_signed_entry_redirection_fail_closed(self):
        self.freeze()
        report=self.root/'bundle/archive-x64-public-report.json'
        report.write_bytes(report.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'Frozen public native report bytes changed'):
            VERIFY.validate_frozen(self.root/'bundle',self.keyring,api=self.api,fetch=self.api.fetch)

    def test_actual_gpg_rejects_a_replaced_final_verification_signature(self):
        self.freeze()
        (self.root/'bundle'/VERIFY.SIGNATURE).write_bytes(b'invalid final signature\n')
        with self.assertRaisesRegex(ValueError,'signature did not independently verify'):
            VERIFY.validate_frozen(self.root/'bundle',self.keyring,api=self.api,fetch=self.api.fetch)

    def test_conflicting_remote_final_asset_is_never_overwritten(self):
        self.freeze()
        with mock.patch.dict(VERIFY.os.environ,dict(ENVIRONMENT,GITHUB_JOB='publish_verification'),clear=True):
            VERIFY.publish(self.root/'bundle',self.root/'first.json',self.keyring,api=self.api,fetch=self.api.fetch)
            tag=VERIFY.verification_tag(1)
            self.api.releases[tag]['assets'][0]['digest']='sha256:'+'0'*64
            before=list(self.api.uploads)
            with self.assertRaisesRegex(ValueError,'Refusing to replace conflicting'):
                VERIFY.publish(self.root/'bundle',self.root/'second.json',self.keyring,api=self.api,fetch=self.api.fetch)
        self.assertEqual(before,self.api.uploads)
        self.assertFalse((self.root/'second.json').exists())

    def test_final_publisher_requires_its_own_protected_job(self):
        with mock.patch.dict(VERIFY.os.environ,dict(ENVIRONMENT,GITHUB_JOB='publish_archive'),clear=True):
            with self.assertRaisesRegex(ValueError,'Only protected main'):
                VERIFY.protected()


if __name__=='__main__':unittest.main()
