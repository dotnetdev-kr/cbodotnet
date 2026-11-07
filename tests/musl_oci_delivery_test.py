"""OCI raw-byte trust, native provenance and immutable publication boundaries."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import musl_oci_delivery as OCI
import musl_archive as ARCHIVE
import musl_packages as PACKAGES
import musl_contract as CONTRACT
import musl_packages_test as FIXTURES
from downstream_release import encoded
from musl_promotion_test import FakeReleases

ORIGIN=dict(repository=CONTRACT.REPOSITORY,workflow=OCI.WORKFLOW,commit='a'*40,runId='123',runAttempt='2')


def platforms():
    return {arch:dict(platform=CONTRACT.ARCHITECTURES[arch]['oci'],digest='sha256:'+value*64,
        configDigest='sha256:'+('3' if arch=='x64' else '4')*64,manifestSize=1234,
        manifestMediaType='application/vnd.oci.image.manifest.v1+json',configSize=567)
        for arch,value in [('x64','1'),('aarch64','2')]}


class Response(io.BytesIO):
    def __init__(self,raw,headers=None,status=200):
        super().__init__(raw);self.headers=headers or {};self.status=status


class RegistryHttp:
    def __init__(self):
        self.manifests={};self.blobs={};self.requests=[];self.puts=[];self.wrong_header=False
    def __call__(self,request,timeout=120):
        self.requests.append(request)
        url=request.full_url
        if '/token?' in url:
            return Response(b'{"token":"fixture-ephemeral-token"}')
        if '/manifests/' in url:
            key=url.split('/manifests/',1)[1]
            if request.get_method()=='PUT':
                self.puts.append((key,request.data))
                self.manifests[key]=request.data
                return Response(b'',status=201)
            if key not in self.manifests:
                raise urllib.error.HTTPError(url,404,'not found',{},None)
            raw=self.manifests[key]
            digest='sha256:'+hashlib.sha256(raw).hexdigest()
            return Response(raw,{'Docker-Content-Digest':'sha256:'+'0'*64 if self.wrong_header else digest})
        key=url.split('/blobs/',1)[1]
        return Response(self.blobs[key])


class RegistryTrustTests(unittest.TestCase):
    def test_actual_raw_bytes_and_response_digest_are_both_verified(self):
        http=RegistryHttp()
        raw=b'{ "schemaVersion":2, "mediaType":"application/vnd.oci.image.index.v1+json", "manifests":[] }\n\n'
        http.manifests['fixture']=raw
        registry=OCI.Registry(opener=http)
        result=registry.manifest(OCI.IMAGE_REPOSITORY+':fixture')
        self.assertEqual(raw,result['raw'])
        self.assertEqual('sha256:'+hashlib.sha256(raw).hexdigest(),result['digest'])
        http.wrong_header=True
        with self.assertRaisesRegex(ValueError,'digest header'):
            registry.manifest(OCI.IMAGE_REPOSITORY+':fixture')

    def test_digest_pull_and_config_blob_do_not_trust_an_unrelated_body(self):
        http=RegistryHttp();registry=OCI.Registry(opener=http)
        digest='sha256:'+'1'*64
        http.manifests[digest]=encoded(dict(schemaVersion=2,mediaType='application/vnd.oci.image.manifest.v1+json'))
        with self.assertRaisesRegex(ValueError,'requested digest'):
            registry.manifest(OCI.IMAGE_REPOSITORY+'@'+digest)
        http.blobs[digest]=b'{"architecture":"arm64"}'
        with self.assertRaisesRegex(ValueError,'requested digest'):
            registry.config(digest)
        with self.assertRaisesRegex(ValueError,'reviewed existing GHCR'):
            registry.manifest('ghcr.io/other/project:latest')

    def test_registry_redirects_keep_credentials_only_on_secure_original_origin(self):
        handler=OCI.StripAuthorizationRedirect()
        request=urllib.request.Request('https://ghcr.io/token',headers={'Authorization':'Basic fixture-value'})
        redirect=handler.redirect_request(request,None,302,'redirect',{},'https://storage.example.invalid/blob')
        self.assertIsNone(redirect.get_header('Authorization'))
        same=handler.redirect_request(request,None,302,'redirect',{},'https://ghcr.io/other')
        self.assertEqual('Basic fixture-value',same.get_header('Authorization'))
        for url in ('http://ghcr.io/other','https://user:password@ghcr.io/other','https://ghcr.io:444/other'):
            with self.subTest(url=url),self.assertRaisesRegex(ValueError,'unsafe origin|downgrade'):
                handler.redirect_request(request,None,302,'redirect',{},url)

    def test_canonical_index_is_exact_raw_immutable_and_never_a_glibc_tag(self):
        http=RegistryHttp();registry=OCI.Registry(opener=http);matrix=platforms()
        tag=CONTRACT.oci_tag('10.0.403',1);reference=OCI.IMAGE_REPOSITORY+':'+tag
        expected=OCI.canonical_index_bytes(matrix)
        http.manifests[tag]=expected
        self.assertEqual(expected,registry.create_index(reference,matrix)['raw'])
        self.assertEqual([],http.puts)
        http.manifests[tag]=expected+b'\n'
        with self.assertRaisesRegex(ValueError,'different immutable bytes'):
            registry.create_index(reference,matrix)
        self.assertEqual([],http.puts)
        with self.assertRaisesRegex(ValueError,'exact musl'):
            registry.create_index(OCI.IMAGE_REPOSITORY+':10.0.403-debian13-r3',matrix)

    def test_missing_canonical_index_is_created_once_with_exact_bytes(self):
        http=RegistryHttp();registry=OCI.Registry(opener=http);matrix=platforms()
        reference=OCI.IMAGE_REPOSITORY+':'+CONTRACT.oci_tag('10.0.403',1)
        with mock.patch.dict(os.environ,GITHUB_TOKEN='fixture-not-a-real-token',GITHUB_ACTOR='fixture'):
            actual=registry.create_index(reference,matrix)
            registry.create_index(reference,matrix)
        self.assertEqual(1,len(http.puts))
        self.assertEqual(OCI.canonical_index_bytes(matrix),actual['raw'])
        puts=[r for r in http.requests if r.get_method()=='PUT']
        self.assertEqual('application/vnd.oci.image.index.v1+json',puts[0].get_header('Content-type'))
        self.assertEqual('*',puts[0].get_header('If-none-match'))

    def test_partial_duplicate_and_wrong_size_platform_indexes_are_rejected(self):
        matrix=platforms();raw=OCI.canonical_index_bytes(matrix);body=json.loads(raw)
        for change in [lambda d:d['manifests'].pop(),lambda d:d['manifests'].append(copy.deepcopy(d['manifests'][0])),
                       lambda d:d['manifests'][0].update(size=1)]:
            current=copy.deepcopy(body);change(current)
            with self.assertRaisesRegex(ValueError,'partial, duplicate or conflicting'):
                OCI.validate_registry_index(dict(mediaType=body['mediaType'],document=current),matrix)

    def test_child_manifest_actual_config_and_layer_graph_are_bound_to_the_native_cpu(self):
        http=RegistryHttp();registry=OCI.Registry(opener=http)
        config=dict(os='linux',architecture='arm64',rootfs=dict(type='layers',diff_ids=['sha256:'+'a'*64]))
        raw=encoded(config);digest='sha256:'+hashlib.sha256(raw).hexdigest();http.blobs[digest]=raw
        image=dict(schemaVersion=2,mediaType='application/vnd.oci.image.manifest.v1+json',
            config=dict(digest=digest,size=len(raw),mediaType='application/vnd.oci.image.config.v1+json'),
            layers=[dict(size=123,digest='sha256:'+'b'*64,mediaType='application/vnd.oci.image.layer.v1.tar+gzip')])
        http.manifests['candidate']=encoded(image)
        platform,observed=OCI.registry_platform(registry,OCI.IMAGE_REPOSITORY+':candidate','aarch64',digest)
        self.assertEqual('linux/arm64',platform['platform']);self.assertEqual(config,observed)
        with self.assertRaisesRegex(ValueError,'another native OS/CPU'):
            OCI.registry_platform(registry,OCI.IMAGE_REPOSITORY+':candidate','x64',digest)
        image['config']['mediaType']='application/octet-stream';http.manifests['candidate']=encoded(image)
        with self.assertRaisesRegex(ValueError,'qualified local config'):
            OCI.registry_platform(registry,OCI.IMAGE_REPOSITORY+':candidate','aarch64',digest)


def report_for(build):
    plan=build['plan'];arch=plan['architecture']['public'];library='/lib/libc.musl-'+('x86_64' if arch=='x64' else 'aarch64')+'.so.1'
    elf=dict(path='dotnet',name='dotnet',size=123,sha256='1'*64,elfType='DYN',elfClass='ELF64',
        machine=CONTRACT.ARCHITECTURES[arch]['elfMachine'],interpreter=CONTRACT.ARCHITECTURES[arch]['interpreter'],
        needed=['libc.musl.so'],runpaths=[],versionNeeds=[],glibcRequirements=[],reviewedAbiVersionLabels=[],
        dependencies=[dict(needed='libc.musl.so',resolved='/qualification/image-rootfs'+library,provider='stock-system',sha256='2'*64)],
        disposition='host-runtime-or-tool')
    audit=dict(status='passed',native=False,architecture=arch,libc='musl',targetRid=plan['targetRid'],
        hostElfCount=1,nonHostElfCount=0,elfFiles=[elf],stockLibraries=[dict(path='/qualification/image-rootfs'+library,
            sha256='2'*64,machine=CONTRACT.ARCHITECTURES[arch]['elfMachine'],elfClass='ELF64',
            versionNeeds=[],versionDefinitions=[],glibcRequirements=[],reviewedAbiVersionLabels=[],needed=[],dependencies=[])])
    return dict(schemaVersion=1,scope='musl-oci-installation',status='passed',native=True,architecture=arch,
        libc='musl',targetRid=plan['targetRid'],identity=ARCHIVE.identity(plan),networkForBuild='none',
        orchestration=copy.deepcopy(ORIGIN),imageId='sha256:'+'3'*64,
        checks=dict.fromkeys(OCI.OCI_CHECKS,'passed'),functionalChecks=dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS,'passed'),
        userSpaces=[dict(variant='alpine-3.24',alpineVersion='3.24.4',base=ARCHIVE.BASES[arch],uid=1654,gid=1654,status='passed',
            elfAudit=audit,dependencies=[name+'-'+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items()],
            ownership=dict(status='passed',uid=0,gid=0,sdkEntries=5,launcherEntries=len(build['commandInventory']),setIdOrWorldWritableEntries=0),
            nativeImageExecution=dict(status='passed',native=True,architecture=arch,targetRid=plan['targetRid'],
                imageId='sha256:'+'3'*64,loader=CONTRACT.ARCHITECTURES[arch]['interpreter'],dynamicElfCount=1,
                loaderOutputSha256='4'*64,stockLibraries=[dict(path=library,sha256='2'*64,apkOwner=library+' is owned by musl-1.2.6-r3')]),
            systemTrustHttps=dict(status='passed',url=ARCHIVE.trust_url(arch),outputSha256='5'*64))])


@unittest.skipUnless(os.name=='posix','POSIX SDK fixture semantics required')
class OciProofTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
        helper=FIXTURES.MuslPackagesTests();helper.directory=self.work
        self.plan,self.sdk=helper.plan('oci')
        self.build=PACKAGES.build_oci_context(self.plan,self.sdk,self.work/'context',PACKAGES.BASE_IMAGES['x64'])

    def test_fixture_missing_runtime_root_user_or_stock_bytes_can_never_qualify(self):
        report=report_for(self.build)
        OCI.validate_native_report(report,self.build,ORIGIN,payload_inventory={'dotnet':['file',0o755,'1'*64]})
        changes=[lambda r:r.update(status='fixture-only',productionQualification=False),
            lambda r:r['functionalChecks'].pop('tls12LoopbackHandshake'),
            lambda r:r['userSpaces'][0].update(uid=0),
            lambda r:r['userSpaces'][0]['nativeImageExecution']['stockLibraries'][0].update(sha256='f'*64),
            lambda r:r['userSpaces'][0]['nativeImageExecution']['stockLibraries'][0].update(path='/usr/lib/substitute.so'),
            lambda r:r['userSpaces'][0]['nativeImageExecution']['stockLibraries'][0].update(apkOwner='unknown stock package'),
            lambda r:r['userSpaces'][0]['elfAudit']['elfFiles'][0].update(dependencies=[]),
            lambda r:r['userSpaces'][0]['elfAudit']['elfFiles'][0]['dependencies'][0].update(resolved='/host/lib/unreviewed.so'),
            lambda r:r['userSpaces'][0]['elfAudit'].update(native=True)]
        for change in changes:
            altered=copy.deepcopy(report);change(altered)
            with self.assertRaises(ValueError):OCI.validate_native_report(altered,self.build,ORIGIN)

    def test_freeze_compares_complete_source_elf_set_not_just_reported_subset(self):
        root=self.work/'payload';root.mkdir()
        first=root/'dotnet';first.write_bytes(b'\x7fELFfirst')
        second=root/'hidden.so';second.write_bytes(b'\x7fELFomitted')
        report=report_for(self.build)
        report['userSpaces'][0]['elfAudit']['elfFiles']=[dict(path='dotnet',sha256=hashlib.sha256(first.read_bytes()).hexdigest())]
        with self.assertRaisesRegex(ValueError,'omits or substitutes'):
            OCI.validate_complete_elf(report,root,'x64')
        report['userSpaces'][0]['elfAudit']['elfFiles'].append(dict(path='hidden.so',sha256=hashlib.sha256(second.read_bytes()).hexdigest()))
        with mock.patch.object(ARCHIVE,'inspect_elf',return_value={'machine':'not-the-reported-machine'}):
            with self.assertRaisesRegex(ValueError,'independent source inspection'):
                OCI.validate_complete_elf(report,root,'x64')

    def test_registry_runtime_configuration_forbids_build_credentials_and_wrong_alias_defaults(self):
        config=dict(os='linux',architecture='amd64',config=dict(User='app',WorkingDir='/work',Cmd=['cbodotnet','--info'],
            Labels=self.build['labels'],Env=['PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
            'DOTNET_ROOT=/opt/cbodotnet/10.0','DOTNET_CLI_TELEMETRY_OPTOUT=1','DOTNET_NOLOGO=1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1']))
        OCI.validate_config(config,self.build)
        config['config']['Env'].append('GITHUB_TOKEN=fixture')
        with self.assertRaisesRegex(ValueError,'unreviewed build/signing environment'):
            OCI.validate_config(config,self.build)
        config['config']['Env'].pop();config['config']['Cmd']=['dotnet','--version']
        with self.assertRaisesRegex(ValueError,'execution configuration'):
            OCI.validate_config(config,self.build)
        config['config']['Cmd']=['cbodotnet','--info']
        config['config']['Env'].append('DOTNET_ROOT=/opt/cbodotnet/10.0')
        with self.assertRaisesRegex(ValueError,'duplicate or unreviewed'):
            OCI.validate_config(config,self.build)


class NativeProvenanceTests(unittest.TestCase):
    def fixtures(self):
        run=dict(id=123,run_attempt=2,path=OCI.WORKFLOW,status='in_progress',conclusion=None,
            head_sha='a'*40,head_branch='main',event='workflow_dispatch',
            repository=dict(full_name=CONTRACT.REPOSITORY),head_repository=dict(full_name=CONTRACT.REPOSITORY))
        jobs=[];artifacts=[];objects={}
        for index,(arch,label) in enumerate(OCI.RUNNER_LABELS.items()):
            jobs.append(dict(id=index+1,name='Qualify musl OCI native '+arch,status='completed',conclusion='success',head_sha='a'*40,
                labels=[label],runner_id=100+index,runner_group_name='GitHub Actions',runner_name='GitHub Actions '+str(100+index),
                started_at='2026-11-07T00:00:00Z',completed_at='2026-11-07T00:02:00Z'))
            out=io.BytesIO()
            with zipfile.ZipFile(out,'w') as archive:
                for name in OCI.NATIVE_FILES:archive.writestr(name,b'{}')
            raw=out.getvalue();objects[index+10]=raw
            artifacts.append(dict(id=index+10,name='musl-native-oci-'+arch+'-123-2',expired=False,size_in_bytes=len(raw),
                digest='sha256:'+hashlib.sha256(raw).hexdigest(),created_at='2026-11-07T00:01:00Z',
                workflow_run=dict(id=123,head_sha='a'*40,head_branch='main',repository_id=1,head_repository_id=1)))
        class API:
            def api(self,endpoint):
                if '/jobs?' in endpoint:return dict(jobs=jobs)
                if '/artifacts?' in endpoint:return dict(artifacts=artifacts)
                return run
        return API(),run,jobs,artifacts,objects

    def test_exact_main_current_run_two_native_jobs_and_actual_zip_digests_are_required(self):
        api,run,jobs,artifacts,objects=self.fixtures()
        with tempfile.TemporaryDirectory() as temporary:
            def download(artifact,path):path.write_bytes(objects[artifact['id']])
            origin,received=OCI.receive_candidates(api,123,2,Path(temporary)/'valid',current=ORIGIN,downloader=download)
            self.assertEqual(ORIGIN,origin);self.assertEqual({'x64','aarch64'},set(received))
            self.assertEqual(OCI.NATIVE_FILES,{p.name for p in received['x64']['directory'].iterdir()})
            artifacts[0]['digest']='sha256:'+'0'*64
            with self.assertRaisesRegex(ValueError,'GitHub API size/digest'):
                OCI.receive_candidates(api,123,2,Path(temporary)/'tampered',current=ORIGIN,downloader=download)
        jobs[1]['labels']=['ubuntu-24.04']
        with self.assertRaisesRegex(ValueError,'exact GitHub-hosted CPU'):
            OCI.native_identity(api,123,2,current=ORIGIN)
        jobs[1]['labels']=['ubuntu-24.04-arm'];run['head_repository']['full_name']='fork/repository'
        with self.assertRaises(ValueError):OCI.native_identity(api,123,2,current=ORIGIN)


class ImmutablePublicationTests(unittest.TestCase):
    def test_exact_signed_assets_publish_once_and_refuse_remote_byte_or_tag_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);matrix=platforms();raw=OCI.canonical_index_bytes(matrix)
            index=OCI.publication_index(matrix,'10.0.403',1,dict(raw=raw,size=len(raw),document=json.loads(raw),
                digest='sha256:'+hashlib.sha256(raw).hexdigest(),mediaType='application/vnd.oci.image.index.v1+json'))
            assets=[]
            for name,content in [('oci-index.json',encoded(index)),('qualification-x64.json',b'{"fixture":"unit"}'),
                                 ('qualification-aarch64.json',b'{"fixture":"unit"}')]:
                (directory/name).write_bytes(content);assets.append(OCI.descriptor(directory/name))
            manifest=dict(identity=dict(channel='oci',sdkVersion='10.0.403',packageRevision=1,libc='musl'),
                tag=CONTRACT.distribution_tag('oci','10.0.403',1),targetCommit='a'*40,sourceOrchestration=ORIGIN,
                ociIndex=index,assets=assets,signingFingerprint='D7D154B4B33C19A82B95B13688135410ACD9C0EA')
            (directory/OCI.MANIFEST).write_bytes(encoded(manifest))
            (directory/OCI.SIGNATURE).write_bytes(b'unit-test-signature-not-production')
            api=FakeReleases()
            registry=mock.Mock();registry.manifest.return_value=dict(digest=index['digest'],raw=raw)
            # Signature/source qualification are independently exercised by their
            # own suites; this test covers the actual immutable remote publisher.
            with mock.patch.object(OCI,'protected',return_value=ORIGIN), \
                 mock.patch.object(OCI,'validate_bundle',return_value=manifest), \
                 mock.patch.object(OCI,'native_identity',return_value=(None,ORIGIN,None)):
                first=OCI.publish_oci(directory,directory/'trusted.gpg',api=api,registry=registry)
                second=OCI.publish_oci(directory,directory/'trusted.gpg',api=api,registry=registry)
                self.assertEqual(first,second);self.assertEqual(1,api.publish_count);self.assertEqual(5,len(api.uploads))
                self.assertEqual('false',api.posts[0]['make_latest'])
                api.release['assets'][0]['digest']='sha256:'+'0'*64
                with self.assertRaisesRegex(ValueError,'conflicting immutable'):
                    OCI.publish_oci(directory,directory/'trusted.gpg',api=api,registry=registry)
                registry.manifest.return_value['digest']='sha256:'+'f'*64
                with self.assertRaisesRegex(ValueError,'tag moved'):
                    OCI.publish_oci(directory,directory/'trusted.gpg',api=api,registry=registry)
                self.assertEqual(1,len(api.posts));self.assertEqual(5,len(api.uploads))


if __name__=='__main__':unittest.main()
