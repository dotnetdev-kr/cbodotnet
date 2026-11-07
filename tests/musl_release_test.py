import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from musl_release import (ROOT, extract_artifact, extract_delivery, validate_artifact,
    validate_run, validate_source_stage, validate_apk_signer, validate_publication_metadata, verify_release_tag)
from musl_contract_test import fixture
import musl_archive
import musl_contract


class MuslOriginTest(unittest.TestCase):
    def setUp(self):
        self.run = dict(id=123, run_attempt=2, path='.github/workflows/musl-sdk.yml', head_sha='a'*40,
            head_branch='main', event='workflow_dispatch', repository=dict(full_name='dotnetdev-kr/cbodotnet'),
            head_repository=dict(full_name='dotnetdev-kr/cbodotnet'), status='completed', conclusion='success')
        self.artifact = dict(id=456, name='native-musl', expired=False, size_in_bytes=100, digest='sha256:'+'b'*64,
            workflow_run=dict(id=123, head_sha='a'*40, head_branch='main', repository_id=10, head_repository_id=10))

    def test_exact_successful_attempt_and_origin(self):
        self.assertEqual(validate_run(self.run, workflow='.github/workflows/musl-sdk.yml', run_id=123, attempt=2), 'a'*40)
        validate_artifact(self.artifact, self.run, 'native-musl')
        for field, value in [('run_attempt', 1), ('event', 'pull_request'), ('conclusion', 'failure'),
                             ('path', '.github/workflows/net10-sdk.yml'), ('head_branch', 'topic')]:
            bad = dict(self.run, **{field:value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_run(bad, workflow='.github/workflows/musl-sdk.yml', run_id=123, attempt=2)
        bad = copy.deepcopy(self.artifact); bad['workflow_run']['head_repository_id'] = 11
        with self.assertRaises(ValueError): validate_artifact(bad, self.run, 'native-musl')

    def test_transport_and_closed_archive_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root/'bundle.zip'
            with zipfile.ZipFile(source, 'w') as archive: archive.writestr('delivery.json', '{}')
            api = dict(size_in_bytes=source.stat().st_size, digest='sha256:'+hashlib.sha256(source.read_bytes()).hexdigest())
            extract_artifact(source, root/'received', {'delivery.json'}, api_artifact=api)
            self.assertEqual((root/'received/delivery.json').read_text(), '{}')
            with self.assertRaises(ValueError):
                extract_artifact(source, root/'substitution', {'different.json'}, api_artifact=api)
            with self.assertRaises(ValueError):
                extract_artifact(source, root/'tampered', {'delivery.json'}, api_artifact=dict(api, digest='sha256:'+'0'*64))

    def test_delivery_rejects_traversal_links_and_duplicate_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, kind in enumerate(('traversal', 'symlink', 'duplicate')):
                source = root/(kind+'.tar.gz')
                with tarfile.open(source, 'w:gz') as archive:
                    item = tarfile.TarInfo('delivery/../outside' if kind == 'traversal' else 'delivery/file')
                    if kind == 'symlink':
                        item.type = tarfile.SYMTYPE; item.linkname = '../../outside'
                        archive.addfile(item)
                    else:
                        item.size = 2
                        archive.addfile(item, io.BytesIO(b'{}'))
                        if kind == 'duplicate': archive.addfile(item, io.BytesIO(b'{}'))
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    extract_delivery(source, root/('out'+str(index)))
            self.assertFalse((root/'outside').exists())

    def test_source_stage_requires_both_cpus_and_unchanged_closed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release, manifest, raw, checksums, catalog, payloads = fixture()
            for name, data in payloads.items(): (root/name).write_bytes(data)
            self.assertEqual(validate_source_stage(root)[0], manifest)
            sdk = root/manifest['architectures']['aarch64']['sdk']['name']
            sdk.write_bytes(b'altered second CPU SDK')
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                validate_source_stage(root)

    def test_approved_apk_key_has_a_publisher_cutoff_and_rejects_changed_pem(self):
        public = ROOT/'releases/cbodotnet-apk-2026.rsa.pub'
        policy = validate_apk_signer(public)
        cutoff = datetime.fromisoformat(policy['publisherNotAfter'].replace('Z','+00:00'))
        with self.assertRaisesRegex(ValueError, 'window'):
            validate_apk_signer(public, now=cutoff)
        with tempfile.TemporaryDirectory() as temporary:
            altered = Path(temporary)/public.name
            altered.write_bytes(public.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'exact PEM'):
                validate_apk_signer(altered)

    def test_real_lightweight_and_annotated_release_tags_bind_the_commit(self):
        tag='musl-sdk-10.0.403-r1'; target='a'*40; annotation='b'*40
        api=mock.Mock()
        api.api.return_value=dict(ref='refs/tags/'+tag,object=dict(type='commit',sha=target))
        self.assertEqual(verify_release_tag(api,tag,target),target)
        api.api.return_value=dict(ref='refs/tags/'+tag,object=dict(type='commit',sha='c'*40))
        with self.assertRaisesRegex(ValueError,'another commit'): verify_release_tag(api,tag,target)
        api.api.side_effect=[dict(ref='refs/tags/'+tag,object=dict(type='tag',sha=annotation)),
            dict(sha=annotation,object=dict(type='commit',sha=target))]
        self.assertEqual(verify_release_tag(api,tag,target),target)
        api.api.side_effect=None; api.api.return_value=None
        self.assertIsNone(verify_release_tag(api,tag,target,allow_pending_draft=True))


class PublicEvidenceTest(unittest.TestCase):
    def setUp(self):
        release, source, raw, sums, self.catalog, payloads = fixture()
        identity = dict(sdkVersion='10.0.403', producerRevision=1, packageRevision=1, libc='musl', channel='archive',
            sourceReleaseTag=source['tag'], sourceManifestSha256=hashlib.sha256(raw).hexdigest())
        tag = musl_contract.distribution_tag('archive','10.0.403')
        base = f'https://github.com/{musl_contract.REPOSITORY}/releases/download/{tag}/'
        self.manifest = dict(schemaVersion=1,kind='musl-distribution-publication',repository=musl_contract.REPOSITORY,
            identity=identity,tag=tag,signingFingerprint='D7D154B4B33C19A82B95B13688135410ACD9C0EA',assets=[],records=[])
        self.reports = {}; public = []
        for arch, target in musl_contract.ARCHITECTURES.items():
            artifact = source['architectures'][arch]['sdk']
            pre_report = dict(name='native-'+arch+'.json',size=2,sha256=hashlib.sha256(b'{}').hexdigest())
            self.manifest['assets'].extend([artifact,pre_report])
            plan = dict(identity,targetRid=target['rid'],producer=self.catalog['builds'][0]['architectures'][arch])
            self.manifest['records'].append(dict(architecture=arch,targetRid=target['rid'],artifactAsset=artifact['name'],
                qualificationReportAsset=pre_report['name'],build=dict(plan=plan,artifact=artifact)))
            report_identity = {key:value for key,value in identity.items() if key!='channel'}
            report = dict(status='passed',native=True,architecture=arch,targetRid=target['rid'],libc='musl',
                identity=dict(report_identity,targetRid=target['rid']),networkForBuild='none',artifact=artifact,
                checks=dict.fromkeys(musl_archive.REPORT_CHECKS,'passed'),
                functionalChecks=dict.fromkeys(musl_archive.FUNCTIONAL_CHECKS,'passed'),
                publicVerification=dict(status='passed',anonymous=True,artifactSha256=artifact['sha256'],
                    manifestSha256='d'*64,manifestUrl=base+'distribution-manifest.json',
                    signingFingerprint=self.manifest['signingFingerprint'],url=base+artifact['name']),
                userSpaces=[dict(variant='alpine-3.24',alpineVersion='3.24.4',uid=10001,gid=10001,
                    elfAudit=dict(status='passed',native=True,libc='musl',architecture=arch,targetRid=target['rid'],
                        hostElfCount=1,stockLibraries=[dict(name='musl')]),systemTrustHttps=dict(status='passed'))])
            raw_report = json.dumps(report).encode(); self.reports[arch] = raw_report
            public.append(dict(architecture=arch,rawJsonSize=len(raw_report),rawJsonSha256=hashlib.sha256(raw_report).hexdigest()))
        self.receipt = dict(kind='musl-distribution-publication-receipt',status='published-postverified',identity=identity,
            tag=tag,releaseUrl=f'https://github.com/{musl_contract.REPOSITORY}/releases/tag/{tag}',
            manifestUrl=base+'distribution-manifest.json',signatureUrl=base+'distribution-manifest.json.asc',
            signingFingerprint=self.manifest['signingFingerprint'],
            manifestSha256='d'*64,
            assets=[dict(row,url=base+row['name']) for row in self.manifest['assets']],postVerification=dict(reports=public))
        self.verification = dict(schemaVersion=1,kind='musl-public-verification',repository=musl_contract.REPOSITORY,
            entries=[copy.deepcopy(self.receipt)])

    def validate(self):
        with mock.patch('musl_release.load_qualification_catalog',return_value=self.catalog):
            return validate_publication_metadata(self.manifest,self.receipt,self.reports,verification_manifest=self.verification)

    def test_final_public_verification_is_required_and_binds_exact_bytes(self):
        self.assertEqual(self.validate(),self.manifest)
        saved = self.verification; self.verification = None
        with self.assertRaisesRegex(ValueError,'final musl public'): self.validate()
        self.verification = saved
        self.reports['aarch64'] += b'\n'
        with self.assertRaisesRegex(ValueError,'Actual public native report bytes'): self.validate()

    def test_hash_alone_cannot_admit_failed_runtime_or_changed_source(self):
        report = json.loads(self.reports['x64'])
        report['functionalChecks']['fullIcuCulturesAndCalendars'] = 'failed'
        raw = json.dumps(report).encode(); self.reports['x64'] = raw
        public = next(row for row in self.receipt['postVerification']['reports'] if row['architecture']=='x64')
        public.update(rawJsonSize=len(raw),rawJsonSha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError,'full offline runtime'): self.validate()


if __name__ == '__main__': unittest.main()
