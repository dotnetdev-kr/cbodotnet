"""Verify real ephemeral signatures and immutable public consumer archive promotion."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

import consumer_archive_test as FIXTURES
import consumer_archive as CA
import consumer_archive_release as CR
import consumer_archive_site as SITE
import consumer_archive_status as STATUS


class FakeGitHub:
    def __init__(self):
        self.release=None;self.files={};self.uploads=0;self.corrupt_public=False

    def find(self,tag):return copy.deepcopy(self.release)

    def create(self,manifest):
        self.release=dict(id=1,tag_name=manifest['tag'],target_commitish=manifest['targetCommit'],draft=True,prerelease=False,
            html_url=f'https://github.com/{CA.REPOSITORY}/releases/tag/{manifest["tag"]}',assets=[])
        return copy.deepcopy(self.release)

    def get(self,release):return copy.deepcopy(self.release)

    def upload(self,release,path):
        if path.name in self.files:raise AssertionError('Existing asset overwritten')
        self.files[path.name]=path.read_bytes();self.uploads+=1
        self.release['assets'].append(dict(id=self.uploads,name=path.name,size=path.stat().st_size,state='uploaded',
            digest='sha256:'+hashlib.sha256(path.read_bytes()).hexdigest(),
            browser_download_url=f'https://github.com/{CA.REPOSITORY}/releases/download/{release["tag_name"]}/{path.name}'))

    def download(self,asset,destination,public=False):
        Path(destination).write_bytes(self.files[asset['name']]+(b'changed' if public and self.corrupt_public else b''))

    def publish(self,release):
        self.release['draft']=False;return copy.deepcopy(self.release)


@unittest.skipUnless(os.name=='posix' and shutil.which('gpg') and shutil.which('gpgv'),'Actual signature fixture requires Linux GnuPG')
class ConsumerArchiveReleaseTests(unittest.TestCase):
    def test_signed_full_matrix_promotes_once_rechecks_public_bytes_and_rejects_revocation(self):
        fixture=FIXTURES.ConsumerArchiveTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.root
        home=root/'gnupg';home.mkdir(mode=0o700)
        subprocess.run(['gpg','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase','',
            '--quick-generate-key','Consumer archive fixture <fixture@example.invalid>','ed25519','sign','1d'],check=True,capture_output=True)
        listing=subprocess.check_output(['gpg','--homedir',str(home),'--with-colons','--list-keys'],text=True)
        fingerprint=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        keyring=root/'trusted.gpg'
        with keyring.open('wb') as output:subprocess.run(['gpg','--homedir',str(home),'--export',fingerprint],stdout=output,check=True)
        now=datetime.now(timezone.utc)
        policy=dict(evidenceSigners={fingerprint:dict(state='active',workflow=CA.WORKFLOW,
            notBefore=(now-timedelta(days=1)).isoformat(),notAfter=(now+timedelta(days=1)).isoformat())})
        source=dict(repository=CA.REPOSITORY,workflow=CA.WORKFLOW,commit='a'*40,runId='1',runAttempt='1')
        builds=[];reports=[];inputs=[]
        for arch in ('x64','aarch64'):
            build=fixture.build(arch,'build-'+arch);plan=build['plan']
            report=dict(schemaVersion=1,scope='consumer-archive-installation',status='passed',architecture=arch,
                identity=CA.identity(plan),artifact=build['artifact'],commands=build['commands'],qualifiedPayload=build['qualifiedPayload'],
                orchestration=source,networkForBuild='none',checks=dict.fromkeys(CA.REPORT_CHECKS,'passed'),
                compatibility=dict(required=False),userSpaces=[dict(variant=variant,status='passed',architecture=arch,native=True,
                    networkForBuild='none',checks=dict.fromkeys(CA.REPORT_CHECKS,'passed'),functionalChecks=dict.fromkeys(CA.FUNCTIONAL_CHECKS,'passed')) for variant in plan['validatedUserSpaces']])
            report_file=root/('report-'+arch+'.json');report_file.write_bytes(CA.encoded(report))
            builds.append(root/('build-'+arch)/'package-build.json');reports.append(report_file);inputs.append(fixture.inputs[arch])
        with mock.patch.object(CA,'load_contract',return_value=fixture.contract),mock.patch.object(CR,'load_contract',return_value=fixture.contract):
            output=root/'bundle'
            manifest=CR.create_bundle(builds,reports,inputs,output,fingerprint,keyring,source,gnupg_home=home,policy=policy)
            self.assertEqual('distribution-archive-sdk-10.0.403-r1',manifest['tag'])
            self.assertEqual(2,len(manifest['records']))
            transport=FakeGitHub()
            receipt=CR.publish_bundle(output,keyring,policy=policy,transport=transport)
            self.assertEqual('published-public-bytes-verified',receipt['status'])
            self.assertEqual('pending-native-public-verification',receipt['consumerInstallationStatus'])
            uploads=transport.uploads;CR.publish_bundle(output,keyring,policy=policy,transport=transport)
            self.assertEqual(uploads,transport.uploads)
            public_reports=[]
            for record in manifest['records']:
                report=json.loads((output/record['reportAsset']).read_bytes())
                report.update(scope='published-consumer-archive-installation',manifestSha256=receipt['manifestSha256'],
                    downloadUrl=f'https://github.com/{CA.REPOSITORY}/releases/download/{manifest["tag"]}/'+record['artifactAsset'])
                raw=CA.encoded(report)
                public_reports.append(dict(architecture=record['architecture'],rawJsonSha256=hashlib.sha256(raw).hexdigest(),rawJsonSize=len(raw),report=report))
            complete=SITE.postverified_receipt(receipt,public_reports,manifest,source=source)
            requested=[]
            def metadata_only(url,maximum):
                name=url.rsplit('/',1)[-1];requested.append(name)
                self.assertFalse(name.endswith('.tar.gz'),'Pages attempted to download a large consumer payload')
                return transport.files[name]
            rows=SITE.archive_rows(status=dict(schemaVersion=1,repository=CA.REPOSITORY,publications=[complete]),
                policy=policy,keyring=keyring,fetch=metadata_only)
            self.assertEqual({'x64','aarch64'},{row['architecture'] for row in rows})
            self.assertEqual(2,len(rows));self.assertTrue(requested)
            activated=STATUS.activate(dict(schemaVersion=1,repository=CA.REPOSITORY,publications=[]),receipt,public_reports,
                source=source,policy=policy,keyring=keyring,fetch=metadata_only)
            self.assertEqual([complete],activated['publications'])
            self.assertEqual(activated,STATUS.activate(activated,receipt,public_reports,source=source,
                policy=policy,keyring=keyring,fetch=metadata_only))
            changed=copy.deepcopy(complete)
            next(item for item in changed['assets'] if item['name'].endswith('.tar.gz'))['sha256']='f'*64
            with self.assertRaisesRegex(ValueError,'exact signed asset'):
                SITE.authenticate_receipt(changed,policy=policy,keyring=keyring,fetch=metadata_only,historical=True)
            transport.corrupt_public=True
            with self.assertRaisesRegex(ValueError,'changed existing|Remote.*changed|digest|bytes'):
                CR.publish_bundle(output,keyring,policy=policy,transport=transport)
            fixture.contract['releases']['10.0.403']['manifestSha256']='f'*64
            with self.assertRaisesRegex(ValueError,'no longer admitted'):
                CR.validate_bundle(output,keyring,policy=policy)


if __name__=='__main__':unittest.main()
