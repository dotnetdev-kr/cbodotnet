from pathlib import Path
from contextlib import ExitStack
from datetime import datetime,timedelta,timezone
import hashlib
import copy
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import cbodotnetup_site as SITE


class InstallerSiteGates(unittest.TestCase):
    def additional_fixture(self):
        sdk=dict(sdkVersion='9.0.123',revision=2,rid='linux-x64',requiresLegacyProvider=False,
            sourceManifestSha256='a'*64,targets=[dict(os='ubuntu',versionId='24.04',rid='linux-x64')],
            archive=dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-9.0.123-r2/cbodotnet-sdk-9.0.123-linux-x64-r2.tar.gz',size=3,sha256='b'*64))
        def expand(catalog,legacy):
            catalog['sdks'][0].update(rid='linux-x64',sourceManifestSha256='e'*64)
            catalog['sdks'].append(sdk);catalog['channels']['9.0']='9.0.123-r2'
        status,raws=self.fixture(alter=expand)
        for proof in status['publicNativeVerification']:
            observation=proof['observation']
            observation.update(variant=proof['variant'],architecture=proof['architecture'],binarySha256='c'*64,
                bootstrapSha256='d'*64,additionalSdkQualifications=[])
            if (proof['variant'],proof['architecture'])==('ubuntu-24.04','x64'):
                from cbodotnetup_matrix import SDK_CHECKS,FUNCTIONAL_CHECKS
                row={key:copy.deepcopy(observation[key]) for key in ('catalogSha256','bootstrapBinarySource',
                    'binarySha256','bootstrapSha256','variant','architecture')}
                row.update(sdkVersion=sdk['sdkVersion'],revision=2,rid=sdk['rid'],target=sdk['targets'][0],
                    archive=copy.deepcopy(sdk['archive']),sourceManifestSha256=sdk['sourceManifestSha256'],status='passed',
                    networkForBuild='none',userId=10001,checks=dict.fromkeys(SDK_CHECKS,'passed'),
                    functionalChecks=dict.fromkeys(FUNCTIONAL_CHECKS,'passed'))
                baseline=dict(sdkVersion='10.0.403',packageRevision=3,targetRid='linux-x64',
                    sourceManifestSha256='e'*64,qualifiedPayloadModified=False)
                selected=dict(sdkVersion=sdk['sdkVersion'],packageRevision=2,targetRid='linux-x64',
                    sourceManifestSha256=sdk['sourceManifestSha256'],qualifiedPayloadModified=False)
                row['aliases']=[copy.deepcopy(baseline),copy.deepcopy(baseline),selected]
                observation['additionalSdkQualifications']=[row]
        status['nativeQualification']=copy.deepcopy(status['publicNativeVerification'])
        for proof in status['nativeQualification']:
            proof['observation']['bootstrapBinarySource']='protected-frozen-candidate'
            for row in proof['observation']['additionalSdkQualifications']:
                row['bootstrapBinarySource']='protected-frozen-candidate'
        return status,raws

    def fixture(self,dual=True,alter=None):
        now=datetime.now(timezone.utc)
        common=dict(kind='cbodotnetup-installation-catalog',sequence=123,
            issuedAt=(now-timedelta(minutes=1)).isoformat(),expiresAt=(now+timedelta(days=30)).isoformat(),
            signingFingerprint='test-pinned-key',revoked=[],tools=[{'version':'0.1.0'},{'version':'0.2.0'}])
        legacy=dict(common,schemaVersion=1,channels={'10.0':'10.0.403-r2'},sdks=[])
        for rid,arch in (('linux-x64','x64'),('linux-arm64','aarch64')):
            legacy['sdks'].append(dict(sdkVersion='10.0.403',revision=2,rid=rid,
                archive=dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-10.0.403-r2/cbodotnet-sdk-10.0.403-linux-'+arch+'-branded-r2.tar.gz')))
        catalog=dict(common,schemaVersion=2,channels={'10.0':'10.0.403-r3'},sdks=[{'sdkVersion':'10.0.403','revision':3}]) if dual else legacy
        if alter:alter(catalog,legacy)
        encode=lambda value:json.dumps(value,sort_keys=True).encode()
        digest=lambda raw:hashlib.sha256(raw).hexdigest()
        raws={'catalog.json':encode(catalog),'catalog.json.asc':b'catalog-signature','get-cbodotnetup.py':b'authenticated bootstrap'}
        if dual:raws.update({'catalog-v1.json':encode(legacy),'catalog-v1.json.asc':b'legacy-signature'})
        freeze={'files':[dict(path=name,size=len(raw),sha256=digest(raw)) for name,raw in raws.items()]}
        raws.update({'freeze.json':encode(freeze),'freeze.json.asc':b'freeze-signature'})
        base='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-123/'
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',version='0.2.0' if dual else '0.1.0',
            catalogSequence=123,catalogSha256=digest(raws['catalog.json']),catalogRelease=dict(tag='cbodotnetup-catalog-123',
            assets=[dict(name=name,url=base+name,size=len(raw),sha256=digest(raw)) for name,raw in raws.items()]))
        if dual:status.update(legacyCatalogSequence=123,legacyCatalogSha256=digest(raws['catalog-v1.json']))
        proofs=[]
        for variant in ('ubuntu-24.04','debian-13','fedora-45','rocky-9.8'):
            for arch in ('x64','aarch64'):
                observation=dict(status='passed',bootstrapBinarySource='public-https',catalogSha256=status['catalogSha256'])
                if dual:observation['migration']=dict(status='passed',protocol='actual-0.1.0-self-update-rollback-reupgrade',legacyCatalogSha256=status['legacyCatalogSha256'])
                proofs.append(dict(variant=variant,architecture=arch,observation=observation))
        status['publicNativeVerification']=proofs
        return status,raws

    def io(self,raws):
        context=ExitStack()
        context.enter_context(patch.object(SITE,'get_bytes',side_effect=lambda url,maximum:raws[url.rsplit('/',1)[-1]]))
        context.enter_context(patch.object(SITE.subprocess,'run'))
        context.enter_context(patch.object(SITE,'load_status',return_value={}))
        verify=context.enter_context(patch.object(SITE,'verify_report_signature'))
        return context,verify

    def test_no_activated_status_publishes_no_installer_feed(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'ROOT',Path(temporary)),patch.object(SITE,'get_bytes') as network:
            output=Path(temporary)/'site'
            self.assertEqual(SITE.prepare(output),'')
            self.assertFalse(output.exists());network.assert_not_called()

    def test_pending_native_qualification_cannot_enable_the_feed(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='prepared')
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_noncanonical_release_identity_is_rejected_before_network(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',catalogSequence=123,catalogRelease=dict(tag='other-123'))
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_untrusted_bootstrap_asset_origin_cannot_be_rendered(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',catalogSequence=123,
            catalogRelease=dict(tag='cbodotnetup-catalog-123',assets=[dict(name='catalog.json',url='https://evil.example/catalog.json',size=1,sha256='a'*64)]))
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_activated_old_release_keeps_original_feed_without_migration_proof(self):
        status,raws=self.fixture(dual=False);context,verify=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            output=Path(temporary)/'site';markup=SITE.prepare(output,status)
            self.assertEqual((output/'cbodotnetup/catalog.json').read_bytes(),raws['catalog.json'])
            self.assertFalse((output/'cbodotnetup/v2').exists())
            self.assertIn('cbodotnetup/catalog.json',markup)
            self.assertEqual({call.args[0].name for call in verify.call_args_list},{'catalog.json','freeze.json'})

    def test_paired_feeds_publish_exact_bytes_to_separate_paths(self):
        status,raws=self.fixture();context,verify=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            output=Path(temporary)/'site';markup=SITE.prepare(output,status)
            for suffix in ('','.asc'):
                self.assertEqual((output/('cbodotnetup/catalog.json'+suffix)).read_bytes(),raws['catalog-v1.json'+suffix])
                self.assertEqual((output/('cbodotnetup/v2/catalog.json'+suffix)).read_bytes(),raws['catalog.json'+suffix])
            self.assertEqual((output/'cbodotnetup/get-cbodotnetup.py').read_bytes(),raws['get-cbodotnetup.py'])
            self.assertIn('href="cbodotnetup/v2/catalog.json"',markup)
            self.assertEqual({call.args[0].name for call in verify.call_args_list},{'catalog.json','catalog-v1.json','freeze.json'})

    def test_additional_sdk_requires_both_candidate_and_public_cell_proof(self):
        for phase in ('nativeQualification','publicNativeVerification'):
            status,raws=self.additional_fixture()
            for proof in status[phase]:proof['observation']['additionalSdkQualifications']=[]
            context,_=self.io(raws)
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as temporary,context:
                with self.assertRaisesRegex(ValueError,'Every additional SDK'):SITE.prepare(Path(temporary),status)
                self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_complete_cell_proofs_expose_only_catalog_sdk_versions(self):
        status,raws=self.additional_fixture();context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            markup=SITE.prepare(Path(temporary),status)
            self.assertIn('<code>10.0.403</code>, <code>9.0.123</code>',markup)
            self.assertNotIn('7.0.120',markup)
            self.assertIn('Versions, lifecycle',markup)

    def test_mismatched_additional_archive_cannot_enable_the_feed(self):
        status,raws=self.additional_fixture()
        status['publicNativeVerification'][0]['observation']['additionalSdkQualifications'][0]['archive']['sha256']='0'*64
        context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'differs'):SITE.prepare(Path(temporary),status)
            self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_public_proof_cannot_substitute_for_candidate_phase(self):
        status,raws=self.additional_fixture();status['nativeQualification']=status['publicNativeVerification'];context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'candidate reports'):SITE.prepare(Path(temporary),status)

    def test_schema2_cannot_replace_the_legacy_endpoint_without_legacy_status(self):
        status,raws=self.fixture();del status['legacyCatalogSha256'];del status['legacyCatalogSequence']
        context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'schema'):SITE.prepare(Path(temporary),status)
            self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_incomplete_paired_identity_fails_before_network(self):
        status,_=self.fixture();del status['legacyCatalogSha256']
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaisesRegex(ValueError,'Incomplete paired'):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_signed_but_incompatible_legacy_catalog_is_rejected(self):
        alterations=[lambda c,l:l.update(sequence=122),lambda c,l:l.update(tools=[]),
            lambda c,l:l.update(newField='breaks-old-client'),
            lambda c,l:l['sdks'][0]['archive'].update(url=l['sdks'][0]['archive']['url'].replace('-branded','')),
            lambda c,l:l['sdks'][0].update(revision=3)]
        for alter in alterations:
            status,raws=self.fixture(alter=alter);context,_=self.io(raws)
            with self.subTest(alter=alter),tempfile.TemporaryDirectory() as temporary,context:
                with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
                self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_legacy_catalog_must_match_activated_hash_and_sequence(self):
        for key,value in (('legacyCatalogSha256','0'*64),('legacyCatalogSequence',122)):
            status,raws=self.fixture();status[key]=value;context,_=self.io(raws)
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temporary,context:
                with self.assertRaisesRegex(ValueError,'Activated legacy'):SITE.prepare(Path(temporary),status)

    def test_each_public_target_needs_actual_old_client_migration_bound_to_legacy_feed(self):
        changes=[lambda proof:proof.pop('migration'),lambda proof:proof['migration'].update(status='pending'),
            lambda proof:proof['migration'].update(protocol='mocked-migration'),
            lambda proof:proof['migration'].update(legacyCatalogSha256='0'*64)]
        for change in changes:
            status,raws=self.fixture();change(status['publicNativeVerification'][-1]['observation']);context,_=self.io(raws)
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary,context:
                with self.assertRaisesRegex(ValueError,'old-client migration'):SITE.prepare(Path(temporary),status)
                self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_all_eight_distinct_public_targets_are_required(self):
        status,raws=self.fixture();status['publicNativeVerification'][-1]=status['publicNativeVerification'][0];context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'eight public'):SITE.prepare(Path(temporary),status)

    def test_legacy_signature_is_verified_before_serving_any_feed(self):
        status,raws=self.fixture();context,verify=self.io(raws)
        def reject_legacy(path,*args):
            if path.name=='catalog-v1.json':raise ValueError('Bad legacy signature')
        verify.side_effect=reject_legacy
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'Bad legacy signature'):SITE.prepare(Path(temporary),status)
            self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_legacy_feed_must_be_part_of_the_signed_frozen_inventory(self):
        status,raws=self.fixture();freeze=json.loads(raws['freeze.json']);freeze['files']=[item for item in freeze['files'] if item['path']!='catalog-v1.json']
        raws['freeze.json']=json.dumps(freeze).encode()
        asset=next(a for a in status['catalogRelease']['assets'] if a['name']=='freeze.json')
        asset.update(size=len(raws['freeze.json']),sha256=hashlib.sha256(raws['freeze.json']).hexdigest());context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'frozen bootstrap inventory'):SITE.prepare(Path(temporary),status)

    def test_expired_paired_feeds_are_not_written(self):
        def expire(c,l):
            for value in (c,l):
                value.update(issuedAt=(datetime.now(timezone.utc)-timedelta(days=40)).isoformat(),
                    expiresAt=(datetime.now(timezone.utc)-timedelta(days=10)).isoformat())
            l['issuedAt']=c['issuedAt'];l['expiresAt']=c['expiresAt']
        status,raws=self.fixture(alter=expire);context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            self.assertIn('expired',SITE.prepare(Path(temporary),status))
            self.assertFalse((Path(temporary)/'cbodotnetup').exists())

    def test_lifetime_bound_includes_fractional_days(self):
        def too_long(c,l):
            c['expiresAt']=(datetime.fromisoformat(c['issuedAt'])+timedelta(days=31,hours=1)).isoformat();l['expiresAt']=c['expiresAt']
        status,raws=self.fixture(alter=too_long);context,_=self.io(raws)
        with tempfile.TemporaryDirectory() as temporary,context:
            with self.assertRaisesRegex(ValueError,'lifetime'):SITE.prepare(Path(temporary),status)


if __name__=='__main__':unittest.main()
