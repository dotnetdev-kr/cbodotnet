from pathlib import Path
from datetime import datetime,timezone
import copy
import hashlib
import tempfile
import sys
import shutil
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import cbodotnetup_release as UP


class InstallerReleaseTests(unittest.TestCase):
    def test_legacy_archive_pin_is_independent_of_the_new_neutral_revision(self):
        def receipt(revision):
            return dict(identity=dict(sdkVersion='10.0.403',packageRevision=revision),status='published-postverified',
                        postVerification=dict(reports=['native-x64','native-aarch64'],workflow={'runId':'123'}))
        pinned=receipt(2);newer=receipt(3);manifest={'records':['signed archive records']}
        with patch.object(UP,'load_archive_status',return_value=dict(publications=[receipt(1),newer,pinned])),\
                patch.object(UP,'authenticate_receipt',return_value=manifest) as authenticate,\
                patch.object(UP,'postverified_receipt') as postverified:
            legacy=dict(UP.load(UP.POLICY),archiveRevisions=UP.load(UP.POLICY)['legacyArchiveRevisions'])
            self.assertEqual(UP.selected_archive('10.0.403',policy=legacy),(pinned,manifest))
            authenticate.assert_called_once_with(pinned,historical=True)
            postverified.assert_called_once_with(pinned,pinned['postVerification']['reports'],manifest,
                                                 source=pinned['postVerification']['workflow'])

    def test_installer_archive_pin_never_falls_back_to_a_different_revision(self):
        other=dict(identity=dict(sdkVersion='10.0.403',packageRevision=3),status='published-postverified')
        with patch.object(UP,'load_archive_status',return_value=dict(publications=[other])),\
                patch.object(UP,'authenticate_receipt') as authenticate:
            with self.assertRaisesRegex(ValueError,'exact pinned'):
                UP.selected_archive('10.0.403',policy={'archiveRevisions':{'10.0.403':2}})
            authenticate.assert_not_called()

    def test_missing_or_invalid_archive_pin_is_rejected_before_source_lookup(self):
        for revision in (None,True,0,-1,'2',2**31):
            with self.subTest(revision=revision),patch.object(UP,'load_archive_status') as status:
                with self.assertRaisesRegex(ValueError,'revision pin'):
                    UP.selected_archive('10.0.403',policy={'archiveRevisions':{'10.0.403':revision}})
                status.assert_not_called()

    def test_ambiguous_or_unverified_pinned_archive_is_rejected(self):
        pinned=dict(identity=dict(sdkVersion='10.0.403',packageRevision=3),status='published-public-bytes-verified')
        with patch.object(UP,'authenticate_receipt') as authenticate:
            with patch.object(UP,'load_archive_status',return_value=dict(publications=[pinned,pinned])):
                with self.assertRaisesRegex(ValueError,'published once'):UP.selected_archive('10.0.403')
            with patch.object(UP,'load_archive_status',return_value=dict(publications=[pinned])):
                with self.assertRaisesRegex(ValueError,'not post-verified'):UP.selected_archive('10.0.403')
            authenticate.assert_not_called()

    def test_new_client_pins_neutral_revision_without_changing_the_old_feed_pin(self):
        policy=UP.load(UP.POLICY)
        self.assertEqual(policy['version'],'0.5.1')
        self.assertEqual(policy['initialSdkVersions'],['10.0.403','9.0.123','8.0.133','7.0.120','6.0.136','5.0.214','3.1.426','3.0.103'])
        self.assertEqual(policy['archiveRevisions'],{'10.0.403':3,'9.0.123':2,'8.0.133':2,'7.0.120':2,'6.0.136':2,'5.0.214':2,'3.1.426':2,'3.0.103':2})
        self.assertEqual(policy['legacyArchiveRevisions'],{'10.0.403':2})
        targets=UP.reviewed_sdk_targets(policy)
        self.assertEqual(sum(len(variants) for sdk in targets.values() for variants in sdk.values()),64)

    def paired_catalogs(self,directory,*,previous_sequence=80,previous_tools=None,previous_revoked=None,provider_aware=False):
        policy=UP.load(UP.POLICY)
        if provider_aware:policy=dict(policy,version='0.4.0')
        if not provider_aware:
            versions=policy['modernSdkVersions']
            policy=dict(policy,version='0.3.0',initialSdkVersions=versions,
                archiveRevisions={v:policy['archiveRevisions'][v] for v in versions},
                sdkTargets={v:policy['sdkTargets'][v] for v in versions})
        source=dict(repository='dotnetdev-kr/cbodotnet',commit='b'*40,workflow=UP.WORKFLOW,runId='123',runAttempt='1')
        builds={}
        for arch,rid in (('x64','linux-x64'),('aarch64','linux-arm64')):
            target=directory/arch;target.mkdir();(target/('cbodotnetup-'+rid)).write_bytes(b'native-'+rid.encode())
            (target/('cbodotnetup-'+rid+'.LICENSE.txt')).write_bytes(b'notices')
            UP.save(target/'build.json',dict(sourceInputs={},source=source,version=policy['version'],architecture=arch,rid=rid,
                securityTests='passed',nativeRuntime=policy['nativeRuntime'],container=UP.MULTI.BASES['rocky-9.8'][arch],
                buildSdk=dict(name='cbodotnet-sdk-10.0.403-linux-'+arch+'-r3.tar.gz'),artifacts=[]))
            builds[arch]=target
        def sdk(selected,schema):
            marker='-branded' if schema==1 else ''
            return [dict(sdkVersion=version,revision=selected['archiveRevisions'][version],rid=rid,
                requiresLegacyProvider=version in ('5.0.214','3.1.426','3.0.103'),
                archive=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{selected["archiveRevisions"][version]}/cbodotnet-sdk-{version}-linux-{arch}{marker}-r{selected["archiveRevisions"][version]}.tar.gz'))
                for version in selected['initialSdkVersions'] for arch,rid in (('x64','linux-x64'),('aarch64','linux-arm64'))]
        previous=dict(sequence=previous_sequence,
            revoked=previous_revoked if previous_revoked is not None else ['tool/0.0.1/linux-x64'],
            tools=previous_tools if previous_tools is not None else [dict(version=v,rid=r)
                for v in (('0.1.0','0.2.0','0.3.0') if provider_aware else ('0.1.0','0.2.0')) for r in ('linux-x64','linux-arm64')])
        real_load=UP.load
        providers=[dict(providerId='test-provider',revision=1,rid=rid,minimumGlibc='2.34') for rid in ('linux-x64','linux-arm64')]
        provider_module=SimpleNamespace(catalog_provider_metadata=lambda sdks:(providers,[]),validate_provider_catalog=lambda *args:None)
        with patch.object(UP,'load',side_effect=lambda path:policy if Path(path)==UP.POLICY else real_load(path)),\
                patch.dict(sys.modules,{'cbodotnetup_providers':provider_module}),\
                patch.object(UP,'source_identity',return_value=source),patch.object(UP,'tool_inputs',return_value={}),\
                patch.object(UP,'previous_catalog',return_value=previous),\
                patch.object(UP,'catalog_sdks',side_effect=sdk):
            UP.catalog(directory,builds,now=datetime(2026,11,6,tzinfo=timezone.utc),sequence=88)
        return UP.load(directory/'catalog.json'),UP.load(directory/'catalog-v1.json'),UP.load(directory/'catalog-v1-bootstrap.json')

    def test_provider_generation_binds_modern_projection_and_keeps_old_clients_modern_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory,provider_aware=True)
            projection=UP.load(directory/'catalog-v2.json')
            self.assertEqual(current['schemaVersion'],3);self.assertEqual(projection['schemaVersion'],2)
            self.assertEqual(len(current['sdks']),16);self.assertEqual(len(projection['sdks']),10)
            self.assertEqual(current['tools'],projection['tools']);self.assertEqual(len(current['tools']),8)
            self.assertTrue(all(not sdk['requiresLegacyProvider'] for sdk in projection['sdks']))
            self.assertEqual(current['compatibilityCatalog']['sha256'],UP.descriptor(directory/'catalog-v2.json')['sha256'])
            self.assertEqual(set(current)-set(projection),{'providers','providerBindings','compatibilityCatalog'})
            for version in ('0.2.0','0.3.0'):
                prior=UP.load(directory/f'catalog-v2-tool-{version[:3]}.json')
                self.assertEqual(prior,dict(projection,sequence=87,tools=[tool for tool in projection['tools'] if tool['version']==version]))
            self.assertEqual(len(UP.load(directory/'catalog-v3-revoked.json')['revoked'])-len(current['revoked']),6)

    def test_provider_generation_rejects_changed_projection_and_abi_fixture(self):
        provider_module=SimpleNamespace(validate_provider_catalog=lambda *args:None)
        for mutation in ('projection','abi-fixture','old-project-client','unknown-field'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory,provider_aware=True)
                if mutation=='projection':
                    value=UP.load(directory/'catalog-v2.json');value['sdks'].pop();UP.save(directory/'catalog-v2.json',value)
                elif mutation=='abi-fixture':
                    value=UP.load(directory/'catalog-v3-provider-incompatible.json');value['providers'][0]['minimumGlibc']='2.34';UP.save(directory/'catalog-v3-provider-incompatible.json',value)
                elif mutation=='old-project-client':
                    value=UP.load(directory/'catalog-v2-tool-0.3.json');value['tools']=current['tools'];UP.save(directory/'catalog-v2-tool-0.3.json',value)
                else:
                    current['unsafeUnknown']=True;UP.save(directory/'catalog.json',current)
                with patch.dict(sys.modules,{'cbodotnetup_providers':provider_module}),self.assertRaises(ValueError):
                    UP.verify_catalog_pair(directory,tool_version='0.4.0')

    def test_paired_catalogs_keep_old_shape_upgrade_tools_and_independent_sdk_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            current,legacy,bootstrap=self.paired_catalogs(Path(temporary))
            self.assertEqual(current['schemaVersion'],2);self.assertEqual(legacy['schemaVersion'],1)
            self.assertEqual(set(current),set(legacy))
            self.assertEqual(current['sequence'],legacy['sequence']);self.assertEqual(current['expiresAt'],legacy['expiresAt'])
            self.assertEqual(current['tools'],legacy['tools']);self.assertEqual(len(current['tools']),6)
            self.assertEqual(current['revoked'],['tool/0.0.1/linux-x64'])
            self.assertEqual(current['channels'],{'10.0':'10.0.403-r3','9.0':'9.0.123-r2','8.0':'8.0.133-r2','7.0':'7.0.120-r2','6.0':'6.0.136-r2'})
            self.assertEqual(legacy['channels'],{'10.0':'10.0.403-r2'})
            self.assertEqual(len(current['sdks']),10)
            self.assertEqual({s['sdkVersion'] for s in legacy['sdks']},{'10.0.403'})
            self.assertTrue(all('-branded-' not in s['archive']['url'] for s in current['sdks']))
            self.assertTrue(all('-branded-r2.tar.gz' in s['archive']['url'] for s in legacy['sdks']))
            self.assertEqual(bootstrap['sequence'],87)
            self.assertEqual({t['version'] for t in bootstrap['tools']},{'0.1.0'})
            expired=UP.load(Path(temporary)/'catalog-v1-expired.json')
            self.assertEqual(expired['sequence'],86)
            self.assertEqual(expired['issuedAt'],'2026-10-05T00:00:00Z')
            self.assertEqual(expired['expiresAt'],'2026-11-04T00:00:00Z')
            self.assertEqual(expired['tools'],bootstrap['tools'])
            revoked=UP.load(Path(temporary)/'catalog-v2-revoked.json')
            expected=set(current['revoked'])|{f'{s["sdkVersion"]}-r{s["revision"]}/{s["rid"]}' for s in current['sdks'] if s['sdkVersion']!='10.0.403'}
            self.assertEqual(revoked,dict(current,revoked=sorted(expected)))
            self.assertFalse(any(value.startswith('10.0.403-') for value in revoked['revoked']))
            prior=UP.load(Path(temporary)/'catalog-v2-tool-0.2.json')
            self.assertEqual(prior,dict(current,sequence=87,tools=[t for t in current['tools'] if t['version']=='0.2.0']))
            self.assertEqual({t['rid'] for t in prior['tools']},{'linux-x64','linux-arm64'})

    def test_project_selection_catalog_requires_actual_unrevoked_previous_tool_on_both_cpus(self):
        all_tools=[dict(version=v,rid=r) for v in ('0.1.0','0.2.0') for r in ('linux-x64','linux-arm64')]
        for tools,revoked in ((all_tools[:-1],[]),(all_tools,['tool/0.2.0/linux-x64'])):
            with self.subTest(tools=tools,revoked=revoked),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError,'Actual 0.2.0 binaries'):
                    self.paired_catalogs(Path(temporary),previous_tools=tools,previous_revoked=revoked)

    def test_previous_tool_fixture_binds_every_sdk_trust_field_and_exact_previous_tool_set(self):
        for mutation in ('missing','sequence','sdk','issuedAt','revoked','tools'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory)
                path=directory/'catalog-v2-tool-0.2.json';prior=UP.load(path)
                if mutation=='missing':path.unlink()
                elif mutation=='sequence':prior['sequence']-=1
                elif mutation=='sdk':prior['sdks'].pop()
                elif mutation=='issuedAt':prior['issuedAt']='2026-11-05T00:00:00Z'
                elif mutation=='revoked':prior['revoked']=[]
                else:prior['tools']=current['tools']
                if mutation!='missing':UP.save(path,prior)
                with self.assertRaises((ValueError,FileNotFoundError)):UP.verify_catalog_pair(directory)

    def test_optional_previous_tool_fixture_is_checked_even_for_a_historical_tool_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory)
            for value,name in ((current,'catalog.json'),(legacy,'catalog-v1.json')):
                value['tools']=[t for t in value['tools'] if t['version']!='0.3.0'];UP.save(directory/name,value)
            revoked=UP.load(directory/'catalog-v2-revoked.json');revoked['tools']=current['tools']
            UP.save(directory/'catalog-v2-revoked.json',revoked)
            prior=UP.load(directory/'catalog-v2-tool-0.2.json');prior['sequence']-=1
            UP.save(directory/'catalog-v2-tool-0.2.json',prior)
            with self.assertRaisesRegex(ValueError,'Previous-tool test fixture'):UP.verify_catalog_pair(directory)

    def test_previous_tool_fixture_is_authenticated_and_frozen_with_the_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);self.paired_catalogs(directory)
            original=directory/'get-cbodotnetup-v0.1.0.py';original.write_bytes(b'original bootstrap test input')
            bootstrap=dict(url=UP.LEGACY_BOOTSTRAP['url'],**{k:UP.descriptor(original)[k] for k in ('size','sha256')})
            for path in directory.glob('catalog*.json'):Path(str(path)+'.asc').write_bytes(b'signature test input')
            freeze=dict(schemaVersion=1,kind='cbodotnetup-frozen-candidate',version='0.3.0',legacyBootstrap=bootstrap,
                source=dict(repository='dotnetdev-kr/cbodotnet',workflow=UP.WORKFLOW),
                files=[UP.descriptor(p)|dict(path=p.relative_to(directory).as_posix()) for p in sorted(directory.rglob('*')) if p.is_file()])
            UP.save(directory/'freeze.json',freeze);(directory/'freeze.json.asc').write_bytes(b'freeze signature test input')
            with patch.object(UP,'LEGACY_BOOTSTRAP',bootstrap),patch.object(UP,'run'),patch.object(UP,'load_status',return_value={}),\
                    patch.object(UP,'verify_report_signature') as authenticate:
                self.assertEqual(UP.verify_bundle(directory),freeze)
                self.assertTrue(any(call.args[0]==directory/'catalog-v2-tool-0.2.json'
                    and call.args[1]==directory/'catalog-v2-tool-0.2.json.asc' for call in authenticate.call_args_list))
                (directory/'catalog-v2-tool-0.2.json.asc').unlink()
                with self.assertRaisesRegex(ValueError,'ordinary artifact'):UP.verify_bundle(directory)

    def test_migration_pair_rejects_legacy_shape_drift_cross_generation_names_and_bad_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);current,legacy,bootstrap=self.paired_catalogs(directory)
            cases=[('catalog-v1.json',dict(legacy,newField=True)),
                   ('catalog-v1.json',dict(legacy,sequence=legacy['sequence']+1)),
                   ('catalog-v1.json',dict(legacy,tools=legacy['tools'][:2])),
                   ('catalog-v1-bootstrap.json',dict(bootstrap,tools=current['tools']))]
            wrong=copy.deepcopy(current);wrong['sdks'][0]['archive']['url']=legacy['sdks'][0]['archive']['url'];cases.append(('catalog.json',wrong))
            for name,value in cases:
                with self.subTest(name=name,value=value):
                    UP.save(directory/'catalog.json',current);UP.save(directory/'catalog-v1.json',legacy);UP.save(directory/'catalog-v1-bootstrap.json',bootstrap)
                    UP.save(directory/name,value)
                    with self.assertRaises(ValueError):UP.verify_catalog_pair(directory)

    def test_historical_v1_bundle_remains_readable_without_new_companion_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);UP.save(directory/'catalog.json',dict(schemaVersion=1))
            self.assertEqual(UP.verify_catalog_pair(directory),({'schemaVersion':1},None))
            with self.assertRaisesRegex(ValueError,'schema2 candidate'):UP.verify_catalog_pair(directory,tool_version='0.3.0')

    def test_renewal_cannot_reuse_or_decrease_a_published_sequence(self):
        for previous in (88,89):
            with self.subTest(previous=previous),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError,'advance'):
                    self.paired_catalogs(Path(temporary),previous_sequence=previous)

    def test_source_admission_binds_exact_archive_naming_to_catalog_schema(self):
        canonical=b'{"source":"reviewed"}';sha=hashlib.sha256(canonical).hexdigest();version='10.0.403'
        contract=dict(releases={version:dict(manifestSha256=sha)},operatingSystems={'ubuntu-24.04':dict(id='ubuntu',versionId='24.04',dependencies=['libicu'])})
        policy=dict(initialSdkVersions=[version],targets=['ubuntu-24.04'],architectures=['x64','aarch64'],
            archiveRevisions={version:3},sdkTargets={version:dict(x64=['ubuntu-24.04'],aarch64=[])})
        for schema,marker,revision,accepted in ((1,'-branded',2,True),(2,'',3,True),(1,'',3,False),(2,'-branded',2,False),(2,'-unbranded',3,False)):
            name=f'cbodotnet-sdk-{version}-linux-x64{marker}-r{revision}.tar.gz'
            asset=dict(name=name,url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/{name}',size=1,sha256='a'*64)
            plan=dict(targetRid='linux-x64',sourceManifestSha256=sha,sourceManifestUrl=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-{version}/release-manifest.json',
                compatibility=dict(required=False),producer=dict(origin='reviewed'),evidence=dict(url='evidence',size=1,sha256='b'*64),
                licensePaths=['LICENSE.txt','ThirdPartyNotices.txt'],securitySupport='community-build-no-additional-security-maintenance')
            manifest=dict(records=[dict(architecture='x64',artifactAsset=name,build=dict(directory='root',plan=plan))])
            receipt=dict(identity=dict(packageRevision=revision),assets=[asset])
            with self.subTest(schema=schema,marker=marker),patch.object(UP,'load_contract',return_value=contract),\
                    patch.object(UP,'selected_archive',return_value=(receipt,manifest)),patch.object(UP,'get_bytes',return_value=canonical):
                if accepted:self.assertEqual(UP.catalog_sdks(policy,schema=schema)[0]['archive']['url'],asset['url'])
                else:
                    with self.assertRaisesRegex(ValueError,'schema/naming'):UP.catalog_sdks(policy,schema=schema)

    def test_missing_or_invalid_per_sdk_cells_fail_before_archive_lookup(self):
        original=UP.load(UP.POLICY);version='9.0.123'
        cases=[]
        missing=copy.deepcopy(original);missing.pop('sdkTargets');cases.append(missing)
        missing=copy.deepcopy(original);missing['sdkTargets'].pop(version);cases.append(missing)
        missing=copy.deepcopy(original);missing['sdkTargets'][version].pop('aarch64');cases.append(missing)
        wrong=copy.deepcopy(original);wrong['sdkTargets'][version]['x64']=['alpine-3.24'];cases.append(wrong)
        wrong=copy.deepcopy(original);wrong['sdkTargets'][version]['x64']=['ubuntu-24.04','ubuntu-24.04'];cases.append(wrong)
        wrong=copy.deepcopy(original);wrong['sdkTargets'][version]['x64']='ubuntu-24.04';cases.append(wrong)
        wrong=copy.deepcopy(original);wrong['sdkTargets'][version]={'x64':[],'aarch64':[]};cases.append(wrong)
        wrong=copy.deepcopy(original);wrong['archiveRevisions'][version]=True;cases.append(wrong)
        wrong=copy.deepcopy(original);wrong['sdkTargets']['2.1.999']=wrong['sdkTargets'][version];cases.append(wrong)
        for policy in cases:
            with self.subTest(policy=policy),patch.object(UP,'selected_archive') as archive:
                with self.assertRaises(ValueError):UP.catalog_sdks(policy,schema=2)
                archive.assert_not_called()

    def test_sdk_records_use_only_their_explicit_os_cpu_cells(self):
        canonical=b'{"source":"reviewed"}';digest=hashlib.sha256(canonical).hexdigest()
        versions=['9.0.123','8.0.133']
        systems={'ubuntu-24.04':dict(id='ubuntu',versionId='24.04',dependencies=['icu-ubuntu']),
                 'debian-13':dict(id='debian',versionId='13',dependencies=['icu-debian'])}
        policy=dict(initialSdkVersions=versions,archiveRevisions={v:2 for v in versions},
            targets=list(systems),architectures=['x64','aarch64'],sdkTargets={
                '9.0.123':dict(x64=['ubuntu-24.04'],aarch64=[]),
                '8.0.133':dict(x64=['debian-13'],aarch64=['ubuntu-24.04'])})
        contract=dict(releases={v:dict(manifestSha256=digest) for v in versions},operatingSystems=systems)
        def archive(version,**unused):
            assets=[];records=[]
            for arch,rid in (('x64','linux-x64'),('aarch64','linux-arm64')):
                name=f'cbodotnet-sdk-{version}-linux-{arch}-r2.tar.gz'
                assets.append(dict(name=name,url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r2/{name}',size=1,sha256='a'*64))
                plan=dict(targetRid=rid,sourceManifestSha256=digest,
                    sourceManifestUrl=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-{version}/release-manifest.json',
                    compatibility=dict(required=False),producer=dict(origin='reviewed'),
                    evidence=dict(url='evidence',size=1,sha256='b'*64),licensePaths=['LICENSE.txt','ThirdPartyNotices.txt'],
                    securitySupport='community-build-no-additional-security-maintenance')
                records.append(dict(architecture=arch,artifactAsset=name,build=dict(directory='root',plan=plan)))
            return dict(identity=dict(packageRevision=2),assets=assets),dict(records=records)
        with patch.object(UP,'load_contract',return_value=contract),patch.object(UP,'selected_archive',side_effect=archive),\
                patch.object(UP,'get_bytes',return_value=canonical):
            records=UP.catalog_sdks(policy,schema=2)
        self.assertEqual([(r['sdkVersion'],r['rid']) for r in records],
            [('9.0.123','linux-x64'),('8.0.133','linux-x64'),('8.0.133','linux-arm64')])
        self.assertEqual([(r['targets'][0]['os'],r['dependencies']) for r in records],
            [('ubuntu',['icu-ubuntu']),('debian',['icu-debian']),('ubuntu',['icu-ubuntu'])])

    def test_revoked_fixture_must_revoke_exact_new_sdk_set_and_preserve_every_other_field(self):
        for mutation in ('missing','omit-sdk','revoke-sdk10','change-archive','leak-into-v1'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory)
                path=directory/'catalog-v2-revoked.json';fixture=UP.load(path)
                if mutation=='missing':path.unlink()
                elif mutation=='omit-sdk':fixture['revoked'].pop();UP.save(path,fixture)
                elif mutation=='revoke-sdk10':fixture['revoked'].append('10.0.403-r3/linux-x64');UP.save(path,fixture)
                elif mutation=='change-archive':fixture['sdks'][0]['archive']['sha256']='c'*64;UP.save(path,fixture)
                else:
                    legacy['sdks'].append(current['sdks'][2]);UP.save(directory/'catalog-v1.json',legacy)
                with self.assertRaises((ValueError,FileNotFoundError)):UP.verify_catalog_pair(directory)

    def test_historical_sdk10_only_v2_bundle_needs_no_new_revocation_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);current,legacy,unused=self.paired_catalogs(directory)
            current['sdks']=[s for s in current['sdks'] if s['sdkVersion']=='10.0.403']
            current['channels']={'10.0':'10.0.403-r3'}
            current['tools']=[t for t in current['tools'] if t['version']!='0.3.0']
            legacy['tools']=current['tools']
            UP.save(directory/'catalog.json',current)
            UP.save(directory/'catalog-v1.json',legacy)
            (directory/'catalog-v2-revoked.json').unlink()
            (directory/'catalog-v2-tool-0.2.json').unlink()
            self.assertEqual(UP.verify_catalog_pair(directory),(current,legacy))

    def test_patched_runtime_is_outside_the_actual_advisory_range(self):
        self.assertTrue(UP.affected('10.0.13','[10.0.0, 10.0.14)'))
        self.assertFalse(UP.affected('10.0.14','[10.0.0, 10.0.14)'))
        self.assertFalse(UP.affected('10.0.14','[11.0.0-preview.1.26104.118, 11.0.0-rc.3.26522.148)'))

    def test_inclusive_exclusive_open_and_exact_ranges(self):
        self.assertTrue(UP.affected('1.2.3','[1.2.3]'))
        self.assertTrue(UP.affected('1.2.3','(, 1.2.3]'))
        self.assertFalse(UP.affected('1.2.3','(, 1.2.3)'))
        self.assertTrue(UP.affected('1.2.3','[1.2.3, )'))
        self.assertFalse(UP.affected('1.2.3','(1.2.3, )'))
        for value in ('1.2.*','>=1.2.3','[1.2.3,2.0.0],[3.0.0,4.0.0]'):
            with self.subTest(value=value),self.assertRaises(ValueError):UP.affected('1.2.3',value)

    def test_an_untrusted_asset_origin_is_rejected_before_any_io(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(UP.urllib.request,'urlopen') as network:
            for url in ('file:///etc/passwd','http://github.com/dotnetdev-kr/cbodotnet/releases/download/a/b','https://github.com/other/repo/releases/download/a/b'):
                with self.subTest(url=url),self.assertRaises(ValueError):UP.fetch_asset(dict(url=url,size=1,sha256='a'*64),Path(directory)/'input')
            network.assert_not_called()

    def test_native_target_proof_matrix_cannot_be_empty(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(UP,'verify_bundle',return_value={}),self.assertRaisesRegex(ValueError,'All eight'):
            UP.qualified_reports(Path(directory),Path(directory))

    def test_public_metadata_reader_keeps_its_separate_narrow_origin_boundary(self):
        with patch.object(UP.urllib.request,'build_opener') as network:
            for url in ('https://api.nuget.org/v3/registration5-gz-semver2/a/index.json','https://dotnetdev.kr/cbodotnet/other.py',
                        'https://evil.example/v3/vulnerabilities/index.json','http://api.nuget.org/v3/vulnerabilities/index.json',
                        'https://api.nuget.org/v3/vulnerabilities/index.json?token=x'):
                with self.subTest(url=url),self.assertRaises(ValueError):UP.public_metadata(url,1024)
            network.assert_not_called()

    def test_official_compressed_metadata_has_a_decoded_size_bound(self):
        import gzip
        with patch.object(UP.urllib.request,'build_opener') as opener:
            response=MagicMock();response.headers={'Content-Encoding':'gzip'};response.read.return_value=gzip.compress(b'{}')
            opener.return_value.open.return_value.__enter__.return_value=response
            self.assertEqual(UP.public_metadata('https://api.nuget.org/v3/vulnerabilities/index.json',1024),b'{}')
            response.read.return_value=gzip.compress(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'Decompressed'):UP.public_metadata('https://api.nuget.org/v3/vulnerabilities/index.json',256)

    def test_public_feed_reader_admits_both_exact_catalog_generations(self):
        with patch.object(UP.urllib.request,'build_opener') as opener:
            response=MagicMock();response.headers={'Content-Encoding':'identity'};response.read.return_value=b'{}'
            opener.return_value.open.return_value.__enter__.return_value=response
            for path in ('catalog.json','catalog.json.asc','v2/catalog.json','v2/catalog.json.asc','v3/catalog.json','v3/catalog.json.asc'):
                with self.subTest(path=path):
                    self.assertEqual(UP.public_metadata('https://dotnetdev.kr/cbodotnet/cbodotnetup/'+path,1024),b'{}')

    def test_draft_resume_uses_the_real_shared_verifier_and_never_clobbers_public_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'cbodotnetup-linux-x64';path.write_bytes(b'verified native binary')
            tag='cbodotnetup-v0.1.0';target='b'*40
            class Transport:
                def __init__(self):
                    self.release=dict(id=123,tag_name=tag,target_commitish=target,draft=True,prerelease=False,assets=[],html_url='https://github.com/dotnetdev-kr/cbodotnet/releases/tag/'+tag)
                    self.uploads=0;self.publishes=0;self.downloads=[]
                def find(self,unused):return self.release
                def get(self,unused):return self.release
                def upload(self,release,file):
                    item=UP.descriptor(file);self.release['assets'].append(dict(id=100,**item,state='uploaded',digest='sha256:'+item['sha256'],browser_download_url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'+tag+'/'+item['name']));self.uploads+=1
                def download(self,asset,destination,public=False):shutil.copyfile(path,destination);self.downloads.append(public)
                def publish(self,unused):self.release['draft']=False;self.publishes+=1;return self.release
                def api(self,unused):return dict(object=dict(type='commit',sha=target))
            transport=Transport()
            with patch.object(UP,'GitHubReleases',return_value=transport):
                result=UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(result['assets'][0]['sha256'],UP.descriptor(path)['sha256'])
                self.assertEqual(transport.downloads,[False,True]);self.assertEqual(transport.uploads,1)
                UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(transport.uploads,1);self.assertEqual(transport.publishes,1)
                path.write_bytes(b'conflicting bytes')
                with self.assertRaisesRegex(ValueError,'conflicts'):UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(transport.uploads,1)


if __name__=='__main__':unittest.main()
