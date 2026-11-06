from pathlib import Path
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import cbodotnetup_legacy as LEGACY
import cbodotnetup_project as PROJECT
import legacy_compat
import legacy_curl
import cbodotnetup_release as RELEASE


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def asset(name):
    return dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/fixture/'+name,size=123,sha256=sha(name))


def project_proof(sdk,baseline,catalog):
    lower=['nearest-ancestor','exact-project-pin','patch-roll-forward','comments','prerelease-policy','host-paths',
           'versioned-alias-precedence','explicit-run-lower-precedence','sdk-info-selection','msbuild-owned-sdk','msbuild-project-conflict']
    higher=['highest-without-project','nearest-file-boundary','major-roll-forward','explicit-run-precedence','msbuild-explicit-override']
    rejected=['feature-band-rejection','missing-sdk-no-install','missing-admitted-sdk-no-install','malformed-fail-closed',
              'trailing-comma-fail-closed','relative-path-rejection','absolute-path-rejection','empty-paths-rejection',
              'symlink-path-rejection','symlink-global-rejection','runtime-options-sdk-rejection']
    rows=[dict(name=name,status='passed',expectedVersion=version,exitCode=0 if version else 1)
          for names,version in [(lower,sdk['sdkVersion']),(higher,baseline['sdkVersion']),(rejected,None)] for name in names]
    rows.append(dict(name='sdk-arguments-offline',status='passed',expectedVersion=sdk['sdkVersion'],exitCode=1))
    rows.extend(dict(name=name,status='passed',expectedVersion=baseline['sdkVersion'],exitCode=129)
                for name in ['missing-app-runtime-dispatch','runtime-options-missing-app'])
    missing=next(release for release in catalog['sdks'] if release['sdkVersion']=='9.0.123' and release['rid']==sdk['rid'])
    return dict(schemaVersion=1,scope=PROJECT.PROJECT_SCOPE,status='passed',sdkVersion=sdk['sdkVersion'],baselineVersion=baseline['sdkVersion'],
        network='none',checks=dict.fromkeys(PROJECT.PROJECT_CHECKS,'passed'),cases=rows,
        identity=dict(sdkVersion=sdk['sdkVersion'],packageRevision=sdk['revision'],targetRid=sdk['rid'],
            sourceManifestSha256=sdk['sourceManifestSha256'],qualifiedPayloadModified=False),projectFilesSha256=sha('project'),
        projectFilesUnchanged=True,ownedStateUnchanged=True,ownedPayloadsUnchanged=True,
        ownedPayloadVerification='signed-receipt-and-inventory-doctor-before-and-after',
        missingAdmittedSdk={key:missing[key] for key in ('sdkVersion','revision','rid','sourceManifestSha256')})


class LegacyQualificationTests(unittest.TestCase):
    def inputs(self,public=True):
        variants=[('ubuntu','24.04'),('debian','13'),('fedora','45'),('rocky','9.8')]
        versions=['10.0.403','9.0.123','8.0.133','7.0.120','6.0.136',*LEGACY.LEGACY_VERSIONS]
        sdks=[];providers=[];bindings=[]
        for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
            targets=[dict(os=os_name,versionId=number,rid=rid) for os_name,number in variants]
            for kind in [LEGACY.BASE_PROVIDER,LEGACY.CURL_PROVIDER]:
                root='/usr/lib/cbodotnet/compat/'+('rocky9' if kind==LEGACY.BASE_PROVIDER else 'curl-rocky8')
                names=['lib/libcrypto.so.1.1.1k','lib/libicudata.so.67.1','lib/libicui18n.so.67.1','lib/libicuuc.so.67.1'] if kind==LEGACY.BASE_PROVIDER else ['lib/libcurl.so.4.5.0']
                manifest=dict(files=[dict(path=name,type='file',sha256=sha(kind+rid+name)) for name in names])
                providers.append(dict(providerId=kind,revision=1,rid=rid,root=root,archive=asset(kind+rid+'.tar.gz'),
                    policySha256=sha(kind+'policy'),manifestSha256=sha(kind+rid+'manifest'),libc='glibc',targets=copy.deepcopy(targets),
                    minimumGlibc='2.34' if kind==LEGACY.BASE_PROVIDER else '2.17',manifest=manifest,
                    sourceManifest=asset(kind+'distribution-manifest.json'),sourceSignature=asset(kind+'distribution-manifest.json.asc')))
            for version in versions:
                sdk=dict(sdkVersion=version,revision=3 if version=='10.0.403' else 2,rid=rid,archiveRoot='cbodotnet-'+version+'-linux-'+arch+'-r2',
                    archive=asset(version+rid+'.tar.gz'),sourceManifestSha256=sha(version+'source'),targets=copy.deepcopy(targets),
                    requiresLegacyProvider=version in LEGACY.LEGACY_VERSIONS)
                sdks.append(sdk)
                if sdk['requiresLegacyProvider']:
                    kinds=[LEGACY.BASE_PROVIDER,LEGACY.CURL_PROVIDER] if version.startswith('3.') else [LEGACY.BASE_PROVIDER]
                    bindings.append(dict(sdkId=LEGACY.sdk_id(sdk),sourceManifestSha256=sdk['sourceManifestSha256'],archiveSha256=sdk['archive']['sha256'],
                        providerIds=[LEGACY.provider_id(provider) for provider in providers if provider['rid']==rid and provider['providerId'] in kinds]))
        tools=[dict(version=version,rid=rid,binary=asset(version+rid)) for version in ['0.3.0','0.4.0'] for rid in ['linux-x64','linux-arm64']]
        compatibility=dict(schemaVersion=2,sequence=321,sdks=[sdk for sdk in sdks if not sdk['requiresLegacyProvider']],tools=tools,revoked=[])
        catalog=dict(schemaVersion=3,sequence=321,sdks=sdks,tools=tools,revoked=[],providers=providers,providerBindings=bindings,
            compatibilityCatalog=dict(asset('catalog-v2.json'),sha256=LEGACY.digest(compatibility)))
        current_hash=LEGACY.digest(catalog); observations=[]
        for os_name,number in variants:
            variant=os_name+'-'+number
            for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
                baseline=next(sdk for sdk in sdks if sdk['sdkVersion']=='10.0.403' and sdk['rid']==rid)
                context=dict(variant=variant,architecture=arch,catalogSha256=current_hash,bootstrapSha256=sha('bootstrap'),
                    binarySha256=sha('current'+rid),bootstrapBinarySource='public-https' if public else 'protected-frozen-candidate')
                old_tools=[tool for tool in tools if tool['version']=='0.3.0']
                prior=dict(compatibility,sequence=320,tools=old_tools)
                migration=dict(status='passed',fromVersion='0.3.0',toVersion='0.4.0',
                    protocol='actual-0.3.0-self-update-rollback-reupgrade' if public else 'protected-frozen-candidate-bootstrap-from-0.3.0',
                    oldBinarySha256=next(tool['binary']['sha256'] for tool in old_tools if tool['rid']==rid),currentBinarySha256=context['binarySha256'],
                    previousCatalogSha256=LEGACY.digest(prior),currentCatalogSha256=current_hash,compatibilityCatalogSha256=LEGACY.digest(compatibility),
                    baseline={key:baseline[key] for key in ('sdkVersion','revision','rid')},baselineReceiptSha256=sha('receipt'),
                    baselineInventorySha256=sha('inventory'),baselineCatalogSha256=LEGACY.digest(prior),baselineOwnedStateSha256=sha('owned'),
                    baselineReceiptUnchanged=True,baselineOwnedStateUnchanged=True,baselinePayloadVerified=True,rollbackVerified=public)
                rows=[]
                for sdk in sdks:
                    if not sdk['requiresLegacyProvider'] or sdk['rid']!=rid:continue
                    required=LEGACY.providers_for(catalog,sdk)
                    prefix='/home/cbot-multi-sdk/.local/share/cbodotnetup-matrix-'+sdk['sdkVersion']
                    records=[]
                    for provider in required:
                        records.append(dict(id=LEGACY.provider_id(provider),providerId=provider['providerId'],revision=provider['revision'],rid=rid,
                            **{key:provider[key] for key in ('archive','policySha256','manifestSha256','sourceManifest','sourceSignature')},
                            storeRelativePath='providers/'+LEGACY.provider_id(provider),
                            root=prefix+'/providers/'+LEGACY.provider_id(provider)+'/content/rootfs'+provider['root'],
                            receiptSha256=sha('receipt'+LEGACY.provider_id(provider)),inventorySha256=sha('inventory'+LEGACY.provider_id(provider)),
                            treeSha256=sha('tree'+LEGACY.provider_id(provider)),retainedCatalogSha256=current_hash))
                    base=records[0]['root']; curl=records[1]['root'] if len(records)==2 else ''
                    components=[row for row in required[0]['manifest']['files'] if row['path'].startswith('lib/libcrypto.so.')]
                    if sdk['sdkVersion'].startswith('3.'):
                        components += [row for row in required[0]['manifest']['files'] if row['path'].startswith('lib/libicu')]
                    components=[dict(path=base+'/'+row['path'],sha256=row['sha256']) for row in components]
                    manager_environment=dict(status='passed',scope='clean-manager-private-provider-environment',userId=10001,network='none',baseRoot=base,
                        curlRoot=curl,certificateFile=legacy_compat.environment(dict(sdkVersion=sdk['sdkVersion'],variant=variant),root=base)['SSL_CERT_FILE'],
                        opensslConfiguration=base+'/openssl.cnf',libraryPath=':'.join(row['root']+'/lib' for row in reversed(records)),
                        components=components,nativeMappings=['1000 r-xp '+entry['path'] for entry in components])
                    peer=next(release for release in sdks if release['sdkVersion']==('3.0.103' if sdk['sdkVersion']=='3.1.426' else '3.1.426') and release['rid']==rid)
                    peer_providers=LEGACY.providers_for(catalog,peer)
                    shared=sorted(set(LEGACY.provider_id(provider) for provider in required)&{LEGACY.provider_id(provider) for provider in peer_providers})
                    sharing=dict(status='passed',peerSdkId=LEGACY.sdk_id(peer),sharedProviderIds=shared,peerArchiveSha256=peer['archive']['sha256'],
                        peerSourceManifestSha256=peer['sourceManifestSha256'],retainedPeerProviderReceipts={LEGACY.provider_id(provider):sha('peer'+LEGACY.provider_id(provider)) for provider in peer_providers},
                        retainedAfterRemove=True,targetProviderStatePreserved=True,unreferencedGc=True)
                    variants_of_catalog=dict(
                        revokedSdk=dict(catalog,revoked=sorted(LEGACY.sdk_id(release) for release in sdks if release['requiresLegacyProvider'])),
                        revokedProvider=dict(catalog,revoked=sorted('provider/'+LEGACY.provider_id(provider) for provider in providers)),
                        incompatibleAbi=dict(catalog,providers=[dict(provider,minimumGlibc='999.0') for provider in providers]))
                    names=dict(revokedSdk='catalog-v3-revoked.json',revokedProvider='catalog-v3-provider-revoked.json',incompatibleAbi='catalog-v3-provider-incompatible.json')
                    negatives={name:dict(status='passed',fixture=names[name],catalogSha256=LEGACY.digest(value),exitCode=1,noPayloadExtracted=True)
                               for name,value in variants_of_catalog.items()}
                    if len(records)==2:
                        payload=prefix+'/toolchains-v3/'+LEGACY.sdk_id(sdk)+'/content/'+sdk['archiveRoot']+'/payload'
                        pins=legacy_curl.runtime_pins(dict(sdkVersion=sdk['sdkVersion'],architecture=dict(public=arch)))
                        native=dict(status='passed',handler='CurlHandler',http='passed',https='passed',httpsDefaultTrust='passed',tls12='passed',callbackCount=1,network='none',userId=10001,
                            nativeHttp=dict(path=payload+'/'+pins['nativeHttp']['path'],sha256=pins['nativeHttp']['sha256']),
                            curl=dict(path=curl+'/'+pins['curl']['path'],sha256=pins['curl']['sha256']))
                        native['nativeMappings']=['1000 r-xp '+native['nativeHttp']['path'],'2000 r-xp '+native['curl']['path']]
                        native_http=[dict(path=pins['nativeHttp']['path'],sha256=pins['nativeHttp']['sha256'],libcurlProviderPath=curl+'/lib/libcurl.so.4')]
                        trust=dict(httpsDefaultTrust='passed',tls12='passed')
                    else:
                        native=None;native_http=[]
                        trust=dict(status='passed',handler='SocketsHttpHandler',defaultTrustHttps='passed',tls12='passed',network='none',userId=10001)
                    proof=dict(status='passed',providers=records,sharing=sharing,negatives=negatives,
                        consentRejected=True,consentNoPayloadExtracted=True,interruptedRecovery=True,missingRejected=True,tamperRejected=True,substitutedRejected=True,
                        managerEnvironment=manager_environment,nativeHttpLibraries=native_http,defaultTrust=trust,nativeCurlHandler=native,
                        ownedSdkBytesUnchanged=True,ownedProviderBytesUnchanged=True,officialAndPackageStateUnchanged=True,unreferencedProvidersCollected=True)
                    if sdk['sdkVersion']=='5.0.214':
                        if public:
                            proof['toolRollback']=dict(status='passed',protocol='actual-0.3.0-recovery-with-installed-legacy-providers',migration=copy.deepcopy(migration),
                                fromVersion='0.4.0',retainedVersion='0.3.0',oldBinarySha256=migration['oldBinarySha256'],currentBinarySha256=context['binarySha256'],
                                sdkIds=sorted(LEGACY.sdk_id(release) for release in (baseline,sdk,peer)),
                                providerIds=sorted({LEGACY.provider_id(provider) for release in (sdk,peer) for provider in LEGACY.providers_for(catalog,release)}),
                                ownedStateBeforeSha256=sha('retained-all-provider-state'),ownedStateAfterSha256=sha('retained-all-provider-state'),
                                modernSdkExecutedAfterRollback=True,legacySdkExecutedAfterReupgrade=True,peerSdkExecutedAfterReupgrade=True,
                                allSdkAndProviderInventoriesVerified=True,selectionAndReceiptsUnchanged=True)
                        else:
                            proof['toolRollback']=dict(status='public-verification-required',protocol='protected-frozen-candidate-bootstrap',migration=copy.deepcopy(migration))
                    else:proof['toolRollback']=None
                    alias=lambda release:dict(sdkVersion=release['sdkVersion'],packageRevision=release['revision'],targetRid=release['rid'],
                        sourceManifestSha256=release['sourceManifestSha256'],qualifiedPayloadModified=False)
                    rows.append(dict(context,schemaVersion=1,scope=LEGACY.SCOPE,status='passed',sdkVersion=sdk['sdkVersion'],revision=sdk['revision'],rid=rid,
                        target=dict(os=os_name,versionId=number,rid=rid),archive=sdk['archive'],sourceManifestSha256=sdk['sourceManifestSha256'],networkForBuild='none',userId=10001,
                        checks=dict.fromkeys(LEGACY.CHECKS,'passed'),functionalChecks=dict.fromkeys(LEGACY.FUNCTIONAL_CHECKS,'passed'),
                        aliases=[alias(baseline),alias(baseline),alias(sdk)],projectSelection=project_proof(sdk,baseline,catalog),providerQualification=proof))
                observations.append(dict(context,projectClientMigration=migration,legacySdkQualifications=rows))
        return catalog,observations,compatibility

    def validate(self,catalog,observations,compatibility):
        return LEGACY.validate_legacy_qualifications(catalog,observations,tool_version='0.4.0',compatibility_catalog=compatibility)

    def test_all_twenty_four_cells_and_actual_previous_project_client_are_bound(self):
        for public in (True,False):
            rows=self.validate(*self.inputs(public))
            self.assertEqual(len(rows),24)
            self.assertEqual({row['sdkVersion'] for row in rows},set(LEGACY.LEGACY_VERSIONS))

    def test_historical_modern_feed_does_not_gain_provider_requirements(self):
        catalog,observations,compatibility=self.inputs()
        self.assertEqual(LEGACY.validate_legacy_qualifications(compatibility,[],tool_version='0.3.0'),[])

    def test_partial_duplicate_or_unqualified_legacy_matrix_is_rejected(self):
        for mutate in [lambda rows:rows.pop(),lambda rows:rows.append(copy.deepcopy(rows[0])),lambda rows:rows[0].update(rid='linux-musl-x64')]:
            catalog,observations,compatibility=self.inputs();mutate(observations[0]['legacySdkQualifications'])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_legacy_source_archive_target_and_workflow_binary_cannot_be_substituted(self):
        for field,value in [('revision',9),('sourceManifestSha256','0'*64),('archive',asset('other.tar.gz')),('catalogSha256','0'*64),
                            ('binarySha256','0'*64),('architecture','aarch64'),('networkForBuild','bridge'),('userId',0)]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_each_provider_consent_recovery_and_preservation_check_is_required(self):
        for field in ('consentRejected','consentNoPayloadExtracted','interruptedRecovery','missingRejected','tamperRejected','substitutedRejected',
                      'ownedSdkBytesUnchanged','ownedProviderBytesUnchanged','officialAndPackageStateUnchanged','unreferencedProvidersCollected'):
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_wrong_companion_hash_source_rid_or_external_root_is_rejected(self):
        for field,value in [('archive',asset('untrusted.tar.gz')),('policySha256','0'*64),('manifestSha256','0'*64),('rid','linux-arm64'),
                            ('retainedCatalogSha256','0'*64),('root','/usr/lib/cbodotnet/compat/rocky9'),('inventorySha256','missing')]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification']['providers'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_legacy_binding_cannot_reference_wrong_source_or_cross_libc_provider(self):
        for mutation in [lambda catalog:catalog['providerBindings'][0].update(archiveSha256='0'*64),
                         lambda catalog:catalog['providers'][0].update(libc='musl'),
                         lambda catalog:catalog['providerBindings'][1]['providerIds'].reverse()]:
            catalog,observations,compatibility=self.inputs();mutation(catalog)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_revoked_companion_cannot_be_promoted(self):
        catalog,observations,compatibility=self.inputs();catalog['revoked']=['provider/'+LEGACY.provider_id(catalog['providers'][0])]
        with self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_sharing_must_keep_exact_peer_source_and_all_common_references(self):
        for field,value in [('retainedAfterRemove',False),('sharedProviderIds',[]),('peerArchiveSha256','0'*64),('retainedPeerProviderReceipts',{})]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][1]['providerQualification']['sharing'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_signed_negative_fixture_hash_and_no_extraction_are_required(self):
        for field,value in [('catalogSha256','0'*64),('noPayloadExtracted',False),('exitCode',0)]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification']['negatives']['incompatibleAbi'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_real_clean_child_must_map_private_crypto_and_correct_ca(self):
        for field,value in [('baseRoot','/usr/lib/cbodotnet/compat/rocky9'),('certificateFile','/untrusted/ca.pem'),('libraryPath','/usr/lib64'),
                            ('components',[]),('nativeMappings',['1000 /usr/lib/libcrypto.so.1.1'])]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification']['managerEnvironment'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_core3_requires_forced_curl_callback_ca_and_exact_source_native_object(self):
        for field,value in [('callbackCount',0),('httpsDefaultTrust','failed'),('nativeHttp',dict(path='/tmp/fake.so',sha256='0'*64)),
                            ('curl',dict(path='/usr/lib64/libcurl.so.4',sha256='0'*64))]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][1]['providerQualification']['nativeCurlHandler'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_sdk5_default_trust_cannot_be_substituted_with_a_core3_summary(self):
        catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification']['defaultTrust']=dict(httpsDefaultTrust='passed',tls12='passed')
        with self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_previous_03_client_requires_actual_binary_fixture_and_public_rollback(self):
        for field,value in [('oldBinarySha256','0'*64),('previousCatalogSha256','0'*64),('compatibilityCatalogSha256','0'*64),('rollbackVerified',False),('baselineOwnedStateUnchanged',False)]:
            catalog,observations,compatibility=self.inputs();observations[0]['projectClientMigration'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_tool_rollback_must_preserve_installed_legacy_sdk_and_both_provider_references(self):
        for field,value in [('ownedStateAfterSha256','0'*64),('providerIds',[]),('peerSdkExecutedAfterReupgrade',False),
                            ('selectionAndReceiptsUnchanged',False),('oldBinarySha256','0'*64)]:
            catalog,observations,compatibility=self.inputs();observations[0]['legacySdkQualifications'][0]['providerQualification']['toolRollback'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def test_unpublished_candidate_cannot_claim_a_real_tool_rollback_with_provider_state(self):
        catalog,observations,compatibility=self.inputs(False)
        observations[0]['legacySdkQualifications'][0]['providerQualification']['toolRollback'].update(status='passed',selectionAndReceiptsUnchanged=True)
        with self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    def rollback_cycle(self,public=True,changed_provider=False):
        catalog,observations,compatibility=self.inputs(public)
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);root=directory/'owned';root.mkdir();binary=directory/'cbodotnetup'
            (root/'owner').write_text('cbodotnetup-v1');(root/'selection.json').write_text('{"active":"retained"}')
            provider=root/'providers/rocky9-r1/linux-x64';provider.mkdir(parents=True);receipt=provider/'receipt.json';receipt.write_text('{"unchanged":true}')
            bundle=directory/'bundle';bundle.mkdir();(bundle/'catalog.json').write_text(json.dumps(catalog));(bundle/'catalog-v2.json').write_text(json.dumps(compatibility))
            policy=directory/'policy.json';policy.write_text('{"version":"0.4.0"}');binary.write_bytes(b'new-client')
            state=dict(version='0.4.0');events=[]
            def execute(actual_root,command):
                command=list(map(str,command));events.append((state['version'],command))
                if command[-2:]==['self','rollback']:
                    state['version']='0.3.0';binary.write_bytes(b'old-client')
                    if changed_provider:receipt.write_text('{"unchanged":false}')
                elif command[-2:]==['self','update']:
                    state['version']='0.4.0';binary.write_bytes(b'new-client')
                if command[-1]=='--version':
                    version=command[2].split('-r')[0] if command[1]=='run' else state['version']
                    return SimpleNamespace(stdout=version+'\n',stderr='Community Build of .NET (built by .NET Dev)\n' if command[1]=='run' else '')
                return SimpleNamespace(stdout='',stderr='')
            api=SimpleNamespace(matrix_user=execute,load=LEGACY.load,POLICY=policy,MULTI=SimpleNamespace(BRAND='Community Build of .NET (built by .NET Dev)'))
            sdk=next(release for release in catalog['sdks'] if release['sdkVersion']=='5.0.214' and release['rid']=='linux-x64')
            peer=next(release for release in catalog['sdks'] if release['sdkVersion']=='3.1.426' and release['rid']=='linux-x64')
            baseline=next(release for release in catalog['sdks'] if release['sdkVersion']=='10.0.403' and release['rid']=='linux-x64')
            migration=dict(oldBinarySha256=hashlib.sha256(b'old-client').hexdigest())
            result=LEGACY._tool_rollback_with_providers(SimpleNamespace(bundle=bundle,public=public),api,root,binary,sdk,peer,baseline,migration)
            return result,events

    def test_actual_recovery_harness_runs_old_client_before_reupgrade_and_keeps_owned_state(self):
        proof,events=self.rollback_cycle()
        operations=[command[-2:] for _,command in events if 'self' in command]
        self.assertEqual(operations,[['self','rollback'],['self','update']])
        self.assertTrue(any(version=='0.3.0' and command[1:3]==['run','10.0.403-r3'] for version,command in events))
        self.assertTrue(any(version=='0.4.0' and command[1:3]==['run','3.1.426-r2'] for version,command in events))
        self.assertEqual(proof['ownedStateBeforeSha256'],proof['ownedStateAfterSha256'])
        self.assertTrue(proof['allSdkAndProviderInventoriesVerified'])

    def test_recovery_harness_rejects_old_client_changes_to_provider_receipts(self):
        with self.assertRaisesRegex(ValueError,'changed legacy SDK/provider state'):self.rollback_cycle(changed_provider=True)

    def test_candidate_recovery_harness_does_not_run_or_claim_unpublished_self_update(self):
        proof,events=self.rollback_cycle(public=False)
        self.assertEqual(proof['status'],'public-verification-required');self.assertEqual(events,[])
        self.assertNotIn('ownedStateAfterSha256',proof)

    def test_03_migration_only_gives_the_old_client_schema2_then_refreshes_schema3(self):
        args=SimpleNamespace(bundle=Path('/bundle'),arch='x64',public=True)
        root,binary=Path('/owned'),Path('/bin/cbodotnetup');state=dict(version='0.3.0');events=[]
        old_sha,new_sha,prior_sha,main_sha,compat_sha='a'*64,'b'*64,'c'*64,'d'*64,'e'*64
        baseline=dict(sdkVersion='10.0.403',revision=3,rid='linux-x64')
        def read(path):
            if Path(path)==RELEASE.POLICY:return dict(version='0.4.0')
            if Path(path).name=='catalog.json':return dict(schemaVersion=3)
            return dict(tools=[dict(version='0.3.0',rid='linux-x64',binary=dict(sha256=old_sha))])
        def describe(path):
            path=Path(path)
            if path==binary:value=old_sha if state['version']=='0.3.0' else new_sha
            elif str(path).endswith('.previous'):value=old_sha
            elif path.name=='catalog-v2-tool-0.3.json':value=prior_sha
            elif path.name=='catalog-v2.json':value=compat_sha
            elif path.name=='catalog.json':value=prior_sha if 'toolchains-v2' in path.parts else main_sha
            else:value='f'*64
            return dict(sha256=value,size=123,name=path.name)
        def execute(actual_root,command):
            command=list(map(str,command));events.append((state['version'],command))
            if command[-2:]==['self','update']:state['version']='0.4.0'
            elif command[-2:]==['self','rollback']:state['version']='0.3.0'
            if command[-1]=='--version':
                return SimpleNamespace(stdout=(baseline['sdkVersion'] if 'run' in command else state['version'])+'\n',stderr=RELEASE.MULTI.BRAND+'\n')
            return SimpleNamespace(stdout='',stderr='')
        with patch.object(RELEASE,'matrix_bootstrap') as bootstrap,patch.object(RELEASE,'load',side_effect=read),\
                patch.object(RELEASE,'descriptor',side_effect=describe),patch.object(RELEASE,'matrix_user',side_effect=execute),\
                patch.object(PROJECT,'owned_sdk_state',return_value={'receipt':'unchanged'}):
            proof=RELEASE.matrix_previous_tool_upgrade(args,root,binary,baseline,previous_version='0.3.0')
        self.assertEqual(bootstrap.call_args.kwargs,dict(published_binary=True,expected_version='0.3.0'))
        self.assertEqual(bootstrap.call_args.args[3],Path('/bundle/catalog-v2-tool-0.3.json'))
        for version,command in events:
            if 'self' in command:self.assertEqual(command[2],'/bundle/catalog-v2.json')
        self.assertTrue(any(version=='0.4.0' and command[-4:]==['--catalog','/bundle/catalog.json','list','--available'] for version,command in events))
        self.assertEqual(proof['compatibilityCatalogSha256'],compat_sha)
        self.assertEqual(proof['currentCatalogSha256'],main_sha);self.assertEqual(proof['baselineCatalogSha256'],prior_sha)

    def test_compatibility_projection_is_mandatory_and_cannot_change_sdk_records(self):
        catalog,observations,compatibility=self.inputs()
        with self.assertRaises(ValueError):LEGACY.validate_legacy_qualifications(catalog,observations,tool_version='0.4.0')
        compatibility['sdks'][0]=dict(compatibility['sdks'][0],revision=99)
        with self.assertRaises(ValueError):self.validate(catalog,observations,compatibility)

    @unittest.skipUnless(sys.platform=='linux','A real POSIX child process is required')
    def test_clean_probe_wrapper_removes_ambient_provider_state_but_preserves_explicit_ca(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);binary=root/'manager';wrapper=root/'wrapper'
            binary.write_text('#!'+sys.executable+'\nimport json,os,sys\nprint(json.dumps(dict(environment=dict(os.environ),arguments=sys.argv[1:])))\n')
            binary.chmod(0o755)
            sdk=dict(sdkVersion='3.1.426',revision=2)
            LEGACY.clean_manager_wrapper(wrapper,root/'owned',binary,sdk)
            environment=dict(os.environ,LD_LIBRARY_PATH='/untrusted/lib',OPENSSL_CONF='/untrusted/ssl',
                CBODOTNET_COMPAT_SCOPE='rocky9',CBODOTNET_COMPAT_ROOT='/untrusted/provider',
                CBODOTNET_COMPAT_SAVED_SSL_CERT_FILE_SET='1',CBODOTNET_COMPAT_SAVED_SSL_CERT_FILE_VALUE='/untrusted/ca',
                SSL_CERT_FILE='/explicit/test-ca.pem',KEEP_ME='unchanged')
            value=json.loads(subprocess.run([wrapper,'--version'],env=environment,check=True,capture_output=True,text=True).stdout)
            child=value['environment'];self.assertEqual(child['SSL_CERT_FILE'],'/explicit/test-ca.pem');self.assertEqual(child['KEEP_ME'],'unchanged')
            self.assertEqual(value['arguments'],['run','3.1.426-r2','--','--version'])
            self.assertFalse(any(name in child for name in LEGACY.ENVIRONMENT))
            self.assertFalse(any(name.startswith('CBODOTNET_COMPAT') for name in child))
            self.assertEqual(environment['LD_LIBRARY_PATH'],'/untrusted/lib')
            LEGACY.clean_manager_wrapper(wrapper,root/'owned',binary,sdk,preserve_certificate=False)
            child=json.loads(subprocess.run([wrapper,'--version'],env=environment,check=True,capture_output=True,text=True).stdout)['environment']
            self.assertNotIn('SSL_CERT_FILE',child)


if __name__=='__main__':unittest.main()
