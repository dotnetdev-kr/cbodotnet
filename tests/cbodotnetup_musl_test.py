"""Explicit installer admission never inherits glibc or candidate musl records."""
import copy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import cbodotnetup_musl as MUSL


def fixture():
    policy=MUSL.load_policy()
    status=json.loads((ROOT/'releases/musl-status.json').read_bytes())
    receipt=copy.deepcopy(next(r for r in status['publications'] if r['identity']['channel']=='archive'))
    source=dict(sdkVersion=policy['sdkVersion'],producerRevision=policy['producerRevision'],architectures={})
    qualified=MUSL.CONTRACT.load_qualification_catalog()['builds'][0]
    for arch in MUSL.ARCHITECTURES:
        source['architectures'][arch]=dict(provenance=qualified['architectures'][arch],
            evidence=dict(name=f'cbodotnet-musl-sdk-10.0.403-linux-musl-{arch}-r1-evidence.tar.gz',size=100,sha256='e'*64))
    canonical=json.dumps(source,sort_keys=True).encode();policy['sourceManifestSha256']=hashlib.sha256(canonical).hexdigest()
    receipt['identity']['sourceManifestSha256']=policy['sourceManifestSha256']
    manifest=dict(identity=receipt['identity'],tag=receipt['tag'],records=[])
    for arch,target in MUSL.ARCHITECTURES.items():
        plan=dict(libc='musl',targetRid=target['rid'],sourceManifestSha256=policy['sourceManifestSha256'],
            sourceManifestUrl='https://github.com/dotnetdev-kr/cbodotnet/releases/download/musl-sdk-10.0.403-r1/release-manifest.json',
            producer=source['architectures'][arch]['provenance'],evidence=source['architectures'][arch]['evidence'],
            dependencies=MUSL.CONTRACT.NATIVE_DEPENDENCIES,licensePaths=['LICENSE.txt','ThirdPartyNotices.txt'],
            securitySupport='community-build-no-additional-security-maintenance')
        manifest['records'].append(dict(architecture=arch,targetRid=target['rid'],artifactAsset=policy['archives'][arch]['name'],
            build=dict(directory=f'cbodotnet-10.0.403-linux-musl-{arch}-r1',plan=plan)))
    status['publications']=[receipt]
    return policy,status,manifest,source,canonical


def catalog_fixture():
    policy,status,manifest,source,canonical=fixture()
    records=[]
    with patch.object(MUSL.CONTRACT,'require_qualified_producer',return_value=source):
        for arch in MUSL.ARCHITECTURES:
            records.append(MUSL.sdk_catalog_record(arch,policy=policy,status=status,
                authenticator=lambda receipt:manifest,fetch=lambda url,maximum:canonical))
    tools=[]
    for version in ('0.5.0','0.5.1'):
        for target in MUSL.ARCHITECTURES.values():
            rid=target['rid'];url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v{version}/cbodotnetup-{rid}'
            tools.append(dict(version=version,rid=rid,binary=dict(url=url,size=100,sha256=hashlib.sha256((version+rid).encode()).hexdigest()),
                notices=dict(url=url+'.LICENSE.txt',size=100,sha256='d'*64)))
    now=datetime.now(timezone.utc)
    catalog=dict(schemaVersion=4,kind='cbodotnetup-installation-catalog',libc='musl',sequence=123,
        issuedAt=now.isoformat(),expiresAt=(now+timedelta(days=30)).isoformat(),signingFingerprint=MUSL.FINGERPRINT,
        sdks=records,tools=tools,channels={'10.0':'10.0.403-r1'},revoked=[])
    qualified=dict(builds=[dict(sdkVersion=policy['sdkVersion'],producerRevision=policy['producerRevision'],
        sourceManifestSha256=policy['sourceManifestSha256'],architectures={arch:row['provenance'] for arch,row in source['architectures'].items()})])
    return policy,catalog,qualified


def observations(catalog,public=True):
    rows=[]
    for arch,target in MUSL.ARCHITECTURES.items():
        rid=target['rid'];tool=next(t for t in catalog['tools'] if t['version']=='0.5.1' and t['rid']==rid)
        old=next(t for t in catalog['tools'] if t['version']=='0.5.0' and t['rid']==rid)
        rows.append(dict(schemaVersion=1,scope='cbodotnetup-native-installation',status='passed',variant='alpine-3.24',
            architecture=arch,libc='musl',rid=rid,native=True,baseImage=MUSL.musl_archive.BASES[arch],
            checks=dict.fromkeys(MUSL.CHECKS,'passed'),functionalChecks=dict.fromkeys(MUSL.musl_archive.FUNCTIONAL_CHECKS,'passed'),
            catalogSha256='a'*64,bootstrapSha256='b'*64,binarySha256=tool['binary']['sha256'],freezeSha256='c'*64,
            bootstrapBinarySource='public-https' if public else 'protected-frozen-candidate',networkForBuild='none',userId=10001,
            packageManagedCommunityIntegrity='unchanged',crossLibcStatePreserved=True,
            migration=dict(status='passed',protocol='actual-musl-0.5.0-self-update-rollback-reupgrade' if public else 'musl-0.5.0-frozen-bootstrap-migration',
                oldVersion='0.5.0',newVersion='0.5.1',oldBinarySha256=old['binary']['sha256'],sdkRollback='passed',interruptedOwnershipRecovery='passed'),
            elfAudit=dict(status='passed'),toolElfAudit=dict(status='passed'),systemTrustHttps=dict(status='passed')))
    return rows


class MuslInstallerAdmissionTests(unittest.TestCase):
    def test_policy_pins_current_actual_signed_archive_and_independent_public_proof(self):
        policy=MUSL.load_policy();status=MUSL.musl_site.load_status()
        receipt=next(r for r in status['publications'] if r['identity']['channel']=='archive')
        self.assertEqual(policy['publication']['manifestSha256'],receipt['manifestSha256'])
        self.assertEqual(policy['publication']['verificationManifestSha256'],receipt['verification']['manifestSha256'])
        self.assertEqual(policy['sourceManifestSha256'],receipt['identity']['sourceManifestSha256'])
        for item in policy['archives'].values():
            self.assertEqual(item,{k:next(a for a in receipt['assets'] if a['name']==item['name'])[k] for k in item})

    def test_catalog_records_require_actual_authenticated_signed_source_and_final_proof(self):
        policy,status,manifest,source,canonical=fixture()
        with patch.object(MUSL.CONTRACT,'require_qualified_producer',return_value=source) as qualify:
            record=MUSL.sdk_catalog_record('x64',policy=policy,status=status,authenticator=lambda value:manifest,fetch=lambda url,bound:canonical)
        self.assertEqual(record['rid'],'linux-musl-x64');self.assertFalse(record['requiresLegacyProvider'])
        self.assertEqual(record['targets'],[dict(os='alpine',versionId='3.24.4',rid='linux-musl-x64')]);qualify.assert_called_once_with(canonical)
        for change in (lambda r:r.update(status='prepared'),lambda r:r['verification'].update(manifestSha256='f'*64),
            lambda r:r['identity'].update(libc='glibc'),lambda r:r.update(manifestSha256='f'*64)):
            bad=copy.deepcopy(status);change(bad['publications'][0])
            with self.assertRaises(ValueError):MUSL.sdk_catalog_record('x64',policy=policy,status=bad,authenticator=lambda value:manifest,fetch=lambda url,bound:canonical)

    def test_wrong_producer_archive_cpu_notices_or_libc_cannot_be_relabelled(self):
        policy,status,manifest,source,canonical=fixture()
        changes=[lambda r:r.update(targetRid='linux-x64'),lambda r:r['build']['plan'].update(libc='glibc'),
            lambda r:r['build']['plan'].update(producer={}),lambda r:r['build']['plan'].update(evidence={}),
            lambda r:r['build']['plan'].update(licensePaths=[]),lambda r:r['build'].update(directory='cbodotnet-10.0.403-linux-x64-r1')]
        with patch.object(MUSL.CONTRACT,'require_qualified_producer',return_value=source):
            for change in changes:
                bad=copy.deepcopy(manifest);change(bad['records'][0])
                with self.subTest(change=change),self.assertRaises(ValueError):
                    MUSL.sdk_catalog_record('x64',policy=policy,status=status,authenticator=lambda value:bad,fetch=lambda url,bound:canonical)

    def test_v4_is_closed_to_musl_sdk10_revision1_and_two_exact_alpine_cpus(self):
        policy,catalog,qualified=catalog_fixture()
        with patch.object(MUSL,'load_policy',return_value=policy),patch.object(MUSL.CONTRACT,'load_qualification_catalog',return_value=qualified):
            MUSL.validate_catalog(catalog)
            changes=[lambda c:c.update(libc='glibc'),lambda c:c.update(schemaVersion=3),lambda c:c.update(providers=[]),
                lambda c:c['sdks'][0].update(rid='linux-x64'),lambda c:c['sdks'][0].update(requiresLegacyProvider=True),
                lambda c:c['sdks'][0]['targets'][0].update(versionId='3.24'),lambda c:c['tools'][0].update(rid='linux-x64'),
                lambda c:c['sdks'][0]['archive'].update(url='https://evil.example/sdk.tar.gz')]
            for change in changes:
                bad=copy.deepcopy(catalog);change(bad)
                with self.subTest(change=change),self.assertRaises(ValueError):MUSL.validate_catalog(bad)

    def test_catalog_lifetime_is_bounded_utc_and_historical_receipts_keep_their_original_expiry(self):
        policy,catalog,qualified=catalog_fixture();now=datetime.now(timezone.utc)
        with patch.object(MUSL,'load_policy',return_value=policy),patch.object(MUSL.CONTRACT,'load_qualification_catalog',return_value=qualified):
            for change in ({'issuedAt':(now+timedelta(minutes=6)).isoformat()},
                {'expiresAt':(now+timedelta(days=32)).isoformat()},
                {'issuedAt':now.replace(tzinfo=timezone(timedelta(hours=9))).isoformat()}):
                with self.subTest(change=change),self.assertRaises(ValueError):MUSL.validate_catalog(dict(catalog,**change),now=now)
            old=dict(catalog,issuedAt=(now-timedelta(days=32)).isoformat(),expiresAt=(now-timedelta(days=2)).isoformat())
            MUSL.validate_catalog(old,now=now)
            with self.assertRaises(ValueError):MUSL.validate_catalog(old,now=now,fresh=True)

    def test_native_build_admission_binds_actual_compiler_bytes_scripts_and_elf_interpreter(self):
        from cbodotnetup_musl_native import build_inputs
        policy=MUSL.load_policy();arch='x64';rid=MUSL.ARCHITECTURES[arch]['rid'];binary='cbodotnetup-'+rid
        profile=json.loads((ROOT/'profiles/dotnet-10.0.403-linux-musl-x64.json').read_bytes())
        digest=hashlib.sha512(b'actual compiler archive').digest()
        normalized=hashlib.sha512(b'NuGet normalized package contents').digest()
        package=dict(id='microsoft.dotnet.ilcompiler',name='microsoft.dotnet.ilcompiler.10.0.14.nupkg',version='10.0.14',
            source='https://api.nuget.org/v3/index.json',size=100,sha256='d'*64,sha512=digest.hex(),
            contentHash=base64.b64encode(normalized).decode(),downloadHash=base64.b64encode(digest).decode())
        archive=dict(policy['archives'][arch],url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-musl-archive-sdk-10.0.403-r1/'+policy['archives'][arch]['name'])
        report=dict(schemaVersion=1,kind='cbodotnetup-native-build',libc='musl',version='0.5.1',architecture=arch,rid=rid,
            nativeRuntime='10.0.14',container=MUSL.musl_archive.BASES[arch],securityTests='passed',
            authenticatedSdk=dict(libc='musl',architecture=arch,targetRid=rid,archive=archive,
                publication=policy['publication'],sourceManifest=dict(sha256=policy['sourceManifestSha256'])),
            buildSdk=archive,sourceInputs={'tools/cbodotnetup/Program.cs':'a'*64},buildInputs=build_inputs(arch),nativePackages=[package],
            toolchain=dict(baseImage=MUSL.musl_archive.BASES[arch],imageId='sha256:'+'b'*64,clang='clang20',lld='LLD20',
                apkInputs=[dict(name='clang20-20.1.8-r3.apk',size=100,sha256='c'*64)],
                indexes=[dict(sha256=row['sha256']) for row in profile['apkIndexes'].values()],installedPackages=['musl-1.2.6-r3']),
            artifacts=[dict(path=binary,sha256='e'*64)],elfAudit=dict(schemaVersion=1,status='passed',native=True,libc='musl',
                architecture=arch,targetRid=rid,hostElfCount=1,nonHostElfCount=0,stockLibraries=[dict(name='musl')],
                elfFiles=[dict(path=binary,machine='Advanced Micro Devices X86-64',interpreter='/lib/ld-musl-x86_64.so.1',sha256='e'*64)]))
        MUSL.validate_tool_report(report,arch)
        self.assertNotEqual(package['contentHash'],package['downloadHash'])
        for change in (lambda r:r['buildInputs'].update({'scripts/cbodotnetup_musl.py':'f'*64}),
            lambda r:r['nativePackages'][0].update(source='https://untrusted.example/v3/index.json'),
            lambda r:r['nativePackages'][0].update(contentHash='invalid NuGet content hash'),
            lambda r:r['nativePackages'][0].update(downloadHash=package['contentHash']),
            lambda r:r['elfAudit']['elfFiles'][0].update(interpreter='/lib64/ld-linux-x86-64.so.2'),
            lambda r:r['toolchain']['indexes'].pop(),lambda r:r['elfAudit'].update(native=False)):
            bad=copy.deepcopy(report);change(bad)
            with self.subTest(change=change),self.assertRaises(ValueError):MUSL.validate_tool_report(bad,arch)
        baseline=dict(report,version='0.5.0')
        with self.assertRaisesRegex(ValueError,'version override'):MUSL.validate_tool_report(baseline,arch,version='0.5.0')
        MUSL.validate_tool_report(dict(baseline,versionOverride='-p:Version=0.5.0'),arch,version='0.5.0')

    def test_both_native_phase_reports_must_bind_exact_bytes_baseline_rollback_and_abi_rejection(self):
        policy,catalog,qualified=catalog_fixture()
        with patch.object(MUSL,'load_policy',return_value=policy),patch.object(MUSL.CONTRACT,'load_qualification_catalog',return_value=qualified):
            for public in (False,True):
                values=observations(catalog,public)
                MUSL.validate_qualifications(catalog,values,catalog_sha256='a'*64,bootstrap_sha256='b'*64,freeze_sha256='c'*64,public=public)
                changes=[lambda r:r.update(native=False),lambda r:r.update(rid='linux-x64'),
                    lambda r:r['checks'].pop('cross-libc-rejection'),lambda r:r.update(catalogSha256='f'*64),
                    lambda r:r['migration'].update(oldBinarySha256='f'*64),lambda r:r.update(crossLibcStatePreserved=False),
                    lambda r:r['toolElfAudit'].update(status='failed')]
                for change in changes:
                    bad=copy.deepcopy(values);change(bad[0])
                    with self.subTest(public=public,change=change),self.assertRaises(ValueError):
                        MUSL.validate_qualifications(catalog,bad,catalog_sha256='a'*64,bootstrap_sha256='b'*64,freeze_sha256='c'*64,public=public)


if __name__=='__main__':unittest.main()
