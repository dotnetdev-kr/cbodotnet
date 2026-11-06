from pathlib import Path
import copy
import hashlib
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cbodotnetup_matrix import SDK_CHECKS,validate_additional_sdk_qualifications
from consumer_archive import FUNCTIONAL_CHECKS


class InstallerMatrixTests(unittest.TestCase):
    def inputs(self):
        variants=[('ubuntu','24.04'),('debian','13'),('fedora','45'),('rocky','9.8')]
        versions=['10.0.403','9.0.123','8.0.133','7.0.120','6.0.136']
        sdks=[]
        for version in versions:
            for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
                revision=3 if version=='10.0.403' else 2
                sdks.append(dict(sdkVersion=version,revision=revision,rid=rid,requiresLegacyProvider=False,
                    archive=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/cbodotnet-sdk-{version}-linux-{arch}-r{revision}.tar.gz',
                                 size=123,sha256=hashlib.sha256((version+rid).encode()).hexdigest()),
                    sourceManifestSha256=hashlib.sha256(version.encode()).hexdigest(),
                    targets=[dict(os=os,versionId=number,rid=rid) for os,number in variants]))
        def alias(sdk):
            return dict(sdkVersion=sdk['sdkVersion'],packageRevision=sdk['revision'],targetRid=sdk['rid'],
                        sourceManifestSha256=sdk['sourceManifestSha256'],qualifiedPayloadModified=False)
        observations=[]
        for os,number in variants:
            for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
                context=dict(variant=os+'-'+number,architecture=arch,catalogSha256='a'*64,
                    bootstrapSha256='b'*64,binarySha256='c'*64,bootstrapBinarySource='public-https')
                baseline=next(sdk for sdk in sdks if sdk['sdkVersion']=='10.0.403' and sdk['rid']==rid)
                rows=[]
                for sdk in sdks:
                    if sdk['rid']!=rid or sdk['sdkVersion']=='10.0.403':continue
                    rows.append(dict(context,status='passed',sdkVersion=sdk['sdkVersion'],revision=sdk['revision'],rid=rid,
                        target=dict(os=os,versionId=number,rid=rid),archive=copy.deepcopy(sdk['archive']),
                        sourceManifestSha256=sdk['sourceManifestSha256'],networkForBuild='none',userId=10001,
                        checks=dict.fromkeys(SDK_CHECKS,'passed'),functionalChecks=dict.fromkeys(FUNCTIONAL_CHECKS,'passed'),
                        aliases=[alias(baseline),alias(baseline),alias(sdk)]))
                observations.append(dict(context,additionalSdkQualifications=rows))
        return dict(schemaVersion=2,sdks=sdks,revoked=[]),observations

    def test_all_thirty_two_cells_are_independently_bound(self):
        catalog,observations=self.inputs()
        rows=validate_additional_sdk_qualifications(catalog,observations)
        self.assertEqual(len(rows),32)
        self.assertEqual({row['sdkVersion'] for row in rows},{'9.0.123','8.0.133','7.0.120','6.0.136'})

    def test_ten_only_historical_feed_needs_no_additional_proof(self):
        catalog,observations=self.inputs()
        catalog['sdks']=[sdk for sdk in catalog['sdks'] if sdk['sdkVersion']=='10.0.403']
        for observation in observations:observation.pop('additionalSdkQualifications')
        self.assertEqual(validate_additional_sdk_qualifications(catalog,observations),[])

    def test_a_passed_target_summary_cannot_replace_one_missing_sdk_cell(self):
        catalog,observations=self.inputs();observations[0]['additionalSdkQualifications'].pop()
        with self.assertRaisesRegex(ValueError,'Every additional'):validate_additional_sdk_qualifications(catalog,observations)

    def test_duplicate_cell_cannot_cover_a_missing_cpu_or_os(self):
        catalog,observations=self.inputs();observations[0]['additionalSdkQualifications'][0]=copy.deepcopy(observations[0]['additionalSdkQualifications'][1])
        with self.assertRaisesRegex(ValueError,'duplicate'):validate_additional_sdk_qualifications(catalog,observations)

    def test_archive_source_revision_and_actual_target_are_closed(self):
        mutations=[lambda row:row['archive'].update(sha256='d'*64),lambda row:row.update(sourceManifestSha256='d'*64),
                   lambda row:row.update(revision=1),lambda row:row['target'].update(versionId='22.04'),
                   lambda row:row.update(architecture='aarch64'),lambda row:row.update(rid='linux-musl-x64'),
                   lambda row:row.update(catalogSha256='d'*64),lambda row:row.update(bootstrapBinarySource='unverified')]
        for mutate in mutations:
            catalog,observations=self.inputs();mutate(observations[0]['additionalSdkQualifications'][0])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):validate_additional_sdk_qualifications(catalog,observations)

    def test_every_lifecycle_and_functional_check_is_required(self):
        for field in ('checks','functionalChecks'):
            catalog,observations=self.inputs();row=observations[0]['additionalSdkQualifications'][0]
            row[field].pop(next(iter(row[field])))
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'incomplete'):validate_additional_sdk_qualifications(catalog,observations)

    def test_offline_non_root_execution_and_alias_sources_are_required(self):
        mutations=[lambda row:row.update(networkForBuild='enabled'),lambda row:row.update(userId=0),
                   lambda row:row['aliases'][2].update(sdkVersion='10.0.403'),
                   lambda row:row['aliases'][0].update(sourceManifestSha256='d'*64),
                   lambda row:row['aliases'][2].update(qualifiedPayloadModified=True)]
        for mutate in mutations:
            catalog,observations=self.inputs();mutate(observations[0]['additionalSdkQualifications'][0])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):validate_additional_sdk_qualifications(catalog,observations)

    def test_revoked_or_legacy_provider_sdk_cannot_be_promoted(self):
        catalog,observations=self.inputs();sdk=next(s for s in catalog['sdks'] if s['sdkVersion']=='9.0.123')
        catalog['revoked']=[sdk['sdkVersion']+'-r'+str(sdk['revision'])+'/'+sdk['rid']]
        with self.assertRaisesRegex(ValueError,'revoked'):validate_additional_sdk_qualifications(catalog,observations)
        catalog['revoked']=[];sdk['requiresLegacyProvider']=True
        with self.assertRaisesRegex(ValueError,'legacy'):validate_additional_sdk_qualifications(catalog,observations)


if __name__=='__main__':unittest.main()
