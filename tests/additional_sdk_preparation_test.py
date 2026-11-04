"""Preparation plans remain complete, source-pinned and unable to claim qualification."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('additional_sdk_preparation', ROOT / 'scripts/prepare-additional-sdks.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


class AdditionalSdkPreparationTests(unittest.TestCase):
    def setUp(self):
        self.data = PREP.load(ROOT / 'releases/additional-sdk-preparation.json')

    def test_all_seventy_seven_plans_are_inert_and_retain_the_production_admission_gate(self):
        result = PREP.prepare_plans(self.data)
        self.assertEqual(77, result['planCount'])
        self.assertEqual('not-run', result['execution'])
        self.assertEqual(12, result['parentEpic']['issueNumber'])
        self.assertEqual(77, len({(row['sdkVersion'], *row['target'].values()) for row in result['plans']}))
        for row in result['plans']:
            self.assertEqual('prepared-unqualified', row['status'])
            self.assertEqual('not-run', row['execution'])
            self.assertTrue(row['requiresProductionVerifiedPlan'])
            for flag in ('qualified', 'published', 'packageBuildAllowed', 'publicationAllowed'):
                self.assertIs(False, row[flag])
            # These planning records deliberately lack the canonical package
            # plan shape accepted after real verified_plan archive intake.
            self.assertNotIn('package', row)
            self.assertNotIn('sdk', row)

    def test_filters_derive_reviewed_namespaces_and_all_three_oci_commands(self):
        result = PREP.prepare_plans(self.data, sdk='8.0.133', channel='oci', variant='debian-13', arch='aarch64')
        self.assertEqual(1, result['planCount'])
        plan = result['plans'][0]
        self.assertEqual('/opt/cbodotnet/8.0', plan['proposedNamespace']['root'])
        self.assertEqual('linux-arm64', plan['targetRid'])
        self.assertEqual(17, plan['issueNumber'])
        self.assertEqual('https://github.com/dotnetdev-kr/cbodotnet/issues/17', plan['issueUrl'])
        self.assertEqual(['/usr/local/bin/cbodotnet-8.0', '/usr/local/bin/cbodotnet', '/usr/local/bin/dotnet'],
                         plan['proposedNamespace']['containerCommands'])
        aur = PREP.prepare_plans(self.data, sdk='9.0.123', channel='aur')['plans']
        self.assertEqual(1, len(aur))
        self.assertEqual('cbodotnet-sdk-9.0-bin', aur[0]['proposedPackageName'])

    def test_unknown_or_unselected_architecture_distro_channel_sdk_cannot_be_planned(self):
        for filters in ({'sdk': '10.0.403'}, {'channel': 'msi'}, {'variant': 'alpine'}, {'arch': 'arm64'},
                        {'channel': 'aur', 'arch': 'aarch64'}, {'channel': 'rpm', 'variant': 'debian-13'}):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                PREP.prepare_plans(self.data, **filters)

    def test_missing_duplicate_or_unsupported_matrix_rows_are_rejected(self):
        mutations = [lambda data: data['sdks'][0]['targets'].pop(),
                     lambda data: data['sdks'][0]['targets'].__setitem__(1, copy.deepcopy(data['sdks'][0]['targets'][0])),
                     lambda data: data['sdks'][0]['targets'][0].update(variant='ubuntu-22.04'),
                     lambda data: data['sdks'].__setitem__(1, copy.deepcopy(data['sdks'][0])),
                     lambda data: data['targetTemplate'].pop()]
        for mutate in mutations:
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                PREP.prepare_plans(data)

    def test_wrong_manifest_pin_embedded_manifest_or_asset_digest_is_rejected(self):
        mutations = [lambda data: data['sdks'][0]['publicRelease']['manifest'].update(sha256='0' * 64),
                     lambda data: data['sdks'][0]['publicRelease']['manifest']['document'].update(repository='someone/fork'),
                     lambda data: data['sdks'][0]['architectures']['x64']['sdk'].update(sha256='0' * 64),
                     lambda data: data['sdks'][0]['architectures']['x64']['source'].update(url='https://example.com/source.tar.gz')]
        for mutate in mutations:
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                PREP.prepare_plans(data)

    def test_wrong_producer_in_either_the_record_or_catalog_is_rejected(self):
        data = copy.deepcopy(self.data)
        data['sdks'][0]['architectures']['x64']['provenance']['runId'] = '999'
        with self.assertRaisesRegex(ValueError, 'producer'):
            PREP.prepare_plans(data)
        catalog = PREP.load(ROOT / 'releases/qualified-builds.json')
        next(row for row in catalog['builds'] if row['sdkVersion'] == '9.0.123')['architectures']['aarch64']['projectCommit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'producer'):
            PREP.prepare_plans(self.data, catalog=catalog)

    def test_execution_admission_or_qualification_flags_cannot_be_enabled(self):
        mutations = [lambda data: data['productionEffect'].update(releaseAdmitted=True),
                     lambda data: data['productionEffect'].update(sdkBuilt=True),
                     lambda data: data['sdks'][0].update(currentContractAdmission=True),
                     lambda data: data['sdks'][0]['targets'][0].update(published=True),
                     lambda data: data['sdks'][0]['targets'][0].update(qualification='qualified'),
                     lambda data: data['sdks'][0]['targets'][0].update(installedPackageOrContainerEvidence='passed'),
                     lambda data: data['sdks'][0]['targets'][0].update(qualified=True),
                     lambda data: data['summary'].update(channelTargetsQualified=1)]
        for mutate in mutations:
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                PREP.prepare_plans(data)

    def test_series_cannot_redirect_an_older_sdk_to_the_published_net10_root(self):
        self.data['sdks'][0]['series'] = '10.0'
        with self.assertRaisesRegex(ValueError, 'namespace'):
            PREP.prepare_plans(self.data)

    def test_legacy_provider_blockers_are_retained_for_every_affected_target(self):
        plans = PREP.prepare_plans(self.data, sdk='3.1.426')['plans']
        self.assertEqual(11, len(plans))
        for plan in plans:
            self.assertEqual('blocked-external-dependency-policy', plan['preparationState'])
            self.assertIn('external-openssl11', plan['requiredGates'])
            if plan['target']['variant'] in {'debian-13', 'fedora-45', 'arch-rolling'}:
                self.assertIn('external-core3-icu', plan['requiredGates'])
        self.data['sdks'][-1]['targets'][0]['requiredGates'].remove('external-openssl11')
        with self.assertRaisesRegex(ValueError, 'gate was omitted'):
            PREP.prepare_plans(self.data)

    def test_local_profile_and_contract_lf_or_crlf_checkouts_produce_identical_plans(self):
        original = Path.read_bytes

        def checkout(path, crlf):
            value = original(path)
            if path.parent == PREP.ROOT / 'profiles' or path == PREP.ROOT / 'releases/distribution-contract.json':
                value = value.replace(b'\r\n', b'\n')
                if crlf:
                    value = value.replace(b'\n', b'\r\n')
            return value

        with mock.patch.object(Path, 'read_bytes', lambda path: checkout(path, False)):
            lf = PREP.prepare_plans(self.data)
        with mock.patch.object(Path, 'read_bytes', lambda path: checkout(path, True)):
            crlf = PREP.prepare_plans(self.data)
        self.assertEqual(77, lf['planCount'])
        self.assertEqual(lf, crlf)

    def test_semantic_profile_change_still_rejects_the_pinned_text_digest(self):
        original = Path.read_bytes
        selected = PREP.ROOT / 'profiles/dotnet-9.0.123-linux-x64.json'

        def changed(path):
            value = original(path)
            if path == selected:
                replacement = value.replace(b'"sdkVersion": "9.0.123"', b'"sdkVersion": "9.0.124"')
                self.assertNotEqual(value, replacement)
                return replacement
            return value

        with mock.patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'Preparation profile changed'):
                PREP.prepare_plans(self.data)

    def test_public_manifests_and_binary_archives_cannot_use_checkout_text_hashing(self):
        for path in (PREP.ROOT / 'releases/release-manifest.json', PREP.ROOT / 'profiles/sdk.tar.gz'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'limited to profile and contract JSON'):
                PREP.checkout_text_digest(path)


if __name__ == '__main__':
    unittest.main()
