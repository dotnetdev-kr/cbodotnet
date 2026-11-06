from pathlib import Path
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cbodotnetup_project as PROJECT


class ProjectReferenceTests(unittest.TestCase):
    def evidence(self):
        fixture = PROJECT.reference_fixture()
        rows = []
        for case in fixture['cases']:
            version = case.get('nativeExpectedVersion', case['expectedVersion'])
            rows.append(dict(name=case['name'], expectedVersion=case['expectedVersion'],
                             nativeExpectedVersion=version, resolvedVersion=version,
                             nativeState=case.get('nativeState', 'not_found' if PROJECT.configuration_bytes(case) is None else 'valid'),
                             exitCode=0 if version else -2147450725, failClosed=case.get('failClosed', False)))
        return dict(schemaVersion=1, scope=PROJECT.REFERENCE_SCOPE, status='passed',
                    fixtureSha256=hashlib.sha256(PROJECT.FIXTURE.read_bytes()).hexdigest(),
                    fixtureKind='empty-SDK-markers-matching-only-no-SDK-execution',
                    library=dict(relativePath='host/fxr/10.0.14/libhostfxr.so', size=123, sha256='a' * 64),
                    cases=rows)

    def test_shared_native_resolver_fixture_covers_nine_policies_and_security_divergences(self):
        cases = PROJECT.reference_fixture()['cases']
        self.assertEqual({row.get('policy') for row in cases if row['category'] == 'rollForward'}, set(PROJECT.POLICIES))
        self.assertGreaterEqual(sum(row['category'] == 'prerelease' for row in cases), 6)
        self.assertIn('comments', {row['name'] for row in cases})
        self.assertIn('trailing-comma', {row['name'] for row in cases if row.get('failClosed')})
        self.assertGreaterEqual(sum(row.get('failClosed', False) for row in cases), 10)
        self.assertEqual(PROJECT.validate_reference_evidence(self.evidence()), len(cases))

    def test_partial_and_duplicate_native_reference_proofs_are_rejected(self):
        for mutation in (lambda rows: rows.pop(), lambda rows: rows.append(rows[0]),
                         lambda rows: rows.__setitem__(1, rows[0]), lambda rows: rows.reverse()):
            value = self.evidence(); mutation(value['cases'])
            with self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    def test_native_result_must_match_the_shared_case_not_just_report_passed(self):
        for field, forged in [('resolvedVersion', '99.0.999'), ('nativeExpectedVersion', '99.0.999'),
                              ('nativeState', 'invalid_data'), ('expectedVersion', '99.0.999'),
                              ('exitCode', -1), ('failClosed', True)]:
            value = self.evidence(); value['cases'][0][field] = forged
            with self.subTest(field=field), self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    def test_undefined_resolver_exit_cannot_be_reported_as_success(self):
        value = self.evidence()
        row = next(row for row in value['cases'] if row['nativeExpectedVersion'] is None)
        row['exitCode'] = 0
        with self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    def test_fail_closed_difference_is_recorded_without_admitting_the_fallback(self):
        value = self.evidence()
        row = next(row for row in value['cases'] if row['name'] == 'malformed-json')
        self.assertIsNone(row['expectedVersion']); self.assertTrue(row['failClosed'])
        self.assertEqual(row['nativeState'], 'invalid_json'); self.assertIsNotNone(row['nativeExpectedVersion'])
        PROJECT.validate_reference_evidence(value)
        row['failClosed'] = False
        with self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    def test_reference_cannot_claim_synthetic_or_preview_sdk_execution(self):
        value = self.evidence(); value['fixtureKind'] = 'preview-SDK-native-qualification'
        with self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    def test_unreviewed_fixture_bytes_and_missing_library_identity_are_rejected(self):
        for field, forged in [('fixtureSha256', 'b' * 64), ('status', 'skipped'), ('scope', 'SDK-execution')]:
            value = self.evidence(); value[field] = forged
            with self.subTest(field=field), self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)
        for key, forged in [('relativePath', '/usr/share/dotnet/host/fxr/10.0.14/libhostfxr.so'),
                            ('relativePath', '../outside/libhostfxr.so'), ('size', 0), ('sha256', 'unbound')]:
            value = self.evidence(); value['library'][key] = forged
            with self.subTest(key=key), self.assertRaises(ValueError): PROJECT.validate_reference_evidence(value)

    @unittest.skipUnless(sys.platform == 'linux' and os.environ.get('CBODOTNETUP_TEST_REFERENCE_PAYLOAD'),
                         'An actual admitted Linux SDK reference payload is required')
    def test_actual_native_host_resolves_identical_shared_fixture_without_payload_edits(self):
        payload = Path(os.environ['CBODOTNETUP_TEST_REFERENCE_PAYLOAD'])
        libraries = list((payload / 'host/fxr').glob('*/libhostfxr.so'))
        before = {path: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in libraries}
        with tempfile.TemporaryDirectory(prefix='cbodotnetup-native-reference-test-') as temporary:
            proof = PROJECT.qualify_reference(payload, Path(temporary) / 'isolated')
            self.assertEqual(PROJECT.validate_reference_evidence(proof), len(PROJECT.reference_fixture()['cases']))
        after = {path: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in libraries}
        self.assertEqual(before, after)


class ProjectNativeEvidenceTests(unittest.TestCase):
    def evidence(self):
        sdk = dict(sdkVersion='9.0.123', revision=2, rid='linux-arm64', sourceManifestSha256='a' * 64)
        baseline = dict(sdkVersion='10.0.403', revision=3, rid='linux-arm64')
        lower = ['nearest-ancestor', 'exact-project-pin', 'patch-roll-forward', 'comments',
                 'prerelease-policy', 'host-paths', 'versioned-alias-precedence',
                 'explicit-run-lower-precedence', 'sdk-info-selection', 'msbuild-owned-sdk', 'msbuild-project-conflict']
        higher = ['highest-without-project', 'nearest-file-boundary', 'major-roll-forward',
                  'explicit-run-precedence', 'msbuild-explicit-override']
        rejected = ['feature-band-rejection', 'missing-sdk-no-install', 'missing-admitted-sdk-no-install', 'malformed-fail-closed',
                    'trailing-comma-fail-closed', 'relative-path-rejection', 'absolute-path-rejection',
                    'empty-paths-rejection', 'symlink-path-rejection', 'symlink-global-rejection', 'runtime-options-sdk-rejection']
        rows = [dict(name=name, status='passed', expectedVersion=version, exitCode=0 if version else 1)
                for names, version in [(lower, sdk['sdkVersion']), (higher, baseline['sdkVersion']), (rejected, None)]
                for name in names]
        rows.append(dict(name='sdk-arguments-offline', status='passed', expectedVersion=sdk['sdkVersion'], exitCode=1))
        rows.extend(dict(name=name, status='passed', expectedVersion=baseline['sdkVersion'], exitCode=129)
                    for name in ['missing-app-runtime-dispatch', 'runtime-options-missing-app'])
        value = dict(schemaVersion=1, scope=PROJECT.PROJECT_SCOPE, status='passed',
                     sdkVersion=sdk['sdkVersion'], baselineVersion=baseline['sdkVersion'], network='none',
                     checks=dict.fromkeys(PROJECT.PROJECT_CHECKS, 'passed'), cases=rows,
                     identity=dict(sdkVersion=sdk['sdkVersion'], packageRevision=sdk['revision'], targetRid=sdk['rid'],
                                   sourceManifestSha256=sdk['sourceManifestSha256'], qualifiedPayloadModified=False),
                     projectFilesSha256='b' * 64, projectFilesUnchanged=True, ownedStateUnchanged=True,
                     missingAdmittedSdk=dict(sdkVersion='8.0.133', revision=2, rid=sdk['rid'], sourceManifestSha256='c' * 64),
                     ownedPayloadsUnchanged=True, ownedPayloadVerification='signed-receipt-and-inventory-doctor-before-and-after')
        return value, sdk, baseline

    def test_project_proof_binds_all_thirty_actual_selection_cases(self):
        value, sdk, baseline = self.evidence()
        self.assertEqual(PROJECT.validate_project_evidence(value, sdk, baseline), 30)

    def test_explicit_override_and_empty_nearest_file_cannot_fall_back_to_project_sdk(self):
        for name in ['explicit-run-precedence', 'nearest-file-boundary', 'msbuild-explicit-override']:
            value, sdk, baseline = self.evidence()
            next(row for row in value['cases'] if row['name'] == name)['expectedVersion'] = sdk['sdkVersion']
            with self.subTest(name=name), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_uninstalled_or_external_project_sdk_cannot_be_reported_as_executable(self):
        for name in ['missing-sdk-no-install', 'feature-band-rejection', 'absolute-path-rejection', 'symlink-path-rejection']:
            value, sdk, baseline = self.evidence()
            next(row for row in value['cases'] if row['name'] == name).update(expectedVersion=sdk['sdkVersion'], exitCode=0)
            with self.subTest(name=name), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_msbuild_conflict_and_ownership_proofs_are_mandatory(self):
        value, sdk, baseline = self.evidence()
        value['cases'] = [row for row in value['cases'] if row['name'] != 'msbuild-project-conflict']
        with self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)
        for field in ['projectFilesUnchanged', 'ownedStateUnchanged', 'ownedPayloadsUnchanged']:
            value, sdk, baseline = self.evidence(); value[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_project_identity_cannot_select_another_source_revision_or_rid(self):
        for field, forged in [('sourceManifestSha256', 'f' * 64), ('packageRevision', 1),
                              ('targetRid', 'linux-x64'), ('sdkVersion', '8.0.133'), ('qualifiedPayloadModified', True)]:
            value, sdk, baseline = self.evidence(); value['identity'][field] = forged
            with self.subTest(field=field), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_online_or_partial_project_run_cannot_activate_the_feed(self):
        for field, forged in [('network', 'bridge'), ('status', 'skipped'), ('projectFilesSha256', 'missing')]:
            value, sdk, baseline = self.evidence(); value[field] = forged
            with self.subTest(field=field), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)
        value, sdk, baseline = self.evidence(); value['checks'].pop('payload-inventory-preserved')
        with self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_missing_project_suggests_only_an_authenticated_admitted_sdk(self):
        value, sdk, baseline = self.evidence()
        record = dict(value['missingAdmittedSdk'], requiresLegacyProvider=False)
        catalog = dict(sdks=[record], revoked=[])
        PROJECT.validate_project_evidence(value, sdk, baseline, catalog)
        for forged in [dict(sdks=[], revoked=[]), dict(sdks=[dict(record, sourceManifestSha256='d' * 64)], revoked=[]),
                       dict(sdks=[record], revoked=['8.0.133-r2/linux-arm64'])]:
            with self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline, forged)

    def test_sdk_argument_error_is_not_an_installer_network_operation(self):
        value, sdk, baseline = self.evidence()
        next(row for row in value['cases'] if row['name'] == 'sdk-arguments-offline')['exitCode'] = 0
        with self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)

    def test_missing_app_must_not_reenter_sdk_resolution_even_under_uninstalled_pin(self):
        for name in ['missing-app-runtime-dispatch', 'runtime-options-missing-app']:
            value, sdk, baseline = self.evidence()
            next(row for row in value['cases'] if row['name'] == name)['exitCode'] = 155
            with self.subTest(name=name), self.assertRaises(ValueError): PROJECT.validate_project_evidence(value, sdk, baseline)


if __name__ == '__main__':
    unittest.main()
