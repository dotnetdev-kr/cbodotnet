"""Reject fabricated reference histories, partial coexistence states and changed payloads."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_side_by_side as M
from musl_archive_test import prepared_inputs
from downstream_release import encoded


def reference_fixture(directory):
    inputs = directory / 'inputs'
    inputs.mkdir()
    catalog = prepared_inputs(inputs)
    plan = M.ARCHIVE.intake(inputs, 'x64', catalog=catalog)
    plan['channel'] = 'apk'
    receipt = copy.deepcopy(M.pinned_receipt()[0])
    producer = catalog['builds'][0]
    receipt['identity']['sourceManifestSha256'] = producer['sourceManifestSha256']
    policy = M.load(ROOT / 'releases/musl-signing-policy.json')['apkSigner']
    signing = dict(filename=policy['publicKeyName'], algorithm='RSA-4096', signatureType='RSA256',
                   digestAlgorithm='SHA-256', spkiSha256=policy['spkiDerSha256'], sha256=policy['publicKeySha256'])
    public = next(row for row in receipt['assets'] if row['name'] == policy['publicKeyName'])
    packages = [dict(kind=kind, name=name, path=name + '-' + version + '.apk', version=version, architecture=arch,
                     size=20, sha256='a' * 64, controlSha256='b' * 64, dataSha256='c' * 64)
                for kind, name, version, arch in [('sdk', 'cbodotnet-sdk-10.0', '10.0.403-r1', 'x86_64'),
                                                  ('host', 'cbodotnet-host', M.APK.HOST_VERSION, 'noarch')]]
    build = dict(plan=plan, signingKey=signing, packages=packages,
                 publicKeyAsset={key: public[key] for key in ('name', 'size', 'sha256')})
    for name, value in (('plan.json', plan), ('package-build.json', build)):
        row = next(row for row in receipt['assets'] if row['name'] == 'apk-x64--' + name)
        row.update(size=len(encoded(value)), sha256=M.digest(value))
    record = dict(schemaVersion=1, kind='musl-public-apk-coexistence-reference', architecture='x64',
                  aggregate={key: receipt[key] for key in ('tag', 'manifestUrl', 'manifestSha256', 'signingFingerprint')},
                  plan=plan, build=build, files=M.reference_files('x64', receipt))
    return record, receipt, producer


def candidate(reference, version='9.0.123', revision=1):
    build = copy.deepcopy(reference['build'])
    plan = build['plan']
    series = '.'.join(version.split('.')[:2])
    plan.update(sdkVersion=version, packageRevision=revision, sourceReleaseTag='musl-sdk-' + version + '-r1',
                sourceManifestSha256='d' * 64)
    plan['package'] = dict(name='cbodotnet-sdk-' + series, root='/opt/cbodotnet/' + series,
                           launcher='/usr/bin/cbodotnet-' + series, version=version + '-r' + str(revision))
    build['signingKey'] = dict(build['signingKey'], filename='build.rsa.pub', sha256='e' * 64)
    for row in build['packages']:
        if row['kind'] == 'sdk':
            row.update(name=plan['package']['name'], version=plan['package']['version'],
                       path=plan['package']['name'] + '-' + plan['package']['version'] + '.apk')
    return build


def proof_fixture(build, upgrade, record, payload):
    inventories = dict(candidate=M.digest(payload), reference=record['files']['payload-inventory.json']['sha256'])
    official = dict(version='10.0.303', owner='/usr/bin/dotnet is owned by dotnet-host-10.0.14-r0',
                    host=dict(name='dotnet', size=100, sha256='f' * 64), treeSha256='1' * 64)
    events = []
    for name, state in M.event_states(build, upgrade, record):
        selected = M.selected_version(state)
        events.append(dict(operation=name, installed={label: dict(identity=M.ARCHIVE.identity(plan), payloadSha256=inventories[label])
                           for label, plan in state.items() if plan is not None}, defaultSdkVersion=selected,
                           defaultExitCode=0 if selected else (None if name == 'host-remove' else 127),
                           officialTreeSha256=official['treeSha256']))
    return dict(schemaVersion=1, scope='musl-apk-community-series-coexistence', status='passed', native=True,
                architecture='x64', libc='musl', targetRid='linux-musl-x64', identity=M.ARCHIVE.identity(build['plan']),
                upgradeIdentity=M.ARCHIVE.identity(upgrade['plan']), referenceRecord=record, networkForTransactions='none',
                executionUser=dict(name='cbot-musl', uid=10001, gid=10001), candidateSigningKey=build['signingKey'],
                inputs=dict(candidate=M.package_inputs(build), upgrade=M.package_inputs(upgrade), reference=M.package_inputs(record['build'])),
                payloadInventories=inventories, official=official, events=events, allCommunityPathsRemoved=True, approvedTrustRestored=True)


class ReferenceAuthentication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.record, receipt, producer = reference_fixture(Path(self.temporary.name))
        self.pins = mock.patch.object(M, 'pinned_receipt', return_value=(receipt, producer))
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def test_reference_authentication_is_pure_and_preserves_retained_history(self):
        with mock.patch.object(M.subprocess, 'run', side_effect=AssertionError('No execution in protected validator')):
            self.assertEqual(self.record, M.authenticate_reference_record(self.record, 'x64'))
        self.assertEqual(8, len(self.record['files']))
        self.assertIn('repository/APKINDEX.tar.gz', self.record['files'])

    def test_reference_source_key_packages_and_extra_fields_cannot_be_relabelled(self):
        for mutate in (lambda r: r['aggregate'].update(manifestSha256='0' * 64),
                       lambda r: r['plan'].update(sourceManifestSha256='0' * 64),
                       lambda r: r['build']['signingKey'].update(sha256='0' * 64),
                       lambda r: r['files']['repository/APKINDEX.tar.gz'].update(sha256='0' * 64),
                       lambda r: r.update(sourceAdmission=True)):
            changed = copy.deepcopy(self.record)
            mutate(changed)
            with self.assertRaises(ValueError):
                M.authenticate_reference_record(changed, 'x64')
        with self.assertRaises(ValueError):
            M.authenticate_reference_record(self.record, 'aarch64')

    def test_complete_real_series_state_matrix_rejects_wrong_default_partial_and_changed_bytes(self):
        payload = {'dotnet': ['file', 0o755, '2' * 64]}
        for version in ('9.0.123', '8.0.133'):
            build, upgrade = candidate(self.record, version), candidate(self.record, version, 2)
            proof = proof_fixture(build, upgrade, self.record, payload)
            self.assertEqual(proof, M.validate(proof, build, upgrade, self.record, candidate_payload=payload))
            self.assertEqual(version, proof['events'][0]['defaultSdkVersion'])
            self.assertEqual('10.0.403', proof['events'][1]['defaultSdkVersion'])
            self.assertEqual(version, proof['events'][5]['defaultSdkVersion'])
            self.assertEqual(127, proof['events'][-2]['defaultExitCode'])
            for mutate in (lambda p: p['events'].pop(),
                           lambda p: p['events'][1].update(defaultSdkVersion=version),
                           lambda p: p['events'][3]['installed']['reference'].update(payloadSha256='0' * 64),
                           lambda p: p['events'][7].update(officialTreeSha256='0' * 64),
                           lambda p: p['inputs']['candidate'][0].update(sha256='0' * 64),
                           lambda p: p.update(native=False),
                           lambda p: p.update(approvedTrustRestored=False),
                           lambda p: p.update(unreviewed=True)):
                changed = copy.deepcopy(proof)
                mutate(changed)
                with self.assertRaises(ValueError):
                    M.validate(changed, build, upgrade, self.record, candidate_payload=payload)
            with self.assertRaisesRegex(ValueError, 'payload inventory'):
                M.validate(proof, build, upgrade, self.record, candidate_payload={'different': []})

    def test_protected_promotion_requires_real_second_series_evidence_for_expanded_sdks(self):
        from musl_apk_promotion_test import lifecycle, ORIGIN
        build, upgrade = candidate(self.record), candidate(self.record, revision=2)
        for value in (build, upgrade):
            value['repository'] = dict(path='APKINDEX.tar.gz', size=20, sha256='a'*64)
        report = lifecycle(build, upgrade)
        with self.assertRaisesRegex(ValueError, 'actual second Community series coexistence'):
            M.PROMOTION.validate_lifecycle(report, build, upgrade, ORIGIN, build['signingKey'])
        report['communitySeriesCoexistence'] = proof_fixture(build, upgrade, self.record, {'dotnet': ['original']})
        self.assertEqual(report, M.PROMOTION.validate_lifecycle(report, build, upgrade, ORIGIN, build['signingKey']))
        report['communitySeriesCoexistence']['events'].pop()
        with self.assertRaises(ValueError):
            M.PROMOTION.validate_lifecycle(report, build, upgrade, ORIGIN, build['signingKey'])


if __name__ == '__main__':
    unittest.main()
