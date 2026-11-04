"""Authenticate downstream evidence and refuse incomplete or conflicting promotion."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_contract as CONTRACT
from distribution_commands import stage_commands
import downstream_release as RELEASE
from release_catalog_test import fixture


class DownstreamReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        release, manifest, manifest_bytes, checksums = fixture()
        (self.inputs / 'release.json').write_text(json.dumps(release))
        (self.inputs / 'release-manifest.json').write_bytes(manifest_bytes)
        (self.inputs / 'SHA256SUMS').write_bytes(checksums)
        for arch, row in manifest['architectures'].items():
            (self.inputs / row['sdk']['name']).write_bytes(('sdk' + arch).encode())
        self.contract = copy.deepcopy(CONTRACT.load_contract())
        self.contract['releases']['10.0.403']['manifestSha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        self.catalog = {'schemaVersion': 1, 'repository': RELEASE.REPOSITORY, 'builds': [
            {'sdkVersion': '10.0.403', 'target': 'net10', 'architectures': {
                arch: {key: value['provenance'][key] for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')}
                for arch, value in manifest['architectures'].items()}}]}
        self.policy = copy.deepcopy(RELEASE.load_status())
        self.policy['channels']['deb']['candidateMatrix'] = [
            {'variant': 'debian-13', 'architecture': arch} for arch in ('x64', 'aarch64')]
        self.orchestration = dict(repository=RELEASE.REPOSITORY, workflow='.github/workflows/downstream-verify.yml',
                                  commit='c' * 40, runId='1234', runAttempt='1')
        self.items = []
        for arch in ('x64', 'aarch64'):
            plan = RELEASE.local_intake(self.inputs, 'deb', 'debian-13', arch, contract=self.contract, catalog=self.catalog)
            artifact = self.root / f'cbodotnet-10.0.403-{arch}.deb'
            artifact.write_bytes(('package-' + arch).encode())
            commands_root = self.root / (arch + '-commands')
            commands_root.mkdir()
            inventory = stage_commands(commands_root, plan)
            packaged = RELEASE.package_record(plan, artifact, self.orchestration,
                                               extra_files={'root': commands_root, 'inventory': inventory})
            target = self.contract['operatingSystems']['debian-13']
            report = {'schemaVersion': 1, 'status': 'passed', 'phase': 'prepublication',
                      'scope': 'channel-installation',
                      **{key: packaged[key] for key in ('contractVersion', 'identity', 'artifact', 'producer', 'orchestration', 'commands', 'branding', 'extraFiles', 'source')},
                      'target': {'osId': target['id'], 'versionId': target['versionId'],
                                 'architecture': arch, 'native': True,
                                 'dependencies': {name: '1.0' for name in target['dependencies']}},
                      'checks': {name: 'passed' for name in RELEASE.PREPUBLICATION_CHECKS
                                 | set(self.policy['channels']['deb']['requiredChecks'])}}
            report_path = self.root / (arch + '-report.json')
            report_path.write_text(json.dumps(report))
            signature = self.root / (arch + '-report.sig')
            signature.write_bytes(b'test-signature')
            keyring = self.root / 'fixture-keyring.gpg'
            keyring.write_bytes(b'test-keyring')
            self.items.append(dict(package=packaged, artifactPath=artifact, reportPath=report_path,
                                   signaturePath=signature, keyringPath=keyring, commandsRoot=commands_root,
                                   inputsDirectory=self.inputs))
        self.ledger = self.root / 'ledger'
        self.ledger.mkdir()
        # Pure gate tests isolate signature cryptography, exercised separately below.
        patcher = mock.patch.object(RELEASE, 'verify_report_signature', return_value='A' * 40)
        patcher.start()
        self.addCleanup(patcher.stop)

    def stage(self, items=None):
        return RELEASE.stage_records(self.items if items is None else items, self.ledger,
                                     self.policy, self.contract, self.catalog)

    def change_report(self, callback):
        path = self.items[0]['reportPath']
        value = json.loads(path.read_bytes())
        callback(value)
        path.write_text(json.dumps(value))

    def test_verified_local_intake_and_complete_stage_are_traceable_and_unpublished(self):
        result = self.stage()
        self.assertEqual('staged-unpublished', result['status'])
        self.assertFalse(result['publicationAllowed'])
        self.assertEqual(self.contract['schemaVersion'], result['contractVersion'])
        self.assertTrue(all(row['contractVersion'] == result['contractVersion'] for row in result['records']))
        self.assertEqual({'aarch64', 'x64'}, {row['architecture'] for row in result['records']})
        self.assertEqual(self.contract['releases']['10.0.403']['manifestSha256'],
                         result['identity']['sourceManifestSha256'])
        self.assertTrue((self.ledger / 'deb-10.0.403-r1.json').is_file())

    def test_matching_retry_reuses_identical_immutable_record(self):
        first = self.stage()
        self.assertEqual(first, self.stage())
        self.assertEqual(1, len(list(self.ledger.iterdir())))

    def test_partial_duplicate_or_extra_matrix_leaves_no_ledger(self):
        for items in (self.items[:1], self.items + self.items[:1]):
            with self.subTest(size=len(items)), self.assertRaisesRegex(ValueError, 'matrix'):
                self.stage(items)
        self.assertEqual([], list(self.ledger.iterdir()))

    def test_corrupt_artifact_is_rejected_even_when_a_report_says_passed(self):
        self.items[0]['artifactPath'].write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact changed'):
            self.stage()

    def test_changed_command_bytes_or_missing_inventory_cannot_pass_stage(self):
        command = self.items[0]['commandsRoot'] / 'usr/bin/cbodotnet'
        command.write_text('#!/bin/sh\nexec dotnet "$@"\n')
        with self.assertRaisesRegex(ValueError, 'command bytes'):
            self.stage()

    def test_rewritten_command_namespace_cannot_take_over_official_dotnet(self):
        self.items[0]['package']['commands']['versioned'] = '/usr/bin/dotnet'
        with self.assertRaisesRegex(ValueError, 'Command namespace'):
            self.stage()

    def test_editable_package_and_signed_report_cannot_substitute_source_descriptors(self):
        item = self.items[0]
        item['package']['source']['sdk']['sha256'] = 'f' * 64
        self.change_report(lambda report: report['source']['sdk'].update(sha256='f' * 64))
        with self.assertRaisesRegex(ValueError, 'canonical qualified'):
            self.stage()

    def test_archive_evidence_does_not_admit_a_deferred_channel_or_unlisted_variant(self):
        item = self.items[0]
        item['package']['identity']['variant'] = 'ubuntu-22.04'
        with self.assertRaisesRegex(ValueError, 'Unsupported distro'):
            self.stage()

    def test_signature_verifier_receives_a_private_snapshot_of_parsed_report_bytes(self):
        original = self.items[0]['reportPath'].read_bytes()
        def authenticate(snapshot_report, snapshot_signature, *args):
            self.assertNotEqual(self.items[0]['reportPath'], snapshot_report)
            self.assertEqual(original, snapshot_report.read_bytes())
            self.items[0]['reportPath'].write_text('{"status":"tampered"}')
            return 'A' * 40
        with mock.patch.object(RELEASE, 'verify_report_signature', side_effect=authenticate):
            item = self.items[0]
            result = RELEASE.validate_record(item['package'], item['artifactPath'], item['reportPath'],
                                              item['signaturePath'], item['keyringPath'], self.policy,
                                              self.contract, self.catalog, item['commandsRoot'], self.inputs)
        self.assertEqual(hashlib.sha256(original).hexdigest(), result['report']['sha256'])

    def test_wrong_os_architecture_or_emulated_target_is_rejected(self):
        original = self.items[0]['reportPath'].read_bytes()
        for key, value in [('osId', 'ubuntu'), ('versionId', '12'), ('architecture', 'aarch64'), ('native', False)]:
            with self.subTest(key=key):
                self.items[0]['reportPath'].write_bytes(original)
                self.change_report(lambda report: report['target'].update({key: value}))
                with self.assertRaisesRegex(ValueError, 'wrong OS'):
                    self.stage()

    def test_unavailable_native_library_is_not_an_accepted_compatibility_result(self):
        self.change_report(lambda report: report['target']['dependencies'].pop('libssl3t64'))
        with self.assertRaisesRegex(ValueError, 'native libraries'):
            self.stage()

    def test_missing_or_failed_branding_alias_upgrade_or_removal_check_blocks_stage(self):
        original = self.items[0]['reportPath'].read_bytes()
        for name in ('command-aliases', 'cli-branding', 'version-stdout-compatible', 'upgrade', 'removal'):
            with self.subTest(name=name):
                self.items[0]['reportPath'].write_bytes(original)
                self.change_report(lambda report: report['checks'].update({name: 'failed'}))
                with self.assertRaisesRegex(ValueError, 'prepublication'):
                    self.stage()

    def test_post_publication_check_is_not_required_to_stage_before_publication(self):
        self.change_report(lambda report: report['checks'].update({'post-publication-digest': 'not-run'}))
        self.assertEqual('staged-unpublished', self.stage()['status'])

    def test_private_prefix_foundation_evidence_cannot_qualify_actual_package_installation(self):
        self.change_report(lambda report: report.update(scope='private-prefix'))
        with self.assertRaisesRegex(ValueError, 'real-channel'):
            self.stage()

    def test_substituted_workflow_artifact_or_source_identity_is_rejected(self):
        original = self.items[0]['reportPath'].read_bytes()
        for field in ('identity', 'artifact', 'producer', 'orchestration'):
            with self.subTest(field=field):
                self.items[0]['reportPath'].write_bytes(original)
                self.change_report(lambda report: report[field].update(unexpected='substitution'))
                with self.assertRaisesRegex(ValueError, 'does not bind'):
                    self.stage()

    def test_same_immutable_revision_with_new_artifact_refuses_replacement(self):
        self.stage()
        item = self.items[0]
        item['artifactPath'].write_bytes(b'new-package')
        item['package']['artifact'] = RELEASE.descriptor(item['artifactPath'])
        self.change_report(lambda report: report.update(artifact=item['package']['artifact']))
        with self.assertRaisesRegex(ValueError, 'Conflicting existing immutable'):
            self.stage()

    def test_live_catalog_producer_and_manifest_pin_are_rechecked_at_stage(self):
        self.catalog['builds'][0]['architectures']['x64']['runId'] = '999'
        with self.assertRaisesRegex(ValueError, 'producer'):
            self.stage()

    def test_unqualified_corrupt_or_partial_source_input_is_rejected(self):
        archive = self.inputs / 'cbodotnet-sdk-10.0.403-linux-x64.tar.gz'
        archive.write_bytes(b'invalid')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            RELEASE.local_intake(self.inputs, 'deb', 'debian-13', 'x64', contract=self.contract, catalog=self.catalog)

    def test_missing_real_publisher_cannot_be_reported_as_publication_success(self):
        staged = self.stage()
        self.policy['channels']['deb']['publisherConfigured'] = False
        with self.assertRaisesRegex(ValueError, 'not configured'):
            RELEASE.publish(staged, self.policy)
        self.assertTrue(all(not row['publications'] for row in RELEASE.load_status()['channels'].values()))


class ReportSignatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = [self.root / name for name in ('report.json', 'report.sig', 'keyring.gpg')]
        for path in self.paths:
            path.write_bytes(b'fixture')
        self.fingerprint = 'A' * 40
        self.workflow = '.github/workflows/downstream-verify.yml'
        self.policy = {'evidenceSigners': {self.fingerprint: dict(state='active', notBefore='2020-01-01T00:00:00Z',
                       notAfter='2100-01-01T00:00:00Z', workflow=self.workflow)}}
        self.output = '[GNUPG:] VALIDSIG ' + self.fingerprint + ' 2026-11-04 1793750400 0 4 0 22 8 00 ' + self.fingerprint + '\n'

    def verify(self, output=None, returncode=0):
        result = subprocess.CompletedProcess([], returncode, stdout=output if output is not None else self.output, stderr='')
        with mock.patch.object(RELEASE.subprocess, 'run', return_value=result):
            return RELEASE.verify_report_signature(*self.paths, self.policy, self.workflow)

    def test_verified_active_pinned_signer_is_accepted(self):
        self.assertEqual(self.fingerprint, self.verify())

    def test_missing_invalid_untrusted_revoked_or_expired_signer_is_rejected(self):
        for output, code in [('', 0), (self.output, 1), (self.output.replace('A' * 40, 'B' * 40), 0),
                             (self.output + '[GNUPG:] REVKEYSIG unknown\n', 0)]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.verify(output, code)
        signer = self.policy['evidenceSigners'][self.fingerprint]
        signer['notAfter'] = '2020-01-02T00:00:00Z'
        with self.assertRaises(ValueError):
            self.verify()
        signer['notAfter'] = '2100-01-01T00:00:00Z'
        signer['state'] = 'revoked'
        with self.assertRaises(ValueError):
            self.verify()

    def test_self_asserted_passed_report_without_configured_signer_is_rejected(self):
        self.policy['evidenceSigners'] = {}
        with self.assertRaisesRegex(ValueError, 'No trusted'):
            self.verify()

    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgv'), 'GnuPG tools are required')
    def test_real_detached_signature_verifies_and_tampered_report_fails(self):
        home = self.root / 'gnupg'
        home.mkdir(mode=0o700)
        def gpg(*args, **kwargs):
            return subprocess.check_output(['gpg', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback',
                                            '--passphrase', '', *args], stderr=subprocess.DEVNULL, **kwargs)
        gpg('--quick-generate-key', 'cbodotnet ephemeral test <test@example.invalid>', 'ed25519', 'sign', '0')
        fingerprint = next(line.split(':')[9] for line in gpg('--with-colons', '--list-keys').decode().splitlines()
                           if line.startswith('fpr:'))
        self.paths[0].write_text('{"status":"passed"}\n')
        self.paths[1].unlink()
        gpg('--output', str(self.paths[1]), '--detach-sign', str(self.paths[0]))
        self.paths[2].write_bytes(gpg('--export', fingerprint))
        self.policy['evidenceSigners'] = {fingerprint: self.policy['evidenceSigners'][self.fingerprint]}
        self.assertEqual(fingerprint, RELEASE.verify_report_signature(*self.paths, self.policy, self.workflow))
        self.paths[0].write_text('{"status":"tampered"}\n')
        with self.assertRaisesRegex(ValueError, 'independently verify'):
            RELEASE.verify_report_signature(*self.paths, self.policy, self.workflow)


if __name__ == '__main__':
    unittest.main()
