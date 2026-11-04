"""Exercise actual downstream publication protocol without remote side effects."""
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
import downstream_publish as PUBLISH
import downstream_release_test as RELEASE_TESTS

REAL_SIGNATURE_VERIFY = PUBLISH.verify_report_signature


class FakeGitHub:
    def __init__(self):
        self.release = None
        self.files = {}
        self.uploads = 0
        self.publications = 0
        self.public_downloads = 0
        self.corrupt_public = False

    def find(self, tag):
        return copy.deepcopy(self.release)

    def create(self, manifest):
        self.release = dict(id=123, tag_name=manifest['tag'], target_commitish=manifest['targetCommit'],
                            draft=True, prerelease=False, assets=[],
                            html_url=f'https://github.com/{PUBLISH.REPOSITORY}/releases/tag/{manifest["tag"]}')
        return copy.deepcopy(self.release)

    def get(self, release):
        return copy.deepcopy(self.release)

    def upload(self, release, path):
        name = path.name
        if name in self.files:
            raise AssertionError('Publisher attempted to upload an existing asset')
        data = path.read_bytes()
        self.files[name] = data
        self.uploads += 1
        self.release['assets'].append(dict(id=self.uploads, name=name, size=len(data), state='uploaded',
            digest='sha256:' + hashlib.sha256(data).hexdigest(),
            browser_download_url=f'https://github.com/{PUBLISH.REPOSITORY}/releases/download/{release["tag_name"]}/{name}'))

    def download(self, asset, destination, public=False):
        self.public_downloads += public
        data = self.files[asset['name']]
        Path(destination).write_bytes(data + b'changed' if public and self.corrupt_public else data)

    def publish(self, release):
        self.publications += 1
        self.release['draft'] = False
        return copy.deepcopy(self.release)


class DownstreamPublishTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RELEASE_TESTS.DownstreamReleaseTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.policy = copy.deepcopy(self.fixture.policy)
        self.policy['channels']['deb'].update(publisherConfigured=True, publisher={'type': 'github-release'})
        self.output = self.root / 'publication'
        self.keyring = self.fixture.items[0]['keyringPath']
        self.signer = 'A' * 40
        self.commit = self.fixture.orchestration['commit']
        patch = mock.patch.object(PUBLISH, 'verify_report_signature', return_value=self.signer)
        patch.start()
        self.addCleanup(patch.stop)
        for name, value in [('load_contract', self.fixture.contract), ('load_catalog', self.fixture.catalog)]:
            trust = mock.patch.object(PUBLISH, name, return_value=value)
            trust.start()
            self.addCleanup(trust.stop)
        self.crypto = mock.patch.object(PUBLISH.subprocess, 'run', side_effect=self.sign)
        self.crypto.start()
        self.addCleanup(self.crypto.stop)

    @staticmethod
    def sign(command, **kwargs):
        Path(command[command.index('--output') + 1]).write_bytes(b'fixture-manifest-signature')
        return subprocess.CompletedProcess(command, 0)

    def bundle(self, extras=()):
        return PUBLISH.create_bundle(self.fixture.items, self.output, self.commit, self.signer, self.keyring,
                                     extras, self.policy, self.fixture.contract, self.fixture.catalog)

    def publish(self, transport):
        return PUBLISH.publish_bundle(self.output, self.keyring, self.commit, self.policy, transport=transport)

    def test_signed_complete_matrix_bundle_binds_unique_artifacts_and_evidence(self):
        repo = self.root / 'cbodotnet-apt-10.0.403-r1.tar.gz'
        repo.write_bytes(b'signed-repository-bundle')
        manifest = self.bundle([repo])
        self.assertEqual('distribution-deb-sdk-10.0.403-r1', manifest['tag'])
        self.assertEqual(2, len(manifest['records']))
        self.assertIn(repo.name, {row['name'] for row in manifest['assets']})
        self.assertEqual(manifest, PUBLISH.validate_bundle(self.output, self.keyring, self.commit, self.policy))

    def test_missing_matrix_never_creates_a_publishable_bundle(self):
        self.fixture.items.pop()
        with self.assertRaisesRegex(ValueError, 'matrix'):
            self.bundle()
        self.assertFalse(self.output.exists())

    def test_changed_local_asset_or_manifest_binding_is_rejected_before_remote_calls(self):
        manifest = self.bundle()
        asset = self.output / manifest['assets'][0]['name']
        asset.write_bytes(b'tampered')
        transport = FakeGitHub()
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            self.publish(transport)
        self.assertIsNone(transport.release)

    def test_publish_rechecks_private_and_public_asset_bytes_and_emits_target_receipts(self):
        manifest = self.bundle()
        transport = FakeGitHub()
        receipt = self.publish(transport)
        self.assertEqual('published-postverified', receipt['status'])
        self.assertEqual(2, len(receipt['publications']))
        self.assertEqual(len(manifest['assets']) + 2, transport.public_downloads)
        self.assertEqual({'x64', 'aarch64'}, {row['architecture'] for row in receipt['publications']})
        self.assertTrue(all(row['manifestSha256'] == receipt['manifestSha256'] for row in receipt['publications']))

    def test_matching_retry_performs_no_upload_or_publication_mutation(self):
        self.bundle()
        transport = FakeGitHub()
        first = self.publish(transport)
        counts = transport.uploads, transport.publications
        self.assertEqual(first, self.publish(transport))
        self.assertEqual(counts, (transport.uploads, transport.publications))

    def test_conflicting_remote_digest_is_never_clobbered(self):
        self.bundle()
        transport = FakeGitHub()
        self.publish(transport)
        transport.release['assets'][0]['digest'] = 'sha256:' + 'f' * 64
        count = transport.uploads
        with self.assertRaisesRegex(ValueError, 'conflicting published digest'):
            self.publish(transport)
        self.assertEqual(count, transport.uploads)

    def test_existing_bytes_are_checked_even_when_api_digest_is_absent(self):
        self.bundle()
        transport = FakeGitHub()
        self.publish(transport)
        asset = transport.release['assets'][0]
        asset.pop('digest')
        original = transport.files[asset['name']]
        transport.files[asset['name']] = b'!' * len(original)
        with self.assertRaisesRegex(ValueError, 'changed existing release bytes'):
            self.publish(transport)

    def test_failed_public_retrieval_cannot_be_reported_as_verified_publication(self):
        self.bundle()
        transport = FakeGitHub()
        transport.corrupt_public = True
        with self.assertRaisesRegex(ValueError, 'remote artifact differs'):
            self.publish(transport)

    def test_incomplete_already_public_release_cannot_be_repaired_in_place(self):
        manifest = self.bundle()
        transport = FakeGitHub()
        transport.create(manifest)
        transport.release['draft'] = False
        with self.assertRaisesRegex(ValueError, 'incomplete public'):
            self.publish(transport)
        self.assertEqual(0, transport.uploads)

    def test_unrelated_commit_and_disabled_publisher_are_rejected(self):
        manifest = self.bundle()
        transport = FakeGitHub()
        transport.create(manifest)
        transport.release['target_commitish'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'unrelated downstream'):
            self.publish(transport)
        self.policy['channels']['deb']['publisherConfigured'] = False
        with self.assertRaisesRegex(ValueError, 'not configured'):
            self.publish(FakeGitHub())

    def test_frozen_bundle_cannot_publish_after_source_pin_or_producer_revocation(self):
        manifest = self.bundle()
        self.fixture.contract['releases']['10.0.403']['manifestSha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'no longer admitted'):
            self.publish(FakeGitHub())
        self.fixture.contract['releases']['10.0.403']['manifestSha256'] = manifest['identity']['sourceManifestSha256']
        self.fixture.catalog['builds'][0]['architectures']['x64']['runId'] = '99999'
        with self.assertRaisesRegex(ValueError, 'producer is no longer admitted'):
            self.publish(FakeGitHub())

    def test_rpm_backend_uses_the_same_signed_immutable_publication_protocol(self):
        # The backend is channel-independent. This synthetic admission exercises
        # RPM publication without claiming a real RPM distribution qualification.
        self.fixture.contract['releases'] = {'10.0.403': self.fixture.contract['releases']['10.0.403']}
        self.fixture.contract['channels']['rpm'] = {'status': 'preparation-only', 'variants': ['debian-13']}
        self.policy['channels']['rpm'] = copy.deepcopy(self.policy['channels']['deb'])
        for item in self.fixture.items:
            item['package']['identity']['channel'] = 'rpm'
            report = json.loads(item['reportPath'].read_bytes())
            report['identity']['channel'] = 'rpm'
            item['reportPath'].write_text(json.dumps(report))
        self.bundle()
        receipt = self.publish(FakeGitHub())
        self.assertEqual('distribution-rpm-sdk-10.0.403-r1', receipt['tag'])
        self.assertEqual('rpm', receipt['identity']['channel'])

    def test_pending_draft_urls_are_verified_by_asset_id_until_publication(self):
        self.bundle()
        class PendingDraft(FakeGitHub):
            def create(inner, manifest):
                result = super().create(manifest)
                inner.release['html_url'] = f'https://github.com/{PUBLISH.REPOSITORY}/releases/tag/untagged-abcd'
                return inner.get(result)

            def upload(inner, release, path):
                super().upload(release, path)
                inner.release['assets'][-1]['browser_download_url'] = f'https://github.com/{PUBLISH.REPOSITORY}/releases/download/untagged-abcd/{path.name}'

            def publish(inner, release):
                super().publish(release)
                inner.release['html_url'] = f'https://github.com/{PUBLISH.REPOSITORY}/releases/tag/{release["tag_name"]}'
                for asset in inner.release['assets']:
                    asset['browser_download_url'] = f'https://github.com/{PUBLISH.REPOSITORY}/releases/download/{release["tag_name"]}/{asset["name"]}'
                return inner.get(release)
        self.assertEqual('published-postverified', self.publish(PendingDraft())['status'])

    def test_pending_draft_missing_from_rest_listing_is_found_by_graphql_database_id(self):
        transport = PUBLISH.GitHubReleases()
        listing = subprocess.CompletedProcess([], 0, stdout='[[]]', stderr='')
        api_responses = [dict(data=dict(repository=dict(release=dict(databaseId=321)))),
                         dict(id=321, tag_name='distribution-deb-sdk-10.0.403-r1', draft=True)]
        with mock.patch.object(PUBLISH.subprocess, 'run', return_value=listing), \
             mock.patch.object(transport, 'api', side_effect=api_responses) as api:
            result = transport.find('distribution-deb-sdk-10.0.403-r1')
        self.assertEqual(321, result['id'])
        self.assertEqual('graphql', api.call_args_list[0].args[0])

    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgv'), 'GnuPG is required')
    def test_actual_detached_manifest_signature_authenticates_and_rejects_tampering(self):
        self.crypto.stop()
        # Report cryptography is exercised by the existing real GPG evidence
        # test. Here the already-validated stage is signed and verified for real.
        home = self.root / 'manifest-gnupg'
        home.mkdir(mode=0o700)
        def gpg(*args):
            return subprocess.check_output(['gpg', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback',
                '--passphrase', '', *args], stderr=subprocess.DEVNULL)
        gpg('--quick-generate-key', 'cbodotnet manifest test <manifest@example.invalid>', 'ed25519', 'sign', '0')
        fingerprint = next(line.split(':')[9] for line in gpg('--with-colons', '--list-keys').decode().splitlines()
                           if line.startswith('fpr:'))
        keyring = self.root / 'manifest-keyring.gpg'
        keyring.write_bytes(gpg('--export', fingerprint))
        self.policy['evidenceSigners'] = {fingerprint: dict(state='active', notBefore='2020-01-01T00:00:00Z',
            notAfter='2100-01-01T00:00:00Z', workflow=self.fixture.orchestration['workflow'])}
        staged = self.fixture.stage()
        with mock.patch.object(PUBLISH, 'stage_records', return_value=staged), \
             mock.patch.object(PUBLISH, 'verify_report_signature', side_effect=REAL_SIGNATURE_VERIFY):
            PUBLISH.create_bundle(self.fixture.items, self.output, self.commit, fingerprint, keyring,
                                  policy=self.policy, gnupg_home=home)
            PUBLISH.validate_bundle(self.output, keyring, self.commit, self.policy)
            path = self.output / PUBLISH.MANIFEST
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'independently verify'):
                PUBLISH.validate_bundle(self.output, keyring, self.commit, self.policy)


if __name__ == '__main__':
    unittest.main()
