"""Exercise actual downstream publication protocol without remote side effects."""
import copy
import hashlib
import io
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


class PublicDownloadTests(unittest.TestCase):
    def test_small_public_download_uses_the_shared_anonymous_size_bound_without_mutating_the_asset(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-9.0.123-r2/distribution-manifest.json'
        payload = b'public-metadata'
        for size in (len(payload), 16 * 1024**2):
            asset = dict(id=123, name='distribution-manifest.json', size=size, browser_download_url=url)
            before = copy.deepcopy(asset)
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(PUBLISH, 'get_bytes', return_value=payload) as fetch, \
                    mock.patch.object(PUBLISH.urllib.request, 'urlopen') as opener:
                destination = Path(temporary)/asset['name']
                PUBLISH.GitHubReleases().download(asset, destination, public=True)
                self.assertEqual(payload, destination.read_bytes())
                self.assertEqual(before, asset)
                fetch.assert_called_once_with(url, size)
                opener.assert_not_called()

    def test_small_public_download_never_replaces_an_existing_destination(self):
        asset = dict(size=14, browser_download_url='https://github.com/example/repo/releases/download/tag/manifest.json')
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(PUBLISH, 'get_bytes', return_value=b'new metadata'):
            destination = Path(temporary)/'manifest.json'
            destination.write_bytes(b'existing bytes')
            with self.assertRaises(FileExistsError):
                PUBLISH.GitHubReleases().download(asset, destination, public=True)
            self.assertEqual(b'existing bytes', destination.read_bytes())

    def test_failed_small_public_fetch_does_not_create_a_destination(self):
        asset = dict(size=14, browser_download_url='https://github.com/example/repo/releases/download/tag/manifest.json')
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(PUBLISH, 'get_bytes', side_effect=ValueError('oversized metadata')):
            destination = Path(temporary)/'manifest.json'
            with self.assertRaisesRegex(ValueError, 'oversized'):
                PUBLISH.GitHubReleases().download(asset, destination, public=True)
            self.assertFalse(destination.exists())

    def test_outer_public_verifier_still_rejects_wrong_small_asset_bytes(self):
        payload = b'exact-metadata'
        name = 'distribution-manifest.json'
        tag = 'distribution-archive-sdk-9.0.123-r2'
        wanted = dict(name=name, size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        asset = dict(id=123, name=name, size=len(payload), state='uploaded', digest='sha256:'+wanted['sha256'],
                     browser_download_url=f'https://github.com/{PUBLISH.REPOSITORY}/releases/download/{tag}/{name}')
        release = dict(tag_name=tag, assets=[asset])
        with mock.patch.object(PUBLISH, 'get_bytes', return_value=b'wrong-metadata') as fetch:
            with self.assertRaisesRegex(ValueError, 'differs from verified publication bytes'):
                PUBLISH.verify_remote_assets(release, {name: wanted}, PUBLISH.GitHubReleases(), public=True)
        fetch.assert_called_once_with(asset['browser_download_url'], asset['size'])

    def test_private_small_asset_download_keeps_the_authenticated_asset_id_transport(self):
        asset = dict(id=123, size=14, browser_download_url='https://github.com/example/repo/releases/download/tag/manifest.json')
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(PUBLISH, 'get_bytes') as fetch, \
                mock.patch.object(PUBLISH.subprocess, 'run') as run:
            PUBLISH.GitHubReleases().download(asset, Path(temporary)/'manifest.json', public=False)
            fetch.assert_not_called()
            self.assertEqual(['gh', 'api', f'repos/{PUBLISH.REPOSITORY}/releases/assets/123', '-H', 'Accept: application/octet-stream'],
                             run.call_args.args[0])

    def test_large_public_retries_obtain_fresh_anonymous_redirects_without_mutating_asset_descriptors(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-9.0.123-r2/cbodotnet-sdk-9.0.123-linux-x64-r2.tar.gz'
        payload = b'exact-public-asset'
        # Only exercise transport streaming here; the outer verifier checks actual size and SHA.
        asset = dict(id=123, name='cbodotnet-sdk-9.0.123-linux-x64-r2.tar.gz', size=25 * 1024**2, digest='sha256:'+hashlib.sha256(payload).hexdigest(),
                     browser_download_url=url)
        before = copy.deepcopy(asset)
        for status in (404, 500, 502, 503, 504):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(PUBLISH.urllib.request, 'urlopen') as opener, \
                    mock.patch.object(PUBLISH.time, 'sleep') as sleep, mock.patch.object(PUBLISH, 'get_bytes') as fetch:
                opener.side_effect = [PUBLISH.urllib.error.HTTPError(url, status, 'transient', {}, None) for _ in range(3)] + [io.BytesIO(payload)]
                destination = Path(temporary)/'asset.json'
                PUBLISH.GitHubReleases().download(asset, destination, public=True)
                self.assertEqual(payload, destination.read_bytes())
                self.assertEqual(before, asset)
                self.assertEqual([mock.call(1), mock.call(2), mock.call(4)], sleep.call_args_list)
                self.assertEqual(4, opener.call_count)
                fetch.assert_not_called()
                for attempt, call in enumerate(opener.call_args_list):
                    request = call.args[0]
                    parsed = PUBLISH.urllib.parse.urlsplit(request.full_url)
                    original = PUBLISH.urllib.parse.urlsplit(url)
                    self.assertEqual((original.scheme, original.netloc, original.path), (parsed.scheme, parsed.netloc, parsed.path))
                    self.assertNotIn('Authorization', dict(request.header_items()))
                    self.assertEqual({'timeout': 60}, call.kwargs)
                    if attempt:
                        self.assertRegex(parsed.query, '^cbodotnet_retry='+str(attempt)+r'-[0-9]+$')
                        self.assertEqual('no-cache', request.get_header('Cache-control'))
                        self.assertEqual('no-cache', request.get_header('Pragma'))
                    else:
                        self.assertEqual(url, request.full_url)
                        self.assertIsNone(request.get_header('Cache-control'))

    def test_public_retry_exhaustion_has_four_attempts_and_does_not_create_a_destination(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/tag/asset.json'
        error = PUBLISH.urllib.error.HTTPError(url, 504, 'transient', {}, None)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(PUBLISH.urllib.request, 'urlopen', side_effect=error) as opener, \
                mock.patch.object(PUBLISH.time, 'sleep') as sleep:
            destination = Path(temporary)/'asset.json'
            with self.assertRaises(PUBLISH.urllib.error.HTTPError) as raised:
                PUBLISH.GitHubReleases().download(dict(size=25 * 1024**2, browser_download_url=url), destination, public=True)
            self.assertIs(error, raised.exception)
            self.assertEqual(4, opener.call_count)
            self.assertEqual([mock.call(1), mock.call(2), mock.call(4)], sleep.call_args_list)
            self.assertFalse(destination.exists())

    def test_public_authentication_errors_are_not_retried(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/tag/asset.json'
        for status in (401, 403):
            error = PUBLISH.urllib.error.HTTPError(url, status, 'permanent', {}, None)
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(PUBLISH.urllib.request, 'urlopen', side_effect=error) as opener, \
                    mock.patch.object(PUBLISH.time, 'sleep') as sleep:
                destination = Path(temporary)/'asset.json'
                with self.assertRaises(PUBLISH.urllib.error.HTTPError):
                    PUBLISH.GitHubReleases().download(dict(size=25 * 1024**2, browser_download_url=url), destination, public=True)
                opener.assert_called_once()
                sleep.assert_not_called()
                self.assertFalse(destination.exists())


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

    def test_transport_error_identifies_method_endpoint_without_request_body_or_query(self):
        result = subprocess.CompletedProcess([], 1, stdout='', stderr='gh: Resource not accessible by integration (HTTP 403)')
        with mock.patch.object(PUBLISH.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                PUBLISH.GitHubReleases().api('repos/example/repository/releases?private-query-value=hidden', 'POST',
                    {'body': 'private-request-body', 'headers': {'Authorization': 'private-token'}})
        message = str(raised.exception)
        self.assertIn('POST repos/example/repository/releases', message)
        self.assertIn('HTTP 403', message)
        self.assertNotIn('private-request-body', message)
        self.assertNotIn('private-token', message)
        self.assertNotIn('hidden', message)

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
