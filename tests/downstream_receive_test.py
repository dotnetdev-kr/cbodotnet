"""Receive published release bytes without exposing corrupt or conflicting SDKs."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_contract as CONTRACT
import downstream_release as RELEASE
from release_catalog_test import fixture


class ChunkedResponse(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.read_count = 0

    def read(self, size=-1):
        self.read_count += 1
        return super().read(min(size, 2) if size >= 0 else 2)


class ReceiveReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'received'
        self.release, self.manifest, self.manifest_bytes, self.checksums = fixture()
        self.contract = copy.deepcopy(CONTRACT.load_contract())
        self.contract['releases']['10.0.403']['manifestSha256'] = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.catalog = {'schemaVersion': 1, 'repository': RELEASE.REPOSITORY, 'builds': [
            {'target': 'net10', 'sdkVersion': '10.0.403', 'architectures': {
                arch: {key: row['provenance'][key] for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')}
                for arch, row in self.manifest['architectures'].items()}}]}
        (self.root / 'releases').mkdir()
        (self.root / 'releases/qualified-builds.json').write_text(json.dumps(self.catalog))
        self.sdk_name = self.manifest['architectures']['x64']['sdk']['name']
        self.sdk_bytes = b'sdkx64'
        self.response_bytes = self.sdk_bytes
        self.base = 'https://github.com/' + RELEASE.REPOSITORY + '/releases/download/sdk-10.0.403/'
        self.streams = []
        for patcher in (
                mock.patch.object(RELEASE, 'load_contract', return_value=self.contract),
                mock.patch.object(CONTRACT, 'load_contract', return_value=self.contract),
                mock.patch.object(CONTRACT, 'ROOT', self.root),
                mock.patch.object(RELEASE, 'ROOT', self.root)):
            patcher.start()
            self.addCleanup(patcher.stop)
        metadata = mock.patch.object(RELEASE, 'get_bytes', side_effect=self.metadata)
        self.metadata_fetch = metadata.start()
        self.addCleanup(metadata.stop)
        download = mock.patch.object(RELEASE.urllib.request, 'urlopen', side_effect=self.sdk_response)
        self.sdk_fetch = download.start()
        self.addCleanup(download.stop)

    def metadata(self, url, maximum, token=None, api=False):
        if url == 'https://api.github.com/repos/' + RELEASE.REPOSITORY + '/releases/tags/sdk-10.0.403':
            self.assertTrue(api)
            return json.dumps(self.release).encode()
        self.assertFalse(api)
        if url == self.base + 'release-manifest.json':
            return self.manifest_bytes
        if url == self.base + 'SHA256SUMS':
            return self.checksums
        self.fail('Unexpected metadata request: ' + url)

    def sdk_response(self, url, timeout):
        self.assertEqual(self.base + self.sdk_name, url)
        self.assertEqual(60, timeout)
        response = ChunkedResponse(self.response_bytes)
        self.streams.append(response)
        return response

    def receive(self, directory=None, tag='sdk-10.0.403'):
        return RELEASE.receive_release(tag, directory or self.directory, 'deb', 'debian-13', 'x64')

    def refresh_manifest_pin_and_api(self):
        self.manifest_bytes = json.dumps(self.manifest).encode()
        digest = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.contract['releases']['10.0.403']['manifestSha256'] = digest
        asset = next(row for row in self.release['assets'] if row['name'] == 'release-manifest.json')
        asset.update(size=len(self.manifest_bytes), digest='sha256:' + digest)

    def test_streamed_success_exposes_only_verified_complete_sdk_and_real_plan(self):
        result = self.receive()
        self.assertEqual('prepared-unqualified', result['status'])
        self.assertEqual('10.0.403', result['sdkVersion'])
        self.assertEqual(self.sdk_bytes, (self.directory / self.sdk_name).read_bytes())
        self.assertFalse((self.directory / (self.sdk_name + '.partial')).exists())
        self.assertEqual(self.manifest_bytes, (self.directory / 'release-manifest.json').read_bytes())
        self.assertEqual(self.checksums, (self.directory / 'SHA256SUMS').read_bytes())
        self.assertEqual(3, self.metadata_fetch.call_count)
        self.assertGreater(self.streams[0].read_count, 2)
        self.sdk_fetch.assert_called_once()

    def test_matching_retry_reuses_sdk_while_rechecking_live_release_metadata(self):
        original = self.receive()
        snapshot = (self.directory / 'release.json').read_bytes()
        self.release['assets'][0]['download_count'] = 999
        self.assertEqual(original, self.receive())
        self.assertEqual(snapshot, (self.directory / 'release.json').read_bytes())
        self.assertEqual(6, self.metadata_fetch.call_count)
        self.sdk_fetch.assert_called_once()

    def test_conflicting_existing_sdk_is_never_replaced_or_downloaded_again(self):
        self.directory.mkdir()
        conflict = self.directory / self.sdk_name
        conflict.write_bytes(b'retained conflicting SDK')
        with self.assertRaisesRegex(ValueError, 'Conflicting existing SDK'):
            self.receive()
        self.assertEqual(b'retained conflicting SDK', conflict.read_bytes())
        self.sdk_fetch.assert_not_called()

    def test_conflicting_existing_manifest_or_checksums_are_never_overwritten(self):
        for name in ('release-manifest.json', 'SHA256SUMS'):
            directory = self.root / ('conflict-' + name)
            directory.mkdir()
            (directory / self.sdk_name).write_bytes(self.sdk_bytes)
            (directory / name).write_bytes(b'retained conflicting metadata')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Conflicting existing release metadata'):
                self.receive(directory)
            self.assertEqual(b'retained conflicting metadata', (directory / name).read_bytes())
        self.sdk_fetch.assert_not_called()

    def test_existing_partial_requires_inspection_and_is_not_replaced(self):
        self.directory.mkdir()
        partial = self.directory / (self.sdk_name + '.partial')
        partial.write_bytes(b'retained interrupted download')
        with self.assertRaisesRegex(ValueError, 'incomplete download'):
            self.receive()
        self.assertEqual(b'retained interrupted download', partial.read_bytes())
        self.assertFalse((self.directory / self.sdk_name).exists())
        self.sdk_fetch.assert_not_called()

    def test_truncated_oversized_and_same_size_corrupt_downloads_never_become_final_sdk(self):
        for label, content in [('truncated', self.sdk_bytes[:-1]), ('oversized', self.sdk_bytes + b'!'),
                               ('same-size-corrupt', b'!' * len(self.sdk_bytes))]:
            self.response_bytes = content
            directory = self.root / label
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.receive(directory)
            self.assertFalse((directory / self.sdk_name).exists())
            self.assertTrue((directory / (self.sdk_name + '.partial')).is_file())

    def test_draft_release_is_rejected_before_any_sdk_request(self):
        self.release['draft'] = True
        with self.assertRaisesRegex(ValueError, 'public and stable'):
            self.receive()
        self.sdk_fetch.assert_not_called()

    def test_partial_architecture_manifest_is_rejected_even_with_matching_reviewed_pin(self):
        self.manifest['architectures'].pop('aarch64')
        self.refresh_manifest_pin_and_api()
        with self.assertRaisesRegex(ValueError, 'both aarch64 and x64'):
            self.receive()
        self.sdk_fetch.assert_not_called()

    def test_unadmitted_version_or_unqualified_manifest_pin_cannot_fetch_sdk(self):
        with self.assertRaisesRegex(ValueError, 'not admitted'):
            self.receive(tag='sdk-10.0.404')
        self.metadata_fetch.assert_not_called()
        self.contract['releases']['10.0.403']['manifestSha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'manifest digest mismatch'):
            self.receive()
        self.sdk_fetch.assert_not_called()

    def test_unqualified_catalog_identity_cannot_trigger_sdk_download(self):
        original = copy.deepcopy(self.catalog)
        changes = [lambda value: value.update(schemaVersion=2),
                   lambda value: value.update(repository='untrusted/repository'),
                   lambda value: value.update(builds=[]),
                   lambda value: value['builds'].append(copy.deepcopy(value['builds'][0])),
                   lambda value: value['builds'][0].update(target='net9'),
                   lambda value: value['builds'][0]['architectures'].pop('aarch64'),
                   lambda value: value['builds'][0]['architectures']['x64'].update(projectCommit='b' * 40),
                   lambda value: value['builds'][0]['architectures']['aarch64'].update(runId='999')]
        for change in changes:
            candidate = copy.deepcopy(original)
            change(candidate)
            (self.root / 'releases/qualified-builds.json').write_text(json.dumps(candidate))
            with self.subTest(catalog=candidate), self.assertRaises(ValueError):
                self.receive()
            self.assertFalse((self.directory / self.sdk_name).exists())
        self.sdk_fetch.assert_not_called()

    def test_concurrent_conflicting_destination_is_never_silently_replaced(self):
        def competing_link(source, destination):
            Path(destination).write_bytes(b'concurrent owner bytes')
            raise FileExistsError('simulated competing receiver')
        with mock.patch.object(RELEASE.os, 'link', side_effect=competing_link):
            with self.assertRaisesRegex(ValueError, 'Conflicting concurrently received'):
                self.receive()
        self.assertEqual(b'concurrent owner bytes', (self.directory / self.sdk_name).read_bytes())
        self.assertTrue((self.directory / (self.sdk_name + '.partial')).is_file())


if __name__ == '__main__':
    unittest.main()
