"""Retain a signed shared RPM only when its exact prior unsigned bytes match."""
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
import distribution_site as SITE
import rpm_publish as PUBLISH


class SharedRpmReuseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.signer = 'A' * 40
        self.signed = b'published-signed-rpm'
        self.unsigned = b'original-unsigned-rpm'
        self.row = dict(kind='host', path='cbodotnet-host-1.0.0-1.cbot.fedora45.noarch.rpm',
                        size=len(self.unsigned), sha256=hashlib.sha256(self.unsigned).hexdigest())
        self.plan = dict(variant='fedora-45', sdkVersion='9.0.123', architecture=dict(public='x64'))
        self.name = 'rpm-fedora-45--' + self.row['path']
        tag = 'distribution-rpm-sdk-10.0.403-r1'
        self.base = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/' + tag + '/'
        self.asset = dict(name=self.name, size=len(self.signed), sha256=hashlib.sha256(self.signed).hexdigest(),
                          url=self.base + self.name)
        self.identity = dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='c' * 64)
        self.document = dict(repository='dotnetdev-kr/cbodotnet', tag=tag, identity=self.identity,
            status='validated-complete-matrix', signingFingerprint=self.signer,
            assets=[{key: self.asset[key] for key in ('name', 'size', 'sha256')}])
        self.receipt = dict(repository='dotnetdev-kr/cbodotnet', tag=tag, identity=self.identity,
            status='published-postverified', signingFingerprint=self.signer,
            manifestUrl=self.base + 'distribution-manifest.json', signatureUrl=self.base + 'distribution-manifest.json.asc',
            manifestSha256='', assets=[self.asset])
        self.policy = dict(channels=dict(rpm=dict(receipts=[self.receipt])))
        self.pin_document()
        self.downloads = []

    def pin_document(self):
        self.document_bytes = json.dumps(self.document, sort_keys=True).encode()
        self.receipt['manifestSha256'] = hashlib.sha256(self.document_bytes).hexdigest()

    def download(self, url, path, maximum, expected=None):
        self.downloads.append(url)
        if url == self.receipt['manifestUrl']:
            value = self.document_bytes
        elif url == self.receipt['signatureUrl']:
            value = b'detached-manifest-signature'
        elif url == self.asset['url']:
            value = self.signed
        else:
            raise AssertionError('Unexpected download: ' + url)
        Path(path).write_bytes(value)
        if expected is not None:
            if len(value) != expected['size'] or hashlib.sha256(value).hexdigest() != expected['sha256']:
                raise ValueError('download differs from pinned asset')
        return hashlib.sha256(value).hexdigest()

    def execute(self, command, **kwargs):
        self.assertEqual(['rpmsign', '--delsign'], command[:2])
        Path(command[-1]).write_bytes(self.unsigned)
        return ''

    def reuse(self, *, signature=None):
        with mock.patch.object(SITE, 'download', side_effect=self.download):
            with mock.patch.object(PUBLISH, 'verify_report_signature', side_effect=signature, return_value=self.signer):
                with mock.patch.object(PUBLISH, 'verify_rpm_signature', return_value={'status': 'passed'}) as rpm_signature:
                    with mock.patch.object(PUBLISH.CORE, 'run', side_effect=self.execute):
                        result = PUBLISH.retained_shared_rpm(self.row, self.plan, self.policy, self.root / 'trusted.gpg', self.signer, self.root)
        return result, rpm_signature

    def test_existing_nevra_reuses_exact_published_signed_bytes_after_unsigned_comparison(self):
        path, signature = self.reuse()
        self.assertEqual(self.root / self.name, path)
        self.assertEqual(self.signed, path.read_bytes())
        self.assertEqual(3, len(self.downloads))
        self.assertEqual(path, signature.call_args.args[0])

    def test_new_nevra_has_no_network_or_signer_side_effect(self):
        self.row['path'] = self.row['path'].replace('1.cbot.', '2.cbot.')
        path, signature = self.reuse()
        self.assertIsNone(path)
        self.assertEqual([], self.downloads)
        signature.assert_not_called()

    def test_changed_unsigned_contents_cannot_reuse_an_existing_nevra(self):
        self.row['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'contents changed under an existing NEVRA'):
            self.reuse()

    def test_conflicting_prior_shared_nevra_hashes_fail_before_download(self):
        other = copy.deepcopy(self.receipt)
        other['assets'][0]['sha256'] = 'f' * 64
        self.policy['channels']['rpm']['receipts'].append(other)
        with self.assertRaisesRegex(ValueError, 'conflicting bytes'):
            self.reuse()
        self.assertEqual([], self.downloads)

    def test_manifest_pin_and_detached_signature_fail_before_rpm_download(self):
        self.receipt['manifestSha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'manifest changed'):
            self.reuse()
        self.assertEqual([self.receipt['manifestUrl']], self.downloads)
        self.pin_document()
        self.downloads.clear()
        with self.assertRaisesRegex(ValueError, 'invalid detached signature'):
            self.reuse(signature=ValueError('invalid detached signature'))
        self.assertNotIn(self.asset['url'], self.downloads)

    def test_signed_asset_binding_and_signer_identity_are_not_replaceable(self):
        original = copy.deepcopy(self.document)
        for change in (dict(signingFingerprint='B' * 40), dict(identity=dict(self.identity, sdkVersion='8.0.133')),
                       dict(assets=[]), dict(status='unqualified')):
            self.document = dict(original, **change)
            self.pin_document()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.reuse()
            self.assertNotIn(self.asset['url'], self.downloads)
            self.downloads.clear()

    def test_foreign_project_tags_or_manifest_locations_are_not_reused(self):
        original = copy.deepcopy(self.document)
        for change in (dict(repository='another/project'), dict(tag='distribution-rpm-sdk-9.0.123-r1')):
            self.document = dict(original, **change)
            self.pin_document()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.reuse()
            self.assertNotIn(self.asset['url'], self.downloads)
            self.downloads.clear()
        self.document = original
        self.pin_document()
        self.receipt['manifestUrl'] = 'https://example.org/manifest.json'
        with self.assertRaises(ValueError):
            self.reuse()


if __name__ == '__main__':
    unittest.main()
