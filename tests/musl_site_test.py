"""A hidden candidate section and independently bound public musl downloads."""
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
import musl_archive
import musl_contract
import musl_site as SITE
from musl_contract_test import fixture as source_fixture

SIGNER = 'D7D154B4B33C19A82B95B13688135410ACD9C0EA'


def fixture(channel='archive'):
    _, source, source_raw, _, catalog, _ = source_fixture()
    version, revision = '10.0.403', 1
    tag = musl_contract.distribution_tag(channel, version, revision)
    verification_tag = 'verification-musl-sdk-10.0.403-r1'
    identity = dict(sdkVersion=version, producerRevision=1, packageRevision=revision, libc='musl', channel=channel,
        sourceReleaseTag=source['tag'], sourceManifestSha256=hashlib.sha256(source_raw).hexdigest())
    manifest = dict(schemaVersion=1, kind='musl-distribution-publication', repository=SITE.REPOSITORY,
        signingFingerprint=SIGNER, tag=tag, identity=identity, records=[], assets=[])
    objects, public = {}, []

    def asset(name, data, release_tag=tag):
        url = SITE.asset_url(release_tag, name)
        objects[url] = data
        return dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(), url=url)

    for arch, target in musl_contract.ARCHITECTURES.items():
        artifact = asset(musl_contract.archive_name(version, arch), b'large-qualified-payload-' + arch.encode())
        qualification = asset('qualification-' + arch + '.json', b'{"status":"passed"}')
        manifest['assets'].extend({key: item[key] for key in ('name', 'size', 'sha256')}
                                   for item in (artifact, qualification))
        record = dict(architecture=arch, targetRid=target['rid'], artifactAsset=artifact['name'],
            qualificationReportAsset=qualification['name'], build=dict(plan=dict(identity,
                targetRid=target['rid'], producer=source['architectures'][arch]['provenance'])))
        if channel == 'apk':
            record['repository'] = dict(url=f'https://github.com/{SITE.REPOSITORY}/releases/download/musl-apk-repo-{version}-alpine324-{arch}-r1/')
        manifest['records'].append(record)
        report_identity = {key: value for key, value in identity.items() if key != 'channel'}
        report = dict(schemaVersion=1, status='passed', native=True, architecture=arch, targetRid=target['rid'], libc='musl',
            networkForBuild='none', identity=dict(report_identity, targetRid=target['rid']),
            functionalChecks=dict.fromkeys(musl_archive.FUNCTIONAL_CHECKS, 'passed'),
            checks=dict.fromkeys(musl_archive.REPORT_CHECKS, 'passed'),
            userSpaces=[dict(variant='alpine-3.24', alpineVersion='3.24.4', status='passed',
                uid=1654 if channel == 'oci' else 10001, gid=1654 if channel == 'oci' else 10001,
                elfAudit=dict(status='passed', native=True, libc='musl', architecture=arch, targetRid=target['rid'],
                    hostElfCount=10, stockLibraries=[dict(name='libc.musl.so.1', sha256='b'*64)]),
                systemTrustHttps=dict(status='passed'))],
            publicVerification=dict(anonymous=True, status='passed', artifactSha256=artifact['sha256']))
        raw = json.dumps(report).encode()
        item = asset('public-' + channel + '-' + arch + '.json', raw, verification_tag)
        public.append(dict(architecture=arch, report=item, rawJsonSize=item['size'], rawJsonSha256=item['sha256']))
    if channel == 'oci':
        manifest['ociIndex'] = dict(repository='ghcr.io/' + SITE.REPOSITORY + '-sdk', digest='sha256:' + 'a'*64,
                                   tag='10.0.403-alpine324-musl-r1', platforms=[])
    raw = json.dumps(manifest).encode()
    manifest_asset = asset('distribution-manifest.json', raw)
    asset('distribution-manifest.json.asc', b'fixture-signature')
    receipt = dict(schemaVersion=1, kind='musl-distribution-publication-receipt', status='published-postverified',
        identity=copy.deepcopy(identity), tag=tag, releaseUrl=f'https://github.com/{SITE.REPOSITORY}/releases/tag/{tag}',
        manifestUrl=manifest_asset['url'], signatureUrl=SITE.asset_url(tag, 'distribution-manifest.json.asc'),
        manifestSha256=manifest_asset['sha256'], signingFingerprint=SIGNER,
        assets=[dict(item, url=SITE.asset_url(tag, item['name'])) for item in manifest['assets']],
        postVerification=dict(reports=public))
    verification = dict(schemaVersion=1, kind='musl-public-verification', repository=SITE.REPOSITORY,
                        entries=[copy.deepcopy(receipt)])
    verification_asset = asset('verification-manifest.json', json.dumps(verification).encode(), verification_tag)
    asset('verification-manifest.json.asc', b'fixture-verification-signature', verification_tag)
    receipt['verification'] = dict(manifestUrl=verification_asset['url'],
        signatureUrl=SITE.asset_url(verification_tag, 'verification-manifest.json.asc'),
        manifestSha256=verification_asset['sha256'], signingFingerprint=SIGNER)
    status = dict(schemaVersion=1, kind='musl-distribution-availability', repository=SITE.REPOSITORY,
        libc='musl', status='published-postverified', publications=[receipt], installerAdmission='separate-issue-30')
    return manifest, receipt, status, objects, catalog


class MuslSiteTests(unittest.TestCase):
    def authenticate(self, receipt, objects, catalog, requested=None):
        def fetch(url, maximum):
            if requested is not None:
                requested.append(url)
            raw = objects[url]
            self.assertGreater(maximum, 0)
            return raw
        with mock.patch('musl_release.verify_publication_signature', return_value=SIGNER), \
             mock.patch('musl_release.load_qualification_catalog', return_value=catalog):
            return SITE.authenticate_receipt(receipt, fetch=fetch, keyring=Path('/fixture/trusted.gpg'))

    def test_unpublished_candidate_is_hidden_without_fetching_or_changing_old_feeds(self):
        status = dict(schemaVersion=1, kind='musl-distribution-availability', repository=SITE.REPOSITORY,
            libc='musl', status='not-published', publications=[], installerAdmission='separate-issue-30')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = root / 'archive-status.json'
            old.write_bytes(b'unchanged glibc feed')
            markup, feed = SITE.prepare(root, status=status, fetch=lambda *args: self.fail('No candidate metadata fetch'))
            self.assertEqual('', markup)
            self.assertEqual([], feed['publications'])
            self.assertEqual('not-published', feed['status'])
            self.assertEqual(b'unchanged glibc feed', old.read_bytes())
            self.assertEqual('musl-download-catalog', json.loads((root / 'musl-status.json').read_bytes())['kind'])

    def test_complete_signed_source_and_final_receipt_bind_both_public_native_reports(self):
        manifest, receipt, status, objects, catalog = fixture()
        requested = []
        observed = self.authenticate(receipt, objects, catalog, requested)
        self.assertEqual(manifest, observed)
        self.assertTrue(any('verification-manifest.json.asc' in url for url in requested))
        self.assertEqual(2, len([url for url in requested if '/public-archive-' in url]))
        self.assertEqual(2, len([url for url in requested if '/qualification-' in url]))
        self.assertFalse(any(url.endswith('.tar.gz') for url in requested))
        rows = SITE.public_rows(status, authenticator=lambda value: observed)
        markup = SITE.render(rows)
        self.assertIn('Alpine Linux', markup)
        self.assertIn('Alpine AArch64', markup)
        self.assertIn('Public verification', markup)
        self.assertNotIn('unbranded', markup.lower())

    def test_final_verification_signature_and_exact_receipt_cannot_be_omitted(self):
        _, receipt, _, objects, catalog = fixture()
        del receipt['verification']
        with self.assertRaisesRegex(ValueError, 'separate immutable signed'):
            self.authenticate(receipt, objects, catalog)
        _, receipt, _, objects, catalog = fixture()
        receipt['postVerification']['reports'][0]['rawJsonSize'] += 1
        with self.assertRaises(ValueError):
            self.authenticate(receipt, objects, catalog)

    def test_report_and_publication_metadata_tampering_fail_closed(self):
        for target in ('report', 'manifest', 'verification'):
            _, receipt, _, objects, catalog = fixture()
            url = (receipt['postVerification']['reports'][0]['report']['url'] if target == 'report' else
                   receipt['manifestUrl'] if target == 'manifest' else receipt['verification']['manifestUrl'])
            objects[url] += b'\n'
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'metadata bytes differ'):
                self.authenticate(receipt, objects, catalog)

    def test_receipt_redirect_wrong_signer_and_unqualified_source_are_rejected(self):
        _, receipt, _, objects, catalog = fixture()
        receipt['manifestUrl'] = 'https://example.org/distribution-manifest.json'
        with self.assertRaises(ValueError):
            self.authenticate(receipt, objects, catalog)
        _, receipt, _, objects, catalog = fixture()
        with mock.patch('musl_release.verify_publication_signature', return_value='B'*40):
            with self.assertRaisesRegex(ValueError, 'receipt signer differs'):
                SITE.authenticate_receipt(receipt, fetch=lambda url, maximum: objects[url], keyring=Path('/fixture/trusted.gpg'))
        catalog['builds'] = []
        with self.assertRaisesRegex(ValueError, 'not the independently qualified'):
            self.authenticate(receipt, objects, catalog)

    def test_partial_cpu_duplicate_publication_and_candidate_asset_advertising_are_rejected(self):
        manifest, receipt, status, _, _ = fixture()
        status['publications'].append(copy.deepcopy(receipt))
        with self.assertRaisesRegex(ValueError, 'Duplicate or ambiguous'):
            SITE.public_rows(status, authenticator=lambda value: manifest)
        status['publications'] = [receipt]
        manifest['records'].pop()
        with self.assertRaisesRegex(ValueError, 'complete two-CPU'):
            SITE.public_rows(status, authenticator=lambda value: manifest)
        status['status'] = 'not-published'
        with self.assertRaisesRegex(ValueError, 'must not advertise candidate'):
            SITE.public_rows(status, authenticator=lambda value: manifest)

    def test_apk_and_oci_render_only_distinct_signed_musl_routes(self):
        for channel in ('apk', 'oci'):
            manifest, _, status, _, _ = fixture(channel)
            rows = SITE.public_rows(status, authenticator=lambda value: manifest)
            markup = SITE.render(rows)
            if channel == 'apk':
                self.assertIn('alpine324-aarch64-r1/', markup)
                self.assertIn('APK repository', markup)
            else:
                self.assertIn('ghcr.io/dotnetdev-kr/cbodotnet-sdk@sha256:', markup)
                self.assertNotIn(':latest', markup)


if __name__ == '__main__':
    unittest.main()
