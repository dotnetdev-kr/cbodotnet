"""Keep public availability and repository extraction bound to signed evidence."""
import copy
import hashlib
import html
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_site as SITE


class StreamingResponse:
    def __init__(self, blocks):
        self.blocks = iter(blocks)
        self.read_sizes = []
        self.closed = False

    def read(self, size):
        if size != 4 * 1024**2:
            raise AssertionError('Large assets must be read in bounded blocks')
        self.read_sizes.append(size)
        block = next(self.blocks, b'')
        if isinstance(block, Exception):
            raise block
        return block

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


class DistributionDownloadTests(unittest.TestCase):
    URL = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-deb-sdk-10.0.403-r3/metadata.json'
    LARGE = 17 * 1024**2

    def test_small_assets_delegate_with_the_tighter_authenticated_size_bound(self):
        data = b'signed metadata'
        expected = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes', return_value=data) as fetch:
            target = Path(temporary) / 'metadata'
            self.assertEqual(expected['sha256'], SITE.download(self.URL, target, 128 * 1024**2, expected))
            fetch.assert_called_once_with(self.URL, len(data))
            self.assertEqual(data, target.read_bytes())

    def test_small_assets_keep_the_caller_bound_when_it_is_tighter_than_the_descriptor(self):
        data = b'data'
        expected = dict(size=20, sha256=hashlib.sha256(data).hexdigest())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes', return_value=data) as fetch:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                SITE.download(self.URL, Path(temporary) / 'metadata', len(data), expected)
            fetch.assert_called_once_with(self.URL, len(data))

    def test_small_assets_preserve_sha_validation_and_exclusive_creation(self):
        data = b'metadata'
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes', return_value=data) as fetch:
            target = Path(temporary) / 'metadata'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                SITE.download(self.URL, target, 100, dict(size=len(data), sha256='0' * 64))
            self.assertEqual(data, target.read_bytes())
            target.write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                SITE.download(self.URL, target, 100)
            self.assertEqual(b'original', target.read_bytes())
            self.assertEqual(2, fetch.call_count)

    def test_small_helper_cannot_exceed_the_download_bound(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes', return_value=b'oversized'):
            target = Path(temporary) / 'metadata'
            with self.assertRaisesRegex(ValueError, 'size bound'):
                SITE.download(self.URL, target, 2)
            self.assertFalse(target.exists())

    def test_small_trusted_repository_metadata_uses_the_shared_anonymous_api_fallback(self):
        url = self.URL.replace('distribution-deb-sdk-', 'repository-deb-debian-13-sdk-')
        data = b'fallback metadata'
        expected = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        error = SITE.urllib.error.HTTPError(url, 504, 'transient', {}, None)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(SITE.urllib.request, 'urlopen', side_effect=error) as opener, \
                mock.patch('release_catalog.anonymous_release_metadata', return_value=data) as fallback, \
                mock.patch.object(SITE.time, 'sleep'):
            target = Path(temporary) / 'metadata'
            self.assertEqual(expected['sha256'], SITE.download(url, target, self.LARGE, expected))
            self.assertEqual(3, opener.call_count)
            fallback.assert_called_once_with(url, len(data))
            self.assertEqual(data, target.read_bytes())

    def test_foreign_or_unadmitted_asset_urls_never_reach_either_download_path(self):
        with mock.patch.object(SITE, 'get_bytes') as helper, mock.patch.object(SITE.urllib.request, 'urlopen') as opener:
            for maximum in (100, self.LARGE):
                for url in ('http://github.com/x', 'https://evil.example/key', 'file:///etc/passwd',
                            self.URL.replace('dotnetdev-kr/cbodotnet', 'other/repository'),
                            self.URL.replace('distribution-deb-sdk-', 'sdk-')):
                    with self.subTest(url=url, maximum=maximum), self.assertRaisesRegex(ValueError, 'Untrusted'):
                        SITE.download(url, Path('unused'), maximum)
            helper.assert_not_called()
            opener.assert_not_called()

    def test_large_transient_connection_failures_retry_fresh_public_urls_before_opening_a_file(self):
        errors = [SITE.urllib.error.HTTPError(self.URL, code, 'transient', {}, None) for code in (502, 503, 504)]
        errors += [SITE.urllib.error.URLError('connection reset'), TimeoutError('timed out')]
        for error in errors:
            with self.subTest(error=str(error)), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(SITE, 'get_bytes') as helper, \
                    mock.patch.object(SITE.time, 'sleep') as sleep, \
                    mock.patch.object(SITE.urllib.request, 'urlopen') as opener:
                target = Path(temporary) / 'archive'
                response = StreamingResponse([b'large-asset-stream'])

                def connect(request, **kwargs):
                    self.assertFalse(target.exists())
                    self.assertEqual(dict(timeout=60), kwargs)
                    if opener.call_count == 1:
                        raise error
                    return response

                opener.side_effect = connect
                expected_hash = hashlib.sha256(b'large-asset-stream').hexdigest()
                self.assertEqual(expected_hash, SITE.download(self.URL, target, self.LARGE))
                self.assertEqual(2, opener.call_count)
                sleep.assert_called_once_with(2)
                original, retry = [call.args[0] for call in opener.call_args_list]
                self.assertEqual(self.URL, original.full_url)
                self.assertEqual(urlsplit(self.URL).path, urlsplit(retry.full_url).path)
                self.assertRegex(urlsplit(retry.full_url).query, r'^cbodotnet_retry=1-[0-9]+$')
                self.assertEqual('no-cache', retry.get_header('Cache-control'))
                self.assertEqual('no-cache', retry.get_header('Pragma'))
                self.assertNotIn('Authorization', dict(retry.header_items()))
                self.assertTrue(response.closed)
                helper.assert_not_called()

    def test_large_connection_retry_is_limited_to_three_attempts_without_api_fallback(self):
        error = SITE.urllib.error.HTTPError(self.URL, 504, 'transient', {}, None)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes') as helper, \
                mock.patch.object(SITE.urllib.request, 'urlopen', side_effect=error) as opener, \
                mock.patch.object(SITE.time, 'sleep') as sleep:
            target = Path(temporary) / 'archive'
            with self.assertRaises(SITE.urllib.error.HTTPError):
                SITE.download(self.URL, target, self.LARGE)
            self.assertEqual(3, opener.call_count)
            self.assertEqual([mock.call(2), mock.call(4)], sleep.call_args_list)
            self.assertFalse(target.exists())
            helper.assert_not_called()

    def test_large_permanent_http_failure_is_not_retried(self):
        error = SITE.urllib.error.HTTPError(self.URL, 404, 'missing', {}, None)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE.urllib.request, 'urlopen', side_effect=error) as opener, \
                mock.patch.object(SITE.time, 'sleep') as sleep:
            target = Path(temporary) / 'archive'
            with self.assertRaises(SITE.urllib.error.HTTPError):
                SITE.download(self.URL, target, self.LARGE)
            opener.assert_called_once()
            sleep.assert_not_called()
            self.assertFalse(target.exists())

    def test_large_asset_streams_blocks_and_verifies_the_exact_descriptor(self):
        blocks = [b'a' * (4 * 1024**2)] * 4 + [b'last block']
        sha = hashlib.sha256()
        for block in blocks:
            sha.update(block)
        expected = dict(size=sum(map(len, blocks)), sha256=sha.hexdigest())
        response = StreamingResponse(blocks)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE, 'get_bytes') as helper, \
                mock.patch.object(SITE.urllib.request, 'urlopen', return_value=response):
            target = Path(temporary) / 'archive'
            self.assertEqual(expected['sha256'], SITE.download(self.URL, target, 128 * 1024**2, expected))
            self.assertEqual(expected['size'], target.stat().st_size)
            self.assertEqual([4 * 1024**2] * 6, response.read_sizes)
            self.assertTrue(response.closed)
            helper.assert_not_called()

    def test_large_descriptor_bound_is_enforced_before_writing_an_excess_block(self):
        response = StreamingResponse([b'a' * (4 * 1024**2)] * 4 + [b'b' * (2 * 1024**2)])
        expected = dict(size=self.LARGE, sha256='0' * 64)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SITE.urllib.request, 'urlopen', return_value=response) as opener, \
                mock.patch.object(SITE.time, 'sleep') as sleep:
            target = Path(temporary) / 'archive'
            with self.assertRaisesRegex(ValueError, 'size bound'):
                SITE.download(self.URL, target, 128 * 1024**2, expected)
            self.assertEqual(16 * 1024**2, target.stat().st_size)
            opener.assert_called_once()
            sleep.assert_not_called()
            self.assertTrue(response.closed)

    def test_large_read_file_and_integrity_failures_are_not_retried(self):
        for failure in ('read', 'existing', 'digest'):
            blocks = [b'partial', SITE.urllib.error.URLError('interrupted')] if failure == 'read' else [b'contents']
            response = StreamingResponse(blocks)
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(SITE.urllib.request, 'urlopen', return_value=response) as opener, \
                    mock.patch.object(SITE.time, 'sleep') as sleep:
                target = Path(temporary) / 'archive'
                expected = dict(size=self.LARGE, sha256='0' * 64) if failure == 'digest' else None
                error = dict(read=SITE.urllib.error.URLError, existing=FileExistsError, digest=ValueError)[failure]
                if failure == 'existing':
                    target.write_bytes(b'original')
                with self.assertRaises(error):
                    SITE.download(self.URL, target, self.LARGE, expected)
                if failure == 'existing':
                    self.assertEqual(b'original', target.read_bytes())
                opener.assert_called_once()
                sleep.assert_not_called()
                self.assertTrue(response.closed)


class DistributionSiteTests(unittest.TestCase):
    def test_install_commands_are_collapsed_per_distribution_and_container_version(self):
        status = dict(channels=dict(
            deb=dict(status='published', publications=[dict(variant='ubuntu-24.04', sdkVersion='10.0.403', packageRevision=1)]),
            rpm=dict(status='published', publications=[dict(variant='fedora-45')]),
            oci=dict(status='published', image=dict(repository='ghcr.io/dotnetdev-kr/cbodotnet-sdk', digest='sha256:' + 'a' * 64),
                     images=[dict(repository='ghcr.io/dotnetdev-kr/cbodotnet-sdk', digest='sha256:' + 'b' * 64, sdkVersion='8.0.133'),
                             dict(repository='ghcr.io/dotnetdev-kr/cbodotnet-sdk', digest='sha256:' + 'a' * 64, sdkVersion='10.0.403')])
        ))
        markup = SITE.render_channels(status)
        self.assertEqual(4, markup.count('<details class="install-details">'))
        self.assertNotIn('<details class="install-details" open', markup)
        self.assertIn('<span>Ubuntu 24.04</span>', markup)
        self.assertIn('<span>Fedora 45</span>', markup)
        self.assertIn('<span>SDK 10.0.403</span>', markup)
        self.assertIn('<span>SDK 8.0.133</span>', markup)
        self.assertLess(markup.index('<span>SDK 10.0.403</span>'), markup.index('<span>SDK 8.0.133</span>'))
        self.assertIn('id="packages"', markup)
        self.assertIn('id="containers"', markup)
        self.assertIn('D7D154B4B33C19A82B95B13688135410ACD9C0EA', markup)
        self.assertIn('docker pull ghcr.io/dotnetdev-kr/cbodotnet-sdk@sha256:' + 'a' * 64, markup)

    def test_all_sdk_repository_urls_and_commands_remain_visible(self):
        publications = [dict(variant='debian-13', sdkVersion=version, packageRevision=1)
                        for version in ('10.0.403', '8.0.133')]
        repositories = [dict(row, repositoryUrl='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'
                        + 'repository-deb-debian-13-sdk-' + row['sdkVersion'] + '-r1/') for row in publications]
        status = dict(channels=dict(deb=dict(status='published', publications=publications, repositories=repositories)))
        markup = SITE.render_channels(status)
        for row in repositories:
            self.assertIn(row['repositoryUrl'], markup)
        self.assertIn('cbodotnet-sdk-8.0', markup)
        self.assertIn('cbodotnet-sdk-10.0', markup)
        status['channels'] = dict(rpm=dict(status='published', publications=publications, repositories=[
            dict(row, repositoryUrl='https://dotnetdev.kr/cbodotnet/packages/rpm/debian-13/sdk-'
                 + row['sdkVersion'] + '-r1/') for row in publications]))
        markup = SITE.render_channels(status)
        self.assertIn('[cbodotnet-sdk-8.0]', markup)
        self.assertIn('[cbodotnet-sdk-10.0]', markup)

    def test_configured_but_unpublished_channel_has_no_install_commands(self):
        policy = json.loads((ROOT / 'releases/downstream-status.json').read_bytes())
        for channel in policy['channels'].values():
            channel.update(status='not-published', publications=[], receipts=[])
        with tempfile.TemporaryDirectory() as temporary:
            status = SITE.prepare_site(policy, Path(temporary) / 'site')
        markup = SITE.render_channels(status)
        self.assertNotIn('apt-get', markup)
        self.assertNotIn('docker pull', markup)
        self.assertNotIn('dnf install', markup)
        self.assertNotIn('evidenceSigners', status)

    def test_published_flag_without_receipt_is_not_a_publication(self):
        policy = json.loads((ROOT / 'releases/downstream-status.json').read_bytes())
        policy['channels']['deb'].update(status='published', publications=[{}], receipts=[])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'site'
            with self.assertRaisesRegex(ValueError, 'verified publication'):
                SITE.prepare_site(policy, output)
            self.assertFalse(output.exists())

    def test_repository_links_and_escape_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (name, kind, link) in enumerate([
                    ('../outside', tarfile.REGTYPE, ''), ('/outside', tarfile.REGTYPE, ''),
                    ('pool/package.deb', tarfile.SYMTYPE, '/etc/passwd'),
                    ('pool/package.deb', tarfile.LNKTYPE, '../outside')]):
                archive = root / f'unsafe-{index}.tar.gz'
                with tarfile.open(archive, 'w:gz') as stream:
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, link
                    stream.addfile(entry)
                destination = root / f'repository-{index}'
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    SITE.extract_repository(archive, destination)
                self.assertFalse(destination.exists())

    def test_ordinary_repository_bytes_survive_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'repository.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                for name, data in [('Release', b'qualified release'), ('pool/sdk.deb', b'qualified package')]:
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = len(data), 0o644
                    stream.addfile(entry, io.BytesIO(data))
            SITE.extract_repository(archive, root / 'repository')
            self.assertEqual(b'qualified package', (root / 'repository/pool/sdk.deb').read_bytes())

    def test_metadata_download_rejects_foreign_hosts_before_network(self):
        with mock.patch.object(SITE.urllib.request, 'urlopen') as fetch:
            for url in ('http://github.com/x', 'https://evil.example/key', 'file:///etc/passwd'):
                with self.assertRaisesRegex(ValueError, 'Untrusted'):
                    SITE.download(url, Path('unused'), 100)
            fetch.assert_not_called()

    def test_apt_uses_flat_deb822_scoped_trust_and_latest_authenticated_revision_per_distro(self):
        rows = [dict(variant=variant, sdkVersion='10.0.403', packageRevision=revision)
                for variant, revision in [('ubuntu-24.04', 1), ('ubuntu-24.04', 2), ('debian-13', 1)]]
        markup = html.unescape(SITE.render_channels({'channels': {'deb': {'status': 'published', 'publications': rows}}}))
        self.assertEqual(2, markup.count('Types: deb\n'))
        self.assertEqual(2, markup.count('Suites: ./\n'))
        self.assertEqual(2, markup.count('Architectures: $(dpkg --print-architecture)\n'))
        self.assertEqual(2, markup.count('Signed-By: /usr/share/keyrings/cbodotnet-archive-keyring.gpg\n'))
        self.assertIn('URIs: https://dotnetdev.kr/cbodotnet/packages/deb/ubuntu-24.04/\n', markup)
        self.assertIn('URIs: https://dotnetdev.kr/cbodotnet/packages/deb/debian-13/\n', markup)
        self.assertIn('install cbodotnet-sdk-10.0=10.0.403-2', markup)
        self.assertIn('install cbodotnet-sdk-10.0=10.0.403-1', markup)
        self.assertIn('sudo rm -f /etc/apt/sources.list.d/cbodotnet.list', markup)
        self.assertIn('/etc/apt/sources.list.d/cbodotnet.sources', markup)
        self.assertNotIn('Components:', markup)
        self.assertNotIn('apt-key', markup)
        self.assertNotIn('deb [signed-by=', markup)

    def test_rpm_commands_require_both_signature_checks_and_pinned_public_identity(self):
        status = {'channels': {'rpm': {'status': 'published', 'publications': [
            {'variant': 'fedora-45'}, {'variant': 'rocky-9.8'}]}, 'aur': {'status': 'not-published'}}}
        markup = SITE.render_channels(status)
        self.assertIn('gpgcheck=1', markup)
        self.assertIn('repo_gpgcheck=1', markup)
        self.assertIn('D7D154B4B33C19A82B95B13688135410ACD9C0EA', markup)
        self.assertIn('packages/rpm/fedora-45/', markup)
        self.assertIn('packages/rpm/rocky-9.8/', markup)
        self.assertIn('sudo dnf install -y ca-certificates gnupg2', markup)
        self.assertIn('command -v curl', markup)
        self.assertIn('|| sudo dnf install -y curl', markup)
        self.assertNotIn('install -y ca-certificates curl', markup)
        self.assertNotIn('aur.archlinux.org', markup)

    def test_rpm_archive_cannot_be_hosted_under_another_variant_or_source_identity(self):
        identity = dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='a' * 64)
        signer = 'B' * 40
        tag = 'distribution-rpm-sdk-10.0.403-r1'
        base = f'https://github.com/{SITE.REPOSITORY}/releases/download/{tag}/'
        publications = [dict(variant='fedora-45', architecture=arch) for arch in ('x64', 'aarch64')]
        archive_name = 'rpm-fedora-45.tar.gz'
        manifest = dict(schemaVersion=1, repository=SITE.REPOSITORY, identity=identity, tag=tag, contractVersion=2,
            status='validated-complete-matrix', signingFingerprint=signer,
            records=[dict(record=dict(identity={'variant': 'fedora-45'}, architecture=arch)) for arch in ('x64', 'aarch64')],
            assets=[dict(name=archive_name, size=7, sha256=hashlib.sha256(b'archive').hexdigest())],
            repositories=[dict(asset=archive_name, kind='rpm-repository', variants=['fedora-45'])])
        files = {'distribution-manifest.json': json.dumps(manifest).encode(),
                 'distribution-manifest.json.asc': b'signature', archive_name: b'archive'}
        assets = [dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(), url=base + name)
                  for name, data in files.items()]
        receipt = dict(status='published-postverified', repository=SITE.REPOSITORY, identity=identity, tag=tag,
            manifestUrl=base + 'distribution-manifest.json', signatureUrl=base + 'distribution-manifest.json.asc',
            manifestSha256=hashlib.sha256(files['distribution-manifest.json']).hexdigest(),
            signingFingerprint=signer, assets=assets, publications=publications)
        policy = dict(schemaVersion=1, repository=SITE.REPOSITORY, status='published',
            channels={name: dict(status='not-published', publications=[]) for name in ('deb', 'rpm', 'oci', 'aur')})
        policy['channels']['rpm'].update(status='published', publications=publications, receipts=[receipt],
            candidateMatrix=publications)
        contract = dict(schemaVersion=2, releases={'10.0.403': {'manifestSha256': identity['sourceManifestSha256']}},
                        channels={'rpm': {'variants': ['fedora-45']}})
        def download(url, destination, limit, expected=None):
            data = files[url.rsplit('/', 1)[1]]
            Path(destination).write_bytes(data)
            return hashlib.sha256(data).hexdigest()
        for field, value in [('variant', 'rocky-9.8'), ('sourceManifestSha256', 'c' * 64), ('signingFingerprint', 'D' * 40)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                key = root / 'key.asc'
                key.write_bytes(b'pinned-key')
                repository_identity = dict(variant='fedora-45', sourceManifestSha256=identity['sourceManifestSha256'],
                                           signingFingerprint=signer) | {field: value}
                with mock.patch.object(SITE, 'load_contract', return_value=contract), \
                     mock.patch.object(SITE, 'download', side_effect=download), \
                     mock.patch.object(SITE.subprocess, 'run'), \
                     mock.patch.object(SITE, 'verify_report_signature', return_value=signer), \
                     mock.patch.object(SITE, 'publication_rows', return_value=publications), \
                     mock.patch.object(SITE, 'extract_repository', side_effect=lambda archive, destination: destination.mkdir()), \
                     mock.patch.object(SITE, 'verify_rpm_repository', return_value=repository_identity):
                    with self.assertRaisesRegex(ValueError, 'RPM repository identity differs'):
                        SITE.prepare_site(policy, root / 'site', key)
