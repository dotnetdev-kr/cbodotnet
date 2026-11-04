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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_site as SITE


class DistributionSiteTests(unittest.TestCase):
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
