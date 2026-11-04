"""Keep public availability and repository extraction bound to signed evidence."""
import copy
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
