"""Read-only tabletop: withdrawn temporary feeds expose no installation links."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import cbodotnetup_site as INSTALLER
import consumer_archive_site as ARCHIVE
import distribution_site as DISTRIBUTION
import musl_site as MUSL


class WithdrawalTabletop(unittest.TestCase):
    def test_withdrawal_removes_active_links_without_mutating_receipt_history(self):
        downstream_path = ROOT / 'releases/downstream-status.json'
        archive_path = ROOT / 'releases/archive-status.json'
        musl_path = ROOT / 'releases/musl-status.json'
        installer_path = ROOT / 'releases/cbodotnetup-status.json'
        before = {path: path.read_bytes() for path in (downstream_path, archive_path, musl_path, installer_path)}
        downstream = json.loads(before[downstream_path]); archive = json.loads(before[archive_path])
        musl = json.loads(before[musl_path])
        for channel in downstream['channels'].values():
            channel.update(status='not-published', publications=[], receipts=[])
        archive['publications'] = []
        musl.update(status='not-published', publications=[])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = DISTRIBUTION.prepare_site(downstream, root / 'site')
            archive_rows = ARCHIVE.archive_rows(status=archive)
            musl_markup = MUSL.render(MUSL.public_rows(musl, authenticator=lambda _: self.fail('No withdrawn receipt may be fetched')))
            with patch.object(INSTALLER, 'ROOT', root):
                installer_markup = INSTALLER.prepare(root / 'site')
            self.assertFalse((root / 'site/packages').exists())

        self.assertTrue(all(channel['publications'] == [] for channel in public['channels'].values()))
        self.assertEqual([], archive_rows)
        self.assertEqual('', musl_markup)
        self.assertEqual('', installer_markup)
        package_commands = DISTRIBUTION.render_channels(public)
        self.assertNotIn('apt-get', package_commands)
        self.assertNotIn('dnf install', package_commands)
        self.assertNotIn('docker pull', package_commands)
        self.assertEqual(before, {path: path.read_bytes() for path in before})


if __name__ == '__main__':
    unittest.main()