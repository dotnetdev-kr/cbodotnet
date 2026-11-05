from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import cbodotnetup_site as SITE


class InstallerSiteGates(unittest.TestCase):
    def test_no_activated_status_publishes_no_installer_feed(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'ROOT',Path(temporary)),patch.object(SITE,'get_bytes') as network:
            output=Path(temporary)/'site'
            self.assertEqual(SITE.prepare(output),'')
            self.assertFalse(output.exists());network.assert_not_called()

    def test_pending_native_qualification_cannot_enable_the_feed(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='prepared')
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_noncanonical_release_identity_is_rejected_before_network(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',catalogSequence=123,catalogRelease=dict(tag='other-123'))
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()

    def test_untrusted_bootstrap_asset_origin_cannot_be_rendered(self):
        status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',catalogSequence=123,
            catalogRelease=dict(tag='cbodotnetup-catalog-123',assets=[dict(name='catalog.json',url='https://evil.example/catalog.json',size=1,sha256='a'*64)]))
        with tempfile.TemporaryDirectory() as temporary,patch.object(SITE,'get_bytes') as network:
            with self.assertRaises(ValueError):SITE.prepare(Path(temporary),status)
            network.assert_not_called()


if __name__=='__main__':unittest.main()
