"""Keep archive metadata fetching bounded and on the common public retry path."""
import unittest
from unittest import mock

import consumer_archive_site as SITE


class ConsumerArchiveMetadataFetchTests(unittest.TestCase):
    def test_fetch_uses_shared_anonymous_metadata_transport_without_rewriting_the_canonical_url(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-10.0.403-r3/consumer-manifest.json'
        with mock.patch.object(SITE, 'get_bytes', return_value=b'metadata') as fetch:
            self.assertEqual(b'metadata', SITE.fetch_bytes(url, 100))
        fetch.assert_called_once_with(url, 100)

    def test_fetch_rejects_untrusted_release_prefix_before_requesting(self):
        for url in ('https://github.com/example/repo/releases/download/distribution-archive-sdk-10.0.403-r3/consumer-manifest.json',
                    'https://api.github.com/repos/dotnetdev-kr/cbodotnet/releases',
                    'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-10.0.403/release-manifest.json'):
            with self.subTest(url=url), mock.patch.object(SITE, 'get_bytes') as fetch:
                with self.assertRaisesRegex(ValueError, 'Untrusted'):
                    SITE.fetch_bytes(url, 100)
                fetch.assert_not_called()

    def test_fetch_retains_nonempty_and_upper_size_bound(self):
        url = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-10.0.403-r3/consumer-manifest.json'
        for data in (b'', b'12345'):
            with self.subTest(data=data), mock.patch.object(SITE, 'get_bytes', return_value=data):
                with self.assertRaisesRegex(ValueError, 'bound'):
                    SITE.fetch_bytes(url, 4)


if __name__ == '__main__':
    unittest.main()
