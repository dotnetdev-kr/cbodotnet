import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_catalog as C

URL = 'https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.6/omnisharp-linux-arm64-net6.0.tar.gz'
BASE = 'https://api.github.com/repos/OmniSharp/omnisharp-roslyn'
PIN = dict(size=41382979, sha256='6e097febba7dc2a1422f1cb992e358a063412c05a08eb6719388561e3a75c734')
ASSET = dict(id=123, name=URL.rsplit('/', 1)[1], state='uploaded', browser_download_url=URL,
             size=PIN['size'], url=BASE + '/releases/assets/123', digest=None)
RELEASE = dict(tag_name='v1.39.6', draft=False, assets=[ASSET])


class PublicAssetRedirect(unittest.TestCase):
    def request(self, release=RELEASE, url=URL, pin=PIN):
        with patch.object(C, 'get_bytes', return_value=json.dumps(release).encode()) as metadata:
            request = C.anonymous_release_download_request(url, pin)
        metadata.assert_called_once_with(BASE + '/releases/tags/v1.39.6', C.MAX_JSON_BYTES, api=True)
        return request

    def test_exact_legacy_asset_without_api_digest_keeps_immutable_pin_and_anonymous_api_origin(self):
        request = self.request()
        self.assertEqual(BASE + '/releases/assets/123', request.full_url)
        self.assertEqual('application/octet-stream', request.get_header('Accept'))
        self.assertIsNone(request.get_header('Authorization'))
        self.assertIsNone(request.get_header('Range'))

    def test_modern_matching_digest_is_also_required_when_present(self):
        release = copy.deepcopy(RELEASE); release['assets'][0]['digest'] = 'sha256:' + PIN['sha256']
        self.request(release)
        release['assets'][0]['digest'] = 'sha256:' + '0' * 64
        with self.assertRaises(ValueError): self.request(release)

    def test_wrong_release_asset_origin_size_state_or_duplicate_are_rejected(self):
        mutations = [lambda r: r.update(draft=True), lambda r: r.update(tag_name='v1.39.7'),
                     lambda r: r['assets'].append(copy.deepcopy(ASSET))]
        for field, value in [('id', True), ('state', 'new'), ('size', PIN['size'] + 1),
                             ('browser_download_url', URL + '?changed=1'),
                             ('url', 'https://example.test/file'), ('name', 'other.tar.gz')]:
            mutations.append(lambda r, field=field, value=value: r['assets'][0].update({field: value}))
        for mutate in mutations:
            release = copy.deepcopy(RELEASE); mutate(release)
            with self.subTest(release=release), self.assertRaises(ValueError): self.request(release)

    def test_untrusted_url_or_incomplete_pin_is_rejected_before_metadata_lookup(self):
        with patch.object(C, 'get_bytes') as metadata:
            for url in (URL.replace('https:', 'http:'), URL + '?token=private', URL + '#fragment',
                        URL.replace('github.com/', 'github.com.evil/')):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    C.anonymous_release_download_request(url, PIN)
            for pin in ({'size': 0, 'sha256': PIN['sha256']}, {'size': True, 'sha256': PIN['sha256']},
                        {'size': PIN['size'], 'sha256': 'unknown'}):
                with self.subTest(pin=pin), self.assertRaises(ValueError):
                    C.anonymous_release_download_request(URL, pin)
            metadata.assert_not_called()


if __name__ == '__main__': unittest.main()
