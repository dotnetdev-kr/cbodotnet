"""Pinned OmniSharp cache recovery fixtures; no real network or SDK execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('net6_test_tools_download', ROOT / 'scripts/prepare-net6-test-tools.py')
H = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(H)
TOOL_INPUT = H.tool_input
BODY = b'exact pinned OmniSharp archive fixture'


class Response(io.BytesIO):
    def __init__(self, body, url='https://release-assets.githubusercontent.com/fixture'):
        super().__init__(body); self.url = url

    def geturl(self):
        return self.url


class PinnedCacheDownload(unittest.TestCase):
    def fixture(self, responses, arch='arm64'):
        temporary = tempfile.TemporaryDirectory(prefix='net6-omnisharp-download-')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        pin = {**TOOL_INPUT(arch), 'bytes': len(BODY), 'sha256': hashlib.sha256(BODY).hexdigest()}
        target = directory / pin['cacheName']
        calls, sleeps = [], []

        def opener(request, timeout):
            self.assertEqual(120, timeout)
            self.assertFalse(target.exists())
            if not isinstance(request, str):
                self.assertIsNone(request.get_header('Authorization'))
                self.assertIsNone(request.get_header('Range'))
            calls.append(request)
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        self.enterContext(patch.object(H, 'tool_input', return_value=pin))
        self.enterContext(patch.object(H.urllib.request, 'urlopen', side_effect=opener))
        self.enterContext(patch.object(H.time, 'sleep', side_effect=sleeps.append))
        fallback = self.enterContext(patch.object(H.CATALOG, 'anonymous_release_download_request',
                                                 side_effect=AssertionError('Unexpected API fallback')))
        return directory, pin, target, calls, sleeps, fallback

    def gateway(self, status=504):
        error = urllib.error.HTTPError('https://github.com/fixture', status, 'gateway', {}, io.BytesIO())
        self.addCleanup(error.close)
        return error

    def assert_no_staging(self, directory):
        self.assertEqual([], list(directory.glob('.omnisharp-download-*')))

    def test_original_architecture_pins_are_unchanged(self):
        arm, x64 = H.tool_input(), H.tool_input('x64')
        self.assertEqual(('1.39.6', 41382979, '6e097febba7dc2a1422f1cb992e358a063412c05a08eb6719388561e3a75c734'),
                         (H.VERSION, arm['bytes'], arm['sha256']))
        self.assertEqual((43149563, 'c631cf552590ee8f00cbea441e99a94f689bf1832f1f8de2d5a00d5d5d18140c'),
                         (x64['bytes'], x64['sha256']))
        self.assertIn('/v1.39.6/omnisharp-linux-arm64-net6.0.tar.gz', arm['url'])
        self.assertIn('/v1.39.6/omnisharp-linux-x64-net6.0.tar.gz', x64['url'])

    def test_first_success_keeps_original_url_whole_hash_and_atomic_cache_publish(self):
        for arch in ('arm64', 'x64'):
            with self.subTest(arch=arch):
                directory, pin, target, calls, sleeps, fallback = self.fixture([Response(BODY)], arch)
                self.assertEqual((target, True), H.cached_archive(directory, arch))
                self.assertEqual(BODY, target.read_bytes())
                self.assertEqual([pin['url']], calls); self.assertEqual([], sleeps)
                fallback.assert_not_called(); self.assert_no_staging(directory)

    def test_gateway_retry_freshens_only_redirect_with_two_and_four_second_waits(self):
        directory, pin, target, calls, sleeps, fallback = self.fixture(
            [self.gateway(502), self.gateway(503), Response(BODY)])
        self.assertEqual((target, True), H.cached_archive(directory))
        self.assertEqual(pin['url'], calls[0])
        for attempt in (1, 2):
            self.assertTrue(calls[attempt].startswith(pin['url'] + '?cbodotnet_retry=' + str(attempt) + '-'))
        self.assertEqual([2, 4], sleeps); fallback.assert_not_called()
        self.assert_no_staging(directory)

    def test_three_gateway_failures_allow_one_anonymous_api_request_with_exact_pin(self):
        directory, pin, target, calls, sleeps, fallback = self.fixture(
            [self.gateway(502), self.gateway(503), self.gateway(), Response(BODY)])
        fallback.side_effect = None
        request = H.urllib.request.Request('https://api.github.com/repos/OmniSharp/omnisharp-roslyn/releases/assets/123',
                                           headers={'Accept': 'application/octet-stream'})
        fallback.return_value = request
        self.assertEqual((target, True), H.cached_archive(directory))
        fallback.assert_called_once_with(pin['url'], {'size': len(BODY), 'sha256': pin['sha256']})
        self.assertIs(request, calls[3]); self.assertEqual(4, len(calls)); self.assertEqual([2, 4], sleeps)
        self.assertEqual(BODY, target.read_bytes()); self.assert_no_staging(directory)

    def test_api_route_body_is_subject_to_all_original_size_and_hash_checks(self):
        for body in (BODY[:-1], b'x' * len(BODY), BODY + b'x'):
            with self.subTest(body=body):
                directory, pin, target, calls, sleeps, fallback = self.fixture(
                    [self.gateway(), self.gateway(), self.gateway(), Response(body)])
                fallback.side_effect = None
                fallback.return_value = H.urllib.request.Request('https://api.github.com/repos/fixture/repo/releases/assets/123')
                with self.assertRaises(ValueError): H.cached_archive(directory)
                self.assertFalse(target.exists()); self.assertEqual(4, len(calls)); self.assertEqual([2, 4], sleeps)
                self.assert_no_staging(directory)

    def test_api_resolution_or_open_failure_is_fatal_without_a_second_fallback(self):
        for resolution_fails in (True, False):
            with self.subTest(resolution=resolution_fails):
                responses = [self.gateway(), self.gateway(), self.gateway()]
                if not resolution_fails: responses.append(self.gateway())
                directory, pin, target, calls, sleeps, fallback = self.fixture(responses)
                fallback.side_effect = self.gateway() if resolution_fails else None
                fallback.return_value = H.urllib.request.Request('https://api.github.com/repos/fixture/repo/releases/assets/123')
                with self.assertRaises(urllib.error.HTTPError): H.cached_archive(directory)
                fallback.assert_called_once()
                self.assertEqual(3 if resolution_fails else 4, len(calls)); self.assertEqual([2, 4], sleeps)
                self.assertFalse(target.exists()); self.assert_no_staging(directory)

    def test_non_gateway_open_failures_have_no_retry_or_fallback(self):
        for error in (self.gateway(403), self.gateway(404), TimeoutError('fixture'),
                      urllib.error.URLError('fixture')):
            with self.subTest(error=type(error).__name__):
                directory, pin, target, calls, sleeps, fallback = self.fixture([error])
                with self.assertRaises(type(error)): H.cached_archive(directory)
                self.assertEqual(1, len(calls)); self.assertEqual([], sleeps); fallback.assert_not_called()
                self.assertFalse(target.exists()); self.assert_no_staging(directory)

    def test_partial_body_gateway_failure_is_never_retried_or_cached(self):
        error = self.gateway()
        class Partial(Response):
            def read(self, size=-1):
                if self.tell(): raise error
                return super().read(3)
        directory, pin, target, calls, sleeps, fallback = self.fixture([Partial(BODY)])
        with self.assertRaises(urllib.error.HTTPError): H.cached_archive(directory)
        self.assertEqual(1, len(calls)); self.assertEqual([], sleeps); fallback.assert_not_called()
        self.assertFalse(target.exists()); self.assert_no_staging(directory)

    def test_initial_truncated_modified_oversized_or_non_https_body_is_not_retried(self):
        for body, url in ((BODY[:-1], 'https://fixture'), (b'x' * len(BODY), 'https://fixture'),
                          (BODY + b'x', 'https://fixture'), (BODY, 'http://fixture')):
            with self.subTest(body=body, url=url):
                directory, pin, target, calls, sleeps, fallback = self.fixture([Response(body, url)])
                with self.assertRaises(ValueError): H.cached_archive(directory)
                self.assertEqual(1, len(calls)); self.assertEqual([], sleeps); fallback.assert_not_called()
                self.assertFalse(target.exists()); self.assert_no_staging(directory)

    def test_exact_existing_cache_reuses_bytes_without_network(self):
        directory, pin, target, calls, sleeps, fallback = self.fixture([])
        target.write_bytes(BODY)
        self.assertEqual((target, False), H.cached_archive(directory))
        self.assertEqual([], calls); self.assertEqual([], sleeps); fallback.assert_not_called()
        self.assertEqual(BODY, target.read_bytes()); self.assert_no_staging(directory)

    def test_wrong_existing_cache_is_preserved_and_fails_without_network(self):
        directory, pin, target, calls, sleeps, fallback = self.fixture([])
        target.write_bytes(b'preserved failed cache')
        with self.assertRaisesRegex(ValueError, 'Existing OmniSharp archive differs'): H.cached_archive(directory)
        self.assertEqual(b'preserved failed cache', target.read_bytes())
        self.assertEqual([], calls); fallback.assert_not_called(); self.assert_no_staging(directory)

    @unittest.skipIf(sys.platform == 'win32', 'Ordinary POSIX symlink cache control')
    def test_cache_symlink_is_rejected_without_network_and_preserved(self):
        directory, pin, target, calls, sleeps, fallback = self.fixture([])
        original = directory / 'original'; original.write_bytes(BODY); target.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'Existing OmniSharp archive differs'): H.cached_archive(directory)
        self.assertTrue(target.is_symlink()); self.assertEqual(BODY, original.read_bytes())
        self.assertEqual([], calls); fallback.assert_not_called(); self.assert_no_staging(directory)

    def test_concurrent_cache_winner_is_never_replaced_and_is_independently_hashed(self):
        real_link = H.os.link
        for winner in (BODY, b'preserved concurrent wrong input'):
            with self.subTest(winner=winner):
                directory, pin, target, calls, sleeps, fallback = self.fixture([Response(BODY)])
                def concurrent(staged, destination):
                    target.write_bytes(winner)
                    return real_link(staged, destination)
                with patch.object(H.os, 'link', side_effect=concurrent):
                    if winner == BODY:
                        self.assertEqual((target, False), H.cached_archive(directory))
                    else:
                        with self.assertRaisesRegex(ValueError, 'Existing OmniSharp archive differs'): H.cached_archive(directory)
                self.assertEqual(winner, target.read_bytes()); self.assert_no_staging(directory)


if __name__ == '__main__': unittest.main()
