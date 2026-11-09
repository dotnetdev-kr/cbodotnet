"""Gateway retries must preserve anonymous, authenticated whole-body downloads."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_distribution as D

URL = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/musl-sdk-7.0.120-r1/sdk.tar.gz'
BODY = b'exact qualified SDK bytes'
EXPECTED = dict(size=len(BODY), sha256=hashlib.sha256(BODY).hexdigest())


class PublicDownload(unittest.TestCase):
    def fixture(self, responses):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / 'sdk.tar.gz'
        calls, sleeps = [], []

        def open_response(request, timeout):
            self.assertFalse(target.exists())
            self.assertEqual(120, timeout)
            self.assertIsNone(request.get_header('Authorization'))
            self.assertIsNone(request.get_header('Range'))
            calls.append(request)
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        self.enterContext(patch.object(D.urllib.request, 'urlopen', side_effect=open_response))
        self.enterContext(patch.object(D.time, 'sleep', side_effect=sleeps.append))
        return target, calls, sleeps

    def gateway(self, code=504):
        return urllib.error.HTTPError(URL, code, 'gateway', {}, io.BytesIO())

    def test_gateway_retry_uses_fresh_anonymous_redirect_and_same_authenticated_bytes(self):
        target, calls, sleeps = self.fixture([self.gateway(), io.BytesIO(BODY)])
        result = D.download_asset(URL, target, EXPECTED)
        self.assertEqual(BODY, target.read_bytes())
        self.assertEqual(EXPECTED['sha256'], result['sha256'])
        self.assertEqual(URL, calls[0].full_url)
        self.assertTrue(calls[1].full_url.startswith(URL + '?cbodotnet_retry=1-'))
        self.assertEqual('no-cache', calls[1].get_header('Cache-control'))
        self.assertEqual([2], sleeps)

    def test_retry_budget_is_three_requests_and_six_seconds(self):
        target, calls, sleeps = self.fixture([self.gateway(502), self.gateway(503), self.gateway()])
        with self.assertRaises(urllib.error.HTTPError): D.download_asset(URL, target, EXPECTED)
        self.assertEqual(3, len(calls)); self.assertEqual([2, 4], sleeps)
        self.assertFalse(target.exists())

    def test_non_gateway_errors_fail_without_retry_or_output(self):
        for error in [self.gateway(404), self.gateway(403), TimeoutError('transport')]:
            with self.subTest(error=error):
                target, calls, sleeps = self.fixture([error])
                with self.assertRaises(type(error)): D.download_asset(URL, target, EXPECTED)
                self.assertEqual(1, len(calls)); self.assertEqual([], sleeps)
                self.assertFalse(target.exists())

    def test_truncated_or_modified_bytes_are_preserved_and_never_retried(self):
        for body in [BODY[:-1], b'x' * len(BODY), BODY + b'x']:
            with self.subTest(body=body):
                target, calls, sleeps = self.fixture([io.BytesIO(body)])
                with self.assertRaises(ValueError): D.download_asset(URL, target, EXPECTED)
                self.assertEqual(1, len(calls)); self.assertEqual([], sleeps)
                self.assertTrue(target.exists())
                self.assertEqual(body if len(body) <= len(BODY) else b'', target.read_bytes())

    def test_existing_output_cannot_be_overwritten(self):
        target, calls, _ = self.fixture([io.BytesIO(BODY)])
        target.write_bytes(b'preserved failed observation')
        # The network call's fixture also asserts the pre-existing boundary.
        with patch.object(D.urllib.request, 'urlopen', return_value=io.BytesIO(BODY)):
            with self.assertRaises(FileExistsError): D.download_asset(URL, target, EXPECTED)
        self.assertEqual(b'preserved failed observation', target.read_bytes())

    def test_foreign_url_is_rejected_before_any_network_request(self):
        target, calls, sleeps = self.fixture([])
        with self.assertRaises(ValueError):
            D.download_asset(URL.replace('dotnetdev-kr/cbodotnet', 'foreign/other'), target, EXPECTED)
        self.assertEqual([], calls); self.assertEqual([], sleeps)
        self.assertFalse(target.exists())


if __name__ == '__main__': unittest.main()
