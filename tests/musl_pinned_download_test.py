"""Complete-response, retry and closed-pin transport boundaries."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tested_pinned_download', ROOT / 'scripts/musl_pinned_download.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
BODY = b'complete reviewed source-built archive'
PIN = dict(url='https://example.test/original.tar.gz', bytes=len(BODY),
           sha256=hashlib.sha256(BODY).hexdigest(), sha512=hashlib.sha512(BODY).hexdigest())


class Response(io.BytesIO):
    def __init__(self, data=BODY, status=200, headers=None):
        super().__init__(data)
        self.code = status
        self.headers = {'Content-Length': str(len(data))} if headers is None else headers

    def getcode(self):
        return self.code

    def geturl(self):
        return PIN['url']


class PinnedDownload(unittest.TestCase):
    def run_download(self, responses, *, pin=PIN):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        target, reports = directory / 'original.tar.gz', directory / 'attempts'
        requests = []

        def opener(request, timeout):
            self.assertFalse(target.exists(), 'an unvalidated payload reached the final input name')
            self.assertEqual(120, timeout)
            self.assertIsNone(request.get_header('Range'))
            self.assertEqual(PIN['url'], request.full_url)
            requests.append(request.full_url)
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return value

        try:
            result = D.download_pinned(pin, target, reports, opener=opener, sleep=lambda _: None)
            error = None
        except ValueError as failure:
            result, error = None, failure
        return target, reports, requests, result, error

    def test_complete_original_input_is_admitted_with_exact_record(self):
        target, reports, requests, result, error = self.run_download([Response()])
        self.assertIsNone(error)
        self.assertEqual(PIN, result)
        self.assertEqual(BODY, target.read_bytes())
        status = json.loads((reports / 'download.json').read_text())
        self.assertEqual('passed', status['status'])
        self.assertEqual(1, len(requests))
        self.assertTrue(status['attempts'][0]['accepted'])
        self.assertEqual({k: PIN[k] for k in D.FP}, status['attempts'][0]['observedFingerprint'])
        self.assertFalse(list(target.parent.glob('*.part')))

    def test_truncated_200_records_actual_bytes_and_retries_the_same_url(self):
        target, reports, requests, result, error = self.run_download([
            Response(BODY[:9], headers={'Content-Length': str(len(BODY))}), Response()])
        self.assertIsNone(error)
        first = json.loads((reports / 'attempt-1.json').read_text())
        self.assertEqual(200, first['httpStatus'])
        self.assertEqual(9, first['observedFingerprint']['bytes'])
        self.assertEqual(hashlib.sha256(BODY[:9]).hexdigest(), first['observedFingerprint']['sha256'])
        self.assertFalse(first['accepted'])
        self.assertEqual([PIN['url']] * 2, requests)
        self.assertEqual(BODY, target.read_bytes())

    def test_full_matching_bytes_cannot_bypass_partial_or_inconsistent_http(self):
        target, reports, requests, _, error = self.run_download([
            Response(status=206, headers={'Content-Length': str(len(BODY)), 'Content-Range': 'bytes 0-36/37'}),
            Response(headers={'Content-Length': str(len(BODY) - 1)}), Response()])
        self.assertIsNone(error)
        self.assertEqual(3, len(requests))
        first = json.loads((reports / 'attempt-1.json').read_text())
        self.assertEqual(PIN['sha512'], first['observedFingerprint']['sha512'])
        self.assertEqual(206, first['httpStatus'])
        self.assertFalse(first['accepted'])
        self.assertFalse(json.loads((reports / 'attempt-2.json').read_text())['accepted'])
        self.assertEqual(BODY, target.read_bytes())

    def test_persistent_full_size_corruption_is_never_admitted_or_re_pinned(self):
        corrupt = bytes([BODY[0] ^ 1]) + BODY[1:]
        target, reports, requests, result, error = self.run_download([Response(corrupt) for _ in range(3)])
        self.assertIsNone(result)
        self.assertIn('3 recorded attempts', str(error))
        self.assertFalse(target.exists())
        self.assertEqual([PIN['url']] * 3, requests)
        status = json.loads((reports / 'download.json').read_text())
        self.assertEqual('failed', status['status'])
        self.assertEqual(PIN, status['expected'])
        self.assertTrue(all(not row['accepted'] and row['observedFingerprint']['bytes'] == len(BODY)
                            and row['observedFingerprint']['sha512'] != PIN['sha512'] for row in status['attempts']))
        self.assertFalse(list(target.parent.glob('*.part')))

    def test_network_and_http_errors_preserve_observations_then_retry(self):
        http = urllib.error.HTTPError(PIN['url'], 503, 'temporarily unavailable',
                                     {'Content-Length': '4'}, io.BytesIO(b'busy'))
        target, reports, requests, _, error = self.run_download([
            urllib.error.URLError('connection closed'), http, Response()])
        self.assertIsNone(error)
        first = json.loads((reports / 'attempt-1.json').read_text())
        second = json.loads((reports / 'attempt-2.json').read_text())
        self.assertEqual('URLError', first['errorType'])
        self.assertIsNone(first['httpStatus'])
        self.assertEqual(503, second['httpStatus'])
        self.assertEqual(hashlib.sha256(b'busy').hexdigest(), second['observedFingerprint']['sha256'])
        self.assertEqual(3, len(requests))
        self.assertEqual(BODY, target.read_bytes())

    def test_unexpected_encoding_and_oversized_responses_are_rejected(self):
        target, reports, requests, _, error = self.run_download([
            Response(headers={'Content-Encoding': 'gzip'}), Response(BODY + b'extra'), Response()])
        self.assertIsNone(error)
        self.assertEqual(3, len(requests))
        second = json.loads((reports / 'attempt-2.json').read_text())
        self.assertEqual(len(BODY) + 1, second['observedFingerprint']['bytes'])
        self.assertFalse(second['responseBodyCompletelyRead'])
        self.assertFalse(second['accepted'])
        self.assertEqual(BODY, target.read_bytes())

    def test_invalid_pin_is_rejected_before_network_or_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for changed in (dict(PIN, url='http://example.test/original.tar.gz'),
                            dict(PIN, sha512='0' * 64), dict(PIN, bytes=True),
                            dict(PIN, url=PIN['url'] + '?replacement=1')):
                with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'static HTTPS'):
                    D.download_pinned(changed, directory / 'input', directory / 'reports',
                                      opener=lambda *_: self.fail('unexpected network request'))
            self.assertFalse((directory / 'reports').exists())


if __name__ == '__main__':
    unittest.main()
