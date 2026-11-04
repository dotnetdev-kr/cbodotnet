"""Historical publication reads retain old trust without granting new promotion."""
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import downstream_release as RELEASE


class SigningHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.paths = [Path(self.temporary.name) / name for name in ('manifest.json', 'manifest.sig', 'keyring.gpg')]
        for path in self.paths:
            path.write_bytes(b'fixture')
        self.fingerprint = 'A' * 40
        self.workflow = '.github/workflows/distribution-release.yml'
        self.signer = dict(state='retired', notBefore='2020-01-01T00:00:00Z',
                           notAfter='2025-01-01T00:00:00Z', workflow=self.workflow)
        self.policy = {'evidenceSigners': {self.fingerprint: self.signer}}
        self.signed_at = int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp())
        self.now = datetime(2026, 11, 4, tzinfo=timezone.utc)

    def verify(self, *, historical=True, timestamp=None, expires=0, digest='8', status='', code=0, valid=True):
        timestamp = self.signed_at if timestamp is None else timestamp
        line = ('[GNUPG:] VALIDSIG ' + self.fingerprint + ' 2024-01-01 ' + str(timestamp)
                + ' ' + str(expires) + ' 4 0 22 ' + digest + ' 00 ' + self.fingerprint + '\n') if valid else ''
        result = subprocess.CompletedProcess([], code, stdout=line + status, stderr='')
        with mock.patch.object(RELEASE.subprocess, 'run', return_value=result), \
                mock.patch.object(RELEASE, 'datetime') as clock:
            clock.now.return_value = self.now
            clock.fromisoformat.side_effect = datetime.fromisoformat
            clock.fromtimestamp.side_effect = datetime.fromtimestamp
            return RELEASE.verify_report_signature(*self.paths, self.policy, self.workflow, historical=historical)

    def test_retired_signature_inside_original_trust_window_remains_readable(self):
        self.assertEqual(self.fingerprint, self.verify())
        with self.assertRaisesRegex(ValueError, 'not active'):
            self.verify(historical=False)

    def test_expired_current_trust_window_is_allowed_only_for_historical_reads(self):
        self.signer['state'] = 'active'
        self.assertEqual(self.fingerprint, self.verify())
        with self.assertRaisesRegex(ValueError, 'not active'):
            self.verify(historical=False)

    def test_before_or_after_original_trust_window_and_future_times_are_rejected(self):
        for value in (self.signed_at - 10 * 365 * 86400,
                      int(datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp()),
                      int(self.now.timestamp()) + 1):
            with self.subTest(timestamp=value), self.assertRaises(ValueError):
                self.verify(timestamp=value)

    def test_revocation_and_invalid_signature_never_get_historical_exception(self):
        for state in ('revoked', 'unknown', None):
            self.signer['state'] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.verify()
        self.signer['state'] = 'retired'
        for status in ('REVKEYSIG', 'KEYREVOKED', 'BADSIG', 'ERRSIG'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.verify(status='[GNUPG:] ' + status + ' unknown\n')
        for kwargs in ({'code': 1}, {'valid': False}, {'digest': '2'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.verify(**kwargs)

    def test_expiry_is_assessed_at_signed_creation_time_for_historical_reads(self):
        expiry = self.signed_at + 86400
        self.assertEqual(self.fingerprint, self.verify(expires=expiry, status='[GNUPG:] EXPSIG old-signature\n'))
        self.assertEqual(self.fingerprint, self.verify(status='[GNUPG:] KEYEXPIRED ' + str(expiry) + '\n'))
        for kwargs in ({'expires': self.signed_at}, {'expires': self.signed_at - 1},
                       {'status': '[GNUPG:] KEYEXPIRED ' + str(self.signed_at - 1) + '\n'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.verify(**kwargs)

    def test_workflow_authority_and_verified_timestamp_format_remain_required(self):
        self.signer['workflow'] = '.github/workflows/untrusted.yml'
        with self.assertRaises(ValueError):
            self.verify()
        self.signer['workflow'] = self.workflow
        for value in ('attacker-passed-time', '-1', '9' * 100):
            with self.subTest(timestamp=value), self.assertRaises(ValueError):
                self.verify(timestamp=value)


if __name__ == '__main__':
    unittest.main()
