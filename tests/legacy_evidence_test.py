"""Reject legacy qualification evidence bound to another provider policy/CPU."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from downstream_release import validate_legacy_evidence
from legacy_compat import POLICY, PROVIDER_ROOT, FINGERPRINT


class LegacyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(sdkVersion='3.1.426', architecture=dict(public='aarch64'))
        self.proof = dict(status='passed', providerRoot=PROVIDER_ROOT, architecture='aarch64',
            policySha256=hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest(),
            signingFingerprint=FINGERPRINT, treeSha256='a' * 64)

    def test_all_three_legacy_families_accept_exact_current_native_provider_proofs(self):
        for version in ('3.0.103', '3.1.426', '5.0.214'):
            for arch in ('x64', 'aarch64'):
                plan = dict(sdkVersion=version, architecture=dict(public=arch))
                report = dict(compatibilityProvider=[dict(self.proof, architecture=arch, phase=phase)
                    for phase in ('after-install', 'after-runtime', 'after-upgrade', 'after-rollback', 'after-remove')])
                with self.subTest(version=version, architecture=arch):
                    validate_legacy_evidence(report, plan)

    def test_stale_provider_policy_root_key_cpu_status_or_tree_hash_is_rejected(self):
        for field, value in [('policySha256', 'f' * 64), ('providerRoot', '/usr/lib64'),
                ('signingFingerprint', 'B' * 40), ('architecture', 'x64'), ('status', 'not-run'),
                ('treeSha256', ''), ('treeSha256', 'not-a-sha256'), ('treeSha256', 'A' * 64)]:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'source, policy or native architecture'):
                validate_legacy_evidence(dict(compatibilityProvider=[dict(self.proof, **{field: value})]), self.plan)

    def test_every_retained_lifecycle_proof_must_have_the_same_current_policy(self):
        later = dict(self.proof, policySha256='f' * 64)
        with self.assertRaises(ValueError):
            validate_legacy_evidence(dict(compatibilityProvider=[self.proof, later]), self.plan)

    def test_missing_empty_or_partial_provider_evidence_is_rejected(self):
        for report in ({}, {'compatibilityProvider': None}, {'compatibilityProvider': []}, {'compatibilityProvider': self.proof}):
            with self.subTest(report=report), self.assertRaisesRegex(ValueError, 'lacks managed compatibility'):
                validate_legacy_evidence(report, self.plan)
        for field in self.proof:
            missing = copy.deepcopy(self.proof)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                validate_legacy_evidence(dict(compatibilityProvider=[missing]), self.plan)

    def test_modern_families_do_not_acquire_a_legacy_provider_requirement(self):
        for version in ('6.0.136', '7.0.120', '8.0.133', '9.0.123', '10.0.403'):
            with self.subTest(version=version):
                validate_legacy_evidence({}, dict(sdkVersion=version, architecture=dict(public='x64')))


if __name__ == '__main__':
    unittest.main()
