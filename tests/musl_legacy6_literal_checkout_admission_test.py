import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('sdk6_checkout_admission_controls', ROOT / 'scripts/musl_legacy6_admission.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


class RequiredCheckoutProofTests(unittest.TestCase):
    def baseline(self):
        closed = A.LITERAL.checkout_policy()
        return dict(kind='sdk6-original-literal-input-source-chains',
            publisherCheckoutRepresentations=dict(kind='sdk6-closed-original-publisher-checkout-representations',
                policySha256=A.LITERAL.CHECKOUT_POLICY_SHA, sourceCommit=closed['commit'], sourceTree=closed['tree'],
                attribute={key: closed['attribute'][key] for key in ('path', 'gitBlob', 'fingerprint', 'mode')},
                acceptedRepresentations={name: {key: row[key] for key in ('fingerprint', 'rawGitBlob', 'canonicalGitBlob', 'mode')}
                    for name, row in closed['representations'].items()},
                completeOriginalSourceFiles=24722, originalSourceAnchors=500,
                sourceFilesRewritten=False, genericEolAcceptanceAllowed=False,
                qualificationAllowed=False, sourceAdmissionAllowed=False))

    def test_full_current_checkout_proof_is_bound(self):
        value = self.baseline()
        self.assertEqual(A.validate_literal_checkout_proof(value), value['publisherCheckoutRepresentations'])

    def test_canonical_original_git_inputs_need_no_checkout_alternative(self):
        value = self.baseline()
        value['publisherCheckoutRepresentations']['acceptedRepresentations'] = {}
        A.validate_literal_checkout_proof(value)

    def test_legacy_result_label_alone_is_rejected(self):
        with self.assertRaises(ValueError):
            A.validate_literal_checkout_proof(dict(kind='sdk6-original-literal-input-source-chains'))

    def test_source_policy_attribute_and_counts_cannot_be_substituted(self):
        changes = [('kind', 'legacy'), ('policySha256', '0' * 64), ('sourceCommit', '0' * 40),
            ('sourceTree', '0' * 40), ('attribute', {}), ('completeOriginalSourceFiles', 24721),
            ('originalSourceAnchors', 499), ('sourceFilesRewritten', True),
            ('genericEolAcceptanceAllowed', True), ('qualificationAllowed', True), ('sourceAdmissionAllowed', True)]
        for key, replacement in changes:
            with self.subTest(key=key):
                value = self.baseline()
                value['publisherCheckoutRepresentations'][key] = replacement
                with self.assertRaises(ValueError):
                    A.validate_literal_checkout_proof(value)

    def test_unlisted_path_and_rehashed_content_are_rejected(self):
        value = self.baseline()
        rows = value['publisherCheckoutRepresentations']['acceptedRepresentations']
        row = next(iter(rows.values()))
        rows['outside.css'] = copy.deepcopy(row)
        with self.assertRaises(ValueError):
            A.validate_literal_checkout_proof(value)
        for key, replacement in [('mode', '100755'), ('rawGitBlob', '0' * 40),
                ('canonicalGitBlob', '0' * 40), ('fingerprint', {})]:
            with self.subTest(key=key):
                value = self.baseline()
                next(iter(value['publisherCheckoutRepresentations']['acceptedRepresentations'].values()))[key] = replacement
                with self.assertRaises(ValueError):
                    A.validate_literal_checkout_proof(value)


if __name__ == '__main__':
    unittest.main()
