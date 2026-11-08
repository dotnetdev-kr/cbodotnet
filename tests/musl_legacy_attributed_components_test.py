"""Missing embedded identities must not become generic source inference."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('closed_component_inputs', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_attributed_components.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


class ClosedComponentSources(unittest.TestCase):
    def test_actual_container_selection_requires_one_closed_variant(self):
        original = set(C.policy()['packages'])
        selected = C.selected_packages(original)
        self.assertEqual(selected[C.ILLINK_CANONICAL], C.ILLINK_CANONICAL)
        signed = original - {C.ILLINK_CANONICAL} | {C.ILLINK_SIGNED}
        self.assertEqual(C.selected_packages(signed)[C.ILLINK_CANONICAL], C.ILLINK_SIGNED)
        for invalid in [original | {C.ILLINK_SIGNED}, original - {C.ILLINK_CANONICAL},
                        original - {C.ILLINK_CANONICAL} | {'0' * 64}]:
            with self.subTest(available=invalid), self.assertRaisesRegex(ValueError, 'unambiguous actual'):
                C.selected_packages(invalid)

    def test_signature_variant_does_not_relax_product_member_or_bytes(self):
        name, row = next((name, row) for name, row in C.policy()['products'].items()
                         if row['packageSha256'] == C.ILLINK_CANONICAL)
        with mock.patch.object(C, 'module', side_effect=AssertionError('Untrusted bytes reached metadata reader')):
            for sha, member in [(C.ILLINK_SIGNED, row['packageMember']),
                                (C.ILLINK_SIGNED, 'tools/another/member.dll'), ('0' * 64, row['packageMember'])]:
                with self.subTest(sha=sha, member=member), self.assertRaisesRegex(ValueError, 'path/package/member'):
                    C.declared_product(name, sha, member, b'MZuntrusted')

    def test_variant_corruption_rejects_before_zip_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'changed-signature.nupkg'; path.write_bytes(b'PKchanged-signature')
            with mock.patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('Unpinned ZIP was parsed')):
                with self.assertRaisesRegex(ValueError, 'exact component package'):
                    C.inspect_package(path, C.ILLINK_SIGNED)

    def test_named_component_cannot_substitute_another_package_or_payload(self):
        for name, row in C.policy()['products'].items():
            with self.subTest(name=name), mock.patch.object(C, 'module', side_effect=AssertionError('Untrusted bytes reached metadata reader')):
                with self.assertRaisesRegex(ValueError, 'path/package/member'):
                    C.declared_product(name, '0' * 64, row['packageMember'], b'MZuntrusted')
                with self.assertRaisesRegex(ValueError, 'path/package/member'):
                    C.declared_product(name, row['packageSha256'], row['packageMember'], b'MZuntrusted')

    def test_corrupt_primary_package_rejects_before_zip_or_code_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'untrusted.nupkg'; path.write_bytes(b'PKfake')
            with mock.patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('Unpinned ZIP was parsed')):
                for sha in C.policy()['packages']:
                    with self.assertRaisesRegex(ValueError, 'exact component package'):
                        C.inspect_package(path, sha)

    def test_canonical_comparison_cannot_accept_an_arbitrary_original_version(self):
        with mock.patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('Unpinned ZIP was parsed')):
            with self.assertRaisesRegex(ValueError, 'Exact original Unsafe package'):
                C.inspect_canonical_unsafe(b'PKversion5-is-not-an-identity')


if __name__ == '__main__': unittest.main()
