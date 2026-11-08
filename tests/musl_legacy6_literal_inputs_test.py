"""Closed SDK6 literal package, layout and transformation boundaries."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tested_sdk6_literals', ROOT / 'scripts/musl_legacy6_literal_inputs.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


class LiteralSixInputs(unittest.TestCase):
    def test_closed_four_packages_cover_exact_layout_and_source_matrix(self):
        p = L.policy()
        self.assertEqual(4, len(p['packages']))
        self.assertEqual(128, len(p['products']))
        self.assertEqual(124, sum(n.startswith('packs/NETStandard.Library.Ref/2.1.0/') for n in p['products']))
        self.assertEqual(387, sum(len(r['literalMembers']) for r in p['packages'].values()))
        self.assertEqual(500, sum(len(r['files']) for r in p['sources'].values()))
        self.assertFalse(p['sourceCompileEqualityClaimed'])
        self.assertFalse(p['templateExecutionQualified'])
        self.assertFalse(p['emscriptenWorkloadQualified'])

    def test_unknown_package_has_no_repository_metadata_fallback(self):
        self.assertIsNone(L.package_origin(Path('absent.nupkg'), '0' * 64))

    def test_same_declared_identity_with_different_package_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'NETStandard.Library.Ref.2.1.0.nupkg'
            package.write_bytes(b'untrusted same-version package')
            with self.assertRaisesRegex(ValueError, 'Exact original SDK6 literal package'):
                L.package_origin(package, next(iter(L.policy()['packages'])))

    def test_whole_templates_remain_packages_and_cannot_become_sdk_assemblies(self):
        rows = [(n, r) for n, r in L.policy()['products'].items() if n.startswith('templates/')]
        self.assertEqual(2, len(rows))
        self.assertTrue(all(r['member'] is None and n.endswith('.nupkg') for n, r in rows))
        for name, row in rows:
            self.assertFalse(L.declared_product('sdk/6.0.136/unknown.dll', row['packageSha256'], None, b'untrusted'))
            self.assertFalse(L.declared_product(name, row['packageSha256'], '', b'untrusted'))

    def test_other_sdk_layout_and_unreviewed_members_are_rejected(self):
        name, row = next(iter(L.policy()['products'].items()))
        self.assertFalse(L.declared_product(name.replace('6.0.100', '7.0.100'), '0' * 64, row['member'], b'untrusted'))
        self.assertFalse(L.declared_product(name, row['packageSha256'], '../escape', b'untrusted'))
        with self.assertRaisesRegex(ValueError, 'SDK6-only'):
            L.validate(Path('absent'), {'sdkVersion': '7.0.120'}, {})

    def test_only_explicit_present_placeholders_and_line_endings_are_transformed(self):
        rule = dict(replacements={'Version': '6.0.36'}, transform='lf-to-crlf')
        self.assertEqual(b'6.0.36\r\n', L._literal(b'${Version}\n', rule))
        for raw in (b'${Other}\n', b'no placeholder\n'):
            with self.assertRaisesRegex(ValueError, 'original template placeholders'):
                L._literal(raw, rule)
        with self.assertRaisesRegex(ValueError, 'remains unresolved'):
            L._literal(b'${Version}${Other}', rule)
        self.assertEqual(b'const value = `${name}`;',
                         L._literal(b'const value = `${name}`;', dict(replacements={}, transform='identity')))
        with self.assertRaisesRegex(ValueError, 'Unreviewed literal'):
            L._literal(b'ordinary', dict(replacements={}, transform='rewrite'))

    def test_source_archive_paths_cannot_escape_or_alias(self):
        for name in ('/absolute', '../escape', 'a/../b', 'a\\b', 'a//b', 'a/./b', 'C:/source'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                L.portable(name)


if __name__ == '__main__':
    unittest.main()
