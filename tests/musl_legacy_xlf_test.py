"""Keep original translated data literal and reject unsafe source XML."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tested_legacy_xlf', ROOT / 'scripts/musl_legacy_xlf.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class OriginalResourceData(unittest.TestCase):
    def fixture(self, root, changed=None):
        resources = root / 'src/Tool/Resources'; xlf = resources / 'xlf'; xlf.mkdir(parents=True)
        (resources / 'Text.resx').write_text('<root><resheader name="version"><value>2.0</value></resheader>'
            '<data name="Key"><value>Original</value></data></root>')
        for culture in M.CULTURES:
            body = ('<xliff xmlns="urn:oasis:names:tc:xliff:document:1.2"><file target-language="' + culture + '">'
                '<body><trans-unit id="Key"><source>Original</source><target>한글 é &amp; literal</target>'
                '</trans-unit></body></file></xliff>')
            if changed is not None and culture == 'ko': body = changed(body)
            (xlf / ('Text.' + culture + '.xlf')).write_text(body)

    def test_all_cultures_preserve_unicode_and_literal_target_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            report = M.generate(root, root / 'receipt.json', '1' * 40)
            self.assertEqual(13, len(report['rows']))
            for row in report['rows']:
                document = M.ET.parse(root / row['generated'])
                self.assertEqual('한글 é & literal', document.findtext('data/value'))
            self.assertFalse(json.loads((root / 'receipt.json').read_text())['englishFallbackGenerated'])

    def test_a_duplicate_translation_key_cannot_replace_original_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, lambda body: body.replace('</body>', '<trans-unit id="Key"><target>changed</target></trans-unit></body>'))
            with self.assertRaisesRegex(ValueError, 'Unique bounded'):
                M.generate(root, root / 'receipt.json', '1' * 40)
            self.assertFalse((root / 'receipt.json').exists())

    def test_entity_declarations_are_rejected_before_translation_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, lambda body: '<!DOCTYPE xliff [<!ENTITY x "expanded">]>' + body)
            with self.assertRaisesRegex(ValueError, 'document types or entities'):
                M.generate(root, root / 'receipt.json', '1' * 40)


if __name__ == '__main__': unittest.main()
