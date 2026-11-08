"""Reject executable input substitution and incomplete localization sources."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('sdk5_localization', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy5_msbuild_resources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class OriginalResourceSources(unittest.TestCase):
    values = {'A': dict(value='translated\r\nline')}
    xlf = b'<xliff><file target-language="de"><body><trans-unit id="A"><source>original</source><target>translated\nline</target></trans-unit></body></file></xliff>'
    resx = b'<root><data name="A"><value>original</value></data></root>'

    def test_original_target_allows_only_observed_crlf_translation(self):
        self.assertEqual(M.compare_resource(self.values, self.xlf, self.resx, 'de'), (0, 1))
        wrong = {'A': dict(value='changed text')}
        with self.assertRaisesRegex(ValueError, 'original XLF target'): M.compare_resource(wrong, self.xlf, self.resx, 'de')

    def test_xlf_source_must_equal_original_neutral_resx(self):
        with self.assertRaisesRegex(ValueError, 'neutral RESX'):
            M.compare_resource(self.values, self.xlf, self.resx.replace(b'original', b'changed'), 'de')

    def test_missing_extra_and_duplicate_source_keys_reject(self):
        for values in [{}, dict(self.values, B=dict(value='extra'))]:
            with self.assertRaisesRegex(ValueError, 'key sets'): M.compare_resource(values, self.xlf, self.resx, 'de')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.compare_resource(self.values, self.xlf.replace(b'</body>', b'<trans-unit id="A" /></body>'), self.resx, 'de')

    def test_foreign_culture_or_ambiguous_target_reject(self):
        with self.assertRaisesRegex(ValueError, 'culture'): M.compare_resource(self.values, self.xlf, self.resx, 'fr')
        with self.assertRaisesRegex(ValueError, 'unambiguous'):
            M.compare_resource(self.values, self.xlf.replace(b'</trans-unit>', b'<target>other</target></trans-unit>'), self.resx, 'de')

    def test_xml_entities_and_foreign_package_reject(self):
        with self.assertRaisesRegex(ValueError, 'entities'): M.xml(b'<!DOCTYPE x [<!ENTITY a "unsafe">]><x/>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'other.nupkg'; path.write_bytes(b'PK\x03\x04')
            with self.assertRaisesRegex(ValueError, 'Exact original SDK5'): M.inspect(path)

    def test_duplicate_neutral_resource_cannot_shadow_original_value(self):
        duplicate = self.resx.replace(b'</root>', b'<data name="A"><value>changed</value></data></root>')
        with self.assertRaisesRegex(ValueError, 'Unique original SDK5 neutral'):
            M.compare_resource(self.values, self.xlf, duplicate, 'de')


if __name__ == '__main__': unittest.main()
