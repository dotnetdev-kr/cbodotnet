"""Reject unreviewed localization inputs and ambiguous source translations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('closed_msbuild_resources', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_msbuild_resources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class ResourceSourceBoundary(unittest.TestCase):
    def test_unreviewed_package_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unreviewed.nupkg'; path.write_bytes(b'PK\x03\x04')
            with self.assertRaisesRegex(ValueError, 'pinned'): M.inspect(path)

    def test_xml_entities_are_rejected(self):
        for raw in (b'<!DOCTYPE x [<!ENTITY translated "wrong">]><x>&translated;</x>',
                    b'<!ENTITY secret SYSTEM "file:///etc/passwd"><x/>'):
            with self.assertRaisesRegex(ValueError, 'entities'): M.xml(raw)

    def test_cross_project_and_cross_culture_substitution_are_rejected(self):
        for args in [('Microsoft.Build', 'Microsoft.Build.Tasks.Core.Strings.cs.resources', 'cs'),
                     ('Microsoft.Build', 'Microsoft.Build.Strings.de.resources', 'cs'),
                     ('MSBuild', 'MSBuild.Strings.ManifestUtilities.cs.resources', 'cs')]:
            with self.assertRaises(ValueError): M.source_path(*args)
        xlf = b'<xliff><file target-language="cs"><body><trans-unit id="A"><target>wrong</target></trans-unit></body></file></xliff>'
        with self.assertRaisesRegex(ValueError, 'own original'):
            M.compare_xlf([dict(strings=[dict(sourceXlf='Strings.cs.xlf', key='A', value='expected')])], {'Strings.cs.xlf': xlf})
        duplicate = xlf.replace(b'</body>', b'<trans-unit id="A"><target>again</target></trans-unit></body>')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.compare_xlf([], {'Strings.cs.xlf': duplicate})


if __name__ == '__main__': unittest.main()
