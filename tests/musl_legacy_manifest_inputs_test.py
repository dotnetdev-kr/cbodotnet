"""Constrain source-only manifest inputs and preserve literal source bytes."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('reviewed_manifest_inputs', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_manifest_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class ManifestSourceBoundary(unittest.TestCase):
    def test_json_comments_trailing_commas_and_url_strings(self):
        source = '{/* title */ "url":"https://example.test/a//b/*c*/", "items":[1,2,], // note\n}'
        self.assertEqual(dict(url='https://example.test/a//b/*c*/', items=[1, 2]), M.jsonc(source))

    def test_duplicate_keys_unterminated_comments_and_nonobjects_rejected(self):
        for text in ('{"a":1,"a":2}', '{/*', '{"a":"unfinished}', '[1,2]', '{"a":1,,}'):
            with self.subTest(text=text), self.assertRaises(ValueError): M.jsonc(text)
        for path in ('../input', '/input', 'C:/input', 'a\\b', 'a//b', 'a/./b'):
            with self.subTest(path=path), self.assertRaises(ValueError): M.portable(path)

    def test_reviewed_source_bytes_only_and_changed_package_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / 'input.nupkg'
            content = {'data/WorkloadManifest.json': b'{"version":"1","workloads":{},"packs":{}}',
                       'data/WorkloadManifest.targets': b'<Project><PropertyGroup/></Project>'}
            with zipfile.ZipFile(package, 'w') as archive:
                for name, raw in content.items(): archive.writestr(name, raw)
            row = dict(key='fixture', id='Manifest', fingerprint=M.fingerprint(package.read_bytes()),
                       entries=[dict(member=name, **M.fingerprint(raw)) for name, raw in content.items()])
            with mock.patch.object(M, 'policy', return_value=[row]):
                self.assertEqual(row, M.inspect(package))
                package.write_bytes(package.read_bytes() + b'changed-wrapper')
                with self.assertRaisesRegex(ValueError, 'Unreviewed'): M.inspect(package)

    def test_executable_and_xml_entities_are_rejected_even_if_listed(self):
        for content in ({'data/WorkloadManifest.targets': b'<!DOCTYPE Project [<!ENTITY a "x">]><Project/>'},
                        {'data/WorkloadManifest.targets': b'MZ executable'},
                        {'native.so': b'\x7fELF executable'}):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary) / 'input.nupkg'
                with zipfile.ZipFile(package, 'w') as archive:
                    for name, raw in content.items(): archive.writestr(name, raw)
                row = dict(fingerprint=M.fingerprint(package.read_bytes()),
                    entries=[dict(member=name, **M.fingerprint(raw)) for name, raw in content.items()])
                with mock.patch.object(M, 'policy', return_value=[row]), self.assertRaises(ValueError): M.inspect(package)


if __name__ == '__main__': unittest.main()
