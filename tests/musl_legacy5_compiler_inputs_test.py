import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_legacy5_compiler_inputs as C


class CompilerInputBoundaries(unittest.TestCase):
    def test_member_rejects_traversal_and_windows_paths(self):
        for name in ('../a', 'a/../b', '/absolute', 'C:/a', 'a\\b', 'a//b', './a'):
            with self.subTest(name=name), self.assertRaises(ValueError): C.member(name)

    def test_official_sdk_is_pinned_before_archive_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'not-the-official-sdk.tar.gz'; path.write_bytes(b'untrusted')
            with self.assertRaisesRegex(ValueError, 'Exact official'): C.selected_sdk(path, 'aarch64')

    def test_unknown_architecture_is_not_accepted_as_portable(self):
        with self.assertRaises(ValueError): C.selected_sdk(Path('unused'), 'armv7')

    def test_embedded_commit_must_match_even_for_il(self):
        raw = bytearray(256); struct.pack_into('<I', raw, 0x3c, 64); struct.pack_into('<H', raw, 68, 0x14c)
        info = dict(cliFlags=1, managedNativeHeaderBytes=0, attributes={'System.Reflection.AssemblyInformationalVersionAttribute': ['wrong']})
        with patch.object(C.MANAGED, 'inspect', return_value=info), self.assertRaisesRegex(ValueError, 'source identity'):
            C.inspect_pe(bytes(raw), 'aarch64', 'correct')

    def test_r2r_foreign_architecture_rejected_before_header_use(self):
        raw = bytearray(256); struct.pack_into('<I', raw, 0x3c, 64); struct.pack_into('<H', raw, 68, 0x7b79 ^ 0x8664)
        info = dict(cliFlags=4, managedNativeHeaderBytes=124, attributes={})
        with patch.object(C.MANAGED, 'inspect', return_value=info), self.assertRaisesRegex(ValueError, 'architecture'):
            C.inspect_pe(bytes(raw), 'aarch64')

    def test_metadata_pair_order_preserves_pairs_duplicates_and_values(self):
        key = 'System.Reflection.AssemblyMetadataAttribute'; left = {'attributes': {key: ['A', '1', 'B', '2', 'A', '1']}}
        right = {'attributes': {key: ['B', '2', 'A', '1', 'A', '1']}}
        self.assertEqual(C.canonical_metadata(left), C.canonical_metadata(right))
        changed = copy.deepcopy(right); changed['attributes'][key][1] = 'different'
        self.assertNotEqual(C.canonical_metadata(left), C.canonical_metadata(changed))
        removed = {'attributes': {key: ['A', '1', 'B', '2']}}
        self.assertNotEqual(C.canonical_metadata(left), C.canonical_metadata(removed))
        with self.assertRaises(ValueError): C.canonical_metadata({'attributes': {key: ['A']}})

    def test_local_package_keeps_original_fsharp_dependency_contract(self):
        template = b'<package xmlns="http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd"><metadata><dependencies><group targetFramework="netcoreapp3.1"><dependency id="Original.Dependency" version="[1.0.0]"/></group></dependencies><contentFiles><files include="any/any/*" buildAction="None"/></contentFiles></metadata></package>'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); record = C.package('fsharp', {'tools/compiler.dll': b'fixture'}, {},
                {'original.nuspec': template}, {'LICENSE.txt': b'original license'}, directory)
            with zipfile.ZipFile(directory / record['package']['path']) as archive:
                origin = json.loads(archive.read('cbodotnet-provenance/origin.json'))
                self.assertFalse(origin['originalPublisherNupkg']); self.assertFalse(origin['compilerLocallySourceBuiltClaimed'])
                self.assertFalse(origin['sourceAdmissionAllowed']); self.assertIn(b'Original.Dependency', archive.read('Microsoft.FSharp.Compiler.nuspec'))
                self.assertEqual(archive.read('cbodotnet-provenance/original-definitions/original.nuspec'), template)


if __name__ == '__main__': unittest.main()
