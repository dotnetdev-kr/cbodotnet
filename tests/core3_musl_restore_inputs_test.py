"""Bound actual package caches and distinguish signed content from ZIP bytes."""
import base64
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import core3_musl_restore_inputs as C
import musl_nuget_content_hash as H


def package(names):
    stream = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(stream, 'w') as archive:
        warnings.simplefilter('ignore', UserWarning)
        for name in names:
            entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, name + '-original-data')
    return stream.getvalue()


class NugetContentHashBoundary(unittest.TestCase):
    def test_original_unsigned_and_three_signature_positions(self):
        original = package(['sample.nuspec', 'lib/sample.dll'])
        expected = base64.b64encode(hashlib.sha512(original).digest()).decode()
        self.assertEqual(expected, H.content_hash(original))
        for names in [['.signature.p7s', 'sample.nuspec', 'lib/sample.dll'],
                      ['sample.nuspec', '.signature.p7s', 'lib/sample.dll'],
                      ['sample.nuspec', 'lib/sample.dll', '.signature.p7s']]:
            with self.subTest(names=names):
                signed = package(names)
                self.assertNotEqual(hashlib.sha512(signed).digest(), hashlib.sha512(original).digest())
                self.assertEqual(expected, H.content_hash(signed))

    def test_ordinary_duplicate_names_are_hashed_without_extraction(self):
        raw = package(['sample.nuspec', 'packageIcon.png', 'packageIcon.png'])
        self.assertEqual(base64.b64encode(hashlib.sha512(raw).digest()).decode(), H.content_hash(raw))
        with self.assertRaisesRegex(ValueError, 'multiple signature'):
            H.content_hash(package(['sample.nuspec', '.signature.p7s', '.signature.p7s']))

    def test_truncation_local_header_and_zip64_are_rejected(self):
        raw = package(['sample.nuspec'])
        bad_local = bytearray(raw)
        bad_local[0] = 0
        zip64 = bytearray(raw)
        struct.pack_into('<H', zip64, len(zip64) - 12, 65535)
        for payload in [raw[:-1], raw[:20], bytes(bad_local), bytes(zip64), b'ELF']:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                H.content_hash(payload)


class ActualCacheBoundary(unittest.TestCase):
    def run_case(self, variant):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, output = root / 'work', root / 'output'
            work.mkdir()
            output.mkdir()
            libraries, folders = {}, []
            for index in range(2):
                cache = work / ('cache' + str(index))
                cache.mkdir()
                folders.append(str(cache) + '/')
                name = 'package' + str(index)
                payload = package([name + '.nuspec', '.signature.p7s'])
                path = cache / name / '1.0.0' / (name + '.1.0.0.nupkg')
                path.parent.mkdir(parents=True)
                path.write_bytes(payload)
                libraries[name + '/1.0.0'] = dict(type='package', path=name + '/1.0.0', sha512=H.content_hash(payload))
            if variant == 'forged-assets-hash':
                libraries['package0/1.0.0']['sha512'] = base64.b64encode(b'0' * 64).decode()
            elif variant == 'undeclared-cache':
                folders = folders[:1]
            elif variant == 'escape':
                libraries['package0/1.0.0']['path'] = '../cache0/package0/1.0.0'
            elif variant == 'outside-cache':
                folders.append(str(root) + '/')
            (work / 'project.assets.json').write_text(json.dumps(dict(packageFolders={path: {} for path in folders}, libraries=libraries)))
            return C.snapshot(work, output)

    def test_each_used_package_is_bound_to_its_declared_actual_cache(self):
        report = self.run_case('valid')
        self.assertEqual(['cache0', 'cache1'], report['cacheRoots'])
        self.assertEqual(2, len(report['usedPackageBindings']))
        self.assertEqual(2, len(report['packages']))
        self.assertFalse(report['qualification'])
        for row in report['usedPackageBindings']:
            self.assertEqual(row['assetsContentHash'], row['nugetContentHash'])
            self.assertNotEqual(base64.b64encode(bytes.fromhex(row['sha512'])).decode(), row['nugetContentHash'])

    def test_hash_forgery_missing_cache_and_path_escape_are_rejected(self):
        for variant in ['forged-assets-hash', 'undeclared-cache', 'escape', 'outside-cache']:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.run_case(variant)


if __name__ == '__main__':
    unittest.main()
