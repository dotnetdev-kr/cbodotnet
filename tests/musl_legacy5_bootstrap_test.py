import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_bootstrap_test', ROOT / 'scripts/musl_legacy5_bootstrap.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


class BootstrapInputs(unittest.TestCase):
    def test_authenticated_archive_keeps_the_exact_pin_and_actual_byte_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'original.tar.gz'; path.write_bytes(b'authenticated archive fixture')
            actual = B.fingerprint(path); expected = dict(version='5.0.401', rid='linux-musl-arm64', url='https://example.test/official', sha512=actual['sha512'])
            with patch.object(B, 'pin', return_value=expected):
                result = B.checked_archive(path, 'legacy5', 'aarch64')
            self.assertEqual(result, {**expected, **actual})
            expected['sha512'] = '0' * 128
            with patch.object(B, 'pin', return_value=expected), self.assertRaisesRegex(ValueError, 'exact native pin'):
                B.checked_archive(path, 'legacy5', 'aarch64')

    def test_explicit_bootstrap_roles_do_not_fall_back_to_another_sdk(self):
        self.assertEqual(B.pin('legacy5', 'aarch64')['version'], '5.0.401')
        self.assertEqual(B.pin('runtime', 'x64')['version'], '5.0.17')
        self.assertEqual(B.pin('vstest', 'aarch64')['version'], '6.0.135')
        with self.assertRaises(ValueError): B.pin('unknown', 'aarch64')
        with self.assertRaises(ValueError): B.pin('legacy5', 'emulated-arm')

    def test_unsafe_member_names_are_rejected_before_filesystem_operations(self):
        for name in ('../escape', 'a/../../escape', '/absolute', 'C:/drive', 'file:stream', 'a\\b', 'a//b', 'a/./b'):
            with self.subTest(name=name), self.assertRaises(ValueError): B.member_name(name)

    def archive(self, path, entries):
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, raw in entries:
                item = tarfile.TarInfo(name); item.type = kind; item.mode = 0o755
                if kind == tarfile.REGTYPE:
                    item.size = len(raw); archive.addfile(item, io.BytesIO(raw))
                else:
                    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): item.linkname = raw.decode()
                    archive.addfile(item)

    def test_original_modes_and_only_matching_framework_prefix_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / 'runtime.tar.gz'; destination = root / 'bootstrap'; destination.mkdir()
            self.archive(archive, [('./', tarfile.DIRTYPE, b''), ('shared/', tarfile.DIRTYPE, b''),
                ('shared/5.0.17/libcoreclr.so', tarfile.REGTYPE, b'official native'), ('dotnet', tarfile.REGTYPE, b'other root host')])
            rows = B.unpack(archive, destination, 'shared/5.0.17/')
            self.assertEqual(set(rows), {'shared/5.0.17/libcoreclr.so'})
            self.assertFalse((destination / 'dotnet').exists())
            self.assertEqual((destination / 'shared/5.0.17/libcoreclr.so').read_bytes(), b'official native')

    def test_links_devices_duplicate_and_escape_entries_are_rejected(self):
        for entries in [[('link', tarfile.SYMTYPE, b'../other')], [('link', tarfile.LNKTYPE, b'file')],
                        [('device', tarfile.CHRTYPE, b'')], [('file', tarfile.REGTYPE, b'one'), ('file', tarfile.REGTYPE, b'two')],
                        [('../outside', tarfile.REGTYPE, b'bad')]]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); archive = root / 'input.tar.gz'; destination = root / 'out'; destination.mkdir()
                self.archive(archive, entries)
                with self.assertRaises(ValueError): B.unpack(archive, destination)


if __name__ == '__main__': unittest.main()
