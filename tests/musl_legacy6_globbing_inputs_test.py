"""The SDK6 historical exception must reject unreviewed input before parsing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_globbing_tested', ROOT / 'scripts/musl_legacy6_globbing_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class OriginalSDK6Inputs(unittest.TestCase):
    def test_same_size_corruption_fails_before_zip_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            path.write_bytes(b'X' * M.policy()['package']['bytes'])
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('no parser')):
                with self.assertRaisesRegex(ValueError, 'Exact original SDK6 Globbing package required'):
                    M.inspect_package(path)

    def test_oversize_fails_before_package_read(self):
        reviewed = M.policy()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            path.write_bytes(b'X' * (reviewed['package']['bytes'] + 1))
            with mock.patch.object(M, 'policy', return_value=reviewed), \
                    mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('no package read')):
                with self.assertRaisesRegex(ValueError, 'package size required'):
                    M.inspect_package(path)

    def test_source_data_path_cannot_escape_or_use_windows_separators(self):
        for name in ('../source', '/source', 'a/../b', 'a//b', 'a\\b', 'x\nsource'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.portable(name)

    def test_consumer_is_bounded_before_zip_loading(self):
        with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('no parser')):
            with self.assertRaisesRegex(ValueError, 'Bounded genuine SDK6 VSTest source package required'):
                M.inspect_consumer(b'X' * (32 * 1024**2 + 1), b'')


if __name__ == '__main__': unittest.main()
