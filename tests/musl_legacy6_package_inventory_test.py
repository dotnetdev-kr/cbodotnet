"""The malformed-path exception cannot establish a shipping artifact."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_unindexed_symbols_tested', ROOT / 'scripts/musl_legacy6_package_inventory.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class UnindexedOriginalDebugInputs(unittest.TestCase):
    def test_wrong_size_input_is_rejected_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'; path.write_bytes(b'bad')
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('parser must not run')):
                with self.assertRaisesRegex(ValueError, 'Exact bounded original'): M.inspect(path, set())

    def test_same_size_modified_raw_container_is_rejected_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            with path.open('wb') as stream: stream.seek(M.policy()['package']['bytes'] - 1); stream.write(b'X')
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('parser must not run')):
                with self.assertRaisesRegex(ValueError, 'raw package differs'): M.inspect(path, set())

    def test_original_raw_package_or_any_excluded_member_cannot_fill_shipping_need(self):
        reviewed = M.policy()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            with path.open('wb') as stream: stream.seek(reviewed['package']['bytes'] - 1); stream.write(b'X')
            for needed in [M.SHA, *(r['sha256'] for r in reviewed['members'].values())]:
                with self.subTest(needed=needed), mock.patch.object(M, 'fingerprint', return_value=reviewed['package']), \
                        mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('parser must not run')):
                    with self.assertRaisesRegex(ValueError, 'cannot satisfy actual shipping origins'): M.inspect(path, {needed})


if __name__ == '__main__': unittest.main()
