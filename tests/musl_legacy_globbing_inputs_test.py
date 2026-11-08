"""Corrupt or oversized historical inputs must fail before ZIP parsing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tested_legacy_globbing', ROOT / 'scripts/musl_legacy_globbing_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class ImmutableHistoricalInputs(unittest.TestCase):
    def test_same_size_tampered_package_is_rejected_before_zip_or_pe_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'; path.write_bytes(b'X' * M.policy()['package']['bytes'])
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parser must not run')):
                with self.assertRaisesRegex(ValueError, 'Pinned Globbing input bytes differ'):
                    M.inspect_package(path)

    def test_oversized_package_is_rejected_before_reading_or_parsing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'; path.write_bytes(b'X' * (M.policy()['package']['bytes'] + 1))
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('ZIP parser must not run')):
                with self.assertRaisesRegex(ValueError, 'exact pinned Globbing input'):
                    M.inspect_package(path)


if __name__ == '__main__': unittest.main()
