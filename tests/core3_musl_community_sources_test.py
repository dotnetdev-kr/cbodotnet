import argparse
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('community_sources', ROOT / 'scripts/core3_musl_community_sources.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class CommunitySourcesTest(unittest.TestCase):
    def test_archive_tamper_rejected_before_directories_are_created(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / 'changed-source.tar.gz'
            bad.write_bytes(b'changed source archive')
            args = argparse.Namespace(component='cli31', official_build_id='20261108.1',
                                      source_archive=bad, source_build_archive=bad,
                                      work_dir=root / 'work', output_dir=root / 'evidence')
            with self.assertRaisesRegex(ValueError, 'input SHA256 differs'):
                M.prepare(args)
            self.assertFalse(args.work_dir.exists())
            self.assertFalse(args.output_dir.exists())

    def test_length_is_checked_even_when_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'original')
            with self.assertRaisesRegex(ValueError, 'input length differs'):
                M.checked(path, dict(sha256=hashlib.sha256(b'original').hexdigest(), bytes=9))

    def test_malformed_official_id_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(component='fsharp31', official_build_id='old-publisher-version',
                                      work_dir=root / 'work', output_dir=root / 'evidence')
            with self.assertRaisesRegex(ValueError, 'OfficialBuildId'):
                M.prepare(args)
            self.assertEqual(list(root.iterdir()), [])

    def test_work_cannot_contain_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(component='cli31', official_build_id='20261108.1',
                                      work_dir=root / 'work', output_dir=root / 'work/evidence')
            with self.assertRaisesRegex(ValueError, 'must be separate'):
                M.prepare(args)
            self.assertEqual(list(root.iterdir()), [])

    def test_existing_work_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / 'work'
            work.mkdir()
            sentinel = work / 'existing'
            sentinel.write_text('preserve')
            args = argparse.Namespace(component='cli31', official_build_id='20261108.1',
                                      work_dir=work, output_dir=root / 'evidence')
            with self.assertRaisesRegex(ValueError, 'use new'):
                M.prepare(args)
            self.assertEqual(sentinel.read_text(), 'preserve')
            self.assertFalse(args.output_dir.exists())


if __name__ == '__main__':
    unittest.main()
