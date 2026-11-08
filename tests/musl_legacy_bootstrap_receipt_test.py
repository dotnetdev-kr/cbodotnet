"""The retained normal bootstrap must be the actual profile-pinned download."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_actual_bootstrap_tested', ROOT / 'scripts/musl_legacy_bootstrap_receipt.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class ActualBootstrapReceipt(unittest.TestCase):
    def fixture(self, root):
        work = root / 'sdk-build'; work.mkdir(); archive = work / 'bootstrap-sdk.tar.gz'; archive.write_bytes(b'actual pinned input bytes')
        profile = dict(sdkVersion='7.0.120', componentCommits=dict(sdk='a' * 40), bootstrap=dict(version='7.0.118',
            rid='linux-musl-arm64', url='https://builds.dotnet.microsoft.com/dotnet/Sdk/7.0.118/bootstrap.tar.gz', sha512=M.fingerprint(archive)['sha512']))
        prepared = dict(sdkVersion='7.0.120', rid='linux-musl-arm64', source=dict(repository='https://github.com/dotnet/sdk', commit='a' * 40),
            bootstrap=dict(path=str(archive.absolute()), url=profile['bootstrap']['url'], **M.fingerprint(archive)))
        (work / 'prepared.json').write_text(json.dumps(prepared)); return work, profile, prepared

    def test_actual_download_and_original_preparation_are_both_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work, profile, original = self.fixture(root); reports = root / 'reports/prepare'
            value = M.retain(work, profile, '7.0.120', 'linux-musl-arm64', reports)
            self.assertEqual(value, json.loads((reports / 'bootstrap.json').read_text()))
            self.assertEqual((work / 'prepared.json').read_bytes(), (reports / 'tooling-prepared.json').read_bytes())
            self.assertEqual(profile['bootstrap']['sha512'], value['sha512'])

    def test_mutated_actual_archive_is_rejected_before_receipt_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work, profile, original = self.fixture(root); (work / 'bootstrap-sdk.tar.gz').write_bytes(b'actual pinned input byteX')
            with self.assertRaisesRegex(ValueError, 'archive/profile identity differs'): M.retain(work, profile, '7.0.120', 'linux-musl-arm64', root / 'reports/prepare')
            self.assertFalse((root / 'reports/prepare/bootstrap.json').exists())

    def test_forged_url_rid_commit_and_hash_are_rejected(self):
        for field in ('url', 'rid', 'commit', 'sha512'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); work, profile, original = self.fixture(root)
                if field == 'url': original['bootstrap']['url'] = original['bootstrap']['url'].replace('7.0.118', '7.0.119')
                elif field == 'rid': original['rid'] = 'linux-musl-x64'
                elif field == 'commit': original['source']['commit'] = 'b' * 40
                else: original['bootstrap']['sha512'] = '0' * 128
                (work / 'prepared.json').write_text(json.dumps(original))
                with self.assertRaises(ValueError): M.retain(work, profile, '7.0.120', 'linux-musl-arm64', root / 'reports/prepare')

    def test_an_existing_receipt_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work, profile, original = self.fixture(root); reports = root / 'reports/prepare'; reports.mkdir(parents=True)
            (reports / 'bootstrap.json').write_text('previous')
            with self.assertRaisesRegex(ValueError, 'Fresh bootstrap preparation receipts'): M.retain(work, profile, '7.0.120', 'linux-musl-arm64', reports)
            self.assertEqual('previous', (reports / 'bootstrap.json').read_text())


if __name__ == '__main__': unittest.main()
