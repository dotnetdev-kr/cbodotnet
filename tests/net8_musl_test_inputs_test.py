"""Original NET8 RID parsing and exact native test fixture boundaries."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('net8_native_test_inputs_tested', ROOT / 'scripts/prepare-net8-musl-tests.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('net8_original_collector_tested', ROOT / 'scripts/collect-artifacts.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
SPEC = importlib.util.spec_from_file_location('modern_failed_tests_tested', ROOT / 'scripts/musl-modern-sdk.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class NativeTestInputs(unittest.TestCase):
    def test_exact_original_parser_changes_only_the_architecture_component(self):
        original = (ROOT / 'tests/fixtures/net8-musl-tests/Config.cs').read_bytes()
        self.assertEqual(N.ORIGINAL_SHA, hashlib.sha256(original).hexdigest())
        adjusted = N.patched(original)
        self.assertEqual(original, adjusted.replace(N.NEW.encode(), N.OLD.encode()))
        for rid, expected in [('linux-musl-arm64', 'arm64'), ('linux-musl-x64', 'x64'), ('linux-arm64', 'arm64')]:
            self.assertEqual(expected, rid.split('-')[-1])
        for changed in [original + b' ', original.replace(b"[1]", b"[0]"), adjusted]:
            with self.assertRaisesRegex(ValueError, 'Unknown original'):
                N.patched(changed)

    def test_only_reviewed_native_fixture_architectures_are_allowed(self):
        for arch, expected in [('aarch64', 'arm64'), ('x64', 'x64')]:
            row = N.fixture(arch)
            self.assertIn('/v1.39.14/omnisharp-linux-musl-' + expected + '-net6.0.tar.gz', row['url'])
            self.assertEqual(64, len(row['sha256']))
            self.assertGreater(row['bytes'], 40 * 1024**2)
        with self.assertRaises(KeyError):
            N.fixture('musl')

    def test_original_net8_artifact_layout_rejects_vmr9_and_wrong_libc_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            other = root / 'artifacts/assets/Release/Sdk/dotnet-sdk-8.0.133-linux-musl-arm64.tar.gz'
            other.parent.mkdir(parents=True)
            other.write_bytes(b'wrong-layout')
            with self.assertRaises(C.CollectionError):
                C.select_sdk(root, '8.0.133', 'linux-musl-arm64', legacy=True, exact_name=True)
            correct = root / 'artifacts/arm64/Release/dotnet-sdk-8.0.133-linux-musl-arm64.tar.gz'
            correct.parent.mkdir(parents=True)
            wrong = correct.with_name('dotnet-sdk-8.0.133-linux-arm64.tar.gz')
            wrong.write_bytes(b'wrong-libc')
            with self.assertRaises(C.CollectionError):
                C.select_sdk(root, '8.0.133', 'linux-musl-arm64', legacy=True, exact_name=True)
            correct.write_bytes(b'exact-original-output')
            selected, records, base = C.select_sdk(root, '8.0.133', 'linux-musl-arm64', legacy=True, exact_name=True)
            self.assertEqual(correct, selected)
            self.assertEqual(correct.parent, base)
            self.assertEqual(hashlib.sha256(correct.read_bytes()).hexdigest(), records[0]['sha256'])

    def test_failed_original_tests_retain_the_sdk_and_preserve_the_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer = M.Producer.__new__(M.Producer)
            producer.sdk = '9.0.123'
            producer.args = SimpleNamespace(arch='aarch64')
            producer.route = dict(sourceOnly=False, source='9f04b57d1366e21b3178648493d6edffeff2216e')
            producer.source = root / 'source'
            producer.reports = root / 'reports'
            (producer.reports / 'test').mkdir(parents=True)
            producer.id = dict(rid='linux-musl-arm64')
            producer.image = 'actual-image-id'
            archive = producer.source / 'artifacts/assets/Release/Sdk/dotnet-sdk-9.0.123-linux-musl-arm64.tar.gz'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'unchanged-build-output')
            trx = producer.source / 'artifacts/TestResults/Release/original.trx'
            trx.parent.mkdir(parents=True)
            trx.write_text('<original-test-failure/>')
            producer.build_command = mock.Mock(return_value=['original-test-command'])
            producer.container = mock.Mock(side_effect=[None, RuntimeError('original failure')])
            with self.assertRaisesRegex(RuntimeError, '^original failure$'):
                producer.test()
            self.assertEqual(archive.read_bytes(), (producer.reports / 'test/failure/sdk.tar.gz').read_bytes())
            self.assertEqual(trx.read_bytes(), (producer.reports / 'test/common.trx').read_bytes())
            receipt = M.load_json(producer.reports / 'test/failure/sdk.json')
            self.assertFalse(receipt['qualificationAllowed'])
            self.assertFalse(receipt['sourceAdmissionAllowed'])
            self.assertFalse(receipt['releasePublished'])
            self.assertFalse((root / 'producer-validation.json').exists())


if __name__ == '__main__':
    unittest.main()
