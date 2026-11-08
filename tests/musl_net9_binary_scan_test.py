"""Check the NET9 absence-on-zero contract without accepting missing scans."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('net9_scan', Path(__file__).parents[1] / 'scripts/musl_net9_binary_scan.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class Net9OriginalScan(unittest.TestCase):
    def fixture(self, root):
        directory = root / 'reports/scan'; directory.mkdir(parents=True)
        command = ['docker', 'run', '--rm', '--network=none', '--user', '1001:1001', '--cap-drop=all', '--security-opt=no-new-privileges',
                   '--env', 'HOME=/home/build', '--volume', '/work/home:/home/build',
                   '--volume', '/work/clean:/clean:ro', '--volume', '/work/source:/vmr:ro',
                   '--volume', '/project:/project:ro', '--volume', '/output:/delivery', '--workdir', '/clean',
                   '--env', 'DOTNET_ROOT=/vmr/.dotnet', '--env', 'DOTNET_ROOT_ARM64=/vmr/.dotnet',
                   '--env', 'DOTNET_HOST_PATH=/vmr/.dotnet/dotnet',
                   '--volume', '/output/reports/diagnostics/container-0001:/diag',
                   '--env', 'MSBUILDDEBUGPATH=/diag', '--env', 'MSBUILDDEBUGCOMM=1',
                   '0' * 64, *M.observed_command()]
        source = root / 'source' / M.SOURCE_PATH; source.parent.mkdir(parents=True); source.write_bytes(b'pinned original source')
        expected = dict(bytes=source.stat().st_size, sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        (directory / 'scan.log').write_text("in Validate mode\nDetecting binaries in '/clean'\nFinished binary detection.\nFinished all binary tasks.\n" +
            '\n'.join('/delivery/reports/scan/' + name for name in M.UPDATED))
        for name in M.UPDATED: (directory / name).write_text('# actual updated policy\n')
        exit_path = root / 'reports/diagnostics/container-0001/exit-code.txt'; exit_path.parent.mkdir(parents=True); exit_path.write_bytes(b'0\n')
        return command, expected

    def test_clean_success_requires_absent_report_and_independent_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); command, source = self.fixture(root)
            with mock.patch.object(M, 'SOURCE', source):
                result = M.record(root, root / 'source', command, 0)
                self.assertFalse((root / 'reports/scan/NewBinaries.txt').exists())
                self.assertEqual(0, result['newBinariesReport']['detectedBinaries'])
                self.assertEqual(result, M.validate(root, [command], {M.SOURCE_PATH: dict(mode='100644', blob=M.SOURCE_BLOB)}))

    def test_new_report_even_empty_nonzero_and_missing_updated_are_rejected(self):
        for failure in ('new-binary', 'synthetic-empty', 'nonzero-argument', 'actual-nonzero', 'missing-updated', 'missing-log'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); command, source = self.fixture(root); code = 0
                if failure in ('new-binary', 'synthetic-empty'):
                    (root / 'reports/scan/NewBinaries.txt').write_text('unknown.dll\n' if failure == 'new-binary' else '')
                elif failure == 'nonzero-argument': code = 1
                elif failure == 'actual-nonzero': (root / 'reports/diagnostics/container-0001/exit-code.txt').write_text('1\n')
                elif failure == 'missing-updated': (root / 'reports/scan' / M.UPDATED[0]).unlink()
                else: (root / 'reports/scan/scan.log').unlink()
                with mock.patch.object(M, 'SOURCE', source), self.assertRaises(ValueError):
                    M.record(root, root / 'source', command, code)

    def test_fresh_output_source_and_invocation_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); command, source = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'fresh'): M.prepare(root)
            with self.assertRaisesRegex(ValueError, 'source differs'): M.record(root, root / 'source', command, 0)
            with mock.patch.object(M, 'SOURCE', source):
                for wrong in ([s.replace('--network=none', '--network=host') for s in command], command + ['--waive']):
                    with self.assertRaises(ValueError): M.record(root, root / 'source', wrong, 0)

    def test_safe_then_overriding_engine_options_are_rejected(self):
        overrides = [('--network=host',), ('--network', 'host'), ('--network=none',),
                     ('--volume', '/other:/clean'), ('--volume', '/other:/vmr'),
                     ('--volume', '/other:/clean/eng:ro'), ('--mount', 'type=bind,src=/x,dst=/clean'),
                     ('--cap-add=SYS_ADMIN',), ('--security-opt=seccomp=unconfined',),
                     ('--user', '0:0'), ('--env', 'DOTNET_ROOT=/other'), ('--workdir', '/other')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); command, source = self.fixture(root); image = command.index('0' * 64)
            with mock.patch.object(M, 'SOURCE', source):
                for options in overrides:
                    with self.subTest(options=options), self.assertRaises(ValueError):
                        M.record(root, root / 'source', command[:image] + list(options) + command[image:], 0)
                forged_wrapper = list(command); forged_wrapper[image + 3] = 'printf "0\\n" > /diag/exit-code.txt; exit 0'
                with self.assertRaisesRegex(ValueError, 'observed command'):
                    M.record(root, root / 'source', forged_wrapper, 0)

    def test_protected_consumer_rejects_forged_observation_source_and_duplicate_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); command, source = self.fixture(root)
            with mock.patch.object(M, 'SOURCE', source):
                M.record(root, root / 'source', command, 0)
                entries = {M.SOURCE_PATH: dict(mode='100644', blob=M.SOURCE_BLOB)}
                with self.assertRaises(ValueError): M.validate(root, [command, command], entries)
                with self.assertRaises(ValueError): M.validate(root, [command], {})
                receipt = root / 'reports/scan' / M.REPORT; changed = json.loads(receipt.read_text()); changed['exitCode'] = 1; receipt.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, 'observation differs'): M.validate(root, [command], entries)


if __name__ == '__main__': unittest.main()
