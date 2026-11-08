import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_semantics5', ROOT / 'scripts/musl-legacy-runtime-semantics5.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class RuntimeSemanticsBoundaryTests(unittest.TestCase):
    def test_runtime_overrides_are_rejected(self):
        for key, value in [('COMPlus_ReadyToRun', '0'), ('DOTNET_ReadyToRun', '0'),
                           ('COMPlus_ZapDisable', '1'), ('COMPlus_TieredCompilation', '0'),
                           ('DOTNET_ROLL_FORWARD', 'Major'), ('COMPlus_GCStress', '1')]:
            with self.assertRaises(ValueError):
                M.validate_environment({key: value})

    def test_normal_runtime_environment_is_accepted(self):
        M.validate_environment({'HOME': '/home/build', 'COMPlus_ReadyToRun': '1',
                                'DOTNET_ROOT': '/candidate', 'DOTNET_MULTILEVEL_LOOKUP': '0',
                                'DOTNET_PROCESSOR_COUNT': '2', 'DOTNET_CLI_HOME': '/tmp/home'})

    def test_nonzero_and_timeout_cannot_be_positive(self):
        for code, timeout in [(1, False), (0, True), (124, True)]:
            with self.assertRaises(ValueError):
                M.check_case('lock', dict(exitCode=code, timedOut=timeout), M.CASES['lock'])

    def test_contended_count_is_required(self):
        for name in ['lock', 'spinlock', 'dictionary-same', 'dictionary-distinct']:
            with self.assertRaises(ValueError):
                M.check_case(name, dict(exitCode=0, timedOut=False), 'PASS ' + name)

    def test_all_actual_eh_clauses_are_required(self):
        positive = M.CASES['metadata'] + '\n' + '\n'.join('EH method' + str(i) for i in range(6))
        M.check_case('metadata', dict(exitCode=0, timedOut=False), positive)
        for count in [0, 1, 5, 7]:
            with self.assertRaises(ValueError):
                M.check_case('metadata', dict(exitCode=0, timedOut=False), M.CASES['metadata'] + '\n' + '\n'.join('EH method' for _ in range(count)))

    def archive(self, directory, rows):
        path = directory / 'candidate.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            for name, kind, body in rows:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(body)
                    stream.addfile(member, io.BytesIO(body))
                else:
                    member.linkname = body.decode()
                    stream.addfile(member)
        return path

    def test_only_safe_ordinary_archive_entries(self):
        for name, kind, body in [('../outside', tarfile.REGTYPE, b'bad'), ('/outside', tarfile.REGTYPE, b'bad'),
                                 ('linked', tarfile.SYMTYPE, b'outside'), ('linked', tarfile.LNKTYPE, b'dotnet'),
                                 ('pipe', tarfile.FIFOTYPE, b'')]:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with self.assertRaises(ValueError):
                    M.extract(self.archive(directory, [(name, kind, body)]), directory / 'sdk')
                self.assertFalse((directory / 'sdk').exists())

    def test_duplicate_archive_member_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(ValueError):
                M.extract(self.archive(directory, [('dotnet', tarfile.REGTYPE, b'one'), ('./dotnet', tarfile.REGTYPE, b'two')]), directory / 'sdk')
            self.assertFalse((directory / 'sdk').exists())

    def test_archive_preserves_actual_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            M.extract(self.archive(directory, [('sdk/source', tarfile.REGTYPE, b'actual\x00bytes')]), directory / 'extracted')
            self.assertEqual((directory / 'extracted/sdk/source').read_bytes(), b'actual\x00bytes')


if __name__ == '__main__': unittest.main()
