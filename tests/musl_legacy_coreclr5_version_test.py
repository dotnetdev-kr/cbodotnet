"""Generated metadata alone must not admit fallback-version native binaries."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native5_version_worker', ROOT / 'scripts/musl-legacy-coreclr5.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class CompiledVersion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.version = '5.0.1726.55803'
        self.marker = '@(#)Version ' + self.version + ' @Commit: ' + M.COMMIT
        self.produced, self.compiled = base / '_version.c', base / 'version.c'
        self.header, self.actual_header = base / 'runtime_version.h', base / 'compiled-runtime_version.h'
        for path in (self.produced, self.compiled):
            path.write_text('static char sccsid[] = "' + self.marker + '";\n')
        for path in (self.header, self.actual_header):
            path.write_text('#define RuntimeProductVersion 5.0.17\n')
        self.commands = [{'file': str(self.compiled), 'command': 'clang -O3 -c ' + str(self.compiled)}]

    def check(self):
        return M.version_inputs(self.produced, self.compiled, self.header,
                                self.actual_header, self.commands, self.version)

    def test_real_compiler_input_and_elf_must_both_match(self):
        self.assertEqual(self.check()[0], self.marker)
        self.assertEqual(M.elf_version(b'ELF\0' + self.marker.encode() + b'\0', self.marker)['occurrences'], 1)

    def test_correct_first_header_cannot_hide_second_producer_fallback(self):
        self.compiled.write_text('static char sccsid[] = "@(#)Version 42.42.42.42424 @Commit: ' + M.COMMIT + '";\n')
        with self.assertRaisesRegex(ValueError, 'actual compiled native version source'):
            self.check()

    def test_changed_actual_header_is_rejected(self):
        self.actual_header.write_text('#define RuntimeProductVersion 42.42.42\n')
        with self.assertRaisesRegex(ValueError, 'actual CMake runtime header'):
            self.check()

    def test_compiler_database_must_reference_the_actual_source(self):
        self.commands[0]['file'] = str(self.produced)
        with self.assertRaisesRegex(ValueError, 'compiler database'):
            self.check()

    def test_missing_fallback_or_mixed_elf_versions_are_rejected(self):
        fallback = b'@(#)Version 42.42.42.42424 @Commit: ' + M.COMMIT.encode()
        for data in (b'ELF\0', b'ELF\0' + fallback + b'\0', self.marker.encode() + b'\0' + fallback + b'\0'):
            with self.subTest(data=data[:50]), self.assertRaisesRegex(ValueError, 'Native ELF dated version'):
                M.elf_version(data, self.marker)


if __name__ == '__main__':
    unittest.main()
