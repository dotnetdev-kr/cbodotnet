"""Fresh SDK5 source-mode choices before any compiler runs."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sdk5_producer_checkout', ROOT / 'scripts/musl_legacy_sdk5.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class FreshCheckoutModes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'source'
        self.source.mkdir()
        self.git('init', '-q')

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=SDK5 Fixture',
            '-c', 'user.email=sdk5-fixture@example.invalid', '-c', 'core.autocrlf=false',
            '-C', str(self.source), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def fixture(self, names):
        (self.source / '.gitattributes').write_bytes(b'*.cmd text eol=crlf\n*.bat text eol=crlf\n*.sln text eol=crlf\n*.props text eol=crlf\n*.cpp text eol=crlf\n')
        for name in names: (self.source / name).write_bytes(b'original first\noriginal second\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'original source rules')
        commit = self.git('rev-parse', 'HEAD')
        checkout = self.source.parent / 'fresh-checkout'
        subprocess.run(['git', 'clone', '-q', '--no-hardlinks', str(self.source), str(checkout)], check=True)
        self.source = checkout
        return commit

    def test_runtime_preserves_declared_original_windows_checkout(self):
        commit = self.fixture(['build.cmd', 'test.bat', 'project.sln'])
        before = {p.name: p.read_bytes() for p in self.source.iterdir() if p.is_file()}
        result = S.materialize_original_checkout(self.source, commit, preserve_windows=True)
        self.assertEqual(len(result['originalWindowsCheckout']), 3)
        self.assertEqual(result['canonicalized'], [])
        self.assertEqual({p.name: p.read_bytes() for p in self.source.iterdir() if p.is_file()}, before)
        self.assertEqual(self.git('status', '--porcelain', '--untracked-files=no'), '')

    def test_canonical_component_mode_preserves_its_reviewed_raw_git_contract(self):
        commit = self.fixture(['input.props'])
        result = S.materialize_original_checkout(self.source, commit)
        self.assertEqual(len(result['canonicalized']), 1)
        self.assertEqual(result['originalWindowsCheckout'], [])
        self.assertEqual((self.source / 'input.props').read_bytes(), b'original first\noriginal second\n')

    def test_runtime_never_transforms_compiler_source_even_with_crlf_attributes(self):
        commit = self.fixture(['implementation.cpp'])
        with self.assertRaisesRegex(ValueError, 'restricted to declared original Windows'):
            S.materialize_original_checkout(self.source, commit, preserve_windows=True)

    def test_windows_checkout_edit_or_undeclared_transform_is_rejected(self):
        commit = self.fixture(['build.cmd'])
        (self.source / 'build.cmd').write_bytes(b'edited first\r\noriginal second\r\n')
        with self.assertRaisesRegex(ValueError, 'more than original line endings'):
            S.materialize_original_checkout(self.source, commit, preserve_windows=True)
        (self.source / 'build.cmd').write_bytes(b'original first\r\noriginal second\r\n')
        (self.source / '.gitattributes').write_bytes(b'*.cmd text eol=lf\n')
        with self.assertRaises(ValueError):
            S.materialize_original_checkout(self.source, commit, preserve_windows=True)


if __name__ == '__main__': unittest.main()
