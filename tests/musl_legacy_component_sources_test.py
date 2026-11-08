"""Keep checkout normalization confined to fresh corresponding sources."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('exact_corresponding_sources', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_component_sources.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class ExactGitSourceBoundary(unittest.TestCase):
    def fixture(self, base):
        source, clone = base / 'origin', base / 'corresponding'
        def git(*args): return subprocess.check_output(['git', *map(str, args)], stderr=subprocess.PIPE)
        git('init', source)
        (source / '.gitattributes').write_bytes(b'*.sln text eol=crlf\n')
        (source / 'Project.sln').write_bytes(b'original\nsolution\n')
        git('-C', source, 'add', '.'); git('-C', source, '-c', 'user.name=Source Test', '-c', 'user.email=source@example.invalid', 'commit', '-qm', 'Original source fixture')
        commit = git('-C', source, 'rev-parse', 'HEAD').decode().strip()
        git('clone', source, clone)
        self.assertEqual(b'original\r\nsolution\r\n', (clone / 'Project.sln').read_bytes())
        return dict(name='corresponding', kind='git', path=str(clone), expectedCommit=commit, role=M.ROLE)

    def test_fresh_corresponding_checkout_retains_literal_git_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = self.fixture(Path(temporary)); report = M.exact_git_bytes(row)
            self.assertEqual(b'original\nsolution\n', (Path(row['path']) / 'Project.sln').read_bytes())
            self.assertEqual(['Project.sln'], [v['path'] for v in report['changedCheckoutFiles']])
            self.assertEqual([], M.exact_git_bytes(row)['changedCheckoutFiles'])

    def test_build_source_role_is_rejected_before_changing_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = self.fixture(Path(temporary)); row['role'] = 'build-source'
            with self.assertRaisesRegex(ValueError, 'corresponding'): M.exact_git_bytes(row)
            self.assertEqual(b'original\r\nsolution\r\n', (Path(row['path']) / 'Project.sln').read_bytes())


if __name__ == '__main__': unittest.main()
