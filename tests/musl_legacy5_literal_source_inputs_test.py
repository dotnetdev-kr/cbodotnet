"""Boundaries for the five original SDK5 non-Git package roles."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('sdk5_literal_source_tested', ROOT / 'scripts/musl_legacy5_literal_source_inputs.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
P = M.module('sdk5_literal_fixture_git', 'package-used-source.py')
B = M.module('sdk5_literal_fixture_bytes', 'musl_legacy_admission.py')


class OriginalPackageBoundary(unittest.TestCase):
    def test_policy_authenticates_before_json_parse(self):
        with mock.patch.object(M.Path, 'read_bytes', return_value=b'{}'), \
                mock.patch.object(M.json, 'loads', side_effect=AssertionError('Untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError, 'policy differs'):
                M.policy()

    def test_closed_policy_keeps_original_absent_and_partial_metadata(self):
        p = M.policy()
        by_id = {row['id']: row for row in p['packages'].values()}
        for name in ['NUnit3.DotNetNew.Template', 'NETStandard.Library.Ref', 'NETStandard.Library', 'System.Runtime.CompilerServices.Unsafe']:
            self.assertIsNone(by_id[name]['originalRepository'])
        self.assertEqual({'type', 'url'}, set(by_id['NuGet.Versioning']['originalRepository']))
        self.assertEqual(18, len(p['arcadeMemberOrigins']))
        self.assertFalse(p['publisherCompilerExecutionClaimed'])

    def test_template_literal_accepts_only_fixed_text_line_endings(self):
        M.literal_correspondence(b'original\ntext\n', b'original\r\ntext\r\n', 'literal-original-text-with-publisher-package-EOL')
        with self.assertRaisesRegex(ValueError, 'original text'):
            M.literal_correspondence(b'original\ntext\n', b'changed\r\ntext\r\n', 'literal-original-text-with-publisher-package-EOL')

    def test_exact_literal_does_not_accept_line_ending_change(self):
        with self.assertRaisesRegex(ValueError, 'Exact original'):
            M.literal_correspondence(b'original\n', b'original\r\n', 'exact')

    def test_eol_correspondence_rejects_opaque_or_unknown_encoding(self):
        for raw, encoding in [(b'original\0\n', 'utf-8-sig'), (b'text\n', 'latin-1')]:
            with self.subTest(encoding=encoding), self.assertRaisesRegex(ValueError, 'encoding'):
                M.literal_correspondence(raw, raw.replace(b'\n', b'\r\n'), 'literal-original-text-with-publisher-package-EOL', encoding)

    def test_corrupt_package_rejects_before_zip_interpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            path.write_bytes(b'changed')
            p = {'packages': {'a': {'fingerprint': M.fingerprint(b'original')}}}
            with mock.patch.object(M.zipfile, 'ZipFile', side_effect=AssertionError('Untrusted ZIP parsed')):
                with self.assertRaisesRegex(ValueError, 'package required'):
                    M.inspect_package(path, 'a', p)

    def test_original_repository_absence_is_not_inferred_from_project_url(self):
        payload = (b'<package><metadata><id>Fixture</id><version>1.0.0</version>'
            b'<projectUrl>https://github.com/example/repo</projectUrl>'
            b'<repository type="git" url="https://github.com/example/repo" commit="' + b'a' * 40
            + b'"/></metadata></package>')
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('Fixture.nuspec', payload)
        raw = buffer.getvalue()
        p = {'packages': {'a': dict(fingerprint=M.fingerprint(raw), members={'Fixture.nuspec': M.fingerprint(payload)},
            nuspec='Fixture.nuspec', id='Fixture', version='1.0.0', originalRepository=None,
            originalLicense={name: None for name in ['license', 'licenseUrl', 'requireLicenseAcceptance']})}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.nupkg'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'repository metadata'):
                M.inspect_package(path, 'a', p)


class CompleteSourceArchiveBoundary(unittest.TestCase):
    def fixture(self, directory, *, body=b'original source\n', baseline_mode='100644', index_mode='100644',
                archive_mode=0o644, root_kind='tree', omit_data=False):
        release = Path(directory)
        (release / 'sources').mkdir()
        original = b'original source\n'
        blob = __import__('hashlib').sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
        baseline = {'Source.cs': dict(mode=baseline_mode, blob=blob)}
        pinned_tree = P.baseline_tree({'Source.cs': dict(mode='100644', blob=blob)})
        rows = [dict(path='source/Source.cs', mode=index_mode, baseline=baseline['Source.cs'], **M.fingerprint(body)),
            dict(path=M.ROOT_NAME + '/data.txt', mode='100644', **M.fingerprint(b'original data\n'))]
        index = ''.join(json.dumps(row) + '\n' for row in rows).encode()
        (release / 'sources/index.jsonl').write_bytes(index)
        archive_path = release / 'sources/source.tar.gz'
        with tarfile.open(archive_path, 'w:gz') as archive:
            item = tarfile.TarInfo('source/Source.cs')
            item.size = len(body)
            item.mode = archive_mode
            archive.addfile(item, io.BytesIO(body))
            if not omit_data:
                item = tarfile.TarInfo(M.ROOT_NAME + '/data.txt')
                item.size = len(b'original data\n')
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(b'original data\n'))
        index_fp = dict(path='index.jsonl', **M.fingerprint(index))
        archive_fp = dict(path='source.tar.gz', **M.fingerprint(archive_path.read_bytes()))
        manifest = dict(sdkVersion='5.0.214', targetRid='linux-musl-arm64', index=index_fp, archive=archive_fp,
            roots=[dict(name='source', kind='git-export', commit='a' * 40, tree=pinned_tree, files=1),
                dict(name=M.ROOT_NAME, kind=root_kind, role=M.ROLE, files=1)])
        policy = dict(sources={'fixture': dict(commit='a' * 40, tree=pinned_tree, files=1, gitlinks=[], selectedFiles={})},
            packages={}, products={})
        installer = SimpleNamespace(validate=lambda *args: {'status': 'fixture-installer-already-guarded'}, PATCHES={})
        def module(name, filename):
            return installer if filename == 'musl_legacy5_installer_inputs.py' else B if filename == 'musl_legacy_admission.py' else P
        return release, manifest, policy, module

    def validate_fixture(self, args):
        release, manifest, policy, module = args
        with mock.patch.object(M, 'policy', return_value=policy), mock.patch.object(M, 'module', side_effect=module), \
                mock.patch.object(M, 'package_bodies', return_value={'data.txt': b'original data\n'}):
            return M.validate(release, manifest, {})

    def test_real_tar_index_and_git_tree_boundary_accepts_exact_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            self.validate_fixture(self.fixture(directory))

    def test_rehashed_source_change_does_not_replace_original_git_blob(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'Git bytes'):
                self.validate_fixture(self.fixture(directory, body=b'changed source\n'))

    def test_self_consistent_mode_forgery_changes_pinned_git_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'Git tree'):
                self.validate_fixture(self.fixture(directory, baseline_mode='100755', index_mode='100755', archive_mode=0o755))

    def test_tar_mode_cannot_disagree_with_authenticated_index(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'type/mode'):
                self.validate_fixture(self.fixture(directory, archive_mode=0o755))

    def test_special_bits_cannot_hide_in_source_tar_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'type/mode'):
                self.validate_fixture(self.fixture(directory, archive_mode=0o4644))

    def test_raw_package_data_cannot_gain_a_git_role(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'non-Git data role'):
                self.validate_fixture(self.fixture(directory, root_kind='git'))

    def test_complete_data_index_cannot_hide_missing_archive_member(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'Complete preferred-source'):
                self.validate_fixture(self.fixture(directory, omit_data=True))


if __name__ == '__main__':
    unittest.main()
