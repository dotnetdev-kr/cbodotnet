"""Original SDK5 packages keep their own missing repository metadata."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_embedded_source', ROOT/'scripts/musl_legacy5_embedded_source_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class OriginalMemberSources(unittest.TestCase):
    def manifest(self):
        return dict(sdkVersion='5.0.214', targetRid='linux-musl-arm64', index={}, archive={},
            roots=[dict(name='source-'+commit,kind='git',commit=commit,tree=row['tree'])for commit,row in M.policy()['sources'].items()]
            + [dict(name=M.ROOT_NAME,kind='tree',commit=None,role=M.ROLE)])

    def test_unlisted_package_cannot_use_missing_repository_as_a_fallback(self):
        self.assertIsNone(M.package_origin(ROOT/'missing.nupkg','0'*64))

    def test_unpinned_policy_rejects_before_parsing(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'), mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy bytes differ'): M.policy()

    def test_same_size_package_corruption_rejects_before_zip_parsing(self):
        sha,row=min(M.policy()['packages'].items(),key=lambda item:item[1]['fingerprint']['bytes'])
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'changed.nupkg';path.write_bytes(b'X'*row['fingerprint']['bytes'])
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted package parsed')):
                with self.assertRaisesRegex(ValueError,'raw bytes differ'): M.inspect_package(path,sha)

    def test_foreign_layout_package_member_and_bytes_reject_before_pe_inspection(self):
        name,row=next(iter(M.policy()['products'].items()));pair=row['allowedPackageMembers'][0]
        for selected,sha,member in [('sdk/6.0.136/foreign.dll',pair['packageSha256'],pair['member']),
                (name,'0'*64,pair['member']),(name,pair['packageSha256'],'../changed.dll'),(name,pair['packageSha256'],pair['member'])]:
            with self.subTest(path=selected,sha=sha,member=member),mock.patch.object(M,'module',side_effect=AssertionError('untrusted PE inspected')):
                with self.assertRaisesRegex(ValueError,'layout/package/member differs'): M.declared_product(selected,sha,member,b'MZchanged')

    def test_missing_or_excluded_full_original_source_rejects(self):
        for excluded in (True,False):
            manifest=self.manifest()
            if excluded:manifest['roots'][0]['exclude']=['src/actual-code.cs']
            else:manifest['roots'].pop(0)
            with self.subTest(excluded=excluded),mock.patch.object(M,'module',return_value=SimpleNamespace(checked=lambda *args:None)):
                with self.assertRaisesRegex(ValueError,'Complete pristine SDK5 per-member Git source'): M.validate(ROOT,manifest,{})

    def test_original_no_repository_package_tree_cannot_claim_git_provenance(self):
        manifest=self.manifest();manifest['roots'][-1].update(kind='git',commit=next(iter(M.policy()['sources'])))
        with mock.patch.object(M,'module',return_value=SimpleNamespace(checked=lambda *args:None)):
            with self.assertRaisesRegex(ValueError,'non-Git role'): M.validate(ROOT,manifest,{})


if __name__=='__main__':unittest.main()
