"""Unsafe source identity cannot authorize unknown native derivation or source."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_unsafe_source', ROOT/'scripts/musl_legacy5_unsafe_source_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class OriginalUnsafeSource(unittest.TestCase):
    def manifest(self):
        p=M.policy()
        return dict(sdkVersion=M.SDK,targetRid='linux-musl-arm64',index={},archive={},roots=[
            dict(name='runtime',kind='git',commit=p['runtime']['commit'],tree=p['runtime']['tree'],submodules=[]),
            dict(name=M.ROOT_NAME,kind='tree',commit=None,role=M.ROLE)])

    def test_policy_hash_checked_before_parse(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'),mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy differs'):M.policy()

    def test_npk_hash_checked_before_zip(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'changed.nupkg';path.write_bytes(b'X'*M.policy()['package']['fingerprint']['bytes'])
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted NPK parsed')):
                with self.assertRaisesRegex(ValueError,'NPK bytes differ'):M.inspect_package(path)

    def test_foreign_sdk_rejects(self):
        manifest=self.manifest();manifest['sdkVersion']='6.0.136'
        with self.assertRaisesRegex(ValueError,'Independent SDK5'):M.validate(ROOT,manifest,ROOT/'absent.nupkg')

    def test_excluded_full_source_rejects(self):
        manifest=self.manifest();manifest['roots'][0]['exclude']=['src/actual.il']
        with mock.patch.object(M,'module',return_value=SimpleNamespace(checked=lambda *args:None)):
            with self.assertRaisesRegex(ValueError,'Complete pristine'):M.validate(ROOT,manifest,ROOT/'absent.nupkg')

    def test_wrong_layout_and_changed_dll_reject(self):
        with self.assertRaisesRegex(ValueError,'layout path'):M.declared_product('sdk/6.0.136/Unsafe.dll',b'X')
        with self.assertRaisesRegex(ValueError,'DLL bytes differ'):M.declared_product(next(iter(M.policy()['products'])),b'X')

    def test_truncated_pe_and_escaped_pe_header_reject(self):
        for raw in (b'MZ', b'MZ'+bytes(58)+b'\xff\xff\xff\xff'+bytes(64)):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):M.managed_view(raw)

    def test_original_source_bytes_checked_before_recipe(self):
        with self.assertRaisesRegex(ValueError,'Git bytes differ'):
            M.source_recipe({name:b'changed'for name in M.policy()['runtime']['files']})

    def test_native_claims_remain_withheld(self):
        p=M.policy()
        for key in ('publisherCompilerExecutionClaimed','localBuildClaimed','nativeCodeDerivationClaimed'):
            self.assertIs(p[key],False)


if __name__=='__main__':unittest.main()
