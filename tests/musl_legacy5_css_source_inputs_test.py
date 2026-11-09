"""Original CSS source declarations do not authorize arbitrary signed images."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sdk5_css_source',ROOT/'scripts/musl_legacy5_css_source_inputs.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class OriginalCssSource(unittest.TestCase):
    def test_policy_hash_checked_before_parse(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'),mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy differs'):M.policy()
    def test_package_hash_checked_before_zip(self):
        p=M.policy();paths={}
        with tempfile.TemporaryDirectory()as directory:
            for role,row in p['packages'].items():
                path=Path(directory)/(role+'.nupkg');path.write_bytes(b'X'*row['fingerprint']['bytes']);paths[row['fingerprint']['sha256']]=path
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted NPK parsed')):
                with self.assertRaisesRegex(ValueError,'package bytes differ'):M.inspect_packages(paths)
    def test_unpinned_images_reject_before_structural_parse(self):
        with mock.patch.object(M.struct,'unpack_from',side_effect=AssertionError('untrusted image parsed')):
            with self.assertRaisesRegex(ValueError,'image fingerprints'):M.certificate_append(b'X',b'Y')
    def test_xml_entities_reject(self):
        with self.assertRaisesRegex(ValueError,'without entities'):M.xml(b'<!DOCTYPE Project [<!ENTITY a "unsafe">]><Project/>')
    def test_foreign_sdk_rejects(self):
        with self.assertRaisesRegex(ValueError,'Independent SDK5'):M.validate(ROOT,dict(sdkVersion='6.0.136',targetRid='linux-musl-arm64'),{})
    def test_missing_full_source_rejects(self):
        with mock.patch.object(M,'module',return_value=SimpleNamespace(checked=lambda *a:None)):
            with self.assertRaisesRegex(ValueError,'Complete pristine'):M.validate(ROOT,dict(sdkVersion=M.SDK,targetRid='linux-musl-arm64',index={},archive={},roots=[]),{})
    def test_recipe_bytes_checked_before_parsing(self):
        sources={role:{name:b'changed'for name in row['files']}for role,row in M.policy()['sources'].items()}
        with mock.patch.object(M.ET,'fromstring',side_effect=AssertionError('untrusted recipe parsed')):
            with self.assertRaisesRegex(ValueError,'Git bytes differ'):M.source_recipe(sources)

if __name__=='__main__':unittest.main()
