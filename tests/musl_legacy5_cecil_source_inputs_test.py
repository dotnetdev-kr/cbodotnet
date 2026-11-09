"""Publisher declarations cannot waive a missing original Cecil source tree."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sdk5_declared_cecil',ROOT/'scripts/musl_legacy5_cecil_source_inputs.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class DeclaredOriginalSource(unittest.TestCase):
    def manifest(self):
        p=M.policy()
        return dict(sdkVersion=M.SDK,targetRid='linux-musl-arm64',index={},archive={},roots=[
            dict(name='linker',kind='git',commit=p['linker']['commit'],tree=p['linker']['tree'],submodules=[dict(path='external/cecil',commit=p['cecil']['commit'],root='cecil')]),
            dict(name='cecil',kind='git',commit=p['cecil']['commit'],tree=p['cecil']['tree'],submodules=[]),
            dict(name=M.ROOT_NAME,kind='tree',commit=None,role=M.ROLE)])

    def test_modified_policy_rejects_before_json_parse(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'),mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy differs'):M.policy()

    def test_changed_original_package_rejects_before_zip_parse(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'changed.nupkg';path.write_bytes(b'X'*M.policy()['package']['fingerprint']['bytes'])
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted package parsed')):
                with self.assertRaisesRegex(ValueError,'NPK bytes differ'):M.inspect_package(path)

    def test_source_xml_entities_reject(self):
        with self.assertRaisesRegex(ValueError,'without entities'):M.xml(b'<!DOCTYPE project [<!ENTITY a "unsafe">]><Project/>')

    def test_foreign_sdk_cannot_use_declared_cecil_sources(self):
        manifest=self.manifest();manifest['sdkVersion']='6.0.136'
        with self.assertRaisesRegex(ValueError,'Independent SDK5'):M.validate(ROOT,manifest,ROOT/'absent.nupkg')

    def test_missing_gitlink_or_excluded_full_source_reject(self):
        for excluded in (False,True):
            manifest=self.manifest()
            if excluded:manifest['roots'][1]['exclude']=['Mono.Cecil/ModuleDefinition.cs']
            else:manifest['roots'][0]['submodules']=[]
            with self.subTest(excluded=excluded),mock.patch.object(M,'module',return_value=SimpleNamespace(checked=lambda *args:None)):
                with self.assertRaises(ValueError):M.validate(ROOT,manifest,ROOT/'absent.nupkg')

    def test_unpinned_project_recipe_rejects_before_xml_parse(self):
        p=M.policy();sources={role:{name:b'changed'for name in p[role]['files']}for role in ('linker','cecil')}
        with mock.patch.object(M.ET,'fromstring',side_effect=AssertionError('untrusted recipe parsed')):
            with self.assertRaisesRegex(ValueError,'Git bytes differ'):M.source_recipe(sources)


if __name__=='__main__':unittest.main()
