"""Publisher source bytes cannot become a generic source-change exception."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sdk5_publisher_source',ROOT/'scripts/musl_legacy5_newtonsoft_source_inputs.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class OriginalPublisherSource(unittest.TestCase):
    def test_unpinned_policy_rejects_before_json_parse(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'),mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy differs'):M.policy()

    def test_unknown_or_changed_original_package_rejects_before_zip_parse(self):
        sha,row=next(iter(M.policy()['packages'].items()))
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'changed.nupkg';path.write_bytes(b'X'*row['fingerprint']['bytes'])
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted NPK parsed')):
                with self.assertRaisesRegex(ValueError,'NPK bytes differ'):M.inspect_package(path,sha)
                with self.assertRaisesRegex(ValueError,'Exact original'):M.inspect_package(path,'0'*64)

    def test_changed_publisher_zip_rejects_before_member_parse(self):
        with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted publisher ZIP parsed')):
            with self.assertRaisesRegex(ValueError,'ZIP bytes differ'):M.distribution_sources(b'PKchanged','9.0.1',{},M.policy())

    def test_version_recipe_does_not_allow_implementation_changes(self):
        original=b'[assembly: AssemblyVersion("7.0.0.0")]\n[assembly: AssemblyFileVersion("7.0.2.18802")]\nclass Actual {}'
        published=original.replace(b'7.0.0.0',b'9.0.0.0').replace(b'7.0.2.18802',b'9.0.1.19813').replace(b'\n',b'\r\n')+b'\r\n'
        M.publisher_metadata('9.0.1','Src/Newtonsoft.Json/Properties/AssemblyInfo.cs',original,published)
        with self.assertRaisesRegex(ValueError,'version output differs'):
            M.publisher_metadata('9.0.1','Src/Newtonsoft.Json/Properties/AssemblyInfo.cs',original,published.replace(b'Actual',b'Changed'))

    def test_original_signing_project_settings_are_exact(self):
        original={'version':'1.0.0-*','frameworks':{'net45':{}}};published=dict(original,version='9.0.1',buildOptions=dict(
            keyFile='C:\\Development\\Releases\\newtonsoft.snk',define=['CODE_ANALYSIS','TRACE','dotnet','SIGNED'],xmlDoc=True,warningsAsErrors=True))
        M.publisher_metadata('9.0.1','Src/Newtonsoft.Json/project.json',json.dumps(original).encode(),json.dumps(published).encode())
        published['buildOptions']['define'].append('DEBUG')
        with self.assertRaisesRegex(ValueError,'project output differs'):
            M.publisher_metadata('9.0.1','Src/Newtonsoft.Json/project.json',json.dumps(original).encode(),json.dumps(published).encode())

    def test_file_version_update_does_not_change_framework_or_other_properties(self):
        original=b'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><FileVersion>11.0.1</FileVersion><VersionSuffix>beta2</VersionSuffix><TargetFramework>net45</TargetFramework></PropertyGroup></Project>'
        published=original.replace(b'>11.0.1<',b'>11.0.1.21818<').replace(b'>beta2<',b'><')
        M.publisher_metadata('11.0.1','Src/Newtonsoft.Json/Newtonsoft.Json.csproj',original,published)
        with self.assertRaisesRegex(ValueError,'project output differs'):
            M.publisher_metadata('11.0.1','Src/Newtonsoft.Json/Newtonsoft.Json.csproj',original,published.replace(b'net45',b'net6.0'))

    def test_unreviewed_file_or_publisher_version_is_not_a_fallback(self):
        for version,name in [('9.0.1','Src/Other/Properties/AssemblyInfo.cs'),('6.0.136','Src/Newtonsoft.Json/project.json')]:
            with self.assertRaisesRegex(ValueError,'Unreviewed'):M.publisher_metadata(version,name,b'original',b'changed')


if __name__=='__main__':unittest.main()
