"""Tiny source/data/provider controls; no CLR/compiler/archive construction."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_generated_data as M


class ExactDataPolicy(unittest.TestCase):
    def test_closed_original_counts_and_partial_scope(self):
        p=M.policy()
        self.assertEqual(tuple(len(p[k])for k in('sourceFiles','dataPackages','dataOutputs','providerPackages','providerMembers','ownedTaskFiles')),(13,3,4,11,13,3))
        for key in ('wholeSourceClosure','qualificationAllowed','sourceAdmissionAllowed','actualRuntimeLoadsAuthenticated'):
            self.assertFalse(p[key])

    def test_graph_git_source_and_original_package_have_distinct_exact_bytes(self):
        p=M.policy();source=p['sourceFiles'][p['graphSourceKey']]
        self.assertEqual(source['fingerprint']['bytes'],51396)
        self.assertEqual(source['gitBlob'],'7d6aa102b506ea58f1d3b52e7f33496d9cc500c8')
        graph=next(row for row in p['dataOutputs'].values()if row['kind']=='original-package-copy')
        self.assertEqual(graph['fingerprint']['bytes'],54594)

    def test_real58_dependencies_are_distinct_from_rebuilt59(self):
        p=M.policy();common={p['providerMembers'][name]['sourceRequirement']['commit']for name in
            ('NuGet.Common.dll','NuGet.Configuration.dll','NuGet.Frameworks.dll','NuGet.Versioning.dll')}
        self.assertEqual(common,{'830c8be45dbbccd411ecf6080abff0c2c98079cf'})
        self.assertEqual(p['providerMembers']['NuGet.Packaging.dll']['sourceRequirement']['commit'],'ebc4f817473f08c3705ed0e5c58c223372f36f7b')
        self.assertNotIn('d525b0e670f3b6cbd5c73a35f04730a9f658c852',common)

    def test_windows_variants_and_json_publisher_basis_remain_distinct(self):
        members=M.policy()['providerMembers'];windows=[row for row in members.values()if row['declaredAssetRole']=='runtimeTargets']
        self.assertEqual(len(windows),2)
        self.assertEqual(members['Newtonsoft.Json.dll']['sourceRequirement']['kind'],'original-Json9-publisher-source-policy-required')
        self.assertIsNone(members['Newtonsoft.Json.dll']['originalEmbeddedSource'])

    def test_source_descriptor_cannot_replace_actual_bytes(self):
        p=M.policy();sources={key:row['fingerprint']for key,row in p['sourceFiles'].items()}
        with self.assertRaisesRegex(ValueError,'descriptors'):M.source_file_correspondence(sources)

    def test_missing_recipe_source_rejects(self):
        with self.assertRaisesRegex(ValueError,'All exact'):M.source_file_correspondence({})

    def test_full_success_cannot_be_enabled_by_descriptors_or_callback(self):
        for value in ({},{'source_archive':{'validated':True}},{'runtime_evidence':True},{'validator':lambda:True}):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'Full four-data construction pending'):
                M.validate_full(**value)


class DataAlgorithms(unittest.TestCase):
    CONFIG=b'{\r\n  "runtimeOptions": {\r\n    "tfm": "net5.0",\r\n    "framework": {\r\n      "name": "Microsoft.NETCore.App",\r\n      "version": "5.0.0"\r\n    }\r\n  }\r\n}'

    def graph(self,value):return json.dumps(dict(runtimes=value)).encode()

    def test_breadth_first_first_occurrence_order(self):
        graph=self.graph({'root':{'#import':['left','right']},'left':{'#import':['shared']},'right':{'#import':['shared','last']}})
        self.assertEqual(M.expand_runtime_graph(graph,'root'),b'root\nleft\nright\nshared\nlast')

    def test_cycle_terminates_without_duplicate_or_final_newline(self):
        self.assertEqual(M.expand_runtime_graph(self.graph({'a':{'#import':['b']},'b':{'#import':['a']}}),'a'),b'a\nb')

    def test_unknown_rid_and_nonarray_import_reject(self):
        with self.assertRaisesRegex(ValueError,'Declared original'):M.expand_runtime_graph(self.graph({'a':{}}),'unknown')
        with self.assertRaisesRegex(ValueError,'import array'):M.expand_runtime_graph(self.graph({'a':{'#import':'b'}}),'a')

    def test_duplicate_json_properties_reject(self):
        for raw in (b'{"runtimes":{},"runtimes":{}}',b'{"runtimes":{"a":{},"a":{}}}'):
            with self.assertRaisesRegex(ValueError,'Duplicate'):M.unique_json(raw)

    def test_graph_expansion_is_bounded(self):
        graph={str(i):{'#import':[str(i+1)]}for i in range(4097)}
        with self.assertRaisesRegex(ValueError,'Bounded'):M.expand_runtime_graph(self.graph(graph),'0')

    def test_exact_crlf_runtime_replacement_preserves_all_other_bytes(self):
        self.assertEqual(len(self.CONFIG),147)
        result=M.replace_tool_runtime_version(self.CONFIG)
        self.assertEqual(result,self.CONFIG.replace(b'5.0.0',b'5.0.17'))
        self.assertEqual(len(result),148);self.assertEqual(result.count(b'\r\n'),self.CONFIG.count(b'\r\n'))
        self.assertFalse(result.endswith(b'\n'))

    def test_changed_framework_or_extra_replacement_rejects(self):
        for raw in (self.CONFIG.replace(b'Microsoft.NETCore.App',b'Microsoft.AspNetCore.App'),
                self.CONFIG.replace(b'5.0.0',b'6.0.0'),self.CONFIG[:-1]+b',"version": "5.0.0"}'):
            with self.assertRaises(ValueError):M.replace_tool_runtime_version(raw)


class OriginalPackageBody(unittest.TestCase):
    SPEC=b'<package><metadata><id>Original</id><version>1.0</version></metadata></package>'

    def package(self,temp,*,duplicate=False,special=False):
        stream=io.BytesIO()
        with warnings.catch_warnings(),zipfile.ZipFile(stream,'w')as z:
            warnings.simplefilter('ignore',UserWarning)
            z.writestr('Original.nuspec',self.SPEC);z.writestr('data.json',b'original\r\n')
            if duplicate:z.writestr('data.json',b'other')
            if special:
                row=zipfile.ZipInfo('link');row.create_system=3;row.external_attr=0o120777<<16;z.writestr(row,b'target')
        raw=stream.getvalue();path=Path(temp)/'original.nupkg';path.write_bytes(raw)
        want=dict(id='Original',version='1.0',repository=None,fingerprint=M.fingerprint(raw),nuspec=dict(path='Original.nuspec',fingerprint=M.fingerprint(self.SPEC)))
        return path,want

    def test_whole_original_package_and_member_positive(self):
        with tempfile.TemporaryDirectory()as temp:
            path,want=self.package(temp);self.assertEqual(M._package(path,want,'data.json'),b'original\r\n')

    def test_changed_complete_package_rejects(self):
        with tempfile.TemporaryDirectory()as temp:
            path,want=self.package(temp);path.write_bytes(path.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'whole package'):M._package(path,want,'data.json')

    def test_selfconsistent_duplicate_member_rejects(self):
        with tempfile.TemporaryDirectory()as temp:
            path,want=self.package(temp,duplicate=True)
            with self.assertRaisesRegex(ValueError,'Unique'):M._package(path,want,'data.json')

    def test_special_entry_rejects_without_extraction(self):
        with tempfile.TemporaryDirectory()as temp:
            path,want=self.package(temp,special=True)
            with self.assertRaisesRegex(ValueError,'Ordinary bounded'):M._package(path,want,'data.json')

    def test_changed_identity_and_missing_member_reject(self):
        with tempfile.TemporaryDirectory()as temp:
            path,want=self.package(temp);changed=copy.deepcopy(want);changed['version']='2.0'
            with self.assertRaisesRegex(ValueError,'identity'):M._package(path,changed,'data.json')
            with self.assertRaisesRegex(ValueError,'unique original'):M._package(path,want,'missing')


class CopiedProviderBoundary(unittest.TestCase):
    def metadata(self,want):
        return dict(assemblyName=want['assemblyName'],assemblyVersion=want['assemblyVersion'],references=want['assemblyReferences'],
            attributes={'System.Reflection.AssemblyInformationalVersionAttribute':want['assemblyInformationalVersions']})

    def test_original_short_prefix_is_not_called_full_embedded_sha(self):
        p=M.policy();want=p['providerMembers']['Microsoft.Build.dll'];package=p['providerPackages'][want['packageSha256']]
        result=M._provider_source(self.metadata(want),want,package)
        self.assertEqual(result['prefix'],'ac19036b0d');self.assertIsNone(want['originalEmbeddedSource'])
        changed=copy.deepcopy(want);changed['originalEmbeddedSource']=dict(sourceCommit=result['commit'],basis='assembly-informational-version')
        with self.assertRaisesRegex(ValueError,'assembly identity'):M._provider_source(self.metadata(want),changed,package)

    def test_actual58_full_source_and_package_repo_must_agree(self):
        p=M.policy();want=p['providerMembers']['NuGet.Common.dll'];package=p['providerPackages'][want['packageSha256']]
        self.assertEqual(M._provider_source(self.metadata(want),want,package)['commit'],'830c8be45dbbccd411ecf6080abff0c2c98079cf')
        changed=copy.deepcopy(package);changed['repository']['commit']='d525b0e670f3b6cbd5c73a35f04730a9f658c852'
        with self.assertRaisesRegex(ValueError,'must agree'):M._provider_source(self.metadata(want),want,changed)

    def test_provider_descriptors_cannot_replace_files(self):
        with self.assertRaisesRegex(ValueError,'descriptors'):M.provider_identities({'validated':True},{})

    def test_extra_renamed_managed_candidate_is_not_ignored(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);(root/'renamed.data').write_bytes(b'MZextra original-provider forgery')
            packages={sha:root/'unused'for sha in M.policy()['providerPackages']}
            with self.assertRaisesRegex(ValueError,'Complete original copied'):M.provider_identities(root,packages)

    def test_missing_dependency_cannot_be_satisfied_with_partial_package_table(self):
        with tempfile.TemporaryDirectory()as temp:
            with self.assertRaisesRegex(ValueError,'All eleven'):M.provider_identities(Path(temp),{})

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO')
    def test_fifo_rejects_before_read(self):
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/'fifo';os.mkfifo(path)
            with self.assertRaisesRegex(ValueError,'safe mode'):M.body(path)


if __name__=='__main__':unittest.main()
