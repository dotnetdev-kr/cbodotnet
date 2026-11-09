import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_package_inputs as M


class PackageInputs(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.release=Path(self.tmp.name);self.roots={}
        self.compiler={name:dict(proof=dict(component=name,sourceCommit=commit,packages=[])) for name,commit in M.CE.COMMITS.items()}
        path=self.release/'raw.nupkg'
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('example.nuspec','<package><metadata><id>Example</id><version>1.0</version></metadata></package>')
            z.writestr('lib/netstandard2.0/Example.dll',b'original bytes')
        fp=M.CE.fingerprint(path);self.sha=fp['sha256'];retained='imported-inputs/'+self.sha+'.nupkg'
        (self.release/'imported-inputs').mkdir();path.rename(self.release/retained)
        self.row=dict(retained=retained,cache='/actual/cache/example/1.0',path='example.1.0.nupkg',actualCacheRole='actual-sdk-restore',
            repository=None,actualCacheReferences=[dict(path='/actual/cache/example/1.0/example.1.0.nupkg',cacheRole='actual-sdk-restore')],**fp)
        self.proof=dict(kind='sdk5-musl-construction-proof',sdkVersion='5.0.214',artifacts={
            'package-'+self.sha:dict(path=retained,kind='managed-package',sourceRoot=None,sourceCommit=None,sourceBasis='original-package-repository',repository=None,**fp)},
            unknowns=[dict(kind='unmapped-package-source',artifact='package-'+self.sha,id='Example',version='1.0',originalRepository=None)])
        self.write_report([self.row])

    def write_report(self,rows):
        p=self.release/'restored.json';p.write_text(json.dumps(dict(schemaVersion=1,packages=rows)))
        self.proof['restoredInputs']=dict(path='restored.json',**M.CE.fingerprint(p))

    def validate(self):return M.validate(self.release,self.proof,self.roots,self.compiler)

    def with_repository(self,component=None):
        commit=M.CE.COMMITS[component] if component else 'a'*40
        path=self.release/'with-repository.nupkg'
        repository={'type':'git','url':'https://example.invalid/original','commit':commit}
        attrs=' '.join(key+'="'+value+'"' for key,value in repository.items())
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('example.nuspec','<package><metadata><id>Example</id><version>1.0</version><repository '+attrs+'/></metadata></package>')
        fp=M.CE.fingerprint(path);self.sha=fp['sha256'];retained='imported-inputs/'+self.sha+'.nupkg';path.rename(self.release/retained)
        self.row.update(retained=retained,repository=repository,**fp);self.write_report([self.row])
        root=component or 'original-source';self.roots[root]=dict(kind='git',commit=commit)
        self.proof['artifacts']={'package-'+self.sha:dict(path=retained,kind='managed-package',sourceRoot=root,sourceCommit=commit,
            sourceBasis='actual-compiler-bound-source-package' if component else 'original-package-repository',repository=repository,**fp)}
        self.proof['unknowns']=[]
        if component:self.compiler[component]['proof']['packages']=[dict(path=retained,**fp)]

    def test_original_missing_repository_remains_unknown(self):
        result=self.validate();self.assertFalse(result['sourceAdmissionAllowed']);self.assertEqual(result['rawUnmappedPackageSources'],self.proof['unknowns'])

    def test_fabricated_repository_is_rejected(self):
        self.proof['artifacts']['package-'+self.sha]['repository']={'commit':'a'*40}
        with self.assertRaisesRegex(ValueError,'remain literal'):self.validate()

    def test_kind_flip_is_rejected(self):
        self.proof['artifacts']['package-'+self.sha]['kind']='generated-installer-data'
        with self.assertRaisesRegex(ValueError,'role/path/bytes'):self.validate()

    def test_dropped_raw_unknown_is_rejected(self):
        self.proof['unknowns']=[]
        with self.assertRaisesRegex(ValueError,'must remain unchanged'):self.validate()

    def test_fabricated_git_source_is_rejected(self):
        self.roots['invented']=dict(kind='git',commit='a'*40)
        self.proof['artifacts']['package-'+self.sha].update(sourceRoot='invented',sourceCommit='a'*40)
        with self.assertRaisesRegex(ValueError,'actual original repository'):self.validate()

    def test_duplicate_restored_package_is_rejected(self):
        self.write_report([self.row,copy.deepcopy(self.row)])
        with self.assertRaisesRegex(ValueError,'Unique canonical'):self.validate()

    def test_self_consistent_cache_metadata_spoof_is_rejected(self):
        row=copy.deepcopy(self.row);row['repository']={'type':'git','commit':'b'*40}
        self.write_report([row]);self.proof['artifacts']['package-'+self.sha]['repository']=row['repository']
        with self.assertRaisesRegex(ValueError,'cache repository metadata'):self.validate()

    def test_original_repository_source_root_is_retained(self):
        self.with_repository();self.assertEqual(len(self.validate()['packageArtifacts']),1)

    def test_actual_compiler_package_source_binding(self):
        self.with_repository('nuget');self.assertEqual(len(self.validate()['restored']),1)

    def test_source_built_package_cannot_be_reclassified_as_import(self):
        self.with_repository('nuget');self.proof['artifacts']['package-'+self.sha]['sourceBasis']='original-package-repository'
        with self.assertRaisesRegex(ValueError,'compiler provenance'):self.validate()


if __name__=='__main__':unittest.main()
