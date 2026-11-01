#!/usr/bin/env python3
"""Regressions for .NET10 reused-framework source closure and marker binding."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('shared_source',ROOT/'scripts/ci-net10-shared-source.py')
S=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(S)


class ReusedFrameworkSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cbodotnet-shared-source-test.')
        self.addCleanup(self.temporary.cleanup); self.root=Path(self.temporary.name)
        self.profile=json.loads((ROOT/'profiles/dotnet-10.0.403-linux-arm64.json').read_text())

    def archive(self,mutation=None):
        path=self.root/'sdk.tar.gz'
        entries=[('shared/'+name+'/10.0.14/.version',(S.SHARED+'\n10.0.14\n').encode(),'file')
                 for name in ['Microsoft.NETCore.App','Microsoft.AspNetCore.App']]
        if mutation: entries=mutation(entries)
        with tarfile.open(path,'w:gz') as stream:
            for name,data,kind in entries:
                entry=tarfile.TarInfo('./'+name); entry.size=len(data)
                if kind=='symlink': entry.type=tarfile.SYMTYPE; entry.linkname='elsewhere'
                stream.addfile(entry,io.BytesIO(data) if kind=='file' else None)
        return path

    def test_both_actual_shared_markers_bind_the_separate_source_pin(self):
        result=S.archive_markers(self.archive(),self.profile)
        self.assertEqual(len(result),2)
        self.assertEqual({row['commit'] for row in result},{S.SHARED})
        self.assertEqual({row['runtimeVersion'] for row in result},{'10.0.14'})
        self.assertTrue(all(len(row['sha256'])==64 and row['bytes']>0 for row in result))

    def test_wrong_missing_duplicate_symlink_and_unsafe_markers_are_rejected(self):
        mutations=[lambda e:[e[0]],lambda e:e+[e[0]],
                   lambda e:[(e[0][0],b'0'*40+b'\n10.0.14\n','file'),e[1]],
                   lambda e:[(e[0][0],(S.SHARED+'\n10.0.13\n').encode(),'file'),e[1]],
                   lambda e:[(e[0][0],b'','symlink'),e[1]],
                   lambda e:e+[('../outside',b'bad','file')]]
        for index,mutation in enumerate(mutations):
            with self.subTest(index=index),self.assertRaises(ValueError): S.archive_markers(self.archive(mutation),self.profile)

    def test_profile_cannot_relabel_reused_binaries_as_fourxx_sources(self):
        for path,value in [('sharedVmrCommit',S.MAIN),('runtime','10.0.13')]:
            profile=copy.deepcopy(self.profile); profile['upstreamInputs'][path]=value
            with self.subTest(path=path),self.assertRaises(ValueError): S.selected(profile)
        profile=copy.deepcopy(self.profile); profile['build']['sourceOnly']=True
        with self.assertRaises(ValueError): S.selected(profile)

    def test_x64_sources_require_the_explicit_x64_profile_and_same_shared_markers(self):
        profile=json.loads((ROOT/'profiles/dotnet-10.0.403-linux-x64.json').read_text())
        self.assertEqual(S.selected(profile,'x64'),S.SHARED)
        self.assertEqual(S.archive_markers(self.archive(),profile,'x64'),S.archive_markers(self.archive(),self.profile))
        with self.assertRaises(ValueError): S.selected(profile)
        with self.assertRaises(ValueError): S.selected(self.profile,'x64')
        profile['host']['architecture']='arm64'
        with self.assertRaises(ValueError): S.selected(profile,'x64')

    def git(self,path,*args):
        return subprocess.check_output(['git','-C',str(path),*args],stderr=subprocess.PIPE).decode().strip()

    def repository(self,path):
        path.mkdir(); self.git(path,'init','-q'); self.git(path,'config','user.name','Fixture')
        self.git(path,'config','user.email','fixture@example.invalid')
        return path

    def test_real_clean_checkout_tree_and_nested_gitlink_are_bound(self):
        child=self.repository(self.root/'nested'); (child/'source.cs').write_text('child source\n')
        self.git(child,'add','.'); self.git(child,'commit','-qm','Child source'); child_pin=self.git(child,'rev-parse','HEAD')
        root=self.repository(self.root/'shared')
        for name in ['runtime','aspnetcore']:
            directory=root/'src'/name; directory.mkdir(parents=True); (directory/'source.cs').write_text(name+'\n')
        self.git(root,'-c','protocol.file.allow=always','submodule','add','-q',str(child),'nested-source')
        self.git(root,'add','.'); self.git(root,'commit','-qm','Full shared source'); pin=self.git(root,'rev-parse','HEAD')
        result=S.checkout_identity(root,pin)
        self.assertTrue(result['pristine']); self.assertEqual(result['tree'],self.git(root,'rev-parse','HEAD^{tree}'))
        self.assertEqual(result['submodules'][0]['commit'],child_pin)
        (root/'src/runtime/source.cs').write_text('tampered\n')
        with self.assertRaises(ValueError): S.checkout_identity(root,pin)

    def test_fetch_and_bind_cli_help_are_read_only(self):
        for args in [['--help'],['prepare','--help'],['bind','--help']]:
            with self.subTest(args=args):
                result=subprocess.run(['python3',str(ROOT/'scripts/ci-net10-shared-source.py'),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
