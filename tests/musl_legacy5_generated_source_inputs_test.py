"""Tiny real archive/Git-object controls; no genuine SDK execution claimed."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_legacy5_generated_source_inputs as M


class ArchivedSources(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.release=Path(self.tmp.name).resolve();(self.release/'sources').mkdir()
        roles=['platforms','installer','aspnetcore','nuget-common58','nuget-packaging58','pkcs','protected-data','msbuild157','json9-publisher']
        self.roots=[];self.policy=[];self.bodies={};self.rows={};self.files={}
        for i,role in enumerate(roles):
            name='installer'if role=='installer'else'root-'+str(i);count=3 if role=='installer'else 2 if role in('aspnetcore','nuget-packaging58')else 1
            baseline={}
            for n in range(count):
                relative='source-'+str(n)+'.txt';raw=('Synthetic source '+role+' '+str(n)+'\n').encode();blob=M.git_object('blob',raw)
                baseline[relative]=dict(mode='100644',blob=blob);path=name+'/'+relative
                self.bodies[path]=raw;self.rows[path]=dict(path=path,mode='100644',baseline=baseline[relative],**M.D.fingerprint(raw))
                self.files[role+':'+relative]=dict(sourceRole=role,path=relative,gitMode='100644',gitBlob=blob,fingerprint=M.D.fingerprint(raw))
            tree=M.P.baseline_tree(baseline);raw=('tree '+tree+'\nauthor Fixture <a@example.invalid> 1 +0000\ncommitter Fixture <a@example.invalid> 1 +0000\n\nSynthetic fixture\n').encode();commit=M.git_object('commit',raw)
            self.roots.append(dict(name=name,kind='git',role='build-source'if role=='installer'else'source-for-serviced-imported-package',commit=commit,tree=tree,commitObjectBase64=base64.b64encode(raw).decode(),files=count,deleted=[],submodules=[]))
            self.policy.append(dict(dataRole=role,commit=commit,tree=tree))
        self.manifest=dict(sdkVersion='5.0.214',targetRid='linux-musl-arm64',roots=self.roots)
        self.addCleanup(patch.stopall)
        patch.object(M.G,'policy',return_value=dict(sources=self.policy)).start()
        patch.object(M.D,'policy',return_value=dict(sourceFiles=self.files)).start()
        patch.object(M.I,'PATCHES',{}).start()
        self.installer=patch.object(M.I,'validate',return_value=dict(status='synthetic-delegation-only')).start()
        self.write()

    def write(self,*,mode=None,extra=None,duplicate=None):
        index=self.release/'sources/index.jsonl';index.write_bytes(b''.join((json.dumps(row)+'\n').encode()for row in self.rows.values()))
        archive=self.release/'sources/sources.tar.gz'
        with tarfile.open(archive,'w:gz')as stream:
            for name,raw in self.bodies.items():
                info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o755 if name==mode else 0o644;stream.addfile(info,io.BytesIO(raw))
                if name==duplicate:stream.addfile(info,io.BytesIO(raw))
            if extra:
                info=tarfile.TarInfo(extra);info.size=1;info.mode=0o644;stream.addfile(info,io.BytesIO(b'x'))
        self.manifest['index']=dict(path=index.name,**M.D.fingerprint(index.read_bytes()))
        self.manifest['archive']=dict(path=archive.name,**M.D.fingerprint(archive.read_bytes()))

    def test_complete_nine_trees_and_thirteen_actual_recipes(self):
        result=M.validate(self.release,self.manifest)
        self.assertEqual((result['completeGitTrees'],result['archivedSourceFiles']),(9,13))
        self.assertTrue(result['archivedGeneratedProviderSourceTreesValidated'])
        self.assertFalse(result['actualRuntimeLoadsAuthenticated'])
        self.assertFalse(result['wholeCombinedSourcePacketValidatedByThisPart'])
        self.assertFalse(result['sourceAdmissionAllowed']);self.installer.assert_called_once()

    @unittest.skipUnless(os.name=='posix','Real source-packer integration uses POSIX Git fixtures')
    def test_real_source_packer_manifest_and_archive_validate(self):
        packer_path=Path(__file__).resolve().parents[1]/'scripts'/'package-used-source.py'
        spec=importlib.util.spec_from_file_location('sdk5_test_source_packer',packer_path)
        packer=importlib.util.module_from_spec(spec);spec.loader.exec_module(packer)
        def git(path,*args):
            subprocess.run(['git','-C',str(path),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def init_repo(path,files):
            path.mkdir(parents=True)
            git(path,'init','-q');git(path,'config','user.name','Fixture');git(path,'config','user.email','fixture@example.invalid')
            for relative,raw in files.items():
                target=path/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            git(path,'add','--all');git(path,'commit','-q','-m','synthetic source')
            commit=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
            tree=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD^{tree}'],text=True).strip()
            return commit,tree

        roots=[];sources=self.release/'source-roots'
        for i,role in enumerate(row['dataRole']for row in self.policy):
            name='installer'if role=='installer'else'root-'+str(i)
            files={relative:raw for key,source in self.files.items()if source['sourceRole']==role
                for relative,raw in [(source['path'],self.bodies[name+'/'+source['path']])]}
            root=sources/name;commit,tree=init_repo(root,files)
            source_policy=next(item for item in self.policy if item['dataRole']==role)
            source_policy.update(commit=commit,tree=tree)
            roots.append(dict(name=name,kind='git',path=str(root),expectedCommit=commit,
                role='build-source'if role=='installer'else'source-for-serviced-imported-package'))
        project_commit,_=init_repo(self.release/'project-git',{'README.md':b'fixture\n'})
        roots_path=self.release/'source-roots.json'
        roots_path.write_text(json.dumps(dict(schemaVersion=1,roots=roots)))
        release=self.release/'real-release';(release/'reports/ci').mkdir(parents=True)
        args=SimpleNamespace(project_root=self.release/'project-git',project_commit=project_commit,
            output_dir=release/'sources',roots_json=roots_path,sdk_version='5.0.214',
            target_rid='linux-musl-arm64',run_id='1',run_attempt='1')
        packer.pack(args)
        manifest=packer.verify(SimpleNamespace(release_dir=release,expected_project_commit=project_commit,
            expected_run_id='1',expected_run_attempt='1',expected_target_rid='linux-musl-arm64'))
        result=M.validate(release,manifest)
        self.assertEqual((result['completeGitTrees'],result['archivedSourceFiles']),(9,13))
        self.assertTrue(result['archivedGeneratedProviderSourceTreesValidated'])

    def test_missing_duplicate_or_wrong_pinned_root_rejected(self):
        for change in('missing','duplicate','tree','commit-object','deleted'):
            data=copy.deepcopy(self.manifest)
            if change=='missing':data['roots'].pop()
            elif change=='duplicate':data['roots'].append(copy.deepcopy(data['roots'][0]))
            elif change=='tree':data['roots'][0]['tree']='0'*40
            elif change=='commit-object':data['roots'][0]['commitObjectBase64']=base64.b64encode(b'tree '+b'0'*40+b'\n').decode()
            else:data['roots'][0]['deleted']=[dict(path='missing.txt')]
            with self.subTest(change=change),self.assertRaises(ValueError):M.validate(self.release,data)

    def test_source_body_cannot_be_rebound_with_new_index_hashes(self):
        name=next(iter(self.bodies));self.bodies[name]=b'forged source\n';self.rows[name].update(M.D.fingerprint(self.bodies[name]));self.write()
        with self.assertRaisesRegex(ValueError,'pristine original Git blob'):M.validate(self.release,self.manifest)

    def test_forged_mode_in_index_and_tar_cannot_change_git_tree(self):
        name=next(iter(self.bodies));self.rows[name]['mode']='100755';self.rows[name]['baseline']['mode']='100755';self.write(mode=name)
        with self.assertRaisesRegex(ValueError,'baseline Git tree'):M.validate(self.release,self.manifest)

    def test_tar_mode_and_extra_and_duplicate_members_rejected(self):
        name=next(iter(self.bodies))
        for kwargs in(dict(mode=name),dict(extra=name.rsplit('/',1)[0]+'/extra.txt'),dict(duplicate=name)):
            self.write(**kwargs)
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):M.validate(self.release,self.manifest)

    def test_missing_or_wrong_gitlink_child_rejected(self):
        for child in('absent',self.roots[1]['name']):
            data=copy.deepcopy(self.manifest);data['roots'][0]['submodules']=[dict(path='child',commit='1'*40,root=child)]
            with self.subTest(child=child),self.assertRaisesRegex(ValueError,'Gitlink'):M.validate(self.release,data)

    def test_complete_gitlink_child_is_read_and_authenticated(self):
        parent=self.roots[0];child=self.roots[5];parent['submodules']=[dict(path='child',commit=child['commit'],root=child['name'])]
        baseline={name.split('/',1)[1]:row['baseline']for name,row in self.rows.items()if name.startswith(parent['name']+'/')}
        baseline['child']=dict(mode='160000',blob=child['commit']);tree=M.P.baseline_tree(baseline);raw=('tree '+tree+'\n\nSynthetic parent with real Gitlink\n').encode()
        parent.update(tree=tree,commit=M.git_object('commit',raw),commitObjectBase64=base64.b64encode(raw).decode());self.policy[0].update(commit=parent['commit'],tree=tree)
        result=M.validate(self.release,self.manifest);self.assertEqual(result['completeGitTrees'],9)

    def test_installer_guard_failure_is_not_accepted_or_replaced(self):
        self.installer.side_effect=ValueError('original six-patch guard rejected')
        with self.assertRaisesRegex(ValueError,'six-patch guard'):M.validate(self.release,self.manifest)

    def test_additional_gitlink_child_outside_nine_origins_is_required(self):
        raw=b'Additional original Gitlink child\n';name='extra-child';relative='child.txt';blob=M.git_object('blob',raw)
        baseline={relative:dict(mode='100644',blob=blob)};tree=M.P.baseline_tree(baseline);commit_raw=('tree '+tree+'\n\nChild\n').encode();commit=M.git_object('commit',commit_raw)
        child=dict(name=name,kind='git',role='source-for-serviced-imported-package',commit=commit,tree=tree,commitObjectBase64=base64.b64encode(commit_raw).decode(),files=1,deleted=[],submodules=[])
        self.roots.append(child);self.bodies[name+'/'+relative]=raw;self.rows[name+'/'+relative]=dict(path=name+'/'+relative,mode='100644',baseline=baseline[relative],**M.D.fingerprint(raw))
        parent=self.roots[0];parent['submodules']=[dict(path='child',commit=commit,root=name)]
        original={n.split('/',1)[1]:row['baseline']for n,row in self.rows.items()if n.startswith(parent['name']+'/')};original['child']=dict(mode='160000',blob=commit)
        tree=M.P.baseline_tree(original);raw=('tree '+tree+'\n\nParent\n').encode();parent.update(tree=tree,commit=M.git_object('commit',raw),commitObjectBase64=base64.b64encode(raw).decode());self.policy[0].update(commit=parent['commit'],tree=tree);self.write()
        result=M.validate(self.release,self.manifest);self.assertEqual((result['completeGitTrees'],result['archivedSourceFiles']),(10,14))
        child['role']='build-source'
        with self.assertRaisesRegex(ValueError,'child role'):M.validate(self.release,self.manifest)

    def test_oversized_file_aggregate_and_row_count_fail_before_archive(self):
        name=next(iter(self.bodies))
        for field,value in(('bytes',M.MAX_FILE+1),('bytes',-1)):
            self.rows[name][field]=value;self.write()
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'bounded actual'):M.validate(self.release,self.manifest)
        self.rows[name]['bytes']=len(self.bodies[name]);self.write()
        with patch.object(M,'MAX_BYTES',1),self.assertRaisesRegex(ValueError,'index budget'):M.validate(self.release,self.manifest)
        with patch.object(M,'MAX_INDEX_ROWS',1),self.assertRaisesRegex(ValueError,'row-count'):M.validate(self.release,self.manifest)

    def test_rebound_whole_archive_cannot_change_original_recipe(self):
        name='installer/source-0.txt';self.bodies[name]=b'wrong original installer recipe\n';self.rows[name].update(M.D.fingerprint(self.bodies[name]));self.write()
        with self.assertRaisesRegex(ValueError,'authored source file'):M.validate(self.release,self.manifest)

    def test_full_recipe_fingerprint_cannot_be_rebound(self):
        key=next(iter(self.files));self.files[key]['fingerprint']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'authored source file'):M.validate(self.release,self.manifest)

    def test_index_line_allocation_is_bounded(self):
        index=self.release/'sources/index.jsonl';index.write_bytes(b' '*65537+b'\n')
        self.manifest['index']=dict(path=index.name,**M.D.fingerprint(index.read_bytes()))
        with self.assertRaisesRegex(ValueError,'index row'):M.validate(self.release,self.manifest)

    def test_wrong_sdk_or_rid_rejected(self):
        for key,value in(('sdkVersion','6.0.136'),('targetRid','linux-x64')):
            data=copy.deepcopy(self.manifest);data[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'Distinct original SDK5'):M.validate(self.release,data)


if __name__=='__main__':unittest.main()
