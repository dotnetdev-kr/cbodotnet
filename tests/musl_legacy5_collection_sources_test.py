import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_legacy5_collection_sources as S


class CollectionCorrespondingSources(unittest.TestCase):
    def test_extra_source_policy_is_sdk5_and_exact_original_publisher_revisions(self):
        rows=S.required_sources();self.assertEqual(len(rows),4);self.assertEqual(len(S.EXTERNAL_LINKS),6)
        self.assertEqual({row['commit']for row in rows},{S.EXTERNAL_COMMIT,'e5ac9a8473dfdefb8fe2cddae433a9aaa94a5b37','d50b912e9948472e122cfaf24ffeebbf77032806','eccb0828682858d8daa029ba29adce07fd70d9a7'})
        self.assertNotIn('4ab34b0461fb595805d092a46a58f35f66c84d6a',{row['commit']for row in rows})

    def test_wrong_sdk_is_rejected_before_source_mutation(self):
        clone=Mock()
        with self.assertRaises(ValueError):S.register('6.0.136',{},clone,Mock(),Path('/unused/report.json'))
        with self.assertRaises(ValueError):S.register_extra('6.0.136',{},clone,Mock(),Path('/unused/report.json'))
        clone.assert_not_called()

    def test_duplicate_existing_commit_is_rejected_without_relabelling_roots(self):
        with tempfile.TemporaryDirectory()as tmp:
            rows=S.required_sources();sources={name:dict(name=name,kind='git',expectedCommit=rows[0]['commit'],path=tmp+'/'+name,role='build-source')for name in ('one','two')};before=copy.deepcopy(sources);clone=Mock()
            with patch.object(S,'expand',side_effect=lambda*a:None),self.assertRaisesRegex(ValueError,'Ambiguous original'):S.register_extra('5.0.214',sources,clone,None,Path(tmp)/'report.json')
            self.assertEqual(sources,before);clone.assert_not_called()

    def test_report_cannot_be_written_into_existing_compiler_source(self):
        with tempfile.TemporaryDirectory()as tmp:
            source=Path(tmp)/'compiler';source.mkdir();sources={'compiler':dict(name='compiler',kind='git',path=str(source),role='build-source')};clone=Mock()
            with self.assertRaisesRegex(ValueError,'must not modify an existing Git'):S.register_extra('5.0.214',sources,clone,Mock(),source/'report.json')
            clone.assert_not_called();self.assertEqual(list(source.iterdir()),[])

    def test_a_new_source_clone_cannot_overwrite_or_nest_in_existing_compiler_root(self):
        with tempfile.TemporaryDirectory()as tmp:
            source=Path(tmp)/'compiler';source.mkdir();sources={'compiler':dict(name='compiler',kind='git',path=str(source),role='build-source')}
            def clone(name,repository,commit):sources[name]=dict(name=name,kind='git',expectedCommit=commit,path=str(source/'replacement'))
            with patch.object(S,'expand',side_effect=lambda*a:None),self.assertRaisesRegex(ValueError,'must not overwrite an existing compiler'):S.register_extra('5.0.214',sources,clone,None,Path(tmp)/'report.json')
            self.assertEqual(sources['compiler']['role'],'build-source');self.assertEqual(list(source.iterdir()),[])

    def test_primary_and_extra_materializers_are_explicit_distinct_steps(self):
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp)/'collection.json';sources={};clone=Mock();expand=Mock()
            with patch.object(S.PRIMARY,'register')as primary,patch.object(S,'register_extra',return_value={'status':'checked'})as extra:
                self.assertEqual(S.register('5.0.214',sources,clone,expand,path),{'status':'checked'})
                primary.assert_called_once_with('5.0.214',sources,clone,expand,path.with_name('collection-primary.json'));extra.assert_called_once_with('5.0.214',sources,clone,expand,path)

    def test_fresh_small_git_materialization_preserves_existing_compiler_checkout(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp)
            def command(*args):return subprocess.check_output(['git',*map(str,args)],stderr=subprocess.DEVNULL).decode().strip()
            def seed(name,text):
                path=root/name;path.mkdir();command('init',path);(path/'.gitattributes').write_text('*.cmd text eol=crlf\n');(path/'original.cmd').write_bytes(text);(path/'source.cpp').write_bytes(b'int original_source;\n');command('-C',path,'add','.');command('-C',path,'-c','user.name=Fixture','-c','user.email=fixture@invalid','commit','-m','Original fixture source');return path,command('-C',path,'rev-parse','HEAD')
            original,compiler_commit=seed('compiler-seed',b'original compiler\n');compiler=root/'compiler';command('clone','--no-hardlinks','--no-local',original,compiler)
            preferred,commit=seed('preferred-seed',b'original preferred\n');tree=command('-C',preferred,'rev-parse','HEAD^{tree}')
            before=(compiler/'original.cmd').read_bytes();cpp=(compiler/'source.cpp').read_bytes();self.assertIn(b'\r\n',before)
            sources={'compiler':dict(name='compiler',kind='git',path=str(compiler),expectedCommit=compiler_commit,role='build-source')}
            def clone(name,repository,pin):
                path=root/name;command('clone','--no-hardlinks','--no-local',repository,path);sources[name]=dict(name=name,kind='git',path=str(path),expectedCommit=pin)
            spec=importlib.util.spec_from_file_location('sdk5_source_fixture_packer',Path(S.__file__).with_name('package-used-source.py'));packer=importlib.util.module_from_spec(spec);spec.loader.exec_module(packer)
            policy=[dict(name='extra',repository=str(preferred),commit=commit,tree=tree,role=S.ROLE)]
            with patch.object(S,'required_sources',return_value=policy),patch.object(S,'EXTERNAL_COMMIT',commit),patch.object(S,'EXTERNAL_LINKS',{}):
                result=S.register_extra('5.0.214',sources,clone,packer.expand_submodules,root/'report.json')
            self.assertEqual((compiler/'original.cmd').read_bytes(),before);self.assertEqual((compiler/'source.cpp').read_bytes(),cpp);self.assertEqual(sources['compiler']['role'],'build-source')
            self.assertEqual((root/'extra/original.cmd').read_bytes(),b'original preferred\n');self.assertEqual(sources['extra']['role'],S.ROLE);self.assertEqual(len(result['freshMaterialization']),1)


if __name__=='__main__':unittest.main()
