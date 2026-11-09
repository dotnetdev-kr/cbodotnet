"""Tiny local Git fixtures only; no public clone, SDK or source archive."""
import copy,json,os
from pathlib import Path
import shutil,subprocess,sys,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_generated_collection as M


class ClosedPolicy(unittest.TestCase):
    def test_nine_exact_origins_four_prior_roots_and_honest_budget(self):
        p=M.policy();rows=M.required_sources()
        self.assertEqual(len(rows),9);self.assertEqual(sum(r['requirePreviouslyRegistered']for r in rows),4)
        self.assertEqual(len({(M.origin(r['repository']),r['commit'])for r in rows}),9)
        self.assertTrue(p['futureAcquisitionBudgetIsProposedAndCallerEnforced'])
        self.assertFalse(p['collectionCallbackGuaranteesAcquisitionBounds']);self.assertFalse(p['sourceAdmissionAllowed'])

    def test_msbuild_short_basis_and_json_publisher_source_are_retained(self):
        rows={r['dataRole']:r for r in M.required_sources()}
        self.assertEqual(rows['msbuild157']['prefix'],'ac19036b0d')
        self.assertIn('short-Git-prefix',rows['msbuild157']['identityBasis'])
        self.assertEqual(rows['json9-publisher']['commit'],'e5ac9a8473dfdefb8fe2cddae433a9aaa94a5b37')
        self.assertEqual(rows['protected-data']['tree'],'c19049409e3596a11e85b8426aa63469d2c94e17')

    def test_origin_normalizes_only_github_case_and_final_git(self):
        self.assertEqual(M.origin('https://github.com/Example/Source.git'),M.origin('https://github.com/example/source'))
        for url in ('/local/source','git@github.com:Example/Source','https://token@github.com/Example/Source',
                    'https://github.com/Example/Source?ref=x','https://github.com/Other/Source/extra'):
            with self.subTest(url=url),self.assertRaises(ValueError):M.origin(url)


class TinyGitRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures=tempfile.TemporaryDirectory(prefix='cbodotnet-generated-source-fixture-');cls.base=Path(cls.fixtures.name).resolve()
        cls.child=cls.make_repo('child','https://github.com/fixture/child')
        cls.parent=cls.make_repo('parent','https://github.com/fixture/parent',child=cls.child)
        cls.other=cls.make_repo('other','https://github.com/fixture/other')
        cls.peak_fixture_bytes=sum(p.stat().st_size for p in cls.base.rglob('*')if p.is_file())
        assert cls.peak_fixture_bytes<2*1024**2

    @classmethod
    def tearDownClass(cls):
        print('tinyLocalGitFixturePeakBytes='+str(cls.peak_fixture_bytes))
        cls.fixtures.cleanup()

    @classmethod
    def make_repo(cls,name,url,child=None):
        root=cls.base/name;root.mkdir()
        def git(*args):return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.PIPE)
        git('init','-q');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
        git('config','core.autocrlf','false');git('config','remote.origin.url',url)
        (root/'source.txt').write_bytes(('original '+name+'\n').encode());git('add','source.txt')
        if child:
            (root/'.gitmodules').write_text('[submodule "child"]\n\tpath = deps/child\n\turl = ../child.git\n')
            git('add','.gitmodules');git('update-index','--add','--cacheinfo','160000,'+child['commit']+',deps/child')
        git('commit','-qm','tiny source')
        return dict(template=root,repository=url,commit=git('rev-parse','HEAD').decode().strip(),tree=git('rev-parse','HEAD^{tree}').decode().strip())

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='cbodotnet-generated-source-case-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.workspace=self.root/'workspace';self.work=self.workspace/'work';self.work.mkdir(parents=True)
        self.report=self.root/'reports/generated.json';self.sources={};self.clones=[]

    def tearDown(self):
        retained=sum(p.stat().st_size for root in(self.base,self.root)for p in root.rglob('*')if p.is_file())
        type(self).peak_fixture_bytes=max(type(self).peak_fixture_bytes,retained)
        self.assertLess(retained,8*1024**2)

    def install(self,name,repo,role='original-compiler-role'):
        target=self.work/name;shutil.copytree(repo['template'],target)
        if repo is self.parent:shutil.copytree(self.child['template'],target/'deps/child')
        self.sources[name]=dict(name=name,path=str(target),kind='git',expectedCommit=repo['commit'],role=role,extra={'preserve':True})
        return target

    def expected(self,repo,name='generated-source',prior=False):
        return dict(dataRole=name,name=name,repository=repo['repository'],commit=repo['commit'],tree=repo['tree'],
            requirePreviouslyRegistered=prior,identityBasis='tiny-real-Git-fixture')

    def clone(self,name,repository,commit):
        repo=next(r for r in(self.child,self.parent,self.other)if r['repository']==repository and r['commit']==commit)
        self.clones.append(name);return self.install(name,repo,role='new-clone-default')

    def expand(self,rows):
        for row in list(rows):
            if row['expectedCommit']==self.parent['commit']:
                name=row['name']+'-child'
                if not any(r['name']==name for r in rows):
                    child=dict(name=name,path=str(Path(row['path'])/'deps/child'),kind='git',expectedCommit=self.child['commit'])
                    if row.get('role')==M.ROLE:child['role']=M.ROLE
                    rows.append(child)
        return rows

    def run_registration(self,expected,*,expand=None,clone=None,report=None):
        with patch.object(M,'required_sources',return_value=expected):
            return M.register('5.0.214',self.sources,clone or self.clone,expand or self.expand,report or self.report,workspace=self.workspace)

    def test_existing_dirty_compiler_source_and_role_are_not_materialized(self):
        path=self.install('compiler',self.child);file=path/'source.txt';file.write_bytes(b'original reviewed compiler edit\r\n')
        before=copy.deepcopy(self.sources);mode=file.stat().st_mode
        with patch.object(M.C.PRIMARY,'materializer',return_value=type('NoOldWrites',(),{'exact_git_bytes':lambda *_:self.fail('old source materialized')})()):
            result=self.run_registration([self.expected(self.child,prior=True)])
        self.assertEqual(self.sources,before);self.assertEqual(file.read_bytes(),b'original reviewed compiler edit\r\n');self.assertEqual(file.stat().st_mode,mode)
        self.assertFalse(self.clones);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_existing_actual_gitlink_satisfies_later_origin_without_clone(self):
        self.install('compiler-parent',self.parent)
        result=self.run_registration([self.expected(self.parent,prior=True),self.expected(self.child)])
        self.assertFalse(self.clones);self.assertEqual(len(result['actualGitlinks']),1)
        self.assertEqual(result['actualGitlinks'][0]['originalUrl'],'../child.git')
        self.assertEqual(result['selectedSources'][1]['name'],'compiler-parent-child')
        self.assertNotIn('role',self.sources['compiler-parent-child'])

    @unittest.skipIf(os.name=='nt','POSIX raw-Git type/mode materialization')
    def test_fresh_parent_and_gitlink_materialize_once_with_explicit_roles(self):
        result=self.run_registration([self.expected(self.parent,'fresh-parent'),self.expected(self.child,'fresh-child')])
        self.assertEqual(self.clones,['fresh-parent']);self.assertEqual(len(result['freshMaterialization']),2)
        self.assertEqual({row['role']for row in self.sources.values()},{M.ROLE})
        self.assertTrue(all(row['actualGitBytesAndModesChecked']for row in result['freshSourceMeasurements']))
        self.assertTrue(result['sourceAcquisitionBudgetProposedAndCallerEnforced']);self.assertFalse(result['collectionCallbackGuaranteesAcquisitionBounds'])

    @unittest.skipIf(os.name=='nt','POSIX raw-Git type/mode materialization')
    def test_source_identity_dedup_selects_one_root_for_two_data_roles(self):
        first=self.expected(self.child,'one');second=dict(first,dataRole='another-consumer')
        result=self.run_registration([first,second]);self.assertEqual(self.clones,['one'])
        self.assertEqual([r['name']for r in result['selectedSources']],['one','one']);self.assertEqual(len(result['freshMaterialization']),1)

    def test_wrong_recorded_head_rejects_before_clone(self):
        self.install('old',self.child);self.sources['old']['expectedCommit']='0'*40
        with self.assertRaisesRegex(ValueError,'HEAD differs'):self.run_registration([self.expected(self.child)])
        self.assertFalse(self.clones)

    def test_same_commit_wrong_actual_origin_rejects_before_clone(self):
        path=self.install('old',self.child);M.git(path,'config','remote.origin.url','https://github.com/other/mirror')
        with self.assertRaisesRegex(ValueError,'conflicting actual origin'):self.run_registration([self.expected(self.child)])
        self.assertFalse(self.clones)

    def test_wrong_pinned_tree_rejects(self):
        self.install('old',self.child);expected=self.expected(self.child);expected['tree']='0'*40
        with self.assertRaisesRegex(ValueError,'origin/HEAD/tree'):self.run_registration([expected])

    def test_ambiguous_physical_roots_reject(self):
        self.install('old-a',self.child);self.install('old-b',self.child)
        with self.assertRaisesRegex(ValueError,'Ambiguous actual'):self.run_registration([self.expected(self.child)])

    def test_required_prior_source_never_silently_clones(self):
        with self.assertRaisesRegex(ValueError,'prior primary'):self.run_registration([self.expected(self.child,prior=True)])
        self.assertFalse(self.clones)

    def test_occupied_fresh_name_or_path_rejects(self):
        (self.work/'taken').mkdir()
        with self.assertRaisesRegex(ValueError,'already occupied'):self.run_registration([self.expected(self.child,'taken')])
        self.assertFalse(self.clones)

    def test_report_inside_existing_or_future_source_rejects_before_materializer(self):
        old=self.install('old',self.other)
        for report in(old/'captured.json',self.work/'future/captured.json'):
            with self.subTest(report=report),self.assertRaisesRegex(ValueError,'report must'):
                self.run_registration([self.expected(self.child,'future')],report=report)
        self.assertFalse(self.clones)

    def test_report_inside_new_expanded_root_rejects_before_materializer(self):
        extra=self.install('extra',self.other);row=self.sources.pop('extra');report=extra/'captured.json'
        def expanded(rows):return rows+[copy.deepcopy(row)]
        with self.assertRaisesRegex(ValueError,'report must remain'):self.run_registration([],expand=expanded,report=report)
        self.assertFalse(report.exists())

    def test_expand_cannot_relabel_original_source_and_preserves_input_metadata(self):
        self.install('old',self.child);before=copy.deepcopy(self.sources)
        def changed(rows):rows[0]['role']=M.ROLE;return rows
        with self.assertRaisesRegex(ValueError,'records/paths/roles'):self.run_registration([self.expected(self.child)],expand=changed)
        self.assertEqual(self.sources,before);self.assertFalse(self.clones)

    def test_missing_or_wrong_gitlink_physical_child_rejects(self):
        parent=self.install('old',self.parent)
        with self.assertRaisesRegex(ValueError,'physical Gitlink child'):
            self.run_registration([self.expected(self.parent)],expand=lambda rows:rows)
        M.git(parent/'deps/child','config','remote.origin.url','https://github.com/other/child')
        with self.assertRaisesRegex(ValueError,'physical Gitlink child'):
            self.run_registration([self.expected(self.parent)])

    def test_clone_returning_unexpected_source_path_rejects_without_report(self):
        def wrong(name,repository,commit):
            path=self.clone(name,repository,commit);return path.parent
        with self.assertRaisesRegex(ValueError,'exact fresh physical'):self.run_registration([self.expected(self.child)],clone=wrong)
        self.assertFalse(self.report.exists())

    def test_clone_callback_cannot_change_unrelated_old_origin_before_materializer(self):
        old=self.install('unrelated-old',self.other)
        def changed(name,repository,commit):
            result=self.clone(name,repository,commit)
            M.git(old,'config','remote.origin.url','https://github.com/fixture/changed-origin')
            return result
        with patch.object(M.C.PRIMARY,'materializer',side_effect=AssertionError('Must reject before materializer')):
            with self.assertRaisesRegex(ValueError,'actual source origin/HEAD/tree'):
                self.run_registration([self.expected(self.child)],clone=changed)
        self.assertFalse(self.report.exists())

    def test_initial_expansion_cannot_change_old_actual_origin(self):
        old=self.install('old',self.child)
        def changed(rows):
            M.git(old,'config','remote.origin.url','https://github.com/fixture/changed-origin');return rows
        with self.assertRaisesRegex(ValueError,'actual source origin/HEAD/tree'):
            self.run_registration([self.expected(self.child,prior=True)],expand=changed)
        self.assertFalse(self.clones);self.assertFalse(self.report.exists())

    @unittest.skipIf(os.name=='nt','POSIX fresh raw-Git mode verification')
    def test_materializer_cannot_change_old_origin_before_report(self):
        old=self.install('unrelated-old',self.other);original=M.C.PRIMARY.materializer()
        class Changed:
            def exact_git_bytes(inner,row):
                result=original.exact_git_bytes(row)
                M.git(old,'config','remote.origin.url','https://github.com/fixture/changed-origin')
                return result
        with patch.object(M.C.PRIMARY,'materializer',return_value=Changed()):
            with self.assertRaisesRegex(ValueError,'actual source origin/HEAD/tree'):
                self.run_registration([self.expected(self.child)])
        self.assertFalse(self.report.exists())

    @unittest.skipIf(os.name=='nt','POSIX original source-mode rejection')
    def test_same_blob_executable_mode_forgery_rejects_after_raw_materializer(self):
        def wrong_mode(name,repository,commit):
            path=self.clone(name,repository,commit);(path/'source.txt').chmod(0o755);return path
        with self.assertRaisesRegex(ValueError,'type/mode'):self.run_registration([self.expected(self.child)],clone=wrong_mode)
        self.assertFalse(self.report.exists())

    @unittest.skipIf(os.name=='nt','POSIX symlink')
    def test_redirected_source_root_rejects(self):
        real=self.root/'real';shutil.copytree(self.child['template'],real);link=self.work/'link';link.symlink_to(real,target_is_directory=True)
        self.sources['link']=dict(name='link',path=str(link),kind='git',expectedCommit=self.child['commit'])
        with self.assertRaisesRegex(ValueError,'unredirected'):self.run_registration([self.expected(self.child)])


if __name__=='__main__':unittest.main()
