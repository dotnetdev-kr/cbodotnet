import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_consumption as M


class AppConsumption(unittest.TestCase):
    def tooling(self):
        package=dict(bytes=1,sha256='a'*64,sha512='b'*128)
        rows=[dict(id=name,version=version,**package) for name,version in M.tooling_packages().items()]
        commands=[dict(name=name,command=['original-command',M.PROPERTY],exitCode=0) for name in
            ('original-product-restore','original-product-build','original-redist-build-pack')]
        return dict(kind='legacy-musl-sdk5-source-tooling',status='passed',sdkVersion='5.0.214',packages=rows,commands=commands),package

    def test_closed25_package_role_and_property_fixture(self):
        tooling,package=self.tooling();self.assertEqual(M.validate_tooling(tooling,package)['version'],M.VERSION)

    def test_old24_feed_cannot_claim_new_app(self):
        tooling,package=self.tooling();tooling['packages']=[r for r in tooling['packages'] if r['id']!=M.ID.lower()]
        with self.assertRaisesRegex(ValueError,'closed25'):M.validate_tooling(tooling,package)

    def test_duplicate_case_variant_property_rejected(self):
        tooling,package=self.tooling();tooling['commands'][0]['command'].append(M.PROPERTY.lower())
        with self.assertRaisesRegex(ValueError,'controlled|override'):M.validate_tooling(tooling,package)

    def test_missing_override_on_one_process_rejected(self):
        tooling,package=self.tooling();tooling['commands'][1]['command']=['original-command']
        with self.assertRaisesRegex(ValueError,'One exact controlled'):M.validate_tooling(tooling,package)

    def test_feed_package_sha512_substitution_rejected(self):
        tooling,package=self.tooling();next(r for r in tooling['packages'] if r['id']==M.ID.lower())['sha512']='c'*128
        with self.assertRaisesRegex(ValueError,'actual genuine'):M.validate_tooling(tooling,package)

    def toolset(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);release=Path(temp.name)
        raw=b'genuine local product fixture';path=release/'toolset.zip'
        with zipfile.ZipFile(path,'w') as z:z.writestr('Microsoft.ApplicationInsights.dll',raw)
        fp=M.CE.fingerprint(path)
        proof=dict(artifacts=dict(toolset=dict(path='toolset.zip',kind='sdk-toolset',sourceRoot='sdk',sourceCommit=M.CE.COMMITS['sdk'],**fp)))
        product=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())
        return release,proof,product

    def test_exact_toolset_member_fixture(self):
        release,proof,product=self.toolset();self.assertEqual(M.validate_toolset_member(release,proof,product)['path'],'toolset.zip')

    def test_old_toolset_member_bytes_rejected(self):
        release,proof,product=self.toolset();product['sha256']='a'*64
        with self.assertRaisesRegex(ValueError,'genuine locally compiled'):M.validate_toolset_member(release,proof,product)

    def test_toolset_member_sha512_must_match(self):
        release,proof,product=self.toolset();product['sha512']='d'*128
        with self.assertRaisesRegex(ValueError,'genuine locally compiled'):M.validate_toolset_member(release,proof,product)

    def test_toolset_kind_flip_rejected(self):
        release,proof,product=self.toolset();proof['artifacts']['toolset']['kind']='generated-installer-data'
        with self.assertRaisesRegex(ValueError,'named actual'):M.validate_toolset_member(release,proof,product)

    def test_all_global_property_aliases_and_compound_overrides_rejected(self):
        target='MicrosoftApplicationInsightsPackageVersion'
        for extra in ('/p:'+target+'=old','-p:'+target+'=old','/property:'+target+'=old','-property:'+target+'=old',
                      '/p:Other=x;'+target+'=old','-property:Other=x;'+target+'=old','/rp:'+target+'=old'):
            tooling,package=self.tooling();tooling['commands'][0]['command'].append(extra)
            with self.subTest(extra=extra),self.assertRaises(ValueError):M.validate_tooling(tooling,package)

    def test_compound_only_target_assignment_is_not_the_controlled_literal(self):
        with self.assertRaises(ValueError):M.controlled_version_property(['dotnet','/p:Other=x;MicrosoftApplicationInsightsPackageVersion='+M.VERSION])

    def test_real_explicit_response_file_cannot_override_controlled_property(self):
        with tempfile.TemporaryDirectory()as directory:
            response=Path(directory)/'override.rsp'
            response.write_text('/p:MicrosoftApplicationInsightsPackageVersion=2.0.0\n',encoding='utf-8')
            M.controlled_version_property(['dotnet',M.PROPERTY])
            with self.assertRaisesRegex(ValueError,'response-file'):
                M.controlled_version_property(['dotnet',M.PROPERTY,'@'+str(response)])

    def csc_task(self,command_reference=None,task_references=None,extra=()):
        expected='/work/work/sdk/.packages/microsoft.applicationinsights/'+M.VERSION+'/'+M.MEMBER
        references=[expected] if task_references is None else task_references
        command_reference=expected if command_reference is None else command_reference
        args=['/bootstrap/dotnet','exec','/bootstrap/sdk/5.0.401/Roslyn/bincore/csc.dll','/noconfig']
        if command_reference:args+=['/reference:'+command_reference]
        args+=list(extra)
        return dict(events=[dict(kind='task-parameter',field='References',text=name) for name in references]
            +[dict(kind='command-line',text=' '.join(args))]),expected

    def test_actual_csc_reference_arguments_and_parameters_agree(self):
        task,expected=self.csc_task();self.assertEqual(M.csc_reference_binding(task,expected,required=True)['appReference'],expected)

    def test_old_unbound_and_absent_command_reference_rejected(self):
        for value in ('/old/Microsoft.ApplicationInsights.dll','/unrelated.dll',''):
            task,expected=self.csc_task(command_reference=value)
            with self.subTest(reference=value),self.assertRaises(ValueError):M.csc_reference_binding(task,expected,required=True)

    def test_app_command_reference_without_task_parameter_rejected(self):
        task,expected=self.csc_task(task_references=[])
        with self.assertRaises(ValueError):M.csc_reference_binding(task,expected)

    def test_absent_app_from_required_consumer_is_rejected(self):
        task,expected=self.csc_task(command_reference='',task_references=[])
        with self.assertRaises(ValueError):M.csc_reference_binding(task,expected,required=True)

    def test_reference_alias_list_duplicate_and_hidden_response_rejected(self):
        task,expected=self.csc_task()
        variants=[dict(reference='Alias='+expected),dict(reference=expected+',/other.dll'),
                  dict(extra=['/r:'+expected]),dict(extra=['@hidden.rsp'])]
        for variant in variants:
            task,expected=self.csc_task(command_reference=variant.get('reference'),extra=variant.get('extra',()))
            with self.subTest(variant=variant),self.assertRaises(ValueError):M.csc_reference_binding(task,expected,required=True)
        task,expected=self.csc_task();task['events'][-1]['text']=task['events'][-1]['text'].replace(' /noconfig','')
        with self.assertRaises(ValueError):M.csc_reference_binding(task,expected,required=True)

    def test_unrelated_aliased_reference_does_not_create_app_scope(self):
        task,expected=self.csc_task(command_reference='Alias=/unrelated.dll',task_references=['/unrelated.dll'])
        self.assertIsNone(M.csc_reference_binding(task,expected))

    def replay_fixture(self):
        result=[]
        for name,value in [('sdk','a'),('redist','b')]:
            result.append(dict(name=name,**{field:dict(path=name+'/'+field,bytes=10,sha256=value*64,sha512=value*128)
                for field in ('status','tasks','binlog')}))
        return result

    def test_two_distinct_replay_content_identities(self):
        self.assertEqual(set(M.distinct_consumer_replays(self.replay_fixture())),{'status','tasks','binlog'})

    def test_relabelled_same_process_content_cannot_supply_two_names(self):
        for field in ('status','tasks','binlog'):
            rows=self.replay_fixture();rows[1][field]=dict(rows[0][field],path='different-file-name/'+field)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'content identities'):M.distinct_consumer_replays(rows)


if __name__=='__main__':unittest.main()
