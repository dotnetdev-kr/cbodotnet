import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_compiler_source_inputs as V


class CompilerOriginalSourceInputs(unittest.TestCase):
    def test_original_constructor_is_distinct_and_fixed(self):
        V.constructor_policy()
        self.assertEqual(V.C.SDK, '5.0.214')
        self.assertEqual(V.CONSTRUCTOR_SHA256, '4ed1f6d7395588d76249a848511899a7e567f8d3ea6ff2d38cb99a7c6f95885e')

    def test_modified_constructor_cannot_change_asset_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'constructor.py';path.write_bytes(b'changed')
            with patch.object(V.C,'__file__',str(path)),self.assertRaisesRegex(ValueError,'Exact distinct SDK5'):V.constructor_policy()

    def test_git_object_hash_includes_kind_and_raw_length(self):
        self.assertEqual(V.git_object('blob',b'test\n'),'9daeafb9864cf43055ae93beb0afd6c7d144bfa4')
        self.assertNotEqual(V.git_object('blob',b'test\n'),V.git_object('commit',b'test\n'))

    def fixture(self):
        raw=b'tree '+b'1'*40+b'\n\nOriginal commit\n';commit=V.git_object('commit',raw)
        row=dict(name='source',kind='git',role='build-source',commit=commit,tree='1'*40,commitObjectBase64=base64.b64encode(raw).decode(),deleted=[],exclude=[])
        return raw,row,{'fixture':('https://github.com/original/source',commit)}

    def test_commit_object_binds_actual_tree_instead_of_claimed_commit_string(self):
        raw,row,policy=self.fixture()
        with patch.dict(V.C.SOURCES,policy,clear=True):
            self.assertEqual(V.source_roots(dict(roots=[row]))['fixture'],row)
            for changed in (dict(row,tree='2'*40),dict(row,commitObjectBase64=base64.b64encode(raw+b'forged').decode())):
                with self.subTest(changed=changed),self.assertRaises(ValueError):V.source_roots(dict(roots=[changed]))

    def test_source_exclusions_deletions_and_generated_data_roles_are_rejected(self):
        raw,row,policy=self.fixture()
        with patch.dict(V.C.SOURCES,policy,clear=True):
            for field,value in [('exclude',['src']),('deleted',['License.txt']),('role','generated-compiler-source')]:
                with self.subTest(field=field),self.assertRaisesRegex(ValueError,'Unexcluded complete'):V.source_roots(dict(roots=[dict(row,**{field:value})]))
            with self.assertRaises(ValueError):V.source_roots(dict(roots=[row,row]))

    def test_derived_input_tree_must_have_its_exact_data_role(self):
        record=dict(sdkVersion='5.0.214',architecture='aarch64')
        for row in (dict(name=V.ROOT_NAME,kind='git',role=V.ROLE),dict(name=V.ROOT_NAME,kind='tree',role='fake-primary-source')):
            with self.subTest(row=row),self.assertRaisesRegex(ValueError,'Distinct complete derived'):V.validate(Path('/unused'),dict(roots=[row]),record,{})

    def test_actual_source_mode_must_equal_authenticated_original_git_mode(self):
        import json
        with tempfile.TemporaryDirectory()as tmp:
            release=Path(tmp);(release/'sources').mkdir();row=dict(path='compiler-fsharp/License.txt',mode='100755',baseline=dict(mode='100644',blob='a'*40))
            (release/'sources/source-index.jsonl').write_text(json.dumps(row)+'\n')
            with patch.object(V,'source_roots',return_value={'fsharp':dict(name='compiler-fsharp')}),self.assertRaisesRegex(ValueError,'original Git blob and mode'):
                V.archived_sources(release,dict(index=dict(path='source-index.jsonl')))


if __name__=='__main__':unittest.main()
