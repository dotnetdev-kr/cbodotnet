import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_legacy5_translation_inputs as T


class OriginalSDK5Translations(unittest.TestCase):
    def fixture(self,culture='zh-Hans',contract=False):
        name='NuGet.VisualStudio.Contracts.resources'if contract else'NuGet.Commands.resources';worker=T.policy()
        binary=dict(assemblyName=name,assemblyVersion='5.9.1.8',culture=worker.METADATA_CULTURES.get(culture,culture),
            publicKeyBase64='original public key',publicKeyToken='b03f5f7f11d50a3a'if contract else'31bf3856ad364e35',nativeImports=['mscoree.dll'],resources=[])
        claimed={key:value for key,value in binary.items()if key!='resources'}
        claimed.update(fileVersion='',productVersion='5.9.1.8',managedResourceOnly=True,emptySatellite=True,methodBodies=0,extraTypes=0,fields=0,linkedResources=0)
        return binary,claimed,culture+'/'+name+'.dll',worker

    def test_distinct_original_sdk5_policy_and_complete_thirteen_culture_matrix(self):
        worker=T.policy();self.assertEqual((worker.SDK,worker.COMMIT),('5.0.214','d525b0e670f3b6cbd5c73a35f04730a9f658c852'))
        self.assertEqual(len(set(worker.relative_names())),286)
        self.assertEqual(set(worker.CULTURES),{'cs','de','es','fr','it','ja','ko','pl','pt-BR','ru','tr','zh-Hans','zh-Hant'})

    def test_original_uppercase_chinese_metadata_and_missing_file_version_are_preserved(self):
        binary,claimed,name,worker=self.fixture();T.satellite_identity(binary,claimed,name,worker)
        for key,value in [('culture','zh-Hans'),('fileVersion','5.9.1.8'),('productVersion','6.0.6.4'),('methodBodies',1),('fields',False)]:
            changed=dict(claimed,**{key:value})
            with self.subTest(key=key),self.assertRaises(ValueError):T.satellite_identity(binary,changed,name,worker)

    def test_visualstudio_contracts_uses_its_actual_distinct_strong_name(self):
        binary,claimed,name,worker=self.fixture(contract=True);T.satellite_identity(binary,claimed,name,worker)
        changed=dict(binary,publicKeyToken='31bf3856ad364e35');changed_claim=dict(claimed,publicKeyToken=changed['publicKeyToken'])
        with self.assertRaises(ValueError):T.satellite_identity(changed,changed_claim,name,worker)

    def schema(self,reverse=False):
        children='<element name="one"/><element name="two"/>'if not reverse else'<element name="two"/><element name="one"/>'
        return ('<schema xmlns="http://www.w3.org/2001/XMLSchema" targetNamespace="{0}" version="{0}" id="{0}">'+children+'</schema>').encode()

    def test_schema_comparison_preserves_child_order_attributes_and_real_text(self):
        original=self.schema();embedded=original.replace(b'><',b'>\n  <')
        self.assertEqual(T.schema_tree(original),T.schema_tree(embedded))
        self.assertNotEqual(T.schema_tree(original),T.schema_tree(self.schema(reverse=True)))
        for raw in (original.replace(b'{0}',b'fixed',1),b'<!DOCTYPE schema>'+original):
            with self.assertRaises(ValueError):T.schema_tree(raw)

    def test_schema_hash_plan_is_sdk5_specific_and_never_uses_sdk6_or_sdk7_values(self):
        self.assertEqual(T.SCHEMA_ORIGINAL,(10620,'b233d67e3879393f0b7fc7a77ea61ae6cf5fe0a1b705c56114c496dcf073dc50'))
        self.assertEqual(T.SCHEMA_EMBEDDED,(10720,'833d53f51d6d492da6e4a5e815819f52cbae94c56488ec1e0d88c1130c1b29de'))
        with self.assertRaises(ValueError):T.validate_schema_equivalence(self.schema(),self.schema())

    def test_wrong_official_sdk_is_rejected_before_tar_parsing(self):
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp)/'not-official.tar.gz';path.write_bytes(b'untrusted')
            with self.assertRaisesRegex(ValueError,'independently pinned SDK5'):T.comparison_inventory(path,dict(sdkVersion='5.0.214',architecture='aarch64'),set())

    def test_modified_extraction_worker_cannot_change_the_sdk5_product_universe(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);(root/'scripts').mkdir();(root/'scripts/musl-legacy5-nuget-resources.py').write_bytes(b'SDK="5.0.214"')
            with patch.object(T,'ROOT',root),self.assertRaisesRegex(ValueError,'Exact tracked original SDK5'):T.policy()


if __name__=='__main__':unittest.main()
