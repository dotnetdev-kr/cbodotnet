import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_literal_dispositions as M


class LiteralSourceComposition(unittest.TestCase):
    def leaf(self):
        p=M.LITERAL.policy()
        return dict(kind=M.LITERAL.KIND,dataRoot=M.LITERAL.ROOT_NAME,
            products={name:dict(row,sourceBasis='closed-original-package-and-distinct-preferred-source-recipe')for name,row in p['products'].items()})

    def test_all126_original_literal_products_including_packs_and_templates(self):
        catalog=M.source_catalog(self.leaf())
        self.assertEqual(len(catalog),126)
        self.assertEqual(sum(row['canonicalPackageMember']['member']is None for row in catalog.values()),2)
        self.assertTrue(any(name.startswith('packs/')for name in catalog))
        self.assertTrue(any(name.startswith('templates/')for name in catalog))
        self.assertTrue(all(row['sourceCommit']is None and not row['localBuildClaimed']for row in catalog.values()))

    def test_missing_or_extra_source_product_rejected(self):
        for mode in('missing','extra'):
            leaf=self.leaf();name=next(iter(leaf['products']))
            if mode=='missing':leaf['products'].pop(name)
            else:leaf['products']['sdk/5.0.214/unreviewed.dll']=copy.deepcopy(leaf['products'][name])
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'All126'):M.source_catalog(leaf)

    def test_changed_full_fingerprint_source_role_or_member_rejected(self):
        for mode in('sha512','sourceRole','member'):
            leaf=self.leaf();row=next(iter(leaf['products'].values()))
            if mode=='sha512':row['fingerprint']['sha512']='0'*128
            else:row[mode]='unreviewed'
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'All126'):M.source_catalog(leaf)

    def fixture(self):
        unknowns=[dict(kind='unmapped-managed-source',path='packs/reference.dll'),
            dict(kind='unmapped-package-source',artifact='package-'+'a'*64,originalRepository=None),
            dict(kind='unmapped-managed-source',path='sdk/5.0.214/Microsoft.ApplicationInsights.dll')]
        proof=dict(unknowns=unknowns)
        base=dict(rawEmitterUnknowns=copy.deepcopy(unknowns),sourceDispositions={'existing/path':{'sourceCorrespondenceValidated':True}},
            independentlyResolvedRawUnknowns=[],pendingSourceGates=[])
        additions={'packs/reference.dll':dict(sourceCorrespondenceValidated=True,actualSupplierBindingValidated=True,
            actualProducerConsumptionValidated=False)}
        return proof,base,additions,{'a'*64:{}}

    def test_raw_unknown_rows_and_other_dispositions_are_preserved(self):
        proof,base,additions,packages=self.fixture();before=copy.deepcopy(proof)
        result=M.combine_correspondence(proof,base,additions,packages)
        self.assertEqual(proof,before);self.assertEqual(result['rawEmitterUnknowns'],before['unknowns'])
        self.assertEqual(len(result['independentlyResolvedRawUnknowns']),2)
        self.assertEqual(result['unresolvedRawUnknowns'][0]['rawUnknown']['path'],'sdk/5.0.214/Microsoft.ApplicationInsights.dll')
        self.assertEqual(result['sourceDispositions']['existing/path'],base['sourceDispositions']['existing/path'])
        self.assertFalse(result['actualProducerConsumptionValidated']);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_raw_repository_absence_may_not_be_rewritten(self):
        proof,base,additions,packages=self.fixture();base['rawEmitterUnknowns'][1]['originalRepository']={'commit':'inferred'}
        with self.assertRaisesRegex(ValueError,'identical original'):M.combine_correspondence(proof,base,additions,packages)

    def test_literal_role_may_not_replace_existing_product_role(self):
        proof,base,additions,packages=self.fixture();base['sourceDispositions'].update(copy.deepcopy(additions))
        with self.assertRaisesRegex(ValueError,'Distinct SDK5 literal'):M.combine_correspondence(proof,base,additions,packages)

    def test_duplicate_resolution_indexes_are_rejected(self):
        proof,base,additions,packages=self.fixture();base['independentlyResolvedRawUnknowns']=[dict(rawUnknownIndex=0),dict(rawUnknownIndex=0)]
        with self.assertRaisesRegex(ValueError,'Unique exact original'):M.combine_correspondence(proof,base,additions,packages)

    def test_unverified_supplier_or_consumption_promotion_cannot_resolve_raw_unknown(self):
        for key,value in [('actualSupplierBindingValidated',False),('actualProducerConsumptionValidated',True)]:
            proof,base,additions,packages=self.fixture();additions['packs/reference.dll'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'without a producer-consumption claim'):
                M.combine_correspondence(proof,base,additions,packages)

    def test_package_kind_or_raw_repository_flip_rejected_before_byte_read(self):
        source=next(iter(M.source_catalog(self.leaf()).values()));sha=source['canonicalPackageMember']['packageSha256'];p=M.LITERAL.policy()['packages'][sha]
        row=dict(path='imported-inputs/'+sha+'.nupkg',kind='managed-package',repository=p['originalRepository'],**p['fingerprint'])
        for mode in('kind','repository'):
            changed=copy.deepcopy(row);changed[mode]='reclassified'
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'canonical named raw'):
                M.actual_supplier(Path('.'),dict(artifacts={'package-'+sha:changed}),source)


if __name__=='__main__':unittest.main()
