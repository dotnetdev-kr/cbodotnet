"""Real tiny NPK envelopes composed with the original named constructor roles."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_construction_inputs as C


def fixture_module(name):
    spec=importlib.util.spec_from_file_location('raw_composition_'+name,ROOT/'tests'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


CONSTRUCTOR=fixture_module('musl_legacy5_construction_inputs_test.py')
PACKAGES=fixture_module('musl_legacy5_package_inputs_test.py')


class RawConstruction(unittest.TestCase):
    def setUp(self):
        self.raw=PACKAGES.PackageInputs('test_original_missing_repository_remains_unknown')
        self.raw.setUp();self.addCleanup(self.raw.doCleanups)
        named,self.roots,self.record,self.installer=CONSTRUCTOR.ConstructorBindings().fixture()
        self.record['sdkVersion']=C.SDK;self.proof=self.raw.proof
        self.proof['artifacts'].update(named)
        self.before=copy.deepcopy(self.proof)

    def validate(self):
        return C.validate_raw_artifact_roles(self.raw.release,self.record,self.proof,self.roots,self.raw.compiler,self.installer)

    def test_real_raw_package_without_repository_stays_literal_and_partial(self):
        result=self.validate();self.assertEqual(self.proof,self.before)
        self.assertEqual(result['originalPackageEnvelopes']['rawUnmappedPackageSources'],self.proof['unknowns'])
        for name in('sourceCorrespondenceValidated','actualProducerConsumptionValidated','sourceAdmissionAllowed','qualificationAllowed'):
            self.assertIs(result[name],False)

    def test_original_strict_entry_still_rejects_raw_missing_source(self):
        with self.assertRaisesRegex(ValueError,'artifact Git source'):
            C.validate_artifact_roles(self.proof['artifacts'],self.roots,{},self.record,self.installer)

    def test_changed_whole_real_package_is_rejected(self):
        path=self.raw.release/self.raw.row['retained'];path.write_bytes(path.read_bytes()+b'changed')
        with self.assertRaises(ValueError):self.validate()

    def test_self_consistent_fabricated_repository_is_rejected(self):
        repository=dict(type='git',commit='a'*40)
        row=copy.deepcopy(self.raw.row);row['repository']=repository;self.raw.write_report([row])
        self.proof['artifacts']['package-'+self.raw.sha]['repository']=repository
        with self.assertRaisesRegex(ValueError,'cache repository metadata'):self.validate()

    def test_raw_kind_cannot_impersonate_generated_source(self):
        self.proof['artifacts']['package-'+self.raw.sha]['kind']='generated-installer-data'
        with self.assertRaises(ValueError):self.validate()

    def test_raw_missing_source_cannot_be_filled_with_fabricated_git(self):
        self.roots['invented']=dict(kind='git',commit='a'*40)
        self.proof['artifacts']['package-'+self.raw.sha].update(sourceRoot='invented',sourceCommit='a'*40)
        with self.assertRaises(ValueError):self.validate()

    def test_raw_unknown_cannot_be_dropped(self):
        self.proof['unknowns']=[]
        with self.assertRaisesRegex(ValueError,'must remain unchanged'):self.validate()

    def test_named_original_runtime_role_is_still_required(self):
        self.proof['artifacts'].pop('runtime')
        with self.assertRaisesRegex(ValueError,'All named'):self.validate()

    def test_named_framework_pin_cannot_be_waived_by_package_validation(self):
        self.proof['artifacts']['aspnet']['sha512']='0'*128
        with self.assertRaisesRegex(ValueError,'independently pinned'):self.validate()

    def test_named_role_cannot_share_a_raw_package_path(self):
        self.proof['artifacts']['toolset']['path']=self.raw.row['retained']
        with self.assertRaisesRegex(ValueError,'exactly one role'):self.validate()

    def test_unnamed_managed_package_cannot_enter_the_named_roles(self):
        artifact=self.proof['artifacts'].pop('package-'+self.raw.sha)
        self.proof['artifacts']['renamed']=artifact
        with self.assertRaisesRegex(ValueError,'canonical named role'):self.validate()

    def test_raw_byte_entry_checks_actual_final_archive_identity_first(self):
        record=dict(self.record,sdk=dict(name='actual.tar.gz',bytes=1,sha256='1'*64,sha512='2'*128))
        proof=dict(self.proof,sdkArchive=dict(path='other.tar.gz',bytes=1,sha256='1'*64,sha512='2'*128))
        with self.assertRaisesRegex(ValueError,'exact final archive'):
            C.validate_raw_byte_inputs(self.raw.release,record,proof,self.roots,self.raw.compiler,self.installer)


if __name__=='__main__':unittest.main()
