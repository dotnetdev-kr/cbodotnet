#!/usr/bin/env python3
"""Bounded compatibility-input and native verification policy checks."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('ci_legacy_verify',ROOT/'scripts/ci-legacy-verify.py')
V=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(V)


class LegacyVerificationTests(unittest.TestCase):
    def test_platform_manifest_binding_accepts_real_index_alias(self):
        digest='sha256:'+'a'*64
        row={'Architecture':'arm64','Os':'linux','Digest':digest,
             'RepoDigests':['docker.io/library/ubuntu@'+digest,'docker.io/library/ubuntu@sha256:'+'b'*64]}
        self.assertEqual(V.manifest_reference(row,'ubuntu'),'docker.io/library/ubuntu@'+digest)
        for change in [{'Architecture':'amd64'},{'Digest':None},{'RepoDigests':[]},
                       {'RepoDigests':['docker.io/library/ubuntu@'+digest]*2}]:
            with self.subTest(change=change),self.assertRaises(ValueError): V.manifest_reference(dict(row,**change),'ubuntu')

    def test_version_specific_native_rids_are_explicit(self):
        self.assertEqual(V.expected_rid('core31','ubuntu22'),'ubuntu.22.04-arm64')
        for family in V.FAMILIES:
            for name,_,_,_,_ in V.USERLANDS:
                if (family,name)!=('core31','ubuntu22'): self.assertEqual(V.expected_rid(family,name),'linux-arm64')

    def valid(self):
        return dict(verificationStatus='passed',sdkVersion='5.0.214',framework='net5.0',reportedRid='linux-arm64',
                    functionalChecks=dict.fromkeys(V.FUNCTIONS,'passed'),
                    archive={'sha256':'a'*64,'sizeBytes':123,'sdkContentMatched':True},
                    abi={'elfFileCount':22,'machines':{'AArch64':22},'glibcCeilingPassed':True,'glibcCeiling':'2.23',
                         'symbolicGlibcRequirements':[],'maximumRequiredVersions':{'GLIBC':'2.17','GLIBCXX':'3.4.21','CXXABI':'1.3.7'}})

    def test_all_six_checks_same_archive_and_native_abi_are_required(self):
        original=self.valid(); archive={'sha256':'a'*64,'bytes':123}
        V.check_verification('net5','debian13',original,archive)
        mutations=[]
        bad=copy.deepcopy(original); bad['functionalChecks'].pop('rsaSha256SignAndVerify'); mutations.append(bad)
        bad=copy.deepcopy(original); bad['archive']['sdkContentMatched']=False; mutations.append(bad)
        bad=copy.deepcopy(original); bad['archive']['sha256']='b'*64; mutations.append(bad)
        bad=copy.deepcopy(original); bad['abi']['machines']={'Advanced Micro Devices X86-64':22}; mutations.append(bad)
        bad=copy.deepcopy(original); bad['abi']['maximumRequiredVersions']['GLIBC']='2.27'; mutations.append(bad)
        bad=copy.deepcopy(original); bad['abi']['maximumRequiredVersions']['GLIBCXX']='3.4.22'; mutations.append(bad)
        for index,bad in enumerate(mutations):
            with self.subTest(index=index),self.assertRaises(ValueError): V.check_verification('net5','debian13',bad,archive)

    def test_public_and_internal_help_have_no_side_effects(self):
        for args in [['--help'],['__export','--help'],['__verify','--help']]:
            with self.subTest(args=args):
                result=subprocess.run([sys.executable,str(ROOT/'scripts/ci-legacy-verify.py'),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
