import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_legacy5_source_dispositions as A


class ImportedSourceDispositions(unittest.TestCase):
    def test_closed_package_union_is_from_distinct_sdk5_leaf_pins(self):
        pins,owners=A.package_pins();self.assertIn(A.F.PACKAGE_SHA,pins);self.assertIn(A.L.policy()['package']['sha256'],pins)
        self.assertEqual(set(owners),{'framework','localization','embedded','newtonsoft','cecil','unsafe','css'})
        self.assertTrue(all(set(fp)==set(A.CE.FP)for fp in pins.values()))

    def test_wrong_version_and_arbitrary_input_roles_fail_before_validation(self):
        with self.assertRaises(ValueError):A.validate_source_leaves(Path('/unused'),dict(sdkVersion='6.0.136'),{}, {})
        with self.assertRaises(ValueError):A.validate_source_leaves(Path('/unused'),dict(sdkVersion='5.0.214'),{},dict(packages={},newtonsoftDistributions={},originalSdkComparison={},extraPermission=True))

    def test_catalog_rejects_omitted_validator_and_duplicate_shipping_paths(self):
        with self.assertRaises(ValueError):A.source_catalog({})
        fp=A.fingerprint(b'original');leaf=dict(products={'sdk/5.0.214/component.dll':dict(fingerprint=fp,allowedPackageMembers=[])})
        with patch.object(A,'COUNTS',dict(embedded=1,newtonsoft=1)),self.assertRaisesRegex(ValueError,'One SDK5 source validator'):A.source_catalog(dict(embedded=leaf,newtonsoft=leaf))

    def test_unknowns_remain_raw_and_source_resolution_never_admits_a_producer(self):
        name='sdk/5.0.214/de/NuGet.Common.resources.dll';fp=A.fingerprint(b'original');unknowns=[dict(kind='unmapped-managed-source',path=name),dict(kind='unmapped-package-source',artifact='package-'+('1'*64))]
        proof=dict(kind='sdk5-musl-construction-proof',sdkVersion='5.0.214',unknowns=copy.deepcopy(unknowns),artifacts={},managedShipping=[dict(path=name,origin='imported-official-translation-data',sourceRoot='nuget',sourceCommit=A.T.COMMIT,packagePath=None,packageMember=None)])
        source=dict(path=name,sourceValidator='translations',fingerprint=fp,sourceRoot='nuget',sourceCommit=A.T.COMMIT,sourceDataRoot=A.T.ROOT_NAME,actualDerivedCompilerContainerRequired=False,allowedActualPackageMembers=[])
        with patch.object(A,'source_catalog',return_value={name:source}),patch.object(A,'package_pins',return_value=({},{})):
            result=A.derive_correspondence(Path('/unused'),proof,{name:fp},{},dict(packages=[]))
        self.assertEqual(proof['unknowns'],unknowns);self.assertEqual(result['rawEmitterUnknowns'],unknowns);self.assertEqual(len(result['independentlyResolvedRawUnknowns']),1);self.assertEqual(len(result['unresolvedRawUnknowns']),1)
        self.assertFalse(result['wholeProducerSourceClosure']);self.assertFalse(result['qualificationAllowed']);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_package_kind_flip_cannot_bypass_actual_raw_member_binding(self):
        with tempfile.TemporaryDirectory()as tmp:
            release=Path(tmp);directory=release/'imported-inputs';directory.mkdir();temporary=directory/'input.nupkg';raw=b'MZ original member'
            with zipfile.ZipFile(temporary,'w')as archive:archive.writestr('lib/component.dll',raw)
            fp=A.CE.fingerprint(temporary);path=directory/(fp['sha256']+'.nupkg');temporary.rename(path);declared=dict(packagePath=path.relative_to(release).as_posix(),packageMember='lib/component.dll')
            artifact=dict(path=declared['packagePath'],kind='managed-package',**fp);proof=dict(artifacts={'package-'+fp['sha256']:artifact})
            self.assertEqual(A._package_pair(release,proof,declared,A.fingerprint(raw)),dict(packageSha256=fp['sha256'],member='lib/component.dll'))
            artifact['kind']=A.F.KIND
            with self.assertRaisesRegex(ValueError,'Actual unchanged SDK5 managed package'):A._package_pair(release,proof,declared,A.fingerprint(raw))

    def test_managed_byte_inventory_has_no_sdk_prefix_or_filename_escape(self):
        with tempfile.TemporaryDirectory()as tmp:
            release=Path(tmp);raw=b'MZ original managed input';name='shared/Microsoft.NETCore.App/5.0.17/payload.dat';archive=release/'candidate.tar.gz'
            with tarfile.open(archive,'w:gz')as target:
                row=tarfile.TarInfo(name);row.size=len(raw);target.addfile(row,io.BytesIO(raw))
            sdk=dict(name=archive.name,**A.CE.fingerprint(archive));record=dict(sdkVersion='5.0.214',architecture='aarch64',sdk=sdk)
            toolset=release/'toolset.zip'
            with zipfile.ZipFile(toolset,'w')as target:target.writestr('original','data')
            replay=release/'installer.json';replay.write_text(json.dumps(dict(transformations=[])))
            proof=dict(sdkArchive=dict(path=sdk['name'],**{key:sdk[key]for key in A.CE.FP}),inventory={name:dict(bytes=len(raw),sha256=A.fingerprint(raw)['sha256'])},artifacts=dict(toolset=dict(path=toolset.name,**A.CE.fingerprint(toolset))),installerBuildReplay=dict(path=replay.name,**A.CE.fingerprint(replay)))
            self.assertEqual(A.managed_input_fingerprints(release,record,proof),{name:A.fingerprint(raw)})
            proof['inventory'][name]['sha256']='0'*64
            with self.assertRaises(ValueError):A.managed_input_fingerprints(release,record,proof)

    def test_missing_raw_declaration_is_derived_only_from_closed_actual_package_pairs(self):
        with tempfile.TemporaryDirectory()as tmp:
            release=Path(tmp);directory=release/'imported-inputs';directory.mkdir();package=directory/'input.nupkg';raw=b'MZ independently supported input';name='sdk/5.0.214/supported.dll'
            with zipfile.ZipFile(package,'w')as archive:archive.writestr('lib/supported.dll',raw)
            fp=A.CE.fingerprint(package);path=directory/(fp['sha256']+'.nupkg');package.rename(path);artifact=dict(path=path.relative_to(release).as_posix(),kind='managed-package',repository=None,sourceRoot=None,sourceCommit=None,**fp)
            unknown=dict(kind='unmapped-managed-source',path=name);proof=dict(kind='sdk5-musl-construction-proof',sdkVersion='5.0.214',unknowns=[unknown],managedShipping=[],artifacts={'package-'+fp['sha256']:artifact});before=copy.deepcopy(proof)
            source=dict(path=name,sourceValidator='embedded',fingerprint=A.fingerprint(raw),actualDerivedCompilerContainerRequired=False,allowedActualPackageMembers=[dict(packageSha256=fp['sha256'],member='lib/supported.dll')])
            with patch.object(A,'source_catalog',return_value={name:source}),patch.object(A,'package_pins',return_value=({},{})):
                result=A.derive_correspondence(release,proof,{name:A.fingerprint(raw)},{},dict(packages=[]))
            self.assertEqual(proof,before);value=result['sourceDispositions'][name];self.assertTrue(value['actualSupplierBindingValidated']);self.assertFalse(value['rawEmitterDeclarationPresent']);self.assertFalse(value['actualProducerConsumptionValidated']);self.assertEqual(len(result['independentlyResolvedRawUnknowns']),1)


if __name__=='__main__':unittest.main()
