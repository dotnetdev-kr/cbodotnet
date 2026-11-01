"""Bounded x64 legacy identity, native ABI and signed-sysroot evidence fixtures."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(name, arch='x64'):
    with mock.patch.object(sys, 'argv', ['fixture', '--arch', arch]):
        return runpy.run_path(str(ROOT/'scripts'/(name+'.py')))


class LegacyX64Tests(unittest.TestCase):
    def test_bootstrap_and_analysis_pins_cannot_select_arm_archives(self):
        helper = module('ci_legacy_arch')
        for version in ('3.0.100', '3.1.422', '5.0.212', '9.0.121'):
            x64 = helper['sdk_pin'](version, 'x64'); arm = helper['sdk_pin'](version, 'arm64')
            self.assertTrue(x64['name'].endswith('-linux-x64.tar.gz'))
            self.assertNotEqual(x64['sha512'], arm['sha512'])
            self.assertEqual(len(x64['sha512']), 128)
        bootstrap = module('prepare-core30-bootstrap')
        self.assertEqual(bootstrap['SDK_BYTES'], 113463755)
        self.assertEqual(bootstrap['SDK_NAME'], 'dotnet-sdk-3.0.100-linux-x64.tar.gz')
        template = module('prepare-core30-template-inputs')['ARCHIVES']['3.0.100']
        self.assertEqual(template['sha512'], bootstrap['SDK_SHA512'])
        self.assertEqual(template['sha256'], '12098fe29d5c857fd6093b1fd63eda9f91b92798e3748fcedc0e0727f1ac01c2')
        self.assertEqual(module('prepare-core30-bootstrap', 'arm64')['SDK_BYTES'], 113669548)

    def test_native_platform_manifest_binding_rejects_arm_image(self):
        verifier = module('ci-legacy-verify'); digest = 'sha256:'+'a'*64
        row = {'Architecture':'amd64','Os':'linux','Digest':digest,
               'RepoDigests':['docker.io/library/ubuntu@'+digest]}
        self.assertEqual(verifier['manifest_reference'](row,'ubuntu'),'docker.io/library/ubuntu@'+digest)
        for architecture in ('arm64','x64','386'):
            with self.subTest(architecture=architecture), self.assertRaises(ValueError):
                verifier['manifest_reference'](dict(row,Architecture=architecture),'ubuntu')

    def test_complete_native_x64_sdk_checks_reject_foreign_machine_and_distro(self):
        verifier = module('ci-legacy-verify')
        archive = {'sha256':'a'*64,'bytes':123}
        result = {'verificationStatus':'passed','sdkVersion':'5.0.214','framework':'net5.0','reportedRid':'linux-x64',
            'functionalChecks':dict.fromkeys(verifier['FUNCTIONS'],'passed'),
            'archive':{'sha256':'a'*64,'sizeBytes':123,'sdkContentMatched':True},
            'abi':{'elfFileCount':20,'machines':{'Advanced Micro Devices X86-64':20},'glibcCeilingPassed':True,
                   'glibcCeiling':'2.23','symbolicGlibcRequirements':[],
                   'maximumRequiredVersions':{'GLIBC':'2.17','GLIBCXX':'3.4.21','CXXABI':'1.3.7'}}}
        verifier['check_verification']('net5','debian13',result,archive)
        bad = copy.deepcopy(result); bad['abi']['machines']={'AArch64':20}
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)
        bad = copy.deepcopy(result); bad['reportedRid']='linux-arm64'
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)
        bad = copy.deepcopy(result); bad['functionalChecks'].pop('frFrDecimalFormatting')
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)

    def test_x64_profiles_preserve_source_pins_without_historical_qualification(self):
        for version, family in [('5.0.214','net5'),('3.1.426','core31'),('3.0.103','core30')]:
            with self.subTest(version=version):
                arm = json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-arm64.json')).read_text())
                x64 = json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-x64.json')).read_text())
                self.assertEqual(x64['source'], arm['source'])
                self.assertEqual(x64['target']['rid'], 'linux-x64')
                self.assertEqual(x64['container']['architecture'], 'amd64')
                self.assertNotEqual(x64['container']['digest'], arm['container']['digest'])
                self.assertNotIn('verification',x64); self.assertNotIn('testing',x64)
                self.assertIn('pending',x64['status'])
                self.assertTrue(x64['build']['patches'])
                for item in x64['build']['patches']:
                    self.assertEqual(hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest(),item['sha256'])
                if family!='net5':
                    manifest = x64['build']['patchManifest']
                    self.assertEqual(hashlib.sha256((ROOT/manifest['path']).read_bytes()).hexdigest(),manifest['sha256'])

    def sysroot(self, temporary):
        root = Path(temporary)/'sysroot'; reports = Path(temporary)/'reports'; reports.mkdir(); root.mkdir()
        library = root/'lib/x86_64-linux-gnu/libc-2.23.so'; library.parent.mkdir(parents=True)
        data = bytearray(64); data[:6]=b'\x7fELF\x02\x01'; data[18:20]=(62).to_bytes(2,'little'); library.write_bytes(data)
        (library.parent/'libc.so.6').symlink_to(library.name)
        def row(path): return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        provenance = {'family':'core30','architecture':'amd64','sysroot':str(root),'method':'explicit-native-amd64-debootstrap',
            'originalGeneratorVerified':True,'packageSignatureVerification':True,'releaseSignatureLogVerified':True,'emulation':False}
        for key in ('producer','archiveRelease','archiveSignature','signatureStatus'):
            path=reports/key; path.write_bytes(('synthetic-'+key).encode()); provenance[key]=row(path)
        source=reports/'producer-ca.pem'; source.write_bytes(b'synthetic retained TLS trust bundle')
        retained=reports/'apt-tls-ca.pem'; retained.write_bytes(source.read_bytes())
        ca_info='/etc/ssl/certs/cbodotnet-producer-ca.pem'
        target=root/ca_info.lstrip('/'); target.parent.mkdir(parents=True); target.write_bytes(source.read_bytes())
        provenance['aptTls']={'source':row(source),'retained':row(retained),'target':row(target),'caInfo':ca_info,
            'peerVerification':True,'hostVerification':True,'packageSignatureVerification':True,
            'arguments':['-o','Acquire::https::CaInfo='+ca_info,'-o','Acquire::https::Verify-Peer=true','-o','Acquire::https::Verify-Host=true']}
        (reports/'sysroot-provenance.json').write_text(json.dumps(provenance))
        (reports/'sysroot-packages.tsv').write_text('libc6:amd64\t2.23-0ubuntu11.3\tamd64\n')
        (reports/'sysroot-symlinks.tsv').write_text(str(library.parent/'libc.so.6')+'\t'+library.name+'\n')
        def seal():
            manifest=reports/'sysroot-files.sha256'
            manifest.write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path)+'\n' for path in (library,target)))
            (reports/'sysroot-file-list.sha256').write_text(hashlib.sha256(manifest.read_bytes()).hexdigest()+'  '+str(manifest)+'\n')
        seal()
        return root,reports,library,seal

    def test_complete_sysroot_index_cannot_relabel_arm_libc_or_accept_extra_files(self):
        helper=module('verify-legacy-x64-sysroot')
        for mode in ('good','foreign-machine','extra-file','changed-producer','changed-ca','disabled-peer','different-ca-target'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='legacy-x64-sysroot-') as temporary:
                root,reports,library,seal=self.sysroot(temporary)
                if mode=='foreign-machine':
                    data=bytearray(library.read_bytes());data[18:20]=(183).to_bytes(2,'little');library.write_bytes(data);seal()
                if mode=='extra-file': (root/'unbound').write_bytes(b'not indexed')
                if mode=='changed-producer': (reports/'producer').write_bytes(b'not the captured producer')
                if mode=='changed-ca': (reports/'apt-tls-ca.pem').write_bytes(b'not the captured trust input')
                if mode in ('disabled-peer','different-ca-target'):
                    path=reports/'sysroot-provenance.json'; provenance=json.loads(path.read_text())
                    if mode=='disabled-peer': provenance['aptTls']['peerVerification']=False
                    else: provenance['aptTls']['target']['path']=str(root/'foreign-ca.pem')
                    path.write_text(json.dumps(provenance))
                args=['fixture','--family','core30','--sysroot',str(root),'--reports-dir',str(reports)]
                with mock.patch.object(sys,'argv',args),contextlib.redirect_stdout(io.StringIO()):
                    if mode=='good': helper['main']()
                    else:
                        with self.assertRaises(ValueError): helper['main']()


if __name__=='__main__': unittest.main()
