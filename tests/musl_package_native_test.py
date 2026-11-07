"""Protected re-signing preserves actual signed bytes and enforces APK key policy."""
import copy
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import musl_packages as APK
import musl_package_native as NATIVE
import musl_packages_test as PACKAGE_FIXTURES
from musl_packages_test import tar_bytes


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl'),'Linux OpenSSL required')
class MuslProtectedPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='ephemeral-resign-tests-')
        cls.directory=Path(cls.temporary.name)
        cls.private=cls.directory/'source.rsa'
        cls.public=cls.directory/'source.rsa.pub'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out',str(cls.private)],
                       check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(cls.private),'-pubout','-out',str(cls.public)],check=True,capture_output=True)
        cls.target_public=cls.directory/'next.rsa.pub'
        cls.target_public.write_bytes(cls.public.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name)

    def signature(self,compressed):
        signable=self.work/'signable.gz'
        signature=self.work/'signature'
        signable.write_bytes(compressed)
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(signature),str(signable)],
                       check=True,capture_output=True)
        prefix=tar_bytes([('.SIGN.RSA256.'+self.public.name,signature.read_bytes(),'file')])[:1024]
        return gzip.compress(prefix,mtime=0)+compressed

    def fixture(self):
        data=gzip.compress(tar_bytes([('usr',b'','directory'),('usr/bin',b'','directory'),('usr/bin/cbodotnet',b'fixture','file')]),mtime=0)
        info=('pkgname = cbodotnet-host\npkgver = 1.0.0-r1\narch = noarch\ndatahash = '+hashlib.sha256(data).hexdigest()+'\n').encode()
        control=gzip.compress(tar_bytes([('.PKGINFO',info,'file')])[:1024],mtime=0)
        package=self.work/'cbodotnet-host-1.0.0-r1.apk'
        package.write_bytes(self.signature(control)+data)
        row=APK.verify_apk(package,self.public)
        text=f"C:{row['indexIdentity']}\nP:{row['name']}\nV:{row['version']}\nA:noarch\nS:{row['size']}\n"
        index=self.work/'APKINDEX.tar.gz'
        index.write_bytes(self.signature(gzip.compress(tar_bytes([('APKINDEX',text.encode(),'file')]),mtime=0)))
        return package,index,row

    def test_resign_changes_only_signature_member_and_retains_control_and_payload(self):
        package,_,prior=self.fixture()
        destination=self.work/'re-signed.apk'
        current=NATIVE.resign_apk(package,self.public,destination,self.private,self.target_public,production=False)
        self.assertNotEqual(prior['sha256'],current['sha256'])
        self.assertEqual('next.rsa.pub',current['signingKey']['filename'])
        for field in ('name','version','architecture','controlSha256','indexIdentity','dataSha256'):
            self.assertEqual(prior[field],current[field])
        self.assertEqual(APK.payload_snapshot(package,prior),APK.payload_snapshot(destination,current))
        with package.open('rb') as source,destination.open('rb') as target:
            APK.gzip_member(source)
            APK.gzip_member(target)
            self.assertEqual(source.read(),target.read())

    def test_production_resign_rejects_an_unapproved_ephemeral_identity(self):
        package,_,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'approved exact PEM'):
            NATIVE.resign_apk(package,self.public,self.work/'not-created.apk',self.private,self.target_public)
        self.assertFalse((self.work/'not-created.apk').exists())

    def test_approved_key_policy_checks_spki_exact_pem_and_rotation_cutoff(self):
        policy=json.loads((ROOT/'releases/musl-signing-policy.json').read_bytes())
        key=ROOT/policy['apkSigner']['publicKeyPath']
        created=datetime.datetime.fromisoformat(policy['apkSigner']['createdAt'].replace('Z','+00:00'))
        actual=NATIVE.approved_signer(key,policy,now=created+datetime.timedelta(hours=1))
        self.assertEqual(policy['apkSigner']['spkiDerSha256'],actual['spkiSha256'])
        cutoff=datetime.datetime.fromisoformat(policy['apkSigner']['publisherNotAfter'].replace('Z','+00:00'))
        with self.assertRaisesRegex(ValueError,'approved signing interval'):
            NATIVE.approved_signer(key,policy,now=cutoff)
        changed=copy.deepcopy(policy)
        changed['apkSigner']['publicKeySha256']='0'*64
        with self.assertRaisesRegex(ValueError,'approved permanent trust identity'):
            NATIVE.approved_signer(key,changed,now=created+datetime.timedelta(hours=1))

    def test_resign_refuses_existing_or_symlink_output(self):
        package,_,_=self.fixture()
        existing=self.work/'existing.apk'
        existing.write_bytes(b'preserve me')
        with self.assertRaisesRegex(ValueError,'Fresh ordinary'):
            NATIVE.resign_apk(package,self.public,existing,self.private,self.target_public,production=False)
        self.assertEqual(b'preserve me',existing.read_bytes())

    def test_protected_repository_updates_signed_index_sizes_without_sdk_execution(self):
        host,_,host_row=self.fixture()
        helper=PACKAGE_FIXTURES.MuslPackagesTests()
        helper.directory=self.work
        plan,_=helper.plan()
        with host.open('rb') as stream:
            APK.gzip_member(stream)
            _,plain=APK.gzip_member(stream)
            data=stream.read()
        info=APK.tar_files(plain)['.PKGINFO'].replace(b'pkgname = cbodotnet-host',b'pkgname = cbodotnet-sdk-10.0') \
            .replace(b'pkgver = 1.0.0-r1',b'pkgver = 10.0.403-r1').replace(b'arch = noarch',b'arch = x86_64')
        sdk=self.work/'cbodotnet-sdk-10.0-10.0.403-r1.apk'
        sdk.write_bytes(self.signature(gzip.compress(tar_bytes([('.PKGINFO',info,'file')])[:1024],mtime=0))+data)
        sdk_row=APK.verify_apk(sdk,self.public)
        original=[dict(host_row,kind='host'),dict(sdk_row,kind='sdk')]
        source=self.work/'candidate'
        repo=source/'repository'
        repo.mkdir(parents=True)
        blocks=[]
        for row in original:
            shutil.copyfile(self.work/row['path'],repo/row['path'])
            blocks.append(f"C:{row['indexIdentity']}\nP:{row['name']}\nV:{row['version']}\nA:{row['architecture']}\nS:{row['size']}\n")
        (repo/'APKINDEX.tar.gz').write_bytes(self.signature(gzip.compress(tar_bytes([('APKINDEX','\n'.join(blocks).encode(),'file')]),mtime=0)))
        build=dict(plan=plan,packages=original,credentialPurpose='ephemeral-fixture',payloadPreserved=True)
        for name,value in [('package-build.json',build),('plan.json',plan),('payload-inventory.json',{}),('command-inventory.json',[])]:
            (source/name).write_text(json.dumps(value))
        for kind in ('sdk','host'):
            path=source/'aports/cbodotnet'/kind
            path.mkdir(parents=True)
            (path/'APKBUILD').write_text('# synthetic recipe fixture\n')
        target=self.work/'signed'
        frozen=NATIVE.resign_repository(source,self.public,target,self.private,self.target_public,production=False)
        self.assertEqual(NATIVE.descriptor(self.target_public),frozen['publicKeyAsset'])
        self.assertTrue(frozen['signingPreservedCompressedControlAndPayload'])
        self.assertFalse(frozen['publicationQualified'])
        self.assertEqual(2,APK.verify_index(target/'repository/APKINDEX.tar.gz',self.target_public,frozen['packages'])['packages'])
        for before,after in zip(original,frozen['packages']):
            self.assertEqual(before['controlSha256'],after['controlSha256'])
            self.assertEqual(before['dataSha256'],after['dataSha256'])
        self.assertFalse((target/'abuild.conf').exists())
        if shutil.which('apk'):
            subprocess.run(['apk','--keys-dir',str(self.directory),'verify',str(target/'repository/APKINDEX.tar.gz')],check=True,capture_output=True)

    @unittest.skipUnless(shutil.which('apk'),'Actual apk-tools required')
    def test_native_apk_rejects_each_valid_stream_tamper_and_wrong_key(self):
        package,index,_=self.fixture()
        result=NATIVE.negative_apk_checks(package,index,self.public,self.work/'negative')
        self.assertEqual({'changed-package-control','changed-package-payload','changed-index',
            'wrong-key-same-name-package','wrong-key-same-name-index','missing-key'},set(result))
        self.assertIn('integrity error',result['changed-package-payload']['diagnostic'])
        self.assertFalse((self.work/'negative').exists())


@unittest.skipUnless(os.name=='posix','POSIX image filesystem semantics required')
class OciFilesystemExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name)

    def image_tar(self,entries):
        path=self.work/'rootfs.tar'
        with tarfile.open(path,'w') as archive:
            for name,content,kind in entries:
                row=tarfile.TarInfo(name)
                row.mode=0o755 if kind=='directory' else 0o644
                if kind=='directory':
                    row.type=tarfile.DIRTYPE
                    archive.addfile(row)
                elif kind=='link':
                    row.type=tarfile.SYMTYPE
                    row.mode=0o777
                    row.linkname=content
                    archive.addfile(row)
                elif kind=='hardlink':
                    row.type=tarfile.LNKTYPE
                    row.linkname=content
                    archive.addfile(row)
                else:
                    row.size=len(content)
                    archive.addfile(row,io.BytesIO(content))
        return path

    def test_absolute_system_symlink_is_anchored_to_export_root(self):
        source=self.image_tar([('lib',b'','directory'),('lib/real.so',b'image-library','file'),
                               ('lib/alias.so','/lib/real.so','link')])
        root=NATIVE.extract_image_root(source,self.work/'root')
        self.assertEqual(root/'lib/real.so',(root/'lib/alias.so').resolve())
        self.assertEqual(b'image-library',(root/'lib/alias.so').read_bytes())

    def test_absolute_and_normalized_hard_links_use_the_exported_ordinary_file(self):
        source=self.image_tar([('lib',b'','directory'),('lib/real.so',b'exported-library','file'),
            ('lib/absolute.so','/lib/real.so','hardlink'),('lib/normalized.so','lib/../lib/real.so','hardlink')])
        root=NATIVE.extract_image_root(source,self.work/'root')
        self.assertEqual(b'exported-library',(root/'lib/absolute.so').read_bytes())
        self.assertEqual((root/'lib/real.so').stat().st_ino,(root/'lib/normalized.so').stat().st_ino)

    def test_tar_traversal_and_writes_through_link_parent_are_rejected(self):
        for label,entries in [('traversal',[('../outside',b'bad','file')]),
                ('link-parent',[('lib','/tmp','link'),('lib/write',b'bad','file')]),
                ('link-escape',[('link','../outside','link')])]:
            with self.subTest(case=label):
                source=self.image_tar(entries)
                with self.assertRaises(ValueError):
                    NATIVE.extract_image_root(source,self.work/label)
        self.assertFalse((self.work/'outside').exists())

    def test_sdk_root_ownership_allows_normal_linux_symlinks_and_rejects_nonroot_files(self):
        plan={'package':{'root':'/opt/cbodotnet/10.0'}}
        source=self.image_tar([('opt/cbodotnet/10.0/file',b'payload','file'),
            ('opt/cbodotnet/10.0/link','file','link')])
        self.assertEqual(2,NATIVE.image_payload_ownership(source,plan,[])['sdkEntries'])
        with tarfile.open(source,'w') as archive:
            row=tarfile.TarInfo('opt/cbodotnet/10.0/file')
            row.uid,row.mode,row.size=10001,0o644,1
            archive.addfile(row,io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError,'owner or immutable mode'):
            NATIVE.image_payload_ownership(source,plan,[])


if __name__=='__main__':
    unittest.main()
