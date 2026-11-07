import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import MagicMock,patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('get_cbodotnetup',ROOT/'scripts/get-cbodotnetup.py')
BOOT=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BOOT)


class InstallerBootstrapTests(unittest.TestCase):
    def elf(self,machine=62,loader='/lib64/ld-linux-x86-64.so.2'):
        data=bytearray(120+len(loader)+1);data[:7]=b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H',data,18,machine);struct.pack_into('<Q',data,32,64)
        struct.pack_into('<HH',data,54,56,1);struct.pack_into('<I',data,64,3)
        struct.pack_into('<Q',data,72,120);struct.pack_into('<Q',data,96,len(loader)+1)
        data[120:]=loader.encode()+b'\0'
        return bytes(data)

    def catalog(self):
        now=datetime.now(timezone.utc)
        return dict(schemaVersion=2,kind='cbodotnetup-installation-catalog',signingFingerprint=BOOT.FINGERPRINT,sequence=1,
                    issuedAt=(now-timedelta(minutes=1)).isoformat(),expiresAt=(now+timedelta(days=30)).isoformat())

    def test_embedded_key_is_exact_independent_repository_trust_root(self):
        self.assertEqual(BOOT.PUBLIC_KEY,(ROOT/'releases/downstream-signing-key.asc').read_text().replace('\r\n','\n'))
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key.asc';key.write_text(BOOT.PUBLIC_KEY)
            result=subprocess.run(['gpg','--batch','--show-keys','--with-colons',str(key)],check=True,capture_output=True,text=True)
            self.assertIn('fpr:::::::::'+BOOT.FINGERPRINT+':',result.stdout)

    def test_catalog_expiry_future_and_identity_fail_closed(self):
        now=datetime.now(timezone.utc);good=self.catalog();BOOT.validate(good,now)
        BOOT.validate(dict(good,schemaVersion=3),now)
        BOOT.validate(dict(good,schemaVersion=4,libc='musl'),now)
        for change in ({'schemaVersion':1},{'schemaVersion':4},{'schemaVersion':True},{'sequence':True},{'sequence':0},{'kind':'other'},{'signingFingerprint':'A'*40},
                       {'expiresAt':(now-timedelta(seconds=1)).isoformat()},
                       {'expiresAt':(now+timedelta(days=32)).isoformat()},
                       {'issuedAt':(now+timedelta(minutes=6)).isoformat()}):
            with self.subTest(change=change),self.assertRaises(ValueError):BOOT.validate(dict(good,**change),now)

    def test_new_bootstrap_uses_only_the_versioned_v3_endpoint(self):
        self.assertEqual(BOOT.CATALOG,'https://dotnetdev.kr/cbodotnet/cbodotnetup/v3/catalog.json')
        self.assertEqual(BOOT.MUSL_CATALOG,'https://dotnetdev.kr/cbodotnet/cbodotnetup/v4/catalog.json')

    def test_actual_elf_loader_and_machine_define_libc_rid_without_execution(self):
        for machine,loader,expected in ((62,'/lib64/ld-linux-x86-64.so.2','linux-x64'),
            (183,'/lib/ld-linux-aarch64.so.1','linux-arm64'),
            (62,'/lib/ld-musl-x86_64.so.1','linux-musl-x64'),
            (183,'/lib/ld-musl-aarch64.so.1','linux-musl-arm64')):
            with self.subTest(expected=expected):self.assertEqual(BOOT.elf_target(self.elf(machine,loader))['rid'],expected)
        invalid=[b'not an executable',self.elf(183,'/lib/ld-musl-x86_64.so.1'),
            self.elf(62,'/tmp/unreviewed-loader'),self.elf()[:-1],self.elf(40)]
        for data in invalid:
            with self.subTest(data=data[:20]),self.assertRaises(ValueError):BOOT.elf_target(data)

    def test_native_musl_host_requires_exact_alpine_point_release_cpu_and_no_compat_layer(self):
        data=self.elf(62,'/lib/ld-musl-x86_64.so.1');release='ID=alpine\nVERSION_ID=3.24.4\n'
        target=BOOT.detect_host('x86_64',data,release,'3.24.4\n','P:musl\n')
        self.assertEqual(target['rid'],'linux-musl-x64')
        cases=[('aarch64',data,release,'3.24.4',''),
            ('x86_64',data,release.replace('3.24.4','3.24.3'),'3.24.4',''),
            ('x86_64',data,release,'3.24.5',''),('x86_64',data,release,'3.24.4','P:gcompat\n'),
            ('x86_64',data,release,'3.24.4','P:libc6-compat\n'),
            ('x86_64',self.elf(),release,'3.24.4',''),
            ('x86_64',data,'ID=ubuntu\nVERSION_ID=24.04','3.24.4','')]
        for values in cases:
            with self.subTest(values=values),self.assertRaises(ValueError):BOOT.detect_host(*values)

    def test_separate_catalogs_reject_cross_libc_before_install_or_extraction(self):
        glibc=BOOT.elf_target(self.elf());musl=BOOT.elf_target(self.elf(62,'/lib/ld-musl-x86_64.so.1'))
        old=dict(schemaVersion=3,tools=[dict(version='0.5.0',rid='linux-x64')],revoked=[])
        new=dict(schemaVersion=4,libc='musl',tools=[dict(version='0.5.0',rid='linux-musl-x64')],revoked=[])
        self.assertEqual(BOOT.admit_tool(old,glibc)[1]['rid'],'linux-x64')
        self.assertEqual(BOOT.admit_tool(new,musl)[1]['rid'],'linux-musl-x64')
        for catalog,target in ((old,musl),(new,glibc),(dict(new,tools=old['tools']),musl),
            (dict(new,tools=[dict(version='0.4.0',rid='linux-musl-x64')]),musl),
            (dict(new,revoked=['tool/0.5.0/linux-musl-x64']),musl)):
            with self.subTest(catalog=catalog),self.assertRaises(ValueError):BOOT.admit_tool(catalog,target)

    def test_bootstrap_requires_gpg_and_system_ca_certificates(self):
        with patch.object(BOOT.Path,'is_file',return_value=False),self.assertRaisesRegex(ValueError,'GnuPG'):BOOT.prerequisites()
        with patch.object(BOOT.Path,'is_file',return_value=True),patch.object(BOOT.os,'access',return_value=True),patch.object(BOOT.ssl,'create_default_context') as context:
            context.return_value.cert_store_stats.return_value={'x509_ca':0}
            with self.assertRaisesRegex(ValueError,'CA certificates'):BOOT.prerequisites()
            context.return_value.cert_store_stats.return_value={'x509_ca':100};BOOT.prerequisites()

    def test_musl_bootstrap_requires_coreutils_before_creating_state_or_downloading(self):
        target=dict(libc='musl',rid='linux-musl-x64',architecture='x64')
        with patch.object(BOOT.Path,'is_file',return_value=False),patch.object(BOOT,'private') as private,patch.object(BOOT,'download') as download:
            with self.assertRaisesRegex(ValueError,'apk add coreutils'):BOOT.prerequisites(target)
            private.assert_not_called();download.assert_not_called()
        with patch.object(BOOT.Path,'is_file',return_value=True),patch.object(BOOT.os,'access',return_value=False):
            with self.assertRaisesRegex(ValueError,'apk add coreutils'):BOOT.prerequisites(target)
        with patch.object(BOOT.Path,'is_file',return_value=True),patch.object(BOOT.os,'access',return_value=True),patch.object(BOOT.subprocess,'run',return_value=subprocess.CompletedProcess(['/bin/stat','--version'],0,'stat (GNU coreutils) 9.11\n','')),patch.object(BOOT.ssl,'create_default_context') as context:
            context.return_value.cert_store_stats.return_value={'x509_ca':100};BOOT.prerequisites(target)

    def test_alpine_gnu_stat_uses_qualified_absolute_fallback_and_rejects_busybox(self):
        with patch.object(BOOT.Path,'is_file',side_effect=lambda:True),patch.object(BOOT.os,'access',side_effect=lambda path,mode:path=='/bin/stat'),patch.object(BOOT.subprocess,'run') as run:
            run.return_value=subprocess.CompletedProcess(['/bin/stat','--version'],0,'stat (GNU coreutils) 9.11\n','')
            self.assertEqual(BOOT.gnu_stat(),'/bin/stat')
            self.assertEqual(run.call_args.args[0],['/bin/stat','--version'])
            self.assertEqual(run.call_args.kwargs['env']['LC_ALL'],'C')
            for code,stdout in ((1,'BusyBox v1.38.0'),(0,'BusyBox v1.38.0'),(0,'')):
                run.return_value=subprocess.CompletedProcess(['/bin/stat','--version'],code,stdout,'')
                with self.subTest(code=code,stdout=stdout),self.assertRaisesRegex(ValueError,'apk add coreutils'):BOOT.gnu_stat()

    def test_duplicate_properties_rejected_at_every_depth(self):
        for raw in (b'{"sequence":1,"sequence":2}',b'{"tools":[{"rid":"linux-x64","rid":"linux-arm64"}]}'):
            with self.assertRaises(ValueError):BOOT.decode(raw)

    def test_https_redirect_boundary(self):
        BOOT.allowed('https://release-assets.githubusercontent.com/a?token=public-signed-url')
        for url in ('http://github.com/a','https://evil.example/a','https://user:password@github.com/a','https://github.com:444/a','file:///etc/passwd','https://dotnetdev.kr/a#fragment'):
            with self.subTest(url=url),self.assertRaises(ValueError):BOOT.allowed(url)

    def test_existing_symlink_and_writable_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):BOOT.ordinary(root/'link')
            shared=root/'shared';shared.mkdir();shared.chmod(0o777)
            with self.assertRaises(ValueError):BOOT.private(shared)

    def test_failed_signature_never_creates_an_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):BOOT.verify(b'{}',b'forged signature',Path(directory))
            self.assertFalse((Path(directory)/'cbodotnetup').exists())

    def test_actual_public_signature_and_long_home_path(self):
        fixtures=ROOT/'tools/cbodotnetup.Tests/fixtures'
        with tempfile.TemporaryDirectory() as directory:
            deep=Path(directory)/('a'*90)/('b'*90);deep.mkdir(parents=True)
            BOOT.verify((fixtures/'public-signed.json').read_bytes(),(fixtures/'public-signed.json.asc').read_bytes(),deep)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):
                BOOT.verify((fixtures/'public-signed.json').read_bytes()+b' ',(fixtures/'public-signed.json.asc').read_bytes(),Path(directory))

    def test_atomic_owned_file_replacement_does_not_follow_a_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);target=root/'target';target.write_bytes(b'original');(root/'link').symlink_to(target)
            with self.assertRaises(ValueError):BOOT.atomic(root/'link',b'bad')
            self.assertEqual(target.read_bytes(),b'original')
            BOOT.atomic(target,b'verified');self.assertEqual(target.read_bytes(),b'verified')

    def test_http_gzip_is_bounded_after_decoding_before_signature_checks(self):
        import gzip
        with patch.object(BOOT.urllib.request,'build_opener') as opener:
            response=MagicMock();response.headers={'Content-Encoding':'gzip'}
            response.read.return_value=gzip.compress(b'verified metadata')
            opener.return_value.open.return_value.__enter__.return_value=response
            self.assertEqual(BOOT.download(BOOT.CATALOG,1024),b'verified metadata')
            response.read.return_value=gzip.compress(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'Decompressed'):BOOT.download(BOOT.CATALOG,256)


if __name__=='__main__':unittest.main()
