import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('get_cbodotnetup',ROOT/'scripts/get-cbodotnetup.py')
BOOT=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BOOT)


class InstallerBootstrapTests(unittest.TestCase):
    def catalog(self):
        now=datetime.now(timezone.utc)
        return dict(schemaVersion=1,kind='cbodotnetup-installation-catalog',signingFingerprint=BOOT.FINGERPRINT,sequence=1,
                    issuedAt=(now-timedelta(minutes=1)).isoformat(),expiresAt=(now+timedelta(days=30)).isoformat())

    def test_embedded_key_is_exact_independent_repository_trust_root(self):
        self.assertEqual(BOOT.PUBLIC_KEY,(ROOT/'releases/downstream-signing-key.asc').read_text().replace('\r\n','\n'))
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key.asc';key.write_text(BOOT.PUBLIC_KEY)
            result=subprocess.run(['gpg','--batch','--show-keys','--with-colons',str(key)],check=True,capture_output=True,text=True)
            self.assertIn('fpr:::::::::'+BOOT.FINGERPRINT+':',result.stdout)

    def test_catalog_expiry_future_and_identity_fail_closed(self):
        now=datetime.now(timezone.utc);good=self.catalog();BOOT.validate(good,now)
        for change in ({'sequence':True},{'sequence':0},{'kind':'other'},{'signingFingerprint':'A'*40},
                       {'expiresAt':(now-timedelta(seconds=1)).isoformat()},
                       {'expiresAt':(now+timedelta(days=32)).isoformat()},
                       {'issuedAt':(now+timedelta(minutes=6)).isoformat()}):
            with self.subTest(change=change),self.assertRaises(ValueError):BOOT.validate(dict(good,**change),now)

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


if __name__=='__main__':unittest.main()
