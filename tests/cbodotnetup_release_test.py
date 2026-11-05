from pathlib import Path
import tempfile
import sys
import shutil
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import cbodotnetup_release as UP


class InstallerReleaseTests(unittest.TestCase):
    def test_patched_runtime_is_outside_the_actual_advisory_range(self):
        self.assertTrue(UP.affected('10.0.13','[10.0.0, 10.0.14)'))
        self.assertFalse(UP.affected('10.0.14','[10.0.0, 10.0.14)'))
        self.assertFalse(UP.affected('10.0.14','[11.0.0-preview.1.26104.118, 11.0.0-rc.3.26522.148)'))

    def test_inclusive_exclusive_open_and_exact_ranges(self):
        self.assertTrue(UP.affected('1.2.3','[1.2.3]'))
        self.assertTrue(UP.affected('1.2.3','(, 1.2.3]'))
        self.assertFalse(UP.affected('1.2.3','(, 1.2.3)'))
        self.assertTrue(UP.affected('1.2.3','[1.2.3, )'))
        self.assertFalse(UP.affected('1.2.3','(1.2.3, )'))
        for value in ('1.2.*','>=1.2.3','[1.2.3,2.0.0],[3.0.0,4.0.0]'):
            with self.subTest(value=value),self.assertRaises(ValueError):UP.affected('1.2.3',value)

    def test_an_untrusted_asset_origin_is_rejected_before_any_io(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(UP.urllib.request,'urlopen') as network:
            for url in ('file:///etc/passwd','http://github.com/dotnetdev-kr/cbodotnet/releases/download/a/b','https://github.com/other/repo/releases/download/a/b'):
                with self.subTest(url=url),self.assertRaises(ValueError):UP.fetch_asset(dict(url=url,size=1,sha256='a'*64),Path(directory)/'input')
            network.assert_not_called()

    def test_native_target_proof_matrix_cannot_be_empty(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(UP,'verify_bundle',return_value={}),self.assertRaisesRegex(ValueError,'All eight'):
            UP.qualified_reports(Path(directory),Path(directory))

    def test_public_metadata_reader_keeps_its_separate_narrow_origin_boundary(self):
        with patch.object(UP.urllib.request,'build_opener') as network:
            for url in ('https://api.nuget.org/v3/registration5-gz-semver2/a/index.json','https://dotnetdev.kr/cbodotnet/other.py',
                        'https://evil.example/v3/vulnerabilities/index.json','http://api.nuget.org/v3/vulnerabilities/index.json',
                        'https://api.nuget.org/v3/vulnerabilities/index.json?token=x'):
                with self.subTest(url=url),self.assertRaises(ValueError):UP.public_metadata(url,1024)
            network.assert_not_called()

    def test_official_compressed_metadata_has_a_decoded_size_bound(self):
        import gzip
        with patch.object(UP.urllib.request,'build_opener') as opener:
            response=MagicMock();response.headers={'Content-Encoding':'gzip'};response.read.return_value=gzip.compress(b'{}')
            opener.return_value.open.return_value.__enter__.return_value=response
            self.assertEqual(UP.public_metadata('https://api.nuget.org/v3/vulnerabilities/index.json',1024),b'{}')
            response.read.return_value=gzip.compress(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'Decompressed'):UP.public_metadata('https://api.nuget.org/v3/vulnerabilities/index.json',256)

    def test_draft_resume_uses_the_real_shared_verifier_and_never_clobbers_public_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'cbodotnetup-linux-x64';path.write_bytes(b'verified native binary')
            tag='cbodotnetup-v0.1.0';target='b'*40
            class Transport:
                def __init__(self):
                    self.release=dict(id=123,tag_name=tag,target_commitish=target,draft=True,prerelease=False,assets=[],html_url='https://github.com/dotnetdev-kr/cbodotnet/releases/tag/'+tag)
                    self.uploads=0;self.publishes=0;self.downloads=[]
                def find(self,unused):return self.release
                def get(self,unused):return self.release
                def upload(self,release,file):
                    item=UP.descriptor(file);self.release['assets'].append(dict(id=100,**item,state='uploaded',digest='sha256:'+item['sha256'],browser_download_url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'+tag+'/'+item['name']));self.uploads+=1
                def download(self,asset,destination,public=False):shutil.copyfile(path,destination);self.downloads.append(public)
                def publish(self,unused):self.release['draft']=False;self.publishes+=1;return self.release
                def api(self,unused):return dict(object=dict(type='commit',sha=target))
            transport=Transport()
            with patch.object(UP,'GitHubReleases',return_value=transport):
                result=UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(result['assets'][0]['sha256'],UP.descriptor(path)['sha256'])
                self.assertEqual(transport.downloads,[False,True]);self.assertEqual(transport.uploads,1)
                UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(transport.uploads,1);self.assertEqual(transport.publishes,1)
                path.write_bytes(b'conflicting bytes')
                with self.assertRaisesRegex(ValueError,'conflicts'):UP.upload_release(tag,target,[path],'title','body')
                self.assertEqual(transport.uploads,1)


if __name__=='__main__':unittest.main()
