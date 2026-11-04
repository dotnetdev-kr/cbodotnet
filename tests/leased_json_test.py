"""Read full status ledgers above Contents inline limits without losing the SHA lease."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import downstream_publish as PUBLISH


class LeasedJsonTests(unittest.TestCase):
    path='releases/downstream-status.json'

    def fixture(self,document=None,*,large=False,wrapped=False):
        document=document if document is not None else {'schemaVersion':1,'history':[]}
        raw=json.dumps(document,separators=(',',':')).encode()
        sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        text=base64.b64encode(raw).decode()
        if wrapped:text='\r\n'.join(text[index:index+60] for index in range(0,len(text),60))+'\r\n'
        metadata=dict(type='file',path=self.path,sha=sha,size=len(raw),encoding='none' if large else 'base64',content='' if large else text)
        blob=dict(sha=sha,size=len(raw),encoding='base64',content=text)
        api=mock.Mock();api.api.side_effect=[metadata,blob] if large else [metadata]
        return api,metadata,blob,document

    def test_inline_wrapped_base64_preserves_exact_contents_lease(self):
        api,metadata,blob,expected=self.fixture(wrapped=True)
        document,lease=PUBLISH.read_leased_json(api,self.path)
        self.assertEqual(expected,document);self.assertIs(metadata,lease)
        api.api.assert_called_once_with(f'repos/{PUBLISH.REPOSITORY}/contents/{self.path}?ref=main')

    def test_large_encoding_none_reads_the_exact_observed_blob_and_all_history(self):
        expected=dict(history=['x'*1048600],sdkVersions=['3.0.103','10.0.403'])
        api,metadata,blob,_=self.fixture(expected,large=True,wrapped=True)
        document,lease=PUBLISH.read_leased_json(api,self.path)
        self.assertEqual(expected,document);self.assertEqual(metadata['sha'],lease['sha'])
        self.assertEqual(f'repos/{PUBLISH.REPOSITORY}/git/blobs/{metadata["sha"]}',api.api.call_args_list[1].args[0])
        self.assertEqual(2,api.api.call_count)

    def test_replaced_branch_cannot_change_the_original_contents_sha_lease(self):
        api,metadata,blob,expected=self.fixture(large=True)
        # A later branch version is never reread or silently substituted.
        api.api.side_effect=[metadata,blob,dict(metadata,sha='f'*40)]
        document,lease=PUBLISH.read_leased_json(api,self.path)
        self.assertEqual(expected,document);self.assertEqual(blob['sha'],lease['sha'])
        self.assertEqual(2,api.api.call_count)

    def test_invalid_contents_identity_encoding_or_size_fails_without_blob_fetch(self):
        changes=[dict(type='symlink'),dict(path='other.json'),dict(sha='not-a-git-sha'),dict(size=True),
            dict(size=0),dict(size=PUBLISH.MAX_LEASED_JSON_BYTES+1),dict(encoding='utf-8')]
        for change in changes:
            with self.subTest(change=change):
                api,metadata,blob,_=self.fixture();api.api.side_effect=[dict(metadata,**change)]
                with self.assertRaises(ValueError):PUBLISH.read_leased_json(api,self.path)
                self.assertEqual(1,api.api.call_count)

    def test_large_metadata_cannot_smuggle_inline_bytes_or_replace_blob_identity(self):
        api,metadata,blob,_=self.fixture(large=True);metadata['content']='unexpected-inline-bytes'
        with self.assertRaisesRegex(ValueError,'substituted inline'):PUBLISH.read_leased_json(api,self.path)
        self.assertEqual(1,api.api.call_count)
        for change in (dict(sha='f'*40),dict(size=1),dict(encoding='none')):
            api,metadata,blob,_=self.fixture(large=True);api.api.side_effect=[metadata,dict(blob,**change)]
            with self.subTest(change=change),self.assertRaises(ValueError):PUBLISH.read_leased_json(api,self.path)

    def test_malformed_base64_whitespace_padding_or_wrong_git_bytes_are_rejected(self):
        for kind in ('illegal','space','padding','wrong-bytes'):
            api,metadata,blob,_=self.fixture()
            if kind=='illegal':metadata['content']='!'+metadata['content'][1:]
            elif kind=='space':metadata['content']=' '+metadata['content'][1:]
            elif kind=='padding':metadata['content']=metadata['content'][:-1]+'!'
            else:metadata['content']=base64.b64encode(b'x'*metadata['size']).decode()
            with self.subTest(kind=kind),self.assertRaises(ValueError):PUBLISH.read_leased_json(api,self.path)
        api,metadata,blob,_=self.fixture(large=True);blob['content']=base64.b64encode(b'x'*blob['size']).decode()
        with self.assertRaisesRegex(ValueError,'Git blob SHA'):PUBLISH.read_leased_json(api,self.path)

    def test_request_bounds_and_paths_are_checked_before_api_access(self):
        for path,maximum in (('../outside.json',100),('/absolute.json',100),('releases/a.json?token=secret',100),
                (self.path,True),(self.path,PUBLISH.MAX_LEASED_JSON_BYTES+1)):
            api=mock.Mock()
            with self.subTest(path=path,maximum=maximum),self.assertRaises(ValueError):
                PUBLISH.read_leased_json(api,path,maximum=maximum)
            api.api.assert_not_called()

    def test_contents_transport_requests_object_media_for_large_metadata(self):
        response=subprocess.CompletedProcess([],0,stdout='{}',stderr='')
        with mock.patch.object(PUBLISH.subprocess,'run',return_value=response) as command:
            PUBLISH.GitHubReleases().api(f'repos/{PUBLISH.REPOSITORY}/contents/{self.path}?ref=main')
        self.assertIn('Accept: application/vnd.github.object+json',command.call_args.args[0])


if __name__=='__main__':unittest.main()
