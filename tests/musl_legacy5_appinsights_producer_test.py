"""Input transport and explicit caller guards; no genuine supplier is executed."""
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_producer as A


class AppNormalProducerInputs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.private=self.root/'workspace/private';self.private.mkdir(parents=True)
        self.target=self.private/'input';self.raw=b'original private acquisition\n'
        self.pin=dict(bytes=len(self.raw),sha256=hashlib.sha256(self.raw).hexdigest(),sha512=hashlib.sha512(self.raw).hexdigest())

    def test_whole_input_bytes_are_retained_privately_with_all_three_fingerprints(self):
        with patch.object(A.urllib.request,'urlopen',return_value=io.BytesIO(self.raw))as request:
            result=A._acquire('https://example.invalid/pinned-input',self.target,self.pin)
        self.assertEqual(self.target.read_bytes(),self.raw)
        self.assertEqual({k:result[k]for k in A.N.FP},self.pin)
        self.assertNotIn('Authorization',request.call_args.args[0].headers)

    def test_bad_or_truncated_body_is_not_retried_and_failure_stays_private(self):
        for raw in (b'bad body',self.raw[:-1]):
            with self.subTest(raw=raw):
                target=self.private/('bad-'+str(len(raw)))
                with patch.object(A.urllib.request,'urlopen',return_value=io.BytesIO(raw))as request:
                    with self.assertRaisesRegex(ValueError,'Whole original'):A._acquire('https://example.invalid/input',target,self.pin)
                self.assertEqual(request.call_count,1);self.assertEqual(target.read_bytes(),raw)
        self.assertFalse((self.root/'delivery').exists())

    def test_oversized_input_is_bounded_before_write(self):
        with patch.object(A.urllib.request,'urlopen',return_value=io.BytesIO(self.raw+b'extra'))as request:
            with self.assertRaisesRegex(ValueError,'size exceeded'):A._acquire('https://example.invalid/input',self.target,self.pin)
        self.assertEqual(request.call_count,1);self.assertLessEqual(self.target.stat().st_size,self.pin['bytes'])

    def test_existing_input_cannot_be_reused(self):
        self.target.write_bytes(self.raw)
        with patch.object(A.urllib.request,'urlopen',side_effect=AssertionError('Unexpected acquisition')):
            with self.assertRaisesRegex(ValueError,'Fresh exact'):A._acquire('https://example.invalid/input',self.target,self.pin)

    def test_only_opening_github_gateway_failures_get_single_exact_api_recovery(self):
        url='https://github.com/example/inputs/releases/download/v1/input.zip'
        failures=[urllib.error.HTTPError(url,504,'gateway',{},None)for _ in range(3)]
        api=urllib.request.Request('https://api.github.com/repos/example/inputs/releases/assets/123')
        with patch.object(A.urllib.request,'urlopen',side_effect=[*failures,io.BytesIO(self.raw)])as request,\
             patch.object(A,'anonymous_release_download_request',return_value=api)as resolver,patch.object(A.time,'sleep')as pause:
            A._acquire(url,self.target,self.pin)
        resolver.assert_called_once_with(url,dict(size=self.pin['bytes'],sha256=self.pin['sha256']))
        self.assertEqual(request.call_count,4);self.assertIs(request.call_args.args[0],api)
        self.assertEqual([row.args[0]for row in pause.call_args_list],[2,4])

    def test_non_gateway_failure_cannot_request_an_api_recovery(self):
        url='https://github.com/example/inputs/releases/download/v1/input.zip'
        with patch.object(A.urllib.request,'urlopen',side_effect=urllib.error.HTTPError(url,404,'absent',{},None)),\
             patch.object(A,'anonymous_release_download_request',side_effect=AssertionError('No recovery')):
            with self.assertRaises(urllib.error.HTTPError):A._acquire(url,self.target,self.pin)
        self.assertFalse(self.target.exists())

    @unittest.skipIf(os.name=='nt','POSIX symlink control')
    def test_redirected_private_input_is_rejected_before_network(self):
        original=self.root/'original';original.mkdir();link=self.root/'redirect';link.symlink_to(original,target_is_directory=True)
        with patch.object(A.urllib.request,'urlopen',side_effect=AssertionError('Redirected acquisition')):
            with self.assertRaisesRegex(ValueError,'Ordinary absolute'):A._acquire('https://example.invalid/input',link/'input',self.pin)

    def test_diagnostic_or_wrong_sdk_caller_is_rejected_before_work(self):
        for sdk,engine,diagnostic,ptrace in [('7.0.120',A.N.P.DOCKER_ENGINE,False,False),
            (A.N.SDK,['podman'],False,False),(A.N.SDK,A.N.P.DOCKER_ENGINE,True,False),
            (A.N.SDK,A.N.P.DOCKER_ENGINE,False,True)]:
            producer=SimpleNamespace(sdk=sdk,engine=engine,diagnostic=diagnostic,diagnostic_ptrace=ptrace)
            with self.subTest(sdk=sdk,diagnostic=diagnostic,ptrace=ptrace),self.assertRaisesRegex(ValueError,'explicit normal Docker'):
                A.prepare_inputs(producer)


if __name__=='__main__':unittest.main()
