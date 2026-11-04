import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
SPEC=importlib.util.spec_from_file_location('core3_curl_probe',ROOT/'scripts/core3-curl-runtime-probe.py')
PROBE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PROBE)


class CandidateProbeTests(unittest.TestCase):
    def test_exact_current_vendor_rpm_source_and_elf_bytes_remain_unqualified(self):
        for arch in ('x64','aarch64'):
            item=PROBE.candidate(arch)
            self.assertTrue(item['url'].startswith('https://dl.rockylinux.org/pub/rocky/9/BaseOS/'))
            self.assertEqual(64,len(item['sha256']))
            self.assertEqual(64,len(PROBE.CANDIDATES[arch]['elfSha256']))
        self.assertEqual('curl-7.76.1-40.el9_8.9.src.rpm',PROBE.SOURCE['name'])

    def test_actual_curl_handler_http_https_callback_tls_and_mappings_are_required(self):
        text=PROBE.program('3.1.426','/qualified/sdk','/candidate/curl')
        for expected in ('AppContext.SetSwitch("System.Net.Http.UseSocketsHttpHandler",false)',
            'SslProtocols.Tls12','ServerCertificateCustomValidationCallback','callbacks==0','"CurlHandler"',
            '/proc/self/maps','System.Net.Http.Native.so','/lib/libcurl.so.4.7.0','await Exchange(client,certificate,false)',
            'await Exchange(client,certificate,true)','forced-curl-http-passed-before-https','Encoding.ASCII.GetByteCount(body)'):
            self.assertIn(expected,text)
        self.assertNotIn('return true;',text)
        self.assertIn('remote.RawData.SequenceEqual(certificate.RawData)',text)

    def test_workflow_never_signs_publishes_or_uses_a_private_key(self):
        text=(ROOT/'.github/workflows/core3-curl-runtime-check.yml').read_text()
        self.assertIn('contents: read',text)
        self.assertNotIn('contents: write',text)
        self.assertNotIn('DOWNSTREAM_SIGNING_KEY',text)
        self.assertIn("github.event_name == 'workflow_dispatch'",text)


if __name__=='__main__':unittest.main()
