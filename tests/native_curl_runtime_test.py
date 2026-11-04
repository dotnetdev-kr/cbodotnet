import base64
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import legacy_curl
import native_curl_runtime as CURL


def proof(version='3.1.426',architecture='x64',root='/opt/cbodotnet/3.1'):
    pins=legacy_curl.runtime_pins(dict(sdkVersion=version,architecture=dict(public=architecture)))
    curl=legacy_curl.PROVIDER_ROOT
    data=dict(status='passed',handler='CurlHandler',http='passed',https='passed',httpsDefaultTrust='passed',tls12='passed',
        callbackCount=1,network='none',userId=10001,nativeHttp=dict(path=root+'/'+pins['nativeHttp']['path'],sha256=pins['nativeHttp']['sha256']),
        curl=dict(path=curl+'/'+pins['curl']['path'],sha256=pins['curl']['sha256']))
    data['nativeMappings']=['0001-0002 r-xp 00000000 00:00 123 '+data[name]['path'] for name in ('nativeHttp','curl')]
    return data


class NativeCurlRuntimeTests(unittest.TestCase):
    def test_sdk5_uses_normal_sockets_default_trust_in_a_fresh_process_without_native_curl(self):
        environment={'LD_LIBRARY_PATH':'/usr/lib/cbodotnet/compat/rocky9/lib','SSL_CERT_FILE':'/etc/ssl/certs/ca-certificates.crt'}
        with patch.object(legacy_curl,'load_policy',side_effect=AssertionError('SDK5 must not load the Core3 Curl policy')):
            script=CURL.standard_trust_script('5.0.214','/opt/cbodotnet/5.0','cbot-smoke',runtime_env=environment)
        self.assertIn('<TargetFramework>net5.0</TargetFramework>',script)
        self.assertIn('const bool NativeCurl=false;',script)
        self.assertNotIn('DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0 cbodotnet',script)
        self.assertIn('standardHandler.ServerCertificateCustomValidationCallback!=null',script)
        self.assertLess(script.index('NativeCurl.dll fixture\n'),script.index('export SSL_CERT_FILE=/work/native-ca/fixture/trusted-ca.pem'))
        subprocess.run(['bash','-n'],input=script,text=True,check=True)
        proof=dict(status='passed',handler='SocketsHttpHandler',defaultTrustHttps='passed',tls12='passed',network='none',userId=10001)
        self.assertEqual(proof,CURL.validate_standard_trust('CBODOTNET_NATIVE_CA_PROOF='+json.dumps(proof)))
        for field,value in [('handler','CurlHandler'),('defaultTrustHttps','not-run'),('userId',0),('network','bridge')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                CURL.validate_standard_trust('CBODOTNET_NATIVE_CA_PROOF='+json.dumps(dict(proof,**{field:value})))

    def test_parser_requires_exact_sdk_provider_objects_and_complete_http_tls_trust_user_proof(self):
        original=proof()
        def parse(value):
            return CURL.validate('build output\nCBODOTNET_NATIVE_CURL_PROOF='+json.dumps(value),'3.1.426',
                '/opt/cbodotnet/3.1',legacy_curl.PROVIDER_ROOT,10001,'x64')
        self.assertEqual(original,parse(original))
        for field,value in [('httpsDefaultTrust','not-run'),('https','not-run'),('callbackCount',0),('network','bridge'),
                            ('userId',0),('handler','SocketsHttpHandler'),('nativeMappings',[])]:
            changed=dict(original,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):parse(changed)
        for name in ('nativeHttp','curl'):
            for key,value in [('sha256','0'*64),('path','/usr/lib/libcurl.so.4')]:
                changed=copy.deepcopy(original);changed[name][key]=value
                with self.subTest(name=name,key=key),self.assertRaises(ValueError):parse(changed)
        with self.assertRaisesRegex(ValueError,'Exactly one'):
            CURL.validate('CBODOTNET_NATIVE_CURL_PROOF='+json.dumps(original)+'\nCBODOTNET_NATIVE_CURL_PROOF='+json.dumps(original),
                '3.1.426','/opt/cbodotnet/3.1',legacy_curl.PROVIDER_ROOT,10001,'x64')

    def test_real_proc_map_octal_escapes_allow_relocated_payload_without_changing_raw_evidence(self):
        original=proof(root='/work/relocated sdk/payload')
        original['nativeMappings'][0]=original['nativeMappings'][0].replace(' ','\\040')
        parsed=CURL.validate('CBODOTNET_NATIVE_CURL_PROOF='+json.dumps(original),'3.1.426',
            '/work/relocated sdk/payload',legacy_curl.PROVIDER_ROOT,10001,'x64')
        self.assertEqual(original['nativeMappings'],parsed['nativeMappings'])

    def test_fixture_process_finishes_before_trust_is_exported_and_fresh_proof_process_starts(self):
        environment={'LD_LIBRARY_PATH':legacy_curl.PROVIDER_ROOT+'/lib','SSL_CERT_FILE':'/etc/ssl/certs/ca-certificates.crt'}
        script=CURL.script('3.1.426','/opt/cbodotnet/3.1','app',runtime_env=environment,
            curl_root=legacy_curl.PROVIDER_ROOT,user_id=1654)
        fixture=script.index('NativeCurl.dll fixture\n')
        trust=script.index('export SSL_CERT_FILE=/work/native-curl/fixture/trusted-ca.pem',fixture)
        execution=script.index('DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0 cbodotnet bin/Debug/',trust)
        self.assertLess(fixture,trust);self.assertLess(trust,execution)
        self.assertIn('CBODOTNET_NATIVE_CURL_PROOF=',script)
        self.assertNotIn('NATIVE_HANDLER_MARKER',script)
        self.assertIn('standardHandler.ServerCertificateCustomValidationCallback!=null',script)
        subprocess.run(['bash','-n'],input=script,text=True,check=True)

    def test_public_image_transfer_rejects_unowned_or_escaping_provider_members(self):
        for name,uid in [('../escape',0),('lib',1654)]:
            output=io.BytesIO()
            with tarfile.open(fileobj=output,mode='w:gz') as archive:
                member=tarfile.TarInfo(name);member.type=tarfile.DIRTYPE;member.uid=uid;member.mode=0o755
                archive.addfile(member)
            encoded=base64.b64encode(output.getvalue()).decode()
            with self.subTest(name=name,uid=uid),self.assertRaises(ValueError):
                CURL.image_provider_proof('image',dict(sdkVersion='3.1.426',architecture=dict(public='x64')),lambda command:encoded)


if __name__=='__main__':unittest.main()
