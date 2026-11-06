"""New Core3 archive launchers verify companions and scope the complete ABI."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive as CA
import legacy_compat as BASE
import legacy_curl as CURL

SCOPED=('LD_LIBRARY_PATH','OPENSSL_CONF','CLR_OPENSSL_VERSION_OVERRIDE','CLR_ICU_VERSION_OVERRIDE','SSL_CERT_FILE')


def plan(version='3.1.426',arch='aarch64',revision=3,launcher=2):
    result=dict(sdkVersion=version,architecture=arch,packageRevision=revision,contractVersion=2,
        sourceReleaseTag='sdk-'+version,sourceManifestSha256=CA.load_contract()['releases'][version]['manifestSha256'],
        targetRid=CA.ARCHITECTURES[arch]['rid'])
    if launcher is not None:result['archiveLauncherVersion']=launcher
    result['compatibility']=CA.compatibility_policy(result)
    native=CA.native_http_compatibility_policy(result)
    if native is not None:result['nativeHttpCompatibility']=native
    return result


class ArchiveLauncherContractTests(unittest.TestCase):
    def test_historical_core3_wrapper_bytes_stay_bound_to_their_public_descriptors(self):
        expected={
            ('3.1.426','aarch64'):('c58ba3f0e234af88a327c823305e1259196cddb158a8a5a6556ef03fd4b9f7f1',8146),
            ('3.1.426','x64'):('c1d598ed611cd2f055eeb837bfe2958d86a8332a756151663f602f1d6adfd43a',9326),
            ('3.0.103','aarch64'):('3cac060f70d215ad19083204a7530f387c81cce3601cd54ae1de2cbf39c6a670',8146),
            ('3.0.103','x64'):('1c0619ae637b495bfe81d510c86a0cbb2ab7efc9e5cdc810c6cd197810f0bb80',9326)}
        for key,(sha,size) in expected.items():
            historical=plan(*key,revision=2,launcher=None)
            self.assertEqual('/etc/ssl/certs/ca-certificates.crt',historical['compatibility']['archiveCaBundle'])
            self.assertNotIn('archiveCaBundles',historical['compatibility'])
            raw=CA.launcher_text(historical).encode()
            with self.subTest(sdk=key):
                self.assertEqual(size,len(raw));self.assertEqual(sha,hashlib.sha256(raw).hexdigest())
                self.assertNotIn(b'CBODOTNET_CURL_COMPAT_ROOT',raw)

    def test_exact_approved_companion_manifests_reconstruct_without_filesystem_or_network(self):
        expected={
            ('x64',BASE.PROVIDER_ROOT):('19a1f16972f653df3f0d32a0ac483689fc3cbd8486eb197030d2446754d4e430',8365),
            ('aarch64',BASE.PROVIDER_ROOT):('c046b0f8b0c2f8bd2bfb3f56f8c4ab449d8c35e97b6441a075a0ea794dd9d4f6',8495),
            ('x64',CURL.PROVIDER_ROOT):('bbdee2b4969c3b708dab32121dd40468e923462e3a0c3fb8652755e3c6cb2ff3',4486),
            ('aarch64',CURL.PROVIDER_ROOT):('80e456481dd20c502b1611569739add56fad29982b569b9ef8ffdcf194f4b3c3',4530)}
        for arch in ('x64','aarch64'):
            records=CA.archive_provider_records(plan(arch=arch))
            self.assertEqual([BASE.PROVIDER_ROOT,CURL.PROVIDER_ROOT],[row['root'] for row in records])
            for record in records:
                manifest=next(row for row in record['inventory'] if row['path']=='provider-manifest.json')
                self.assertEqual(expected[(arch,record['root'])],(manifest['sha256'],manifest['size']))

    def test_new_contract_is_explicit_core3_only_and_binds_reviewed_ca_candidates(self):
        value=plan()
        self.assertEqual(['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt'],value['compatibility']['archiveCaBundles'])
        self.assertNotIn('archiveCaBundle',value['compatibility'])
        wrapper=CA.launcher_text(value)
        self.assertIn('CBODOTNET_CURL_COMPAT_ROOT',wrapper)
        self.assertIn('"archiveLauncherVersion":2',wrapper)
        for invalid in (True,0,3,'2'):
            with self.subTest(version=invalid),self.assertRaisesRegex(ValueError,'launcher version'):
                CA.launcher_text(dict(value,archiveLauncherVersion=invalid))
        for invalid in (dict(value,packageRevision=2),plan('5.0.214')):
            with self.assertRaisesRegex(ValueError,'only admitted'):
                CA.launcher_text(invalid)
        changed=copy.deepcopy(value);changed['compatibility']['archiveCaBundles'].append('/tmp/unreviewed')
        with self.assertRaisesRegex(ValueError,'reviewed archive CA'):
            CA.launcher_text(changed)


@unittest.skipUnless(os.name=='posix' and all(shutil.which(name) for name in ('sh','sha256sum','find','stat','readlink','grep')),
                     'POSIX archive launcher/coreutils execution required')
class Core3ArchiveProcessTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='Core3 archive fixture-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.base=self.root/'base "quoted"\\ ssl';self.curl=self.root/'curl with spaces'
        for root,names in ((self.base,['lib/libcrypto.so.1.1','lib/libssl.so.1.1','lib/libicuuc.so.67',
            'lib/libicui18n.so.67','lib/libicudata.so.67','openssl.cnf','provider-manifest.json']),
            (self.curl,['lib/libcurl.so.4.5.0','provider-manifest.json'])):
            (root/'lib').mkdir(parents=True)
            for name in names:
                path=root/name;path.write_bytes(('fixture:'+root.name+':'+name).encode())
                path.chmod(0o755 if name.startswith('lib/') else 0o644)
        (self.curl/'lib/libcurl.so.4').symlink_to('libcurl.so.4.5.0')
        records=[dict(variable=variable,root=module.PROVIDER_ROOT,providerId='test-'+module.PROVIDER_ROOT.rsplit('/',1)[-1],
            inventory=BASE.tree_inventory(root)) for variable,module,root in
            [('CBODOTNET_COMPAT_ROOT',BASE,self.base),('CBODOTNET_CURL_COMPAT_ROOT',CURL,self.curl)]]
        patch=mock.patch.object(CA,'archive_provider_records',return_value=records);patch.start();self.addCleanup(patch.stop)
        self.legacy=self.wrapper('legacy',plan())
        self.modern=self.wrapper('modern',plan('10.0.403',launcher=None))
        self.sdk5=self.wrapper('sdk5',plan('5.0.214',launcher=None))
        self.environment={key:value for key,value in os.environ.items() if not (key in SCOPED or key.startswith('CBODOTNET_COMPAT_') or key=='CBODOTNET_CURL_COMPAT_ROOT')}
        self.environment.update(CBODOTNET_COMPAT_ROOT=str(self.base),CBODOTNET_CURL_COMPAT_ROOT=str(self.curl))

    def wrapper(self,name,selected):
        root=self.root/name;(root/'payload').mkdir(parents=True)
        prints=''.join('printf \'%s=%s:%s\\n\' '+key+' "${'+key+'+x}" "${'+key+'-}"\n' for key in SCOPED+('CBODOTNET_COMPAT_SCOPE',))
        host='#!/bin/sh\ncase "${1-}" in\n--version) printf \'%s\\n\' '+selected['sdkVersion']+' ;;\n'
        host+='nested) shift; exec "$NEXT_WRAPPER" "$@" ;;\nnested-after-failure) shift; sh -c \'exit 7\'; result=$?; [ "$result" = 7 ] || exit 99; exec "$NEXT_WRAPPER" "$@" ;;\n'
        host+='fail) '+prints+'exit 7 ;;\n*) '+prints+';;\nesac\n'
        (root/'payload/dotnet').write_text(host);(root/'payload/dotnet').chmod(0o755)
        wrapper=root/'cbodotnet';wrapper.write_text(CA.launcher_text(selected));wrapper.chmod(0o755)
        return wrapper

    def invoke(self,*arguments,extra=None):
        env=dict(self.environment);env.update(extra or {})
        result=subprocess.run([str(self.legacy),*arguments],env=env,capture_output=True,text=True)
        return result

    def state(self,result):
        self.assertEqual('',result.stderr)
        return dict(line.split('=',1) for line in result.stdout.splitlines())

    def test_roots_only_activate_curl_first_and_retain_unset_empty_or_custom_caller_scope(self):
        for original in ({},{key:'' for key in SCOPED},{key:'/caller '+key for key in SCOPED}):
            with self.subTest(original=original):
                result=self.invoke('print',extra=original);self.assertEqual(0,result.returncode)
                current=self.state(result)
                expected=str(self.curl)+'/lib:'+str(self.base)+'/lib'+(':'+original['LD_LIBRARY_PATH'] if original.get('LD_LIBRARY_PATH') else '')
                self.assertEqual('x:'+expected,current['LD_LIBRARY_PATH'])
                self.assertEqual('x:'+str(self.base)+'/openssl.cnf',current['OPENSSL_CONF'])
                self.assertEqual('x:1.1',current['CLR_OPENSSL_VERSION_OVERRIDE']);self.assertEqual('x:67',current['CLR_ICU_VERSION_OVERRIDE'])
                ca=original.get('SSL_CERT_FILE',next(path for path in plan()['compatibility']['archiveCaBundles'] if Path(path).is_file()))
                self.assertEqual('x:'+ca,current['SSL_CERT_FILE'])
                self.assertEqual('x:rocky9',current['CBODOTNET_COMPAT_SCOPE'])
                failed=self.invoke('fail',extra=original);self.assertEqual(7,failed.returncode);self.assertEqual(current,self.state(failed))

    def test_modern_and_sdk5_children_restore_the_original_caller_after_success_or_failed_child(self):
        for original in ({},{key:'' for key in SCOPED},{key:'/caller '+key for key in SCOPED}):
            for command in ('nested','nested-after-failure'):
                with self.subTest(original=original,command=command):
                    result=self.invoke(command,'print',extra=dict(original,NEXT_WRAPPER=str(self.modern)))
                    self.assertEqual(0,result.returncode);current=self.state(result)
                    self.assertEqual({key:('x:'+original[key] if key in original else ':') for key in SCOPED},
                                     {key:current[key] for key in SCOPED})
                    self.assertEqual(':',current['CBODOTNET_COMPAT_SCOPE'])
            sdk5=self.invoke('nested','print',extra=dict(original,NEXT_WRAPPER=str(self.sdk5)))
            self.assertEqual(0,sdk5.returncode);current=self.state(sdk5)
            self.assertEqual('x:'+str(self.base)+'/lib'+(':'+original['LD_LIBRARY_PATH'] if original.get('LD_LIBRARY_PATH') else ''),current['LD_LIBRARY_PATH'])
            self.assertEqual('x:'+original['CLR_ICU_VERSION_OVERRIDE'] if 'CLR_ICU_VERSION_OVERRIDE' in original else ':',current['CLR_ICU_VERSION_OVERRIDE'])

    def test_missing_substituted_modified_and_unaccounted_companions_fail_before_payload_execution(self):
        self.assertEqual('3.1.426\n',self.invoke('--version').stdout)
        for path in (self.base/'openssl.cnf',self.curl/'lib/libcurl.so.4.5.0',self.curl/'provider-manifest.json'):
            original=path.read_bytes();path.write_bytes(original+b'substituted')
            failed=self.invoke('--version');self.assertEqual(70,failed.returncode);self.assertEqual('',failed.stdout)
            path.write_bytes(original)
            moved=path.with_name(path.name+'.missing');path.rename(moved)
            failed=self.invoke('--version');self.assertEqual(70,failed.returncode);self.assertEqual('',failed.stdout)
            moved.rename(path)
        extra=self.curl/'lib/unreviewed.so';extra.write_bytes(b'wrong loader dependency')
        self.assertEqual(70,self.invoke('--version').returncode);extra.unlink()
        link=self.curl/'lib/libcurl.so.4';link.unlink();link.symlink_to('/unreviewed/libcurl.so.4')
        self.assertEqual(70,self.invoke('--version').returncode);link.unlink();link.symlink_to('libcurl.so.4.5.0')
        library=self.curl/'lib/libcurl.so.4.5.0';library.chmod(0o777)
        self.assertEqual(70,self.invoke('--version').returncode);library.chmod(0o755)
        self.assertEqual(70,self.invoke('--version',extra={'CBODOTNET_CURL_COMPAT_ROOT':str(self.base)}).returncode)
        self.assertEqual('3.1.426\n',self.invoke('--version').stdout)

    def test_unsafe_or_symlinked_roots_fail_while_identity_stays_provider_free(self):
        for key in ('CBODOTNET_COMPAT_ROOT','CBODOTNET_CURL_COMPAT_ROOT'):
            for value in ('relative','/','/a/../other','/a/./other','/double//slash','/unsafe:root','/unsafe;root',
                          '/unsafe$ORIGIN','/unsafe\nroot','/unsafe\troot'):
                with self.subTest(key=key,value=value):
                    failed=self.invoke('--version',extra={key:value})
                    self.assertEqual(70,failed.returncode);self.assertEqual('',failed.stdout)
            missing=self.root/'missing'
            self.assertEqual(70,self.invoke('--version',extra={key:str(missing)}).returncode)
        alias=self.root/'base-alias';alias.symlink_to(self.base,target_is_directory=True)
        self.assertEqual(70,self.invoke('--version',extra={'CBODOTNET_COMPAT_ROOT':str(alias)}).returncode)
        ancestor=self.root/'ancestor-alias';ancestor.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(70,self.invoke('--version',extra={'CBODOTNET_COMPAT_ROOT':str(ancestor/self.base.name)}).returncode)
        info=self.invoke('--cbodotnet-info',extra={'CBODOTNET_COMPAT_ROOT':'/missing','CBODOTNET_CURL_COMPAT_ROOT':'/missing'})
        self.assertEqual(0,info.returncode);self.assertEqual(2,json.loads(info.stdout)['archiveLauncherVersion'])


if __name__=='__main__':unittest.main()
