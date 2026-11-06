"""New Core3 archive evidence cannot inherit the old ambient-loader false positive."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import consumer_archive_clean as CLEAN
import consumer_archive_ci as CI
from downstream_release import encoded


def synthetic_report():
    """Explicit metadata-only fixture; it is never a release receipt or runtime proof."""
    version, arch = '3.1.426', 'x64'
    base, curl = '/usr/lib/cbodotnet/compat/rocky9', '/usr/lib/cbodotnet/compat/curl-rocky8'
    plan = dict(sdkVersion=version, packageRevision=3, architecture=arch, archiveLauncherVersion=2,
        sourceManifestSha256='1' * 64, compatibility=dict(root=base), nativeHttpCompatibility=dict(root=curl))
    files = [dict(type='file', path=name, sha256=str(index) * 64) for index, name in enumerate(
        ('lib/libcrypto.so.1.1', 'lib/libicuuc.so.67.1', 'lib/libicui18n.so.67.1', 'lib/libicudata.so.67.1'), 2)]
    files.append(dict(type='file',path='lib/libssl.so.1.1',sha256='6'*64))
    compatibility = dict(companion=dict(path='base.tar.gz', size=12, sha256='a' * 64), manifest=dict(files=files))
    native = dict(companion=dict(path='curl.tar.gz', size=13, sha256='b' * 64), manifest=dict(files=[]))
    payload = dict(sha256='c' * 64, entries=5, files=4, links=1)
    artifact = dict(name='cbodotnet-sdk-3.1.426-linux-x64-r2.tar.gz', size=100, sha256='d' * 64)
    command = dict(path='cbodotnet', size=20, sha256='e' * 64, mode='0755')
    previous = dict(directory='cbodotnet-3.1.426-linux-x64-r2',plan=dict(sourceManifestSha256=plan['sourceManifestSha256']), qualifiedPayload=payload,
                    commands=[command])
    manifest = dict(tag='distribution-archive-sdk-3.1.426-r2', identity=dict(sdkVersion=version, packageRevision=2),
        signingFingerprint='AB' * 20, records=[dict(architecture=arch, build=previous, artifactAsset=artifact['name'])],
        assets=[artifact], compatibility=[dict(architecture=arch, record=compatibility)],
        nativeHttpCompatibility=[dict(architecture=arch, record=native)])
    manifest_sha = hashlib.sha256(encoded(manifest)).hexdigest()
    prefix = f'https://github.com/{CLEAN.REPOSITORY}/releases/download/{manifest["tag"]}/'
    source = dict(schemaVersion=1, status='authenticated', revision=2, sdkVersion=version, architecture=arch,
        manifestUrl=prefix + 'distribution-manifest.json', manifestSha256=manifest_sha,
        signatureUrl=prefix + 'distribution-manifest.json.asc', signingFingerprint=manifest['signingFingerprint'],
        artifact=dict(artifact, url=prefix + artifact['name']), qualifiedPayload=payload, command=command,
        signature=dict(name='distribution-manifest.json.asc', size=228, sha256=CLEAN.HISTORICAL_SIGNATURES[version]))
    components = [dict(path=base + '/' + row['path'], sha256=row['sha256']) for row in files
                  if not row['path'].startswith('lib/libssl.so.')]
    crypto = [dict(path=base + '/' + row['path'],sha256=row['sha256']) for row in files
              if row['path'].startswith(('lib/libcrypto.so.','lib/libssl.so.'))]
    probe = dict(status='passed', scope='clean-archive-private-provider-environment', baseRoot=base, curlRoot=curl,
        certificateFile='/etc/ssl/certs/ca-certificates.crt', opensslConfiguration=base + '/openssl.cnf',
        libraryPath=curl + '/lib:' + base + '/lib', userId=10001, network='none', components=components,
        nativeMappings=['1000-2000 r-xp 0000 00:00 1 ' + row['path'] for row in components])
    functional, native_curl = {'fixture': 'passed'}, {'fixture': 'native-curl',
        'nativeMappings':['1000-2000 r-xp 0000 00:00 1 '+row['path'] for row in crypto]}
    proof = dict(schemaVersion=1, scope=CLEAN.SCOPE, status='passed',
        callerEnvironment='verified-root-variables-only', removedVariables=list(CLEAN.REMOVED),
        rootVariables=CLEAN.roots(plan), cliIsolation='env-unset-before-each-wrapper-execution',
        apphostEnvironment='explicit-documented-provider-environment', providerProbe=probe,
        functionalChecks=functional, nativeCurlHandler=native_curl, nativeCryptoComponents=crypto,
        negativeCases={name: dict(status='passed', exitCode=70, noHostOutput=True) for name in CLEAN.NEGATIVES},
        historicalR2=dict(status='passed', scope='actual-published-r2-clean-caller-curl-failure', source=source,
            runtimeRoot='/opt/cbodotnet-consumer-validation/historical r2 archive/'+previous['directory']+'/payload',
            userId=10001, network='none', forcedSocketsHttpHandler='0',
            positiveControl='passed', correctedRevision=3, historicalExitCode=134, historicalStdout='',
            historicalStderr='System.Net.Http.Native: CURL_OPENSSL_3 was not found', programSha256='1' * 64,
            assembly=dict(name='Repro.dll', size=10, sha256='2' * 64)))
    corrected_artifact=dict(name='cbodotnet-sdk-3.1.426-linux-x64-r3.tar.gz',size=101,sha256='3'*64)
    # The detailed lifecycle validator has separate actual-transaction tests.
    # This fixture isolates clean-caller/source/component binding tests only.
    proof['lifecycle']=dict(reinstall=dict(artifact=dict(corrected_artifact)))
    report = dict(artifact=corrected_artifact,qualifiedPayload=payload, compatibility=compatibility, nativeHttpCompatibility=native,
        historicalR2Publication=dict(source, manifest=manifest), userSpaces=[dict(variant='ubuntu-24.04',
            functionalChecks=functional, nativeCurlHandler=native_curl, cleanCallerEnvironment=proof)])
    return plan, report, manifest_sha


class CleanArchiveTests(unittest.TestCase):
    def test_historical_and_modern_reports_do_not_gain_new_requirements(self):
        for version, revision in [('3.0.103', 1), ('3.1.426', 2), ('5.0.214', 3), ('10.0.403', 99)]:
            plan = dict(sdkVersion=version, packageRevision=revision)
            self.assertFalse(CLEAN.required(plan))
            CLEAN.validate_clean_report({}, plan)

    def test_corrected_core3_cannot_omit_or_downgrade_the_launcher_contract(self):
        for value in (None, 1, '2', True, 3):
            with self.subTest(value=value):
                plan = dict(sdkVersion='3.1.426', packageRevision=3)
                if value is not None:
                    plan['archiveLauncherVersion'] = value
                with self.assertRaises(ValueError):
                    CLEAN.validate_clean_report({}, plan)

    def test_clean_environment_removes_inherited_provider_scope_and_host_roots(self):
        parent = dict.fromkeys((*CLEAN.REMOVED, 'SSL_CERT_FILE'), 'ambient')
        parent.update(PATH='/usr/bin', HOME='/home/user', DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER='0')
        self.assertEqual({'PATH': '/usr/bin', 'HOME': '/home/user',
            'DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER': '0'}, CLEAN.clean_environment(parent))
        self.assertEqual('ambient', CLEAN.clean_environment(parent, preserve_certificate=True)['SSL_CERT_FILE'])
        self.assertEqual('ambient', parent['LD_LIBRARY_PATH'])

    @unittest.skipUnless(os.name == 'posix' and shutil.which('python3'), 'Actual POSIX environment boundary required')
    def test_real_shim_strips_outer_smoke_exports_and_preserves_arguments_and_explicit_ca(self):
        plan = dict(compatibility=dict(root='/verified base'), nativeHttpCompatibility=dict(root='/verified curl'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / 'actual wrapper command'
            actual.write_text('#!/bin/sh\nexec python3 -c \'import os,sys,json; print(json.dumps(dict(arguments=sys.argv[1:], '
                'variables={k:os.environ.get(k) for k in ["LD_LIBRARY_PATH","OPENSSL_CONF","SSL_CERT_FILE",'
                '"CBODOTNET_COMPAT_SCOPE","DOTNET_ROOT","CBODOTNET_COMPAT_ROOT","CBODOTNET_CURL_COMPAT_ROOT"]})))\' "$@"\n')
            actual.chmod(0o755)
            normal = CLEAN.clean_wrapper(root / 'clean shim', actual, plan)
            stock = CLEAN.clean_wrapper(root / 'stock shim', actual, plan, preserve_certificate=False)
            parent = dict(os.environ, LD_LIBRARY_PATH='/ambient/lib', OPENSSL_CONF='/ambient/config',
                SSL_CERT_FILE='', CBODOTNET_COMPAT_SCOPE='rocky9', DOTNET_ROOT='/wrong/runtime')
            output = subprocess.check_output([normal, 'argument with spaces', ''], env=parent, text=True)
            proof = json.loads(output)
            self.assertEqual(['argument with spaces', ''], proof['arguments'])
            self.assertEqual('', proof['variables']['SSL_CERT_FILE'])
            self.assertEqual('/verified base', proof['variables']['CBODOTNET_COMPAT_ROOT'])
            self.assertEqual('/verified curl', proof['variables']['CBODOTNET_CURL_COMPAT_ROOT'])
            self.assertTrue(all(proof['variables'][name] is None for name in
                ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CBODOTNET_COMPAT_SCOPE', 'DOTNET_ROOT')))
            self.assertIsNone(json.loads(subprocess.check_output([stock], env=parent, text=True))['variables']['SSL_CERT_FILE'])
            self.assertEqual('/ambient/lib', parent['LD_LIBRARY_PATH'])

    def test_exact_provider_components_and_original_r2_asset_bindings_are_mandatory(self):
        plan, report, manifest_sha = synthetic_report()
        with mock.patch.dict(CLEAN.HISTORICAL_MANIFESTS, {plan['sdkVersion']: manifest_sha}),\
                mock.patch('consumer_archive_lifecycle.validate_lifecycle_evidence') as lifecycle_gate:
            CLEAN.validate_clean_report(report, plan)
            lifecycle_gate.assert_called_once_with(report['userSpaces'][0]['cleanCallerEnvironment']['lifecycle'],plan)
            mutations = [
                lambda r: r['userSpaces'][0].pop('cleanCallerEnvironment'),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['providerProbe']['components'][0].update(sha256='0' * 64),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['providerProbe'].update(libraryPath='/system/lib'),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['nativeCryptoComponents'].pop(),
                lambda r: r['userSpaces'][0]['nativeCurlHandler']['nativeMappings'].pop(),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['historicalR2'].update(historicalExitCode=0),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['historicalR2'].update(positiveControl='not-run'),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['historicalR2'].update(runtimeRoot='/wrong/payload'),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['historicalR2']['assembly'].update(size=0),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['negativeCases'].pop('tampered-curl'),
                lambda r: r['historicalR2Publication']['artifact'].update(sha256='0' * 64),
                lambda r: r['historicalR2Publication'].update(signatureUrl='https://example.invalid/fake.asc'),
                lambda r: r['historicalR2Publication']['signature'].update(sha256='0' * 64),
                lambda r: r['historicalR2Publication']['signature'].update(size=229),
                lambda r: r['userSpaces'][0]['cleanCallerEnvironment']['lifecycle']['reinstall']['artifact'].update(sha256='0'*64),
                lambda r: r['historicalR2Publication']['manifest']['records'][0]['build']['commands'][0].update(sha256='0' * 64),
            ]
            for index, mutate in enumerate(mutations):
                changed = copy.deepcopy(report); mutate(changed)
                with self.subTest(case=index), self.assertRaises(ValueError):
                    CLEAN.validate_clean_report(changed, plan)

    def test_corrected_archive_cannot_skip_real_lifecycle_validation(self):
        plan,report,manifest_sha=synthetic_report()
        report['userSpaces'][0]['cleanCallerEnvironment'].pop('lifecycle')
        with mock.patch.dict(CLEAN.HISTORICAL_MANIFESTS,{plan['sdkVersion']:manifest_sha}):
            with self.assertRaisesRegex(ValueError,'lifecycle proof'):
                CLEAN.validate_clean_report(report,plan)

    def test_native_rpm_bases_are_per_cpu_and_bootstrap_installs_reviewed_python_before_harness(self):
        for variant in ('fedora-45', 'rocky-9.8'):
            self.assertNotEqual(CI.base_image(variant, 'x64'), CI.base_image(variant, 'aarch64'))
            self.assertTrue(all('@sha256:' in CI.base_image(variant, arch) for arch in ('x64', 'aarch64')))
            command = CI.container_prepare_command(variant)
            self.assertIn('dnf -y', command)
            if variant == 'rocky-9.8':
                self.assertIn('/usr/bin/python3.12', command)
            if shutil.which('bash'):
                subprocess.run(['bash', '-n'], input=command + 'true', text=True, check=True)


if __name__ == '__main__':
    unittest.main()
