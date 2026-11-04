"""Reject misleading RPM target, integrity, offline and provenance evidence."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('rpm_ci', ROOT / 'scripts/rpm-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class RpmCiTests(unittest.TestCase):
    def test_native_library_observation_uses_the_same_scoped_provider_without_mutating_parent_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / 'sdk'
            paths = ['dotnet', 'host/fxr/3.1.32/libhostfxr.so',
                *['shared/Microsoft.NETCore.App/3.1.32/' + name for name in ('libcoreclr.so', 'libhostpolicy.so',
                   'libSystem.Native.so', 'libSystem.Globalization.Native.so', 'libSystem.Security.Cryptography.Native.OpenSsl.so')]]
            for name in paths:
                path = sdk / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fixture-elf')
            scoped = {'LD_LIBRARY_PATH': '/usr/lib/cbodotnet/compat/rocky9/lib', 'CLR_OPENSSL_VERSION_OVERRIDE': '1.1'}
            original = dict(CI.os.environ)
            with mock.patch.object(CI, 'run', return_value='all native dependencies resolved\n') as inspect:
                CI.native_libraries(dict(package=dict(root=str(sdk))), root, runtime_env=scoped)
            self.assertEqual(7, inspect.call_count)
            self.assertTrue(all(call.kwargs['env']['LD_LIBRARY_PATH'] == scoped['LD_LIBRARY_PATH'] for call in inspect.call_args_list))
            self.assertEqual(original, dict(CI.os.environ))

    def test_signed_reinstall_retains_independent_verified_bytes_before_dnf_cache_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            delivery = Path(temporary)
            source = delivery / 'cache/sdk.rpm'
            source.parent.mkdir()
            source.write_bytes(b'authenticated-rpm')
            with mock.patch.object(CI, 'verify_package_signature') as signature:
                paths = CI.retain_signed_packages(delivery, [source])
            signature.assert_called_once_with(source)
            source.unlink()
            self.assertEqual(b'authenticated-rpm', paths[0].read_bytes())
            self.assertEqual(delivery / 'retained-packages/sdk.rpm', paths[0])

    def test_hosted_repository_preserves_initial_alias_and_isolates_each_later_sdk_revision(self):
        base = 'https://dotnetdev.kr/cbodotnet/packages/rpm'
        self.assertEqual(base + '/fedora-45', CI.hosted_repository_url(base, 'fedora-45', '10.0.403', 1))
        self.assertEqual(base + '/rocky-9.8/sdk-9.0.123-r1', CI.hosted_repository_url(base, 'rocky-9.8', '9.0.123', 1))
        self.assertEqual(base + '/fedora-45/sdk-10.0.403-r2', CI.hosted_repository_url(base, 'fedora-45', '10.0.403', 2))
        for bad_base, variant, version, revision in [('https://example.com/rpm', 'fedora-45', '9.0.123', 1),
                (base, '../fedora-45', '9.0.123', 1), (base, 'fedora-45', '9.0.123/..', 1), (base, 'fedora-45', '9.0.123', 0)]:
            with self.subTest(base=bad_base, variant=variant, version=version, revision=revision), self.assertRaises(ValueError):
                CI.hosted_repository_url(bad_base, variant, version, revision)

    def publication_fixture(self, directory):
        from downstream_publish import MANIFEST, SIGNATURE, PUBLIC_KEY, publication_rows
        from downstream_release import descriptor
        contract = CI.load_contract()
        identity = dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1,
                        sourceReleaseTag='sdk-10.0.403',
                        sourceManifestSha256=contract['releases']['10.0.403']['manifestSha256'])
        tag = 'distribution-rpm-sdk-10.0.403-r1'
        base = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/' + tag + '/'
        signer = 'A' * 40
        record = dict(identity=dict(identity, variant='fedora-45'), architecture='x64',
                      artifact={'sha256': 'b' * 64}, report={'sha256': 'c' * 64})
        manifest = dict(schemaVersion=1, status='validated-complete-matrix', repository='dotnetdev-kr/cbodotnet',
                        contractVersion=contract['schemaVersion'], identity=identity, tag=tag,
                        signingFingerprint=signer, repositories=[],
                        assets=[{'name': PUBLIC_KEY, 'size': 12, 'sha256': 'd' * 64}],
                        records=[dict(record=record, artifactAsset='sdk.rpm', reportAsset='report.json')])
        CI.save(directory / MANIFEST, manifest)
        (directory / SIGNATURE).write_bytes(b'fixture-signature')
        digest = CI.SHARED.digest(directory / MANIFEST)
        assets = manifest['assets'] + [descriptor(directory / name) for name in (MANIFEST, SIGNATURE)]
        receipt = dict(schemaVersion=1, status='published-postverified', publicationAllowed=True,
                       repository=manifest['repository'], identity=identity, tag=tag,
                       releaseUrl='https://github.com/dotnetdev-kr/cbodotnet/releases/tag/' + tag,
                       manifestUrl=base + MANIFEST, signatureUrl=base + SIGNATURE, publicKeyUrl=base + PUBLIC_KEY,
                       manifestSha256=digest, signingFingerprint=signer, repositories=[],
                       publications=publication_rows(manifest, digest, base),
                       assets=[dict(item, url=base + item['name']) for item in assets])
        return receipt, manifest, signer

    def test_public_receipt_rejects_other_projects_tags_sources_and_urls_before_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, _, _ = self.publication_fixture(Path(temporary))
            self.assertTrue(CI.validate_receipt(receipt).endswith(receipt['tag'] + '/'))
            for key, replacement in [('repository', 'someone/cbodotnet'), ('tag', 'distribution-rpm-sdk-10.0.403-r2'),
                                     ('manifestUrl', 'https://example.com/manifest.json'), ('publicationAllowed', False)]:
                modified = copy.deepcopy(receipt)
                modified[key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError):
                    CI.validate_receipt(modified)
            modified = copy.deepcopy(receipt)
            modified['identity']['sourceManifestSha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'no longer admitted'):
                CI.validate_receipt(modified)

    def test_signed_publication_binds_receipt_identity_assets_and_target_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt, manifest, signer = self.publication_fixture(directory)
            CI.bind_signed_receipt(receipt, manifest, signer, directory)
            for field in ('identity', 'tag', 'signingFingerprint', 'contractVersion'):
                changed = copy.deepcopy(manifest)
                changed[field] = {'channel': 'rpm'} if field == 'identity' else 'unexpected'
                with self.subTest(manifest=field), self.assertRaises(ValueError):
                    CI.bind_signed_receipt(receipt, changed, signer, directory)
            for field in ('repositories', 'publications', 'assets'):
                changed = copy.deepcopy(receipt)
                changed[field] = [] if field != 'repositories' else [{'asset': 'other.tar.gz'}]
                with self.subTest(receipt=field), self.assertRaises(ValueError):
                    CI.bind_signed_receipt(changed, manifest, signer, directory)
            changed = copy.deepcopy(manifest)
            changed['records'][0]['record']['identity']['sourceManifestSha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'target identity'):
                CI.bind_signed_receipt(receipt, changed, signer, directory)

    def test_target_requires_exact_distribution_version_and_native_architecture(self):
        contract = {'operatingSystems': {'fedora-45': {'id': 'fedora', 'versionId': '45'},
                                        'rocky-9.8': {'id': 'rocky', 'versionId': '9.8'}}}
        plan = {'variant': 'rocky-9.8', 'architecture': {'public': 'aarch64'}}
        with mock.patch.object(CI, 'load_contract', return_value=contract):
            self.assertEqual(contract['operatingSystems']['rocky-9.8'],
                             CI.validate_target(plan, {'ID': 'rocky', 'VERSION_ID': '9.8'}, 'aarch64'))
            for release, machine in [({'ID': 'rocky', 'VERSION_ID': '9.7'}, 'aarch64'),
                                     ({'ID': 'almalinux', 'VERSION_ID': '9.8'}, 'aarch64'),
                                     ({'ID': 'rocky', 'VERSION_ID': '9.8'}, 'x86_64')]:
                with self.subTest(release=release, machine=machine), self.assertRaises(ValueError):
                    CI.validate_target(plan, release, machine)

    def test_integrity_requires_empty_output_even_if_rpm_returns_success(self):
        with mock.patch.object(CI, 'run', return_value='S.5....T. /usr/bin/cbodotnet\n'):
            with self.assertRaisesRegex(ValueError, 'changed or missing'):
                CI.strict_integrity(['cbodotnet-sdk-10.0', 'cbodotnet-host'])
        with mock.patch.object(CI, 'run', side_effect=RuntimeError('rpm verification failed')):
            with self.assertRaises(RuntimeError):
                CI.strict_integrity(['cbodotnet-host'])

    def test_installed_rpm_identity_cannot_substitute_release_or_architecture(self):
        plan = {'sdkVersion': '10.0.403', 'packageRevision': 1, 'architecture': {'rpm': 'aarch64'},
                'package': {'name': 'cbodotnet-sdk-10.0', 'rpmRelease': '1.cbot.rocky9.8'}}
        with mock.patch.object(CI, 'run', side_effect=['10.0.403\t1.cbot.rocky9.8\taarch64', '1.0.0\t1.cbot.rocky9.8\tnoarch']):
            self.assertEqual('aarch64', CI.package_identities(plan)['cbodotnet-sdk-10.0']['architecture'])
        for replacement in ('10.0.403\t1.cbot.fedora45\taarch64', '10.0.403\t1.cbot.rocky9.8\tx86_64'):
            with self.subTest(replacement=replacement), mock.patch.object(CI, 'run', return_value=replacement):
                with self.assertRaisesRegex(ValueError, 'RPM identity'):
                    CI.package_identities(plan)

    def test_all_native_dependency_providers_must_be_observed(self):
        plan = {'dependencies': ['glibc', 'zlib-ng-compat']}
        with mock.patch.object(CI, 'run', side_effect=['glibc-2.42-1.x86_64\n', 'zlib-ng-compat-2.2-1.x86_64\n']):
            self.assertEqual(set(plan['dependencies']), set(CI.observed_dependencies(plan)))
        with mock.patch.object(CI, 'run', side_effect=['glibc-2.42-1.x86_64', 'no package provides zlib-ng-compat']):
            with self.assertRaisesRegex(ValueError, 'Unavailable native'):
                CI.observed_dependencies(plan)

    def test_prefixed_dnf_cache_assets_are_selected_by_complete_rpm_header_identity(self):
        plan = {'sdkVersion': '10.0.403', 'packageRevision': 1, 'architecture': {'rpm': 'aarch64'},
                'package': {'name': 'cbodotnet-sdk-10.0', 'rpmRelease': '1.cbot.rocky9.8'}}
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            sdk = cache / 'rpm-rocky-9.8-aarch64--cbodotnet-sdk-10.0-10.0.403-1.cbot.rocky9.8.aarch64.rpm'
            host = cache / 'rpm-rocky-9.8--cbodotnet-host-1.0.0-1.cbot.rocky9.8.noarch.rpm'
            unrelated = cache / 'unrelated-runtime.rpm'
            for path in (sdk, host, unrelated):
                path.write_bytes(b'fixture')
            headers = {sdk: 'cbodotnet-sdk-10.0\t10.0.403\t1.cbot.rocky9.8\taarch64',
                       host: 'cbodotnet-host\t1.0.0\t1.cbot.rocky9.8\tnoarch',
                       unrelated: 'glibc\t2.34\t1.el9\taarch64'}
            with mock.patch.object(CI, 'run', side_effect=lambda command: headers[command[-1]]):
                self.assertEqual([host, sdk], CI.cached_packages(plan, cache))
                headers[sdk] = 'cbodotnet-sdk-10.0\t10.0.403\t2.cbot.rocky9.8\taarch64'
                with self.assertRaisesRegex(ValueError, 'differs from the reviewed'):
                    CI.cached_packages(plan, cache)
                headers[sdk] = 'cbodotnet-sdk-10.0\t10.0.403\t1.cbot.rocky9.8\taarch64'
                duplicate = cache / 'duplicate.rpm'
                duplicate.write_bytes(b'fixture')
                headers[duplicate] = headers[host]
                with self.assertRaisesRegex(ValueError, 'duplicated'):
                    CI.cached_packages(plan, cache)

    def test_signed_local_transaction_never_disables_package_signature_checks(self):
        with mock.patch.object(CI, 'repository_options', return_value=['--disable-repo=*']):
            with mock.patch.object(CI, 'run', return_value='') as execute:
                CI.local_transaction(['/delivery/packages/sdk.rpm'], signed=True)
                command = execute.call_args.args[0]
                self.assertIn('--disable-repo=*', command)
                self.assertIn('--setopt=localpkg_gpgcheck=1', command)
                self.assertNotIn('--setopt=localpkg_gpgcheck=0', command)
                self.assertNotIn('--nogpgcheck', command)

    def test_rpm4_and_rpm6_require_successful_signatures_independent_of_output_case(self):
        for name in ('Signature', 'signature'):
            value = 'package.rpm:\n    Header OpenPGP ' + name + ', key fingerprint: ' + 'a' * 40 + ': OK\n    Payload SHA256 digest: OK\n'
            with self.subTest(name=name), mock.patch.object(CI, 'run', return_value=value):
                self.assertEqual(value, CI.verify_package_signature(Path('package.rpm')))
        for value in ('Header SHA256 digest: OK\nPayload SHA256 digest: OK\n',
                      'Header OpenPGP signature: NOKEY\n', 'Header Signature: NOT OK\n',
                      'Header signature: OK\nPayload digest: BAD\n', 'Header signature: NOTFOUND\n'):
            with self.subTest(value=value), mock.patch.object(CI, 'run', return_value=value):
                with self.assertRaisesRegex(ValueError, 'payload signature failed'):
                    CI.verify_package_signature(Path('package.rpm'))
        with mock.patch.object(CI, 'run', side_effect=RuntimeError('rpmkeys rejected payload')):
            with self.assertRaises(RuntimeError):
                CI.verify_package_signature(Path('package.rpm'))

    def test_modern_and_legacy_dnf_repository_scope_are_explicit(self):
        with mock.patch.object(CI.Path, 'exists', return_value=True):
            self.assertEqual(['--disable-repo=*', '--enable-repo=cbodotnet-validation'],
                             CI.repository_options('cbodotnet-validation'))
        with mock.patch.object(CI.Path, 'exists', return_value=False):
            self.assertEqual(['--disablerepo=*', '--enablerepo=cbodotnet-validation'],
                             CI.repository_options('cbodotnet-validation'))

    def test_offline_lifecycle_refuses_an_external_network_before_sdk_execution(self):
        args = argparse.Namespace(delivery=Path('/delivery/rpm-fedora-45'))
        with mock.patch.object(CI.os, 'geteuid', return_value=0), mock.patch.object(CI.Path, 'is_file', return_value=True):
            with mock.patch.object(CI.Path, 'iterdir', return_value=iter([Path('lo'), Path('eth0')])):
                with mock.patch.object(CI, 'run') as execute:
                    with self.assertRaisesRegex(ValueError, 'network none'):
                        CI.lifecycle(args)
                    execute.assert_not_called()

    def test_correct_version_but_wrong_manifest_provenance_is_rejected(self):
        plan = {'sdkVersion': '10.0.403', 'packageRevision': 1, 'sourceManifestSha256': 'a' * 64,
                'package': {'root': '/opt/cbodotnet/10.0'}, 'targetRid': 'linux-x64'}
        version = subprocess.CompletedProcess([], 0, stdout='10.0.403\n', stderr=CI.BRAND + '\n')
        identity = dict(sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='b' * 64,
                        sdkRoot='/opt/cbodotnet/10.0')
        with mock.patch.object(CI.subprocess, 'run', return_value=version), mock.patch.object(CI, 'as_user', return_value=json.dumps(identity)):
            with self.assertRaisesRegex(ValueError, 'another qualified root'):
                CI.check_aliases(plan)

    def test_record_binds_native_results_to_canonical_source_and_workflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            delivery = Path(temporary) / 'rpm-fedora-45'
            (delivery / 'packages').mkdir(parents=True)
            (delivery / 'commands').mkdir()
            CI.save(delivery / 'plan.json', {'sdkVersion': '10.0.403'})
            CI.save(delivery / 'commands.json', [])
            CI.save(delivery / 'packages/package-build.json', {'packages': [{'kind': 'sdk', 'path': 'sdk.rpm'}]})
            CI.save(delivery / 'installation-result.json', {'schemaVersion': 1, 'status': 'passed',
                    'target': {'native': True}, 'checks': {'offline-build-run': 'passed'}})
            packaged = {key: {'test': key} for key in ('identity', 'artifact', 'source', 'producer',
                        'orchestration', 'branding', 'commands', 'extraFiles')}
            packaged['contractVersion'] = 2
            environment = dict(GITHUB_SHA='c' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2',
                GITHUB_WORKFLOW_REF='dotnetdev-kr/cbodotnet/.github/workflows/distribution-release.yml@refs/heads/main')
            with mock.patch.dict(CI.os.environ, environment), mock.patch.object(CI, 'package_record', return_value=packaged):
                item = CI.record(delivery, Path(temporary) / 'inputs')
            report = CI.load(delivery / 'report.json')
            self.assertEqual('passed', report['status'])
            self.assertEqual('prepublication', report['phase'])
            self.assertEqual('channel-installation', report['scope'])
            self.assertEqual(packaged['source'], report['source'])
            self.assertEqual(packaged['producer'], report['producer'])
            self.assertEqual(str(delivery / 'packages/sdk.rpm'), item['artifactPath'])


if __name__ == '__main__':
    unittest.main()
