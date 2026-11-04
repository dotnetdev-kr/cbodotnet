"""Reject misleading RPM target, integrity, offline and provenance evidence."""
import argparse
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

    def test_signed_local_transaction_never_disables_package_signature_checks(self):
        with mock.patch.object(CI, 'repository_options', return_value=['--disable-repo=*']):
            with mock.patch.object(CI, 'run', return_value='') as execute:
                CI.local_transaction(['/delivery/packages/sdk.rpm'], signed=True)
                command = execute.call_args.args[0]
                self.assertIn('--disable-repo=*', command)
                self.assertIn('--setopt=localpkg_gpgcheck=1', command)
                self.assertNotIn('--setopt=localpkg_gpgcheck=0', command)
                self.assertNotIn('--nogpgcheck', command)

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
