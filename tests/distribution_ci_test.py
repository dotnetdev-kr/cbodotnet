"""Keep real-image promotion immutable and CI transport confined."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile
import hashlib
import subprocess
import argparse
import copy
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('distribution_ci', ROOT / 'scripts/distribution-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class DistributionCiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def items(self):
        items = []
        for arch, platform in [('x64', 'amd64'), ('aarch64', 'arm64')]:
            directory = self.root / arch
            directory.mkdir()
            image = dict(tag='cbodotnet-verified:' + arch, id='sha256:' + ('a' if arch == 'x64' else 'b') * 64,
                         architecture=platform)
            (directory / 'image.json').write_text(json.dumps(image))
            items.append(dict(packagePath=str(directory / 'package.json'), artifactPath=str(directory / 'image.tar'),
                package=dict(architecture=arch, identity=dict(sdkVersion='10.0.403', packageRevision=1))))
        return items

    def test_deb_selection_is_available_only_to_native_read_only_validation(self):
        args = argparse.Namespace(channel='deb')
        self.assertEqual(('deb',), CI.selected_channels(args, native=True))
        with self.assertRaisesRegex(ValueError, 'Unsupported distribution'):
            CI.selected_channels(args)
        self.assertEqual(('deb', 'oci'), CI.selected_channels(argparse.Namespace()))
        self.assertEqual(('oci',), CI.selected_channels(argparse.Namespace(channel='oci')))

    def test_deb_native_builds_both_distros_without_official_tar_or_any_oci_stage(self):
        args = argparse.Namespace(workspace=self.root / 'delivery', channel='deb', arch='x64', tag='sdk-10.0.403',
                                  revision=1, ubuntu_base='ubuntu:24@sha256:' + 'a' * 64, debian_base='debian:13@sha256:' + 'b' * 64)

        def package(command, **kwargs):
            self.assertEqual(CI.ROOT / 'scripts/package-sdk.py', command[1])
            self.assertEqual('deb', command[command.index('--channel') + 1])
            output = Path(command[command.index('--output') + 1])
            output.mkdir()
            (output / 'plan.json').write_text(json.dumps(dict(channel='deb', sdkVersion='10.0.403')))
            (output / 'package-build.json').write_text('{}')
            (output / 'cbodotnet-sdk-10.0.deb').write_bytes(b'sdk')
            (output / 'cbodotnet-host.deb').write_bytes(b'host')
            return ''

        def commands(build, target):
            target.mkdir()
            (target.parent / 'commands.json').write_text('[]')

        def lifecycle(workspace, delivery, base, variant, mode):
            self.assertEqual('deb', mode)
            (delivery / 'installation-result.json').write_text(json.dumps(dict(status='passed')))

        with mock.patch.object(CI.os, 'getuid', return_value=1001), mock.patch.object(CI.platform, 'machine', return_value='x86_64'):
            with mock.patch.object(CI, 'run', side_effect=package) as builds, mock.patch.object(CI, 'receive_release'):
                with mock.patch.object(CI, 'copy_commands', side_effect=commands), mock.patch.object(CI, 'record', return_value={'test': 'record'}):
                    with mock.patch.object(CI, 'container_lifecycle', side_effect=lifecycle) as installs, mock.patch.object(CI, 'official_archive') as archive:
                        CI.native(args)
        archive.assert_not_called()
        self.assertEqual(4, builds.call_count)
        self.assertEqual({'ubuntu-24.04', 'debian-13'}, {call.args[3] for call in installs.call_args_list})
        self.assertFalse((args.workspace / 'oci-debian-13').exists())
        self.assertEqual(2, len(json.loads((args.workspace / 'items.json').read_bytes())))

    def test_installation_is_committed_before_an_explicit_network_none_lifecycle(self):
        responses = ['container-id', '', json.dumps([dict(State=dict(ExitCode=0))]), 'sha256:prepared', '']
        with mock.patch.object(CI, 'run', side_effect=responses) as command, mock.patch.object(CI.subprocess, 'run'):
            CI.container_lifecycle(self.root, self.root / 'deb-ubuntu-24.04', 'ubuntu:pinned', 'ubuntu-24.04', 'deb')
        calls = [call.args[0] for call in command.call_args_list]
        self.assertEqual(['docker', 'create'], calls[0][:2])
        self.assertEqual('prepare', calls[0][-1])
        self.assertEqual(['docker', 'commit', 'container-id'], calls[3])
        self.assertEqual(['docker', 'run', '--rm', '--network', 'none'], calls[4][:5])
        self.assertEqual('lifecycle', calls[4][-1])

    def test_external_network_is_rejected_before_any_installed_sdk_execution(self):
        with mock.patch.object(CI.Path, 'iterdir', return_value=iter([Path('lo'), Path('eth0')])):
            with mock.patch.object(CI, 'run') as command, mock.patch.object(CI, 'installation_context') as context:
                with self.assertRaisesRegex(ValueError, 'network none'):
                    CI.installed(argparse.Namespace(phase='lifecycle'))
        command.assert_not_called()
        context.assert_not_called()

    def test_dpkg_integrity_rejects_nonempty_success_output(self):
        with mock.patch.object(CI, 'run', return_value='??5?????? /usr/bin/cbodotnet\n'):
            with self.assertRaisesRegex(ValueError, 'full dpkg integrity'):
                CI.strict_dpkg_integrity(['cbodotnet-host'])

    def test_actual_read_only_workflow_path_is_retained_and_unknown_paths_rejected(self):
        environment = dict(GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
            GITHUB_WORKFLOW_REF='dotnetdev-kr/cbodotnet/.github/workflows/apt-completeness.yml@refs/heads/main')
        with mock.patch.dict(os.environ, environment):
            self.assertEqual('.github/workflows/apt-completeness.yml', CI.orchestration()['workflow'])
            os.environ['GITHUB_WORKFLOW_REF'] = 'dotnetdev-kr/cbodotnet/.github/workflows/unreviewed.yml@refs/heads/main'
            with self.assertRaisesRegex(ValueError, 'Unsupported native evidence'):
                CI.orchestration()

    def test_upgrade_rollback_remove_reinstall_and_installed_purge_preserve_official_proofs(self):
        self.exercise_deb_lifecycle()

    def test_purge_cannot_be_reported_for_an_already_removed_configuration_record(self):
        with self.assertRaisesRegex(ValueError, 'actual SDK package first'):
            self.exercise_deb_lifecycle(reinstall_status='deinstall ok config-files')

    def exercise_deb_lifecycle(self, reinstall_status='install ok installed'):
        delivery = self.root / 'deb-lifecycle'
        delivery.mkdir()
        for directory in ('packages', 'upgrade'):
            (delivery / directory).mkdir()
            for name in ('sdk', 'host'):
                (delivery / directory / (name + '.deb')).write_bytes(b'fixture')
        plan = dict(sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='a' * 64,
                    package=dict(name='cbodotnet-sdk-10.0', root=str(self.root / 'sdk')))
        revision = 1
        commands = []

        def execute(command, **kwargs):
            nonlocal revision
            commands.append(command)
            if command[0] == 'dpkg-query':
                return reinstall_status
            if command[:2] == ['apt-get', 'install']:
                revision = 2 if any('/upgrade/' in str(part) for part in command) else 1
            return ''

        def identity(command):
            return json.dumps(dict(packageRevision=revision, sdkVersion=plan['sdkVersion'],
                                   sourceManifestSha256=plan['sourceManifestSha256']))

        official = mock.Mock()
        with mock.patch.object(CI, 'run', side_effect=execute), mock.patch.object(CI, 'inventory', return_value={'fixture': 'same'}):
            with mock.patch.object(CI, 'strict_dpkg_integrity'), mock.patch.object(CI, 'assert_removed_deb') as removed:
                with mock.patch.object(CI.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stdout='', stderr='')):
                    try:
                        phases = CI.deb_lifecycle(plan, delivery, {'fixture': 'same'}, identity, official)
                    except ValueError:
                        self.assertFalse(any(command[:2] == ['apt-get', 'purge'] for command in commands))
                        raise
        self.assertEqual(['after-install', 'after-runtime', 'after-upgrade', 'after-rollback', 'after-remove', 'after-reinstall', 'after-purge'], phases)
        self.assertEqual(phases[2:], [call.args[0] for call in official.call_args_list])
        self.assertEqual(2, removed.call_count)
        purge = next(index for index, command in enumerate(commands) if command[:2] == ['apt-get', 'purge'])
        self.assertEqual('dpkg-query', commands[purge - 1][0])
        self.assertTrue(any('--allow-downgrades' in command for command in commands))
        for command in commands:
            if command[:2] == ['apt-get', 'install']:
                self.assertNotIn('--no-download', command)
                local_files = [Path(str(value)) for value in command if str(value).endswith('.deb')]
                self.assertEqual(2, len(local_files))
                self.assertTrue(all(path.is_absolute() and path.is_file() for path in local_files))

    def test_partial_native_image_matrix_cannot_login_or_push(self):
        with mock.patch.object(CI, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'Both native'):
                CI.push_images(self.items()[:1], self.root)
            command.assert_not_called()

    def test_conflicting_existing_platform_tag_is_never_overwritten(self):
        items = self.items()
        def command(arguments, **kwargs):
            if arguments[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([dict(Id='sha256:' + 'a' * 64)])
            return ''
        with mock.patch.dict(os.environ, GITHUB_TOKEN='test-token', GITHUB_ACTOR='test-user'):
            with mock.patch.object(CI, 'run', side_effect=command) as commands:
                with mock.patch.object(CI, 'registry_manifest', return_value=(dict(digest='sha256:' + 'c' * 64),
                      dict(config=dict(digest='sha256:' + 'd' * 64)))):
                    with self.assertRaisesRegex(ValueError, 'immutable image tag'):
                        CI.push_images(items, self.root)
                self.assertFalse(any(call.args[0][:2] == ['docker', 'push'] for call in commands.call_args_list))

    def test_empty_or_escaping_transport_is_rejected_before_extraction(self):
        for name in ('../escape', '/absolute'):
            archive_path = self.root / 'native-x64.tar.gz'
            with tarfile.open(archive_path, 'w:gz') as archive:
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b'x'))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe native'):
                CI.unpack_deliveries(self.root)
            archive_path.unlink()

    def test_sdk_listing_rejects_other_roots_versions_or_global_fallback(self):
        CI.validate_sdk_listing('10.0.403 [/opt/cbodotnet/10.0/sdk]\n', '10.0.403', '/opt/cbodotnet/10.0')
        for listing in ('10.0.403 [/usr/share/dotnet/sdk]\n', '10.0.404 [/opt/cbodotnet/10.0/sdk]\n',
                        '10.0.403 [/opt/cbodotnet/10.0/sdk]\n10.0.100 [/usr/share/dotnet/sdk]\n'):
            with self.subTest(listing=listing), self.assertRaisesRegex(ValueError, 'SDK listing'):
                CI.validate_sdk_listing(listing, '10.0.403', '/opt/cbodotnet/10.0')

    def test_consumer_config_rejects_changed_provenance_root_user_and_credentials(self):
        labels = {'org.opencontainers.image.licenses': 'MIT AND LicenseRef-Dotnet-ThirdPartyNotices',
                  'kr.dotnetdev.cbodotnet.sdk.sha256': 'a' * 64}
        image = dict(Architecture='amd64', Os='linux', Config=dict(User='app', WorkingDir='/work', Cmd=['cbodotnet', '--info'],
            Env=['PATH=/usr/local/bin:/usr/bin', 'DOTNET_ROOT=/opt/cbodotnet/10.0'], Labels=labels))
        CI.validate_image_config(image, 'amd64', '/opt/cbodotnet/10.0', labels)
        changed = copy.deepcopy(image)
        changed['Config']['Labels']['kr.dotnetdev.cbodotnet.sdk.sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'labels differ'):
            CI.validate_image_config(changed, 'amd64', '/opt/cbodotnet/10.0', labels)
        for field, value in [('User', '0'), ('WorkingDir', '/root'), ('Env', ['PATH=/usr/bin', 'DOTNET_ROOT=/usr/share/dotnet']),
                             ('Env', [*image['Config']['Env'], 'GITHUB_TOKEN=not-a-real-token'])]:
            changed = copy.deepcopy(image)
            changed['Config'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                CI.validate_image_config(changed, 'amd64', '/opt/cbodotnet/10.0', labels)


    def test_new_revision_cannot_fall_back_to_legacy_or_partial_metadata(self):
        index = dict(tag='10.0.403-debian13-r2')
        expected = dict(architecture='amd64')
        with self.assertRaisesRegex(ValueError, 'complete metadata policy'):
            CI.validate_published_metadata(index, expected)
        self.assertIsNone(CI.validate_published_metadata(dict(tag='10.0.403-debian13-r1'), expected))
        qualified = {'org.opencontainers.image.licenses': 'MIT AND LicenseRef-Dotnet-ThirdPartyNotices',
                     'kr.dotnetdev.cbodotnet.sdk.sha256': 'a' * 64}
        expected.update(metadataPolicyVersion=2, sdkRoot='/opt/cbodotnet/10.0', labels=dict(qualified,
            **{'org.opencontainers.image.base.name': 'debian:13@sha256:' + 'b' * 64}))
        with mock.patch.object(CI, 'qualified_oci_labels', return_value=qualified):
            CI.validate_published_metadata(index, expected)
            expected['labels'].pop('org.opencontainers.image.licenses')
            with self.assertRaisesRegex(ValueError, 'complete qualified'):
                CI.validate_published_metadata(index, expected)


class PublishedRepositoryLocationTests(unittest.TestCase):
    def test_core3_production_image_audits_native_http_before_any_bootstrap_as_default_nonroot_offline(self):
        path = '/opt/cbodotnet/3.1/shared/Microsoft.NETCore.App/3.1.32/System.Net.Http.Native.so'
        output = 'CBODOTNET_NATIVE_HTTP=' + path + '\n' + 'a' * 64 + '  ' + path + '\nlibcurl.so.4 => /lib/aarch64-linux-gnu/libcurl.so.4 (0x123)\n'
        with mock.patch.object(CI, 'run', side_effect=['0:0:755\n' * 4, '', output]) as command:
            proof = CI.inspect_consumer_files('actual-pulled-image@sha256:fixed', '/opt/cbodotnet/3.1')
        http = proof['nativeHttpLibraries']
        self.assertEqual(('passed', '1654', 'none'), (http['status'], http['user'], http['network']))
        self.assertEqual('a' * 64, http['libraries'][0]['sha256'])
        invocation = command.call_args.args[0]
        self.assertEqual(['docker', 'run', '--rm', '--network', 'none', 'actual-pulled-image@sha256:fixed'], invocation[:6])
        self.assertNotIn('--user', invocation)
        self.assertIn('test "$(id -u)" = 1654', invocation[-1])
        self.assertIn('LD_LIBRARY_PATH=/usr/lib/cbodotnet/compat/curl-rocky8/lib:/usr/lib/cbodotnet/compat/rocky9/lib', invocation[-1])
        self.assertNotIn('apt-get', invocation[-1])

    def test_production_core3_missing_unresolved_or_substituted_native_http_proof_fails(self):
        path = '/opt/cbodotnet/3.0/shared/Microsoft.NETCore.App/3.0.3/System.Net.Http.Native.so'
        prefix = 'CBODOTNET_NATIVE_HTTP=' + path + '\n' + 'a' * 64 + '  ' + path + '\n'
        for output in ('', prefix + 'libcurl.so.4 => not found\n', prefix + 'libc.so.6 => /lib/libc.so.6 (0x123)\n',
                       prefix.replace('/opt/cbodotnet/3.0', '/usr/share/dotnet') + 'libcurl.so.4 => /lib/libcurl.so.4 (0x123)\n'):
            with self.subTest(output=output), mock.patch.object(CI, 'run', return_value=output), self.assertRaises(ValueError):
                CI.inspect_core3_image_http('actual-image', '/opt/cbodotnet/3.0')

    def test_other_production_sdk_families_keep_existing_image_file_proofs_without_new_http_requirement(self):
        for family in ('5.0', '6.0', '7.0', '8.0', '9.0', '10.0'):
            with self.subTest(family=family), mock.patch.object(CI, 'run', side_effect=['0:0:755\n' * 4, '']) as command:
                proof = CI.inspect_consumer_files('image', '/opt/cbodotnet/' + family)
                self.assertNotIn('nativeHttpLibraries', proof)
                self.assertEqual(2, command.call_count)

    def test_oci_managed_dependency_uses_verified_source_versions_without_claiming_dpkg_ownership(self):
        import legacy_compat
        provider = legacy_compat.load_policy()
        plan = dict(sdkVersion='3.1.426', variant='debian-13', architecture=dict(public='aarch64'),
                    dependencies=['libc6', 'cbodotnet-compat-rocky9'])
        state = dict(required=True, packages=provider['architectures']['aarch64']['packages'],
                     signingFingerprint=provider['signingFingerprint'])
        with mock.patch.object(CI, 'run', return_value='2.41') as query:
            with mock.patch.object(legacy_compat, 'runtime_environment'), mock.patch.object(legacy_compat, 'assert_unchanged', return_value={'status': 'passed'}):
                observed = CI.observed_dependencies(plan, 'oci', state)
                self.assertIn('isolated managed OCI tree', observed['cbodotnet-compat-rocky9'])
                for package in state['packages']:
                    self.assertIn(package['version'] + '-' + package['release'], observed['cbodotnet-compat-rocky9'])
                query.assert_called_once_with(['dpkg-query', '-W', '-f=${Version}', 'libc6'])
                with self.assertRaisesRegex(ValueError, 'authenticated native source versions'):
                    CI.observed_dependencies(plan, 'oci', dict(state, packages=[]))
                query.reset_mock()
                CI.observed_dependencies(plan, 'deb', state)
                self.assertEqual(['dpkg-query', '-W', '-f=${Version}', 'cbodotnet-compat-rocky9'], query.call_args.args[0])

    def test_oci_build_propagates_the_exact_sdk_series_for_initial_and_upgrade_contexts(self):
        base = 'debian:13@sha256:' + 'a' * 64
        for version in ('10.0.403', '9.0.123', '8.0.133', '7.0.120', '6.0.136', '5.0.214', '3.1.426', '3.0.103'):
            family = '.'.join(version.split('.')[:2])
            for revision in ('1', '2'):
                metadata = dict(plan=dict(sdkVersion=version, package=dict(root='/opt/cbodotnet/' + family)),
                    buildArgs=dict(BASE_IMAGE=base, SDK_SERIES=family), labels={'kr.dotnetdev.cbodotnet.package.revision': revision})
                command = CI.oci_build_arguments(base, metadata)
                self.assertIn('SDK_SERIES=' + family, command)
                self.assertIn('kr.dotnetdev.cbodotnet.package.revision=' + revision, command)
                if family != '10.0':
                    metadata['buildArgs']['SDK_SERIES'] = '10.0'
                    with self.subTest(version=version, revision=revision), self.assertRaisesRegex(ValueError, 'selected SDK series'):
                        CI.oci_build_arguments(base, metadata)

    def test_only_signed_exact_flat_delivery_changes_installation_from_historical_file_pool(self):
        plan = dict(variant='debian-13', sdkVersion='9.0.123', packageRevision=2)
        metadata = dict(kind='apt-repository', variants=['debian-13'], delivery='github-release-flat',
                        releaseTag='repository-deb-debian-13-sdk-9.0.123-r2')
        self.assertEqual('https://github.com/dotnetdev-kr/cbodotnet/releases/download/' + metadata['releaseTag'] + '/',
                         CI.published_apt_location(metadata, plan))
        self.assertIsNone(CI.published_apt_location(dict(kind='apt-repository', variants=['debian-13']), plan))
        for change in (dict(releaseTag='repository-deb-debian-13-sdk-9.0.123-r1'),
                       dict(variants=['ubuntu-24.04']), dict(kind='rpm-repository'), dict(delivery='unknown')):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'Signed flat APT'):
                CI.published_apt_location(dict(metadata, **change), plan)


class FrozenPromotionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / 'promotion'
        self.archive = io.BytesIO()
        with zipfile.ZipFile(self.archive, 'w') as output:
            output.writestr('bundle-deb/manifest.json', '{}')
            output.writestr('bundle-oci/manifest.json', '{}')
            output.writestr('oci-index.json', '{}')
            output.writestr('promotion.json', '{}')
        self.data = self.archive.getvalue()
        self.metadata = dict(head_branch='main', event='workflow_dispatch', path='.github/workflows/distribution-release.yml',
            repository=dict(full_name='dotnetdev-kr/cbodotnet'), head_repository=dict(full_name='dotnetdev-kr/cbodotnet'))
        self.jobs = dict(jobs=[dict(name='Sign, promote and post-verify immutable distributions', conclusion='failure',
            steps=[dict(name='Freeze signed promotion bytes before publication', conclusion='success')])])
        self.artifact = dict(id=123, name='downstream-frozen-promotion-456-1', expired=False,
                             digest='sha256:' + hashlib.sha256(self.data).hexdigest())

    def fetch(self):
        def api(command, **kwargs):
            endpoint = command[-1]
            if endpoint.endswith('/artifacts?per_page=100'):
                return json.dumps(dict(artifacts=[self.artifact]))
            if '/attempts/' in endpoint:
                return json.dumps(self.jobs)
            return json.dumps(self.metadata)
        def download(command, **kwargs):
            kwargs['stdout'].write(self.data)
            return subprocess.CompletedProcess(command, 0, stderr=b'')
        with mock.patch.object(CI, 'run', side_effect=api), mock.patch.object(CI.subprocess, 'run', side_effect=download):
            CI.receive_frozen('456', '1', self.destination)

    def test_exact_api_digest_and_successful_freeze_step_allow_failed_publication_resume(self):
        self.fetch()
        self.assertEqual('{}', (self.destination / 'bundle-deb/manifest.json').read_text())
        self.assertTrue((self.destination / 'oci-index.json').is_file())

    def test_corrupt_zip_is_rejected_before_any_extraction(self):
        self.artifact['digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ValueError, 'API digest'):
            self.fetch()
        self.assertFalse(self.destination.exists())

    def test_failed_freeze_or_untrusted_run_cannot_resume(self):
        self.jobs['jobs'][0]['steps'][0]['conclusion'] = 'failure'
        with self.assertRaisesRegex(ValueError, 'did not preserve'):
            self.fetch()
        self.jobs['jobs'][0]['steps'][0]['conclusion'] = 'success'
        self.metadata['head_branch'] = 'feature'
        with self.assertRaisesRegex(ValueError, 'trusted main'):
            self.fetch()
        self.assertFalse(self.destination.exists())

    def test_even_digest_matching_artifacts_cannot_extract_escaping_or_linked_members(self):
        for name, mode in [('../escape', 0o100644), ('bundle-deb/link', 0o120777)]:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w') as output:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                output.writestr(entry, '../../escape')
            self.data = archive.getvalue()
            self.artifact['digest'] = 'sha256:' + hashlib.sha256(self.data).hexdigest()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe frozen'):
                self.fetch()
            self.assertFalse(self.destination.exists())

    def test_conflicting_signed_channels_are_rejected_before_either_publication(self):
        self.destination.mkdir()
        for channel in ('deb', 'oci'):
            (self.destination / ('bundle-' + channel)).mkdir()
        (self.destination / 'promotion.json').write_text(json.dumps(dict(channels=dict(deb='deb-tag', oci='oci-tag'))))
        (self.destination / 'oci-index.json').write_text('{}')
        identity = dict(sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='a' * 64)
        first = dict(targetCommit='b' * 40, identity=dict(identity, channel='deb'), assets=[])
        second = dict(targetCommit='c' * 40, identity=dict(identity, channel='oci'), assets=[])
        args = argparse.Namespace(promotion=self.destination, keyring=self.root / 'trusted.gpg', frozen_run='', frozen_attempt='1')
        with mock.patch.dict(os.environ, GITHUB_REF='refs/heads/main', GITHUB_REPOSITORY='dotnetdev-kr/cbodotnet'):
            with mock.patch('downstream_publish.validate_bundle', side_effect=[first, second]):
                with mock.patch('downstream_publish.publish_bundle') as publisher:
                    with self.assertRaisesRegex(ValueError, 'different verified source'):
                        CI.publish_staged(args)
                    publisher.assert_not_called()
        self.assertFalse((self.root.parent / 'escape').exists())

    def test_oci_only_recovery_rejects_debian_bundle_before_publication(self):
        self.destination.mkdir()
        for channel in ('deb', 'oci'):
            (self.destination / ('bundle-' + channel)).mkdir()
        (self.destination / 'promotion.json').write_text(json.dumps(dict(channels=dict(oci='oci-tag'))))
        args = argparse.Namespace(promotion=self.destination, keyring=self.root / 'trusted.gpg', frozen_run='', frozen_attempt='1', channel='oci')
        with mock.patch.dict(os.environ, GITHUB_REF='refs/heads/main', GITHUB_REPOSITORY='dotnetdev-kr/cbodotnet'):
            with mock.patch('downstream_publish.publish_bundle') as publisher:
                with self.assertRaisesRegex(ValueError, 'unexpected channels'):
                    CI.publish_staged(args)
                publisher.assert_not_called()

    def test_oci_only_recovery_publishes_only_exact_selected_signed_bundle(self):
        self.destination.mkdir()
        (self.destination / 'bundle-oci').mkdir()
        index_bytes = json.dumps(dict(digest='sha256:' + 'c' * 64)).encode()
        (self.destination / 'oci-index.json').write_bytes(index_bytes)
        (self.destination / 'promotion.json').write_text(json.dumps(dict(channels=dict(oci='oci-tag'))))
        manifest = dict(tag='oci-tag', targetCommit='b' * 40,
            identity=dict(channel='oci', sdkVersion='10.0.403', packageRevision=2, sourceManifestSha256='a' * 64),
            assets=[dict(name='oci-index.json', sha256=hashlib.sha256(index_bytes).hexdigest())])
        args = argparse.Namespace(promotion=self.destination, keyring=self.root / 'trusted.gpg', frozen_run='', frozen_attempt='1', channel='oci')
        with mock.patch.dict(os.environ, GITHUB_REF='refs/heads/main', GITHUB_REPOSITORY='dotnetdev-kr/cbodotnet'):
            with mock.patch('downstream_publish.validate_bundle', return_value=manifest):
                with mock.patch('downstream_publish.publish_bundle', return_value={}) as publisher:
                    CI.publish_staged(args)
                    publisher.assert_called_once_with(self.destination / 'bundle-oci', args.keyring, 'b' * 40)
        self.assertTrue((self.destination / 'oci-publication.json').is_file())
        self.assertFalse((self.destination / 'deb-publication.json').exists())

    def test_transport_dangling_symlink_and_escaping_hardlink_are_rejected(self):
        for kind, target in [(tarfile.SYMTYPE, 'inside'), (tarfile.LNKTYPE, '../outside')]:
            archive_path = self.root / 'native-aarch64.tar.gz'
            with tarfile.open(archive_path, 'w:gz') as archive:
                member = tarfile.TarInfo('delivery-aarch64/file')
                member.type, member.linkname = kind, target
                archive.addfile(member)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'Unsafe native'):
                CI.unpack_deliveries(self.root)
            archive_path.unlink()

    def test_transport_preserves_contained_provider_soname_links_and_modes(self):
        archive_path = self.root / 'native-rpm-aarch64.tar.gz'
        prefix = 'delivery-rpm-aarch64/compatibility-build/rootfs/usr/lib/cbodotnet/compat/rocky9/lib/'
        with tarfile.open(archive_path, 'w:gz') as archive:
            ordinary = tarfile.TarInfo(prefix + 'libssl.so.1.1.1k')
            ordinary.size, ordinary.mode = 3, 0o755
            archive.addfile(ordinary, io.BytesIO(b'elf'))
            link = tarfile.TarInfo(prefix + 'libssl.so.1.1')
            link.type, link.linkname = tarfile.SYMTYPE, 'libssl.so.1.1.1k'
            archive.addfile(link)
        CI.extract_native_transport(archive_path, self.root)
        target = self.root / prefix / 'libssl.so.1.1'
        self.assertTrue(target.is_symlink())
        self.assertEqual('libssl.so.1.1.1k', os.readlink(target))
        self.assertEqual(b'elf', target.read_bytes())
        self.assertEqual(0o755, target.stat().st_mode & 0o777)
        with self.assertRaisesRegex(ValueError, 'fresh'):
            CI.extract_native_transport(archive_path, self.root)

    def test_transport_rejects_duplicate_link_parents_cycles_and_foreign_roots_before_activation(self):
        for mutation in ('duplicate', 'link-parent', 'cycle', 'absolute-link', 'parent-link',
                         'foreign-root', 'normalized-alias', 'fifo'):
            archive_path = self.root / 'native-x64.tar.gz'
            prefix = 'delivery-x64/'
            with tarfile.open(archive_path, 'w:gz') as archive:
                file = tarfile.TarInfo(prefix + 'ordinary'); file.size = 1
                archive.addfile(file, io.BytesIO(b'x'))
                member = tarfile.TarInfo(prefix + 'link')
                member.type, member.linkname = tarfile.SYMTYPE, 'ordinary'
                if mutation == 'duplicate': member.name = prefix + 'ordinary'
                elif mutation == 'link-parent':
                    child = tarfile.TarInfo(prefix + 'link/child'); child.size = 1
                    archive.addfile(child, io.BytesIO(b'x'))
                elif mutation == 'cycle': member.linkname = 'link'
                elif mutation == 'absolute-link': member.linkname = '/etc/passwd'
                elif mutation == 'parent-link': member.linkname = '../ordinary'
                elif mutation == 'foreign-root': member.name = 'delivery-aarch64/link'
                elif mutation == 'normalized-alias': member.name = prefix + './link'
                else: member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'Unsafe native'):
                CI.extract_native_transport(archive_path, self.root)
            self.assertFalse((self.root / 'delivery-x64').exists())


if __name__ == '__main__':
    unittest.main()
