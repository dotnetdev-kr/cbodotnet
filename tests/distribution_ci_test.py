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

    def test_transport_symlink_and_escaping_hardlink_are_rejected(self):
        for kind, target in [(tarfile.SYMTYPE, 'inside'), (tarfile.LNKTYPE, '../outside')]:
            archive_path = self.root / 'native-aarch64.tar.gz'
            with tarfile.open(archive_path, 'w:gz') as archive:
                member = tarfile.TarInfo('delivery-aarch64/file')
                member.type, member.linkname = kind, target
                archive.addfile(member)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'Unsafe native'):
                CI.unpack_deliveries(self.root)
            archive_path.unlink()


if __name__ == '__main__':
    unittest.main()
