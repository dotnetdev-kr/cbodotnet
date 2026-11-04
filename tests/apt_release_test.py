"""Exercise real signed flat APT indexes without publishing to a remote service."""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import apt_release as APT
import channel_packages as PACKAGES
import channel_packages_test as PACKAGE_TESTS
from downstream_publish_test import FakeGitHub
from published_apt import package_descriptors, verify_packages_index


@unittest.skipUnless(os.name == 'posix' and all(shutil.which(tool) for tool in ('dpkg-deb', 'apt-ftparchive', 'gpg', 'gpgv')),
                     'Actual Debian packaging, repository and GnuPG tools are required')
class FlatAptReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PACKAGE_TESTS.ChannelPackagesTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.directory
        manifests = []
        for arch in ('x64', 'aarch64'):
            plan, source = self.fixture.fixture(arch=arch)
            output = self.root / (arch + '-packages')
            PACKAGES.build_deb(plan, source, output)
            manifests.append(output / 'package-build.json')
        self.home = self.root / 'gnupg'
        self.home.mkdir(mode=0o700)
        subprocess.run(PACKAGES.gpg_command(self.home, '--quick-generate-key',
            'cbodotnet ephemeral flat APT test <test@example.invalid>', 'ed25519', 'sign', '0'),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listing = subprocess.check_output(PACKAGES.gpg_command(self.home, '--with-colons', '--list-keys'), stderr=subprocess.PIPE).decode()
        self.signer = next(row.split(':')[9] for row in listing.splitlines() if row.startswith('fpr:'))
        self.repositories = self.root / 'repositories'
        PACKAGES.build_repositories(manifests, 'deb', self.repositories, self.signer, self.home)
        self.repository = self.repositories / 'debian-13'
        self.keyring = self.repository / 'cbodotnet-archive-keyring.gpg'
        self.archive = self.repositories / 'apt-debian-13.tar.gz'

    def flatten(self):
        with mock.patch.dict(os.environ, GNUPGHOME=str(self.home)):
            return APT.prepare_flat_repositories(self.repositories, self.signer, self.keyring)

    def parent(self):
        return dict(repository=APT.REPOSITORY, targetCommit='b' * 40, tag='distribution-deb-sdk-10.0.403-r1',
            identity=dict(channel='deb', sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='a' * 64),
            repositories=[dict(kind='apt-repository', variants=['debian-13'], delivery='github-release-flat',
                releaseTag=APT.release_tag('debian-13', '10.0.403', 1), asset=self.archive.name,
                flatAssets=APT.flat_asset_descriptors(self.archive))])

    def publish(self, parent, transport):
        with mock.patch.object(APT, 'validate_bundle', return_value=parent):
            return APT.publish_flat_repositories(self.repositories, self.keyring, transport)

    def test_real_flat_index_retains_both_native_architectures_and_authenticates_every_byte(self):
        before = {path.name: PACKAGES.sha256_file(path) for path in (self.repository / 'pool').glob('*.deb')}
        build = self.flatten()
        self.assertFalse((self.repository / 'pool').exists())
        self.assertEqual(before, {path.name: PACKAGES.sha256_file(path) for path in self.repository.glob('*.deb')})
        release = subprocess.check_output(['gpgv', '--keyring', str(self.keyring), '--output', '-', str(self.repository / 'InRelease')], stderr=subprocess.PIPE).decode()
        packages = (self.repository / 'Packages').read_bytes()
        verify_packages_index(release, packages)
        for arch in ('amd64', 'arm64'):
            selected = package_descriptors(packages, '10.0.403', 1, arch, flat=True)
            self.assertEqual({arch, 'all'}, {row['architecture'] for row in selected})
            self.assertTrue(all('/' not in row['filename'].removeprefix('./') for row in selected))
        manifest = json.loads((self.repository / 'repository-manifest.json').read_bytes())
        self.assertEqual('github-release-flat', manifest['delivery'])
        self.assertEqual(APT.repository_url('debian-13', '10.0.403', 1), manifest['repositoryUrl'])
        self.assertEqual(APT.flat_asset_descriptors(self.archive), sorted(
            [APT.descriptor(path) for path in self.repository.iterdir()], key=lambda row: row['name']))
        self.assertEqual(PACKAGES.sha256_file(self.archive), build['archives'][0]['sha256'])

    def test_deleted_or_changed_native_package_cannot_be_flattened_and_signed(self):
        package = next((self.repository / 'pool').glob('*_arm64.deb'))
        package.unlink()
        with self.assertRaises(ValueError):
            self.flatten()
        package.write_bytes(b'tampered-native-package')
        with self.assertRaises(ValueError):
            self.flatten()

    def test_verified_publication_is_idempotent_and_rechecks_anonymous_downloaded_bytes(self):
        self.flatten()
        parent = self.parent()
        transport = FakeGitHub()
        first = self.publish(parent, transport)
        count = transport.uploads
        self.assertEqual(1, transport.publications)
        self.assertGreater(transport.public_downloads, 0)
        second = self.publish(parent, transport)
        self.assertEqual(first, second)
        self.assertEqual(count, transport.uploads)
        self.assertEqual(1, transport.publications)
        transport.corrupt_public = True
        with self.assertRaisesRegex(ValueError, 'Re-downloaded'):
            self.publish(parent, transport)

    def test_foreign_tag_source_asset_bindings_or_existing_release_are_rejected_before_upload(self):
        self.flatten()
        parent = self.parent()
        for change in (dict(releaseTag='repository-deb-debian-13-sdk-9.0.123-r1'),
                       dict(flatAssets=[]), dict(variants=['ubuntu-24.04'])):
            modified = copy.deepcopy(parent)
            modified['repositories'][0].update(change)
            transport = FakeGitHub()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.publish(modified, transport)
            self.assertEqual(0, transport.uploads)
        modified = copy.deepcopy(parent)
        modified['identity']['sourceManifestSha256'] = 'f' * 64
        transport = FakeGitHub()
        with self.assertRaisesRegex(ValueError, 'content identity'):
            self.publish(modified, transport)
        self.assertEqual(0, transport.uploads)
        transport = FakeGitHub()
        transport.create(dict(tag=parent['repositories'][0]['releaseTag'], targetCommit='c' * 40))
        with self.assertRaisesRegex(ValueError, 'Unrelated'):
            self.publish(parent, transport)
        self.assertEqual(0, transport.uploads)

    def test_parent_authentication_failure_precedes_every_transport_operation(self):
        transport = FakeGitHub()
        with mock.patch.object(APT, 'validate_bundle', side_effect=ValueError('untrusted parent signature')):
            with self.assertRaisesRegex(ValueError, 'untrusted parent signature'):
                APT.publish_flat_repositories(self.repositories, self.keyring, transport)
        self.assertIsNone(transport.release)


class FlatArchiveBoundaryTests(unittest.TestCase):
    def test_escaping_linked_duplicate_or_nested_assets_are_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'flat.tar.gz'
            for name, kind in [('../outside', tarfile.REGTYPE), ('dir/package.deb', tarfile.REGTYPE), ('package.deb', tarfile.SYMTYPE)]:
                with tarfile.open(path, 'w:gz') as archive:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.size = 1 if kind == tarfile.REGTYPE else 0
                    entry.linkname = 'outside' if kind == tarfile.SYMTYPE else ''
                    archive.addfile(entry, io.BytesIO(b'x') if entry.size else None)
                with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                    APT.flat_asset_descriptors(path)


if __name__ == '__main__':
    unittest.main()
