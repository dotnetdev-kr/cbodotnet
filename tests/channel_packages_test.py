"""Build real Debian fixtures and reject unsafe or unqualified package inputs."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import channel_packages as PACKAGES
from distribution_contract import ARCHITECTURES, BRANDING


@unittest.skipUnless(os.name == 'posix', 'Package builders require Linux filesystem modes')
class ChannelPackagesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def fixture(self, arch='x64', channel='deb', revision=1):
        archive = self.directory / ('cbodotnet-sdk-10.0.403-linux-' + arch + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as output:
            for name, content, mode in [('dotnet', b'#!/bin/sh\nprintf "10.0.403\\n"\n', 0o755),
                                         ('LICENSE.txt', b'Original license bytes\n', 0o644),
                                         ('ThirdPartyNotices.txt', b'Original notice bytes\n', 0o644),
                                         ('sdk/10.0.403/reference.dll', b'qualified-managed-bytes', 0o644)]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(content), mode
                output.addfile(entry, io.BytesIO(content))
        plan = {'schemaVersion': 1, 'contractVersion': 2, 'status': 'prepared-unqualified', 'publicationAllowed': False,
                'sdkVersion': '10.0.403', 'channel': channel, 'variant': 'debian-13', 'packageRevision': revision,
                'architecture': copy.deepcopy(ARCHITECTURES[arch]), 'targetRid': ARCHITECTURES[arch]['rid'],
                'package': {'name': 'cbodotnet-sdk-10.0', 'version': f'10.0.403-{revision}',
                            'root': '/opt/cbodotnet/10.0', 'launcher': '/usr/bin/cbodotnet-10.0'},
                'sdk': {'name': archive.name, 'size': archive.stat().st_size, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                        'url': 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-10.0.403/' + archive.name},
                'sourceReleaseTag': 'sdk-10.0.403', 'sourceManifestSha256': 'a' * 64,
                'licensePaths': ['LICENSE.txt', 'ThirdPartyNotices.txt'], 'additionalDirectories': ['metadata'],
                'dependencies': ['libc6', 'libicu76', 'libssl3t64'], 'branding': copy.deepcopy(BRANDING)}
        return plan, archive

    def test_staging_preserves_qualified_payload_and_inventories_separate_commands(self):
        plan, archive = self.fixture()
        output, rootfs, commands, payload = PACKAGES.stage_payload(plan, archive, self.directory / 'stage')
        self.assertEqual(b'qualified-managed-bytes', (rootfs / 'opt/cbodotnet/10.0/sdk/10.0.403/reference.dll').read_bytes())
        self.assertEqual({'/usr/bin/cbodotnet', '/usr/bin/cbodotnet-10.0'}, {row['path'] for row in commands})
        self.assertNotIn('metadata', payload)
        self.assertTrue((rootfs / 'opt/cbodotnet/10.0/metadata').is_dir())
        self.assertFalse((rootfs / 'usr/bin/dotnet').exists())

    def test_corrupt_archive_and_namespace_collision_fail_before_staging(self):
        plan, archive = self.fixture()
        original = plan['sdk']['sha256']
        plan['sdk']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'archive changed'):
            PACKAGES.stage_payload(plan, archive, self.directory / 'stage')
        self.assertFalse((self.directory / 'stage').exists())
        plan['sdk']['sha256'] = original
        plan['package']['root'] = '/usr/share/dotnet'
        with self.assertRaisesRegex(ValueError, 'namespace'):
            PACKAGES.stage_payload(plan, archive, self.directory / 'stage')

    def test_oci_requires_pinned_base_and_exposes_all_three_names(self):
        plan, archive = self.fixture(channel='oci')
        with self.assertRaisesRegex(ValueError, 'pinned'):
            PACKAGES.build_oci_context(plan, archive, self.directory / 'bad-oci', 'debian:13')
        result = PACKAGES.build_oci_context(plan, archive, self.directory / 'oci', 'debian:13@sha256:' + 'b' * 64)
        paths = {row['path'] for row in result['commandInventory']}
        self.assertTrue({'/usr/local/bin/cbodotnet', '/usr/local/bin/cbodotnet-10.0', '/usr/local/bin/dotnet'} <= paths)
        self.assertEqual('debian:13@sha256:' + 'b' * 64, result['buildArgs']['BASE_IMAGE'])
        self.assertFalse(result['publicationQualified'])

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'dpkg-deb is required')
    def test_real_debs_have_distinct_ownership_and_preserve_payload(self):
        plan, archive = self.fixture()
        output = self.directory / 'deb'
        result = PACKAGES.build_deb(plan, archive, output)
        sdk = output / next(row['path'] for row in result['packages'] if row['kind'] == 'sdk')
        host = output / next(row['path'] for row in result['packages'] if row['kind'] == 'host')
        control = subprocess.check_output(['dpkg-deb', '--field', str(sdk)]).decode()
        self.assertIn('Architecture: amd64', control)
        self.assertIn('cbodotnet-host (>= 1.0.0-1)', control)
        self.assertIn('libicu76', control)
        extracted_host = self.directory / 'host-extracted'
        subprocess.run(['dpkg-deb', '--extract', str(host), str(extracted_host)], check=True)
        self.assertTrue((extracted_host / 'usr/bin/cbodotnet').is_file())
        self.assertFalse((extracted_host / 'opt').exists())
        self.assertFalse((output / 'deb-verified/usr/bin/cbodotnet').exists())
        self.assertTrue((output / 'deb-verified/usr/bin/cbodotnet-10.0').is_file())
        self.assertTrue(result['payloadPreserved'])

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'dpkg-deb is required')
    def test_common_package_bytes_are_identical_across_architectures_and_sdk_revisions(self):
        digests = []
        for arch, revision in [('x64', 1), ('aarch64', 2)]:
            plan, archive = self.fixture(arch=arch, revision=revision)
            output = self.directory / (arch + '-deb')
            result = PACKAGES.build_deb(plan, archive, output)
            digests.append(next(row['sha256'] for row in result['packages'] if row['kind'] == 'host'))
        self.assertEqual(digests[0], digests[1])

    def test_rpm_and_aur_adapters_require_reviewed_native_dependency_policies(self):
        plan, archive = self.fixture(channel='rpm')
        with self.assertRaisesRegex(ValueError, 'RPM-specific'):
            PACKAGES.render_rpm_spec(plan)
        plan['rpmDependencies'] = ['glibc', 'libicu', 'openssl-libs', 'libstdc++', 'zlib']
        spec = PACKAGES.render_rpm_spec(plan)
        self.assertIn('%global __os_install_post %{nil}', spec)
        self.assertIn('BuildArch: x86_64', spec)
        self.assertNotIn('/usr/bin/dotnet', spec)
        with self.assertRaisesRegex(ValueError, 'shell-safe'):
            PACKAGES.build_rpm(plan, archive, self.directory / 'literal-$(touch marker)')
        plan['channel'] = 'aur'
        with self.assertRaisesRegex(ValueError, 'Arch-specific'):
            PACKAGES.render_aur(plan)
        plan['aurDependencies'] = ['glibc', 'icu', 'openssl', 'gcc-libs', 'zlib']
        recipe, srcinfo = PACKAGES.render_aur(plan)
        self.assertIn("options=('!strip' '!debug' '!lto')", recipe)
        self.assertIn(plan['sdk']['sha256'], recipe)
        self.assertNotIn('SKIP', recipe)
        self.assertIn('arch = x86_64', srcinfo)

    def test_repository_matrix_and_package_bytes_are_checked_before_signing(self):
        plan, _ = self.fixture()
        package = self.directory / 'fixture.deb'
        package.write_bytes(b'package')
        manifest = self.directory / 'package-build.json'
        value = {'schemaVersion': 1, 'channel': 'deb', 'plan': plan, 'payloadPreserved': True,
                 'packages': [{**PACKAGES.descriptor(package), 'kind': 'sdk'}, {**PACKAGES.descriptor(package), 'kind': 'host'}]}
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'both architectures'):
            PACKAGES.validate_package_builds([manifest], 'deb')
        package.write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            PACKAGES.validate_package_builds([manifest], 'deb')

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('dpkg-deb', 'apt-ftparchive', 'gpg', 'gpgv')),
                         'Debian repository tools and GnuPG are required')
    def test_real_signed_apt_bundle_has_complete_architectures_and_verifiable_metadata(self):
        manifests = []
        for arch in ('x64', 'aarch64'):
            plan, archive = self.fixture(arch=arch)
            output = self.directory / (arch + '-packages')
            PACKAGES.build_deb(plan, archive, output)
            manifests.append(output / 'package-build.json')
        home = self.directory / 'gnupg'
        home.mkdir(mode=0o700)
        subprocess.run(PACKAGES.gpg_command(home, '--quick-generate-key', 'cbodotnet ephemeral repository test <test@example.invalid>',
                                            'ed25519', 'sign', '0'), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listing = subprocess.check_output(PACKAGES.gpg_command(home, '--with-colons', '--list-keys')).decode()
        fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        output = self.directory / 'repository'
        result = PACKAGES.build_repositories(manifests, 'deb', output, fingerprint, home)
        self.assertEqual(['debian-13'], [row['variant'] for row in result['archives']])
        repository = output / 'debian-13'
        packages = (repository / 'Packages').read_text()
        self.assertIn('Architecture: amd64', packages)
        self.assertIn('Architecture: arm64', packages)
        self.assertEqual(1, packages.count('Package: cbodotnet-host\n'))
        self.assertTrue((output / 'apt-debian-13.tar.gz').is_file())
        subprocess.run(['gpgv', '--keyring', str(repository / 'cbodotnet-archive-keyring.gpg'),
                        str(repository / 'InRelease')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tarfile.open(output / 'apt-debian-13.tar.gz') as archive:
            names = archive.getnames()
        self.assertIn('InRelease', names)
        self.assertTrue(any(name.startswith('pool/cbodotnet-sdk-10.0_') for name in names))


if __name__ == '__main__':
    unittest.main()
