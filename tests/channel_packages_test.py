"""Build real Debian fixtures and reject unsafe or unqualified package inputs."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.parse
import xml.etree.ElementTree as ET

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
                'sourceManifestUrl': 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-10.0.403/release-manifest.json',
                'source': {'url': 'https://example.invalid/qualified-source.tar.gz', 'sha256': 'c' * 64},
                'evidence': {'url': 'https://example.invalid/qualified-evidence.tar.gz', 'sha256': 'd' * 64},
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
        labels = result['labels']
        self.assertEqual('MIT AND LicenseRef-Dotnet-ThirdPartyNotices', labels['org.opencontainers.image.licenses'])
        self.assertEqual('/opt/cbodotnet/10.0/LICENSE.txt', labels['kr.dotnetdev.cbodotnet.license.path'])
        self.assertEqual('/opt/cbodotnet/10.0/ThirdPartyNotices.txt', labels['kr.dotnetdev.cbodotnet.notices.path'])
        self.assertEqual(plan['source']['url'], labels['kr.dotnetdev.cbodotnet.source.url'])
        self.assertEqual(plan['evidence']['sha256'], labels['kr.dotnetdev.cbodotnet.evidence.sha256'])
        self.assertEqual(plan['sourceManifestUrl'], labels['kr.dotnetdev.cbodotnet.manifest.url'])

    def test_oci_packaging_upgrade_updates_its_own_labels_without_changing_sdk_payload(self):
        plan, archive = self.fixture(channel='oci', revision=2)
        first = PACKAGES.build_oci_context(plan, archive, self.directory / 'oci-r2', 'debian:13@sha256:' + 'b' * 64)
        upgraded = copy.deepcopy(plan)
        upgraded['packageRevision'] = 3
        upgraded['package']['version'] = '10.0.403-3'
        second = PACKAGES.build_oci_context(upgraded, archive, self.directory / 'oci-r3', 'debian:13@sha256:' + 'b' * 64)
        self.assertEqual('2', first['labels']['kr.dotnetdev.cbodotnet.package.revision'])
        self.assertEqual('3', second['labels']['kr.dotnetdev.cbodotnet.package.revision'])
        self.assertEqual(first['labels']['kr.dotnetdev.cbodotnet.sdk.sha256'], second['labels']['kr.dotnetdev.cbodotnet.sdk.sha256'])
        self.assertEqual(PACKAGES.sdk_tools().snapshot(self.directory / 'oci-r2/rootfs/opt/cbodotnet/10.0'),
                         PACKAGES.sdk_tools().snapshot(self.directory / 'oci-r3/rootfs/opt/cbodotnet/10.0'))

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

    def rpm_fixture(self, arch='x64', revision=1, variant='fedora-45'):
        plan, archive = self.fixture(arch=arch, channel='rpm', revision=revision)
        plan['variant'] = variant
        plan['rpmDependencies'] = ['glibc', 'libgcc', 'libstdc++', 'zlib-ng-compat' if variant == 'fedora-45' else 'zlib',
                                   'krb5-libs', 'ca-certificates', 'libicu', 'openssl-libs']
        return plan, archive

    def test_rpm_distribution_release_and_dependency_identities_are_distinct(self):
        fedora, _ = self.rpm_fixture()
        rocky, _ = self.rpm_fixture(variant='rocky-9.8')
        self.assertEqual('1.cbot.fedora45', PACKAGES.rpm_release(fedora))
        self.assertEqual('1.cbot.rocky9.8', PACKAGES.rpm_release(rocky))
        self.assertIn('Release: 1.cbot.fedora45', PACKAGES.render_rpm_spec(fedora))
        self.assertIn('zlib-ng-compat', PACKAGES.render_rpm_spec(fedora))
        self.assertIn('Requires: glibc, libgcc, libstdc++, zlib,', PACKAGES.render_rpm_spec(rocky))
        rocky['package']['rpmRelease'] = '1.cbot.fedora45'
        with self.assertRaisesRegex(ValueError, 'canonical distro identity'):
            PACKAGES.render_rpm_spec(rocky)
        for variant in ('fedora-45;touch', '../rocky-9.8', 'rocky-9.8\nRequires: malicious'):
            fedora['variant'] = variant
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                PACKAGES.render_rpm_spec(fedora)

    def test_rpm_specs_disable_sdk_rewrites_and_fix_reproducible_common_metadata(self):
        plan, _ = self.rpm_fixture()
        for spec in (PACKAGES.render_rpm_spec(plan), PACKAGES.render_rpm_host_spec(plan)):
            self.assertIn('%global _rpmformat 4', spec)
            self.assertIn('%global __spec_install_post %{nil}', spec)
            self.assertIn('%global _buildhost reproducible.cbodotnet.invalid', spec)
            self.assertIn('%global use_source_date_epoch_as_buildtime 1', spec)
            self.assertIn('%global _binary_payload w6.xzdio', spec)
            self.assertNotIn('/usr/bin/dotnet', spec)
        host = PACKAGES.render_rpm_host_spec(plan)
        self.assertIn('BuildArch: noarch', host)
        self.assertIn('%global optflags %{nil}', host)
        self.assertNotIn('%global optflags %{nil}', PACKAGES.render_rpm_spec(plan))
        self.assertNotIn('/opt/cbodotnet', host)
        self.assertIn('%license /usr/share/licenses/cbodotnet-host/LICENSE', host)

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('rpmbuild', 'rpm', 'rpm2cpio', 'cpio')),
                         'Native RPM build/extraction tools are required')
    def test_real_rpm_payload_identity_and_common_package_reproducibility(self):
        shared = []
        arch = 'aarch64' if platform.machine() in {'aarch64', 'arm64'} else 'x64'
        for revision in (1, 2):
            plan, archive = self.rpm_fixture(arch=arch, revision=revision)
            output = self.directory / ('rpm-r' + str(revision))
            result = PACKAGES.build_rpm(plan, archive, output)
            common = next(item for item in result['packages'] if item['kind'] == 'host')
            sdk = next(item for item in result['packages'] if item['kind'] == 'sdk')
            shared.append(common['sha256'])
            self.assertEqual('1.cbot.fedora45', common['release'])
            self.assertEqual('noarch', common['architecture'])
            self.assertEqual(str(revision) + '.cbot.fedora45', sdk['release'])
            actual = subprocess.check_output(['rpm', '--query', '--package', '--queryformat',
                      '%{BUILDTIME}\n%{BUILDHOST}\n%{PAYLOADCOMPRESSOR}\n%{FILEDIGESTALGO}\n',
                      str(output / common['path'])]).decode().splitlines()
            self.assertEqual([PACKAGES.SOURCE_DATE_EPOCH, 'reproducible.cbodotnet.invalid', 'xz', '8'], actual)
            self.assertEqual(b'qualified-managed-bytes',
                             (output / 'rpm-verified/opt/cbodotnet/10.0/sdk/10.0.403/reference.dll').read_bytes())
            self.assertFalse((output / 'rpm-verified/usr/bin/cbodotnet').exists())
            self.assertFalse((output / 'rpm-host-verified/opt').exists())
        self.assertEqual(shared[0], shared[1])
        # The common package uses a canonical noarch target. A native target
        # would leak its architecture into byte 9 of RPM's legacy package lead
        # even when all queried noarch header tags and payload bytes match.
        cross = self.directory / 'rpm-common-cross-target'
        for directory in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
            (cross / directory).mkdir(parents=True)
        shutil.copyfile(output / 'rpmbuild/SOURCES/host.tar.gz', cross / 'SOURCES/host.tar.gz')
        spec = cross / 'SPECS/host.spec'
        other = copy.deepcopy(plan)
        other['architecture'] = copy.deepcopy(ARCHITECTURES['x64' if arch == 'aarch64' else 'aarch64'])
        spec.write_text(PACKAGES.render_rpm_host_spec(other))
        subprocess.run(['rpmbuild', '--define', '_topdir ' + str(cross), '--target', 'noarch', '-bb', str(spec)],
                       env=dict(os.environ, SOURCE_DATE_EPOCH=PACKAGES.SOURCE_DATE_EPOCH, TZ='UTC', LC_ALL='C'),
                       check=True, stdout=subprocess.PIPE)
        cross_package = next((cross / 'RPMS').rglob('cbodotnet-host-*.rpm'))
        self.assertEqual(shared[0], PACKAGES.sha256_file(cross_package))

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('rpmbuild', 'rpm', 'rpm2cpio', 'cpio')),
                         'Native RPM build/extraction tools are required')
    def test_common_only_builder_ignores_native_compiler_flags_without_changing_its_payload(self):
        run = subprocess.run
        hashes = []
        for index, flags in enumerate(('-O2 -m64 -march=x86-64-v2', '-O2 -mbranch-protection=standard')):
            output = self.directory / ('common-native-flags-' + str(index))
            def execute(command, **kwargs):
                if command[0] == 'rpmbuild':
                    command = [*command[:1], '--define', 'optflags ' + flags, *command[1:]]
                return run(command, **kwargs)
            with mock.patch.object(PACKAGES.subprocess, 'run', side_effect=execute), \
                 mock.patch.object(PACKAGES, 'stage_payload', side_effect=AssertionError('Common build must not receive an SDK')):
                result = PACKAGES.build_common_rpm('fedora-45', output)
            row = result['packages'][0]
            hashes.append(row['sha256'])
            actual_flags = subprocess.check_output(['rpm', '--query', '--package', '--queryformat', '%{OPTFLAGS}',
                                                     str(output / row['path'])]).decode()
            self.assertNotIn('-m64', actual_flags)
            self.assertNotIn('-mbranch-protection', actual_flags)
            self.assertTrue(result['payloadPreserved'])
            self.assertEqual(PACKAGES.default_launcher_text().encode(),
                             (output / 'rpm-host-verified/usr/bin/cbodotnet').read_bytes())
        self.assertEqual(hashes[0], hashes[1])

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('rpmbuild', 'rpm', 'rpm2cpio', 'cpio', 'rpmkeys',
                                                          'rpmsign', 'createrepo_c', 'gpg', 'gpgv')),
                         'RPM repository and signing tools are required')
    def test_signed_rpm_metadata_references_immutable_assets_without_archiving_package_blobs(self):
        arch = 'aarch64' if platform.machine() in {'aarch64', 'arm64'} else 'x64'
        plan, archive = self.rpm_fixture(arch=arch)
        build_dir = self.directory / 'rpm-publish-input'
        build = PACKAGES.build_rpm(plan, archive, build_dir)
        other_plan, other_archive = self.rpm_fixture(arch='x64' if arch == 'aarch64' else 'aarch64')
        other_dir = self.directory / 'rpm-publish-other-arch'
        # This shell-only package fixture exercises index identities for the
        # other CPU without claiming execution there. --target still sets its
        # header; omitting BuildArch avoids RPM's native-build compatibility gate.
        render = PACKAGES.render_rpm_spec
        with mock.patch.object(PACKAGES, 'render_rpm_spec', side_effect=lambda value: render(value).replace(
                'BuildArch: ' + value['architecture']['rpm'] + '\n', '')):
            other_build = PACKAGES.build_rpm(other_plan, other_archive, other_dir)
        builds = [(build_dir, build), (other_dir, other_build)]
        home = self.directory / 'rpm-signing'
        home.mkdir(mode=0o700)
        subprocess.run(PACKAGES.gpg_command(home, '--quick-generate-key', 'cbodotnet ephemeral rpm test <test@example.invalid>',
                                            'rsa2048', 'sign', '0'), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listing = subprocess.check_output(PACKAGES.gpg_command(home, '--with-colons', '--list-keys'), stderr=subprocess.PIPE).decode()
        fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        base = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-rpm-sdk-10.0.403-r1/'
        admission = (builds, plan, ['fedora-45'])
        unsigned_output = self.directory / 'unsigned-rpm-repository'
        with mock.patch.object(PACKAGES, 'validate_package_builds', return_value=admission):
            with self.assertRaisesRegex(ValueError, 'verified package signatures'):
                PACKAGES.build_repositories([], 'rpm', unsigned_output, fingerprint, home, rpm_asset_base_url=base)
        self.assertFalse((unsigned_output / 'fedora-45/repodata/repomd.xml').exists())
        signed_common = None
        for parent, current_build in builds:
            for item in current_build['packages']:
                path = parent / item['path']
                if item['kind'] == 'host' and signed_common is not None:
                    shutil.copyfile(signed_common, path)
                else:
                    signed = subprocess.run(['rpmsign', '--define', '_gpg_name ' + fingerprint, '--define', '_gpg_path ' + str(home),
                                             '--define', '__gpg ' + shutil.which('gpg'), '--define', '_gpg_digest_algo sha256', '--addsign', str(path)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.assertEqual(0, signed.returncode, signed.stdout + signed.stderr)
                    if item['kind'] == 'host':
                        signed_common = path
                item.update(PACKAGES.descriptor(path))
        output = self.directory / 'rpm-published-repository'
        with mock.patch.object(PACKAGES, 'validate_package_builds', return_value=admission):
            result = PACKAGES.build_repositories([], 'rpm', output, fingerprint, home, rpm_asset_base_url=base)
        assets = {row['assetName']: row for row in result['packageAssets']}
        self.assertEqual(3, len(assets))
        self.assertTrue(any(name.startswith('rpm-fedora-45--cbodotnet-host-') for name in assets))
        self.assertTrue(any(name.startswith('rpm-fedora-45-' + arch + '--cbodotnet-sdk-') for name in assets))
        repository = output / 'fedora-45'
        repo_manifest = json.loads((repository / 'repository-manifest.json').read_bytes())
        self.assertEqual(base, repo_manifest['assetBaseUrl'])
        self.assertEqual(set(assets), set(repo_manifest['packages']))
        for name, row in repo_manifest['packages'].items():
            self.assertEqual(base + name, row['url'])
            self.assertEqual(assets[name]['sha256'], row['sha256'])
            self.assertEqual(assets[name]['size'], row['size'])
        namespace = {'repo': 'http://linux.duke.edu/metadata/repo', 'common': 'http://linux.duke.edu/metadata/common'}
        metadata = ET.parse(repository / 'repodata/repomd.xml')
        primary = next(item for item in metadata.findall('repo:data', namespace) if item.attrib['type'] == 'primary')
        href = primary.find('repo:location', namespace).attrib['href']
        with gzip.open(repository / href) as stream:
            packages = ET.parse(stream)
        locations = packages.findall('common:package/common:location', namespace)
        urls = {urllib.parse.urljoin(item.attrib.get('{http://www.w3.org/XML/1998/namespace}base', ''), item.attrib['href'])
                for item in locations}
        self.assertEqual({base + name for name in assets}, urls)
        import rpm_repository
        rpm_repository.verify_repository(repository, repository / 'cbodotnet-archive-keyring.gpg', assets, base)
        with tarfile.open(output / 'rpm-fedora-45.tar.gz') as bundle:
            self.assertFalse(any(name.endswith('.rpm') for name in bundle.getnames()))
            self.assertIn('repodata/repomd.xml.asc', bundle.getnames())
            self.assertIn('cbodotnet-rpm-signing-key.asc', bundle.getnames())

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
