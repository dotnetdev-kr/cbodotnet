"""Keep downstream preparation bound to qualified bytes and isolated names."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_contract as CONTRACT
from release_catalog_test import fixture

COEXISTENCE_SPEC = importlib.util.spec_from_file_location(
    'distribution_coexistence', ROOT / 'scripts/test-distribution-coexistence.py')
COEXISTENCE = importlib.util.module_from_spec(COEXISTENCE_SPEC)
COEXISTENCE_SPEC.loader.exec_module(COEXISTENCE)


class DistributionContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.contract = copy.deepcopy(CONTRACT.load_contract())
        self.release, self.manifest, self.manifest_bytes, self.checksums = fixture()
        self.contract['releases']['10.0.403']['manifestSha256'] = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.catalog = {'schemaVersion': 1, 'repository': 'dotnetdev-kr/cbodotnet', 'builds': [
            {'target': 'net10', 'sdkVersion': '10.0.403', 'architectures': {
                arch: {key: row['provenance'][key]
                       for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')}
                for arch, row in self.manifest['architectures'].items()}}]}
        self.paths = {}
        for arch, row in self.manifest['architectures'].items():
            path = self.directory / row['sdk']['name']
            path.write_bytes(('sdk' + arch).encode())
            self.paths[arch] = path

    def refresh_manifest(self):
        """Pin intentional fixture changes independently of the checked condition."""
        self.manifest_bytes = json.dumps(self.manifest).encode()
        digest = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.contract['releases']['10.0.403']['manifestSha256'] = digest
        asset = next(row for row in self.release['assets'] if row['name'] == 'release-manifest.json')
        asset.update(size=len(self.manifest_bytes), digest='sha256:' + digest)

    def plan(self, arch='x64', channel='deb', variant='debian-13', revision=1):
        return CONTRACT.verified_plan(self.release, self.manifest_bytes, self.checksums,
                                      self.paths.get(arch, self.paths['x64']), channel, variant, arch,
                                      revision=revision, contract=self.contract, catalog=self.catalog)

    def test_deb_contract_maps_both_architectures_and_preserves_exact_release_identity(self):
        for arch, rid, deb, rpm, oci in (
                ('x64', 'linux-x64', 'amd64', 'x86_64', 'linux/amd64'),
                ('aarch64', 'linux-arm64', 'arm64', 'aarch64', 'linux/arm64')):
            with self.subTest(arch=arch):
                result = self.plan(arch)
                self.assertEqual('prepared-unqualified', result['status'])
                self.assertEqual('10.0.403', result['sdkVersion'])
                self.assertEqual(rid, result['targetRid'])
                self.assertEqual({'public': arch, 'rid': rid, 'deb': deb,
                                  'rpm': rpm, 'aur': rpm, 'oci': oci}, result['architecture'])
                self.assertEqual('cbodotnet-sdk-10.0', result['package']['name'])
                self.assertEqual('10.0.403-1', result['package']['version'])
                self.assertEqual('/opt/cbodotnet/10.0', result['package']['root'])
                self.assertEqual('/usr/bin/cbodotnet-10.0', result['package']['launcher'])
                self.assertEqual(hashlib.sha256(self.manifest_bytes).hexdigest(),
                                 result['sourceManifestSha256'])

    def test_candidate_oci_and_ubuntu_targets_can_prepare_without_claiming_qualification(self):
        for channel, variant in (('oci', 'debian-13'), ('deb', 'ubuntu-24.04')):
            with self.subTest(channel=channel, variant=variant):
                result = self.plan(channel=channel, variant=variant)
                self.assertEqual('prepared-unqualified', result['status'])
                self.assertEqual(channel, result['channel'])
                self.assertEqual(variant, result['variant'])

    def test_packaging_revision_changes_package_identity_without_changing_sdk(self):
        result = self.plan(revision=2)
        self.assertEqual('10.0.403-2', result['package']['version'])
        self.assertEqual(2, result['packageRevision'])
        self.assertEqual('10.0.403', result['sdkVersion'])

    def test_rpm_targets_bind_their_own_dependencies_and_distro_release_identity(self):
        for variant, dependency in [('fedora-45', 'zlib-ng-compat'), ('rocky-9.8', 'zlib')]:
            plan = self.plan(channel='rpm', variant=variant)
            self.assertIn(dependency, plan['rpmDependencies'])
            self.assertEqual(plan['dependencies'], plan['rpmDependencies'])
            self.assertEqual('1.cbot.' + variant.replace('-', ''), plan['package']['rpmRelease'])
            self.assertFalse(plan['publicationAllowed'])
            if variant == 'fedora-45':
                self.assertIn('openssl3-libs', plan['rpmDependencies'])
                self.assertNotIn('openssl-libs', plan['rpmDependencies'])

    def test_arch_recipe_admits_only_independently_selected_x64(self):
        plan = self.plan(channel='aur', variant='arch-rolling')
        self.assertEqual('cbodotnet-sdk-10.0-bin', plan['package']['aurName'])
        self.assertIn('libstdc++', plan['aurDependencies'])
        with self.assertRaisesRegex(ValueError, 'not admitted'):
            self.plan(arch='aarch64', channel='aur', variant='arch-rolling')

    def test_unknown_and_non_public_architecture_aliases_are_rejected(self):
        for arch in ('arm64', 'amd64', 'x86_64', 'riscv64', 'any', '../x64', ''):
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                self.plan(arch=arch)

    def test_unsupported_channels_and_os_versions_are_rejected(self):
        for channel, variant in (('deb', 'ubuntu-22.04'), ('deb', 'ubuntu-26.04'),
                                 ('deb', 'alpine-3.23'), ('deb', 'debian-12'),
                                 ('oci', 'ubuntu-24.04'), ('rpm', 'fedora-43'),
                                 ('aur', 'arch'), ('unknown', 'debian-13')):
            with self.subTest(channel=channel, variant=variant), self.assertRaises(ValueError):
                self.plan(channel=channel, variant=variant)

    def test_invalid_or_ambiguous_revisions_are_rejected(self):
        for revision in (0, -1, True, False, '1', 1.5, None):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.plan(revision=revision)

    def test_manifest_digest_must_match_independently_pinned_release(self):
        self.contract['releases']['10.0.403']['manifestSha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.plan()

    def test_same_sized_corrupt_payload_is_rejected(self):
        path = self.paths['x64']
        path.write_bytes(b'!' * path.stat().st_size)
        with self.assertRaises(ValueError):
            self.plan()

    def test_payload_size_mismatch_and_missing_payload_are_rejected(self):
        path = self.paths['x64']
        path.write_bytes(path.read_bytes() + b'!')
        with self.assertRaises(ValueError):
            self.plan()
        path.unlink()
        with self.assertRaises(ValueError):
            self.plan()

    def test_sdk_payload_from_other_architecture_is_rejected(self):
        self.paths['x64'].write_bytes(self.paths['aarch64'].read_bytes())
        with self.assertRaises(ValueError):
            self.plan()

    def test_partial_release_and_wrong_rid_are_rejected_even_with_matching_manifest_pin(self):
        original = copy.deepcopy(self.manifest)
        self.manifest['architectures'].pop('aarch64')
        self.refresh_manifest()
        with self.assertRaises(ValueError):
            self.plan()
        self.manifest = original
        self.manifest['architectures']['aarch64']['provenance']['targetRid'] = 'linux-x64'
        self.refresh_manifest()
        with self.assertRaises(ValueError):
            self.plan()

    def test_draft_and_prerelease_inputs_are_rejected(self):
        for field in ('draft', 'prerelease'):
            with self.subTest(field=field):
                self.release[field] = True
                with self.assertRaises(ValueError):
                    self.plan()
                self.release[field] = False

    def test_each_producer_identity_must_equal_the_qualification_catalog(self):
        for key, value in (('projectCommit', 'b' * 40), ('runId', '999'),
                           ('runAttempt', '2'), ('artifactId', '999')):
            with self.subTest(key=key):
                row = self.catalog['builds'][0]['architectures']['x64']
                original = row[key]
                row[key] = value
                with self.assertRaises(ValueError):
                    self.plan()
                row[key] = original

    def test_unqualified_or_ambiguous_catalog_version_is_rejected(self):
        row = self.catalog['builds'].pop()
        with self.assertRaises(ValueError):
            self.plan()
        self.catalog['builds'] = [row, copy.deepcopy(row)]
        with self.assertRaises(ValueError):
            self.plan()

    def test_manifest_and_api_digest_disagreement_is_rejected(self):
        self.release['assets'][0]['digest'] = 'sha256:' + 'f' * 64
        with self.assertRaises(ValueError):
            self.plan()

    def test_corrupt_checksum_list_is_rejected(self):
        self.checksums = self.checksums.replace(b'  cbodotnet-sdk-', b'  unqualified-sdk-', 1)
        self.manifest['checksums'].update(size=len(self.checksums),
                                         sha256=hashlib.sha256(self.checksums).hexdigest())
        asset = next(row for row in self.release['assets'] if row['name'] == 'SHA256SUMS')
        asset.update(size=len(self.checksums), digest='sha256:' + hashlib.sha256(self.checksums).hexdigest())
        self.refresh_manifest()
        with self.assertRaises(ValueError):
            self.plan()

    def test_namespace_and_path_collisions_are_rejected(self):
        for key, value in (('rootTemplate', '/usr/share/dotnet'),
                           ('rootTemplate', '/opt/cbodotnet/../dotnet'),
                           ('launcherTemplate', '/usr/bin/dotnet'),
                           ('packageTemplate', 'dotnet-sdk-{series}'),
                           ('aurPackageTemplate', 'dotnet-sdk-{series}-bin')):
            with self.subTest(key=key, value=value):
                original = self.contract['installation'][key]
                self.contract['installation'][key] = value
                with self.assertRaises(ValueError):
                    self.plan()
                self.contract['installation'][key] = original

    def test_unadmitted_sdk_and_legacy_versions_fail_closed(self):
        for version in ('10.0.404', '9.0.123', '5.0.214', '3.1.426'):
            with self.subTest(version=version):
                release, _, manifest, checksums = fixture(version)
                with self.assertRaises(ValueError):
                    CONTRACT.verified_plan(release, manifest, checksums, self.paths['x64'],
                                           'deb', 'debian-13', 'x64', contract=self.contract,
                                           catalog=self.catalog)


class DistributionExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / 'sdk.tar.gz'
        self.destination = self.directory / 'installation'

    @staticmethod
    def member(name, kind=tarfile.REGTYPE, data=b'payload', link='', mode=0o644):
        entry = tarfile.TarInfo(name)
        entry.type = kind
        entry.mode = mode
        entry.linkname = link
        entry.size = len(data) if kind == tarfile.REGTYPE else 0
        return entry, data

    def write_archive(self, entries):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for entry, data in entries:
                archive.addfile(entry, io.BytesIO(data) if entry.isfile() else None)

    def extract(self):
        with mock.patch.object(COEXISTENCE.shutil, 'disk_usage', return_value=mock.Mock(free=2**40)):
            COEXISTENCE.extract_sdk(self.archive, self.destination)

    def reject_before_writing(self, entries):
        self.write_archive(entries)
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.destination.exists(), 'Unsafe input was rejected only after extraction began')

    def test_escaping_absolute_and_platform_specific_paths_are_rejected(self):
        for name in ('../escape', '/absolute', 'sdk/../../escape', 'C:escape', 'sdk\\escape'):
            with self.subTest(name=name):
                self.reject_before_writing([self.member(name)])
        self.assertFalse((self.directory / 'escape').exists())

    def test_file_or_link_cannot_be_the_parent_of_another_member(self):
        for kind, link in ((tarfile.REGTYPE, ''), (tarfile.SYMTYPE, 'target')):
            with self.subTest(kind=kind):
                self.reject_before_writing([
                    self.member('target'), self.member('sdk', kind, link=link),
                    self.member('sdk/dotnet', mode=0o755)])

    def test_unsafe_missing_or_directory_link_targets_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            for target in ('../outside', '/etc/passwd', 'missing', 'directory', 'C:outside', 'a\\b'):
                with self.subTest(kind=kind, target=target):
                    self.reject_before_writing([
                        self.member('directory', tarfile.DIRTYPE, mode=0o755),
                        self.member('link', kind, link=target)])

    def test_link_cycles_and_link_chains_are_rejected(self):
        for second_target in ('first', 'target'):
            with self.subTest(second_target=second_target):
                self.reject_before_writing([
                    self.member('target'), self.member('first', tarfile.SYMTYPE, link='second'),
                    self.member('second', tarfile.SYMTYPE, link=second_target)])

    def test_special_files_and_elevated_permission_bits_are_rejected(self):
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE):
            with self.subTest(kind=kind):
                self.reject_before_writing([self.member('dotnet', kind)])
        for mode in (0o4755, 0o2755, 0o1755):
            with self.subTest(mode=mode):
                self.reject_before_writing([self.member('dotnet', mode=mode)])

    def test_duplicate_normalized_names_are_rejected(self):
        self.reject_before_writing([self.member('dotnet'), self.member('./dotnet')])

    @unittest.skipUnless(os.name == 'posix', 'SDK file links require POSIX filesystem semantics')
    def test_ordinary_sdk_files_and_contained_file_links_preserve_bytes_and_modes(self):
        self.write_archive([
            self.member('.', tarfile.DIRTYPE, mode=0o755),
            self.member('dotnet', data=b'executable-host', mode=0o755),
            self.member('host', tarfile.DIRTYPE, mode=0o755),
            self.member('host/hostfxr.so', data=b'qualified-library'),
            self.member('host/link.so', tarfile.SYMTYPE, link='hostfxr.so', mode=0o777),
            self.member('host/hard.so', tarfile.LNKTYPE, link='host/hostfxr.so'),
            self.member('implicit/template.txt', data=b'template-content'),
        ])
        self.extract()
        self.assertEqual(b'executable-host', (self.destination / 'dotnet').read_bytes())
        self.assertEqual(0o755, stat.S_IMODE((self.destination / 'dotnet').stat().st_mode))
        self.assertEqual(b'qualified-library', (self.destination / 'host/link.so').read_bytes())
        self.assertTrue((self.destination / 'host/link.so').is_symlink())
        self.assertEqual('hostfxr.so', os.readlink(self.destination / 'host/link.so'))
        self.assertEqual((self.destination / 'host/hostfxr.so').stat().st_ino,
                         (self.destination / 'host/hard.so').stat().st_ino)
        self.assertEqual(b'template-content', (self.destination / 'implicit/template.txt').read_bytes())


if __name__ == '__main__':
    unittest.main()
