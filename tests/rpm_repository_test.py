"""Authenticate RPM index bytes, exact package identities, and public URLs."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rpm_repository as REPOSITORY


class RpmRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / 'fedora-45'
        (self.directory / 'repodata').mkdir(parents=True)
        self.matrix()

    def matrix(self, version='10.0.403'):
        self.base = REPOSITORY.asset_base(version, 1)
        series = '.'.join(version.split('.')[:2])
        self.identities = {
            f'rpm-fedora-45-x64--cbodotnet-sdk-{series}-{version}-1.cbot.fedora45.x86_64.rpm':
                ('cbodotnet-sdk-' + series, 'x86_64', version, '1.cbot.fedora45'),
            f'rpm-fedora-45-aarch64--cbodotnet-sdk-{series}-{version}-1.cbot.fedora45.aarch64.rpm':
                ('cbodotnet-sdk-' + series, 'aarch64', version, '1.cbot.fedora45'),
            'rpm-fedora-45--cbodotnet-host-1.0.0-1.cbot.fedora45.noarch.rpm':
                ('cbodotnet-host', 'noarch', '1.0.0', '1.cbot.fedora45')}
        if version in {'5.0.214', '3.1.426', '3.0.103'}:
            for public, native in [('x64', 'x86_64'), ('aarch64', 'aarch64')]:
                self.identities[f'rpm-fedora-45-{public}--cbodotnet-compat-rocky9-2026.11.4-1.cbot.fedora45.{native}.rpm'] = (
                    'cbodotnet-compat-rocky9', native, '2026.11.4', '1.cbot.fedora45')
        self.assets = {name: {'name': name, 'size': 123 + index, 'sha256': str(index + 1) * 64}
                       for index, name in enumerate(self.identities)}
        self.manifest = dict(schemaVersion=1, channel='rpm', sdkVersion=version, packageRevision=1,
            variant='fedora-45', architectures=['x64', 'aarch64'], assetBaseUrl=self.base,
            packages={name: {key: value for key, value in row.items() if key != 'name'} | {'url': self.base + name}
                      for name, row in self.assets.items()})
        self.primary = ET.Element(REPOSITORY.COMMON + 'metadata', packages=str(len(self.identities)))
        for name, (package, arch, version, release) in self.identities.items():
            row = ET.SubElement(self.primary, REPOSITORY.COMMON + 'package', type='rpm')
            ET.SubElement(row, REPOSITORY.COMMON + 'name').text = package
            ET.SubElement(row, REPOSITORY.COMMON + 'arch').text = arch
            ET.SubElement(row, REPOSITORY.COMMON + 'version', epoch='0', ver=version, rel=release)
            ET.SubElement(row, REPOSITORY.COMMON + 'checksum', type='sha256').text = self.assets[name]['sha256']
            ET.SubElement(row, REPOSITORY.COMMON + 'size', package=str(self.assets[name]['size']))
            ET.SubElement(row, REPOSITORY.COMMON + 'location', {'href': name, REPOSITORY.XML_BASE: self.base})
        self.save()

    def save(self, open_hash=None):
        raw = ET.tostring(self.primary)
        compressed = gzip.compress(raw, mtime=1700000000)
        path = self.directory / 'repodata/primary.xml.gz'
        path.write_bytes(compressed)
        metadata = ET.Element(REPOSITORY.REPO + 'repomd')
        row = ET.SubElement(metadata, REPOSITORY.REPO + 'data', type='primary')
        ET.SubElement(row, REPOSITORY.REPO + 'location', href='repodata/primary.xml.gz')
        ET.SubElement(row, REPOSITORY.REPO + 'checksum', type='sha256').text = hashlib.sha256(compressed).hexdigest()
        ET.SubElement(row, REPOSITORY.REPO + 'size').text = str(len(compressed))
        ET.SubElement(row, REPOSITORY.REPO + 'open-checksum', type='sha256').text = open_hash or hashlib.sha256(raw).hexdigest()
        ET.SubElement(row, REPOSITORY.REPO + 'open-size').text = str(len(raw))
        (self.directory / 'repodata/repomd.xml').write_bytes(ET.tostring(metadata))
        (self.directory / 'repository-manifest.json').write_text(json.dumps(self.manifest))

    def validate(self):
        return REPOSITORY.validate_metadata(self.directory, self.assets, self.base)

    def test_complete_matrix_binds_public_urls_and_all_compressed_and_open_digests(self):
        self.assertEqual(self.manifest, self.validate())

    def test_legacy_repositories_require_both_exact_separate_compatibility_packages(self):
        for version in ['5.0.214', '3.1.426', '3.0.103']:
            with self.subTest(version=version):
                self.matrix(version)
                self.assertEqual(self.manifest, self.validate())
                name = next(name for name in self.manifest['packages'] if '-aarch64--cbodotnet-compat-' in name)
                self.manifest['packages'].pop(name)
                self.save()
                with self.assertRaisesRegex(ValueError, 'provider architectures'):
                    self.validate()

    def test_provider_name_release_version_architecture_and_epoch_are_pinned(self):
        for field, value in [('name', 'openssl11'), ('arch', 'noarch'), ('ver', '2026.11.5'),
                             ('rel', '1.cbot.rocky9.8'), ('epoch', '1')]:
            with self.subTest(field=field):
                self.matrix('3.1.426')
                row = next(row for row in self.primary if row.findtext(REPOSITORY.COMMON + 'name') == 'cbodotnet-compat-rocky9')
                if field in {'name', 'arch'}:
                    row.find(REPOSITORY.COMMON + field).text = value
                else:
                    row.find(REPOSITORY.COMMON + 'version').set(field, value)
                self.save()
                with self.assertRaisesRegex(ValueError, 'authenticated packages'):
                    self.validate()

    def test_legacy_provider_cannot_be_added_to_a_modern_repository(self):
        self.matrix('3.1.426')
        self.manifest['sdkVersion'] = '10.0.403'
        self.manifest['assetBaseUrl'] = REPOSITORY.asset_base('10.0.403', 1)
        self.base = self.manifest['assetBaseUrl']
        self.save()
        with self.assertRaisesRegex(ValueError, 'provider architectures'):
            self.validate()

    def test_asset_origin_revision_and_cross_variant_or_partial_matrices_are_rejected(self):
        for change in ('origin', 'revision', 'missing-arch', 'duplicate-arch', 'variant'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.manifest)
                if change == 'origin':
                    self.manifest['assetBaseUrl'] = 'https://example.invalid/'
                elif change == 'revision':
                    self.manifest['packageRevision'] = 2
                elif change == 'variant':
                    self.manifest['variant'] = 'rocky-9.8'
                else:
                    name = next(name for name in self.manifest['packages'] if '-aarch64--' in name)
                    row = self.manifest['packages'].pop(name)
                    if change == 'duplicate-arch':
                        self.manifest['packages'][name.replace('-aarch64--', '-x64--')] = row
                self.save()
                with self.assertRaises(ValueError):
                    self.validate()
                self.manifest = original

    def test_release_asset_size_and_hash_cannot_be_substituted(self):
        for field, value in [('size', 999), ('sha256', 'f' * 64), ('url', 'https://example.invalid/package.rpm')]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.manifest)
                next(iter(self.manifest['packages'].values()))[field] = value
                self.save()
                with self.assertRaisesRegex(ValueError, 'signed release asset'):
                    self.validate()
                self.manifest = original

    def test_primary_package_header_and_absolute_or_relative_url_tampering_are_rejected(self):
        for field, value in [('arch', 'noarch'), ('name', 'dotnet-sdk-10.0'), ('release', '1.cbot.rocky9.8'),
                             ('url', 'https://example.invalid/evil.rpm'), ('url', '../evil.rpm')]:
            with self.subTest(field=field, value=value):
                original = copy.deepcopy(self.primary)
                row = self.primary.find(REPOSITORY.COMMON + 'package')
                if field == 'url':
                    row.find(REPOSITORY.COMMON + 'location').set('href', value)
                elif field == 'release':
                    row.find(REPOSITORY.COMMON + 'version').set('rel', value)
                else:
                    row.find(REPOSITORY.COMMON + field).text = value
                self.save()
                with self.assertRaises(ValueError):
                    self.validate()
                self.primary = original

    def test_compressed_and_open_hashes_are_independently_required(self):
        path = self.directory / 'repodata/primary.xml.gz'
        path.write_bytes(path.read_bytes() + b'corrupt')
        with self.assertRaisesRegex(ValueError, 'metadata digest mismatch'):
            self.validate()
        self.save(open_hash='f' * 64)
        with self.assertRaisesRegex(ValueError, 'Uncompressed RPM metadata digest mismatch'):
            self.validate()

    def test_duplicate_package_and_escaping_metadata_location_fail(self):
        self.primary.append(copy.deepcopy(self.primary[0]))
        self.save()
        with self.assertRaisesRegex(ValueError, 'primary index differs'):
            self.validate()
        path = self.directory / 'repodata/repomd.xml'
        metadata = ET.fromstring(path.read_bytes())
        metadata.find(REPOSITORY.REPO + 'data/' + REPOSITORY.REPO + 'location').set('href', '../outside.gz')
        path.write_bytes(ET.tostring(metadata))
        with self.assertRaisesRegex(ValueError, 'Unsafe RPM metadata location'):
            self.validate()

    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgv'), 'GnuPG required')
    def test_real_signed_metadata_is_verified_and_any_unsigned_change_fails(self):
        home = self.root / 'gnupg'
        home.mkdir(mode=0o700)
        command = ['gpg', '--batch', '--homedir', str(home), '--pinentry-mode', 'loopback', '--passphrase', '']
        subprocess.run([*command, '--quick-generate-key', 'RPM metadata fixture <test@example.invalid>',
                        'rsa2048', 'sign', '0'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        keyring = self.root / 'trusted.gpg'
        keyring.write_bytes(subprocess.check_output([*command, '--export']))
        metadata = self.directory / 'repodata/repomd.xml'
        subprocess.run([*command, '--armor', '--detach-sign', str(metadata)], check=True, stderr=subprocess.PIPE)
        self.assertEqual(self.manifest, REPOSITORY.verify_repository(self.directory, keyring, self.assets, self.base))
        metadata.write_bytes(metadata.read_bytes() + b' ')
        with self.assertRaises(subprocess.CalledProcessError):
            REPOSITORY.verify_repository(self.directory, keyring, self.assets, self.base)


if __name__ == '__main__':
    unittest.main()
