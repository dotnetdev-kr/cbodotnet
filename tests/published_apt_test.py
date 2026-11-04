"""Reject mismatched metadata or cached bytes before hosted APT lifecycle checks."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import published_apt as APT


class PublishedAptTests(unittest.TestCase):
    fingerprint = 'D7D154B4B33C19A82B95B13688135410ACD9C0EA'

    def stanza(self, package, version, architecture, filename=None, payload=b'package'):
        return '\n'.join((f'Package: {package}', f'Version: {version}', f'Architecture: {architecture}',
            'Filename: ' + (filename or f'pool/{package}_{version}_{architecture}.deb'),
            f'Size: {len(payload)}', 'SHA256: ' + hashlib.sha256(payload).hexdigest())) + '\n\n'

    def packages(self, architecture='amd64'):
        return (self.stanza('cbodotnet-sdk-10.0', '10.0.403-1', architecture)
                + self.stanza('cbodotnet-host', '1.0.0-1', 'all')).encode()

    def test_flat_deb822_source_scopes_architecture_and_signing_key(self):
        for variant in ('ubuntu-24.04', 'debian-13'):
            for architecture in ('amd64', 'arm64'):
                repository = 'https://dotnetdev.kr/cbodotnet/packages/deb/' + variant
                source = APT.deb822_source(repository, architecture)
                self.assertEqual(source, f'Types: deb\nURIs: {repository}\nSuites: ./\n'
                    + f'Architectures: {architecture}\nSigned-By: {APT.KEYRING}\n')
                self.assertNotIn('Components:', source)
        for repository, architecture in [('https://example.org/repo', 'amd64'),
                ('https://dotnetdev.kr/cbodotnet/packages/deb/debian-13', 'all')]:
            with self.subTest(repository=repository, architecture=architecture), self.assertRaises(ValueError):
                APT.deb822_source(repository, architecture)

    def test_keyring_requires_exactly_one_reviewed_primary_ignoring_subkeys(self):
        listing = 'pub:::::::::\nfpr:::::::::' + self.fingerprint + ':\nsub:::::::::\nfpr:::::::::' + 'B' * 40 + ':\n'
        APT.verify_primary_fingerprint(listing, self.fingerprint)
        for invalid in ('', listing.replace(self.fingerprint, 'C' * 40),
                        listing + 'pub:::::::::\nfpr:::::::::' + 'D' * 40 + ':\n', 'pub:\nfpr:'):
            with self.subTest(listing=invalid), self.assertRaises(ValueError):
                APT.verify_primary_fingerprint(invalid, self.fingerprint)

    def test_packages_must_match_signed_release_hash_and_size(self):
        packages = self.packages()
        row = f' {hashlib.sha256(packages).hexdigest()} {len(packages)} Packages\n'
        release = 'Origin: Community Build of .NET\nSHA256:\n' + row + ' 00 1 Packages.gz\n'
        APT.verify_packages_index(release, packages)
        for invalid in (release.replace(str(len(packages)) + ' Packages', '1 Packages'),
                        release.replace(row, row + row), release.replace('SHA256:', 'MD5Sum:')):
            with self.subTest(release=invalid), self.assertRaises(ValueError):
                APT.verify_packages_index(invalid, packages)
        with self.assertRaises(ValueError):
            APT.verify_packages_index(release, packages.replace(b'cbodotnet-host', b'cbodotnet-hosT'))

    def test_exact_native_sdk_revision_and_shared_host_are_selected(self):
        packages = self.packages() + self.stanza('cbodotnet-sdk-10.0', '10.0.403-1', 'arm64').encode()
        records = APT.package_descriptors(packages, '10.0.403', 1, 'amd64')
        self.assertEqual({(row['package'], row['version'], row['architecture']) for row in records},
            {('cbodotnet-sdk-10.0', '10.0.403-1', 'amd64'), ('cbodotnet-host', '1.0.0-1', 'all')})
        for architecture, revision in [('arm64', 1), ('amd64', 2)]:
            with self.subTest(architecture=architecture, revision=revision), self.assertRaises(ValueError):
                APT.package_descriptors(self.packages(), '10.0.403', revision, architecture)
        with self.assertRaises(ValueError):
            APT.package_descriptors(self.stanza('cbodotnet-sdk-10.0', '10.0.403-1', 'amd64').encode(),
                                    '10.0.403', 1, 'amd64')

    def test_duplicate_or_unsafe_authenticated_package_descriptors_are_rejected(self):
        host = self.stanza('cbodotnet-host', '1.0.0-1', 'all')
        for filename in ('/pool/sdk.deb', 'pool/../sdk.deb', 'pool//sdk.deb', 'pool/sdk\\file.deb', 'sdk.deb'):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                APT.package_descriptors((self.stanza('cbodotnet-sdk-10.0', '10.0.403-1', 'amd64', filename) + host).encode(),
                                        '10.0.403', 1, 'amd64')
        for packages in (self.packages() * 2, self.packages().replace(b'Size: 7', b'Size: 0'),
                         self.packages().replace(b'Package: cbodotnet-host', b'Package: cbodotnet-host\nSize: 7')):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                APT.package_descriptors(packages, '10.0.403', 1, 'amd64')

    def test_retained_package_size_and_sha_are_checked_again_before_reinstall(self):
        descriptor = APT.package_descriptors(self.packages(), '10.0.403', 1, 'amd64')[0]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'retained.deb'
            package.write_bytes(b'package')
            APT.verify_cache_file(package, descriptor)
            for corrupted in (b'packagE', b'package-extra'):
                package.write_bytes(corrupted)
                with self.subTest(bytes=corrupted), self.assertRaises(ValueError):
                    APT.verify_cache_file(package, descriptor)

    def test_offline_reinstall_restores_authenticated_apt_cache_and_requests_exact_versions(self):
        records = APT.package_descriptors(self.packages(), '10.0.403', 1, 'amd64')
        with tempfile.TemporaryDirectory() as directory:
            state_root, apt_cache = Path(directory) / 'state', Path(directory) / 'apt-cache'
            (state_root / 'cache').mkdir(parents=True); apt_cache.mkdir()
            for record in records:
                record['cacheFile'] = record['filename'].split('/')[-1]
                (state_root / 'cache' / record['cacheFile']).write_bytes(b'package')
            with mock.patch.object(APT, 'STATE', state_root), mock.patch.object(APT, 'APT_CACHE', apt_cache), \
                    mock.patch.object(APT, 'run') as commands:
                APT.reinstall_cached_packages({'authenticatedPackages': records})
                commands.assert_called_once_with(['apt-get', 'install', '-y', '--no-download',
                    'cbodotnet-sdk-10.0=10.0.403-1', 'cbodotnet-host=1.0.0-1'])
                for record in records:
                    self.assertEqual((apt_cache / record['cacheFile']).read_bytes(), b'package')
                commands.reset_mock()
                (state_root / 'cache' / records[0]['cacheFile']).write_bytes(b'packagE')
                with self.assertRaises(ValueError):
                    APT.reinstall_cached_packages({'authenticatedPackages': records})
                commands.assert_not_called()


if __name__ == '__main__':
    unittest.main()
