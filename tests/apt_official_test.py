"""Keep official-package coexistence evidence native, scoped and sensitive to changes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import apt_official as APT


class AptOfficialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_host_or_wrong_os_cannot_run_any_bootstrap_command(self):
        with mock.patch.object(APT.os, 'geteuid', return_value=0), \
             mock.patch.object(APT.Path, 'is_file', return_value=False), mock.patch.object(APT, 'run') as commands:
            with self.assertRaisesRegex(ValueError, 'disposable root Docker'):
                APT.bootstrap('debian-13', 'x64', 'cbot-smoke', self.root / 'state.json')
            commands.assert_not_called()
        with mock.patch.object(APT.os, 'geteuid', return_value=0), \
             mock.patch.object(APT.Path, 'is_file', return_value=True), \
             mock.patch.object(APT, 'os_release', return_value={'ID': 'debian', 'VERSION_ID': '12'}), \
             mock.patch.object(APT, 'run') as commands:
            with self.assertRaisesRegex(ValueError, 'OS/version'):
                APT.guard('debian-13', 'x64', 'cbot-smoke')
            commands.assert_not_called()

    def test_wrong_cpu_or_package_architecture_cannot_claim_native_execution(self):
        for machine, package_arch in [('aarch64', 'amd64'), ('x86_64', 'arm64')]:
            with self.subTest(machine=machine), mock.patch.object(APT.os, 'geteuid', return_value=0), \
                 mock.patch.object(APT.Path, 'is_file', return_value=True), \
                 mock.patch.object(APT, 'os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}), \
                 mock.patch.object(APT.platform, 'machine', return_value=machine), \
                 mock.patch.object(APT, 'run', return_value=package_arch):
                with self.assertRaisesRegex(ValueError, 'exact native architecture'):
                    APT.guard('ubuntu-24.04', 'x64', 'cbot-smoke')

    def test_microsoft_source_binds_only_exact_target_architecture_and_private_keyring(self):
        text = APT.microsoft_source('aarch64')
        for required in ('Types: deb\n', 'URIs: https://packages.microsoft.com/debian/13/prod\n',
                         'Suites: trixie\nComponents: main\n', 'Architectures: arm64\n',
                         'Signed-By: ' + APT.MICROSOFT_KEYRING + '\n'):
            self.assertIn(required, text)
        self.assertNotIn('trusted.gpg', text)
        self.assertNotIn('apt-key', text)

    def test_primary_fingerprints_ignore_subkeys_but_preserve_every_appended_primary(self):
        listing = 'pub:::::::::\nfpr:::::::::' + APT.MICROSOFT_FINGERPRINT + ':\nsub:::::::::\nfpr:::::::::' + 'B' * 40 + ':\n'
        self.assertEqual([APT.MICROSOFT_FINGERPRINT], APT.primary_fingerprints(listing))
        listing += 'pub:::::::::\nfpr:::::::::' + 'C' * 40 + ':\n'
        self.assertEqual([APT.MICROSOFT_FINGERPRINT, 'C' * 40], APT.primary_fingerprints(listing))

    def test_foreign_or_appended_key_never_becomes_repository_trust(self):
        for fingerprints in ([APT.MICROSOFT_FINGERPRINT, 'B' * 40], ['B' * 40], []):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = APT.MICROSOFT_KEY_URL
            response.read.return_value = b'armored-public-key'
            listing = ''.join('pub:::::::::\nfpr:::::::::' + value + ':\n' for value in fingerprints).encode()
            with self.subTest(fingerprints=fingerprints), \
                 mock.patch.object(APT.urllib.request, 'urlopen', return_value=response), \
                 mock.patch.object(APT, 'run', return_value=listing), mock.patch.object(APT, 'write_config') as write:
                with self.assertRaisesRegex(ValueError, 'reviewed primary fingerprint'):
                    APT.configure_microsoft('x64')
                write.assert_not_called()

    def test_candidate_must_bind_version_origin_suite_and_architecture(self):
        source = dict(repository='https://packages.microsoft.com/debian/13/prod', suite='trixie', component='main')
        text = ('dotnet-sdk-10.0:\n  Installed: (none)\n  Candidate: 10.0.403-1\n  Version table:\n'
                '     10.0.403-1 500\n        500 https://packages.microsoft.com/debian/13/prod trixie/main arm64 Packages\n')
        self.assertEqual('10.0.403-1', APT.candidate(text, source, 'aarch64'))
        for changed in (text.replace('https://packages.microsoft.com/debian/13/prod', 'https://example.invalid'),
                        text.replace('trixie/main', 'bookworm/main'), text.replace('arm64 Packages', 'amd64 Packages'),
                        text.replace('Candidate: 10.0.403-1', 'Candidate: (none)'),
                        text.replace('Candidate: 10.0.403-1', 'Candidate: 10.0.404-1')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                APT.candidate(changed, source, 'aarch64')

    def test_microsoft_detached_signature_is_bound_to_exact_apt_cached_cleartext(self):
        cached = self.root / 'InRelease'
        release = b'Origin: Microsoft\nSHA256:\n abc 123 Packages\n'
        cached.write_bytes(b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n' + release
                           + b'\n-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n')
        repository = 'https://packages.microsoft.com/debian/13/prod'
        def fetch(url, **kwargs):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = url
            response.read.return_value = release if url.endswith('/Release') else b'detached-signature'
            return response
        with mock.patch.object(APT.urllib.request, 'urlopen', side_effect=fetch), \
             mock.patch.object(APT, 'run', return_value='verified') as verifier:
            status, evidence = APT.verify_microsoft_release(cached, self.root / 'key.gpg', repository)
            self.assertEqual('verified', status)
            self.assertEqual(hashlib.sha256(release).hexdigest(), evidence['signedReleaseSha256'])
            self.assertIn('gpgv', verifier.call_args.args[0])
            cached.write_bytes(cached.read_bytes().replace(b'abc 123', b'bad 999'))
            verifier.reset_mock()
            with self.assertRaisesRegex(ValueError, 'differs from APT cached metadata'):
                APT.verify_microsoft_release(cached, self.root / 'key.gpg', repository)
            verifier.assert_not_called()

    def test_root_digest_changes_for_actual_bytes_modes_links_and_ownership(self):
        root = self.root / 'official'
        root.mkdir()
        target = root / 'dotnet'
        target.write_bytes(b'official-host')
        target.chmod(0o755)
        link = root / 'host-link'
        link.symlink_to('dotnet')
        baseline = APT.root_inventory(root)
        self.assertEqual((3, 1, 1, 13), tuple(baseline[key] for key in ('entries', 'files', 'links', 'bytes')))
        self.assertEqual({'sha256', 'entries', 'files', 'links', 'bytes'}, set(baseline))
        target.write_bytes(b'altered-host')
        self.assertNotEqual(baseline, APT.root_inventory(root))
        target.write_bytes(b'official-host')
        target.chmod(0o700)
        self.assertNotEqual(baseline, APT.root_inventory(root))
        target.chmod(0o755)
        link.unlink(); link.symlink_to('another-host')
        self.assertNotEqual(baseline, APT.root_inventory(root))
        link.unlink(); link.symlink_to('dotnet')
        metadata = APT.file_metadata
        def changed_owner(path):
            row = metadata(path)
            return dict(row, uid=row['uid'] + 1) if Path(path) == target else row
        with mock.patch.object(APT, 'file_metadata', side_effect=changed_owner):
            self.assertNotEqual(baseline, APT.root_inventory(root))

    def test_dpkg_baseline_permits_only_missing_official_documentation(self):
        APT.validate_dpkg_baseline('')
        APT.validate_dpkg_baseline('missing     /usr/share/doc/dotnet-sdk-10.0/copyright\n'
                                   'missing     /usr/share/man/man1/dotnet.1.gz\n')
        for value in ('missing     /usr/lib/dotnet/dotnet\n', 'missing c /etc/dotnet/install_location\n',
                      '??5??????   /usr/share/doc/dotnet-sdk-10.0/copyright\n',
                      'missing     /usr/share/doc/unrelated-package/copyright\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'outside minimal-image documentation'):
                APT.validate_dpkg_baseline(value)

    @unittest.skipUnless(shutil.which('dpkg'), 'dpkg required for isolated read-only verification fixture')
    def test_real_missing_documentation_verification_exits_zero_and_retains_exact_output(self):
        root, admin = self.root / 'package-root', self.root / 'package-db'
        root.mkdir(); (admin / 'info').mkdir(parents=True)
        (admin / 'status').write_text('Package: dotnet-sdk-fixture\nStatus: install ok installed\n'
            'Architecture: all\nVersion: 1.0\nMaintainer: Fixture <test@example.invalid>\nDescription: isolated fixture\n\n')
        (admin / 'info/dotnet-sdk-fixture.list').write_text('/usr/share/doc/dotnet-sdk-fixture/copyright\n')
        (admin / 'info/dotnet-sdk-fixture.md5sums').write_text(hashlib.md5(b'notice').hexdigest()
            + '  usr/share/doc/dotnet-sdk-fixture/copyright\n')
        result = subprocess.run(['dpkg', '--root=' + str(root), '--admindir=' + str(admin), '--verify', 'dotnet-sdk-fixture'],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('missing     /usr/share/doc/dotnet-sdk-fixture/copyright\n', result.stdout)
        APT.validate_dpkg_baseline(result.stdout)

    def test_official_version_runs_absolute_host_in_empty_cwd_with_no_inherited_environment(self):
        account = dict(name='fixture-user', uid=os.getuid(), gid=os.getgid(), home=str(self.root))
        with mock.patch.object(APT, 'run', side_effect=['10.0.403\n', '10.0.403 [/usr/share/dotnet/sdk]\n']) as commands:
            version, listing = APT.official_version(account)
        self.assertEqual('10.0.403', version)
        self.assertEqual(['10.0.403 [/usr/share/dotnet/sdk]'], listing)
        for call in commands.call_args_list:
            command = call.args[0]
            self.assertIn('/usr/bin/dotnet', command)
            self.assertIn('-i', command)
            self.assertFalse(any(item.startswith('DOTNET_ROOT=') for item in command))
            self.assertNotEqual(ROOT, Path(call.kwargs['cwd']))

    def fixture_state(self):
        profile, keyring = self.root / 'microsoft.sources', self.root / 'microsoft.gpg'
        profile.write_bytes(b'scoped-source'); keyring.write_bytes(b'approved-public-key')
        account = dict(name='cbot-smoke', uid=10001, gid=10001, home='/home/cbot-smoke')
        snapshot = dict(officialRoot='/usr/share/dotnet', sdkVersion='10.0.403', sdkListing=['10.0.403 [/usr/share/dotnet/sdk]'],
            command=dict(path='/usr/bin/dotnet', owner='dotnet-host', linkTarget='../share/dotnet/dotnet',
                         resolvedPath='/usr/share/dotnet/dotnet', mode='0777', uid=0, gid=0, sha256='a' * 64),
            packages=[dict(name='dotnet-sdk-10.0', version='10.0.403-1', architecture='arm64', status='installed')],
            packageInventorySha256='b' * 64, rootInventory=dict(sha256='c' * 64, entries=100, files=90, links=2, bytes=1000),
            dpkgVerificationOutput='missing /usr/share/doc/dotnet-sdk-10.0/copyright\n')
        state = dict(schemaVersion=1, scope='official-deb-coexistence', variant='debian-13', architecture='aarch64',
            testUser=account, provider='microsoft', source=dict(repository='https://packages.microsoft.com/debian/13/prod',
                keyring=str(keyring), signingFingerprint=APT.MICROSOFT_FINGERPRINT, keyringSha256=APT.digest(keyring),
                profileFiles=[dict(path=str(profile), sha256=APT.digest(profile))]), **snapshot)
        path = self.root / 'state.json'; path.write_bytes(APT.encoded(state))
        policy = dict(APT.POLICIES['debian-13'], keyring=str(keyring))
        return path, state, snapshot, account, policy, profile

    def test_stable_dpkg_exclusions_are_retained_but_any_package_or_host_change_fails(self):
        path, state, snapshot, account, policy, profile = self.fixture_state()
        with mock.patch.object(APT, 'guard', return_value=(policy, account)), \
             mock.patch.object(APT, 'MICROSOFT_SOURCE', str(profile)), \
             mock.patch.object(APT, 'capture', return_value=snapshot):
            summary = APT.assert_unchanged(path)
        self.assertEqual('passed', summary['status'])
        self.assertNotIn('dpkgVerificationOutput', summary)
        for field in ('sdkVersion', 'command', 'packages', 'packageInventorySha256', 'rootInventory', 'dpkgVerificationOutput'):
            changed = copy.deepcopy(snapshot)
            changed[field] = 'changed'
            with self.subTest(field=field), mock.patch.object(APT, 'guard', return_value=(policy, account)), \
                 mock.patch.object(APT, 'capture', return_value=changed):
                with self.assertRaisesRegex(ValueError, 'verification changed'):
                    APT.assert_unchanged(path)

    def test_repository_keyring_change_fails_even_when_official_sdk_bytes_match(self):
        path, state, snapshot, account, policy, profile = self.fixture_state()
        Path(policy['keyring']).write_bytes(b'appended-key')
        with mock.patch.object(APT, 'guard', return_value=(policy, account)), \
             mock.patch.object(APT, 'MICROSOFT_SOURCE', str(profile)), \
             mock.patch.object(APT, 'capture', return_value=snapshot):
            with self.assertRaisesRegex(ValueError, 'trust or source configuration changed'):
                APT.assert_unchanged(path)

    def test_package_owner_does_not_accept_missing_or_ambiguous_dpkg_ownership(self):
        for listing in ('', 'diversion by another-package: /usr/bin/dotnet\ndotnet-host: /usr/bin/dotnet\n',
                        'dotnet-host: /another/path\n'):
            with self.subTest(listing=listing), mock.patch.object(APT, 'run', return_value=listing):
                with self.assertRaisesRegex(ValueError, 'package ownership'):
                    APT.package_owner('/usr/bin/dotnet')


if __name__ == '__main__':
    unittest.main()
