import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rpm_official as OFFICIAL


class OfficialRpmTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = copy.deepcopy(OFFICIAL.POLICIES['fedora-45'])
        self.key = self.root / 'fedora-primary.asc'
        self.key.write_text('fixture-public-key')
        self.policy['key'] = str(self.key)
        self.profile = self.root / 'fedora.repo'
        self.write_profile()

    def write_profile(self, origin='https://mirrors.fedoraproject.org/metalink?repo=fedora-45', gpgcheck='1', key=None):
        self.profile.write_text(''.join('[' + name + ']\nmetalink=' + origin + '\ngpgcheck=' + gpgcheck
            + '\ngpgkey=file://' + str(key or self.key) + '\n' for name in ('fedora', 'updates')))

    def repository(self, fingerprint=None):
        fingerprint = fingerprint or self.policy['fingerprint']
        with mock.patch.object(OFFICIAL, 'POLICIES', {'fedora-45': self.policy}):
            with mock.patch.object(OFFICIAL, 'REPOSITORY_DIRECTORIES', (str(self.root),)):
                with mock.patch.object(OFFICIAL, 'run', return_value='pub:::::::::\nfpr:::::::::' + fingerprint + ':\n'):
                    return OFFICIAL.repository_policy('fedora-45', 'x64')

    def test_only_stock_repository_origins_and_reviewed_primary_key_are_admitted(self):
        proof = self.repository()
        self.assertEqual({'fedora', 'updates'}, set(proof['repositories']))
        self.assertEqual(self.policy['fingerprint'], proof['signingFingerprint'])
        self.assertEqual(OFFICIAL.digest(self.key), proof['keySha256'])
        self.assertFalse(proof['repositories']['fedora']['repositoryMetadataSignaturesRequired'])

    def test_disabled_signatures_foreign_origins_and_other_keys_are_rejected(self):
        for kwargs in ({'gpgcheck': '0'}, {'origin': 'https://example.com/fedora'}, {'key': self.root / 'other.asc'}):
            self.write_profile(**kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.repository()
        self.write_profile()
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            self.repository('A' * 40)

    def test_duplicate_stock_repository_id_is_rejected(self):
        (self.root / 'injected.repo').write_bytes(self.profile.read_bytes())
        with self.assertRaisesRegex(ValueError, 'more than once'):
            self.repository()

    def test_installation_disables_every_other_repository_and_keeps_signatures_enabled(self):
        state = self.root / 'state.json'
        policy = copy.deepcopy(self.policy)
        account = dict(name='cbot-smoke', uid=10001, gid=10001, home='/home/cbot-smoke')
        current = dict(officialRoot='/usr/lib64/dotnet', sdkVersion='10.0.114', packages=[])
        with mock.patch.object(OFFICIAL, 'guard', return_value=(policy, account)), mock.patch.object(OFFICIAL.os.path, 'lexists', return_value=False):
            with mock.patch.object(OFFICIAL, 'repository_policy', return_value={'trusted': True}), mock.patch.object(OFFICIAL, 'capture', return_value=current):
                with mock.patch.object(OFFICIAL, 'cached_signature_proofs', return_value=[]), mock.patch.object(OFFICIAL, 'run', return_value='') as execute:
                    OFFICIAL.bootstrap('fedora-45', 'x64', 'cbot-smoke', state)
        command = execute.call_args.args[0]
        self.assertIn('--setopt=gpgcheck=1', command)
        self.assertIn('--setopt=keepcache=True', command)
        self.assertTrue(any(value in command for value in ('--disable-repo=*', '--disablerepo=*')))
        self.assertTrue(any(value.endswith('=fedora') for value in command))
        self.assertTrue(any(value.endswith('=updates') for value in command))
        self.assertNotIn('--nogpgcheck', command)

    def test_lifecycle_snapshot_rejects_root_owner_link_version_or_package_changes(self):
        state_path = self.root / 'state.json'
        account = dict(name='cbot-smoke', uid=10001, gid=10001, home='/home/cbot-smoke')
        current = dict(officialRoot='/usr/lib64/dotnet', sdkVersion='10.0.114', command={'owner': 'dotnet-host'},
                       packages=[{'name': OFFICIAL.SDK_PACKAGE}], rootInventory={'sha256': 'a' * 64})
        state = dict(schemaVersion=1, scope='official-rpm-coexistence', variant='fedora-45', architecture='x64',
                     testUser=account, source={'trusted': True}, **current)
        for field in current:
            state_path.write_text(json.dumps(state))
            changed = dict(current, **{field: 'different'})
            with self.subTest(field=field), mock.patch.object(OFFICIAL, 'guard', return_value=(self.policy, account)):
                with mock.patch.object(OFFICIAL, 'repository_policy', return_value=state['source']), mock.patch.object(OFFICIAL, 'capture', return_value=changed):
                    with self.assertRaisesRegex(ValueError, 'owner, command, version, files or package inventory'):
                        OFFICIAL.assert_unchanged(state_path)

    def test_unsupported_target_and_non_container_execution_fail_before_installation(self):
        for variant, arch in [('fedora-44', 'x64'), ('rocky-9.8', 'arm64')]:
            with self.subTest(variant=variant, arch=arch), self.assertRaisesRegex(ValueError, 'Unsupported'):
                OFFICIAL.guard(variant, arch, 'cbot-smoke')
        with mock.patch.object(OFFICIAL.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'disposable root Docker'):
                OFFICIAL.guard('fedora-45', 'x64', 'cbot-smoke')


if __name__ == '__main__':
    unittest.main()
