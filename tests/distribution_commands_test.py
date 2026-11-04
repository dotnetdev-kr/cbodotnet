"""Exercise default SDK choice and the complete container command surface."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_commands as COMMANDS


@unittest.skipUnless(os.name == 'posix', 'Executable POSIX shell command tests require Linux')
class DistributionCommandsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.prefix = Path(self.temporary.name)
        self.official = self.prefix / 'official'
        self.official.mkdir()
        self.write_host(self.official / 'dotnet', 'official')
        self.environment = dict(os.environ, PATH=str(self.official) + os.pathsep + os.environ.get('PATH', ''),
                                DOTNET_ROOT=str(self.official), DOTNET_ROOT_X64=str(self.official),
                                DOTNET_ROOT_ARM64=str(self.official))

    @staticmethod
    def write_host(path, result):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!/bin/sh\nprintf "%s\\n" "' + result + '"\nprintf "<%s>\\n" "$@"\n')
        path.chmod(0o755)

    @staticmethod
    def plan(version):
        series = '.'.join(version.split('.')[:2])
        return {'sdkVersion': version, 'architecture': {'public': 'x64'},
                'sourceReleaseTag': 'sdk-' + version, 'sourceManifestSha256': 'a' * 64, 'packageRevision': 1,
                'package': {'name': 'cbodotnet-sdk-' + series, 'root': '/opt/cbodotnet/' + series,
                            'launcher': '/usr/bin/cbodotnet-' + series}}

    def install(self, version='10.0.403', mode='package'):
        plan = self.plan(version)
        self.write_host(self.prefix / plan['package']['root'].lstrip('/') / 'dotnet', version)
        return COMMANDS.stage_commands(self.prefix, plan, mode=mode, runtime_prefix=str(self.prefix))

    def run_command(self, command, *arguments):
        return subprocess.run([str(command), *arguments], env=self.environment, text=True, capture_output=True)

    def test_package_adds_default_and_versioned_commands_without_system_dotnet(self):
        inventory = self.install()
        self.assertEqual({'/usr/bin/cbodotnet', '/usr/bin/cbodotnet-10.0'}, {row['path'] for row in inventory})
        self.assertEqual('cbodotnet-host', next(row['owner'] for row in inventory if row['path'] == '/usr/bin/cbodotnet'))
        self.assertFalse((self.prefix / 'usr/bin/dotnet').exists())
        self.assertFalse((self.prefix / 'usr/local/bin/dotnet').exists())
        for name in ('cbodotnet-10.0', 'cbodotnet'):
            result = self.run_command(self.prefix / 'usr/bin' / name, 'build', 'a b')
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('10.0.403\n<build>\n<a b>\n', result.stdout)

    def test_default_selection_is_numeric_and_removal_falls_back(self):
        for version in ('9.0.123', '10.0.403', '10.2.100', '10.10.100'):
            self.install(version)
        command = self.prefix / 'usr/bin/cbodotnet'
        self.assertEqual('10.10.100\n<probe>\n', self.run_command(command, 'probe').stdout)
        shutil.rmtree(self.prefix / 'opt/cbodotnet/10.10')
        (self.prefix / 'usr/bin/cbodotnet-10.10').unlink()
        self.assertEqual('10.2.100\n<probe>\n', self.run_command(command, 'probe').stdout)
        self.assertEqual('9.0.123\n<probe>\n', self.run_command(self.prefix / 'usr/bin/cbodotnet-9.0', 'probe').stdout)

    def test_malformed_roots_and_missing_or_linked_hosts_never_select_official_dotnet(self):
        self.install()
        for series in ('99.0', '100.0', '001.0', '11.0.0', '999999999999999999.0', '11.x'):
            root = self.prefix / 'opt/cbodotnet' / series
            root.mkdir()
            self.write_host(self.prefix / 'usr/bin' / ('cbodotnet-' + series), series)
        (self.prefix / 'opt/cbodotnet/99.0/dotnet').symlink_to(self.official / 'dotnet')
        command = self.prefix / 'usr/bin/cbodotnet'
        self.assertEqual('10.0.403\n<probe>\n', self.run_command(command, 'probe').stdout)
        shutil.rmtree(self.prefix / 'opt/cbodotnet/10.0')
        result = self.run_command(command)
        self.assertEqual(127, result.returncode)
        self.assertEqual('', result.stdout)
        self.assertIn('no usable cbodotnet SDK', result.stderr)

    def test_all_container_commands_pin_the_same_sdk_even_with_another_root(self):
        inventory = self.install(mode='oci')
        self.write_host(self.prefix / 'opt/cbodotnet/99.0/dotnet', 'wrong-sdk')
        self.write_host(self.prefix / 'usr/bin/cbodotnet-99.0', 'wrong-sdk')
        self.assertEqual(5, len(inventory))
        for relative in ('usr/bin/cbodotnet-10.0', 'usr/bin/cbodotnet',
                         'usr/local/bin/cbodotnet-10.0', 'usr/local/bin/cbodotnet', 'usr/local/bin/dotnet'):
            result = self.run_command(self.prefix / relative, '--version')
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('10.0.403\n<--version>\n', result.stdout)

    def test_missing_container_host_fails_for_every_command_without_official_fallback(self):
        self.install(mode='oci')
        (self.prefix / 'opt/cbodotnet/10.0/dotnet').unlink()
        for name in ('cbodotnet-10.0', 'cbodotnet', 'dotnet'):
            result = self.run_command(self.prefix / 'usr/local/bin' / name, '--version')
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('official', result.stdout)

    def test_matching_retry_reuses_commands_and_conflict_fails_before_any_write(self):
        plan = self.plan('10.0.403')
        first = self.install()
        second = COMMANDS.stage_commands(self.prefix, plan, runtime_prefix=str(self.prefix))
        self.assertEqual(first, second)
        for row in first:
            path = self.prefix / row['path'].lstrip('/')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row['sha256'])
        default = self.prefix / 'usr/bin/cbodotnet'
        default.write_text('conflict')
        versioned = self.prefix / 'usr/bin/cbodotnet-10.0'
        versioned.unlink()
        with self.assertRaisesRegex(ValueError, 'conflicting command'):
            COMMANDS.stage_commands(self.prefix, plan, runtime_prefix=str(self.prefix))
        self.assertFalse(versioned.exists())
        self.assertEqual('conflict', default.read_text())

    def test_namespace_and_staging_symlinks_are_rejected(self):
        plan = self.plan('10.0.403')
        plan['package']['launcher'] = '/usr/bin/dotnet'
        with self.assertRaisesRegex(ValueError, 'namespace collision'):
            COMMANDS.stage_commands(self.prefix, plan)
        plan = self.plan('10.0.403')
        (self.prefix / 'usr').symlink_to(self.official)
        with self.assertRaisesRegex(ValueError, 'contains a link'):
            COMMANDS.stage_commands(self.prefix, plan)
        self.assertEqual(['dotnet'], [path.name for path in self.official.iterdir()])

    def test_production_staging_uses_installed_paths_not_the_staging_prefix(self):
        inventory = COMMANDS.stage_commands(self.prefix, self.plan('10.0.403'), mode='oci')
        self.assertEqual(5, len(inventory))
        self.assertIn('DOTNET_ROOT=/opt/cbodotnet/10.0', (self.prefix / 'usr/bin/cbodotnet-10.0').read_text())
        self.assertIn('exec /usr/bin/cbodotnet-10.0', (self.prefix / 'usr/local/bin/dotnet').read_text())
        self.assertNotIn(str(self.prefix), (self.prefix / 'usr/bin/cbodotnet-10.0').read_text())

    def test_template_tokens_and_shell_characters_in_prefix_remain_literal(self):
        prefix = self.prefix / "literal @BIN_DIR@ ' $(printf expanded)"
        prefix.mkdir()
        self.write_host(prefix / 'opt/cbodotnet/10.0/dotnet', '10.0.403')
        COMMANDS.stage_commands(prefix, self.plan('10.0.403'), runtime_prefix=str(prefix))
        result = self.run_command(prefix / 'usr/bin/cbodotnet', 'probe')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('10.0.403\n<probe>\n', result.stdout)


if __name__ == '__main__':
    unittest.main()
