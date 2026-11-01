"""Keep public AArch64 aliases compatible with official and archived identities."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('public_arch_names', ROOT / 'scripts/ci_arch.py')
ARCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCH)


class PublicArchitectureTests(unittest.TestCase):
    def test_alias_keeps_every_official_identity(self):
        self.assertEqual(ARCH.get_arch('aarch64'), ARCH.get_arch('arm64'))
        self.assertEqual(ARCH.get_arch('aarch64')['rid'], 'linux-arm64')
        self.assertEqual(ARCH.get_arch('aarch64')['image'], 'arm64')
        self.assertEqual(ARCH.public_arch('arm64'), 'aarch64')
        self.assertEqual(ARCH.public_arch('x64'), 'x64')
        changed = ARCH.get_arch('aarch64'); changed['machine'] = 62
        self.assertEqual(ARCH.get_arch('aarch64')['machine'], 183)
        with self.assertRaises(ValueError):
            ARCH.get_arch('aarch65')

    def test_project_paths_preserve_historical_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('profiles', 'containers'):
                (root / directory).mkdir()
            current = root / 'profiles/dotnet-10.0.403-linux-aarch64.json'
            legacy = root / 'profiles/dotnet-10.0.403-linux-arm64.json'
            self.assertEqual(ARCH.profile_path(root, '10.0.403', 'aarch64'), current)
            legacy.write_text('historical')
            self.assertEqual(ARCH.profile_path(root, '10.0.403', 'aarch64'), legacy)
            current.write_text('current')
            self.assertEqual(ARCH.profile_path(root, '10.0.403', 'arm64'), current)
            old_recipe = root / 'containers/arm64-net10.Containerfile'
            new_recipe = root / 'containers/aarch64-net10.Containerfile'
            old_recipe.write_text('historical')
            self.assertEqual(ARCH.container_path(root, 'net10', 'aarch64'), old_recipe)
            new_recipe.write_text('current')
            self.assertEqual(ARCH.container_path(root, 'net10', 'arm64'), new_recipe)

    def test_all_pinned_public_files_exist_with_matching_rids(self):
        import json
        for version, target in [('10.0.403', 'net10'), ('9.0.123', 'net9'), ('8.0.133', 'net8'),
                                ('7.0.120', 'net7'), ('6.0.136', 'net6'), ('5.0.214', 'net5'),
                                ('3.1.426', 'core31'), ('3.0.103', 'core30')]:
            with self.subTest(version=version):
                path = ARCH.profile_path(ROOT, version, 'aarch64')
                self.assertIn('aarch64', path.name)
                profile = json.loads(path.read_text())
                self.assertEqual(profile['host']['architecture'], 'arm64')
                self.assertEqual(profile['target']['rid'], 'linux-arm64')
                self.assertTrue(ARCH.container_path(ROOT, target, 'aarch64').is_file())

    def test_public_sdk_selector_normalizes_the_cli_alias(self):
        import json
        output = subprocess.check_output([sys.executable, str(ROOT / 'scripts/ci-sdk.py'),
                                          'describe', '--target', 'net10', '--arch', 'aarch64'])
        selected = json.loads(output)
        self.assertEqual(selected['target_rid'], 'linux-arm64')
        self.assertEqual(selected['architecture'], 'aarch64')


if __name__ == '__main__':
    unittest.main()
