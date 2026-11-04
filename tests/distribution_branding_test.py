"""Keep distribution branding visible without changing SDK or application output."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_contract as CONTRACT

BRAND = 'Community Build of .NET (built by .NET Dev)'


@unittest.skipUnless(os.name == 'posix', 'Executable POSIX launchers require Linux')
class DistributionBrandingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.sdk = self.directory / 'sdk'
        self.invocations = self.directory / 'host-invocations'
        self.official = self.directory / 'official'
        self.official.mkdir()
        (self.official / 'dotnet').write_text('#!/bin/sh\nprintf "official-fallback\\n"\n')
        (self.official / 'dotnet').chmod(0o755)
        self.environment = dict(os.environ,
                                PATH=str(self.official) + os.pathsep + os.environ.get('PATH', ''),
                                DOTNET_ROOT=str(self.official), DOTNET_ROOT_X64=str(self.official),
                                DOTNET_ROOT_ARM64=str(self.official), DOTNET_HOST_PATH=str(self.official / 'dotnet'))
        self.launcher = self.install(self.sdk)

    def install(self, sdk, arch='x64', plan=None):
        sdk.mkdir()
        host = sdk / 'dotnet'
        host.write_text(
            '#!/bin/sh\n'
            'printf "invoked\\n" >> ' + shlex.quote(str(self.invocations)) + '\n'
            'if [ "$#" -eq 0 ]; then printf "upstream usage\\n"; exit 0; fi\n'
            'case "$1" in\n'
            '  --version) printf "10.0.403\\n" ;;\n'
            '  --info) printf ".NET SDK:\\n Version: 10.0.403\\n Commit: original-commit\\n RID: linux-x64\\n" ;;\n'
            '  --help|-h|help) printf "upstream help\\n" ;;\n'
            '  environment) printf "%s\\n" "$DOTNET_ROOT" "$DOTNET_HOST_PATH" "${DOTNET_ROOT_X64-unset}" "${DOTNET_ROOT_ARM64-unset}" ;;\n'
            '  exit-code) printf "original error\\n" >&2; exit 37 ;;\n'
            '  *) printf "upstream stdout\\n"; printf "argument=<%s>\\n" "$@"; printf "upstream stderr\\n" >&2; exit 23 ;;\n'
            'esac\n', encoding='utf-8')
        host.chmod(0o755)
        launcher = sdk.parent / (sdk.name + '-launcher')
        launcher.write_text(CONTRACT.launcher_text(str(sdk), arch, plan=plan), encoding='utf-8')
        launcher.chmod(0o755)
        return launcher

    def run_launcher(self, *arguments, launcher=None):
        return subprocess.run([str(launcher or self.launcher), *arguments], cwd=self.directory,
                              env=self.environment, text=True, capture_output=True)

    def test_version_keeps_numeric_stdout_and_brands_stderr(self):
        result = self.run_launcher('--version')
        self.assertEqual(0, result.returncode)
        self.assertEqual('10.0.403\n', result.stdout)
        self.assertEqual(BRAND + '\n', result.stderr)

    def test_info_preserves_original_sdk_details_after_one_brand_header(self):
        result = self.run_launcher('--info')
        self.assertEqual(0, result.returncode)
        self.assertEqual(BRAND + '\n.NET SDK:\n Version: 10.0.403\n Commit: original-commit\n RID: linux-x64\n', result.stdout)
        self.assertEqual('', result.stderr)

    def test_top_level_help_and_no_arguments_have_one_brand_header(self):
        for arguments, upstream in (((), 'upstream usage\n'), (('--help',), 'upstream help\n'),
                                    (('-h',), 'upstream help\n'), (('help',), 'upstream help\n')):
            with self.subTest(arguments=arguments):
                result = self.run_launcher(*arguments)
                self.assertEqual(0, result.returncode)
                self.assertEqual(BRAND + '\n' + upstream, result.stdout)
                self.assertEqual('', result.stderr)

    def test_information_json_binds_exact_distribution_without_executing_host(self):
        result = self.run_launcher('--cbodotnet-info')
        self.assertEqual(0, result.returncode)
        self.assertEqual('', result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        identity = json.loads(result.stdout)
        contract = CONTRACT.load_contract()
        self.assertEqual(1, identity['schemaVersion'])
        self.assertEqual(contract['schemaVersion'], identity['contractVersion'])
        self.assertEqual(BRAND, identity['distributionBrand'])
        self.assertEqual('10.0.403', identity['sdkVersion'])
        self.assertEqual('sdk-10.0.403', identity['sourceReleaseTag'])
        self.assertEqual(contract['releases']['10.0.403']['manifestSha256'], identity['sourceManifestSha256'])
        self.assertEqual(str(self.sdk), identity['sdkRoot'])
        self.assertEqual('linux-x64', identity['targetRid'])
        self.assertEqual(1, identity['packageRevision'])
        self.assertEqual('distribution-wrapper', identity['brandingScope'])
        self.assertFalse(identity['qualifiedPayloadModified'])
        self.assertFalse(self.invocations.exists(), 'Provenance command executed SDK CLI code')

    def test_information_json_preserves_the_prepared_package_revision(self):
        contract = CONTRACT.load_contract()
        plan = dict(sdkVersion='10.0.403', sourceReleaseTag='sdk-10.0.403', packageRevision=3,
                    sourceManifestSha256=contract['releases']['10.0.403']['manifestSha256'])
        launcher = self.install(self.directory / 'revision-sdk', plan=plan)
        result = self.run_launcher('--cbodotnet-info', launcher=launcher)
        self.assertEqual(3, json.loads(result.stdout)['packageRevision'])
        self.assertFalse(self.invocations.exists())

    def test_ordinary_app_and_subcommand_arguments_keep_output_and_exit_status(self):
        for arguments in (('app.dll', '--version'), ('build', '--help'),
                          ('run', '--', '--cbodotnet-info'), ('app.dll', '--info'),
                          ('build', 'a b', 'literal$HOME', "it's-literal")):
            with self.subTest(arguments=arguments):
                result = self.run_launcher(*arguments)
                self.assertEqual(23, result.returncode)
                self.assertEqual('upstream stdout\n' + ''.join('argument=<' + value + '>\n' for value in arguments), result.stdout)
                self.assertEqual('upstream stderr\n', result.stderr)
                self.assertNotIn(BRAND, result.stdout + result.stderr)

    def test_original_error_status_and_stderr_are_preserved(self):
        result = self.run_launcher('exit-code')
        self.assertEqual(37, result.returncode)
        self.assertEqual('', result.stdout)
        self.assertEqual('original error\n', result.stderr)

    def test_explicit_host_and_architecture_environment_override_inherited_roots(self):
        result = self.run_launcher('environment')
        self.assertEqual(0, result.returncode)
        self.assertEqual([str(self.sdk), str(self.sdk / 'dotnet'), str(self.sdk), 'unset'], result.stdout.splitlines())
        arm = self.directory / 'arm-sdk'
        launcher = self.install(arm, arch='aarch64')
        result = self.run_launcher('environment', launcher=launcher)
        self.assertEqual([str(arm), str(arm / 'dotnet'), 'unset', str(arm)], result.stdout.splitlines())

    def test_missing_host_fails_before_branding_or_metadata_without_path_fallback(self):
        (self.sdk / 'dotnet').unlink()
        for arguments in (('--version',), ('--info',), ('--cbodotnet-info',), ('build',)):
            with self.subTest(arguments=arguments):
                result = self.run_launcher(*arguments)
                self.assertEqual(127, result.returncode)
                self.assertEqual('', result.stdout)
                self.assertIn('selected SDK host is missing', result.stderr)
                self.assertNotIn('official-fallback', result.stdout + result.stderr)
        self.assertFalse(self.invocations.exists())

    def test_non_executable_host_cannot_be_reported_as_a_usable_distribution(self):
        (self.sdk / 'dotnet').chmod(0o644)
        result = self.run_launcher('--cbodotnet-info')
        self.assertEqual(127, result.returncode)
        self.assertEqual('', result.stdout)
        self.assertFalse(self.invocations.exists())

    def assert_unusable_distribution(self):
        for arguments in (('--cbodotnet-info',), ('--version',), ('--info',), ('build',)):
            with self.subTest(arguments=arguments):
                result = self.run_launcher(*arguments)
                self.assertEqual(127, result.returncode)
                self.assertEqual('', result.stdout)
                self.assertIn('selected SDK host is missing', result.stderr)
                self.assertNotIn(BRAND, result.stdout + result.stderr)
                self.assertNotIn('official-fallback', result.stdout + result.stderr)
        self.assertFalse(self.invocations.exists())

    def test_executable_directory_cannot_advertise_distribution_identity(self):
        (self.sdk / 'dotnet').unlink()
        (self.sdk / 'dotnet').mkdir(mode=0o755)
        self.assert_unusable_distribution()

    def test_host_symlink_to_official_dotnet_cannot_advertise_distribution_identity(self):
        (self.sdk / 'dotnet').unlink()
        (self.sdk / 'dotnet').symlink_to(self.official / 'dotnet')
        self.assert_unusable_distribution()

    def test_sdk_root_symlink_cannot_advertise_distribution_identity(self):
        retained = self.directory / 'retained-sdk'
        self.sdk.rename(retained)
        self.sdk.symlink_to(self.official, target_is_directory=True)
        self.assert_unusable_distribution()

    def test_root_shell_metacharacters_are_literal_in_execution_and_json(self):
        for name in ('sdk with spaces', "sdk's-root", 'sdk $(touch PWNED)'):
            with self.subTest(name=name):
                sdk = self.directory / name
                launcher = self.install(sdk)
                result = self.run_launcher('environment', launcher=launcher)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(str(sdk), result.stdout.splitlines()[0])
                result = self.run_launcher('--cbodotnet-info', launcher=launcher)
                self.assertEqual(str(sdk), json.loads(result.stdout)['sdkRoot'])
                self.assertFalse((self.directory / 'PWNED').exists())

    def test_malformed_roots_and_unknown_architectures_are_rejected(self):
        for root in ('relative', '/', '/sdk/../system', '/sdk//nested', '/sdk/./nested',
                     '/sdk\\nested', '/sdk:stream', '/sdk\nline', '/sdk\rline', '/sdk\0nul'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                CONTRACT.launcher_text(root, 'x64')
        for arch in ('amd64', 'arm64', 'x86_64', 'any', ''):
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                CONTRACT.launcher_text(str(self.sdk), arch)


if __name__ == '__main__':
    unittest.main()
