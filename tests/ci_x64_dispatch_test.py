#!/usr/bin/env python3
"""Exercise trusted architecture dispatch with real source and transport bundles.

Family gates are isolated at their subprocess boundary. These fixtures prove
common extraction, source verification and dispatch, never SDK qualification.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import ci_delivery_test as transport_fixtures
import source_delivery_test as source_fixtures

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('x64_common_dispatch', ROOT / 'scripts/ci-sdk.py')
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)
DELIVERY = transport_fixtures.D


class NativeDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-x64-dispatch.')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0
        self.executed_download = self.root / 'downloaded-code-was-executed'

    def describe(self, target, arch=None):
        self.serial += 1
        output = self.root / ('selection-' + str(self.serial))
        command = ['ci-sdk.py', 'describe', '--target', target]
        if arch is not None:
            command += ['--arch', arch]
        captured = io.StringIO()
        with mock.patch.object(sys, 'argv', command), mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), contextlib.redirect_stdout(captured):
            SDK.main()
        selected = json.loads(captured.getvalue())
        exported = dict(line.split('=', 1) for line in output.read_text().splitlines())
        self.assertEqual(exported, selected)
        profile = json.loads((ROOT / 'profiles' / ('dotnet-' + selected['sdk_version'] + '-' + selected['target_rid'] + '.json')).read_text())
        self.assertEqual(profile['sdkVersion'], selected['sdk_version'])
        self.assertEqual(profile['target']['rid'], selected['target_rid'])
        self.assertEqual(profile['host']['architecture'], selected['architecture'])
        self.assertTrue((ROOT / selected['driver']).is_file())
        return selected

    def source(self, sdk, arch):
        fixture = source_fixtures.SourceDeliveryTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        # Deliberately executable Python evidence catches a future regression
        # that runs code from the delivery instead of the trusted checkout.
        poison = 'from pathlib import Path\nPath(' + repr(str(self.executed_download)) + ').write_text("unsafe")\nraise RuntimeError("Downloaded source executed")\n'
        project_script = fixture.project / 'scripts/ci-sdk.py'
        project_script.parent.mkdir()
        project_script.write_text(poison)
        fixture.command(fixture.project, 'add', '.')
        fixture.command(fixture.project, 'commit', '-qm', 'Nonexecuted source fixture')
        fixture.args.project_commit = fixture.head(fixture.project)
        fixture.args.sdk_version = sdk
        fixture.args.target_rid = 'linux-' + arch
        fixture.capture()
        frozen_script = fixture.release / 'reports/ci-inputs/project/scripts/ci-sdk.py'
        frozen_script.parent.mkdir(parents=True)
        frozen_script.write_text(poison)
        (fixture.release / ('cbodotnet-sdk-' + sdk + '-linux-' + arch + '-build.123.tar.gz')).write_bytes(b'Synthetic SDK boundary fixture, not a product archive.\n')
        return fixture

    def bundle(self, fixture, target, sdk, transport_arch, root_arch=None):
        self.serial += 1
        directory = self.root / ('transport-' + str(self.serial))
        directory.mkdir()
        name = 'cbodotnet-' + target + '-linux-' + transport_arch + '-123-1.tar.gz'
        path = directory / name
        root_name = sdk + '-linux-' + (root_arch or transport_arch)
        with tarfile.open(path, 'w:gz') as archive:
            for source in sorted(fixture.release.rglob('*')):
                if source.is_file():
                    archive.add(source, arcname=root_name + '/' + source.relative_to(fixture.release).as_posix(), recursive=False)
        for algorithm in ('sha256', 'sha512'):
            digest = hashlib.new(algorithm, path.read_bytes()).hexdigest()
            (directory / (name + '.' + algorithm)).write_text(digest + '  ' + name + '\n')
        command = ['ci-delivery.py', '--download-dir', str(directory), '--destination', str(self.root / ('verified-' + str(self.serial))),
                   '--target', target, '--sdk-version', sdk, '--expected-project-commit', fixture.args.project_commit,
                   '--expected-run-id', '123', '--expected-run-attempt', '1']
        if transport_arch != 'arm64':
            command += ['--arch', transport_arch]
        return command

    def verify_common(self, command, target):
        real_run = subprocess.run
        calls = []
        family = []
        trusted_sdk = str(ROOT / 'scripts/ci-sdk.py')
        trusted_source = str(ROOT / 'scripts/package-used-source.py')
        expected_family = str(ROOT / ('scripts/ci-net10-evidence.py' if target == 'net10' else 'scripts/' + SDK.PROFILES[target][1]))

        def dispatch(arguments, **kwargs):
            calls.append(list(arguments))
            self.assertIs(kwargs.get('check'), True)
            executable = str(arguments[1])
            if executable == trusted_sdk:
                self.assertEqual(arguments[0], sys.executable)
                with mock.patch.object(sys, 'argv', list(arguments[1:])):
                    SDK.main()
                return subprocess.CompletedProcess(arguments, 0)
            if executable == trusted_source:
                self.assertEqual(arguments[0], sys.executable)
                return real_run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if executable == expected_family:
                family.append(list(arguments))
                self.assertIn(arguments[0], ('bash', sys.executable))
                return subprocess.CompletedProcess(arguments, 0)
            self.fail('A downloaded or unexpected verifier was selected: ' + executable)

        with mock.patch.object(sys, 'argv', command), mock.patch.object(subprocess, 'run', side_effect=dispatch), contextlib.redirect_stdout(io.StringIO()):
            DELIVERY.main()
        self.assertFalse(self.executed_download.exists())
        self.assertEqual(len(family), 1)
        self.assertEqual(sum(call[1] == trusted_source for call in calls), 1)
        self.assertIn('verify-release', family[0])
        self.assertIn(command[command.index('--expected-project-commit') + 1], family[0])
        return calls, family[0]

    def test_all_x64_selections_reach_trusted_source_and_matching_family_gates(self):
        for target in SDK.PROFILES:
            with self.subTest(target=target):
                selected = self.describe(target, 'x64')
                fixture = self.source(selected['sdk_version'], 'x64')
                command = self.bundle(fixture, target, selected['sdk_version'], 'x64')
                calls, family = self.verify_common(command, target)
                self.assertEqual(family[family.index('--arch') + 1], 'x64')
                source = next(call for call in calls if call[1] == str(ROOT / 'scripts/package-used-source.py'))
                self.assertEqual(source[source.index('--expected-target-rid') + 1], selected['target_rid'])

    def test_default_arm64_delivery_keeps_legacy_dispatch(self):
        selected = self.describe('net7')
        fixture = self.source(selected['sdk_version'], 'arm64')
        command = self.bundle(fixture, 'net7', selected['sdk_version'], 'arm64')
        _, family = self.verify_common(command, 'net7')
        self.assertNotIn('--arch', family)

    def test_x64_rejects_arm_root_and_relabelled_arm_sources_for_the_same_sdk_run(self):
        fixture = self.source('7.0.120', 'arm64')
        wrong_root = self.bundle(fixture, 'net7', '7.0.120', 'x64', root_arch='arm64')
        with self.assertRaisesRegex(ValueError, 'Unsafe'), mock.patch.object(subprocess, 'run') as verifier:
            with mock.patch.object(sys, 'argv', wrong_root):
                DELIVERY.main()
        verifier.assert_not_called()
        relabelled = self.bundle(fixture, 'net7', '7.0.120', 'x64')
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.verify_common(relabelled, 'net7')
        self.assertIn('Source delivery target RID differs', error.exception.stderr)
        self.assertFalse(self.executed_download.exists())

    def test_image_alias_cannot_select_a_native_cli_architecture(self):
        with mock.patch.object(sys, 'argv', ['ci-sdk.py', 'describe', '--target', 'net10', '--arch', 'amd64']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                SDK.main()
        self.assertEqual(error.exception.code, 2)

    def test_default_arm64_rejects_relabelled_x64_sources_for_the_same_sdk_run(self):
        fixture = self.source('7.0.120', 'x64')
        relabelled = self.bundle(fixture, 'net7', '7.0.120', 'arm64')
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.verify_common(relabelled, 'net7')
        self.assertIn('Source delivery target RID differs', error.exception.stderr)
        self.assertFalse(self.executed_download.exists())


if __name__ == '__main__':
    unittest.main()
