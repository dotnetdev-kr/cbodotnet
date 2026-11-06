from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cbodotnetup_release as UP
import cbodotnetup_project as PROJECT


class PreviousSchema2UpgradeTests(unittest.TestCase):
    def test_candidate_old_tool_bootstrap_must_download_public_bytes(self):
        args = SimpleNamespace(bundle=Path('/bundle'), arch='x64', public=False)
        calls = []
        def execute(root, command):
            calls.append(list(map(str, command)))
            return SimpleNamespace(stdout='0.2.0\n')
        with patch.object(UP, 'matrix_user', side_effect=execute):
            UP.matrix_bootstrap(args, Path('/owned'), Path('/bin/cbodotnetup'),
                                Path('/bundle/catalog-v2-tool-0.2.json'), published_binary=True, expected_version='0.2.0')
        self.assertNotIn('--binary-file', calls[0])
        self.assertIn('/bundle/catalog-v2-tool-0.2.json', calls[0])
        self.assertEqual(calls[1], ['/bin/cbodotnetup', '--version'])

    def test_candidate_current_tool_uses_only_the_frozen_binary(self):
        args = SimpleNamespace(bundle=Path('/bundle'), arch='aarch64', public=False)
        with patch.object(UP, 'matrix_user', return_value=SimpleNamespace(stdout='0.3.0\n')) as execute, \
                patch.object(UP, 'load', return_value=dict(version='0.3.0')):
            UP.matrix_bootstrap(args, Path('/owned'), Path('/bin/cbodotnetup'), Path('/bundle/catalog.json'))
        command = list(map(str, execute.call_args_list[0].args[1]))
        self.assertEqual(command[-2:], ['--binary-file', '/bundle/tools/linux-arm64/cbodotnetup-linux-arm64'])

    def exercise(self, public, *, changed_state=False, broken_rollback=False, wrong_sdk=False):
        args = SimpleNamespace(bundle=Path('/bundle'), arch='x64', public=public)
        root, binary = Path('/owned'), Path('/bin/cbodotnetup')
        baseline = dict(sdkVersion='10.0.403', revision=3, rid='linux-x64')
        state = dict(version='0.2.0', upgraded=False, rolledBack=False)
        bootstraps, events = [], []
        old_sha, new_sha, previous_sha, current_sha = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64
        def bootstrap(*values, **options):
            bootstraps.append((values, options))
            state['version'] = options.get('expected_version', '0.3.0')
            if state['version'] == '0.3.0': state['upgraded'] = True
        def execute(actual_root, command):
            command = list(map(str, command)); events.append(command)
            if command[-2:] == ['self', 'update']:
                state.update(version='0.3.0', upgraded=True)
            elif command[-2:] == ['self', 'rollback']:
                state.update(version='0.2.0', rolledBack=True)
            if command[-1] == '--version':
                if 'run' in command:
                    return SimpleNamespace(stdout=('9.0.123' if wrong_sdk else baseline['sdkVersion'])+'\n', stderr=UP.MULTI.BRAND+'\n')
                return SimpleNamespace(stdout=state['version']+'\n', stderr='')
            return SimpleNamespace(stdout='', stderr='')
        def describe(path):
            path = Path(path)
            if path == binary:
                sha = old_sha if state['version'] == '0.2.0' else new_sha
                if broken_rollback and state['rolledBack']: sha = 'f' * 64
            elif str(path).endswith('.previous'): sha = old_sha
            elif path.name == 'catalog-v2-tool-0.2.json': sha = previous_sha
            elif path.name == 'catalog.json': sha = previous_sha if 'toolchains-v2' in path.parts else current_sha
            else: sha = 'e' * 64
            return dict(sha256=sha, name=path.name, size=123)
        def load(path):
            if Path(path) == UP.POLICY: return dict(version='0.3.0')
            return dict(tools=[dict(version='0.2.0', rid=baseline['rid'], binary=dict(sha256=old_sha))])
        def owned(actual_root):
            return {'receipt': 'changed' if changed_state and state['upgraded'] else 'unchanged'}
        with patch.object(UP, 'matrix_bootstrap', side_effect=bootstrap), \
                patch.object(UP, 'matrix_user', side_effect=execute), \
                patch.object(UP, 'descriptor', side_effect=describe), \
                patch.object(UP, 'load', side_effect=load), \
                patch.object(PROJECT, 'owned_sdk_state', side_effect=owned):
            result = UP.matrix_previous_tool_upgrade(args, root, binary, baseline)
        return result, bootstraps, events

    def test_public_migration_runs_actual_self_update_rollback_sdk_and_reupgrade(self):
        result, bootstraps, events = self.exercise(True)
        self.assertEqual(len(bootstraps), 1)
        self.assertEqual(bootstraps[0][1], dict(published_binary=True, expected_version='0.2.0'))
        operations = [command[-2:] for command in events if 'self' in command]
        self.assertEqual(operations, [['self', 'update'], ['self', 'rollback'], ['self', 'update']])
        self.assertTrue(any('run' in command and '10.0.403-r3' in command for command in events))
        self.assertEqual(result['protocol'], 'actual-0.2.0-self-update-rollback-reupgrade')
        self.assertTrue(result['rollbackVerified']); self.assertTrue(result['baselineOwnedStateUnchanged'])
        self.assertEqual(result['oldBinarySha256'], 'a' * 64); self.assertEqual(result['currentBinarySha256'], 'b' * 64)

    def test_candidate_migration_uses_public_old_then_frozen_current_without_claiming_rollback(self):
        result, bootstraps, events = self.exercise(False)
        self.assertEqual(len(bootstraps), 2)
        self.assertEqual(bootstraps[0][1], dict(published_binary=True, expected_version='0.2.0'))
        self.assertEqual(bootstraps[1][1], {})
        self.assertFalse(any('self' in command for command in events))
        self.assertEqual(result['protocol'], 'protected-frozen-candidate-bootstrap-from-0.2.0')
        self.assertFalse(result['rollbackVerified'])

    def test_tool_upgrade_cannot_change_the_retained_sdk_state(self):
        for public in (True, False):
            with self.subTest(public=public), self.assertRaisesRegex(ValueError, 'changed retained SDK'):
                self.exercise(public, changed_state=True)

    def test_wrong_rollback_binary_or_sdk_cannot_be_reported_as_recovered(self):
        with self.assertRaisesRegex(ValueError, 'restore public 0.2.0 bytes'):
            self.exercise(True, broken_rollback=True)
        with self.assertRaisesRegex(ValueError, 'retained SDK'):
            self.exercise(True, wrong_sdk=True)


if __name__ == '__main__':
    unittest.main()
