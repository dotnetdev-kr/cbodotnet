"""Protect legacy producer routing and the pure publication validation boundary."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('tested_musl_expansion_dispatch', ROOT / 'scripts/musl-sdk-expand.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
import musl_contract as CONTRACT
legacy_spec = importlib.util.spec_from_file_location('tested_musl_legacy_dispatch', ROOT / 'scripts/musl-legacy-sdk.py')
LEGACY = importlib.util.module_from_spec(legacy_spec)
legacy_spec.loader.exec_module(LEGACY)


class ExpansionBoundary(unittest.TestCase):
    def test_every_expansion_route_has_a_separate_candidate_contract(self):
        self.assertEqual(set(CONTRACT.SOURCES) - {'10.0.403'}, set(M.ROUTES))
        for version in M.ROUTES:
            self.assertEqual(CONTRACT.EXPANSION_WORKFLOW, CONTRACT.producer_workflow(version))
        self.assertFalse(CONTRACT.load_contract()['publicationAllowed'])

    def test_unreviewed_versions_cannot_fall_back_to_a_repack_or_other_sdk(self):
        for version in ('5.0.214', '3.1.426', '10.0.403', '7.0.121', '6.0.137', None):
            arguments = ['run'] + (['--sdk-version', version] if version else [])
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'Unreviewed'):
                M.dispatch_identity(arguments)

    def test_receiver_uses_sealed_version_and_rejects_cli_identity_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            for version in ('7.0.120', '6.0.136'):
                (release / 'producer-validation.json').write_text(json.dumps({'sdkVersion': version}))
                self.assertEqual(('validate', version, release), M.dispatch_identity(['validate', '--release-dir', temporary]))
                for extra in (['--sdk-version', '9.0.123'], ['--expected-project-commit', 'a' * 40]):
                    with self.subTest(version=version, extra=extra), self.assertRaisesRegex(ValueError, 'only the sealed'):
                        M.dispatch_identity(['validate', '--release-dir', temporary] + extra)

    def test_nonobject_or_oversized_identity_is_rejected_before_routing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'producer-validation.json'
            path.write_text('[]')
            with self.assertRaisesRegex(ValueError, 'identity object'):
                M.dispatch_identity(['validate', '--release-dir', temporary])
            with path.open('wb') as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                M.dispatch_identity(['validate', '--release-dir', temporary])

    def test_publication_validation_imports_only_the_pure_legacy_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            for version, filename in [('7.0.120', 'musl_legacy_admission.py'), ('6.0.136', 'musl_legacy6_admission.py')]:
                (release / 'producer-validation.json').write_text(json.dumps({'sdkVersion': version}))
                record = dict(status='passed', sdkVersion=version, architecture='aarch64',
                              projectCommit='a' * 40, runId='123', runAttempt='1')
                gate = mock.Mock(return_value=record)
                with self.subTest(version=version), \
                        mock.patch.object(sys, 'argv', ['musl-sdk-expand.py', 'validate', '--release-dir', temporary]), \
                        mock.patch.object(M, 'module', return_value=SimpleNamespace(validate=gate)) as imported, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    M.main()
                imported.assert_called_once_with(filename)
                gate.assert_called_once_with(release)
                self.assertEqual(record, json.loads(output.getvalue()))

    def test_sdk6_validation_rejects_failed_or_wrong_version_gate_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            (release / 'producer-validation.json').write_text(json.dumps({'sdkVersion': '6.0.136'}))
            for record in (dict(status='failed', sdkVersion='6.0.136'), dict(status='passed', sdkVersion='7.0.120')):
                gate = mock.Mock(return_value=record)
                with self.subTest(record=record), \
                        mock.patch.object(sys, 'argv', ['musl-sdk-expand.py', 'validate', '--release-dir', temporary]), \
                        mock.patch.object(M, 'module', return_value=SimpleNamespace(validate=gate)) as imported, \
                        self.assertRaisesRegex(ValueError, 'Independent legacy producer validation'):
                    M.main()
                imported.assert_called_once_with('musl_legacy6_admission.py')

    def test_run_dispatch_preserves_modern_and_legacy_cli_routes(self):
        for version, filename in [('9.0.123', 'musl-modern-sdk.py'), ('8.0.133', 'musl-modern-sdk.py'),
                                  ('7.0.120', 'musl-legacy-sdk.py'), ('6.0.136', 'musl-legacy-sdk.py')]:
            entry = mock.Mock()
            with self.subTest(version=version), \
                    mock.patch.object(sys, 'argv', ['musl-sdk-expand.py', 'run', '--sdk-version', version]), \
                    mock.patch.object(M, 'module', return_value=SimpleNamespace(main=entry)) as imported:
                M.main()
            imported.assert_called_once_with(filename)
            entry.assert_called_once_with()

    def test_legacy_cli_sdk6_run_selects_its_isolated_producer(self):
        for version in ('6.0.136', '7.0.120'):
            arguments = ['musl-legacy-sdk.py', 'run', '--sdk-version', version, '--arch', 'aarch64',
                '--workspace', '/builder', '--output-dir', '/delivery', '--build-id', '20261109.1',
                '--run-id', '123', '--run-attempt', '1']
            own = mock.Mock()
            with self.subTest(version=version), mock.patch.object(sys, 'argv', arguments), \
                    mock.patch.object(LEGACY, 'module', return_value=SimpleNamespace(Producer=own)) as imported, \
                    mock.patch.object(LEGACY, 'Producer') as shared:
                LEGACY.main()
            selected = own if version == '6.0.136' else shared
            selected.assert_called_once()
            self.assertEqual(version, selected.call_args.args[0].sdk_version)
            selected.return_value.execute.assert_called_once_with()
            if version == '6.0.136':
                imported.assert_called_once_with('isolated_sdk6_normal_producer', 'musl_legacy_sdk6.py')
                shared.assert_not_called()
            else:
                imported.assert_not_called()
                own.assert_not_called()

    def test_legacy_cli_uses_sdk6_gate_and_preserves_expected_identity_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            record = dict(kind='musl-sdk-producer-validation', sdkVersion='6.0.136', architecture='aarch64',
                          projectCommit='a' * 40, runId='123', runAttempt='1')
            (release / 'producer-validation.json').write_text(json.dumps(record))
            expected = dict(sdk_version=record['sdkVersion'], arch=record['architecture'],
                expected_project_commit=record['projectCommit'], expected_run_id=record['runId'],
                expected_run_attempt=record['runAttempt'])
            gate = mock.Mock()
            with mock.patch.object(LEGACY, 'module', return_value=SimpleNamespace(validate=gate)) as imported, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                LEGACY.validate(SimpleNamespace(release_dir=release, **expected))
            imported.assert_called_once_with('strict_legacy_admission_cli', 'musl_legacy6_admission.py')
            gate.assert_called_once_with(release)
            self.assertEqual(dict(status='validated-producer-proof', sourceAdmissionAllowed=False), json.loads(output.getvalue()))
            for field, value in [('sdk_version', '7.0.120'), ('arch', 'x64'), ('expected_project_commit', 'b' * 40),
                                 ('expected_run_id', '124'), ('expected_run_attempt', '2')]:
                changed = dict(expected, **{field: value})
                with self.subTest(field=field), \
                        mock.patch.object(LEGACY, 'module', return_value=SimpleNamespace(validate=mock.Mock())), \
                        self.assertRaisesRegex(ValueError, 'Expected legacy producer identity differs'):
                    LEGACY.validate(SimpleNamespace(release_dir=release, **changed))


if __name__ == '__main__':
    unittest.main()
