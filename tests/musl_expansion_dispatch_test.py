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


class ExpansionBoundary(unittest.TestCase):
    def test_every_expansion_route_has_a_separate_candidate_contract(self):
        self.assertEqual(set(CONTRACT.SOURCES) - {'10.0.403'}, set(M.ROUTES))
        for version in M.ROUTES:
            self.assertEqual(CONTRACT.EXPANSION_WORKFLOW, CONTRACT.producer_workflow(version))
        self.assertFalse(CONTRACT.load_contract()['publicationAllowed'])

    def test_unreviewed_versions_cannot_fall_back_to_a_repack_or_other_sdk(self):
        for version in ('6.0.136', '5.0.214', '3.1.426', '10.0.403', '7.0.121', None):
            arguments = ['run'] + (['--sdk-version', version] if version else [])
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'Unreviewed'):
                M.dispatch_identity(arguments)

    def test_receiver_uses_sealed_version_and_rejects_cli_identity_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            (release / 'producer-validation.json').write_text(json.dumps({'sdkVersion': '7.0.120'}))
            self.assertEqual(('validate', '7.0.120', release), M.dispatch_identity(['validate', '--release-dir', temporary]))
            for extra in (['--sdk-version', '9.0.123'], ['--expected-project-commit', 'a' * 40]):
                with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, 'only the sealed'):
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
            (release / 'producer-validation.json').write_text(json.dumps({'sdkVersion': '7.0.120'}))
            record = dict(status='passed', sdkVersion='7.0.120', architecture='aarch64',
                          projectCommit='a' * 40, runId='123', runAttempt='1')
            gate = mock.Mock(return_value=record)
            with mock.patch.object(sys, 'argv', ['musl-sdk-expand.py', 'validate', '--release-dir', temporary]), \
                    mock.patch.object(M, 'module', return_value=SimpleNamespace(validate=gate)) as imported, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                M.main()
            imported.assert_called_once_with('musl_legacy_admission.py')
            gate.assert_called_once_with(release)
            self.assertEqual(record, json.loads(output.getvalue()))


if __name__ == '__main__':
    unittest.main()
