"""The aggregate Arch proof cannot substitute for missing individual qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('aur_coinstall', ROOT / 'scripts/aur-coinstall-ci.py')
COINSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COINSTALL)


class AurCoinstallGatesTests(unittest.TestCase):
    def test_exact_unique_run_and_attempt_for_every_sdk_is_required(self):
        names = COINSTALL.versions()
        rows = {version: index + 100 for index, version in enumerate(names)}
        parsed = COINSTALL.parse_runs(json.dumps(rows), names)
        self.assertEqual(8, len(parsed))
        self.assertTrue(all(row['attempt'] == 1 for row in parsed.values()))
        for change in ['missing', 'duplicate-run', 'negative', 'boolean', 'extra']:
            candidate = copy.deepcopy(rows)
            if change == 'missing':
                candidate.pop(names[0])
            elif change == 'duplicate-run':
                candidate[names[1]] = candidate[names[0]]
            elif change == 'negative':
                candidate[names[0]] = -1
            elif change == 'boolean':
                candidate[names[0]] = True
            else:
                candidate['2.0.100'] = 999
            with self.subTest(change=change), self.assertRaises(ValueError):
                COINSTALL.parse_runs(json.dumps(candidate), names)
        duplicate_json = json.dumps(rows)[:-1] + ', "' + names[0] + '": 999}'
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            COINSTALL.parse_runs(duplicate_json, names)

    def test_trusted_successful_main_workflow_job_is_mandatory(self):
        path = '.github/workflows/distribution-release.yml'
        run = dict(status='completed', conclusion='success', head_branch='main', path=path,
                   head_repository={'full_name': 'dotnetdev-kr/cbodotnet'}, event='workflow_dispatch')
        job = dict(status='completed', conclusion='success')
        COINSTALL.validate_run(run, job, path)
        for field, value in [('conclusion', None), ('head_branch', 'unreviewed'), ('event', 'pull_request'),
                             ('head_repository', {'full_name': 'another/repo'}), ('path', 'another.yml')]:
            candidate = dict(run, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                COINSTALL.validate_run(candidate, job, path)
        with self.assertRaises(ValueError):
            COINSTALL.validate_run(run, dict(job, conclusion='failure'), path)

    def test_individual_native_runtime_checks_cannot_be_replaced_by_version_only_or_provider_only(self):
        functional = {name: 'passed' for name in ['consoleDllExecution', 'consoleApphostExecution',
            'aspNetCoreLoopbackHttp', 'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting',
            'tls12LoopbackHandshake']}
        report = dict(status='passed', networkForBuild='none', publicationStatus='not-published',
            target=dict(osId='arch', versionId='rolling', architecture='x64', native=True),
            runtimePolicy=COINSTALL.sdk_runtime.runtime_policy('9.0.123', 'x64'), functionalChecks=functional)
        COINSTALL.validate_report(report, '9.0.123')
        for change in ['missing-tls', 'wrong-sdk', 'emulated', 'network', 'provider']:
            candidate = copy.deepcopy(report)
            if change == 'missing-tls':
                candidate['functionalChecks'].pop('tls12LoopbackHandshake')
            elif change == 'wrong-sdk':
                candidate['runtimePolicy']['sdkVersion'] = '8.0.133'
            elif change == 'emulated':
                candidate['target']['native'] = False
            elif change == 'network':
                candidate['networkForBuild'] = 'enabled'
            else:
                candidate.pop('runtimePolicy')
                candidate['scope'] = 'provider-package-only'
            with self.subTest(change=change), self.assertRaises(ValueError):
                COINSTALL.validate_report(candidate, '9.0.123')


if __name__ == '__main__':
    unittest.main()
