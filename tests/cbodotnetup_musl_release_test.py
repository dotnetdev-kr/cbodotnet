"""Release integration binds both musl CPUs to immutable inputs and actual jobs."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import cbodotnetup_release as UP
import cbodotnetup_musl as MUSL
import cbodotnetup_musl_native as NATIVE
from cbodotnetup_musl_test import catalog_fixture


class MuslCatalogIntegrationTests(unittest.TestCase):
    def test_separate_musl_pair_cannot_drift_from_shared_trust_or_real_baseline(self):
        policy, current, qualified = catalog_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            glibc = {key: copy.deepcopy(value) for key, value in current.items() if key != 'libc'}
            glibc['schemaVersion'] = 3
            UP.save(bundle / 'catalog.json', glibc)
            baseline = dict(current, sequence=current['sequence'] - 1,
                            tools=[tool for tool in current['tools'] if tool['version'] == '0.5.0'])
            UP.save(bundle / 'catalog-musl-baseline.json', baseline)
            with patch.object(MUSL, 'load_policy', return_value=policy), \
                    patch.object(MUSL.CONTRACT, 'load_qualification_catalog', return_value=qualified):
                UP.save(bundle / 'catalog-musl.json', current)
                self.assertEqual(UP.verify_musl_pair(bundle), current)
                for mutate in (lambda value: value.update(sequence=value['sequence'] + 1),
                               lambda value: value.update(issuedAt='2020-01-01T00:00:00Z'),
                               lambda value: value.update(expiresAt='2099-01-01T00:00:00Z'),
                               lambda value: value.update(revoked=['tool/0.5.0/linux-musl-x64']),
                               lambda value: value['tools'].pop()):
                    changed = copy.deepcopy(current)
                    mutate(changed)
                    UP.save(bundle / 'catalog-musl.json', changed)
                    with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                        UP.verify_musl_pair(bundle)
                UP.save(bundle / 'catalog-musl.json', current)
                baseline['tools'][0]['binary']['sha256'] = 'f' * 64
                UP.save(bundle / 'catalog-musl-baseline.json', baseline)
                with self.assertRaisesRegex(ValueError, 'baseline'):
                    UP.verify_musl_pair(bundle)

    def test_current_and_baseline_catalogs_use_exact_built_bytes_for_both_cpus(self):
        policy, expected, qualified = catalog_fixture()
        def expected_build_inputs(arch):
            return {name: hashlib.sha256((name + arch).encode()).hexdigest() for name in ('script', 'container', 'profile')}
        build_inputs_patch = patch.object(NATIVE, 'build_inputs', side_effect=expected_build_inputs)
        build_inputs_patch.start()
        self.addCleanup(build_inputs_patch.stop)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builds = {}
            for arch, target in MUSL.ARCHITECTURES.items():
                rid = target['rid']
                directory = root / rid
                (directory / 'baseline').mkdir(parents=True)
                source = dict(repository='dotnetdev-kr/cbodotnet', workflow=UP.WORKFLOW)
                build_inputs = NATIVE.build_inputs(arch)
                UP.save(directory / 'baseline/provenance.json', dict(source=source, sourceInputs={}, buildInputs=build_inputs))
                artifacts = []
                for prefix in ('', 'baseline/'):
                    for suffix in ('', '.LICENSE.txt'):
                        path = directory / (prefix + 'cbodotnetup-' + rid + suffix)
                        path.write_bytes((prefix + rid + suffix).encode())
                        artifacts.append(dict(UP.descriptor(path), path=path.relative_to(directory).as_posix()))
                artifacts.append(dict(UP.descriptor(directory / 'baseline/provenance.json'), path='baseline/provenance.json'))
                UP.save(directory / 'build.json', dict(artifacts=artifacts, source=source, sourceInputs={}, buildInputs=build_inputs))
                builds[rid] = directory
            output = root / 'catalogs'
            output.mkdir()
            common = {key: value for key, value in expected.items()
                      if key not in ('schemaVersion', 'libc', 'sdks', 'tools', 'channels')}
            with patch.object(MUSL, 'load_policy', return_value=policy), \
                    patch.object(MUSL.CONTRACT, 'load_qualification_catalog', return_value=qualified), \
                    patch.object(MUSL, 'sdk_catalog_record', side_effect=expected['sdks']), \
                    patch.object(MUSL, 'validate_tool_report') as validate, \
                    patch.object(UP, 'previous_musl_catalog', return_value=None):
                UP.catalog_musl(output, builds, common)
                self.assertEqual({call.args[1] for call in validate.call_args_list}, {'x64', 'aarch64'})
            catalog = UP.load(output / 'catalog-musl.json')
            self.assertEqual(len(catalog['tools']), 4)
            for tool in catalog['tools']:
                directory = builds[tool['rid']]
                if tool['version'] == '0.5.0':
                    directory = directory / 'baseline'
                self.assertEqual(tool['binary']['sha256'], UP.descriptor(directory / ('cbodotnetup-' + tool['rid']))['sha256'])
            baseline = UP.load(output / 'catalog-musl-baseline.json')
            self.assertEqual(baseline['sequence'], catalog['sequence'] - 1)
            self.assertEqual({tool['version'] for tool in baseline['tools']}, {'0.5.0'})
            # A later release must retain published musl recovery identities
            # and revocations even though the glibc catalog never held them.
            previous = copy.deepcopy(catalog)
            previous['sequence'] -= 1
            previous['revoked'] = ['tool/0.5.0/linux-musl-x64']
            real_load = UP.load
            def next_policy(path):
                value = real_load(path)
                return dict(value, version='0.6.0') if Path(path) == UP.POLICY else value
            sdk_by_arch = {arch: sdk for arch, sdk in zip(MUSL.ARCHITECTURES, expected['sdks'])}
            with patch.object(UP, 'load', side_effect=next_policy), \
                    patch.object(MUSL, 'load_policy', return_value=policy), \
                    patch.object(MUSL.CONTRACT, 'load_qualification_catalog', return_value=qualified), \
                    patch.object(MUSL, 'sdk_catalog_record', side_effect=lambda arch: sdk_by_arch[arch]), \
                    patch.object(MUSL, 'validate_tool_report'), \
                    patch.object(UP, 'previous_musl_catalog', return_value=previous):
                UP.catalog_musl(output, builds, common)
                renewed = real_load(output / 'catalog-musl.json')
                self.assertTrue(set(previous['revoked']) <= set(renewed['revoked']))
                self.assertEqual({tool['version'] for tool in renewed['tools']}, {'0.5.0', '0.5.1', '0.6.0'})
                retained = {(tool['version'], tool['rid']): tool for tool in renewed['tools']}
                for tool in previous['tools']:
                    self.assertEqual(retained[tool['version'], tool['rid']], tool)
                next(tool for tool in previous['tools'] if tool['version'] == '0.5.0')['binary']['sha256'] = 'f' * 64
                with self.assertRaisesRegex(ValueError, 'conflicting bytes'):
                    UP.catalog_musl(output, builds, common)
            for rid in builds:
                missing = {key: value for key, value in builds.items() if key != rid}
                with self.assertRaisesRegex(ValueError, 'Both native musl'):
                    UP.catalog_musl(output, missing, common)
            report_path = builds['linux-musl-x64'] / 'build.json'
            original_report = real_load(report_path)
            changed_report = copy.deepcopy(original_report)
            changed_report['buildInputs'][next(iter(changed_report['buildInputs']))] = 'f' * 64
            UP.save(report_path, changed_report)
            with patch.object(MUSL, 'validate_tool_report'), self.assertRaisesRegex(ValueError, 'inputs changed'):
                UP.catalog_musl(output, builds, common)
            UP.save(report_path, original_report)
            (builds['linux-musl-x64'] / 'cbodotnetup-linux-musl-x64').write_bytes(b'changed after build')
            with patch.object(MUSL, 'validate_tool_report'), self.assertRaisesRegex(ValueError, 'artifact differs'):
                UP.catalog_musl(output, builds, common)


class ActualMuslJobProofTests(unittest.TestCase):
    def exercise(self, *, public=False, mutation=None, supplied_change=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs = {}
            jobs = {}
            artifacts = {}
            zips = {}
            for number, arch in enumerate(('x64', 'aarch64'), start=1):
                source = dict(repository='dotnetdev-kr/cbodotnet', workflow=UP.WORKFLOW,
                              commit=str(number) * 40, runId=str(700 + number), runAttempt='1')
                value = dict(variant='alpine-3.24', architecture=arch, orchestration=source)
                directory = root / arch
                directory.mkdir()
                UP.save(directory / 'report.json', value)
                record = dict(head_sha=source['commit'], path=UP.WORKFLOW, head_branch='main', event='workflow_dispatch',
                              repository=dict(full_name=source['repository']), head_repository=dict(full_name=source['repository']))
                job_name = ('Verify public cbodotnetup on ' if public else 'Qualify cbodotnetup on ') + 'alpine-3.24 native ' + arch
                job = dict(name=job_name, id=2000 + number, status='completed', conclusion='success')
                transport = io.BytesIO()
                with zipfile.ZipFile(transport, 'w') as archive:
                    archive.writestr('report.json', (directory / 'report.json').read_bytes())
                raw = transport.getvalue()
                artifact = dict(id=3000 + number, name=('cbodotnetup-public-proof-' if public else 'cbodotnetup-native-proof-')
                                + 'alpine-3.24-' + arch + '-' + source['runId'] + '-1', expired=False,
                                size_in_bytes=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest())
                if mutation:
                    mutation(record, job, artifact)
                if supplied_change and number == 1:
                    value['changed'] = True
                    UP.save(directory / 'report.json', value)
                run_path = f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}'
                runs[run_path + '/attempts/1'] = record
                jobs[run_path + '/attempts/1/jobs?per_page=100'] = dict(jobs=[job])
                artifacts[run_path + '/artifacts?per_page=100'] = dict(total_count=1, artifacts=[artifact])
                zips[f'repos/dotnetdev-kr/cbodotnet/actions/artifacts/{artifact["id"]}/zip'] = raw
            def api(path):
                return (runs | jobs | artifacts)[path]
            with patch.object(UP, 'GitHubReleases') as github, \
                    patch.object(NATIVE, 'validate_qualification_report') as validate, \
                    patch.object(UP.subprocess, 'check_output', side_effect=lambda command: zips[command[-1]]):
                github.return_value.api.side_effect = api
                proof = UP.qualified_musl_reports(root / 'bundle', root, public=public)
                self.assertEqual(validate.call_count, 2)
                return proof

    def test_both_candidate_and_public_phases_require_actual_successful_main_jobs_and_exact_zip_bytes(self):
        for public in (False, True):
            proof = self.exercise(public=public)
            self.assertEqual({row['architecture'] for row in proof}, {'x64', 'aarch64'})
            self.assertTrue(all(row['workflow']['workflow'] == UP.WORKFLOW for row in proof))

    def test_wrong_provenance_failed_native_job_expired_or_conflicting_zip_is_rejected(self):
        for mutation in (lambda run, job, artifact: run.update(head_branch='untrusted'),
                         lambda run, job, artifact: run.update(head_sha='f' * 40),
                         lambda run, job, artifact: job.update(conclusion='failure'),
                         lambda run, job, artifact: artifact.update(expired=True),
                         lambda run, job, artifact: artifact.update(digest='sha256:' + 'f' * 64)):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.exercise(mutation=mutation)
        with self.assertRaisesRegex(ValueError, 'actual job'):
            self.exercise(supplied_change=True)


if __name__ == '__main__':
    unittest.main()
