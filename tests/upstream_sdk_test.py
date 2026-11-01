"""Exercise upstream selection, immutable source admission and sandbox derivation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('upstream_sdk_tested', ROOT / 'scripts/upstream-sdk.py')
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


def document(channel, entries):
    return {'channel-version': channel, 'support-phase': 'eol', 'releases': entries}


def release(*versions):
    return {'release-date': '2026-11-10', 'runtime': {'version': '10.0.15'},
            'sdk': {'version': versions[0], 'runtime-version': '10.0.15'},
            'sdks': [{'version': item, 'runtime-version': '10.0.15'} for item in versions]}


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.policy = MODULE.load(ROOT / 'profiles/upstream-policy.json')

    def test_latest_numeric_version_per_band_includes_both_sdk_shapes(self):
        data = document('10.0', [release('10.0.409', '10.0.115'), release('10.0.410', '10.0.114'),
                                release('10.0.500-preview.1')])
        self.assertEqual([row['sdkVersion'] for row in MODULE.latest_sdks(data)], ['10.0.115', '10.0.410'])

    def test_end_of_life_and_unknown_future_channel_remain_visible(self):
        docs = [document('6.0', [release('6.0.428')]), document('12.0', [release('12.0.100')])]
        result = MODULE.plan(self.policy, docs, set(), resolve=lambda tag: '1' * 40)
        self.assertEqual([row['status'] for row in result['records']], ['pending-adapter', 'pending-adapter'])
        self.assertTrue(MODULE.eligible_channel('12.0'))
        self.assertFalse(MODULE.eligible_channel('2.1'))

    def test_missing_source_is_pending_without_substitution(self):
        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], set(), resolve=lambda tag: None)
        self.assertEqual(result['records'][0]['status'], 'pending-source')
        self.assertEqual(result['candidates'], [])

    def test_missing_source_in_unadmitted_newer_band_is_visible(self):
        docs = [document('8.0', [release('8.0.427')]), document('9.0', [release('9.0.320')])]
        result = MODULE.plan(self.policy, docs, set(), resolve=lambda tag: None)
        self.assertEqual([row['status'] for row in result['records']], ['pending-source', 'pending-source'])

    def test_registry_can_admit_multiple_source_families_without_changing_net10_candidates(self):
        family = {'adapter': {'name': 'net9-1xx-portable', 'target': 'net9', 'channel': '9.0',
                             'featureBand': 100, 'baselineSdk': '9.0.123'}}
        docs = [document('9.0', [release('9.0.124')]), document('10.0', [release('10.0.404')])]
        inputs = {'runtime': '10.0.15'}
        result = MODULE.plan(dict(self.policy, maximumCandidatesPerRun=2), docs, set(),
                             resolve=lambda tag: '1' * 40, values=lambda sdk, pin: inputs,
                             registry=[(self.policy, None), (family, None)])
        self.assertEqual([item['sdkVersion'] for item in result['candidates']], ['9.0.124', '10.0.404'])
        self.assertEqual(result['candidates'][0]['target'], 'net9')
        self.assertNotIn('target', result['candidates'][1])

    def test_bootstrap_gap_is_reported_separately(self):
        def missing(sdk, commit):
            raise ValueError('pending-bootstrap: official SDK checksum is not published')

        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], set(),
                             resolve=lambda tag: '1' * 40, values=missing)
        self.assertEqual(result['records'][0]['status'], 'pending-bootstrap')

    def test_explicit_baseline_qualification_cannot_succeed_without_admission(self):
        (ROOT / '.build').mkdir(exist_ok=True)
        policy = dict(self.policy, minimumChannels=['10.0'])
        candidate = dict(schemaVersion=1, adapter=policy['adapter']['name'], sdkVersion='10.0.403',
                         sourceCommit=policy['adapter']['baselineSource'], runtimeVersion='10.0.14',
                         releaseDate='2026-10-25', qualificationOnly=True)
        fake_plan = dict(schemaVersion=1, selection=policy['selection'], candidates=[], records=[])
        with tempfile.TemporaryDirectory(dir=ROOT / '.build', prefix='upstream-qualification-') as directory:
            base = Path(directory); policy_path = base / 'policy.json'; MODULE.write(policy_path, policy)
            args = argparse.Namespace(policy=policy_path, output=base / 'plan.json',
                                      qualify_baseline=True, qualify_target='net10')
            with mock.patch.object(MODULE, 'adapter_registry', return_value=[(policy, None)]), \
                 mock.patch.object(MODULE, 'request', return_value=b'{"releases-index":[]}'), \
                 mock.patch.object(MODULE, 'release_states', return_value={'published': set(), 'drafts': set()}), \
                 mock.patch.object(MODULE, 'plan', return_value=fake_plan), \
                 mock.patch.object(MODULE, 'baseline_candidate', return_value=candidate), \
                 mock.patch.object(MODULE, 'source_metadata'), \
                 mock.patch.object(MODULE, 'compatibility', side_effect=ValueError('pending-bootstrap: missing input')):
                with self.assertRaisesRegex(ValueError, 'failed immutable source admission'):
                    MODULE.discover(args)
            result = MODULE.load(args.output)
            self.assertEqual(result['candidates'], [])
            self.assertEqual(result['records'][0]['sdkVersion'], '10.0.403')
            self.assertEqual(result['records'][0]['status'], 'pending-bootstrap')

    def test_partial_draft_prevents_conflicting_automatic_rebuild(self):
        resolve = mock.Mock()
        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], set(),
                             resolve=resolve, drafts={'10.0.404'})
        self.assertEqual(result['records'][0]['status'], 'pending-publication-recovery')
        self.assertEqual(result['candidates'], [])
        resolve.assert_not_called()

    def test_new_source_is_actual_candidate_and_published_version_is_idempotent(self):
        inputs = dict(runtime='10.0.15', bootstrapSdk='10.0.403', sharedVmrCommit='2' * 40,
                      sharedSdkPackage='10.0.115-servicing.26599.1')
        resolve = mock.Mock(return_value='1' * 40)
        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], set(), resolve, lambda sdk, pin: inputs)
        self.assertEqual(result['candidates'][0]['sourceCommit'], '1' * 40)
        self.assertEqual(result['candidates'][0]['sdkVersion'], '10.0.404')
        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], {'10.0.404'}, resolve)
        self.assertEqual(result['records'][0]['status'], 'published')
        self.assertEqual(resolve.call_count, 1)

    def test_runtime_mismatch_is_pending_adapter(self):
        result = MODULE.plan(self.policy, [document('10.0', [release('10.0.404')])], set(),
                             lambda tag: '1' * 40, lambda sdk, pin: {'runtime': '10.0.14'})
        self.assertEqual(result['records'][0]['status'], 'pending-adapter')

    def test_missed_poll_does_not_skip_intermediate_updates(self):
        inputs = dict(runtime='10.0.15', bootstrapSdk='10.0.403', sharedVmrCommit='2' * 40,
                      sharedSdkPackage='10.0.115-servicing.26599.1')
        docs = [document('10.0', [release('10.0.404'), release('10.0.405')])]
        result = MODULE.plan(self.policy, docs, set(), lambda tag: '1' * 40, lambda sdk, pin: inputs)
        self.assertEqual(result['candidates'][0]['sdkVersion'], '10.0.404')
        self.assertEqual(result['deferredCandidates'], 1)
        result = MODULE.plan(self.policy, docs, {'10.0.404'}, lambda tag: '1' * 40, lambda sdk, pin: inputs)
        self.assertEqual(result['candidates'][0]['sdkVersion'], '10.0.405')

    def test_incompatible_older_update_does_not_starve_later_version(self):
        inputs = dict(runtime='10.0.15', bootstrapSdk='10.0.403', sharedVmrCommit='2' * 40,
                      sharedSdkPackage='10.0.115-servicing.26599.1')
        policy = dict(self.policy, maximumCandidatesPerRun=100)
        result = MODULE.plan(policy, [document('10.0', [release('10.0.404'), release('10.0.405')])], set(),
                             lambda tag: '1' * 40, lambda sdk, pin: inputs)

        def check(candidate):
            if candidate['sdkVersion'] == '10.0.404':
                raise ValueError('The original scenario runner changed')
            return {'status': 'compatible'}

        MODULE.admit_candidates(result, 1, check)
        self.assertEqual(result['candidates'][0]['sdkVersion'], '10.0.405')
        self.assertEqual(result['records'][0]['status'], 'pending-adapter')

    def test_metadata_may_not_cross_channel_or_conflict(self):
        with self.assertRaises(ValueError):
            MODULE.latest_sdks(document('10.0', [release('9.0.123')]))
        first = release('10.0.404'); second = release('10.0.404')
        second['sdk']['runtime-version'] = '10.0.16'; second['sdks'] = []
        with self.assertRaises(ValueError):
            MODULE.latest_sdks(document('10.0', [first, second]))

    def test_historical_null_sdk_lists_are_allowed(self):
        data = document('6.0', [{'release-date': '2024-11-12', 'sdks': None, 'sdk': None}])
        self.assertEqual(MODULE.latest_sdks(data), [])

    def test_baseline_qualification_is_explicit_and_uses_exact_admitted_source(self):
        inputs = dict(runtime='10.0.15', bootstrapSdk='10.0.401', sharedVmrCommit='2' * 40,
                      sharedSdkPackage='10.0.114-servicing.26522.126')
        candidate = MODULE.baseline_candidate(self.policy, [document('10.0', [release('10.0.403')])],
                     lambda tag: self.policy['adapter']['baselineSource'], lambda sdk, pin: inputs)
        self.assertTrue(candidate['qualificationOnly'])
        self.assertEqual(candidate['sdkVersion'], '10.0.403')
        with self.assertRaisesRegex(ValueError, 'baseline release tag differs'):
            MODULE.baseline_candidate(self.policy, [document('10.0', [release('10.0.403')])],
                                      lambda tag: '1' * 40, lambda sdk, pin: inputs)

    def test_manifest_requires_shared_sdk_and_runtime_to_bind_same_commit(self):
        xml = ('<Dependencies><Dependency Name="Microsoft.NET.Sdk" Version="10.0.115-servicing.26599.1">'
               '<Sha>' + '2' * 40 + '</Sha></Dependency><Dependency Name="Microsoft.NETCore.App.Ref" Version="10.0.15">'
               '<Sha>' + '3' * 40 + '</Sha></Dependency></Dependencies>').encode()
        read = lambda path: b'{"sdk":{"version":"10.0.403"}}' if path == 'global.json' else xml
        with self.assertRaisesRegex(ValueError, 'one public corresponding VMR'):
            MODULE.manifest_values('10.0.404', '1' * 40, read)


class GitAdmissionTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.build').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.build', prefix='upstream-tests-')
        self.root = Path(self.temp.name)
        self.repo = self.root / 'source'; self.repo.mkdir()
        MODULE.git(self.repo, 'init', '--quiet')
        MODULE.git(self.repo, 'config', 'user.name', 'Fixture')
        MODULE.git(self.repo, 'config', 'user.email', 'fixture@example.invalid')

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, data):
        target = self.repo / path; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data, encoding='utf-8', newline='\n')

    def commit(self):
        MODULE.git(self.repo, 'add', '--all'); MODULE.git(self.repo, 'commit', '--quiet', '-m', 'Fixture')
        return MODULE.git(self.repo, 'rev-parse', 'HEAD').decode().strip()

    def test_changed_original_patch_and_test_inventory_fail_closed(self):
        self.put('eng/tool.sh', 'original\n'); self.put('test/Test.cs', 'class Test {}\n')
        old = self.commit()
        policy = {'adapter': {'baselineSource': old, 'requiredUnchangedFiles': ['eng/tool.sh'], 'testRoots': ['test']}}
        self.put('test/NewTest.cs', 'class NewTest {}\n'); new = self.commit()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            MODULE.compatibility(self.repo, policy, {'sourceCommit': new})
        self.put('eng/tool.sh', 'changed\n'); changed = self.commit()
        with self.assertRaisesRegex(ValueError, 'compatibility input changed'):
            MODULE.compatibility(self.repo, policy, {'sourceCommit': changed})
        (self.repo / 'eng/tool.sh').unlink(); deleted = self.commit()
        with self.assertRaisesRegex(ValueError, 'disappeared'):
            MODULE.compatibility(self.repo, policy, {'sourceCommit': deleted})

    def test_attribute_audit_uses_full_git_index_and_nested_rules(self):
        self.put('.gitattributes', '*.txt eol=crlf\n')
        self.put('normal.txt', 'one\n'); self.put('nested/.gitattributes', '*.txt eol=lf\n')
        self.put('nested/normal.txt', 'two\n'); pin = self.commit()
        audit = MODULE.attribute_audit(self.repo, pin, {'schemaVersion': 1, 'role': 'source-for-reused-shared-input'})
        self.assertEqual(audit['paths'], ['normal.txt'])
        self.assertEqual(len(audit['attributeFiles']), 2)
        self.assertEqual(audit['commit'], pin)

    def test_generation_is_deterministic_and_does_not_change_parent_checkout(self):
        # The miniature committed parent exercises the same complete transformation and Git commit mechanism.
        old = '1' * 40; shared = '2' * 40; new = '3' * 40; new_shared = '4' * 40
        original_audit = dict(schemaVersion=1, role='source-for-reused-shared-input', commit=shared,
                              tree='5' * 40, attributeFiles=[], paths=['one'])
        inputs = dict(bootstrapSdk='10.0.401', sharedSdkPackage='10.0.114-servicing.26522.126',
                      sharedVmrCommit=shared, runtime='10.0.14')
        policy = dict(schemaVersion=1, adapter=dict(name='net10-4xx-portable', baselineSdk='10.0.403', baselineSource=old,
                      baselineSharedSource=shared, generatedFiles=['scripts/package-used-source.py', 'scripts/ci-net10-evidence.py']))
        self.put('profiles/upstream-policy.json', json.dumps(policy))
        for arch in ('aarch64', 'x64'):
            self.put('profiles/dotnet-10.0.403-linux-' + arch + '.json', json.dumps(dict(sdkVersion='10.0.403',
                     source=dict(commit=old), upstreamInputs=inputs, build={})))
        self.put('scripts/net10-shared-source-crlf.json', json.dumps(original_audit))
        self.put('scripts/package-used-source.py', "sdk='10.0.403'\n# len(policy['paths']) == 1\n")
        self.put('scripts/ci-net10-evidence.py', "ref='" + MODULE.REPOSITORY + "/.github/workflows/sdk-x64.yml@refs/heads/main'\n")
        parent = self.commit(); before = MODULE.git(self.repo, 'rev-parse', 'HEAD')
        candidate = dict(schemaVersion=1, adapter='net10-4xx-portable', sdkVersion='10.0.404', sourceCommit=new,
                         sourceTag='v10.0.404', releaseDate='2026-11-10', runtimeVersion='10.0.15',
                         upstreamInputs=dict(bootstrapSdk='10.0.403', sharedSdkPackage='10.0.115-servicing.26599.1',
                                             sharedVmrCommit=new_shared, runtime='10.0.15'))
        candidate_path = self.root / 'candidate.json'; MODULE.write(candidate_path, candidate)
        audit = dict(original_audit, commit=new_shared, tree='6' * 40, paths=['one', 'two'])
        results = []
        with mock.patch.dict(os.environ, {'GITHUB_SHA': parent}), mock.patch.object(MODULE, 'source_metadata'), \
             mock.patch.object(MODULE, 'manifest_values', return_value=candidate['upstreamInputs']), \
             mock.patch.object(MODULE, 'compatibility', return_value={'status': 'fixture'}), \
             mock.patch.object(MODULE, 'attribute_audit', return_value=audit), \
             mock.patch.object(MODULE, 'peel_tag', return_value=new):
            for number in (1, 2):
                attestation = self.root / ('attestation' + str(number) + '.json')
                destination = self.root / ('generated' + str(number))
                MODULE.generate(argparse.Namespace(project_root=self.repo, candidate=candidate_path,
                                destination=destination, attestation=attestation))
                result = MODULE.load(attestation); results.append(result)
                self.assertEqual(MODULE.git(destination, 'rev-parse', 'HEAD^').decode().strip(), parent)
                self.assertEqual(MODULE.git(destination, 'status', '--porcelain').strip(), b'')
                self.assertTrue((destination / 'profiles/dotnet-10.0.404-linux-aarch64.json').exists())
        self.assertEqual(results[0], results[1])
        self.assertEqual(MODULE.git(self.repo, 'rev-parse', 'HEAD'), before)
        self.assertEqual(MODULE.git(self.repo, 'status', '--porcelain').strip(), b'')

    def test_registered_family_generation_delegates_without_net10_shared_inputs_and_bounds_mutations(self):
        policy = {'adapter': dict(name='net8-1xx-source-build', target='net8', channel='8.0', featureBand=100,
                                 baselineSdk='8.0.133', baselineSource='1' * 40, generatedFiles=['scripts/ci-sdk.py'])}
        self.put('profiles/upstream-policy.json', json.dumps(policy))
        self.put('scripts/ci-sdk.py', "SDK='8.0.133'\n")
        for arch in ('aarch64', 'x64'):
            self.put('profiles/dotnet-8.0.133-linux-' + arch + '.json', '{"sdkVersion":"8.0.133"}')
        parent = self.commit()
        inputs = {'runtime': '8.0.34', 'bootstrapSdk': '8.0.133',
                  'archive': {'url': 'https://example.invalid/immutable.tar.gz', 'bytes': 123,
                              'hashes': {'sha512': '2' * 128, 'sha256': '3' * 64}}}
        candidate = dict(schemaVersion=1, adapter=policy['adapter']['name'], target='net8', sdkVersion='8.0.134',
                         sourceCommit='3' * 40, sourceTag='v8.0.134', upstreamInputs=inputs,
                         runtimeVersion='8.0.34', releaseDate='2026-11-10')
        path = self.root / 'family-candidate.json'; MODULE.write(path, candidate)

        def transform(destination, supplied_policy, supplied_candidate, helpers):
            self.assertEqual(supplied_policy, policy); self.assertEqual(supplied_candidate, candidate)
            self.assertEqual(helpers.WORKFLOW, MODULE.WORKFLOW)
            (destination / 'scripts/ci-sdk.py').write_text("SDK='8.0.134'\nINPUTS=" + repr(supplied_candidate['upstreamInputs']) + '\n')
            for arch in ('aarch64', 'x64'):
                (destination / ('profiles/dotnet-8.0.134-linux-' + arch + '.json')).write_text('{"sdkVersion":"8.0.134"}')

        module = SimpleNamespace(manifest_values=mock.Mock(return_value=inputs),
                                 compatibility=mock.Mock(return_value={'family': 'net8'}), transform=transform)
        with mock.patch.dict(os.environ, {'GITHUB_SHA': parent}), \
             mock.patch.object(MODULE, 'adapter_registry', return_value=[(policy, module)]), \
             mock.patch.object(MODULE, 'source_metadata') as metadata, \
             mock.patch.object(MODULE, 'attribute_audit', side_effect=AssertionError('NET10-only audit called')), \
             mock.patch.object(MODULE, 'peel_tag', return_value=candidate['sourceCommit']):
            destination = self.root / 'family-generated'; attestation = self.root / 'family-attestation.json'
            MODULE.generate(argparse.Namespace(project_root=self.repo, candidate=path,
                            destination=destination, attestation=attestation))
            metadata.assert_called_once_with(self.root / 'family-generated-metadata', ['1' * 40, '3' * 40])
            result = MODULE.load(attestation)
            self.assertEqual(result['compatibility'], {'family': 'net8'})
            self.assertNotIn('sharedAttributeAuditSha256', result)
            self.assertIn('profiles/dotnet-8.0.134-linux-aarch64.json', result['changedFiles'])
            module.compatibility.assert_called_once()

            def reverse_keys(value):
                if isinstance(value, dict):
                    return {key: reverse_keys(item) for key, item in reversed(list(value.items()))}
                if isinstance(value, list):
                    return [reverse_keys(item) for item in value]
                return value

            reordered = self.root / 'reordered-candidate.json'
            reordered.write_text(json.dumps(reverse_keys(candidate)))
            self.assertEqual(MODULE.digest(MODULE.load(reordered)), MODULE.digest(candidate))
            reordered_attestation = self.root / 'reordered-attestation.json'
            MODULE.generate(argparse.Namespace(project_root=self.repo, candidate=reordered,
                            destination=self.root / 'family-reordered', attestation=reordered_attestation))
            replay = MODULE.load(reordered_attestation)
            self.assertEqual(replay['candidateSha256'], result['candidateSha256'])
            self.assertEqual(replay['generatedProjectTree'], result['generatedProjectTree'])
            self.assertEqual(replay['generatedProjectCommit'], result['generatedProjectCommit'])

            def unbounded(*args):
                transform(*args)
                (args[0] / 'unexpected.txt').write_text('outside the mutation policy')

            module.transform = unbounded
            with self.assertRaisesRegex(ValueError, 'outside its explicit mutation policy'):
                MODULE.generate(argparse.Namespace(project_root=self.repo, candidate=path,
                                destination=self.root / 'family-unbounded', attestation=self.root / 'unbounded.json'))


class DriverContractTests(unittest.TestCase):
    def test_host_uses_canonical_architecture_and_attestation_is_bound_before_collect(self):
        for target, sdk in [('net10', '10.0.404'), ('net9', '9.0.124'), ('net8', '8.0.134')]:
            with self.subTest(target=target):
                self.exercise_target(target, sdk)

    def exercise_target(self, target, sdk):
        spec = importlib.util.spec_from_file_location('ci_upstream_tested', ROOT / 'scripts/ci-upstream.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        (ROOT / '.build').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.build', prefix='upstream-driver-') as directory:
            base = Path(directory); project = base / 'project'; project.mkdir()
            output = base / (sdk + '-linux-arm64'); attestation = base / 'adapter.json'
            MODULE.write(attestation, dict(generatedProjectCommit='1' * 40, candidate={'sdkVersion': sdk, 'target': target}))
            calls = []
            driver = 'ci-' + target + '.sh'

            def run(command, environment=None):
                command = list(map(str, command)); calls.append(command)
                if command[1].endswith('ci-net10-host.sh') and command[2] == 'prepare':
                    self.assertEqual(command[command.index('--arch') + 1], 'arm64')
                    self.assertEqual(command[command.index('--minimum-free-gib') + 1], '30' if target == 'net10' else '90')
                    Path(command[command.index('--reports-dir') + 1]).mkdir()
                if command[1].endswith(driver) and command[2] == 'prepare':
                    (output / 'reports/ci').mkdir(parents=True)
                if command[1].endswith(driver) and command[2] == 'collect':
                    self.assertEqual(MODULE.load(output / 'reports/ci/upstream-attestation.json'), MODULE.load(attestation))

            environment = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', SDK_BUILD_ID='20261110.1')
            with mock.patch.dict(os.environ, environment), mock.patch.object(module.UPSTREAM, 'git', return_value=b'1' * 40), \
                 mock.patch.object(module, 'run', side_effect=run), mock.patch.object(module.subprocess, 'Popen'):
                module.build(argparse.Namespace(generated_root=project, arch='aarch64', attestation=attestation,
                             workspace=base / 'work', release_dir=output, bundle_dir=base / 'bundles'))
            self.assertTrue((base / ('bundles/cbodotnet-' + target + '-linux-arm64-123-1.tar.gz')).is_file())
            self.assertEqual([call[2] for call in calls if call[1].endswith(driver)],
                             ['prepare', 'build', 'scan', 'test', 'verify', 'collect'])
            validation = next(call for call in calls if call[1].endswith('ci-sdk.py'))
            self.assertEqual(validation[validation.index('--target') + 1], target)

if __name__ == '__main__':
    unittest.main()
