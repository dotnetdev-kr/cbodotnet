#!/usr/bin/env python3
"""Complete synthetic x64 generated-source gates, never SDK qualification.

Reuse the ARM64 schema fixture, preserve its original controls outside the
delivery, then run real x64 Git freezing and the production origin assembler.
No actual SDK, PSB, native execution or signing claim is made by these files.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import ci_net67_delivery_test as generated_fixtures

ROOT = Path(__file__).resolve().parents[1]
E = generated_fixtures.E
H = generated_fixtures.H


class NativeGeneratedDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.helper = generated_fixtures.CompleteGeneratedDeliveryTests(methodName='runTest')

    def edit(self, release, name, change):
        path = release / name
        value = E.load(path)
        change(value)
        self.helper.json(path, value)

    def fixture(self, root, major):
        release, _ = self.helper.fixture(root, major)
        reports = release / 'reports'
        selected = E.version_config(major, 'x64')
        architecture = E.get_arch('x64')
        source = root / 'source'
        comparison = E.load(reports / 'construction/identity/shared-framework-identity.json')
        for name in ('ci-inputs', 'construction'):
            original = reports / name
            saved = root / ('original-arm64-' + name)
            self.assertTrue(original.resolve().is_relative_to(root.resolve()))
            original.rename(saved)
        for relative in ('artifacts/arm64', 'artifacts/obj/arm64'):
            path = source / relative
            path.rename(path.with_name('x64'))
        for path in list(source.rglob('*linux-arm64*.tar.gz')):
            path.rename(path.with_name(path.name.replace('linux-arm64', 'linux-x64')))
        replay = reports / 'origin-tools/replay.json'
        value = E.load(replay)
        for task in value['tasks']:
            for attempt in task['Attempts']:
                for name in ('Source', 'Destination'):
                    attempt[name] = attempt[name].replace('/arm64/', '/x64/').replace('linux-arm64', 'linux-x64')
        self.helper.json(replay, value)
        observed = reports / 'build/installer-observations.jsonl'
        observations = [json.loads(line) for line in observed.read_text().splitlines()]
        for row in observations:
            for name in ('feed', 'destination'):
                row[name] = row[name].replace('/arm64/', '/x64/').replace('linux-arm64', 'linux-x64')
        observed.write_text(''.join(json.dumps(row) + '\n' for row in observations))
        sdk_source = source / 'artifacts/x64/Release' / ('dotnet-sdk-' + selected['sdk'] + '-linux-x64.tar.gz')
        comparison['sdkArchive'].update(path=str(sdk_source), **E.fingerprint(sdk_source))
        run = H.D.Run.__new__(H.D.Run)
        run.major, run.sdk, run.selected = major, selected['sdk'], selected
        run.arch, run.architecture = 'x64', architecture
        run.source, run.output, run.reports = source, release, reports
        run.script = lambda name: '/frozen/scripts/' + name
        run.container = lambda *args, **kwargs: self.helper.json(reports / 'construction/identity/shared-framework-identity.json', comparison)
        run.origin()

        project = root / 'x64-project'
        (project / 'profiles').mkdir(parents=True)
        profile_name = 'dotnet-' + selected['sdk'] + '-linux-x64.json'
        shutil.copyfile(ROOT / 'profiles' / profile_name, project / 'profiles' / profile_name)
        (project / 'fixture.py').write_text('# Synthetic frozen x64 source only.\n')
        def git(*args):
            return subprocess.check_output(['git', '-C', str(project), *args], stderr=subprocess.PIPE).decode().strip()
        git('init', '-q'); git('config', 'user.name', 'Native gate fixture'); git('config', 'user.email', 'fixture@example.invalid')
        git('add', '.'); git('commit', '-qm', 'Synthetic native x64 orchestration')
        identity = dict(projectCommit=git('rev-parse', 'HEAD'), runId='123', runAttempt='1', buildId='20261101.1', buildRevision='123')
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_WORKFLOW_REF': 'dotnetdev-kr/cbodotnet/.github/workflows/sdk-x64.yml@refs/heads/main'}):
            snapshot = E.freeze(project, release, major, identity, arch='x64')
        profile = E.load(reports / 'ci-inputs/effective-profile.json')
        for name in ('prepare', 'build', 'scan', 'test', 'verify'):
            def stage(value):
                value.update(identity)
                value['environment'] = dict(architecture='x86_64', uid=1001, gid=1001, allowedCpuSelection='0,1')
            self.edit(release, 'reports/ci/stages/' + name + '.json', stage)
        self.edit(release, 'reports/sysroot/sysroot-provenance.json',
                  lambda value: value.update(generatorArguments=['x64', 'xenial', '--rootfsdir', '/inputs/x64-xenial']))
        psb_name = 'Private.SourceBuilt.Artifacts.' + selected['bootstrap'] + '.centos.' + ('7' if major == '6' else '8') + '-x64.tar.gz'
        original = dict(path='/inputs/original-bootstrap/' + psb_name, bytes=selected['psbSize'], sha256=selected['psbSha256'], sha512='d' * 128)
        native_rid, count = ('linux-x64', 14) if major == '6' else ('centos.8-x64', 12)
        self.helper.json(reports / 'bootstrap/bootstrap-inputs.json', dict(installerCommit=selected['commit'], bootstrapSdk=selected['bootstrap'],
            targetArchitecture='x64', bootstrapMode='native-original-inputs', nativePackageRid=native_rid,
            originalInputs=[original], finalInputs=[dict(original, path='/work/source-v' + selected['sdk'] + '/packages/archive/' + psb_name)],
            nativePackageEntries=['synthetic.native' + str(number) + '.' + native_rid + '.fixture.nupkg' for number in range(count)]))
        members = self.helper.put(reports / ('test/net' + major + '-test-tool-members.json'), b'{"syntheticOnly":true}\n')
        self.helper.json(reports / ('test/net' + major + '-test-tools.json'), dict(status='passed',
            url='https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.6/omnisharp-linux-x64-net6.0.tar.gz',
            expectedArchive={'bytes': 43149563, 'sha256': 'c631cf552590ee8f00cbea441e99a94f689bf1832f1f8de2d5a00d5d5d18140c'},
            extractedMembersVerified=True, memberReceipt=E.record(release, members), scope='Synthetic native fixture identity only.'))
        self.helper.json(reports / 'test-inputs/official-sdk-baseline.json', dict(version=selected['sdk'], rid='linux-x64',
            bytes=selected['baselineSize'], sha512=selected['baselineSha512']))
        archive = release / ('cbodotnet-sdk-' + selected['sdk'] + '-linux-arm64-build.123.tar.gz')
        archive.rename(release / archive.name.replace('linux-arm64', 'linux-x64'))
        for name, rid in zip(('ubuntu22', 'ubuntu24', 'debian13'), selected['rids']):
            def native(value):
                value.update(reportedRid=rid, hostArchitecture='x86_64')
                value['abi'].update(machines={architecture['elf']: 22}, symbolicGlibcRequirements=[])
            self.edit(release, 'reports/verify-' + name + '/verification.json', native)
            def userland(value):
                value.update(architecture='x86_64')
                value['environmentOverrides']['DOTNET_ROOT_X64'] = None
            self.edit(release, 'reports/ci/' + name + '-userland.json', userland)
            self.edit(release, 'reports/ci/' + name + '-verification-image.json', lambda value: value[0].update(Architecture='amd64'))
        source_control = E.load(release / 'sources/source-manifest.json')
        source_control['targetRid'] = 'linux-x64'
        for path in (release / 'sources/source-manifest.json', reports / 'ci/used-source.json'):
            self.helper.json(path, source_control)
        manifest = E.load(release / 'build-manifest.json')
        archive = release / ('cbodotnet-sdk-' + selected['sdk'] + '-linux-x64-build.123.tar.gz')
        manifest.update(targetRid='linux-x64', sdkArchive=E.record(release, archive), profile={'contents': profile})
        manifest['rebuildInputs'] = [dict(path=row['path'].removeprefix('reports/ci-inputs/project/'),
            **{key: row[key] for key in ('bytes', 'sha256', 'sha512')}) for row in snapshot['projectFiles']]
        self.helper.json(release / 'build-manifest.json', manifest)
        for algorithm, name in (('sha256', 'SHA256SUMS'), ('sha512', 'SHA512SUMS')):
            self.helper.put(release / name, (manifest['sdkArchive'][algorithm] + '  ' + archive.name + '\n').encode())
        self.edit(release, 'collect-receipt.json', lambda value: value.update(identity))
        self.helper.reseal(release)
        return release, {key: identity[key] for key in ('projectCommit', 'runId', 'runAttempt')}

    def test_real_freeze_origin_assembly_and_complete_native_gates_for_both_versions(self):
        for major in ('6', '7'):
            with self.subTest(major=major), tempfile.TemporaryDirectory() as temporary:
                release, expected = self.fixture(Path(temporary), major)
                result = E.validate(release, expected, arch='x64')
                self.assertEqual(result['targetRid'], 'linux-x64')
                self.assertEqual(result['tests']['omniSharpPassed'], 12)
                E.write(release / 'ci-validation.json', result)
                self.assertEqual(E.validate(release, expected, arch='x64'), result)
                with self.assertRaises(ValueError):
                    E.validate(release, expected)

    def test_resealed_cross_architecture_and_bootstrap_contract_changes_are_rejected(self):
        for major in ('6', '7'):
            for mutation in ('profile', 'elf', 'image', 'host', 'workflow', 'source', 'root', 'bootstrap-mode', 'bootstrap-bytes', 'bootstrap-rid', 'bootstrap-entry', 'sdk-name', 'symbolic-abi', 'observer'):
                with self.subTest(major=major, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    release, expected = self.fixture(Path(temporary), major)
                    if mutation == 'profile':
                        path = release / 'reports/ci-inputs/effective-profile.json'; profile = E.load(path)
                        profile['host']['architecture'] = 'arm64'; self.helper.json(path, profile)
                        self.edit(release, 'reports/ci-inputs/snapshot.json', lambda value: value.update(effectiveProfile=E.record(release, path)))
                    elif mutation == 'elf':
                        self.edit(release, 'reports/verify-ubuntu22/verification.json', lambda value: value['abi'].update(machines={'AArch64': 22}))
                    elif mutation == 'image':
                        self.edit(release, 'reports/ci/ubuntu22-verification-image.json', lambda value: value[0].update(Architecture='arm64'))
                    elif mutation == 'host':
                        self.edit(release, 'reports/verify-ubuntu22/verification.json', lambda value: value.update(hostArchitecture='aarch64'))
                    elif mutation == 'workflow':
                        self.edit(release, 'reports/ci-inputs/snapshot.json', lambda value: value.update(workflowRef='dotnetdev-kr/cbodotnet/.github/workflows/sdk-matrix.yml@refs/heads/main'))
                    elif mutation == 'source':
                        value = E.load(release / 'sources/source-manifest.json'); value['targetRid'] = 'linux-arm64'
                        for path in ('sources/source-manifest.json', 'reports/ci/used-source.json'):
                            self.helper.json(release / path, value)
                    elif mutation == 'root':
                        self.edit(release, 'reports/ci/ubuntu22-userland.json', lambda value: value['environmentOverrides'].update(DOTNET_ROOT_X64='/other-sdk'))
                    elif mutation == 'bootstrap-mode':
                        self.edit(release, 'reports/bootstrap/bootstrap-inputs.json', lambda value: value.update(bootstrapMode='arm64-transformed'))
                    elif mutation == 'bootstrap-bytes':
                        self.edit(release, 'reports/bootstrap/bootstrap-inputs.json', lambda value: value['finalInputs'][0].update(sha256='0' * 64))
                    elif mutation == 'bootstrap-rid':
                        self.edit(release, 'reports/bootstrap/bootstrap-inputs.json', lambda value: value.update(nativePackageRid='linux-arm64'))
                    elif mutation == 'bootstrap-entry':
                        def wrong_entry(value):
                            value['nativePackageEntries'][0] = 'synthetic.native.linux-arm64.fixture.nupkg'
                        self.edit(release, 'reports/bootstrap/bootstrap-inputs.json', wrong_entry)
                    elif mutation == 'sdk-name':
                        manifest_path = release / 'build-manifest.json'; manifest = E.load(manifest_path)
                        path = release / manifest['sdkArchive']['path']; renamed = path.with_name(path.name.replace('linux-x64', 'linux-arm64'))
                        path.rename(renamed); manifest['sdkArchive'] = E.record(release, renamed)
                        self.helper.json(manifest_path, manifest)
                        for algorithm, sidecar in (('sha256', 'SHA256SUMS'), ('sha512', 'SHA512SUMS')):
                            (release / sidecar).write_text(manifest['sdkArchive'][algorithm] + '  ' + renamed.name + '\n')
                    elif mutation == 'symbolic-abi':
                        self.edit(release, 'reports/verify-ubuntu22/verification.json', lambda value: value['abi'].update(symbolicGlibcRequirements=['GLIBC_PRIVATE']))
                    else:
                        path = release / 'reports/build/installer-observations.jsonl'
                        rows = [json.loads(line) for line in path.read_text().splitlines()]
                        rows[0]['feed'] = rows[0]['feed'].replace('/x64/', '/arm64/')
                        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
                    self.helper.reseal(release)
                    with self.assertRaises(ValueError):
                        E.validate(release, expected, arch='x64')


if __name__ == '__main__':
    unittest.main()
