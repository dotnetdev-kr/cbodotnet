#!/usr/bin/env python3
"""Bounded adversarial fixtures for the portable .NET 10 evidence gate."""
import copy
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('evidence', ROOT / 'scripts/ci-net10-evidence.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def dump(path, data):
    return write(path, json.dumps(data, indent=2) + '\n')


def results(directory):
    ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    root = ET.Element('{' + ns + '}TestRun')
    tests = ET.SubElement(root, '{' + ns + '}Results')
    for index in range(13):
        ET.SubElement(tests, '{' + ns + '}UnitTestResult', executionId=str(index), outcome='Passed',
                      testName='Microsoft.DotNet.Tests.BinaryScanTest.ScanForBinaries' if index == 0 else 'Common.Test' + str(index))
    summary = ET.SubElement(root, '{' + ns + '}ResultSummary')
    ET.SubElement(summary, '{' + ns + '}Counters', total='13', executed='13', passed='13', failed='0')
    trx = write(directory / 'common.trx', ET.tostring(root))
    scenarios = ET.Element('assemblies')
    assembly = ET.SubElement(scenarios, 'assembly', total='36', passed='34', failed='0', skipped='2', errors='0')
    collection = ET.SubElement(assembly, 'collection')
    for index in range(34):
        ET.SubElement(collection, 'test', name='Scenario' + str(index), method='Method' + str(index), result='Pass')
    for name in sorted(GATE.SKIPS):
        ET.SubElement(collection, 'test', name=name, method=name, result='Skip')
    return trx, write(directory / 'scenarios.xml', ET.tostring(scenarios))


class Bundle:
    """Synthetic documents model evidence structure, never a product CI result."""
    def __init__(self, root):
        self.root = root
        self.frozen = root / 'reports/ci-inputs/project'
        original = {'sdkVersion': GATE.SDK, 'source': {'commit': GATE.SOURCE},
                    'build': {'sourceOnly': False, 'officialBuildId': '20261028.1'}}
        for name in GATE.CRITICAL:
            write(self.frozen / name, '# Fixture source: ' + name + '\n')
        dump(self.frozen / GATE.PROFILE, original)
        # Independent Git builds the object graph; the gate must reconstruct it.
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Evidence fixture')
        self.git('add', '.')
        self.git('commit', '-qm', 'Fixture tree')
        commit = self.git('rev-parse', 'HEAD').strip()
        commit_bytes = subprocess.check_output(['git', '-C', str(self.frozen), 'cat-file', 'commit', commit])
        rows = []
        for entry in self.git('ls-files', '--stage', '-z').split('\0'):
            if not entry:
                continue
            metadata, name = entry.split('\t'); mode, blob, _ = metadata.split()
            canonical = subprocess.check_output(['git', '-C', str(self.frozen), 'cat-file', 'blob', blob])
            rows.append(dict(GATE.record(root, self.frozen / name), gitMode=mode, gitBlobSha1=blob,
                             **GATE.checkout_details(self.frozen, name, blob, canonical)))
        # The download contains files and commit proof, not a mutable Git store.
        import shutil
        shutil.rmtree(self.frozen / '.git')
        self.identity = dict(sourceCommit=GATE.SOURCE, projectCommit=commit, runId='12345', runAttempt='1',
                             buildId='20261031.1', buildRevision='12345')
        effective = copy.deepcopy(original); effective['build']['officialBuildId'] = self.identity['buildId']
        dump(root / 'reports/ci-inputs/effective-profile.json', effective)
        write(root / 'reports/ci-inputs/project-commit.txt', commit_bytes)
        snapshot = dict(self.identity, schemaVersion=1, executionContext='github-actions', sourceInitiallyPristine=True,
                        inputRepresentation='canonical-git-blobs-with-verified-checkout',
                        projectInitiallyPristine=True, projectFiles=rows, workflowRef='fixture/workflow@refs/heads/main',
                        originalProfile=GATE.record(root, self.frozen / GATE.PROFILE),
                        effectiveProfile=GATE.record(root, root / 'reports/ci-inputs/effective-profile.json'),
                        projectCommitObject=GATE.record(root, root / 'reports/ci-inputs/project-commit.txt'))
        dump(root / 'reports/ci-inputs/snapshot.json', snapshot)
        self.archive = dict(path='cbodotnet-sdk-10.0.403-linux-arm64-build.12345.tar.gz',
                            **GATE.fingerprint(write(root / 'cbodotnet-sdk-10.0.403-linux-arm64-build.12345.tar.gz', b'fixture SDK archive')))
        self.archive['copiedWithoutModification'] = True
        for algorithm in ('sha256', 'sha512'):
            write(root / (algorithm.upper() + 'SUMS'), self.archive[algorithm] + '  ' + self.archive['path'] + '\n')
        prepare = root / 'reports/prepare'
        write(prepare / 'sysroot-prepare.log', '--force-check-gpg --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSignature verified successfully.\n')
        write(prepare / 'sysroot-files.sha256', 'a' * 64 + '  /inputs/arm64-bionic/lib/example.so\n')
        write(prepare / 'sysroot-file-list.sha256', GATE.fingerprint(prepare / 'sysroot-files.sha256')['sha256'] + '  /delivery/reports/prepare/sysroot-files.sha256\n')
        write(prepare / 'sysroot-symlinks.tsv', '/inputs/arm64-bionic/lib/example.so.1\texample.so\n')
        producers = []
        for name, blob in GATE.SYSROOT_PRODUCERS.items():
            path = write(prepare / 'sysroot-inputs' / Path(name).name, ('Fixture producer ' + name).encode())
            producers.append(dict(GATE.record(root, path), originalPath=name, gitBlobSha1=blob))
        keyring = write(prepare / 'sysroot-inputs/ubuntu-archive-keyring.gpg', 'Fixture signing keyring')
        dump(prepare / 'sysroot-validation.json', dict(status='passed', sourceCommit=GATE.SOURCE, files=1, symlinks=1,
             signatureVerificationRequired=True, signatureSuccessRecords=1, producerInputsMatchPinnedGit=True, producerInputs=producers,
             signingKeyring=dict(GATE.record(root, keyring), originalPath='/usr/share/keyrings/ubuntu-archive-keyring.gpg', installedPackage='fixture-1'),
             inventory={name: GATE.record(root, prepare / name) for name in
                        ['sysroot-files.sha256', 'sysroot-file-list.sha256', 'sysroot-symlinks.tsv', 'sysroot-prepare.log']}))
        scan = dict(mode='Validate', sourceCommit=GATE.SOURCE, cleanSourceCommit=GATE.SOURCE, exitCode=0,
                    sourceMountedReadOnly=True, originalAllowlistUsed=True, worktreeCleanBeforeScan=True,
                    worktreeCleanAfterScan=True, reportAbsentBefore=True, allowlistsMatchPinnedGit=True,
                    commands=[['dotnet', 'msbuild', '/project/scripts/scan-clean-source.proj']])
        for key in ('report', 'toolAssembly', 'allowedBinaries', 'allowedSourceBuildBinaries', 'scanLog', 'scanBinlog'):
            path = write(root / ('reports/scan/' + key), b'' if key == 'report' else ('actual fixture ' + key).encode())
            scan[key] = GATE.record(root, path)
        dump(root / 'reports/scan/scan-execution.json', scan)
        status = dict(exitCode=0, sourceCommit=GATE.SOURCE, officialBuildId=self.identity['buildId'], sourceOnly=False)
        dump(root / 'reports/build/build-status.json', dict(status, action='build', targetRid='linux-arm64',
             startedAt='2026-10-31T00:01:01Z', finishedAt='2026-10-31T00:01:29Z'))
        dump(root / 'reports/test/test-status.json', dict(status, action='test', targetRid='linux-arm64',
             startedAt='2026-10-31T00:03:01Z', finishedAt='2026-10-31T00:03:29Z'))
        results(root / 'reports/test')
        paths = {'prepare': {'sysrootValidation': 'reports/prepare/sysroot-validation.json'},
                 'build': {'buildStatus': 'reports/build/build-status.json'},
                 'scan': {'scanExecution': 'reports/scan/scan-execution.json'},
                 'test': {'testStatus': 'reports/test/test-status.json', 'commonTrx': 'reports/test/common.trx',
                          'scenarioXml': 'reports/test/scenarios.xml'}, 'verify': {}}
        verify_commands = []
        for name in ('ubuntu22', 'ubuntu24', 'debian13'):
            path = 'reports/verify-' + name + '/verification.json'
            paths['verify'][name] = path
            dump(root / path, dict(verificationStatus='passed', smokeStatus='passed', sdkVersion=GATE.SDK,
                                  reportedRid='linux-arm64', hostArchitecture='aarch64', framework='net10.0',
                                  functionalChecks=dict.fromkeys(GATE.FUNCTIONS, 'passed'),
                                  archive=dict(sdkContentMatched=True, sha256=self.archive['sha256'], sizeBytes=self.archive['bytes']),
                                  abi=dict(elfFileCount=24, machines={'AArch64': 24}, glibcCeiling='2.27', glibcCeilingPassed=True,
                                           symbolicGlibcRequirements=[], maximumRequiredVersions={'GLIBC': '2.27', 'GLIBCXX': '3.4.22', 'CXXABI': '1.3.7'})))
            distribution, version, icu, ssl = GATE.USERLANDS[name]
            tag = 'localhost/cbodotnet-net10-verify-' + name + ':12345-1'
            image = {'Id': 'b' * 64, 'Architecture': 'arm64', 'Os': 'linux', 'RepoTags': [tag]}
            base = 'docker.io/library/' + distribution + '@sha256:' + 'c' * 64
            dump(root / ('reports/ci/' + name + '-verification-image.json'), [image])
            dump(root / ('reports/ci/' + name + '-base-image.json'), [dict(image, Digest='sha256:' + 'c' * 64,
                 RepoDigests=[base, 'docker.io/library/' + distribution + '@sha256:' + 'd' * 64])])
            verify_commands.extend([['podman', 'build', '--file', '/project/containers/verify-net10.Containerfile',
                                     '--build-arg', 'BASE_IMAGE=' + base, '--tag', tag, '/project'],
                                    ['podman', 'run', '--network=none', image['Id']]])
            dump(root / ('reports/ci/' + name + '-userland.json'), dict(imageId=image['Id'], architecture='aarch64', uid=1000,
                 osRelease={'ID': distribution, 'VERSION_ID': version},
                 installedPackages=dict.fromkeys([icu, ssl, 'libc6', 'libstdc++6', 'zlib1g', 'libgssapi-krb5-2'], 'fixture-1'),
                 environmentOverrides={'LD_LIBRARY_PATH': None, 'DOTNET_ROOT': None, 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT': None,
                                       'CLR_ICU_VERSION_OVERRIDE': None, 'DOTNET_EnableDiagnostics': None, 'COMPlus_EnableDiagnostics': None}))
        self.image = 'a' * 64
        dump(root / 'reports/prepare/build-image.json', [{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}])
        for index, name in enumerate(('prepare', 'build', 'scan', 'test', 'verify')):
            dump(root / ('reports/ci/stages/' + name + '.json'), dict(self.identity, stage=name, status='passed', exitCode=0,
                 commands=verify_commands if name == 'verify' else [['fixture', name, '--network=none', 'b' * 64]],
                 imageId=self.image, paths=paths[name], environment={'nativeArchitecture': 'aarch64', 'uid': 1000},
                 startedAtUtc='2026-10-31T00:%02d:00Z' % index, finishedAtUtc='2026-10-31T00:%02d:30Z' % index))
        write(root / 'collect.log', 'Actual fixture collector output\n')
        write(root / 'collect-commands.jsonl', '["fixture", "collect"]\n')
        self.manifest = dict(sdkVersion=GATE.SDK, targetRid='linux-arm64', sourceOnly=False, buildRevision='12345',
                             construction={'upstreamSharedRuntimeReused': True},
                             source={'actualCommit': GATE.SOURCE, 'commitVerified': True}, sdkArchive=self.archive,
                             buildImage={'id': self.image}, profile=dict(contents=effective,
                             **GATE.fingerprint(root / 'reports/ci-inputs/effective-profile.json')),
                             rebuildInputs=[GATE.record(self.frozen, p) for folder in ('scripts', 'containers', 'patches')
                                            for p in (self.frozen / folder).rglob('*') if p.is_file()])
        self.seal()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.frozen), *args]).decode()

    def seal(self):
        reports = self.root / 'reports'
        self.manifest['reports'] = {'files': [GATE.record(reports, p) for p in sorted(reports.rglob('*')) if p.is_file()]}
        dump(self.root / 'build-manifest.json', self.manifest)
        dump(self.root / 'collect-receipt.json', dict(self.identity, status='passed', exitCode=0,
             startedAtUtc='2026-10-31T00:05:00Z', finishedAtUtc='2026-10-31T00:05:30Z',
             manifest=GATE.record(self.root, self.root / 'build-manifest.json'),
             log=GATE.record(self.root, self.root / 'collect.log'), commandsFile=GATE.record(self.root, self.root / 'collect-commands.jsonl')))

    def alter(self, relative, change):
        path = self.root / relative; data = GATE.load(path); change(data); dump(path, data); self.seal()


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).absolute()
        self.producers = mock.patch.dict(GATE.SYSROOT_PRODUCERS,
             {name: GATE.git_hash('blob', ('Fixture producer ' + name).encode()) for name in GATE.SYSROOT_PRODUCERS}, clear=True)
        self.producers.start()

    def tearDown(self):
        self.producers.stop()
        self.temporary.cleanup()

    def test_portable_complete_bundle_and_git_tree(self):
        bundle = Bundle(self.root)
        result = GATE.validate_bundle(self.root)
        self.assertEqual(result['tests']['scenarios']['passed'], 34)
        self.assertEqual(result['projectCommit'], bundle.identity['projectCommit'])
        dump(self.root / 'ci-validation.json', result)
        self.assertEqual(GATE.validate_bundle(self.root), result)

    def test_freeze_preserves_canonical_git_blobs_from_clean_crlf_checkout(self):
        project, source, release = [self.root / name for name in ('project', 'source', 'delivery')]

        def git(root, *args):
            return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()

        def commit(root):
            git(root, 'init', '-q'); git(root, 'config', 'user.email', 'fixture@example.invalid')
            git(root, 'config', 'user.name', 'Evidence fixture'); git(root, 'add', '.')
            git(root, 'commit', '-qm', 'Canonical fixture'); return git(root, 'rev-parse', 'HEAD')

        write(source / 'source.txt', 'Pinned fixture source\n'); source_commit = commit(source)
        for name in GATE.CRITICAL:
            write(project / name, '# Executed fixture input\n')
        dump(project / GATE.PROFILE, {'sdkVersion': GATE.SDK, 'source': {'commit': source_commit},
                                     'build': {'sourceOnly': False, 'officialBuildId': '20261028.1'}})
        write(project / '.gitattributes', '* text=auto eol=lf\n*.cmd text eol=crlf\n*.bat text eol=crlf\n')
        raw_cmd = b'@echo off\r\necho fixture\r\n'
        write(project / 'scripts/test.cmd', raw_cmd)
        project_commit = commit(project); git(project, 'checkout-index', '-f', '-a')
        self.assertEqual(git(project, 'status', '--porcelain', '--untracked-files=all'), '')
        self.assertEqual((project / 'scripts/test.cmd').read_bytes(), raw_cmd)
        args = SimpleNamespace(project_root=project, source_dir=source, release_dir=release, project_commit=project_commit,
                               run_id='12345', run_attempt='1', build_revision='12345', build_id='20261031.1', workflow_ref='fixture/main')
        with mock.patch.object(GATE, 'SOURCE', source_commit), mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), contextlib.redirect_stdout(io.StringIO()):
            GATE.freeze(args)
        snapshot = GATE.load(release / 'reports/ci-inputs/snapshot.json')
        frozen = release / 'reports/ci-inputs/project'
        row = next(r for r in snapshot['projectFiles'] if r['path'].endswith('/scripts/test.cmd'))
        self.assertEqual(row['checkoutRepresentation'], 'crlf-checkout')
        self.assertEqual(row['checkout'], GATE.byte_fingerprint(raw_cmd))
        self.assertEqual((frozen / 'scripts/test.cmd').read_bytes(), raw_cmd.replace(b'\r\n', b'\n'))
        self.assertEqual(GATE.project_tree(release, snapshot['projectFiles'])[0], git(project, 'rev-parse', 'HEAD^{tree}'))
        self.assertEqual(GATE.checkout_details(project, 'scripts/test.cmd', row['gitBlobSha1'], (frozen / 'scripts/test.cmd').read_bytes()),
                         {key: row[key] for key in ('checkout', 'checkoutRepresentation')})
        # A clean-filter-equivalent executable still must retain exact raw bytes.
        executable = 'scripts/ci-net10.sh'; canonical = (frozen / executable).read_bytes()
        write(project / executable, canonical.replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(ValueError, 'Unreviewed checkout transformation'):
            GATE.checkout_details(project, executable, git(project, 'rev-parse', 'HEAD:' + executable), canonical)

    def test_download_verifier_requires_exact_run_identity(self):
        bundle = Bundle(self.root)
        dump(self.root / 'ci-validation.json', GATE.validate_bundle(self.root))
        command = ['ci-net10-evidence.py', 'verify-release', '--release-dir', str(self.root),
                   '--expected-project-commit', bundle.identity['projectCommit'], '--expected-run-id', '12345', '--expected-run-attempt', '1']
        with mock.patch.object(sys, 'argv', command), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(GATE.main(), 0)
        command[-3] = '54321'
        with mock.patch.object(sys, 'argv', command), self.assertRaisesRegex(ValueError, 'another commit/run/attempt'):
            GATE.main()

    def test_sdk_mutation_is_rejected(self):
        bundle = Bundle(self.root)
        write(self.root / bundle.archive['path'], b'changed SDK bytes')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            GATE.validate_bundle(self.root)

    def test_fabricated_empty_scan_without_execution_is_rejected(self):
        bundle = Bundle(self.root)
        bundle.alter('reports/scan/scan-execution.json', lambda data: data.update(commands=[['touch', 'NewBinaries.txt']]))
        with self.assertRaisesRegex(ValueError, 'original scan task invocation'):
            GATE.validate_bundle(self.root)

    def test_missing_common_result_rejected_even_after_resealing(self):
        bundle = Bundle(self.root)
        path = self.root / 'reports/test/common.trx'; root = ET.parse(path).getroot()
        tests = root.find('{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}Results')
        tests.remove(tests[-1]); path.write_bytes(ET.tostring(root)); bundle.seal()
        with self.assertRaisesRegex(ValueError, '13 actual common'):
            GATE.validate_bundle(self.root)

    def test_unapproved_scenario_skip_is_rejected(self):
        bundle = Bundle(self.root)
        path = self.root / 'reports/test/scenarios.xml'; root = ET.parse(path).getroot()
        root.findall('./assembly/collection/test')[-1].set('method', 'UnexpectedSkip')
        path.write_bytes(ET.tostring(root)); bundle.seal()
        with self.assertRaisesRegex(ValueError, 'Only the pinned workload'):
            GATE.validate_bundle(self.root)

    def test_workflow_forgery_cannot_be_resealed_as_same_commit(self):
        bundle = Bundle(self.root)
        name = 'reports/ci-inputs/project/.github/workflows/net10-sdk.yml'
        write(self.root / name, '# Forged workflow\n')
        snapshot = GATE.load(self.root / 'reports/ci-inputs/snapshot.json')
        row = next(r for r in snapshot['projectFiles'] if r['path'] == name)
        row.update(GATE.fingerprint(self.root / name)); row['gitBlobSha1'] = GATE.git_hash('blob', (self.root / name).read_bytes())
        row['checkout'] = GATE.byte_fingerprint((self.root / name).read_bytes())
        dump(self.root / 'reports/ci-inputs/snapshot.json', snapshot); bundle.seal()
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            GATE.validate_bundle(self.root)

    def test_skipped_crypto_is_rejected(self):
        bundle = Bundle(self.root)
        bundle.alter('reports/verify-debian13/verification.json', lambda data: data['functionalChecks'].update(rsaSha256SignAndVerify='skipped'))
        with self.assertRaisesRegex(ValueError, 'six native functional'):
            GATE.validate_bundle(self.root)

    def test_renamed_same_userland_is_rejected(self):
        bundle = Bundle(self.root)
        bundle.alter('reports/ci/debian13-userland.json', lambda data: data.update(osRelease={'ID': 'ubuntu', 'VERSION_ID': '24.04'}))
        with self.assertRaisesRegex(ValueError, 'user-space identity'):
            GATE.validate_bundle(self.root)

    def test_platform_digest_binding_allows_extra_index_but_rejects_invalid_metadata(self):
        digest = 'sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11'
        expected = 'docker.io/library/ubuntu@' + digest
        base = {'Architecture': 'arm64', 'Os': 'linux', 'Digest': digest,
                'RepoDigests': [expected, 'docker.io/library/ubuntu@sha256:' + 'a' * 64]}
        self.assertEqual(GATE.verification_base(base, 'ubuntu'), expected)
        mutations = [dict(Digest='sha256:short'), dict(Digest='sha256:' + 'e' * 64),
                     dict(RepoDigests=['docker.io/library/debian@' + digest]),
                     dict(RepoDigests=[expected, expected]), dict(RepoDigests=[expected, 'malformed']),
                     dict(Architecture='amd64')]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                GATE.verification_base(dict(base, **change), 'ubuntu')

    def test_verifier_build_cannot_substitute_index_digest_or_another_tag(self):
        bundle = Bundle(self.root)
        path = 'reports/ci/stages/verify.json'
        original = GATE.load(self.root / path)

        def substitute_index(data):
            command = data['commands'][0]
            index = command.index('--build-arg') + 1
            command[index] = 'BASE_IMAGE=docker.io/library/ubuntu@sha256:' + 'd' * 64

        bundle.alter(path, substitute_index)
        with self.assertRaisesRegex(ValueError, 'bind the inspected base Digest'):
            GATE.validate_bundle(self.root)
        dump(self.root / path, original); bundle.seal()
        bundle.alter('reports/ci/ubuntu22-verification-image.json', lambda images: images[0].update(RepoTags=['localhost/another-image:tag']))
        with self.assertRaisesRegex(ValueError, 'run/user-space tag'):
            GATE.validate_bundle(self.root)

    def test_unsigned_sysroot_and_source_mutation_rejected(self):
        bundle = Bundle(self.root)
        bundle.alter('reports/prepare/sysroot-validation.json', lambda data: data.update(signatureVerificationRequired=False))
        with self.assertRaisesRegex(ValueError, 'Authenticated complete sysroot'):
            GATE.validate_bundle(self.root)
        bundle.alter('reports/prepare/sysroot-validation.json', lambda data: data.update(signatureVerificationRequired=True))
        path = self.root / 'reports/prepare/sysroot-inputs/build-rootfs.sh'; write(path, 'modified producer')
        validation = GATE.load(self.root / 'reports/prepare/sysroot-validation.json')
        validation['producerInputs'][0].update(GATE.fingerprint(path))
        dump(self.root / 'reports/prepare/sysroot-validation.json', validation); bundle.seal()
        with self.assertRaisesRegex(ValueError, 'differs from pinned source'):
            GATE.validate_bundle(self.root)

    def test_extra_report_or_outer_file_is_rejected(self):
        Bundle(self.root)
        extra = write(self.root / 'reports/uninventoried.log', 'late report')
        with self.assertRaisesRegex(ValueError, 'report membership'):
            GATE.validate_bundle(self.root)
        extra.unlink(); write(self.root / 'unbound.txt', 'outside reports')
        with self.assertRaisesRegex(ValueError, 'Unbound files'):
            GATE.validate_bundle(self.root)

    def test_source_only_override_is_rejected(self):
        bundle = Bundle(self.root)
        bundle.alter('reports/ci-inputs/effective-profile.json', lambda data: data['build'].update(sourceOnly=True))
        snapshot = GATE.load(self.root / 'reports/ci-inputs/snapshot.json')
        snapshot['effectiveProfile'].update(GATE.fingerprint(self.root / 'reports/ci-inputs/effective-profile.json'))
        dump(self.root / 'reports/ci-inputs/snapshot.json', snapshot); bundle.seal()
        with self.assertRaisesRegex(ValueError, 'Only the explicit CI'):
            GATE.validate_bundle(self.root)

    def test_newline_path_escape_and_xml_entities_rejected(self):
        for name in ('../secret', '/absolute', 'reports/../secret', 'reports\\secret', 'C:secret'):
            with self.assertRaises(ValueError):
                GATE.member(self.root, name)
        path = write(self.root / 'entity.xml', '<!DOCTYPE x [<!ENTITY y SYSTEM "file:///secret">]><x>&y;</x>')
        with self.assertRaisesRegex(ValueError, 'Unsupported XML'):
            GATE.xml(path)


if __name__ == '__main__':
    unittest.main()
