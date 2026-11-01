"""Reject substituted producers and unsafe or mutable release promotions."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PUBLISH = load('publish_release', 'publish-release.py')
PREPARE = load('prepare_release', 'prepare-release.py')


def descriptor(path):
    return {'name': path.name, 'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def staged(root):
    root.mkdir()
    manifest = {'schemaVersion': 1, 'repository': PUBLISH.REPOSITORY, 'sdkVersion': '10.0.403',
                'tag': 'sdk-10.0.403', 'architectures': {}}
    checksums = []
    for arch, rid in PUBLISH.ARCHES.items():
        entry = {'provenance': {'targetRid': rid, 'projectCommit': 'a' * 40,
                 'runId': '123', 'runAttempt': '1', 'artifactId': '456',
                 'workflowUrl': 'https://github.com/' + PUBLISH.REPOSITORY + '/actions/runs/123'}}
        for kind in ('sdk', 'source', 'evidence'):
            name = ('evidence-' + arch if kind == 'evidence' else
                    'cbodotnet-' + kind + '-10.0.403-linux-' + arch) + '.tar.gz'
            path = root / name
            path.write_bytes((kind + '-' + arch).encode())
            entry[kind] = descriptor(path)
            checksums.append(entry[kind]['sha256'] + '  ' + name + '\n')
        manifest['architectures'][arch] = entry
    path = root / 'SHA256SUMS'
    path.write_text(''.join(checksums), encoding='ascii')
    manifest['checksums'] = descriptor(path)
    (root / 'release-manifest.json').write_text(json.dumps(manifest))
    return manifest


class FakeGitHub:
    def __init__(self, args, release=None, tag_exists=False):
        self.args = args
        self.release = release
        self.tag_exists = tag_exists
        self.calls = []

    def asset(self, name):
        record = descriptor(self.args.staging / name)
        return {'name': name, 'size': record['size'], 'digest': 'sha256:' + record['sha256'], 'state': 'uploaded',
                'browser_download_url': 'https://github.com/' + PUBLISH.REPOSITORY +
                    '/releases/download/sdk-10.0.403/' + name}

    def __call__(self, args, *command, **options):
        self.calls.append(command)
        if command[0] == 'api':
            if '/git/ref/' in command[1]:
                return '{}' if self.tag_exists else None
            if '/releases?' in command[1]:
                return json.dumps([[self.release]] if self.release is not None else [[]])
            if '/releases/tags/' in command[1] and self.release['draft']:
                raise AssertionError('The real by-tag REST API cannot find pending drafts')
            return json.dumps(self.release) if self.release is not None else None
        if command[:2] == ('release', 'create'):
            self.release = {'id': 789, 'tag_name': 'sdk-10.0.403', 'draft': True, 'prerelease': False,
                'target_commitish': args.target_commit, 'assets': [],
                'html_url': 'https://github.com/' + PUBLISH.REPOSITORY + '/releases/tag/sdk-10.0.403'}
        elif command[:2] == ('release', 'upload'):
            self.release['assets'].append(self.asset(Path(command[3]).name))
        elif command[:2] == ('release', 'edit'):
            self.release['draft'] = False
        else:
            raise AssertionError(command)
        return ''


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.args = argparse.Namespace(staging=self.root / 'staging', target_commit='a' * 40, gh='gh')
        self.manifest = staged(self.args.staging)

    def run_publish(self, remote):
        with mock.patch.object(PUBLISH, 'gh', side_effect=remote), mock.patch('builtins.print'):
            PUBLISH.publish(self.args)

    def test_new_release_uploads_complete_archives_and_never_uses_overwrite(self):
        remote = FakeGitHub(self.args)
        self.run_publish(remote)
        self.assertFalse(remote.release['draft'])
        self.assertEqual(8, len(remote.release['assets']))
        uploads = [command for command in remote.calls if command[:2] == ('release', 'upload')]
        self.assertEqual(8, len(uploads))
        self.assertTrue(all('--clobber' not in command for command in remote.calls))
        last_upload = max(index for index, command in enumerate(remote.calls) if command[:2] == ('release', 'upload'))
        edit = next(index for index, command in enumerate(remote.calls) if command[:2] == ('release', 'edit'))
        self.assertLess(last_upload, edit)
        self.assertTrue(all('/releases/tags/' not in command[1] for command in remote.calls if command[0] == 'api'))

    def test_duplicate_pending_tag_drafts_are_rejected(self):
        with mock.patch.object(PUBLISH, 'gh', return_value=json.dumps([[{'id': 1, 'tag_name': 'sdk-10.0.403'},
                {'id': 2, 'tag_name': 'sdk-10.0.403'}]])):
            with self.assertRaisesRegex(ValueError, 'Multiple releases'):
                PUBLISH.find_release(self.args, 'sdk-10.0.403')

    def test_exact_published_release_is_idempotent_across_new_main_commit(self):
        remote = FakeGitHub(self.args)
        self.run_publish(remote)
        remote.calls.clear()
        self.args.target_commit = 'b' * 40
        self.run_publish(remote)
        self.assertTrue(all(command[0] == 'api' for command in remote.calls))

    def test_exact_partial_draft_resumes_only_missing_assets(self):
        remote = FakeGitHub(self.args)
        remote(self.args, 'release', 'create')
        name = self.manifest['architectures']['x64']['sdk']['name']
        remote.release['assets'] = [remote.asset(name)]
        remote.calls.clear()
        self.run_publish(remote)
        uploads = [command for command in remote.calls if command[:2] == ('release', 'upload')]
        self.assertEqual(7, len(uploads))
        self.assertTrue(all(Path(command[3]).name != name for command in uploads))

    def test_unrelated_draft_and_unreleased_existing_tag_are_rejected(self):
        remote = FakeGitHub(self.args)
        remote(self.args, 'release', 'create')
        remote.release['target_commitish'] = 'b' * 40
        remote.calls.clear()
        with self.assertRaisesRegex(ValueError, 'unrelated draft'):
            self.run_publish(remote)
        self.assertTrue(all(command[0] == 'api' for command in remote.calls))
        remote = FakeGitHub(self.args, tag_exists=True)
        with self.assertRaisesRegex(ValueError, 'existing tag'):
            self.run_publish(remote)
        self.assertTrue(all(command[0] == 'api' for command in remote.calls))

    def test_remote_collision_and_partial_public_release_never_upload(self):
        for collision in (True, False):
            remote = FakeGitHub(self.args)
            remote(self.args, 'release', 'create')
            name = self.manifest['architectures']['x64']['sdk']['name']
            remote.release['assets'] = [remote.asset(name)]
            if collision:
                remote.release['assets'][0]['digest'] = 'sha256:' + 'f' * 64
            else:
                remote.release['draft'] = False
            remote.calls.clear()
            with self.assertRaises(ValueError):
                self.run_publish(remote)
            self.assertTrue(all(command[0] == 'api' for command in remote.calls))

    def test_local_payload_tamper_fails_before_any_remote_operation(self):
        path = self.args.staging / self.manifest['architectures']['x64']['sdk']['name']
        path.write_bytes(b'tampered')
        remote = FakeGitHub(self.args)
        with self.assertRaisesRegex(ValueError, 'staged asset changed'):
            self.run_publish(remote)
        self.assertEqual([], remote.calls)

    def test_semantically_wrong_checksums_fail_before_any_remote_operation(self):
        path = self.args.staging / 'SHA256SUMS'
        path.write_text(path.read_text().splitlines()[0] + '\n')
        self.manifest['checksums'] = descriptor(path)
        (self.args.staging / 'release-manifest.json').write_text(json.dumps(self.manifest))
        remote = FakeGitHub(self.args)
        with self.assertRaisesRegex(ValueError, 'complete release'):
            self.run_publish(remote)
        self.assertEqual([], remote.calls)

    def test_failed_upload_keeps_release_draft(self):
        remote = FakeGitHub(self.args)

        def failed_upload(args, *command, **options):
            if command[:2] == ('release', 'upload'):
                raise RuntimeError('simulated upload failure')
            return remote(args, *command, **options)

        with mock.patch.object(PUBLISH, 'gh', side_effect=failed_upload), self.assertRaisesRegex(RuntimeError, 'failure'):
            PUBLISH.publish(self.args)
        self.assertTrue(remote.release['draft'])
        self.assertFalse(any(command[:2] == ('release', 'edit') for command in remote.calls))

    def test_payload_copy_is_unchanged_and_rejects_changed_destination(self):
        source = self.root / 'sdk.tar.gz'
        source.write_bytes(b'qualified sdk bytes')
        expected = {'bytes': source.stat().st_size, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        destination = self.root / 'alias.tar.gz'
        PUBLISH.copy_payload(source, destination, expected)
        self.assertEqual(source.read_bytes(), destination.read_bytes())
        with mock.patch.object(PUBLISH.shutil, 'copyfile', side_effect=lambda _, target: target.write_bytes(b'changed')):
            with self.assertRaisesRegex(ValueError, 'qualified bytes'):
                PUBLISH.copy_payload(source, destination, expected)

    def test_evidence_preserves_original_names_and_excludes_large_payloads(self):
        release = self.root / 'qualified'
        (release / 'sources').mkdir(parents=True)
        sdk = release / 'sdk-linux-arm64.tar.gz'
        source = release / 'sources/source-linux-arm64.tar.gz'
        sdk.write_bytes(b'sdk')
        source.write_bytes(b'source')
        (release / 'report.json').write_text('{"status":"passed"}')
        (release / 'sources/source-index.jsonl').write_text('{"path":"product.cs"}\n')
        output = self.root / 'evidence.tar.gz'
        PUBLISH.pack_evidence(release, output, {sdk, source})
        with tarfile.open(output) as archive:
            self.assertEqual({'report.json', 'sources/source-index.jsonl'}, set(archive.getnames()))
        self.assertEqual(b'sdk', sdk.read_bytes())
        self.assertEqual(b'source', source.read_bytes())


class ProducerTests(unittest.TestCase):
    def fixture(self):
        row = {'projectCommit': 'a' * 40, 'runId': '123', 'runAttempt': '1', 'artifactId': '456'}
        artifact = {'id': 456, 'name': 'sdk-net10-linux-arm64-123-1', 'expired': False, 'digest': 'sha256:' + 'b' * 64,
                    'workflow_run': {'id': 123, 'head_sha': 'a' * 40, 'head_branch': 'main',
                                     'head_repository_id': 789, 'repository_id': 789}}
        run = {'id': 123, 'run_attempt': 1, 'head_sha': 'a' * 40, 'head_branch': 'main',
               'repository': {'full_name': PUBLISH.REPOSITORY}, 'head_repository': {'full_name': PUBLISH.REPOSITORY},
               'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/sdk-matrix.yml'}
        return row, artifact, run

    def test_exact_legacy_and_current_aarch64_producers_are_accepted(self):
        row, artifact, run = self.fixture()
        PREPARE.validate_producer(row, artifact, run, 'net10', 'aarch64')
        artifact['name'] = 'sdk-net10-linux-aarch64-123-1'
        PREPARE.validate_producer(row, artifact, run, 'net10', 'aarch64')

    def test_failed_substituted_expired_and_fork_producers_are_rejected(self):
        row, artifact, run = self.fixture()
        mutations = [(0, 'projectCommit', 'c' * 40), (0, 'runAttempt', '2'), (0, 'artifactId', '999'),
                     (1, 'expired', True), (1, 'name', 'sdk-net9-linux-arm64-123-1'), (1, 'digest', None),
                     (2, 'conclusion', 'failure'), (2, 'status', 'in_progress'), (2, 'head_branch', 'topic'),
                     (2, 'path', '.github/workflows/untrusted.yml'),
                     (2, 'head_repository', {'full_name': 'fork/cbodotnet'})]
        for index, key, value in mutations:
            changed = copy.deepcopy([row, artifact, run])
            changed[index][key] = value
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, TypeError)):
                PREPARE.validate_producer(*changed, 'net10', 'aarch64')

    def test_zip_requires_exact_ordinary_flat_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'input.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('transport.tar.gz', b'payload')
                archive.writestr('transport.tar.gz.sha256', b'checksum')
            output = root / 'output'
            PREPARE.extract_zip(path, output, {'transport.tar.gz', 'transport.tar.gz.sha256'})
            self.assertEqual(b'payload', (output / 'transport.tar.gz').read_bytes())
            with self.assertRaises(FileExistsError):
                PREPARE.extract_zip(path, output, {'transport.tar.gz', 'transport.tar.gz.sha256'})

    def test_zip_rejects_traversal_absolute_symlink_duplicate_and_extra_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = [('../escape', False), ('/absolute', False), ('C:drive', False), ('nested/member', False),
                     ('back\\slash', False), ('linked', True)]
            for index, (name, linked) in enumerate(cases):
                path = root / (str(index) + '.zip')
                with zipfile.ZipFile(path, 'w') as archive:
                    info = zipfile.ZipInfo(name)
                    if linked:
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                    archive.writestr(info, b'payload')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    PREPARE.extract_zip(path, root / ('output-' + str(index)), {name})
            self.assertFalse((root / 'escape').exists())
            with zipfile.ZipFile(root / 'extra.zip', 'w') as archive:
                archive.writestr('expected', b'payload')
                archive.writestr('extra', b'payload')
            with self.assertRaises(ValueError):
                PREPARE.extract_zip(root / 'extra.zip', root / 'extra-output', {'expected'})


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        plan = {'schemaVersion': 1, 'sdkVersion': '10.0.403', 'target': 'net10', 'architectures': {}}
        for arch, rid in PUBLISH.ARCHES.items():
            release = self.root / arch
            (release / 'sources').mkdir(parents=True)
            sdk = release / ('original-sdk-' + rid + '.tar.gz')
            sdk.write_bytes(('qualified-sdk-' + arch).encode())
            source = release / 'sources' / ('original-sources-' + rid + '.tar.gz')
            source.write_bytes(('qualified-source-' + arch).encode())

            def original_descriptor(path):
                row = descriptor(path)
                return {'path': path.name, 'bytes': row['size'], 'sha256': row['sha256']}

            validation = {'status': 'passed', 'sdkArchive': original_descriptor(sdk)}
            source_manifest = {'status': 'captured-used-source', 'sdkVersion': '10.0.403', 'targetRid': rid,
                               'archive': original_descriptor(source)}
            (release / 'ci-validation.json').write_text(json.dumps(validation))
            (release / 'sources/source-manifest.json').write_text(json.dumps(source_manifest))
            plan['architectures'][arch] = {'releaseDirectory': str(release), 'projectCommit': 'a' * 40,
                                          'runId': '123', 'runAttempt': '1', 'artifactId': '456'}
        self.plan = self.root / 'deliveries.json'
        self.plan.write_text(json.dumps(plan))
        self.args = argparse.Namespace(deliveries=self.plan, sdk_version='10.0.403', target='net10',
                                       project_root=ROOT, output=self.root / 'public-staging')

    def run_stage(self, verifier=None, described='10.0.403'):
        with mock.patch.object(PUBLISH.subprocess, 'check_output', return_value=json.dumps({'sdk_version': described})), \
             mock.patch.object(PUBLISH.subprocess, 'run', side_effect=verifier) as checked, mock.patch('builtins.print'):
            PUBLISH.stage(self.args)
            return checked.call_args_list

    def test_stage_requires_own_trusted_full_verification_for_both_bound_producers(self):
        calls = self.run_stage()
        self.assertEqual(2, len(calls))
        for call, arch in zip(calls, ('arm64', 'x64')):
            command = call.args[0]
            self.assertIn('verify-release', command)
            self.assertEqual(arch, command[command.index('--arch') + 1])
            self.assertEqual('a' * 40, command[command.index('--expected-project-commit') + 1])
            self.assertEqual('123', command[command.index('--expected-run-id') + 1])
            self.assertEqual('1', command[command.index('--expected-run-attempt') + 1])
            self.assertTrue(call.kwargs['check'])
        manifest = json.loads((self.args.output / 'release-manifest.json').read_text())
        for arch in ('aarch64', 'x64'):
            self.assertEqual(('qualified-sdk-' + arch).encode(),
                             (self.args.output / manifest['architectures'][arch]['sdk']['name']).read_bytes())
            self.assertEqual(('qualified-source-' + arch).encode(),
                             (self.args.output / manifest['architectures'][arch]['source']['name']).read_bytes())

    def test_verification_failure_stops_before_copying_any_payload(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_stage(verifier=subprocess.CalledProcessError(1, ['trusted-verifier']))
        self.assertEqual([], list(self.args.output.iterdir()))

    def test_wrong_adapter_version_and_reused_output_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'different SDK version'):
            self.run_stage(described='10.0.404')
        self.assertFalse(self.args.output.exists())
        self.args.output.mkdir()
        (self.args.output / 'existing').write_text('keep me')
        with self.assertRaisesRegex(ValueError, 'fresh staging'):
            self.run_stage()
        self.assertEqual('keep me', (self.args.output / 'existing').read_text())


if __name__ == '__main__':
    unittest.main()
