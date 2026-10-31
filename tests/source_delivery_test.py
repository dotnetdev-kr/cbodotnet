#!/usr/bin/env python3
"""Test capture of real dirty Git/exported sources and tamper detection."""
import contextlib
import base64
import copy
import importlib.util
import io
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('source_delivery', ROOT / 'scripts/package-used-source.py')
SOURCE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(SOURCE)


class SourceDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cbodotnet-source-test.')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.project = self.repo('project'); self.code = self.repo('code')
        self.release = self.root / 'release'; (self.release / 'reports/ci').mkdir(parents=True)
        self.roots = self.root / 'roots.json'
        self.args = SimpleNamespace(project_root=self.project, project_commit=self.head(self.project),
                                    sdk_version='10.0.403', target_rid='linux-arm64', run_id='123', run_attempt='1',
                                    roots_json=self.roots, output_dir=self.release / 'sources')
        self.check = SimpleNamespace(release_dir=self.release, expected_project_commit=self.args.project_commit,
                                     expected_run_id='123', expected_run_attempt='1')

    def command(self, directory, *args):
        return subprocess.check_output(['git', '-C', str(directory), *args]).decode().strip()

    def head(self, directory):
        return self.command(directory, 'rev-parse', 'HEAD')

    def repo(self, name):
        directory = self.root / name; directory.mkdir()
        self.command(directory, 'init', '-q'); self.command(directory, 'config', 'user.name', 'Source fixture')
        self.command(directory, 'config', 'user.email', 'fixture@example.invalid')
        (directory / 'code.cs').write_text('original source\n')
        (directory / 'removed.cs').write_text('removed during preparation\n')
        (directory / '.gitignore').write_text('obj/\n')
        self.command(directory, 'add', '.'); self.command(directory, 'commit', '-qm', 'Original source')
        return directory

    def capture(self, root=None):
        selected = root or {'name': 'vmr', 'kind': 'git', 'path': str(self.code), 'expectedCommit': self.head(self.code)}
        self.roots.write_text(json.dumps({'schemaVersion': 1, 'roots': selected if isinstance(selected, list) else [selected]}))
        with contextlib.redirect_stdout(io.StringIO()):
            SOURCE.pack(self.args)

    def verify(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return SOURCE.verify(self.check)

    def test_actual_patch_new_source_and_deletion_survive_capture(self):
        (self.code / 'code.cs').write_text('actual patched consumer\n')
        (self.code / 'generated.cs').write_text('actual generated source\n')
        (self.code / 'removed.cs').unlink()
        (self.code / 'obj').mkdir(); (self.code / 'obj/cache.dll').write_bytes(b'not source')
        self.capture(); manifest = self.verify()
        root = next(row for row in manifest['roots'] if row['name'] == 'vmr')
        self.assertEqual([row['path'] for row in root['deleted']], ['removed.cs'])
        with tarfile.open(self.args.output_dir / manifest['archive']['path']) as archive:
            self.assertEqual(archive.extractfile('vmr/code.cs').read(), b'actual patched consumer\n')
            self.assertEqual(archive.extractfile('vmr/generated.cs').read(), b'actual generated source\n')
            self.assertNotIn('vmr/obj/cache.dll', archive.getnames())
            self.assertTrue(any(name.startswith('orchestration/') for name in archive.getnames()))

    def test_export_uses_bare_origin_and_actual_consumer(self):
        bare = self.root / 'origin.git'
        subprocess.run(['git', 'clone', '--bare', '-q', str(self.code), str(bare)], check=True)
        consumer = self.root / 'consumer'; shutil.copytree(self.code, consumer, ignore=shutil.ignore_patterns('.git'))
        (consumer / '.git').mkdir(); (consumer / '.git/HEAD').write_text(self.head(self.code) + '\n')
        (consumer / 'code.cs').write_text('patched actual exported consumer\n')
        (consumer / 'generated.cs').write_text('new generated source\n')
        (consumer / 'obj').mkdir(); (consumer / 'obj/cache.dll').write_bytes(b'cache')
        self.capture({'name': 'component', 'kind': 'git-export', 'path': str(consumer),
                      'gitDir': str(bare), 'expectedCommit': self.head(self.code), 'exclude': ['obj']})
        manifest = self.verify()
        with tarfile.open(self.args.output_dir / manifest['archive']['path']) as archive:
            self.assertEqual(archive.extractfile('component/code.cs').read(), b'patched actual exported consumer\n')
            self.assertNotIn('component/obj/cache.dll', archive.getnames())

    def test_archive_content_tamper_is_rejected_even_with_resealed_hash(self):
        self.capture(); manifest_path = self.args.output_dir / 'source-manifest.json'
        manifest = json.loads(manifest_path.read_text()); archive_path = self.args.output_dir / manifest['archive']['path']
        entries = []
        with tarfile.open(archive_path) as archive:
            for member in archive:
                data = archive.extractfile(member).read(); entries.append((copy.copy(member), data))
        with tarfile.open(archive_path, 'w:gz') as archive:
            for member, data in entries:
                if member.name == 'vmr/code.cs':
                    data = b'forged source\n'; member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        manifest['archive'].update(SOURCE.fingerprint(archive_path))
        encoded = json.dumps(manifest).encode(); manifest_path.write_bytes(encoded)
        (self.release / 'reports/ci/used-source.json').write_bytes(encoded)
        with self.assertRaisesRegex(ValueError, 'Source content differs'):
            self.verify()

    def test_missing_source_wrong_identity_and_unbound_output_are_rejected(self):
        self.capture(); self.check.expected_run_id = '124'
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.verify()
        self.check.expected_run_id = '123'; (self.args.output_dir / 'extra').write_text('unbound')
        with self.assertRaisesRegex(ValueError, 'Unbound'):
            self.verify()

    def test_source_symlink_cannot_escape_root(self):
        (self.code / 'escape').symlink_to('../outside')
        with self.assertRaisesRegex(ValueError, 'symlink escapes'):
            self.capture()

    def test_git_baseline_cannot_be_relabelled_after_capture(self):
        self.capture(); path = self.args.output_dir / 'source-manifest.json'
        manifest = json.loads(path.read_text())
        root = next(row for row in manifest['roots'] if row['name'] == 'vmr')
        root['deleted'].append({'path': 'invented.cs', 'mode': '100644', 'blob': 'a' * 40})
        encoded = json.dumps(manifest).encode(); path.write_bytes(encoded)
        (self.release / 'reports/ci/used-source.json').write_bytes(encoded)
        with self.assertRaisesRegex(ValueError, 'baseline does not reconstruct'):
            self.verify()

    def test_submodule_requires_its_actual_pinned_consumer(self):
        child = self.repo('child')
        self.command(self.code, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(child), 'component')
        self.command(self.code, 'commit', '-qam', 'Declare source component')
        self.capture([{'name': 'vmr', 'kind': 'git', 'path': str(self.code), 'expectedCommit': self.head(self.code)},
                      {'name': 'component', 'kind': 'git', 'path': str(self.code / 'component'), 'expectedCommit': self.head(child)}])
        manifest = self.verify()
        parent = next(row for row in manifest['roots'] if row['name'] == 'vmr')
        self.assertEqual(parent['submodules'][0]['root'], 'component')

    def test_nested_submodule_is_automatically_captured(self):
        child = self.repo('auto-child')
        self.command(self.code, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(child), 'component')
        self.command(self.code, 'commit', '-qam', 'Declare automatically captured component')
        self.capture(); manifest = self.verify()
        parent = next(row for row in manifest['roots'] if row['name'] == 'vmr')
        child_name = parent['submodules'][0]['root']
        actual_child = next(row for row in manifest['roots'] if row['name'] == child_name)
        self.assertEqual(actual_child['commit'], self.head(child))
        with tarfile.open(self.args.output_dir / manifest['archive']['path']) as archive:
            self.assertEqual(archive.extractfile(child_name + '/code.cs').read(), b'original source\n')

    def test_only_exact_windows_command_crlf_checkout_is_pristine(self):
        canonical = b'@echo off\necho fixture\n'; checkout = canonical.replace(b'\n', b'\r\n')
        digest = lambda data: hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        row = {'path': 'orchestration/scripts/test.cmd', 'mode': '100644',
               'baseline': {'mode': '100644', 'blob': digest(canonical)}}
        self.assertTrue(SOURCE.pristine_blob(row, digest(checkout), checkout))
        self.assertFalse(SOURCE.pristine_blob(row, digest(checkout + b'changed'), checkout + b'changed'))
        self.assertFalse(SOURCE.pristine_blob(row, digest(checkout), checkout.replace(b'\r\n', b'\n', 1)))
        for extension in ['.py', '.sh', '.proj']:
            alternate = dict(row, path='orchestration/scripts/test' + extension)
            self.assertFalse(SOURCE.pristine_blob(alternate, digest(checkout), checkout))
        linked = dict(row, mode='120000', baseline={'mode': '120000', 'blob': digest(canonical)})
        self.assertFalse(SOURCE.pristine_blob(linked, digest(checkout), checkout))

    def test_exact_shared_pin_audit_accepts_nine_real_linux_checkout_samples(self):
        fixture = json.loads((ROOT / 'tests/fixtures/source-crlf/net10-shared-samples.json').read_text())
        root = {'role': 'source-for-reused-shared-input', 'commit': fixture['commit'], 'tree': fixture['tree']}
        allowed = SOURCE.pristine_crlf_paths(root)
        self.assertEqual(len(allowed), 987)
        self.assertEqual(len(fixture['files']), 9)
        digest = lambda data: hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        for sample in fixture['files']:
            with self.subTest(path=sample['path']):
                data = base64.b64decode(sample['checkoutBase64'], validate=True)
                self.assertEqual(hashlib.sha256(data).hexdigest(), sample['checkoutSha256'])
                self.assertNotEqual(digest(data), sample['gitBlobSha1'])
                self.assertEqual(digest(data.replace(b'\r\n', b'\n')), sample['gitBlobSha1'])
                self.assertIn(sample['path'], allowed)
                row = {'path': 'shared-vmr/' + sample['path'], 'mode': '100644',
                       'baseline': {'mode': '100644', 'blob': sample['gitBlobSha1']}}
                self.assertTrue(SOURCE.pristine_blob(row, digest(data), data, sample['path'] in allowed))
                self.assertFalse(SOURCE.pristine_blob(row, digest(data), data))
                self.assertFalse(SOURCE.pristine_blob(row, digest(data + b'tamper'), data + b'tamper', True))
                mixed = data.replace(b'\r\n', b'\n', 1)
                self.assertFalse(SOURCE.pristine_blob(row, digest(mixed), mixed, True))
                linked = dict(row, mode='120000', baseline={'mode':'120000', 'blob':sample['gitBlobSha1']})
                self.assertFalse(SOURCE.pristine_blob(linked, digest(data), data, True))

    def test_shared_crlf_scope_unknown_paths_binary_and_policy_tamper_are_rejected(self):
        root = {'role': 'source-for-reused-shared-input', 'commit': '0427b9abbead3fa64c6655eb4290c537397131fa',
                'tree': 'ed143c381dc0e4742aa1f9afd3652af5f21c15d6'}
        allowed = SOURCE.pristine_crlf_paths(root)
        for key, value in [('role','build-source'), ('role','orchestration'), ('commit','a' * 40), ('tree','b' * 40)]:
            self.assertEqual(SOURCE.pristine_crlf_paths(dict(root, **{key:value})), frozenset())
        digest = lambda data: hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        canonical = b'original source\n'; checkout = canonical.replace(b'\n', b'\r\n')
        for path in ['src/runtime/unknown.sln', 'src/runtime/unknown.py', 'src/runtime/unknown.sh',
                     'src/nuget-client/not-audited.props', 'src/source-build-assets/unknown.cs']:
            row = {'path':'shared-vmr/' + path, 'mode':'100644', 'baseline':{'mode':'100644','blob':digest(canonical)}}
            self.assertNotIn(path, allowed)
            self.assertFalse(SOURCE.pristine_blob(row, digest(checkout), checkout, path in allowed))
        binary = b'\0binary\r\n'
        row = {'path':'shared-vmr/src/nuget-client/Directory.Build.props', 'mode':'100644',
               'baseline':{'mode':'100644','blob':digest(binary.replace(b'\r\n', b'\n'))}}
        self.assertFalse(SOURCE.pristine_blob(row, digest(binary), binary, True))
        SOURCE.shared_crlf_policy.cache_clear()
        try:
            with mock.patch.object(Path, 'read_bytes', return_value=b'{}'):
                with self.assertRaisesRegex(ValueError, 'checkout policy changed'):
                    SOURCE.pristine_crlf_paths(root)
        finally:
            SOURCE.shared_crlf_policy.cache_clear()

    def test_streaming_verifier_buffers_only_explicit_audited_paths_and_keeps_raw_bytes(self):
        path = self.code / 'example.props'; canonical = b'<Project>\n</Project>\n'
        path.write_bytes(canonical); self.command(self.code, 'add', 'example.props')
        self.command(self.code, 'commit', '-qm', 'A fixture source with a checkout transform')
        checkout = canonical.replace(b'\n', b'\r\n'); path.write_bytes(checkout)
        self.capture({'name':'shared', 'kind':'git', 'path':str(self.code),
                      'expectedCommit':self.head(self.code), 'role':'source-for-reused-shared-input'})
        with self.assertRaisesRegex(ValueError, 'Pristine corresponding source differs'):
            self.verify()
        # Scope selection is tested against the real pin above. This isolated
        # repository exercises the actual archive-reading/buffering branch.
        with mock.patch.object(SOURCE, 'pristine_crlf_paths', side_effect=lambda root: frozenset({'example.props'}) if root['name'] == 'shared' else frozenset()):
            manifest = self.verify()
        with tarfile.open(self.args.output_dir / manifest['archive']['path']) as archive:
            self.assertEqual(archive.extractfile('shared/example.props').read(), checkout)

    def test_existing_output_and_wrong_source_commit_are_rejected(self):
        self.capture()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.capture()
        shutil.rmtree(self.args.output_dir); (self.release / 'reports/ci/used-source.json').unlink()
        with self.assertRaises(Exception):
            self.capture({'name': 'vmr', 'kind': 'git', 'path': str(self.code), 'expectedCommit': 'a' * 40})


if __name__ == '__main__':
    unittest.main()
