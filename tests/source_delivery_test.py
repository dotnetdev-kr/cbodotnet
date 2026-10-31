#!/usr/bin/env python3
"""Test capture of real dirty Git/exported sources and tamper detection."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

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

    def test_existing_output_and_wrong_source_commit_are_rejected(self):
        self.capture()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.capture()
        shutil.rmtree(self.args.output_dir); (self.release / 'reports/ci/used-source.json').unlink()
        with self.assertRaises(Exception):
            self.capture({'name': 'vmr', 'kind': 'git', 'path': str(self.code), 'expectedCommit': 'a' * 40})


if __name__ == '__main__':
    unittest.main()
