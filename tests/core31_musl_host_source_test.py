import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('core31_host_source_controls', ROOT / 'scripts/core31_musl_host_source.py')
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


class PublishedAuditorTests(unittest.TestCase):
    def test_all_pinned_auditor_inputs_are_the_actual_files(self):
        self.assertEqual(len(HOST.AUDIT_SOURCES), 10)
        for name, identity in HOST.AUDIT_SOURCES.items():
            self.assertEqual(fingerprint((ROOT / name).read_bytes()), identity, name)
        pins = json.loads((ROOT / 'scripts/core31-musl-host-elf-audit-pins.json').read_bytes())
        self.assertEqual(len(pins['codeFiles']), 8)
        for name, identity in pins['codeFiles'].items():
            self.assertEqual(HOST.AUDIT_SOURCES[name], identity)

    def test_source_adaptations_reject_unknown_original_bytes(self):
        for function in (HOST.adapt_build, HOST.adapt_sdk_resolver):
            with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                function(b'Unexpected source revision\n')

    def test_restore_evidence_requires_a_fresh_directory(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name).resolve()
            self.assertEqual(HOST.fresh_restore_output(output), output / 'restore-inputs')
            with self.assertRaises(ValueError):
                HOST.fresh_restore_output(output)


@unittest.skipUnless(os.name == 'posix', 'Native source mode controls require POSIX')
class AtomicOriginalSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name).resolve()
        self.originals = {'first.sln': b'first\nsource\n', 'nested/second.sln': b'second\nsource\n'}
        self.policy = {}
        for name, raw in self.originals.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw.replace(b'\n', b'\r\n'))
            path.chmod(0o644)
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.policy[name] = dict(gitBlob=blob, original=fingerprint(raw), checkout=fingerprint(path.read_bytes()))
        self.tree = b''.join(('100644 blob ' + value['gitBlob'] + '\t' + name + '\0').encode()
                             for name, value in self.policy.items())
        self.patch = patch.object(HOST, 'DECLARED_CHECKOUT_EOL', self.policy)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def run_git(self, label, command, directory, **kwargs):
        self.assertEqual(directory, self.source)
        if command[:3] == ['git', 'cat-file', 'blob']:
            return next(self.originals[name] for name, row in self.policy.items() if row['gitBlob'] == command[3])
        self.assertEqual(command[:3], ['git', 'check-attr', '-z'])
        name = command[-1]
        return (name + '\0text\0auto\0' + name + '\0eol\0crlf\0').encode()

    def invoke(self, run=None):
        return HOST.materialize_declared_checkout_eol(self.source, self.tree, run or self.run_git)

    def assert_first_unchanged(self):
        self.assertEqual((self.source / 'first.sln').read_bytes(), self.originals['first.sln'].replace(b'\n', b'\r\n'))

    def test_exact_publisher_checkout_materializes_original_git_bytes(self):
        result = self.invoke()
        self.assertEqual(result['filesWritten'], 2)
        self.assertEqual(result['sourcePolicyExceptions'], [])
        for name, raw in self.originals.items():
            self.assertEqual((self.source / name).read_bytes(), raw)

    def test_original_git_bytes_need_no_write(self):
        for name, raw in self.originals.items():
            (self.source / name).write_bytes(raw)
        self.assertEqual(self.invoke()['filesWritten'], 0)

    def test_second_file_tampering_rejects_before_first_write(self):
        (self.source / 'nested/second.sln').write_bytes(b'changed\n')
        with self.assertRaises(ValueError):
            self.invoke()
        self.assert_first_unchanged()

    def test_second_file_executable_mode_rejects_before_first_write(self):
        (self.source / 'nested/second.sln').chmod(0o755)
        with self.assertRaises(ValueError):
            self.invoke()
        self.assert_first_unchanged()

    def test_changed_original_tree_rejects_before_first_write(self):
        self.tree = self.tree.replace(b'100644 blob ', b'100755 blob ', 1)
        with self.assertRaises(ValueError):
            self.invoke()
        self.assert_first_unchanged()

    def test_attributes_are_authenticated_before_any_write(self):
        def changed(label, command, directory, **kwargs):
            value = self.run_git(label, command, directory, **kwargs)
            return value.replace(b'crlf', b'lf') if command[1] == 'check-attr' else value
        with self.assertRaises(ValueError):
            self.invoke(changed)
        self.assert_first_unchanged()

    def test_changed_git_blob_rejects_before_any_write(self):
        def changed(label, command, directory, **kwargs):
            value = self.run_git(label, command, directory, **kwargs)
            return value + b'changed' if command[1] == 'cat-file' else value
        with self.assertRaises(ValueError):
            self.invoke(changed)
        self.assert_first_unchanged()

    def test_redirected_second_file_rejects_before_first_write(self):
        path = self.source / 'nested/second.sln'
        preserved = self.source / 'second-original'
        path.rename(preserved)
        path.symlink_to(preserved)
        with self.assertRaises(ValueError):
            self.invoke()
        self.assert_first_unchanged()


if __name__ == '__main__':
    unittest.main()
