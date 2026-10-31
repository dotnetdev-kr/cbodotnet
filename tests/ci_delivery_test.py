#!/usr/bin/env python3
"""Exercise transport corruption and unsafe archive boundaries."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('delivery', ROOT / 'scripts/ci-delivery.py')
D = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(D)


class DeliveryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.download = self.root / 'download'; self.download.mkdir()
        self.name = 'cbodotnet-net7-linux-arm64-123-1.tar.gz'
        self.command = ['ci-delivery.py', '--download-dir', str(self.download), '--destination', str(self.root / 'verified'),
                        '--target', 'net7', '--sdk-version', '7.0.120', '--expected-project-commit', 'a' * 40,
                        '--expected-run-id', '123', '--expected-run-attempt', '1']

    def bundle(self, names):
        path = self.download / self.name
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind in names:
                item = tarfile.TarInfo(name); item.mode = 0o644
                if kind == 'symlink':
                    item.type = tarfile.SYMTYPE; item.linkname = '/tmp/outside'; archive.addfile(item)
                else:
                    data = b'Fixture payload, not SDK evidence.\n'; item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
        raw = path.read_bytes()
        for algorithm in ('sha256', 'sha512'):
            (self.download / (self.name + '.' + algorithm)).write_text(hashlib.new(algorithm, raw).hexdigest() + '  ' + self.name + '\n')

    def invoke(self):
        with mock.patch.object(sys, 'argv', self.command), mock.patch.object(subprocess, 'run') as verifier:
            D.main()
            return verifier.call_args

    def test_real_extraction_routes_to_trusted_verifier_with_exact_identity(self):
        self.bundle([('7.0.120-linux-arm64/fixture.txt', 'file')])
        call = self.invoke(); command = call.args[0]
        self.assertIn(str(ROOT / 'scripts/ci-sdk.py'), command)
        self.assertIn('verify-release', command); self.assertIn('a' * 40, command)
        self.assertEqual((self.root / 'verified/7.0.120-linux-arm64/fixture.txt').read_bytes(), b'Fixture payload, not SDK evidence.\n')

    def test_traversal_absolute_links_duplicate_and_wrong_root_are_rejected(self):
        for names in [[('../escape', 'file')], [('/tmp/escape', 'file')],
                      [('7.0.120-linux-arm64/link', 'symlink')], [('8.0.133-linux-arm64/x', 'file')],
                      [('7.0.120-linux-arm64/x', 'file'), ('7.0.120-linux-arm64/x', 'file')]]:
            with self.subTest(names=names):
                self.bundle(names)
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    self.invoke()
                self.assertFalse((self.root / 'verified').exists())

    def test_checksum_mutation_or_extra_transport_cannot_reach_verifier(self):
        self.bundle([('7.0.120-linux-arm64/fixture.txt', 'file')])
        with (self.download / self.name).open('ab') as stream: stream.write(b'tamper')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.invoke()
        (self.download / 'extra').write_text('unbound')
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            self.invoke()

    def test_existing_destination_is_not_modified(self):
        self.bundle([('7.0.120-linux-arm64/fixture.txt', 'file')])
        destination = self.root / 'verified'; destination.mkdir(); (destination / 'keep').write_text('unchanged')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.invoke()
        self.assertEqual((destination / 'keep').read_text(), 'unchanged')


if __name__ == '__main__': unittest.main()
