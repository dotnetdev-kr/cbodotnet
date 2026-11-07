"""Security boundaries used when admitting musl producer artifacts."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('musl_sdk_producer', ROOT / 'scripts/musl-sdk.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
INPUT_SPEC = importlib.util.spec_from_file_location('musl_input_recorder', ROOT / 'scripts/musl-sdk-inputs.py')
INPUTS = importlib.util.module_from_spec(INPUT_SPEC)
INPUT_SPEC.loader.exec_module(INPUTS)


def elf(loader='/lib/ld-musl-x86_64.so.1', machine=62):
    data = bytearray(120)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', data, 16, 3, machine)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<I', data, 64, 3)
    struct.pack_into('<Q', data, 72, 120)
    value = loader.encode() + b'\0'
    struct.pack_into('<Q', data, 96, len(value))
    return bytes(data) + value


class DeliveryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'producer-validation.json').write_text('{}')
        (self.root / 'payload').write_bytes(b'original bytes')
        self.row = dict(path='payload', **M.fingerprint(self.root / 'payload'))

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_byte_binding_accepts_original_and_rejects_tampering(self):
        M.delivery_index(self.root, [self.row])
        (self.root / 'payload').write_bytes(b'altered bytes')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            M.delivery_index(self.root, [self.row])

    def test_path_escape_absolute_duplicate_and_nonportable_paths_are_rejected(self):
        for name in ('../outside', '/outside', 'nested/../payload', './payload', 'C:/payload', 'a\\b'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                M.delivery_index(self.root, [dict(self.row, path=name)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            M.delivery_index(self.root, [self.row, self.row])

    def test_unbound_files_are_rejected(self):
        (self.root / 'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'Unbound'):
            M.delivery_index(self.root, [self.row])

    def test_symlink_alias_is_rejected(self):
        try:
            (self.root / 'alias').symlink_to('payload')
        except OSError:
            self.skipTest('Symlinks unavailable on this test filesystem')
        with self.assertRaises(ValueError):
            M.delivery_index(self.root, [self.row])

    def test_duplicate_json_properties_are_rejected(self):
        path = self.root / 'record.json'
        path.write_text('{"status":"failed","status":"passed"}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.load_json(path)

    def test_passed_label_without_required_stages_is_rejected(self):
        result = dict(schemaVersion=1, status='passed', kind='musl-sdk-producer-validation',
                      libc='musl', sdkVersion=M.SDK, sourceCommit=M.SOURCE, sharedVmrCommit=M.SHARED,
                      architecture='x64', targetRid='linux-musl-x64', projectCommit='a' * 40,
                      runId='1', runAttempt='1', allRequiredStages=['build'], files=[self.row])
        (self.root / 'producer-validation.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'six required'):
            M.validate(self.root)


class ActualElfBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, bodies, hardlink=False):
        path = self.root / 'sdk.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, body in bodies:
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            if hardlink:
                info = tarfile.TarInfo('dotnet-link')
                info.type, info.linkname = tarfile.LNKTYPE, 'dotnet'
                archive.addfile(info)
        return path

    def test_header_loader_and_digest_are_bound_including_hardlinks(self):
        body = elf()
        found = M.sdk_elf_inventory(self.archive([('dotnet', body)], True), 62, '/lib/ld-musl-x86_64.so.1')
        self.assertEqual(set(found), {'dotnet', 'dotnet-link'})
        self.assertEqual(found['dotnet']['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(found['dotnet'], found['dotnet-link'])

    def test_relabelled_glibc_and_foreign_cpu_payloads_are_rejected(self):
        for body in (elf('/lib64/ld-linux-x86-64.so.2'), elf(machine=183)):
            with self.subTest(body=body[:24]), self.assertRaises(ValueError):
                M.sdk_elf_inventory(self.archive([('dotnet', body)]), 62, '/lib/ld-musl-x86_64.so.1')

    def test_duplicate_actual_payload_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.sdk_elf_inventory(self.archive([('dotnet', elf()), ('dotnet', elf())]),
                                62, '/lib/ld-musl-x86_64.so.1')


class ImportedInputObservationTests(unittest.TestCase):
    def test_cleanup_does_not_destroy_recorded_actual_input_hashes_and_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'repository/artifacts/.packages'
            package = cache / 'upstream.package/1.0/upstream.package.1.0.nupkg'
            package.parent.mkdir(parents=True)
            package.write_bytes(b'actual immutable upstream package bytes')
            (package.parent / '.nupkg.metadata').write_text(json.dumps({'source': 'https://api.nuget.org/v3/index.json'}))
            output = root / 'evidence'
            INPUTS.record(cache, output, 'sdk')
            original = next(output.glob('*.json')).read_bytes()
            INPUTS.record(cache, output, 'sdk')
            self.assertEqual(len(list(output.glob('*.json'))), 1)
            package.unlink()
            record = json.loads(original)
            self.assertEqual(record['packages'][0]['source'], 'https://api.nuget.org/v3/index.json')
            self.assertEqual(record['packages'][0]['sha256'],
                             hashlib.sha256(b'actual immutable upstream package bytes').hexdigest())
            self.assertEqual(next(output.glob('*.json')).read_bytes(), original)


if __name__ == '__main__':
    unittest.main()

