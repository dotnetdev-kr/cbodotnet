"""Read identity without execution; reject malformed or ambiguous PE metadata."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('pure_managed_identity', Path(__file__).resolve().parents[1] / 'scripts/musl_managed_metadata.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def fixture(version='7.0.120+' + 'a' * 40, constructor=11, named=b'\0\0'):
    strings, blobs = bytearray(b'\0'), bytearray(b'\0')
    def string(value):
        offset = len(strings); strings.extend(value.encode() + b'\0'); return offset
    def blob(value):
        if len(value) >= 128: raise ValueError('Small fixture blob required')
        offset = len(blobs); blobs.extend(bytes([len(value)]) + value); return offset
    module, assembly, namespace = string('Sample.dll'), string('Sample'), string('System.Reflection')
    attribute, ctor, runtime = string('AssemblyInformationalVersionAttribute'), string('.ctor'), string('System.Runtime')
    module_type = string('<Module>')
    signature = blob(bytes([0x20, 1, 1, 0x0e]))
    raw_version = version.encode()
    value = blob(b'\x01\0' + bytes([len(raw_version)]) + raw_version + named)
    rows = {
        0: struct.pack('<HHHHH', 0, module, 1, 0, 0),
        1: struct.pack('<HHH', 6, attribute, namespace),
        2: struct.pack('<IHHHHH', 0, module_type, 0, 0, 1, 1),
        10: struct.pack('<HHH', 9, ctor, signature),
        12: struct.pack('<HHH', 46, constructor, value),
        32: struct.pack('<IHHHHIHHH', 0x8004, 1, 2, 3, 4, 0, 0, assembly, 0),
        35: struct.pack('<HHHHIHHHH', 7, 0, 0, 0, 0, 0, runtime, 0, 0)}
    tables = struct.pack('<IBBBBQQ', 0, 2, 0, 0, 1, sum(1 << i for i in rows), 0)
    tables += b''.join(struct.pack('<I', 1) for i in sorted(rows)) + b''.join(rows[i] for i in sorted(rows))
    streams = {'#~': tables, '#Strings': bytes(strings), '#Blob': bytes(blobs), '#GUID': b'\0' * 16}
    version_header = b'v4.0.30319\0'; version_header += b'\0' * (-len(version_header) % 4)
    header = b'BSJB' + struct.pack('<HHII', 1, 1, 0, len(version_header)) + version_header + struct.pack('<HH', 0, len(streams))
    names = {name: name.encode() + b'\0' for name in streams}
    names = {name: value + b'\0' * (-len(value) % 4) for name, value in names.items()}
    cursor = len(header) + sum(8 + len(names[name]) for name in streams)
    descriptors, content, offsets = [], bytearray(), {}
    for name, data in streams.items():
        offsets[name] = 0x300 + cursor
        descriptors.append(struct.pack('<II', cursor, len(data)) + names[name]); content.extend(data)
        content.extend(b'\0' * (-len(content) % 4)); cursor = len(header) + sum(8 + len(names[key]) for key in streams) + len(content)
    metadata = header + b''.join(descriptors) + content
    data = bytearray(8192); data[:2] = b'MZ'; struct.pack_into('<I', data, 0x3c, 0x80); data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x14c, 1); struct.pack_into('<H', data, 0x94, 224)
    struct.pack_into('<H', data, 0x98, 0x10b); struct.pack_into('<I', data, 0x98 + 92, 16)
    struct.pack_into('<II', data, 0x98 + 96 + 14 * 8, 0x2000, 72)
    section = 0x98 + 224; struct.pack_into('<III', data, section + 12, 0x2000, len(data) - 0x200, 0x200)
    struct.pack_into('<IIII', data, 0x200, 72, 0, 0x2100, len(metadata)); data[0x300:0x300 + len(metadata)] = metadata
    return bytes(data), offsets


class ManagedIdentityBoundary(unittest.TestCase):
    def test_original_identity_and_utf8_attributes_are_read_as_data(self):
        for version in ('7.0.120+' + 'a' * 40, 'Community 빌드'):
            actual = M.inspect(fixture(version)[0])
            self.assertEqual('Sample', actual['assemblyName'])
            self.assertEqual('1.2.3.4', actual['assemblyVersion'])
            self.assertEqual('', actual['publicKeyToken'])
            self.assertEqual([version], actual['attributes']['System.Reflection.AssemblyInformationalVersionAttribute'])
            self.assertEqual([dict(name='System.Runtime', version='7.0.0.0')], actual['references'])

    def test_truncated_sections_and_heap_pointers_are_rejected(self):
        original, offsets = fixture()
        for data in (b'ELF', original[:250], original[:0x350], original[:0x40]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError): M.inspect(data)
        changed = bytearray(original); struct.pack_into('<I', changed, 0x208, 0x7fffffff)
        with self.assertRaisesRegex(ValueError, 'RVA'): M.inspect(bytes(changed))
        changed = bytearray(original); struct.pack_into('<H', changed, offsets['#~'] + 24 + 7 * 4 + 10 + 2, 0xffff)
        with self.assertRaisesRegex(ValueError, 'string heap'): M.inspect(bytes(changed))

    def test_constructor_forgery_and_named_argument_payload_are_rejected(self):
        for data in (fixture(constructor=8)[0], fixture(constructor=10)[0], fixture(named=b'\x01\0')[0]):
            with self.assertRaises(ValueError): M.inspect(data)

    def test_duplicate_or_overlapping_metadata_heaps_are_rejected(self):
        original, offsets = fixture(); changed = bytearray(original)
        location = original.index(b'#Blob\0', 0x300)
        changed[location:location + 5] = b'#~\0\0\0'
        with self.assertRaisesRegex(ValueError, 'Duplicate'): M.inspect(bytes(changed))
        changed = bytearray(original); struct.pack_into('<I', changed, location - 8, 0)
        with self.assertRaisesRegex(ValueError, 'Overlapping'): M.inspect(bytes(changed))


if __name__ == '__main__': unittest.main()
