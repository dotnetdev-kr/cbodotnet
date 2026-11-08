"""Reject native source/version substitutions and final SDK copy mismatches."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native6_inputs', ROOT / 'scripts/musl_legacy6_native_inputs.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)
P = N.module('native6_test_source_packer', 'package-used-source.py')


def elf(parts):
    names = b'\0' + b''.join(name.encode() + b'\0' for name in ['.shstrtab', *parts])
    bodies = {'.shstrtab': names, **parts}
    raw = bytearray(64)
    raw[:6] = b'\x7fELF\x02\x01'
    rows = [bytes(64)]
    for name, body in bodies.items():
        offset = len(raw)
        raw.extend(body)
        rows.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode() + b'\0'), 1,
                                0, 0, offset, len(body), 0, 0, 1, 0))
    struct.pack_into('<Q', raw, 40, len(raw))
    struct.pack_into('<HHH', raw, 58, 64, len(rows), 1)
    return bytes(raw) + b''.join(rows)


class Native6Inputs(unittest.TestCase):
    def test_original_sln_crlf_recovers_exact_git_blob(self):
        raw = b'original solution\n'
        import hashlib
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        row = dict(path='runtime/a.sln', mode='100644', baseline=dict(mode='100644', blob=blob))
        self.assertTrue(N.pristine_runtime(P, row, raw.replace(b'\n', b'\r\n')))
        self.assertFalse(N.pristine_runtime(P, row, b'edited solution\r\n'))
        row['path'] = 'runtime/a.cpp'
        self.assertFalse(N.pristine_runtime(P, row, raw.replace(b'\n', b'\r\n')))

    def compiler_rows(self):
        source = '/work/work/runtime'
        obj = source + '/artifacts/obj/coreclr/Linux.arm64.Release'
        definitions = ' '.join('-D' + name for name in ('FEATURE_PGO', 'FEATURE_READYTORUN', 'FEATURE_EVENT_TRACE', 'FEATURE_PERFTRACING'))
        return source, obj, [dict(directory=obj + '/jit', file=obj + '/version.c',
            command='/usr/lib/llvm20/bin/clang -O3 -O3 ' + definitions + ' -c ' + obj + '/version.c -o CMakeFiles/version.o',
            output='jit/CMakeFiles/version.o') for _ in range(100)]

    def test_relative_outputs_use_original_distinct_bases(self):
        source, obj, rows = self.compiler_rows()
        self.assertEqual(N.compiler_database(rows, source, obj)['versionSourceEntries'], 100)

    def test_compiler_source_output_flags_and_features_cannot_be_substituted(self):
        source, obj, original = self.compiler_rows()
        changes = [('output', '../../outside.o'), ('file', '/other/version.c'),
                   ('command', original[0]['command'].replace('-O3', '-O0')),
                   ('command', original[0]['command'] + ' -O1'),
                   ('command', original[0]['command'] + ' -Os'),
                   ('command', original[0]['command'] + ' -o /other.o'),
                   ('directory', obj + '/../elsewhere')]
        for key, value in changes:
            rows = copy.deepcopy(original)
            rows[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                N.compiler_database(rows, source, obj)
        for row in original:
            row['command'] = row['command'].replace('-DFEATURE_EVENT_TRACE', '')
        with self.assertRaisesRegex(ValueError, 'PGO/ReadyToRun/tracing'):
            N.compiler_database(original, source, obj)

    def test_debug_link_requires_matching_build_id_and_crc(self):
        debug = elf({'.note.gnu.build-id': b'original build identity'})
        name = b'libcoreclr.so.dbg\0'
        link = name + bytes((-len(name)) % 4) + struct.pack('<I', zlib.crc32(debug) & 0xffffffff)
        normal = elf({'.note.gnu.build-id': b'original build identity', '.gnu_debuglink': link})
        N.debug_binding(normal, debug, 'libcoreclr.so.dbg')
        with self.assertRaisesRegex(ValueError, 'CRC'):
            N.debug_binding(normal, debug + b'changed', 'libcoreclr.so.dbg')
        with self.assertRaisesRegex(ValueError, 'identities'):
            N.debug_binding(normal, elf({'.note.gnu.build-id': b'different build identity'}), 'libcoreclr.so.dbg')
        with self.assertRaisesRegex(ValueError, 'sidecar link'):
            N.debug_binding(normal, debug, 'unrelated.dbg')

    def test_truncated_elf_section_table_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'section table'):
            N.sections(elf({'.note.gnu.build-id': b'id'})[:-1])

    def test_an_additional_nonfallback_version_identity_is_rejected(self):
        marker = b'@(#)Version 6.0.3626.55901 @Commit: ' + N.COMMIT.encode()
        N.elf_version(b'\0' + marker + b'\0', marker)
        for raw in (b'no marker', marker + b'\0@(#)Version 6.0.1.2 @Commit: other\0',
                    b'@(#)Version 42.42.42.42424 @Commit: other\0'):
            with self.subTest(raw=raw[:30]), self.assertRaisesRegex(ValueError, 'version identities'):
                N.elf_version(raw, marker)

    def inventory(self):
        members = {name: N.fingerprint(name.encode()) for name in N.PRODUCTS}
        actual = {'shared/Microsoft.NETCore.App/6.0.36/' + name: row for name, row in members.items()}
        return members, actual

    def test_final_sdk_requires_every_native_product_and_all_duplicate_copies(self):
        members, actual = self.inventory()
        with patch.object(N, 'validate_native_only', return_value=dict(members=members, fullSdkConsumption=False)):
            self.assertTrue(N.validate(None, None, None, None, actual)['fullSdkConsumption'])
            del actual['shared/Microsoft.NETCore.App/6.0.36/libcoreclr.so']
            with self.assertRaisesRegex(ValueError, 'all five'):
                N.validate(None, None, None, None, actual)
        members, actual = self.inventory()
        actual['sdk/6.0.136/other/libclrjit.so'] = N.fingerprint(b'old fallback native product')
        with patch.object(N, 'validate_native_only', return_value=dict(members=members, fullSdkConsumption=False)):
            with self.assertRaisesRegex(ValueError, 'different native'):
                N.validate(None, None, None, None, actual)

    def test_native_only_proof_cannot_admit_an_sdk_without_actual_inventory(self):
        with self.assertRaisesRegex(ValueError, 'Actual final SDK'):
            N.validate(None, None, None, None)

    def test_archived_source_mount_cannot_be_substituted_or_shadowed(self):
        from types import SimpleNamespace
        B = SimpleNamespace(P=SimpleNamespace(DOCKER_ENGINE=['docker']))
        manifest = dict(roots=[dict(name='runtime', originalPath='/host/work/work/runtime')])
        command = ['docker', 'run', '--volume', '/host/work:/work', 'sha256:builder', 'python3',
                   '/project/scripts/musl-legacy6-coreclr.py', '--sdk', N.SDK, '--arch', 'aarch64',
                   '--source', '/work/work/runtime', '--dotnet', '/bootstrap/dotnet',
                   '--output', '/delivery/reports/build/native-runtime', '--build-id', '20261109.1']
        prepare = dict(imageId='sha256:builder')
        N.build_boundary(B, manifest, dict(build=dict(commands=[command])), prepare, 'aarch64', '20261109.1')
        for mount in ('/other:/work', '/host/work:/other'):
            changed = command.copy(); changed[3] = mount
            with self.subTest(mount=mount), self.assertRaisesRegex(ValueError, 'exact archived'):
                N.build_boundary(B, manifest, dict(build=dict(commands=[changed])), prepare, 'aarch64', '20261109.1')
        changed = command[:4] + ['--volume', '/other:/work/work/runtime/src'] + command[4:]
        with self.assertRaisesRegex(ValueError, 'shadows'):
            N.build_boundary(B, manifest, dict(build=dict(commands=[changed])), prepare, 'aarch64', '20261109.1')
        for alias in (['-v', '/hidden:/work/work/runtime/src'], ['-v/hidden:/work/work/runtime/src'],
                      ['--volume=/hidden:/work/work/runtime/src'],
                      ['--mount', 'type=bind,src=/hidden,dst=/work/work/runtime/src'], ['--volumes-from=other']):
            changed = command[:4] + alias + command[4:]
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                N.build_boundary(B, manifest, dict(build=dict(commands=[changed])), prepare, 'aarch64', '20261109.1')


if __name__ == '__main__':
    unittest.main()
