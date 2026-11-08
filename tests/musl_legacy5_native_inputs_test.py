import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_legacy5_native_inputs as N


class SDK5NativeInputs(unittest.TestCase):
    def version_fixture(self):
        result = dict(runtimeAssemblyVersion='5.0', nativeFileVersion='5.0.1.2', buildId='20261109.1')
        header = b'\n'.join(('#define ' + name + ' ' + value).encode() for name, value in [
            ('RuntimeAssemblyMajorVersion', '5'), ('RuntimeAssemblyMinorVersion', '0'),
            ('RuntimeFileMajorVersion', '5'), ('RuntimeFileMinorVersion', '0'), ('RuntimeFileBuildVersion', '1'),
            ('RuntimeFileRevisionVersion', '2'), ('RuntimeProductVersion', '5.0.17')]) + b'\n'
        marker = ('@(#)Version 5.0.1.2 @Commit: ' + N.COMMIT).encode(); return header, marker, result

    def test_actual_compiled_version_must_match_both_original_inputs(self):
        header, marker, result = self.version_fixture()
        self.assertEqual(N.versions(marker, header, marker, header, result), marker)
        with self.assertRaises(ValueError): N.versions(marker, header, b'42.42.42.42424', header, result)
        with self.assertRaises(ValueError): N.versions(marker, header, marker, header + b'changed', result)

    def test_runtime_abi_and_source_version_cannot_be_relabelled(self):
        header, marker, result = self.version_fixture()
        with self.assertRaises(ValueError): N.versions(marker, header, marker, header, dict(result, runtimeAssemblyVersion='6.0'))
        changed = marker.replace(N.COMMIT.encode(), b'0' * 40)
        with self.assertRaises(ValueError): N.versions(changed, header, changed, header, result)

    def test_every_elf_version_marker_is_significant(self):
        header, marker, result = self.version_fixture(); N.elf_version(marker + b'\0', marker)
        for raw in (marker + b'\0' + marker + b'\0', marker + b'\0@(#)Version 42.42.42.42424 @Commit: other\0', b'no marker'):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError): N.elf_version(raw, marker)

    def compiler_fixture(self, file='src/coreclr/src/vm/object.cpp', flags='-O3 -O3'):
        source = '/work/work/runtime'; obj = source + '/artifacts/obj/coreclr/Linux.arm64.Release'
        row = dict(directory=obj, file=source + '/' + file, output='object.o',
            command='/usr/lib/llvm20/bin/clang++ ' + flags + ' -o object.o -c ' + source + '/' + file)
        return row, source, obj

    def test_later_optimization_override_is_rejected(self):
        row, source, obj = self.compiler_fixture(); N.compiler_row(row, source, obj)
        for flag in ('-O0', '-O1', '-Os', '-Oz', '-Ofast'):
            changed = dict(row, command=row['command'] + ' ' + flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError): N.compiler_row(changed, source, obj)

    def test_only_original_unused_asmparse_has_o0(self):
        row, source, obj = self.compiler_fixture('src/coreclr/src/ilasm/prebuilt/asmparse.cpp', '-O3 -O3 -O0')
        N.compiler_row(row, source, obj)
        changed = dict(row, file=source + '/src/coreclr/src/vm/object.cpp', command=row['command'].replace('ilasm/prebuilt/asmparse.cpp', 'vm/object.cpp'))
        with self.assertRaises(ValueError): N.compiler_row(changed, source, obj)

    def test_source_and_output_escape_or_duplicate_operand_rejected(self):
        row, source, obj = self.compiler_fixture()
        for changed in (dict(row, output='../../../../host.o'), dict(row, directory='/foreign'),
                        dict(row, command=row['command'] + ' -c ' + row['file'])):
            with self.assertRaises(ValueError): N.compiler_row(changed, source, obj)

    def test_both_actual_reviewed_patches_keep_their_exact_target_sets(self):
        for path, (sha, targets) in N.PATCHES.items():
            raw = (ROOT / path).read_bytes(); self.assertEqual(tuple(N.patch_sections(raw, targets)), targets)
            with self.assertRaises(ValueError): N.patch_sections(raw, targets + ('unexpected.cpp',))

    def test_every_final_sdk_native_copy_is_checked(self):
        members = {name: dict(bytes=10, sha256=name, sha512=name) for name in N.PRODUCTS}
        proof = dict(members=members, archivedSourceClosure=True)
        actual = {'shared/Microsoft.NETCore.App/5.0.17/' + name: dict(members[name]) for name in N.SHIPPING}
        with patch.object(N, 'validate_native_only', return_value=proof):
            self.assertTrue(N.validate('unused', {}, {}, {}, actual=actual)['fullSdkConsumption'])
            changed = copy.deepcopy(actual); changed['elsewhere/libcoreclr.so'] = dict(bytes=10, sha256='different')
            with self.assertRaises(ValueError): N.validate('unused', {}, {}, {}, actual=changed)
            with self.assertRaises(ValueError): N.validate('unused', {}, {}, {}, actual=dict(actual, crossgen=members['crossgen']))

    def test_original_windows_checkout_encoding_does_not_allow_source_edits(self):
        P = N.module('sdk5_original_native_encoding_test', 'package-used-source.py')
        original = b'original line\nsecond line\n'
        blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
        for name in ('runtime/build.cmd', 'runtime/build.bat', 'runtime/project.sln'):
            row = dict(path=name, mode='100644', baseline=dict(mode='100644', blob=blob))
            self.assertTrue(N.pristine_runtime(P, row, original.replace(b'\n', b'\r\n')))
            self.assertFalse(N.pristine_runtime(P, row, b'changed\r\nsecond line\r\n'))
        row = dict(path='runtime/implementation.cpp', mode='100644', baseline=dict(mode='100644', blob=blob))
        self.assertFalse(N.pristine_runtime(P, row, original.replace(b'\n', b'\r\n')))


if __name__ == '__main__': unittest.main()
