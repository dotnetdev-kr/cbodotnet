import copy
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_construction_inputs as C


class ConstructorBindings(unittest.TestCase):
    def archive(self, directory, name, managed):
        path = directory / name
        with tarfile.open(path, 'w:gz') as archive:
            for member, raw in [('shared/Microsoft.NETCore.App/5.0.17/libcoreclr.so', b'\x7fELFsame native'),
                                ('sdk/5.0.214/managed.dll', managed)]:
                entry = tarfile.TarInfo(member); entry.size = len(raw); archive.addfile(entry, io.BytesIO(raw))
        return path

    def test_old_archive_cannot_replace_actual_managed_bytes_with_same_native(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); old = self.archive(directory, 'old.tar.gz', b'MZold managed'); new = self.archive(directory, 'new.tar.gz', b'MZnew managed')
            old_fp, new_fp = C.fingerprint(old), C.fingerprint(new)
            record = dict(sdkVersion=C.SDK, architecture='aarch64', sdk=dict(name=new.name, **new_fp))
            C.validate_final_sdk_archive(record, dict(sdkArchive=dict(path=new.name, **new_fp)))
            self.assertEqual(C.B.members(old, 'sdk')['shared/Microsoft.NETCore.App/5.0.17/libcoreclr.so'],
                             C.B.members(new, 'sdk')['shared/Microsoft.NETCore.App/5.0.17/libcoreclr.so'])
            for descriptor in (dict(path=old.name, **old_fp), dict(path=new.name, **old_fp),
                               dict(path=new.name, **dict(new_fp, sha512=old_fp['sha512']))):
                with self.subTest(descriptor=descriptor), self.assertRaisesRegex(ValueError, 'exact final archive'):
                    C.validate_final_sdk_archive(record, dict(sdkArchive=descriptor))

    def fixture(self):
        roots = {name: dict(kind='git', commit=pin) for name, pin in C.COMMITS.items()}
        artifacts = {}
        for name, kind, source in [('toolset', 'sdk-toolset', 'sdk'), ('runtime', 'official-runtime', 'runtime'),
            ('aspnet', 'official-aspnet', 'aspnetcore'), ('crypto', 'native-crypto', 'runtime'),
            ('original-sdk-comparison', 'official-sdk-comparison', 'installer'),
            ('source-crossgen', 'native-crossgen-construction-input', 'runtime'), ('translations', 'nuget-translation-data', 'nuget')]:
            artifacts[name] = dict(path=name+'.input', kind=kind, sourceRoot=source, sourceCommit=C.COMMITS[source],
                                  bytes=10, sha256='1'*64, sha512='2'*128)
        artifacts['runtime']['sha512'] = C.BOOT.pin('runtime', 'aarch64')['sha512']
        artifacts['aspnet']['sha512'] = C.ASPNET_SHA512['aarch64']
        artifacts['original-sdk-comparison'].update(sha512=C.COMPILERS.SDK_HASHES['aarch64'], constructionOnly=True)
        artifacts['source-crossgen'].update(path='reports/build/native-runtime/crossgen', constructionOnly=True)
        for name in C.NATIVE.SHIPPING:
            artifacts['native-'+name] = dict(path='reports/build/native-runtime/'+name, kind='native-coreclr',
                sourceRoot='runtime', sourceCommit=C.COMMITS['runtime'], bytes=10, sha256='1'*64, sha512='2'*128)
        return artifacts, roots, dict(architecture='aarch64'), dict(transformations=[], generatedOutputs=[])

    def test_named_roles_cardinality_and_framework_pins_are_closed(self):
        artifacts, roots, record, installer = self.fixture()
        C.validate_artifact_roles(artifacts, roots, {}, record, installer)
        for name, edit in [('framework-kind-flip', lambda a: a['runtime'].update(kind='generated-installer-data')),
            ('wrong-official-hash', lambda a: a['aspnet'].update(sha512='0'*128)),
            ('native-removed', lambda a: a.pop('native-libcoreclr.so')),
            ('extra-native-role', lambda a: a.update(extra=dict(a['native-libcoreclr.so'], path='extra.input'))),
            ('construction-payload-flip', lambda a: a['source-crossgen'].update(constructionOnly=False))]:
            changed = copy.deepcopy(artifacts); edit(changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                C.validate_artifact_roles(changed, roots, {}, record, installer)

    def test_source_role_and_duplicate_path_cannot_replace_named_origin(self):
        artifacts, roots, record, installer = self.fixture()
        for edit in (lambda a: a['runtime'].update(sourceRoot='installer', sourceCommit=C.COMMITS['installer']),
                     lambda a: a['runtime'].update(path=a['aspnet']['path'])):
            changed = copy.deepcopy(artifacts); edit(changed)
            with self.assertRaises(ValueError): C.validate_artifact_roles(changed, roots, {}, record, installer)

    def test_toolset_equals_compiler_package_including_sha512(self):
        artifacts, _, _, _ = self.fixture(); package = dict(artifacts['toolset'])
        compiler = dict(sdk=dict(proof=dict(packages=[package])))
        C.validate_toolset_binding(artifacts, compiler)
        package['sha512'] = '0'*128
        with self.assertRaises(ValueError): C.validate_toolset_binding(artifacts, compiler)

    def test_generated_data_cannot_impersonate_managed_code_outside_sdk_prefix(self):
        name = 'shared/Microsoft.AspNetCore.App/5.0.17/foreign.dll'; identity = dict(bytes=20, sha256='1'*64, signature='4d5a0000')
        proof = dict(layout=[dict(path=name, input='generated', member=name)])
        with self.assertRaisesRegex(ValueError, 'impersonate managed code'):
            C.validate_layout(proof, dict(generated=dict(kind='generated-installer-data')),
                dict(generated={name: identity}), {name: identity}, dict(transformations=[], generatedOutputs=[dict(archivePath=name)]))

    def test_snapshot_extra_and_missing_final_layout_members_reject(self):
        name = 'sdk/5.0.214/original.json'; identity = dict(bytes=20, sha256='1'*64, signature='7b202020')
        proof = dict(layout=[dict(path=name, input='generated', member=name)])
        artifacts = dict(generated=dict(kind='generated-installer-data')); inventories = dict(generated={name: identity}); actual = {name: identity}
        installer = dict(transformations=[], generatedOutputs=[dict(archivePath=name)])
        C.validate_layout(proof, artifacts, inventories, actual, installer)
        with self.assertRaises(ValueError): C.validate_layout(dict(layout=[]), artifacts, inventories, actual, installer)
        with self.assertRaises(ValueError): C.validate_layout(proof, artifacts, dict(generated=dict(inventories['generated'], extra=identity)), actual, installer)


if __name__ == '__main__': unittest.main()
