"""Reject incomplete, relabeled or byte-unbound legacy producer evidence."""
import copy
import difflib
import hashlib
import importlib.util
import io
import json
import struct
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_legacy_admission as M
import musl_legacy_nuget_evidence as N


class ResourceDataBoundary(unittest.TestCase):
    def fixture(self, value='Texte traduit'):
        def text(value, encoding='utf-8'):
            data = value.encode(encoding)
            self.assertLess(len(data), 128)
            return bytes([len(data)]) + data
        manager = text('System.Resources.ResourceReader, mscorlib') + text('System.Resources.RuntimeResourceSet')
        header = struct.pack('<Iii', 0xbeefcace, 1, len(manager)) + manager + struct.pack('<iii', 2, 1, 0)
        header += b'\0' * (-len(header) % 8)
        name = text('Message', 'utf-16-le') + struct.pack('<i', 0)
        data = b'\x01' + text(value)
        return header + struct.pack('<iii', 0, 0, len(header) + 12 + len(name)) + name + data

    def test_intrinsic_strings_are_recomputed_without_loading_assemblies(self):
        actual = M.resource_strings(self.fixture())
        self.assertEqual({'Message': dict(value='Texte traduit',
            keySha256=hashlib.sha256(b'Message').hexdigest(),
            valueSha256=hashlib.sha256('Texte traduit'.encode()).hexdigest())}, actual)

    def test_serialized_objects_custom_readers_and_trailing_data_are_rejected(self):
        original = self.fixture()
        for data in (original + b'opaque', original[:-1], original[:-len('Texte traduit') - 2] + b'\x40\x00',
                     original.replace(b'System.Resources.ResourceReader,', b'System.Resources.MalwareReader,')):
            with self.subTest(data=data[-20:]), self.assertRaises((ValueError, UnicodeDecodeError)):
                M.resource_strings(data)

    def test_unknown_or_modified_schema_and_native_pe_are_rejected(self):
        for pristine, embedded in ((b'<schema/>', b'<schema/>'), (b'<!DOCTYPE a><schema/>', b'<schema/>')):
            with self.assertRaisesRegex(ValueError, 'Unreviewed NuGet metadata schema'):
                M.validate_schema_equivalence(pristine, embedded)
        for data in (b'not PE', b'MZ' + b'\0' * 100):
            with self.assertRaises(ValueError):
                M.resource_only_pe(data)

    def test_derived_forwarder_role_cannot_hide_executable_or_unreviewed_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'reports').mkdir()
            (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=[])))
            name = 'sdk/7.0.120/System.Memory.dll'
            row = dict(path=name, origin='derived-facade-metadata-source', sourceRoot=M.FACADE_INPUTS.ROOT_NAME,
                sourceCommit=None, packagePath='unchanged-original.nupkg', packageMember='System.Memory.dll')
            roots = {M.FACADE_INPUTS.ROOT_NAME: dict(kind='tree', role=M.FACADE_INPUTS.ROLE, commit=None)}
            policy = dict(kind=M.FACADE_INPUTS.KIND, basis='full-derived-facade-IL', products={})
            with self.assertRaisesRegex(ValueError, 'exact independently validated literal'):
                M.validate_managed_shipping(root, [row], {name:dict(bytes=1,sha256='0'*64)}, {}, {}, roots,
                    dict(sdkVersion='7.0.120'), facade_policy=policy)
            roots[M.FACADE_INPUTS.ROOT_NAME]['kind'] = 'git'
            with self.assertRaisesRegex(ValueError, 'non-Git literal metadata'):
                M.validate_managed_shipping(root, [row], {name:dict(bytes=1,sha256='0'*64)}, {}, {}, roots,
                    dict(sdkVersion='7.0.120'), facade_policy=policy)

    def test_preferred_implementation_il_cannot_cover_unreviewed_real_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'reports').mkdir()
            (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=[])))
            name = 'sdk/7.0.120/System.Memory.dll'
            row = dict(path=name, origin='upstream-framework-implementation-il', sourceRoot='assets',
                sourceCommit=M.FRAMEWORK_IL_INPUTS.COMMIT, packagePath='original.nupkg', packageMember='original.dll',
                dataRoot=M.FRAMEWORK_IL_INPUTS.ROOT_NAME, canonicalPrimaryPackagePath='original.nupkg',
                canonicalPrimaryMember='original.dll')
            roots = dict(assets=dict(kind='git', commit=M.FRAMEWORK_IL_INPUTS.COMMIT))
            policy = dict(kind=M.FRAMEWORK_IL_INPUTS.KIND, basis='upstream-full-IL-source', products={})
            with self.assertRaisesRegex(ValueError, 'independently validated 27 implementations'):
                M.validate_managed_shipping(root, [row], {name:dict(bytes=1,sha256='0'*64)}, {}, {}, roots,
                    dict(sdkVersion='7.0.120'), framework_policy=policy)
            row['componentSource'] = dict(sourceCommit='0'*40)
            with self.assertRaisesRegex(ValueError, 'Shipping managed source coverage'):
                M.validate_managed_shipping(root, [row], {name:dict(bytes=1,sha256='0'*64)}, {}, {}, roots,
                    dict(sdkVersion='7.0.120'), framework_policy=policy)

    def test_closed_missing_identity_policy_cannot_infer_an_arbitrary_component(self):
        data = b'bounded metadata parser exercised independently'
        metadata = dict(attributes={})
        name = 'sdk/7.0.120/Unreviewed.Real.Code.dll'
        source = dict(sourceRoot='unknown', sourceCommit='a'*40, basis='publisher-declared-original-source-gitlink')
        row = dict(path=name, origin='imported-package', sourceRoot='container', sourceCommit='c'*40,
                   packagePath='original.nupkg', packageMember='lib/unknown.dll', componentSource=source)
        forged = dict(kind=M.ATTRIBUTED_COMPONENTS.KIND, products={name:dict(source, packageSha256='b'*64,
            packageMember=row['packageMember'], fingerprint=M.ATTRIBUTED_COMPONENTS.fingerprint(data), metadata=metadata)})
        with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata), self.assertRaisesRegex(ValueError, 'exact independently validated'):
            M.validate_imported_component(data, row, dict(unknown=dict(kind='git', commit='a'*40)),
                package_fp=dict(sha256='b'*64), attributed_policy=forged)


class RestoredComponentInputBoundary(unittest.TestCase):
    """Exercise restored-primary selection without treating layout artifacts as provenance."""
    def fixture(self, directory):
        restored, products, shipping, roots = [], {}, [], []
        packages = {}
        for number in range(3):
            path = directory / ('primary-' + str(number) + '.nupkg')
            path.write_bytes(('ordinary selector input ' + str(number)).encode())
            fp = M.fingerprint(path); packages[fp['sha256']] = fp
            restored.append(dict(retained=path.name, **fp))
            roots.append(dict(name='source-' + str(number), kind='git', commit=str(number + 1) * 40))
        for number in range(8):
            index = number % 3; sha = restored[index]['sha256']
            name = 'sdk/7.0.120/Component' + str(number) + '.dll'
            source = dict(sourceRoot=roots[index]['name'], sourceCommit=roots[index]['commit'], basis='reviewed-original-source')
            products[name] = dict(source, packageSha256=sha, packageMember='lib/Component' + str(number) + '.dll')
            shipping.append(dict(path=name, origin='imported-package', sourceRoot=source['sourceRoot'],
                sourceCommit=source['sourceCommit'], packagePath=restored[index]['retained'],
                packageMember=products[name]['packageMember'], componentSource=source))
        return dict(packages=packages, products=products), dict(kind=M.ATTRIBUTED_COMPONENTS.KIND, products=products), restored, shipping, dict(roots=roots)

    def run_fixture(self, directory, fixture):
        policy, validated, restored, shipping, manifest = fixture
        with mock.patch.object(M.ATTRIBUTED_COMPONENTS, 'policy', return_value=policy), \
             mock.patch.object(M.ATTRIBUTED_COMPONENTS, 'validate', return_value=validated) as validate:
            result = M.validate_attributed_inputs(directory, manifest, restored, shipping)
        self.assertEqual(validated, result)
        self.assertEqual({row['sha256']:directory / row['retained'] for row in restored}, validate.call_args.args[2])
        return result

    def test_canonical_primary_inputs_need_no_duplicate_layout_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.run_fixture(root, self.fixture(root))

    def test_missing_duplicate_and_same_hash_at_another_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            cases = []
            missing = copy.deepcopy(original); missing[2].pop(); cases.append(missing)
            duplicate = copy.deepcopy(original); duplicate[2].append(dict(duplicate[2][0])); cases.append(duplicate)
            alias = copy.deepcopy(original); alias[2].append(dict(alias[2][0], retained='another-path.nupkg')); cases.append(alias)
            forged_alias = copy.deepcopy(alias); forged_alias[2][-1]['sha512'] = 'f' * 128; cases.append(forged_alias)
            for fixture in cases:
                with self.subTest(restored=fixture[2]), self.assertRaisesRegex(ValueError, 'unique exact actual restored'):
                    self.run_fixture(root, fixture)

    def test_size_both_hashes_and_actual_retained_bytes_are_rechecked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            for field, value in [('bytes', 0), ('sha256', 'f' * 64), ('sha512', 'f' * 128)]:
                fixture = copy.deepcopy(original); fixture[2][0][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'unique exact actual restored'):
                    self.run_fixture(root, fixture)
            (root / original[2][0]['retained']).write_bytes(b'tampered after restore')
            with self.assertRaisesRegex(ValueError, 'Bound legacy artifact bytes differ'):
                self.run_fixture(root, original)

    def test_missing_duplicate_or_repointed_shipping_rows_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            missing = copy.deepcopy(original); missing[3].pop()
            duplicate = copy.deepcopy(original); duplicate[3].append(dict(duplicate[3][0]))
            for fixture in (missing, duplicate):
                with self.assertRaisesRegex(ValueError, 'unique actual shipping'):
                    self.run_fixture(root, fixture)
            for field, value in [('packagePath', 'alias.nupkg'), ('packageMember', 'lib/other.dll'), ('origin', 'rebuilt-sdk')]:
                fixture = copy.deepcopy(original); fixture[3][0][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'canonical restored primary'):
                    self.run_fixture(root, fixture)

    def test_forged_source_roots_commits_and_basis_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            for field, value in [('sourceRoot', 'undeclared'), ('sourceCommit', 'f' * 40), ('basis', 'unreviewed')]:
                fixture = copy.deepcopy(original); fixture[3][0]['componentSource'][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source membership differs'):
                    self.run_fixture(root, fixture)
            for kind in ('tree', 'undeclared-git-kind'):
                fixture = copy.deepcopy(original); fixture[4]['roots'][0]['kind'] = kind
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'source membership differs'):
                    self.run_fixture(root, fixture)
            for field, value in [('sourceRoot', 'undeclared'), ('sourceCommit', 'f' * 40)]:
                fixture = copy.deepcopy(original); fixture[3][0][field] = value
                with self.subTest(containerField=field), self.assertRaisesRegex(ValueError, 'source membership differs'):
                    self.run_fixture(root, fixture)


class ReviewedRestoredLeafBoundary(unittest.TestCase):
    """Test canonical source/member bindings; full leaf decoding has separate archive proofs."""
    def fixture(self, root):
        identities, sources, restored, shipping, actual, roots = [], [], [], [], {}, []
        for number in range(4):
            path = root / ('reviewed-' + str(number) + '.nupkg')
            payload = ('literal binding fixture ' + str(number)).encode()
            with zipfile.ZipFile(path, 'w') as package: package.writestr('lib/member.dll', payload)
            identity = M.fingerprint(path); identities.append(identity)
            restored.append(dict(retained=path.name, **identity))
            name = 'sdk/7.0.120/Reviewed' + str(number) + '.dll'
            source = dict(sourceRoot='source-' + str(number), sourceCommit=str(number + 1) * 40,
                          allowedLayoutPaths=[name] if number else [],
                          products={name:M.ATTRIBUTED_COMPONENTS.fingerprint(payload)} if number else {})
            sources.append(source); roots.append(dict(name=source['sourceRoot'], kind='git', commit=source['sourceCommit']))
            if number:
                actual[name] = M.ATTRIBUTED_COMPONENTS.fingerprint(payload)
                shipping.append(dict(path=name, origin='imported-package', packagePath=path.name,
                    packageMember='lib/member.dll', sourceRoot=source['sourceRoot'], sourceCommit=source['sourceCommit']))
        return identities, sources, restored, shipping, actual, dict(roots=roots)

    def run_fixture(self, root, fixture, local_vstest=None, transformed=None, artifacts=None):
        identities, sources, restored, shipping, actual, manifest = fixture
        with mock.patch.object(M, 'NETSTANDARD21', identities[0]), mock.patch.object(M, 'CSS_PARSER', identities[1]), \
             mock.patch.object(M.MSBUILD_RESOURCES, 'PACKAGE', identities[2]), \
             mock.patch.object(M.GLOBBING_INPUTS, 'policy', return_value=dict(package=identities[3])), \
             mock.patch.object(M, 'validate_netstandard_source_chain', return_value=sources[0]) as netstandard, \
             mock.patch.object(M, 'validate_css_source_chain', return_value=sources[1]) as css, \
             mock.patch.object(M.MSBUILD_RESOURCES, 'validate', return_value=sources[2]) as msbuild, \
             mock.patch.object(M.GLOBBING_INPUTS, 'validate', return_value=sources[3]) as globbing:
            reviewed, paths = M.validate_reviewed_shipping_inputs(root, manifest, restored)
            M.validate_reviewed_shipping_bindings(root, manifest, reviewed, paths, shipping, actual, local_vstest, transformed, artifacts)
            for index, validate in enumerate((netstandard, css, msbuild, globbing)):
                validate.assert_called_once_with(root, manifest, root / restored[index]['retained'])
        self.assertEqual({identity['sha256']:source for identity, source in zip(identities, sources)}, reviewed)
        self.assertEqual({row['sha256']:row['retained'] for row in restored}, paths)

    def test_all_four_full_source_validators_use_canonical_restored_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.run_fixture(root, self.fixture(root))

    def test_missing_duplicate_and_altered_primary_descriptors_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            for mode in ('missing', 'duplicate', 'alternate-path', 'sha512'):
                fixture = copy.deepcopy(original)
                if mode == 'missing': fixture[2].pop()
                elif mode == 'duplicate': fixture[2].append(dict(fixture[2][0]))
                elif mode == 'alternate-path': fixture[2].append(dict(fixture[2][0], retained='alias.nupkg'))
                else: fixture[2][0]['sha512'] = 'f' * 128
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'unique exact actual restored'):
                    self.run_fixture(root, fixture)

    def test_forged_source_member_bytes_and_membership_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = self.fixture(root)
            for field, value in [('packageMember', 'lib/forged.dll'), ('packagePath', 'alias.nupkg'),
                                 ('sourceRoot', 'undeclared'), ('sourceCommit', 'f' * 40)]:
                fixture = copy.deepcopy(original); fixture[3][0][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source/package/member differs'):
                    self.run_fixture(root, fixture)
            fixture = copy.deepcopy(original); next(iter(fixture[4].values()))['sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'source/package/member differs'):
                self.run_fixture(root, fixture)
            fixture = copy.deepcopy(original); fixture[5]['roots'][0]['kind'] = 'tree'
            with self.assertRaisesRegex(ValueError, 'original source membership'):
                self.run_fixture(root, fixture)

    def test_globbing_keeps_genuine_vstest_copy_origin_separate_from_primary_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture = self.fixture(root)
            source = fixture[1][3]; row = fixture[3][-1]
            member = 'contentFiles/any/net7.0/Microsoft.Extensions.FileSystemGlobbing.dll'
            package = root / 'genuine-vstest.nupkg'
            with zipfile.ZipFile(root / row['packagePath']) as original: raw = original.read(row['packageMember'])
            with zipfile.ZipFile(package, 'w') as archive: archive.writestr(member, raw)
            row.update(packagePath=package.name, packageMember=member, sourceRoot='vstest', sourceCommit=M.VSTEST7_COMMIT,
                       componentSource=dict(sourceRoot=source['sourceRoot'], sourceCommit=source['sourceCommit'],
                                            basis='assembly-metadata-commit-hash'))
            fixture[5]['roots'].append(dict(name='vstest',kind='git',commit=M.VSTEST7_COMMIT))
            vstest = dict(packagePaths={package.name:M.fingerprint(package)}, importedMembers={
                (package.name,member):dict(sourceCommit=source['sourceCommit'], **M.ATTRIBUTED_COMPONENTS.fingerprint(raw))})
            self.run_fixture(root, fixture, vstest)
            for field, value in [('packagePath','unreviewed.nupkg'), ('packageMember','contentFiles/forged.dll'),
                                 ('sourceCommit','f'*40)]:
                changed = copy.deepcopy(fixture); changed[3][-1][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'genuine VSTest copy origin'):
                    self.run_fixture(root, changed, vstest)
            name = row['path']; original = source['products'][name]
            fixture[4][name] = M.ATTRIBUTED_COMPONENTS.fingerprint(b'observed Globbing ready-to-run output fixture')
            toolset = root / 'actual-toolset.zip'
            with zipfile.ZipFile(toolset,'w') as archive: archive.writestr('lib/globbing.dll',raw)
            artifacts = dict(toolset=dict(path=toolset.name,kind='sdk-toolset',**M.fingerprint(toolset)))
            transformed = {name:dict(archivePath=name,input='toolset',member='lib/globbing.dll',task='Crossgen',context='1:2:3:4',
                inputSha256=original['sha256'],outputSha256=fixture[4][name]['sha256'])}
            self.run_fixture(root,fixture,vstest,transformed,artifacts)
            for field,value in [('inputSha256','f'*64),('outputSha256','f'*64),('context',''),('member','lib/forged.dll')]:
                changed=copy.deepcopy(transformed);changed[name][field]=value
                with self.subTest(r2rField=field),self.assertRaises(ValueError):self.run_fixture(root,fixture,vstest,changed,artifacts)

    def test_original_member_binds_validated_r2r_input_and_actual_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture = self.fixture(root)
            name = fixture[3][0]['path']; original = fixture[4][name]
            fixture[4][name] = M.ATTRIBUTED_COMPONENTS.fingerprint(b'observed R2R output binding fixture')
            transformed = {name:dict(archivePath=name, task='Crossgen', context='1:2:3:4',
                inputSha256=original['sha256'], outputSha256=fixture[4][name]['sha256'])}
            self.run_fixture(root, fixture, transformed=transformed)
            for field, value in [('inputSha256','f'*64), ('outputSha256','f'*64),
                                 ('archivePath','sdk/7.0.120/Another.dll'), ('task','Unreviewed')]:
                changed = copy.deepcopy(transformed); changed[name][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'validated R2R input/output'):
                    self.run_fixture(root, fixture, transformed=changed)


class AttributedR2RProductBoundary(unittest.TestCase):
    """Check original member fingerprints after the separate raw Crossgen task validation."""
    def fixture(self, root):
        names = list(M.ATTRIBUTED_COMPONENTS.policy()['products'])
        products, actual, originals = {}, {}, {}
        for number, name in enumerate(names):
            raw = ('canonical original member ' + str(number)).encode(); originals[name] = raw
            products[name] = dict(fingerprint=M.ATTRIBUTED_COMPONENTS.fingerprint(raw))
            actual[name] = dict(products[name]['fingerprint'])
        name = names[0]; actual[name] = M.ATTRIBUTED_COMPONENTS.fingerprint(b'actual ready-to-run output binding fixture')
        path = root / 'actual-toolset.zip'
        with zipfile.ZipFile(path, 'w') as archive: archive.writestr('lib/original.dll', originals[name])
        artifacts = dict(toolset=dict(path=path.name, kind='sdk-toolset', **M.fingerprint(path)))
        transformed = {name:dict(archivePath=name,input='toolset',member='lib/original.dll',task='Crossgen',context='1:2:3:4',
            inputSha256=products[name]['fingerprint']['sha256'],outputSha256=actual[name]['sha256'])}
        return dict(products=products), dict(kind=M.ATTRIBUTED_COMPONENTS.KIND,products=products), actual, transformed, artifacts

    def run_fixture(self, root, fixture):
        declared, policy, actual, transformed, artifacts = fixture
        with mock.patch.object(M.ATTRIBUTED_COMPONENTS,'policy',return_value=declared):
            M.validate_attributed_products_after_crossgen(root,policy,actual,transformed,artifacts)

    def test_original_source_input_and_actual_r2r_output_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); self.run_fixture(root,self.fixture(root))

    def test_forged_input_output_context_member_and_artifact_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); original=self.fixture(root); name=next(iter(original[3]))
            for field,value in [('inputSha256','f'*64),('outputSha256','f'*64),('context',''),
                                ('member','lib/forged.dll'),('input','not-an-actual-input'),('task','Unreviewed')]:
                fixture=copy.deepcopy(original);fixture[3][name][field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):self.run_fixture(root,fixture)

    def test_complete_original_input_fingerprint_and_unchanged_products_remain_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); original=self.fixture(root);name=next(iter(original[3]))
            fixture=copy.deepcopy(original);fixture[1]['products'][name]['fingerprint']['sha512']='f'*128
            with self.assertRaisesRegex(ValueError,'complete canonical fingerprint'):self.run_fixture(root,fixture)
            fixture=copy.deepcopy(original);unchanged=next(n for n in fixture[2]if n!=name);fixture[2][unchanged]['sha256']='f'*64
            with self.assertRaisesRegex(ValueError,'Untransformed original'):self.run_fixture(root,fixture)


class ElfDataBoundary(unittest.TestCase):
    def fixture(self, needed='libc.musl-aarch64.so.1', version=None):
        strings = b'\0' + needed.encode() + b'\0$ORIGIN\0'
        version_offset = len(strings)
        if version:
            strings += version.encode() + b'\0'
        data = bytearray(1024)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', data, 16, 3, 183)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x400000, 0, len(data), len(data), 4096)
        tags = [(1, 1), (5, 0x400200), (10, len(strings)), (29, len(needed) + 2)]
        if version:
            tags += [(0x6ffffffe, 0x400280), (0x6fffffff, 1)]
            struct.pack_into('<HHIII', data, 640, 1, 1, 1, 16, 0)
            struct.pack_into('<IHHII', data, 656, 0, 0, 2, version_offset, 0)
        tags += [(0, 0)]
        struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 256, 0x400100, 0, len(tags) * 16, len(tags) * 16, 8)
        for index, (tag, value) in enumerate(tags):
            struct.pack_into('<qQ', data, 256 + index * 16, tag, value)
        data[512:512 + len(strings)] = strings
        return data

    def test_dt_needed_runpath_and_version_providers_come_from_actual_elf(self):
        actual = M.elf_dynamic(self.fixture())
        self.assertEqual(['libc.musl-aarch64.so.1'], actual['needed'])
        self.assertEqual(['$ORIGIN'], actual['runpaths'])
        self.assertEqual([], actual['glibcRequirements'])
        abi = M.module('legacy_admission_test_abi', 'musl_archive.py')
        native = M.elf_dynamic(self.fixture('libgcc_s.so.1', 'GLIBC_2.0'))
        self.assertEqual([dict(file='libgcc_s.so.1', version='GLIBC_2.0', disposition='gcc-unwind-abi-label')], abi.reviewed_gcc_abi_labels(native))
        glibc = M.elf_dynamic(self.fixture('libc.so.6', 'GLIBC_2.34'))
        with self.assertRaisesRegex(ValueError, 'genuine glibc'):
            abi.reviewed_gcc_abi_labels(glibc)

    def test_truncated_escaped_or_unterminated_dynamic_metadata_rejects(self):
        data = self.fixture()
        escaped = bytearray(data)
        struct.pack_into('<Q', escaped, 256 + 16 + 8, 0x900000)
        unterminated = bytearray(data)
        length = struct.unpack_from('<Q', data, 256 + 32 + 8)[0]
        unterminated[513:512 + length] = b'A' * (length - 1)
        for changed in (data[:100], escaped, unterminated):
            with self.assertRaises(ValueError):
                M.elf_dynamic(changed)


class NativeSourceBoundary(unittest.TestCase):
    def version_fixture(self):
        header = (b'#define RuntimeAssemblyMajorVersion 7\n#define RuntimeAssemblyMinorVersion 0\n\n'
            b'#define RuntimeFileMajorVersion 7\n#define RuntimeFileMinorVersion 0\n#define RuntimeFileBuildVersion 2026\n'
            b'#define RuntimeFileRevisionVersion 55801\n\n#define RuntimeProductMajorVersion 7\n'
            b'#define RuntimeProductMinorVersion 0\n#define RuntimeProductPatchVersion 20\n\n#define RuntimeProductVersion 7.0.20\n')
        result = dict(runtimeAssemblyVersion='7.0', runtimeVersion='7.0.20', nativeFileVersion='7.0.2026.55801',
            sourceCommit=M.POLICIES['7.0.120']['runtimeCommit'], buildId='20261108.1')
        marker = b'@(#)Version 7.0.2026.55801 @Commit: ' + result['sourceCommit'].encode()
        source = b'static char sccsid[] __attribute__((used)) = "' + marker + b'";\n'
        return header, source, result, marker

    def test_original_generated_version_templates_bind_all_macros_and_result_identities(self):
        header, source, result, marker = self.version_fixture()
        self.assertEqual(marker, M.native_version_marker(header, source, result))
        for h, s, r in [(header.replace(b'55801', b'55802'), source, result),
                        (header + b'#define RuntimeFileBuildVersion 2026\n', source, result),
                        (header, source + b'void unrelated_code() {}\n', result),
                        (header, source.replace(b'7.0.2026.55801', b'42.42.42.42424'), result),
                        (header.replace(b'7.0.20', b'7.0.21'), source, result),
                        (header, source, dict(result, nativeFileVersion='7.0.2026.55802'))]:
            with self.subTest(header=h[-40:], source=s[-40:]), self.assertRaises(ValueError):
                M.native_version_marker(h, s, r)

    def test_each_native_elf_must_have_one_exact_expected_marker_without_fallback_or_mixture(self):
        marker = self.version_fixture()[-1]
        M.validate_native_elf_version(b'\x7fELF\0' + marker + b'\0', marker)
        for raw in (b'no marker', marker + b'\0' + marker + b'\0',
                    marker + b'\0@(#)Version 7.0.2026.55901 @Commit: other\0',
                    marker + b'\0fallback 42.42.42.42424\0', marker.replace(b'55801', b'55802') + b'\0'):
            with self.subTest(raw=raw[-50:]), self.assertRaises(ValueError):
                M.validate_native_elf_version(raw, marker)

    def test_all_four_native_shipping_targets_must_compile_the_original_dated_version_source(self):
        source = '/work/work/runtime'; obj = source + '/artifacts/obj/coreclr/Linux.arm64.Release'
        version = source + '/artifacts/obj/_version.c'; rows = []
        for library, relative in M.NATIVE_CORECLR.items():
            target = library.removeprefix('lib').removesuffix('.so')
            directory = obj + '/' + relative.rsplit('/', 1)[0]
            rows.append(dict(directory=directory, file=version,
                command='clang -O3 -O3 -o CMakeFiles/' + target + '.dir/' + version.lstrip('/') + '.o -c ' + version,
                output=directory + '/CMakeFiles/' + target + '.dir/' + version.lstrip('/') + '.o'))
        M.validate_native_version_compilation(rows, source, obj)
        for selected in (rows[:-1], rows + [rows[0]],
                         [dict(row, file=obj + '/version.c') if index == 0 else row for index, row in enumerate(rows)],
                         [dict(row, directory=source + '/unrelated') if index == 0 else row for index, row in enumerate(rows)]):
            with self.assertRaises(ValueError):
                M.validate_native_version_compilation(selected, source, obj)

    def test_original_uppercase_native_release_cache_keeps_target_and_optimization_contract(self):
        cache = dict(CMAKE_BUILD_TYPE='RELEASE', CMAKE_HOME_DIRECTORY='/runtime/src/coreclr',
            CMAKE_EXPORT_COMPILE_COMMANDS='ON', CLR_CMAKE_TARGET_ARCH='arm64')
        M.validate_native_cache(cache, '/runtime', 'aarch64')
        for key, value in [('CMAKE_BUILD_TYPE', 'DEBUG'), ('CMAKE_BUILD_TYPE', 'Release'),
                           ('CMAKE_HOME_DIRECTORY', '/unrelated/src/coreclr'),
                           ('CMAKE_EXPORT_COMPILE_COMMANDS', 'OFF'), ('CLR_CMAKE_TARGET_ARCH', 'x64')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                M.validate_native_cache(dict(cache, **{key: value}), '/runtime', 'aarch64')

    def test_native_compile_output_is_bound_across_cmake_relative_path_bases(self):
        obj = '/runtime/artifacts/obj/coreclr/Linux.arm64.Release'
        row = dict(directory=obj + '/vm', file='/runtime/src/coreclr/vm/threads.cpp',
            command='clang++ -O3 -o CMakeFiles/vm.dir/threads.cpp.o -c /runtime/src/coreclr/vm/threads.cpp',
            output='vm/CMakeFiles/vm.dir/threads.cpp.o')
        rows = [copy.deepcopy(row) for _ in range(100)]
        M.validate_native_compile_commands(rows, '/runtime', obj)
        external = dict(directory='/runtime/artifacts/obj/external/libunwind', file='/runtime/src/native/external/libunwind/src/os-linux.c',
            command='clang -O3 -o CMakeFiles/libunwind.dir/os-linux.c.o -c /runtime/src/native/external/libunwind/src/os-linux.c',
            output='/runtime/artifacts/obj/external/libunwind/CMakeFiles/libunwind.dir/os-linux.c.o')
        M.validate_native_compile_commands(rows + [external], '/runtime', obj)
        for changes in [dict(output='vm/CMakeFiles/vm.dir/unrelated.cpp.o'),
                        dict(output='../../../../../../tmp/threads.cpp.o'),
                        dict(directory='/unrelated/build'), dict(file='/unrelated/threads.cpp'),
                        dict(command=row['command'].replace('-O3', '-O0')),
                        dict(command=row['command'].replace('-O3', '')),
                        dict(command=row['command'].replace('-O3', '-O3 -O1')),
                        dict(command=row['command'].replace('-O3', '-O3 -Og')),
                        dict(command=row['command'].replace('-O3', '-O3 -Ofast')),
                        dict(command=row['command'] + ' -o CMakeFiles/vm.dir/hidden.cpp.o')]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                M.validate_native_compile_commands(rows + [dict(row, **changes)], '/runtime', obj)

    def test_only_original_nonshipping_ilasm_source_may_end_in_o0(self):
        obj = '/runtime/artifacts/obj/coreclr/Linux.arm64.Release'
        path = '/runtime/src/coreclr/ilasm/prebuilt/asmparse.cpp'
        row = dict(directory=obj + '/ilasm', file=path,
            command='clang++ -O3 -O3 -O0 -o CMakeFiles/ilasm.dir/asmparse.cpp.o -c ' + path,
            output='ilasm/CMakeFiles/ilasm.dir/asmparse.cpp.o')
        M.validate_native_compile_commands([copy.deepcopy(row) for _ in range(100)], '/runtime', obj)
        for flags in ('-O0 -O3 -O0', '-O3 -O1 -O0', '-O3 -O0 -Og', '-O0'):
            changed = dict(row, command=row['command'].replace('-O3 -O3 -O0', flags))
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                M.validate_native_compile_commands([copy.deepcopy(changed) for _ in range(100)], '/runtime', obj)

    def test_exact_reviewed_patch_result_recovers_the_original_git_blob(self):
        pristine = b'first\nold\nthird\nfourth\nlast\n'
        actual = b'first\nnew\nadded\nthird\nfourth\nlast\n'
        patch = ''.join(difflib.unified_diff(pristine.decode().splitlines(True), actual.decode().splitlines(True),
                                            fromfile='a/src/file.cpp', tofile='b/src/file.cpp')).encode()
        self.assertEqual(pristine, M.reverse_reviewed_patch(actual, patch, 'src/file.cpp'))
        for body, diff, target in ((actual.replace(b'third', b'changed'), patch, 'src/file.cpp'),
                                    (actual, patch, 'src/unrelated.cpp'),
                                    (actual, patch.replace(b'@@ -1,5 +1,6 @@', b'@@ -1,5 +2,6 @@'), 'src/file.cpp')):
            with self.subTest(target=target), self.assertRaises(ValueError):
                M.reverse_reviewed_patch(body, diff, target)

    def test_native_output_is_an_individual_observed_file_not_an_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'libcoreclr.so'
            path.write_bytes(b'\x7fELFactual-native-product')
            self.assertEqual({'': dict(bytes=25, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), signature='7f454c46')},
                             M.members(path, 'native-coreclr'))

    def test_native_command_log_and_sidecar_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / 'build.log'
            log.write_text('actual original compiler command\n')
            row = dict(name='build', command=['cmake', '--build', '/source/artifacts/obj'], exitCode=0,
                startedAt='2026-11-08T00:00:00+00:00', completedAt='2026-11-08T00:01:00+00:00',
                log='build.log', **M.fingerprint(log))
            sidecar = directory / 'build-command.json'
            sidecar.write_text(json.dumps(row))
            self.assertEqual(row['command'], M.native_command_records(directory, dict(commands=[row]))['build']['command'])
            log.write_text('substituted compiler output\n')
            with self.assertRaisesRegex(ValueError, 'artifact bytes differ'):
                M.native_command_records(directory, dict(commands=[row]))
            log.write_text('actual original compiler command\n')
            sidecar.write_text(json.dumps(dict(row, command=['touch', '/source/libcoreclr.so'])))
            with self.assertRaisesRegex(ValueError, 'sidecar differs'):
                M.native_command_records(directory, dict(commands=[row]))

    def test_scanner_applicability_is_bound_to_the_original_solution_filter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'reports').mkdir(); (root / 'sources').mkdir()
            raw = b'{"solution":{"projects":["src/CLI.csproj","src/Tasks.csproj"]}}'
            report = dict(status='not-applicable', reason='Original regular graph has no VMR scanner', sourceOnly=False,
                importedInputsRequireInventory=True, sourceCommit=M.POLICIES['7.0.120']['sdk'],
                sourceGraph=dict(path='sdk/source-build.slnf', projects=['src/CLI.csproj', 'src/Tasks.csproj'], bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest()))
            (root / 'reports/scan-applicability.json').write_text(json.dumps(report))
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            (root / 'sources/index.jsonl').write_text(json.dumps(dict(path='sdk/source-build.slnf', baseline=dict(blob=blob))) + '\n')
            manifest = dict(index=dict(path='index.jsonl'))
            with mock.patch.object(M, 'source_member', return_value=raw):
                M.validate_scan_applicability(root, dict(sdkVersion='7.0.120'), manifest)
                report['sourceGraph']['projects'].pop()
                (root / 'reports/scan-applicability.json').write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError, 'applicability differs'):
                    M.validate_scan_applicability(root, dict(sdkVersion='7.0.120'), manifest)
                report['sourceGraph']['projects'].append('src/Tasks.csproj')
                (root / 'reports/scan-applicability.json').write_text(json.dumps(report))
                (root / 'sources/index.jsonl').write_text(json.dumps(dict(path='sdk/source-build.slnf', baseline=dict(blob='0' * 40))) + '\n')
                with self.assertRaisesRegex(ValueError, 'pinned Git source'):
                    M.validate_scan_applicability(root, dict(sdkVersion='7.0.120'), manifest)

    def test_vstest_source_scope_cannot_claim_vendor_version_or_full_mono_hosts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / 'reports/build/vstest'; directory.mkdir(parents=True)
            report = dict(schemaVersion=1, kind='legacy-musl-vstest-source-build', status='passed', sdkVersion='7.0.120',
                architecture='aarch64', sourceCommit=M.VSTEST7_COMMIT, sourceGraph='TestPlatform_BuildFromSource.sln',
                version=M.VSTEST7_VERSION, originalSourceBuildFramework='net7.0', originalXlfFiles=247,
                managedPackageMembers=307, sourceCommitAttributedMembers=301,
                importedDependenciesRequireSeparateSourceAttribution=True, originalSourceBuildCoreHostScope=True,
                originalShellUnconditionalClosedCoverageCopyNotUsed=True, compiledResourceAssembliesImported=False,
                fullMonoNetFrameworkTestHostProvided=False, closedCoverageInputImported=False, vendorVersionRelabeled=False,
                readyToRunDisabled=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
            changes = [dict(vendorVersionRelabeled=True), dict(fullMonoNetFrameworkTestHostProvided=True),
                dict(compiledResourceAssembliesImported=True), dict(closedCoverageInputImported=True),
                dict(sourceCommitAttributedMembers=307), dict(originalXlfFiles=234),
                dict(sourceGraph='TestPlatform.sln'), dict(version='17.4.1-release-20230405-06')]
            for change in changes:
                (directory / 'results.json').write_text(json.dumps(dict(report, **change)))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'Original Core VSTest source-build scope'):
                    M.validate_vstest_worker(root, dict(sdkVersion='7.0.120', architecture='aarch64'), {})


class AdmissionBoundary(unittest.TestCase):
    def test_diagnostics_cannot_be_renamed_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = dict(sdkVersion='7.0.120', schemaVersion=2, producerRevision=1,
                kind='musl-sdk-producer-validation', status='passed', diagnosticPodman=False,
                diagnosticPtrace=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
            for changes in (dict(diagnosticPodman=True), dict(diagnosticPtrace=True),
                            dict(sourceAdmissionAllowed=True), dict(qualificationAllowed=True),
                            dict(status='candidate-review-required'), dict(schemaVersion=1)):
                (root / 'producer-validation.json').write_text(json.dumps(dict(base, **changes)))
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'Diagnostic or self-admitted'):
                    M.validate(root)

    def test_unreviewed_sdk6_and_sdk5_original_suites_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for sdk in ('6.0.136', '5.0.214', '7.0.121'):
                (root / 'producer-validation.json').write_text(json.dumps(dict(sdkVersion=sdk, status='passed')))
                with self.assertRaisesRegex(ValueError, 'Unreviewed legacy SDK'):
                    M.validate(root)

    def test_artifact_path_and_fingerprint_cannot_escape_or_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'input.bin'
            path.write_bytes(b'authentic')
            record = dict(path='input.bin', **M.fingerprint(path))
            self.assertEqual(path, M.checked(root, record))
            for change in (dict(path='../input.bin'), dict(path='C:/input.bin'),
                           dict(path='a\\input.bin'), dict(sha512='0' * 128), dict(unreviewed=True)):
                with self.assertRaises(ValueError):
                    M.checked(root, dict(record, **change))
            path.write_bytes(b'counterfeit')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                M.checked(root, record)


class ArchiveAndReplay(unittest.TestCase):
    def tar(self, path, names):
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in names:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def test_complete_member_inventory_detects_duplicates_and_escapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'input.tar.gz'
            self.tar(path, [('a.dll', b'a'), ('b.dll', b'b')])
            self.assertEqual({'a.dll', 'b.dll'}, set(M.members(path, 'sdk')))
            for names in ([('a.dll', b'a'), ('a.dll', b'b')], [('../a.dll', b'a')]):
                self.tar(path, names)
                with self.assertRaises(ValueError):
                    M.members(path, 'sdk')
            with zipfile.ZipFile(root / 'input.zip', 'w') as archive:
                entry = zipfile.ZipInfo('link')
                entry.external_attr = 0o120777 << 16
                archive.writestr(entry, 'outside')
            with self.assertRaisesRegex(ValueError, 'linked'):
                M.members(root / 'input.zip', 'sdk-toolset')

    def test_original_component_version_markers_are_actual_archive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'runtime.tar.gz'
            marker = 'shared/Microsoft.NETCore.App/7.0.20/.version'
            self.tar(path, [(marker, b'own-runtime-source\n7.0.20\n')])
            self.assertEqual(['own-runtime-source', '7.0.20'], M.tar_text(path, marker))
            self.tar(path, [(marker, b'old-bootstrap-source\n7.0.9\n')])
            self.assertNotEqual(['own-runtime-source', '7.0.20'], M.tar_text(path, marker))

    def test_self_labeled_framework_version_does_not_replace_official_archive_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'forged-runtime.tar.gz'
            marker = 'shared/Microsoft.NETCore.App/7.0.20/.version'
            source = M.POLICIES['7.0.120']['runtimeCommit']
            self.tar(path, [(marker, (source + '\n7.0.20\n').encode())])
            self.assertEqual([source, '7.0.20'], M.tar_text(path, marker))
            descriptor = dict(kind='official-runtime', **M.fingerprint(path))
            with self.assertRaisesRegex(ValueError, 'independently reviewed official'):
                M.validate_official_framework(descriptor, dict(sdkVersion='7.0.120', architecture='aarch64'))
            for (kind, architecture), digest in M.SDK7_FRAMEWORK_SHA512.items():
                M.validate_official_framework(dict(kind=kind, sha512=digest), dict(sdkVersion='7.0.120', architecture=architecture))

    def test_replay_must_bind_actual_successful_complete_binlog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'sdk.binlog').write_bytes(b'original successful build log')
            events = [dict(eventNumber=number, timestamp='2026-11-08T00:00:00.0000001Z', kind=kind,
                           field=field, text=text, metadata={}, succeeded=succeeded)
                for number, kind, field, text, succeeded in [(1, 'task-started', None, None, None),
                    (2, 'task-parameter', 'OutputAssembly', '/source/artifacts/obj/dotnet.dll', None),
                    (3, 'task-parameter', 'Sources', 'src/Cli/dotnet/Program.cs', None),
                    (4, 'command-line', None, 'dotnet csc.dll /out:/source/artifacts/obj/dotnet.dll src/Cli/dotnet/Program.cs', None),
                    (5, 'task-finished', None, None, True)]]
            task = dict(context='1:2:3:4', taskName='Csc', projectFile='/source/src/Cli/dotnet.csproj',
                        taskFile='/source/.packages/compilers/Microsoft.CSharp.Core.targets', succeeded=True, events=events)
            (root / 'tasks.jsonl').write_text(json.dumps(task) + '\n')
            base = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
                inputSha256=M.fingerprint(root / 'sdk.binlog')['sha256'],
                compiledOutputs=[dict(archivePath='sdk/7.0.120/dotnet.dll', context='1:2:3:4',
                    outputPath='/source/artifacts/obj/dotnet.dll')], transformations=[], sourceMountRoot='/source',
                tasks=dict(path='tasks.jsonl', **M.fingerprint(root / 'tasks.jsonl')))
            for changes in ({}, dict(inputSha256='0' * 64), dict(completedReplay=False),
                            dict(buildSucceeded=False), dict(unfinishedTasks=1), dict(compiledOutputs=[])):
                path = root / 'replay.json'
                path.write_text(json.dumps(dict(base, **changes)))
                descriptor = dict(path=path.name, **M.fingerprint(path))
                if changes:
                    with self.assertRaises(ValueError):
                        M.validate_replay(root, descriptor, 'sdk.binlog', compiled=True)
                else:
                    self.assertEqual(base, M.validate_replay(root, descriptor, 'sdk.binlog', compiled=True))
            for skip, command in ((True, True), (False, False)):
                changed = copy.deepcopy(task)
                if skip:
                    changed['events'].insert(-1, dict(changed['events'][1], eventNumber=4, field='SkipCompilerExecution', text='True'))
                if not command:
                    changed['events'] = [event for event in changed['events'] if event['kind'] != 'command-line']
                (root / 'tasks.jsonl').write_text(json.dumps(changed) + '\n')
                value = dict(base, tasks=dict(path='tasks.jsonl', **M.fingerprint(root / 'tasks.jsonl')))
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'compiler execution'):
                    M.validate_replay(root, dict(path=path.name, **M.fingerprint(path)), 'sdk.binlog', compiled=True)

    def test_raw_task_boundaries_and_native_crossgen_inputs_are_recomputed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = '/installer'
            archive_path = 'sdk/7.0.120/Roslyn/bincore/csc.dll'
            assembly = source + '/artifacts/bin/redist/Release/dotnet/' + archive_path
            compiler = source + '/.packages//microsoft.netcore.app.crossgen2.linux-musl-arm64/7.0.20/tools/crossgen2'
            parameters = dict(SourceAssembly=assembly, DestinationPath=assembly, ReadyToRun='True',
                              Architecture='arm64', CrossgenPath=compiler)
            def row():
                events = [dict(eventNumber=0, timestamp='2026-11-08T00:00:00.100+00:00', kind='task-started',
                    field=None, text=None, metadata={}, succeeded=None)]
                for name, value in parameters.items():
                    events.append(dict(eventNumber=len(events), timestamp='2026-11-08T00:00:00.1000001+00:00',
                        kind='message', field=None, text='Task Parameter:' + name + '=' + value, metadata={}, succeeded=None))
                events.append(dict(eventNumber=len(events), timestamp='2026-11-08T00:00:00.101+00:00', kind='command-line',
                    field=None, text='> ' + compiler + ' "' + assembly + '" -o "/tmp/compiler/csc.dll" --targetarch arm64', metadata={}, succeeded=None))
                events.append(dict(eventNumber=len(events), timestamp='2026-11-08T00:00:00.102+00:00', kind='task-finished',
                    field=None, text=None, metadata={}, succeeded=True))
                return dict(context='1:2:3:4', taskName='Crossgen', projectFile=source + '/src/redist/redist.csproj',
                    taskFile=source + '/src/redist/targets/Crossgen.targets', succeeded=True, events=events)
            path = root / 'tasks.jsonl'
            task = row()
            path.write_text(json.dumps(task) + '\n')
            tasks = M.read_tasks(path)
            output = dict(context='1:2:3:4', task='Crossgen', archivePath=archive_path, inputPath=assembly, outputPath=assembly)
            record = dict(sdkVersion='7.0.120', architecture='aarch64', targetRid='linux-musl-arm64')
            M.validate_crossgen_task(output, dict(sourceMountRoot=source), tasks, record)
            for values in (dict(Architecture='x64'), dict(ReadyToRun='False'),
                           dict(CrossgenPath=compiler.replace('linux-musl-arm64', 'linux-arm64'))):
                saved = dict(parameters)
                parameters.update(values)
                task = row()
                path.write_text(json.dumps(task) + '\n')
                with self.assertRaises(ValueError):
                    M.validate_crossgen_task(output, dict(sourceMountRoot=source), M.read_tasks(path), record)
                parameters = saved
            task = row()
            for mutation in (lambda item: item['events'].pop(),
                             lambda item: item['events'][-1].__setitem__('succeeded', False),
                             lambda item: item['events'][2].__setitem__('eventNumber', -1)):
                changed = copy.deepcopy(task)
                mutation(changed)
                path.write_text(json.dumps(changed) + '\n')
                with self.assertRaises(ValueError):
                    M.read_tasks(path)

    def test_managed_shipping_requires_every_file_and_actual_package_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reports').mkdir()
            (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=[])))
            name = 'sdk/7.0.120/Unknown.dll'
            actual = {name: dict(bytes=4, sha256=hashlib.sha256(b'code').hexdigest())}
            record = dict(sdkVersion='7.0.120')
            with self.assertRaisesRegex(ValueError, 'Every shipping'):
                M.validate_managed_shipping(root, [], actual, {}, {}, {}, record)
            row = dict(path=name, origin='rebuilt-sdk', sourceRoot='sdk', sourceCommit='a' * 40,
                       packagePath=None, packageMember=None)
            roots = dict(sdk=dict(commit='a' * 40, kind='git'))
            with self.assertRaisesRegex(ValueError, 'observed locally compiled'):
                M.validate_managed_shipping(root, [row], actual, {}, {}, roots, record)
            row['origin'] = 'imported-official-translation-data'
            with self.assertRaisesRegex(ValueError, 'Unreviewed shipping'):
                M.validate_managed_shipping(root, [row], actual, {}, {}, roots, record)

    def test_critical_imported_families_require_their_own_source(self):
        examples = {'NuGet.Common.dll': 'nuget', 'Microsoft.Build.Tasks.Core.dll': 'msbuild',
                    'MSBuild.resources.dll': 'msbuild', 'Microsoft.CodeAnalysis.resources.dll': 'roslyn',
                    'Microsoft.Build.NuGetSdkResolver.dll': 'nuget', 'fsc.dll': 'fsharp',
                    'Microsoft.CodeAnalysis.CSharp.dll': 'roslyn', 'Microsoft.CodeAnalysis.Razor.Compiler.dll': 'razor',
                    'Microsoft.TemplateEngine.Core.dll': 'templating'}
        for filename, family in examples.items():
            self.assertEqual(family, M.shipping_family('sdk/7.0.120/' + filename))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reports').mkdir()
            (root / 'reports/restored-inputs.json').write_text('{"packages": []}')
            name = 'sdk/7.0.120/NuGet.Common.dll'
            row = dict(path=name, origin='imported-package', sourceRoot='unattributed-tree',
                       sourceCommit=None, packagePath='input.nupkg', packageMember='NuGet.Common.dll')
            with self.assertRaisesRegex(ValueError, 'source coverage'):
                M.validate_managed_shipping(root, [row], {name: {}}, {}, {},
                    {'unattributed-tree': dict(kind='tree')}, dict(sdkVersion='7.0.120'))

    def test_unchanged_template_package_has_a_narrow_whole_package_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reports').mkdir()
            package = root / 'template.nupkg'
            commit = 'a' * 40
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('template.nuspec', '<package><metadata><id>template</id><version>1.0</version>'
                    '<repository commit="' + commit + '"/><license type="expression">MIT</license></metadata></package>')
                archive.writestr('content/template.cs', 'source text')
            fp = M.fingerprint(package)
            (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=[dict(retained=package.name, **fp)])))
            name = 'sdk/7.0.120/Templates/template.nupkg'
            identity = dict(bytes=fp['bytes'], sha256=fp['sha256'], signature='504b0304')
            artifact = dict(kind='managed-package', **fp)
            M.validate_layout_member(name, '', artifact, {}, identity)
            row = dict(path=name, origin='imported-package', sourceRoot='templates', sourceCommit=commit,
                       packagePath=package.name, packageMember=None)
            roots = dict(templates=dict(kind='git', commit=commit))
            M.validate_managed_shipping(root, [row], {name: identity}, {}, {}, roots, dict(sdkVersion='7.0.120'))
            for bad_name, bad_member, bad_artifact, bad_actual in (
                (name.replace('.nupkg', '.dll'), '', artifact, identity),
                (name, None, artifact, identity),
                (name, '', dict(artifact, kind='sdk-toolset'), identity),
                (name, '', artifact, dict(identity, sha256='0' * 64)),
                (name, '', artifact, dict(identity, bytes=1))):
                with self.subTest(name=bad_name, member=bad_member), self.assertRaises(ValueError):
                    M.validate_layout_member(bad_name, bad_member, bad_artifact, {}, bad_actual)
            changed = dict(row, path=name.replace('.nupkg', '.dll'))
            with self.assertRaisesRegex(ValueError, 'unchanged actual restored whole nupkg'):
                M.validate_managed_shipping(root, [changed], {changed['path']: identity}, {}, {}, roots, dict(sdkVersion='7.0.120'))
            (root / 'reports/restored-inputs.json').write_text('{"packages": []}')
            with self.assertRaisesRegex(ValueError, 'not actually restored'):
                M.validate_managed_shipping(root, [row], {name: identity}, {}, {}, roots, dict(sdkVersion='7.0.120'))

    def test_netstandard_exception_is_exact_and_requires_both_source_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / 'similar-netstandard.nupkg'
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('NETStandard.Library.Ref.nuspec', '<package><metadata><id>NETStandard.Library.Ref</id>'
                    '<version>2.1.0</version><description>' + M.NETSTANDARD21['packagingCommit'] + '</description>'
                    '<licenseUrl>' + M.NETSTANDARD21['licenseUrl'] + '</licenseUrl></metadata></package>')
            with self.assertRaisesRegex(ValueError, 'Unreviewed missing-repository/license'):
                M.reviewed_netstandard_identity(package, M.NETSTANDARD21['packagingCommit'])
            with self.assertRaisesRegex(ValueError, 'correspondence is unknown'):
                M.package_metadata(package, M.NETSTANDARD21['packagingCommit'])

    def test_css_declared_gitlink_basis_does_not_allow_arbitrary_missing_metadata(self):
        commit = M.CSS_PARSER['sourceCommit']
        name = 'sdk/7.0.120/Sdks/Microsoft.NET.Sdk.Razor/tools/Microsoft.Css.Parser.dll'
        policy = dict(kind='sdk-declared-source-gitlink', sourceRoot='css', sourceCommit=commit, allowedLayoutPaths=[name])
        source = dict(sourceRoot='css', sourceCommit=commit, basis='sdk-declared-source-gitlink')
        row = dict(path=name, sourceRoot='css', sourceCommit=commit, componentSource=source)
        metadata = dict(assemblyName='Microsoft.Css.Parser', assemblyVersion='1.0.0.0', publicKeyToken='adb9793829ddae60',
            attributes={'System.Reflection.AssemblyInformationalVersionAttribute': ['1.0.0-20200708.1']})
        fp = {key: M.CSS_PARSER[key] for key in M.FP}
        roots = dict(css=dict(kind='git', commit=commit))
        with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata):
            self.assertEqual(commit, M.validate_imported_component(b'PE', row, roots,
                reviewed_sources={fp['sha256']: policy}, package_fp=fp)[1])
            for bad_row, bad_roots, proofs in ((row, roots, {}), (dict(row, path='sdk/7.0.120/Other.dll'), roots, {fp['sha256']: policy}),
                (dict(row, componentSource=dict(source, basis='assembly-informational-version')), roots, {fp['sha256']: policy}),
                (row, dict(css=dict(kind='tree')), {fp['sha256']: policy})):
                with self.subTest(row=bad_row, roots=bad_roots), self.assertRaisesRegex(ValueError, 'CSS component requires'):
                    M.validate_imported_component(b'PE', bad_row, bad_roots, reviewed_sources=proofs, package_fp=fp)
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / 'lookalike-css.nupkg'
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('css.nuspec', '<package><metadata><id>Microsoft.Css.Parser</id><version>1.0.0-20200708.1</version>'
                    '<licenseUrl>' + M.CSS_PARSER['licenseUrl'] + '</licenseUrl></metadata></package>')
            with self.assertRaisesRegex(ValueError, 'Unreviewed missing-repository CSS'):
                M.reviewed_css_identity(package, commit)

    def test_reference_cache_generator_has_exact_original_task_and_output(self):
        name = 'sdk/7.0.120/SDKPrecomputedAssemblyReferences.cache'
        output = '/installer/artifacts/bin/redist/Release/dotnet/' + name
        row = dict(archivePath=name, task='ResolveAssemblyReference', outputPath=output)
        replay = dict(sourceMountRoot='/installer')
        task = dict(taskName='ResolveAssemblyReference', succeeded=True,
            taskFile='/installer/src/redist/targets/GenerateLayout.targets', projectFile='/installer/src/redist/redist.csproj',
            events=[dict(kind='task-parameter', field='AssemblyInformationCacheOutputPath', text=output)])
        M.validate_generated_task(row, replay, task, '7.0.120')
        for bad_row, bad_task in ((dict(row, archivePath=name.replace('.cache', '.data')), task),
            (row, dict(task, taskFile='/installer/src/redist/targets/Injected.targets')),
            (row, dict(task, projectFile='/installer/src/other.csproj')),
            (row, dict(task, events=[dict(kind='task-parameter', field='Unrelated', text=output)])),
            (row, dict(task, succeeded=False))):
            with self.subTest(row=bad_row, task=bad_task), self.assertRaises(ValueError):
                M.validate_generated_task(bad_row, replay, bad_task, '7.0.120')

    def test_literal_manifest_tree_is_not_a_general_non_git_source_exception(self):
        name = M.MANIFEST_INPUTS.ROOT_NAME
        root = dict(kind='tree', role=M.MANIFEST_INPUTS.ROLE)
        artifact = dict(kind=M.MANIFEST_INPUTS.KIND, sourceRoot=name, sourceCommit=None)
        M.validate_artifact_source(artifact, {name: root})
        for changed, roots in ((dict(artifact, sourceCommit='a' * 40), {name: root}),
            (dict(artifact, kind='managed-package'), {name: root}),
            (artifact, {name: dict(root, kind='git', commit='a' * 40)}),
            (artifact, {name: dict(root, role='opaque-package-inputs')}),
            (dict(artifact, sourceRoot='other-tree'), {'other-tree': root})):
            with self.subTest(artifact=changed, roots=roots), self.assertRaises(ValueError):
                M.validate_artifact_source(changed, roots)

    def test_original_sdk7_universe_preserves_all_templates_languages_and_r2r(self):
        cases = M.original_sdk7_cases()
        self.assertEqual(42, len(cases))
        self.assertEqual(12, sum('.OmniSharpTests.' in name for name in cases))
        for language in ('CSharp', 'FSharp', 'VB'):
            self.assertTrue(any('Language = ' + language in name and 'PublishR2R' in name for name in cases))
        self.assertIn('Microsoft.DotNet.SourceBuild.SmokeTests.DotNetFormatTests.FormatProject', cases)
        self.assertIn('Microsoft.DotNet.SourceBuild.SmokeTests.DotNetWatchTests.WatchTests', cases)

    def test_retained_vstest_package_does_not_become_nuget_corresponding_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reports').mkdir()
            path = root / 'vstest.nupkg'
            commit = '79d56b02b69a582cd90428878a5e9411ab7538f5'
            data = b'imported NuGet assembly'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('content/NuGet.Common.dll', data)
                archive.writestr('VSTest.nuspec', '<package><metadata><license type="expression">MIT</license>'
                    '<repository commit="' + commit + '" url="https://github.com/microsoft/vstest"/></metadata></package>')
            (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=[dict(retained=path.name, **M.fingerprint(path))])))
            name = 'sdk/7.0.120/NuGet.Common.dll'
            row = dict(path=name, origin='imported-package', sourceRoot='vstest', sourceCommit=commit,
                       packagePath=path.name, packageMember='content/NuGet.Common.dll')
            actual = {name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())}
            metadata = dict(attributes={'System.Reflection.AssemblyInformationalVersionAttribute': ['1.0+' + commit]})
            with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata):
                with self.assertRaisesRegex(ValueError, 'unrelated package/source attribution: nuget'):
                    M.validate_managed_shipping(root, [row], actual, {}, {},
                        dict(vstest=dict(kind='git', commit=commit)), dict(sdkVersion='7.0.120'))

    def test_bundled_code_requires_its_own_embedded_commit_and_full_source(self):
        compiler = M.SDK7_IMPORT_SOURCES['roslyn'][2]
        container = '4a47c89b8c223dee2f4cab042fcb58edcdf97f54'
        row = dict(origin='imported-package', sourceRoot='format', sourceCommit=container)
        roots = dict(format=dict(kind='git', commit=container), roslyn=dict(kind='git', commit=compiler))
        metadata = dict(attributes={'System.Reflection.AssemblyInformationalVersionAttribute': ['4.4.0+' + compiler]})
        with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata):
            with self.assertRaisesRegex(ValueError, 'rather than only the enclosing package'):
                M.validate_imported_component(b'PE body checked independently by metadata parser', row, roots)
            row['componentSource'] = dict(sourceRoot='roslyn', sourceCommit=compiler, basis='assembly-informational-version')
            self.assertEqual(compiler, M.validate_imported_component(b'PE', row, roots)[1])
            for change in (dict(sourceRoot='format'), dict(sourceCommit=container), dict(basis='package-container'), dict(unreviewed=True)):
                bad = dict(row, componentSource=dict(row['componentSource'], **change))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'own actual embedded identity'):
                    M.validate_imported_component(b'PE', bad, roots)
        for values in ([], ['4.4.0'], ['4.4.0+' + compiler + '+' + container]):
            metadata['attributes']['System.Reflection.AssemblyInformationalVersionAttribute'] = values
            with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata), self.assertRaises(ValueError):
                M.validate_imported_component(b'PE', row, roots)

    def test_compiler_family_does_not_absorb_independent_analyzers_or_razor_runtime(self):
        self.assertEqual('roslyn-analyzers', M.shipping_family('Microsoft.CodeAnalysis.CSharp.NetAnalyzers.dll'))
        self.assertEqual('roslyn-analyzers', M.shipping_family('de/Microsoft.CodeAnalysis.NetAnalyzers.resources.dll'))
        for name in ('Microsoft.CodeAnalysis.Elfie.dll', 'Microsoft.CodeAnalysis.AnalyzerUtilities.dll',
                     'Microsoft.AspNetCore.Mvc.Razor.dll', 'Microsoft.AspNetCore.Mvc.RazorPages.dll', 'Microsoft.AspNetCore.Razor.Runtime.dll'):
            self.assertIsNone(M.shipping_family(name))
        for name in ('Microsoft.CodeAnalysis.CSharp.dll', 'Microsoft.CodeAnalysis.Workspaces.dll'):
            self.assertEqual('roslyn', M.shipping_family(name))

    def test_actual_commit_hash_metadata_is_typed_and_conflicts_fail_closed(self):
        commit = '3ebc38de585fc641a04b0e78ed69468453b0f8a1'
        metadata = dict(attributes={'System.Reflection.AssemblyInformationalVersionAttribute': ['2.14.1+3ebc38de58'],
            'System.Reflection.AssemblyMetadataAttribute': ['CommitHash', commit, 'RepositoryUrl', 'https://github.com/Humanizr/Humanizer']})
        self.assertEqual(dict(sourceCommit=commit, basis='assembly-metadata-commit-hash'), M.embedded_component_source(metadata))
        row = dict(sourceRoot='container', sourceCommit='a' * 40,
            componentSource=dict(sourceRoot='humanizer', sourceCommit=commit, basis='assembly-metadata-commit-hash'))
        roots = dict(container=dict(kind='git', commit='a' * 40), humanizer=dict(kind='git', commit=commit))
        with mock.patch.object(M.MANAGED, 'inspect', return_value=metadata):
            self.assertEqual(commit, M.validate_imported_component(b'actual parser tested separately', row, roots)[1])
            with self.assertRaises(ValueError):
                M.validate_imported_component(b'PE', dict(row, componentSource=dict(row['componentSource'], basis='assembly-informational-version')), roots)
        for pairs in (['CommitHash'], ['NotCommitHash', commit], ['CommitHash', commit[:10]]):
            changed = copy.deepcopy(metadata); changed['attributes']['System.Reflection.AssemblyMetadataAttribute'] = pairs
            if len(pairs) % 2:
                with self.assertRaises(ValueError): M.embedded_component_source(changed)
            else: self.assertIsNone(M.embedded_component_source(changed))
        metadata['attributes']['System.Reflection.AssemblyInformationalVersionAttribute'] = ['2.14.1+' + 'b' * 40]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            M.embedded_component_source(metadata)


class FunctionalEvidence(unittest.TestCase):
    def test_every_cold_worker_keeps_immutable_image_mount_and_network_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'reports/prepare'
            directory.mkdir(parents=True)
            prepare = dict(imageId='sha256:' + 'a' * 64, verificationImageId='sha256:' + 'b' * 64)
            for name, key in [('image.json', 'imageId'), ('verify_image.json', 'verificationImageId')]:
                (directory / name).write_text(json.dumps([dict(Id=prepare[key], Architecture='arm64', Os='linux')]))
            record = dict(architecture='aarch64', sdkVersion='7.0.120', targetRid='linux-musl-arm64', sdk=dict(name='genuine.tar.gz'))
            common = M.P.DOCKER_ENGINE + ['run', '--volume', '/repo:/project:ro', '--volume', '/output:/delivery',
                '--volume', '/home:/home/build', '--volume', '/evidence:/diag', prepare['verificationImageId']]
            archive = ['--archive', '/delivery/genuine.tar.gz']
            calls = [common + ['--network=none', '/project/scripts/verify-sdk.sh'] + archive +
                ['--expected-version', '7.0.120', '--expected-rid', 'linux-musl-arm64', '--framework', 'net7.0', '--arch', 'arm64'],
                common + ['--network=none', '/project/scripts/musl-sdk-audit.py'] + archive,
                common + ['--network=none', '/project/scripts/musl-legacy-functional.py', 'offline'] + archive,
                common + ['--network=host', '/project/scripts/musl-legacy-functional.py', 'tls'] + archive]
            stages = dict(verify=dict(commands=calls))
            M.validate_verification_boundary(root, record, prepare, stages)
            mutations = [lambda call: call.__setitem__(call.index(prepare['verificationImageId']), prepare['imageId']),
                         lambda call: call.extend(['--volume', '/bootstrap:/work']),
                         lambda call: call.extend(['--env', 'NUGET_PACKAGES=/home/build/.nuget/packages']),
                         lambda call: call.__setitem__(call.index('--network=none'), '--network=host'),
                         lambda call: call.__setitem__(call.index('/delivery/genuine.tar.gz'), '/delivery/imported.tar.gz')]
            for mutation in mutations:
                changed = copy.deepcopy(stages)
                mutation(changed['verify']['commands'][0])
                with self.assertRaises(ValueError):
                    M.validate_verification_boundary(root, record, prepare, changed)

    def test_original_test_assertion_changes_deletions_and_duplicate_cases_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            directory = release / 'reports/test/original-smoke'
            (directory / 'trx').mkdir(parents=True)
            (release / 'sources').mkdir()
            prefix = 'installer/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests/'
            raw = b"return TargetRid.Split('-')[1];\n"
            name = prefix + 'Config.cs'
            manifest = dict(index=dict(path='index.jsonl'), archive=dict(path='source.tar.gz'), roots=[dict(name='installer', deleted=[])])
            record = dict(sdkVersion='7.0.120', architecture='aarch64', sdk=dict(bytes=99, sha256='a' * 64))
            baseline = dict(mode='100644', blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
            def write_source(actual):
                row = dict(path=name, mode='100644', baseline=baseline, bytes=len(actual), sha256=hashlib.sha256(actual).hexdigest())
                (release / 'sources/index.jsonl').write_text(json.dumps(row) + '\n')
                with tarfile.open(release / 'sources/source.tar.gz', 'w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    member.size = len(actual)
                    archive.addfile(member, io.BytesIO(actual))
                (directory / 'identity.json').write_text(json.dumps(dict(sdkVersion='7.0.120', architecture='aarch64',
                    upstreamCaseCount=42, sdkArchive=record['sdk'], sourceFiles=[dict(path='Config.cs', bytes=len(actual), sha256=row['sha256'])])))
            write_source(raw.replace(b'return', b'/* original assertions removed */ return'))
            with self.assertRaisesRegex(ValueError, 'assertion/source bytes differ'):
                M.validate_original_smoke(release, record, manifest)
            write_source(raw)
            manifest['roots'][0]['deleted'] = [dict(path=name.removeprefix('installer/'))]
            with self.assertRaisesRegex(ValueError, 'was removed'):
                M.validate_original_smoke(release, record, manifest)
            manifest['roots'][0]['deleted'] = []
            (directory / 'test-rid-parser.patch').write_text('unreviewed assertion suppression')
            with self.assertRaisesRegex(ValueError, 'test-parser adjustment'):
                M.validate_original_smoke(release, record, manifest)
            config = raw.decode()
            adjusted = config.replace("TargetRid.Split('-')[1]", "TargetRid.Split('-')[^1]")
            (directory / 'test-rid-parser.patch').write_text(''.join(difflib.unified_diff(
                config.splitlines(True), adjusted.splitlines(True), fromfile='a/Config.cs', tofile='b/Config.cs')))
            rows = ''.join('<UnitTestResult executionId="' + str(index) + '" testName="duplicate"/>' for index in range(42))
            (directory / 'trx/fake.trx').write_text('<TestRun>' + rows + '</TestRun>')
            with self.assertRaisesRegex(ValueError, 'test universe differs'):
                M.validate_original_smoke(release, record, manifest)

    def fixture(self, root):
        directory = root / 'reports/verify/functional'
        directory.mkdir(parents=True)
        sdk = dict(name='candidate.tar.gz', bytes=17, sha256='a' * 64, sha512='b' * 128)
        record = dict(sdkVersion='7.0.120', targetRid='linux-musl-arm64', architecture='aarch64', sdk=sdk)
        checks = ('consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
                  'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp')
        path = root / 'reports/verify/sdk'
        path.mkdir()
        (path / 'verification.json').write_text(json.dumps(dict(sdkVersion='7.0.120', reportedRid=record['targetRid'],
            verificationStatus='passed', smokeStatus='passed', archive=sdk, functionalChecks=dict.fromkeys(checks, 'passed'))))
        (directory / 'candidate.json').write_text(json.dumps(dict(sdkVersion='7.0.120', architecture='aarch64', archive=sdk)))
        (directory / 'offline-summary.json').write_text(json.dumps(dict(status='passed', network='none', uid=10001,
            nativeArchitecture='aarch64', hostSdkUsed=False, compilerInstalled=False)))
        results = dict({'sdk-info': record['targetRid'], 'offline-build': 'Build succeeded',
            'icu': 'ICU 13 CULTURES OK', 'crypto': 'CRYPTO SHA256 RSA ECDSA AESGCM X509 OID OK',
            'aspnet': 'ASPNET HTTP OK', 'apphost': 'ICU 13 CULTURES OK', 'tls': 'SYSTEM TRUST TLS OK'})
        for name, output in results.items():
            (directory / (name + '.json')).write_text(json.dumps(dict(exitCode=0, output=output,
                defaultTrust=True, certificateValidationBypass=False)))
        source = ROOT / 'scripts/musl-negative-certificates.cs'
        (directory / 'negative-certificate-fixture.cs').write_bytes(source.read_bytes())
        (directory / 'negative-certificates.json').write_text(json.dumps(dict(status='passed',
            fixture=dict(path='negative-certificate-fixture.cs', sha256=M.fingerprint(source)['sha256']),
            readyToRun=True, defaultSslStream=True, certificateValidationCallback=False, ephemeralUserTrustStore=True,
            uid=10001, network='none', nativeArchitecture='aarch64', commands=[dict(exitCode=0), dict(exitCode=0)])))
        (directory / 'negative-execution.log').write_text('\n'.join(('PASS trusted-control connects',
            'PASS untrusted-self-signed fails closed', 'PASS expired fails closed', 'PASS wrong-hostname fails closed',
            'PASS invalid-CA managed chain fails closed', 'PASS invalid-CA TLS fails closed',
            'PASS all certificate cases; no remote validation callback')))
        stages = dict(verify=dict(commands=[['--network=none', '/project/scripts/musl-legacy-functional.py', 'offline'],
            ['--network=host', '/project/scripts/musl-legacy-functional.py', 'tls']]))
        return record, stages

    def test_all_functional_boundaries_are_required_not_only_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, stages = self.fixture(root)
            M.validate_functional(root, record, stages)
            directory = root / 'reports/verify/functional'
            changes = [('candidate.json', dict(archive=dict(record['sdk'], sha256='0' * 64))),
                       ('offline-summary.json', dict(network='host')), ('crypto.json', dict(exitCode=1)),
                       ('tls.json', dict(certificateValidationBypass=True)),
                       ('negative-certificates.json', dict(certificateValidationCallback=True)),
                       ('negative-certificates.json', dict(readyToRun=False))]
            for filename, values in changes:
                path = directory / filename
                original = path.read_text()
                item = json.loads(original)
                item.update(values)
                path.write_text(json.dumps(item))
                with self.subTest(filename=filename, values=values), self.assertRaises(ValueError):
                    M.validate_functional(root, record, stages)
                path.write_text(original)
            (directory / 'negative-execution.log').write_text('PASS trusted-control connects\n')
            with self.assertRaisesRegex(ValueError, 'assertions are incomplete'):
                M.validate_functional(root, record, stages)


class OriginalNuGetCompilerProof(unittest.TestCase):
    def fixture(self, root):
        directory = root / 'reports/build'
        directory.mkdir(parents=True)
        (root / 'outputs').mkdir()
        (directory / 'nuget.binlog').write_bytes(b'bound original NuGet build log')
        tasks, rows, feed, restored = [], [], [], []
        commit = M.POLICIES['7.0.120']['nuget']
        for package in sorted(M.NUGET7_PACKAGES):
            path = root / 'outputs' / (package + '.nupkg')
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr(package + '.nuspec', '<package><metadata><id>' + package + '</id><version>6.4.3-rc.1</version>'
                    '<repository url="https://github.com/NuGet/NuGet.Client"/><license type="expression">Apache-2.0</license></metadata></package>')
                for tfm in ('net472', 'net7.0'):
                    member = 'lib/' + tfm + '/' + package + '.dll'
                    data = (package + '-' + tfm).encode()
                    archive.writestr(member, data)
                    context = str(len(tasks) + 1) + ':1:1:1'
                    output = '/nuget/artifacts/' + package + '/obj/Release/' + tfm + '/' + package + '.dll'
                    events = [dict(eventNumber=number, timestamp='2026-11-08T00:00:00.1234567Z', kind=kind,
                        field=field, text=text, metadata={}, succeeded=success) for number, kind, field, text, success in
                        [(1, 'task-started', None, None, None), (2, 'task-parameter', 'OutputAssembly', output, None),
                         (3, 'task-parameter', 'Sources', package + '.cs', None),
                         (4, 'command-line', None, 'dotnet csc.dll /out:' + output + ' ' + package + '.cs', None),
                         (5, 'task-finished', None, None, True)]]
                    tasks.append(dict(context=context, taskName='Csc', projectFile='/nuget/src/' + package + '.csproj',
                        taskFile='/bootstrap/sdk/7.0.118/Roslyn/Microsoft.CSharp.Core.targets', succeeded=True, events=events))
                    rows.append(dict(packagePath=path.relative_to(root).as_posix(), member=member, sha256=hashlib.sha256(data).hexdigest(),
                        sourceRoot='nuget', sourceCommit=commit, context=context, outputPath=output))
            fp = M.fingerprint(path)
            feed.append(dict(file=package + '.6.4.3-rc.1.nupkg', origin='rebuilt-exact-nuget-original-library-target-matrix', sourceCommit=commit, **fp))
            if package != 'nuget.packagemanagement':
                restored.append(dict(path=package + '/6.4.3-rc.1/' + package + '.6.4.3-rc.1.nupkg', retained=path.relative_to(root).as_posix(), **fp))
        (directory / 'tasks.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in tasks))
        (directory / 'bootstrap-feed.json').write_text(json.dumps(dict(packages=feed)))
        (root / 'reports/restored-inputs.json').write_text(json.dumps(dict(packages=restored)))
        replay = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
            inputSha256=M.fingerprint(directory / 'nuget.binlog')['sha256'], sourceMountRoot='/nuget',
            tasks=dict(path='reports/build/tasks.jsonl', **M.fingerprint(directory / 'tasks.jsonl')), compiledOutputs=rows, transformations=[])
        return replay

    def test_all_original_frameworks_and_unconsumed_build_outputs_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay = self.fixture(root)
            path = root / 'reports/build/replay.json'
            def validate(value):
                path.write_text(json.dumps(value))
                return M.validate_nuget_build(root, dict(sdkVersion='7.0.120'),
                    dict(path=path.relative_to(root).as_posix(), **M.fingerprint(path)), {})
            proof = validate(replay)
            self.assertEqual(19, len(proof['packages']))
            self.assertEqual(38, len(proof['members']))
            unused = root / 'outputs/nuget.packagemanagement.nupkg'
            M.package_metadata(unused, M.POLICIES['7.0.120']['nuget'], proof)
            with self.assertRaisesRegex(ValueError, 'correspondence is unknown'):
                M.package_metadata(unused, M.POLICIES['7.0.120']['nuget'])
            for mutation in (lambda rows: rows.pop(), lambda rows: rows[0].__setitem__('sha256', '0' * 64),
                             lambda rows: rows[0].__setitem__('sourceCommit', '0' * 40)):
                value = copy.deepcopy(replay)
                mutation(value['compiledOutputs'])
                with self.assertRaises(ValueError):
                    validate(value)


class NuGetEvidenceEmitter(unittest.TestCase):
    def fixture(self, root):
        replay = OriginalNuGetCompilerProof().fixture(root)
        source = root / 'source'
        for row in replay['compiledOutputs']:
            output = source / row['outputPath'].removeprefix('/nuget/')
            output.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(root / row['packagePath']) as package:
                output.write_bytes(package.read(row['member']))
        feed_path = root / 'reports/build/bootstrap-feed.json'
        feed = M.load(feed_path)
        for row in feed['packages']:
            package_id = row['file'].removesuffix('.6.4.3-rc.1.nupkg')
            row['extraPath'] = str(root / 'outputs' / (package_id + '.nupkg'))
        feed_path.write_text(json.dumps(feed))
        status = root / 'status.json'
        status.write_text(json.dumps(dict(completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
                                          inputSha256=replay['inputSha256'])))
        context = dict(sdkVersion='7.0.120', bootstrapFeed=str(feed_path),
            restoredInputs=str(root / 'reports/restored-inputs.json'), nugetReplay=dict(status=str(status),
                tasks=str(root / 'reports/build/tasks.jsonl'), binlog=str(root / 'reports/build/nuget.binlog'), sourceMountRoot='/nuget'))
        roots = dict(nuget=dict(path=str(source), commit=M.POLICIES['7.0.120']['nuget']))
        return context, roots

    def test_normal_outputs_retain_all_tfms_and_only_observed_restore_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context, roots = self.fixture(root)
            feed = (root / 'reports/build/bootstrap-feed.json').read_bytes()
            with mock.patch.object(N.subprocess, 'check_output', return_value=M.POLICIES['7.0.120']['nuget']):
                proof = N.emit(context, root, roots)
            self.assertEqual(19, len(proof['builtPackages']))
            self.assertEqual(38, proof['primaryLibraryMembers'])
            self.assertEqual(18, sum(bool(row['actualRestoreRecords']) for row in proof['builtPackages']))
            self.assertEqual([], proof['diagnosticUnusedWrapperDerivations'])
            self.assertEqual(feed, (root / 'reports/build/bootstrap-feed.json').read_bytes())

    def test_renamed_or_changed_package_cannot_replace_recorded_wrapper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context, roots = self.fixture(root)
            unused = root / 'outputs/nuget.packagemanagement.nupkg'
            unused.write_bytes(unused.read_bytes() + b'changed wrapper')
            with mock.patch.object(N.subprocess, 'check_output', return_value=M.POLICIES['7.0.120']['nuget']):
                with self.assertRaisesRegex(ValueError, 'Exact retained built NuGet package bytes'):
                    N.emit(context, root, roots)

    def test_old_list_normalization_requires_diagnostic_and_exact_old_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / 'nuget.common.6.4.3-rc.1.nupkg'
            package.write_bytes(b'original old wrapper')
            path = root / 'old-index.json'
            path.write_text(json.dumps([dict(file=package.name, sha256='0' * 64,
                sourceCommit=M.POLICIES['7.0.120']['nuget'], origin='source-built-exact-nuget-original-library-matrix')]))
            with self.assertRaisesRegex(ValueError, 'Only explicit diagnostic'):
                N.feed_record(dict(bootstrapFeedDir=str(root)), path, M.POLICIES['7.0.120']['nuget'])
            with self.assertRaisesRegex(ValueError, 'differs from its original index'):
                N.feed_record(dict(diagnosticOnly=True, bootstrapFeedDir=str(root)), path, M.POLICIES['7.0.120']['nuget'])


class ActualClosureBoundary(unittest.TestCase):
    def fixture(self, root):
        raw = bytearray(64); raw[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', raw, 16, 3, 183)
        with tarfile.open(root / 'sdk.tar.gz', 'w:gz') as archive:
            entry = tarfile.TarInfo('dotnet'); entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        record = dict(sdkVersion='7.0.120', architecture='aarch64', targetRid='linux-musl-arm64', sdk=dict(name='sdk.tar.gz'))
        row = dict(path='dotnet', sha256=hashlib.sha256(raw).hexdigest(), interpreter=None)
        closure = dict(schemaVersion=1, scope='musl-complete-payload-elf-closure', native=True, libc='musl',
                       architecture='aarch64', targetRid='linux-musl-arm64', symlinks=[], hostElfCount=1, elfFiles=[copy.deepcopy(row)])
        report = dict(violations=[], emulation=False, nativeArchitecture='aarch64', symlinks=[],
                      files=[row], elfCount=1, closure=closure)
        return record, report

    def test_closure_leaf_binds_actual_archive_before_reading_dynamic_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, original = self.fixture(root)
            omitted = copy.deepcopy(original); omitted['files'] = []; omitted['elfCount'] = 0
            omitted['closure'].update(elfFiles=[], hostElfCount=0)
            changed = copy.deepcopy(original)
            for row in [changed['files'][0], changed['closure']['elfFiles'][0]]: row['sha256'] = '0' * 64
            interpreter = copy.deepcopy(original)
            for row in [interpreter['files'][0], interpreter['closure']['elfFiles'][0]]: row['interpreter'] = '/lib/ld-musl-aarch64.so.1'
            for report in (omitted, changed, interpreter):
                with self.subTest(report=report['elfCount']), mock.patch.object(M, 'elf_dynamic',
                        side_effect=AssertionError('Unbound report reached dependency parser')):
                    with self.assertRaisesRegex(ValueError, 'unchanged archive bytes and interpreter'):
                        M.validate_elf_closure(root, record, {}, report)


if __name__ == '__main__':
    unittest.main()
