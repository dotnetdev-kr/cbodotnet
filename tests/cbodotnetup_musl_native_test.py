"""Fail closed on native installer package, ELF and qualification tampering."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import cbodotnetup_musl_native as NATIVE
import musl_archive as ARCHIVE


def profile_fixture():
    marker = b'Unrelated retained state; not an executable SDK fixture.\n'
    return {'.': dict(type='directory', mode=0o755, uid=10001, gid=10001),
        'preservation-only.txt': dict(type='file', mode=0o644, uid=10001, gid=10001,
            size=len(marker), sha256=hashlib.sha256(marker).hexdigest())}


class NativePackageInputTests(unittest.TestCase):
    def test_actual_nupkg_bytes_and_credential_free_origin_must_match_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            name, version = 'microsoft.dotnet.ilcompiler', '10.0.14'
            package = cache / name / version
            package.mkdir(parents=True)
            content = b'actual downloaded NativeAOT compiler package fixture'
            archive = package / (name + '.' + version + '.nupkg')
            archive.write_bytes(content)
            raw_hash = base64.b64encode(hashlib.sha512(content).digest()).decode()
            content_hash = base64.b64encode(hashlib.sha512(b'unsigned normalized package contents').digest()).decode()
            (package / (archive.name + '.sha512')).write_text(raw_hash)
            origin = package / '.nupkg.metadata'
            metadata = dict(source='https://api.nuget.org/v3/index.json', contentHash=content_hash)
            origin.write_text(json.dumps(metadata))
            assets = dict(libraries={name + '/' + version: dict(type='package', sha512=content_hash)})
            rows = NATIVE.native_packages(cache, assets)
            self.assertEqual(name, rows[0]['id'])
            self.assertEqual(archive.name, rows[0]['name'])
            self.assertEqual(hashlib.sha256(content).hexdigest(), rows[0]['sha256'])
            self.assertEqual(content_hash, rows[0]['contentHash'])
            self.assertEqual(raw_hash, rows[0]['downloadHash'])
            self.assertNotEqual(rows[0]['contentHash'], rows[0]['downloadHash'])
            archive.write_bytes(content + b'tampered')
            with self.assertRaisesRegex(ValueError, 'download hash'):
                NATIVE.native_packages(cache, assets)
            archive.write_bytes(content)
            origin.write_text(json.dumps(dict(metadata, source='https://unreviewed.example/v3/index.json')))
            with self.assertRaisesRegex(ValueError, 'origin'):
                NATIVE.native_packages(cache, assets)
            origin.write_text(json.dumps(dict(metadata, contentHash=raw_hash)))
            with self.assertRaisesRegex(ValueError, 'contentHash'):
                NATIVE.native_packages(cache, assets)

    def test_build_pins_native_runtime_and_supports_a_real_distinct_baseline_compile(self):
        script = NATIVE.build_script('linux-musl-arm64', Path('/work/sdk/dotnet'), '10.0.14',
            output='/work/output/baseline', version='0.5.0')
        self.assertIn('--runtime linux-musl-arm64 --self-contained true', script)
        self.assertIn('-p:RuntimeFrameworkVersion=10.0.14 -p:IlcPackageVersion=10.0.14', script)
        self.assertIn('-p:Version=0.5.0', script)
        self.assertIn('/work/output/baseline/cbodotnetup-linux-musl-arm64 --version', script)
        with self.assertRaises(ValueError):
            NATIVE.build_script('linux-arm64', Path('/sdk/dotnet'), '10.0.14')


class NativeToolEntrypointTests(unittest.TestCase):
    def test_explicit_tool_entrypoint_has_complete_closure_without_faking_dotnet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, system = root / 'tool', root / 'system'
            payload.mkdir()
            (system / 'lib').mkdir(parents=True)
            binary = payload / 'cbodotnetup-linux-musl-x64'
            binary.write_bytes(b'\x7fELFnative-tool')
            libc = system / 'lib/libc.musl-x86_64.so.1'
            libc.write_bytes(b'\x7fELFstock-musl')
            common = dict(machine='Advanced Micro Devices X86-64', elfType='DYN', elfClass='ELF64',
                interpreter=None, needed=[], runpaths=[], glibcRequirements=[], versionNeeds=[], versionDefinitions=[])
            records = {str(binary): dict(common, interpreter='/lib/ld-musl-x86_64.so.1', needed=[libc.name]), str(libc): common}
            with mock.patch.object(ARCHIVE, 'inspect_elf', side_effect=lambda path: copy.deepcopy(records[str(path)])):
                report = ARCHIVE.audit_elf(payload, 'x64', system_root=system, native=False, entrypoint=binary.name)
                self.assertEqual(binary.name, report['elfFiles'][0]['path'])
                self.assertEqual(1, len(report['stockLibraries']))
                self.assertFalse((payload / 'dotnet').exists())
                with self.assertRaisesRegex(ValueError, 'native dotnet host'):
                    ARCHIVE.audit_elf(payload, 'x64', system_root=system, native=False)
                records[str(binary)]['interpreter'] = None
                with self.assertRaisesRegex(ValueError, 'matching native interpreter'):
                    ARCHIVE.audit_elf(payload, 'x64', system_root=system, native=False, entrypoint=binary.name)
            for entrypoint in ('../tool', '/tool', 'tool/sub'):
                with self.assertRaisesRegex(ValueError, 'entrypoint filename'):
                    ARCHIVE.audit_elf(payload, 'x64', system_root=system, native=False, entrypoint=entrypoint)


class NativeQualificationTests(unittest.TestCase):
    def test_package_coexistence_probe_preserves_numeric_stdout_and_brand_stderr(self):
        brand = ARCHIVE.BRANDING['displayName'] + '\n'
        result = subprocess.CompletedProcess(['/usr/bin/cbodotnet', '--version'], 0, stdout='10.0.403\n', stderr=brand)
        with mock.patch.object(NATIVE, 'user', return_value=result) as user:
            self.assertEqual('10.0.403', NATIVE.package_version('10.0.403'))
            user.assert_called_once_with(['/usr/bin/cbodotnet', '--version'])
        for stdout, stderr in ((brand + '10.0.403\n', ''), ('10.0.303\n', brand), ('10.0.403\n', '')):
            with self.subTest(stdout=stdout, stderr=stderr), mock.patch.object(NATIVE, 'user',
                    return_value=subprocess.CompletedProcess([], 0, stdout=stdout, stderr=stderr)):
                with self.assertRaisesRegex(ValueError, 'version or branding'):
                    NATIVE.package_version('10.0.403')

    def test_missing_native_security_evidence_or_wrong_public_byte_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            for name in ('freeze.json', 'get-cbodotnetup.py'):
                (bundle / name).write_text(name)
            rid, sha = 'linux-musl-x64', 'a' * 64
            catalog = dict(tools=[dict(version='0.5.1', rid=rid, binary=dict(sha256=sha)),
                dict(version='0.5.0', rid=rid, binary=dict(sha256='b' * 64))])
            NATIVE.save(bundle / 'catalog-musl.json', catalog)
            audit = dict(status='passed', native=True, libc='musl', architecture='x64', targetRid=rid,
                elfFiles=[dict(path='cbodotnetup', sha256=sha, interpreter='/lib/ld-musl-x86_64.so.1',
                    machine='Advanced Micro Devices X86-64')], stockLibraries=[dict(path='/lib/actual-stock-musl')])
            value = dict(schemaVersion=1, scope='cbodotnetup-native-installation', status='passed', variant='alpine-3.24',
                architecture='x64', libc='musl', rid=rid, native=True, baseImage=ARCHIVE.BASES['x64'], networkForBuild='none', userId=10001,
                checks=dict.fromkeys(NATIVE.CHECKS, 'passed'), functionalChecks=dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS, 'passed'),
                catalogSha256=NATIVE.descriptor(bundle / 'catalog-musl.json')['sha256'],
                bootstrapSha256=NATIVE.descriptor(bundle / 'get-cbodotnetup.py')['sha256'],
                freezeSha256=NATIVE.descriptor(bundle / 'freeze.json')['sha256'], binarySha256=sha,
                bootstrapBinarySource='public-https', packageManagedCommunityIntegrity='unchanged', crossLibcStatePreserved=True,
                migration=dict(status='passed', oldVersion='0.5.0', newVersion='0.5.1', oldBinarySha256='b' * 64,
                    protocol='actual-musl-0.5.0-self-update-rollback-reupgrade', sdkRollback='passed', interruptedOwnershipRecovery='passed'),
                elfAudit=audit, toolElfAudit=audit, systemTrustHttps=dict(status='passed', url=ARCHIVE.trust_url('x64'), outputSha256=sha))
            value['runtimeProfilePreservation'] = NATIVE.runtime_profile_preservation(profile_fixture(), profile_fixture())
            NATIVE.validate_qualification_report(value, bundle, 'x64', public=True)
            for key, changed in (('native', False), ('binarySha256', 'c' * 64), ('bootstrapBinarySource', 'protected-frozen-candidate'),
                ('functionalChecks', {}), ('toolElfAudit', {}), ('crossLibcStatePreserved', False)):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    NATIVE.validate_qualification_report(dict(value, **{key: changed}), bundle, 'x64', public=True)


class RuntimeProfilePreservationTests(unittest.TestCase):
    def test_inventory_records_real_empty_runtime_lock_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'empty-lock.server').touch()
            inventory = NATIVE.runtime_profile_inventory(root)
            self.assertEqual(0, inventory['empty-lock.server']['size'])
            self.assertEqual(hashlib.sha256(b'').hexdigest(), inventory['empty-lock.server']['sha256'])
            self.assertEqual('directory', inventory['.']['type'])
            NATIVE.validate_profile_inventory(inventory)

    def inventories(self):
        before = profile_fixture()
        after = copy.deepcopy(before)
        for path, mode in (
            ('corefx', 0o2700), ('corefx/Runtime', 0o2700), ('corefx/Runtime/SharedMemory', 0o2700),
            ('corefx/Runtime/SharedMemory/.dotnet', 0o700), ('corefx/Runtime/SharedMemory/.dotnet/lockfiles', 0o700),
            ('corefx/Runtime/SharedMemory/.dotnet/lockfiles/global', 0o700), ('corefx/Runtime/SharedMemory/.dotnet/shm', 0o700),
            ('corefx/Runtime/SharedMemory/.dotnet/shm/global', 0o700), ('corefx/cryptography', 0o2755),
            ('corefx/cryptography/x509stores', 0o2755), ('corefx/cryptography/x509stores/my', 0o2755)):
            after[path] = dict(type='directory', mode=mode, uid=10001, gid=10001)
        self.pfx = 'corefx/cryptography/x509stores/my/9FB8E4306F3B68AC87BCEDDE7776772C94E0DCFB.pfx'
        self.lock = 'corefx/Runtime/SharedMemory/.dotnet/lockfiles/global/vUGL2tcPsIOP73WAtK8QgeBfmeqaX8y_5Z7WaFidueA.server'
        self.shared = self.lock.replace('/lockfiles/', '/shm/')
        for path, size in ((self.pfx, 2300), (self.lock, 0), (self.shared, 4096)):
            after[path] = dict(type='file', mode=0o600, uid=10001, gid=10001, size=size, sha256='a' * 64)
        return before, after

    def test_actual_observed_certificate_and_shared_memory_additions_are_metadata_only(self):
        before, after = self.inventories()
        report = NATIVE.runtime_profile_preservation(before, after)
        self.assertEqual(14, len(report['additions']))
        self.assertEqual(before, {name: after[name] for name in before})
        self.assertEqual(report, NATIVE.validate_runtime_profile_preservation(report))
        self.assertEqual({'path', 'type', 'mode', 'uid', 'gid', 'size', 'sha256'},
            set(next(row for row in report['additions'] if row['path'] == self.pfx)))

    def test_old_file_mode_owner_link_and_root_changes_or_deletions_are_rejected(self):
        before, after = self.inventories()
        before['old-alias'] = dict(type='link', mode=0o777, uid=10001, gid=10001, target='preservation-only.txt')
        after['old-alias'] = copy.deepcopy(before['old-alias'])
        NATIVE.runtime_profile_preservation(before, after)
        for path, key, changed in (('preservation-only.txt', 'sha256', 'b' * 64),
            ('preservation-only.txt', 'mode', 0o600), ('preservation-only.txt', 'uid', 0),
            ('old-alias', 'target', '/outside'), ('.', 'mode', 0o700)):
            mutated = copy.deepcopy(after)
            mutated[path][key] = changed
            with self.subTest(path=path, key=key), self.assertRaisesRegex(ValueError, 'existing runtime profile'):
                NATIVE.runtime_profile_preservation(before, mutated)
        del after['preservation-only.txt']
        with self.assertRaisesRegex(ValueError, 'existing runtime profile'):
            NATIVE.runtime_profile_preservation(before, after)

    def test_arbitrary_growth_wrong_prefix_links_and_wrong_runtime_modes_are_rejected(self):
        before, after = self.inventories()
        for path, item in (
            ('unrelated-new-file', dict(type='file', mode=0o600, uid=10001, gid=10001, size=1, sha256='a' * 64)),
            (self.pfx.replace('/my/', '/root/'), dict(type='file', mode=0o600, uid=10001, gid=10001, size=1, sha256='a' * 64)),
            (self.pfx, dict(type='link', mode=0o777, uid=10001, gid=10001, target='/outside/private-key')),
            (self.pfx, dict(type='file', mode=0o644, uid=10001, gid=10001, size=1, sha256='a' * 64)),
            (self.shared, dict(type='file', mode=0o600, uid=0, gid=10001, size=1, sha256='a' * 64))):
            mutated = copy.deepcopy(after)
            mutated[path] = item
            with self.subTest(path=path, item=item), self.assertRaises(ValueError):
                NATIVE.runtime_profile_preservation(before, mutated)
        mutated = copy.deepcopy(after)
        mutated['corefx/Runtime/SharedMemory/.dotnet/shm/global'] = dict(type='link', mode=0o777, uid=10001, gid=10001, target='/outside')
        with self.assertRaisesRegex(ValueError, 'linked parent'):
            NATIVE.runtime_profile_preservation(before, mutated)

    def test_evidence_cannot_omit_additions_or_include_certificate_contents(self):
        before, after = self.inventories()
        report = NATIVE.runtime_profile_preservation(before, after)
        with self.assertRaisesRegex(ValueError, 'classification'):
            NATIVE.validate_runtime_profile_preservation(dict(report, additions=[]))
        report['finalInventory'][self.pfx]['contents'] = 'private data is forbidden'
        with self.assertRaisesRegex(ValueError, 'private contents'):
            NATIVE.validate_runtime_profile_preservation(report)


if __name__ == '__main__':
    unittest.main()
