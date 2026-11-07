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
            NATIVE.validate_qualification_report(value, bundle, 'x64', public=True)
            for key, changed in (('native', False), ('binarySha256', 'c' * 64), ('bootstrapBinarySource', 'protected-frozen-candidate'),
                ('functionalChecks', {}), ('toolElfAudit', {}), ('crossLibcStatePreserved', False)):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    NATIVE.validate_qualification_report(dict(value, **{key: changed}), bundle, 'x64', public=True)


if __name__ == '__main__':
    unittest.main()
