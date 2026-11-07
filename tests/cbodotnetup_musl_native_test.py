"""Fail closed on native installer package, ELF and qualification tampering."""
import base64
import copy
import hashlib
import json
from pathlib import Path
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
            origin = package / '.nupkg.metadata'
            origin.write_text(json.dumps(dict(source='https://api.nuget.org/v3/index.json')))
            assets = dict(libraries={name + '/' + version: dict(type='package', sha512=base64.b64encode(hashlib.sha512(content).digest()).decode())})
            rows = NATIVE.native_packages(cache, assets)
            self.assertEqual(name, rows[0]['id'])
            self.assertEqual(archive.name, rows[0]['name'])
            self.assertEqual(hashlib.sha256(content).hexdigest(), rows[0]['sha256'])
            archive.write_bytes(content + b'tampered')
            with self.assertRaisesRegex(ValueError, 'contentHash'):
                NATIVE.native_packages(cache, assets)
            archive.write_bytes(content)
            origin.write_text(json.dumps(dict(source='https://unreviewed.example/v3/index.json')))
            with self.assertRaisesRegex(ValueError, 'origin'):
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
