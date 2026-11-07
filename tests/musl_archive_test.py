"""Preserve SDK bytes and require closed native-musl/foreign-target ELF evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_archive as ARCHIVE
import musl_contract as CONTRACT
from musl_contract_test import fixture


def prepared_inputs(directory):
    release, manifest, raw, checksums, catalog, payloads = fixture()
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w:gz') as archive:
        for name, data, mode in (
            ('dotnet', b'#!/bin/sh\nprintf "10.0.403\\n"\n', 0o755),
            ('LICENSE.txt', b'Upstream license\n', 0o644),
            ('ThirdPartyNotices.txt', b'Upstream notices\n', 0o644),
            ('sdk/10.0.403/sentinel', b'Original SDK bytes\n', 0o644)):
            row = tarfile.TarInfo(name)
            row.mode, row.size = mode, len(data)
            archive.addfile(row, io.BytesIO(data))
    item = manifest['architectures']['x64']['sdk']
    payloads[item['name']] = content.getvalue()
    item.update(size=len(content.getvalue()), sha256=hashlib.sha256(content.getvalue()).hexdigest())
    names = [entry[kind]['name'] for entry in manifest['architectures'].values() for kind in CONTRACT.KINDS]
    checksums = ''.join(hashlib.sha256(payloads[name]).hexdigest() + '  ' + name + '\n' for name in names).encode()
    manifest['checksums'].update(size=len(checksums), sha256=hashlib.sha256(checksums).hexdigest())
    raw = json.dumps(manifest).encode()
    payloads.update({'SHA256SUMS': checksums, 'release-manifest.json': raw})
    for entry in release['assets']:
        data = payloads[entry['name']]
        entry.update(size=len(data), digest='sha256:' + hashlib.sha256(data).hexdigest())
    catalog['builds'][0]['sourceManifestSha256'] = hashlib.sha256(raw).hexdigest()
    for name, data in payloads.items():
        (directory / name).write_bytes(data)
    (directory / 'release.json').write_text(json.dumps(release))
    return catalog


class MuslArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.catalog = prepared_inputs(self.inputs)

    def plan(self, channel='archive'):
        result = ARCHIVE.intake(self.inputs, 'x64', catalog=self.catalog)
        result['channel'] = channel
        return result

    def test_build_preserves_complete_payload_and_uses_neutral_musl_names(self):
        result = ARCHIVE.build_archive(self.inputs, 'x64', 1, self.root / 'consumer', catalog=self.catalog)
        self.assertEqual('cbodotnet-sdk-10.0.403-linux-musl-x64-r1.tar.gz', result['artifact']['name'])
        self.assertEqual('cbodotnet-10.0.403-linux-musl-x64-r1', result['directory'])
        tree = self.root / 'consumer' / result['directory']
        payload = tree / 'payload'
        self.assertEqual(b'Original SDK bytes\n', (payload / 'sdk/10.0.403/sentinel').read_bytes())
        self.assertEqual(b'Upstream license\n', (payload / 'LICENSE.txt').read_bytes())
        self.assertEqual((ROOT / 'LICENSE').read_bytes(), (tree / 'LICENSE.wrapper.txt').read_bytes())
        self.assertEqual(['metadata'], result['additionalDirectories'])
        self.assertFalse(result['publicationAllowed'])
        for command in ('dotnet', 'cbodotnet', 'cbodotnet-10.0'):
            output = subprocess.run([str(tree / command), '--version'], text=True, capture_output=True)
            self.assertEqual(0, output.returncode)
            self.assertEqual('10.0.403\n', output.stdout)
            self.assertEqual(CONTRACT.BRANDING['displayName'] + '\n', output.stderr)

    def test_archive_movement_preserves_runtime_root_json_and_fixed_apk_root(self):
        result = ARCHIVE.build_archive(self.inputs, 'x64', 1, self.root / 'consumer', catalog=self.catalog)
        tree = self.root / 'consumer' / result['directory']
        moved = self.root / 'with spaces and "quotes"'
        tree.rename(moved)
        information = json.loads(subprocess.check_output([str(moved / 'cbodotnet'), '--cbodotnet-info'], text=True))
        self.assertEqual(str(moved / 'payload'), information['sdkRoot'])
        self.assertEqual('musl', information['libc'])
        self.assertEqual('linux-musl-x64', information['targetRid'])
        fixed = ARCHIVE.launcher_text(self.plan('apk'), root='/opt/cbodotnet/10.0')
        self.assertIn('DOTNET_ROOT=/opt/cbodotnet/10.0', fixed)
        self.assertNotIn('LD_LIBRARY_PATH=', fixed)

    def test_missing_host_does_not_fall_back_to_a_dotnet_on_path(self):
        result = ARCHIVE.build_archive(self.inputs, 'x64', 1, self.root / 'consumer', catalog=self.catalog)
        tree = self.root / 'consumer' / result['directory']
        (tree / 'payload/dotnet').unlink()
        output = subprocess.run([str(tree / 'cbodotnet'), '--version'], text=True, capture_output=True)
        self.assertNotEqual(0, output.returncode)
        self.assertIn('selected archive payload host is missing', output.stderr)

    def test_unqualified_source_cannot_build_or_reuse_an_output_directory(self):
        with self.assertRaisesRegex(ValueError, 'not independently qualified'):
            ARCHIVE.build_archive(self.inputs, 'x64', 1, self.root / 'consumer')
        self.assertFalse((self.root / 'consumer').exists())
        (self.root / 'consumer').mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh ordinary directory'):
            ARCHIVE.build_archive(self.inputs, 'x64', 1, self.root / 'consumer', catalog=self.catalog)

    def test_smoke_includes_full_icu_calendars_timezones_and_trust_uses_normal_https(self):
        plan = self.plan()
        script = ARCHIVE.full_smoke_script(plan, Path('/payload'), Path('/cli'), Path('/work'))
        for required in ('ThaiBuddhistCalendar', 'UmAlQuraCalendar', 'Korean collation', 'Asia/Seoul',
                         'Europe/Paris', 'SslProtocols.Tls12', '<clear />', 'build --no-restore'):
            self.assertIn(required, script)
        trust = ARCHIVE.trust_probe_script(plan, Path('/payload'), Path('/cli'), Path('/work'))
        self.assertIn('X509Store(StoreName.Root,StoreLocation.LocalMachine)', trust)
        self.assertIn('/x86_64/APKINDEX.tar.gz', trust)
        self.assertNotIn('ServerCertificateCustomValidationCallback', trust)


class MuslElfAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root / 'payload'
        self.system = self.root / 'system'
        self.payload.mkdir()
        (self.system / 'lib').mkdir(parents=True)
        self.host = self.write(self.payload / 'dotnet')
        self.libc = self.write(self.system / 'lib/libc.musl-x86_64.so.1')
        self.records = {
            str(self.host): self.record(interpreter='/lib/ld-musl-x86_64.so.1', needed=['libc.musl-x86_64.so.1']),
            str(self.libc): self.record(),
        }

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\x7fELFfixture-' + path.name.encode())
        return path

    def record(self, **changes):
        return dict(dict(machine='Advanced Micro Devices X86-64', elfType='DYN', elfClass='ELF64',
                         interpreter=None, needed=[], runpaths=[], glibcRequirements=[], versionNeeds=[], versionDefinitions=[]), **changes)

    def audit(self, policy=None):
        with mock.patch.object(ARCHIVE, 'inspect_elf', side_effect=lambda path: copy.deepcopy(self.records[str(path)])):
            return ARCHIVE.audit_elf(self.payload, 'x64', policy, system_root=self.system, native=False)

    def test_host_transitive_closure_and_link_inventory_are_recorded(self):
        crypto = self.write(self.system / 'lib/libcrypto.so.3')
        self.records[str(crypto)] = self.record(needed=['libc.musl-x86_64.so.1'])
        self.records[str(self.host)]['needed'].append('libcrypto.so.3')
        (self.payload / 'host-alias').symlink_to('dotnet')
        result = self.audit()
        self.assertEqual(1, result['hostElfCount'])
        self.assertEqual(2, len(result['stockLibraries']))
        self.assertEqual('dotnet', result['symlinks'][0]['resolved'])
        self.assertFalse(result['native'])
        self.assertEqual({'libc.musl-x86_64.so.1', 'libcrypto.so.3'},
                         {row['needed'] for row in result['elfFiles'][0]['dependencies']})

    def test_glibc_interpreter_symbols_foreign_cpu_and_missing_library_fail_closed(self):
        for field, value in (('interpreter', '/lib64/ld-linux-x86-64.so.2'), ('glibcRequirements', ['GLIBC_2.17']),
                             ('machine', 'AArch64'), ('needed', ['missing-library.so'])):
            original = copy.deepcopy(self.records[str(self.host)])
            self.records[str(self.host)][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.audit()
            self.records[str(self.host)] = original

    def test_glibc_symbol_in_a_transitive_system_dependency_is_rejected(self):
        self.records[str(self.libc)]['glibcRequirements'] = ['GLIBC_2.39']
        with self.assertRaisesRegex(ValueError, 'GLIBC version requirements'):
            self.audit()

    def test_gcc_unwind_abi_label_requires_its_exact_stock_provider_definition(self):
        gcc = self.write(self.system / 'lib/libgcc_s.so.1')
        self.records[str(gcc)] = self.record(versionDefinitions=['GLIBC_2.0', 'GCC_3.0'])
        self.records[str(self.host)].update(needed=['libgcc_s.so.1'], glibcRequirements=['GLIBC_2.0'],
            versionNeeds=[dict(file='libgcc_s.so.1', versions=['GLIBC_2.0', 'GCC_3.0'])])
        report = self.audit()
        self.assertEqual([dict(file='libgcc_s.so.1', version='GLIBC_2.0', disposition='gcc-unwind-abi-label')],
                         report['elfFiles'][0]['reviewedAbiVersionLabels'])
        self.records[str(gcc)]['versionDefinitions'] = []
        with self.assertRaisesRegex(ValueError, 'does not define'):
            self.audit()
        self.records[str(gcc)]['versionDefinitions'] = ['GLIBC_2.0']
        self.records[str(self.host)]['versionNeeds'][0]['file'] = 'libc.so.6'
        with self.assertRaisesRegex(ValueError, 'genuine glibc version requirements'):
            self.audit()

    def test_exact_foreign_target_pack_can_be_classified_but_never_used_by_host(self):
        relative = 'packs/Microsoft.NETCore.App.Host.linux-arm64/10.0.14/runtimes/linux-arm64/native/apphost'
        foreign = self.write(self.payload / relative)
        self.records[str(foreign)] = self.record(machine='AArch64', interpreter='/lib/ld-linux-aarch64.so.1', glibcRequirements=['GLIBC_2.17'])
        policy = [dict(path=relative, sha256=hashlib.sha256(foreign.read_bytes()).hexdigest(),
                       targetRid='linux-arm64', reason='Foreign cross-target apphost link input; never executed by host SDK')]
        with self.assertRaisesRegex(ValueError, 'wrong architecture'):
            self.audit()
        result = self.audit(policy)
        self.assertEqual(1, result['nonHostElfCount'])
        self.assertEqual('non-host-target-pack', next(row for row in result['elfFiles'] if row['path'] == relative)['disposition'])
        self.records[str(self.host)]['needed'] = ['apphost']
        self.records[str(self.host)]['runpaths'] = ['$ORIGIN/' + str(Path(relative).parent)]
        with self.assertRaisesRegex(ValueError, 'resolves to a non-host target pack'):
            self.audit(policy)
        self.records[str(self.host)]['needed'] = ['libc.musl-x86_64.so.1']
        self.records[str(self.host)]['runpaths'] = []
        foreign.write_bytes(b'\x7fELFchanged')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            self.audit(policy)

    def test_generic_pack_exemptions_loader_tokens_and_escaping_links_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exact foreign RID pack'):
            self.audit([dict(path='packs/**', sha256='a' * 64, targetRid='linux-arm64', reason='Broad exemption')])
        self.records[str(self.host)]['runpaths'] = ['$LIB:/unreviewed']
        with self.assertRaisesRegex(ValueError, 'loader token'):
            self.audit()
        self.records[str(self.host)]['runpaths'] = []
        (self.payload / 'escape').symlink_to(self.libc)
        with self.assertRaisesRegex(ValueError, 'Payload link escapes'):
            self.audit()

    def test_native_guard_prevents_test_fixture_evidence_from_claiming_native_success(self):
        with self.assertRaisesRegex(ValueError, 'actual Alpine root'):
            ARCHIVE.audit_elf(self.payload, 'x64', system_root=self.system, native=True)


if __name__ == '__main__':
    unittest.main()
