#!/usr/bin/env python3
"""Bounded native x64 helper fixtures; these never qualify or build an SDK."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / name)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def elf(machine):
    data = bytearray(20); data[:6] = b'\x7fELF\x02\x01'; data[18:20] = machine.to_bytes(2, 'little')
    return bytes(data)


class NativeHelpers(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-x64-helper-fixture.')
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)

    def bootstrap_fixture(self, major):
        helper = module('bootstrap' + major + '-inputs.py'); source = self.root / ('source' + major)
        version, centos, rid, count = ('6.0.135', '7', 'linux-x64', 14) if major == '6' else ('7.0.118', '8', 'centos.8-x64', 12)
        archive = source / ('packages/archive/Private.SourceBuilt.Artifacts.' + version + '.centos.' + centos + '-x64.tar.gz')
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, 'w:gz') as stream:
            for name, data in [('PackageVersions.props', b'<Project/>')] + [
                    ('runtime.' + rid + '.Fixture' + str(index) + '.1.0.nupkg', b'fixture package') for index in range(count)]:
                item = tarfile.TarInfo(name); item.size = len(data); stream.addfile(item, io.BytesIO(data))
        sdk = write(source / '.dotnet/dotnet', elf(62))
        write(source / ('.dotnet/sdk/' + version + '/MSBuild.dll'), 'fixture versioned SDK')
        write(source / ('.dotnet/sdk/' + version + '/.version'), version)
        write(source / '.dotnet/dotnet-install.sh', '# fixture install source\n')
        write(source / 'prep.sh', '# fixture upstream prep source\n')
        write(source / 'packages/archive/archiveArtifacts.txt', 'https://example.invalid/pinned-original\n')
        if major == '6':
            for name, pin in [('installer', helper.INSTALLER), ('runtime', helper.RUNTIME)]:
                write(source / ('git-info/' + name + '.props'), '<Project><PropertyGroup><GitCommitHash>' + pin + '</GitCommitHash></PropertyGroup></Project>')
            write(source / 'scripts/bootstrap/buildBootstrapPreviouslySB.csproj', '<Project><ItemGroup/></Project>')
            write(source / 'scripts/bootstrap/OverrideBootstrapVersions.props', '<Project/>')
        pin = {key: value for key, value in helper.fingerprint(archive).items() if key != 'path'}
        inputs = self.root / ('inputs' + major); inputs.mkdir()
        return helper, source, inputs, archive, sdk, version, rid, count, pin

    def test_native_original_state_machine_preserves_bytes_and_rejects_mutation(self):
        for major in ('6', '7'):
            with self.subTest(major=major):
                helper, source, inputs, archive, sdk, version, rid, count, pin = self.bootstrap_fixture(major)
                original = archive.read_bytes()
                for index, action in enumerate(['save-originals', 'finalize', 'verify']):
                    report = self.root / ('report' + major + str(index) + '.json')
                    argv = ['bootstrap', action, '--source-dir', str(source), '--inputs-dir', str(inputs), '--report', str(report), '--arch', 'x64']
                    with mock.patch.object(sys, 'argv', argv), mock.patch.object(helper.platform, 'machine', return_value='x86_64'), \
                            mock.patch.object(helper.subprocess, 'check_output', return_value=version), mock.patch.object(helper, 'NATIVE_PSB', pin), \
                            contextlib.redirect_stdout(io.StringIO()):
                        helper.main()
                    self.assertEqual(archive.read_bytes(), original)
                record = json.loads(report.read_text())
                self.assertEqual(record['targetArchitecture'], 'x64'); self.assertEqual(record['bootstrapMode'], 'native-original-inputs')
                self.assertEqual(record['nativePackageRid'], rid); self.assertEqual(len(record['nativePackageEntries']), count)
                self.assertNotIn('arm64PackageEntries', record)
                saved = next((inputs / ('original-bootstrap' + major)).glob('*.tar.gz'))
                self.assertEqual(saved.read_bytes(), original)
                archive.write_bytes(original + b'modified')
                with mock.patch.object(helper, 'NATIVE_PSB', pin), self.assertRaisesRegex(ValueError, 'original bytes'):
                    helper.native_inputs(source, [archive], record, sdk, version)
                sdk.write_bytes(elf(183))
                with self.assertRaisesRegex(ValueError, 'machine 62'): helper.native_host(sdk)

    def test_native_bootstrap_rejects_other_host_before_sdk_execution(self):
        for major in ('6', '7'):
            helper = module('bootstrap' + major + '-inputs.py')
            argv = ['bootstrap', 'verify', '--source-dir', str(self.root), '--inputs-dir', str(self.root), '--report', str(self.root / 'report'), '--arch', 'x64']
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(helper.platform, 'machine', return_value='aarch64'), \
                    mock.patch.object(helper.subprocess, 'check_output') as execute, self.assertRaisesRegex(ValueError, 'native Linux x64'):
                helper.main()
            execute.assert_not_called()

    def test_native_source_preparation_uses_normal_original_prep_only(self):
        for major in ('6', '7'):
            for arch, machine in [('arm64', 'aarch64'), ('x64', 'x86_64')]:
                with self.subTest(major=major, arch=arch):
                    base = self.root / (major + arch); scripts = base / 'scripts'; scripts.mkdir(parents=True)
                    source, inputs, reports = [base / name for name in ['source', 'inputs', 'reports']]
                    for path in [source, inputs, reports]: path.mkdir()
                    script = scripts / ('prepare-source' + major + '.sh'); shutil.copyfile(ROOT / 'scripts' / script.name, script)
                    write(scripts / ('bootstrap' + major + '-inputs.py'), 'import sys\nfrom pathlib import Path\nwith (Path(__file__).parent/"helper-calls").open("a") as out:out.write(" ".join(sys.argv[1:])+"\\n")\n')
                    prep = write(source / 'prep.sh', '#!/bin/sh\nprintf "%s\\n" "$*" >> prep-calls\n'); prep.chmod(0o755)
                    tools = base / 'tools'; tools.mkdir()
                    uname = write(tools / 'uname', '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo ' + machine + '; fi\n'); uname.chmod(0o755)
                    import os
                    result = subprocess.run(['bash', str(script), str(source), str(inputs), str(reports), '--arch', arch],
                        env={**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH']}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = (source / 'prep-calls').read_text().splitlines()
                    self.assertEqual(calls, ['', '--bootstrap'] if arch == 'arm64' else [''])
                    self.assertTrue(all('--arch ' + arch in line for line in (scripts / 'helper-calls').read_text().splitlines()))

    def test_x64_sysroot_inventory_requires_amd64_libc_and_package_architecture(self):
        for major in ('6', '7'):
            with self.subTest(major=major):
                base = self.root / ('sysroot' + major); root = base / 'x64-xenial'; reports = base / 'reports'; reports.mkdir(parents=True)
                libc = write(root / 'lib/x86_64-linux-gnu/libc-2.23.so', elf(62))
                (libc.parent / 'libc.so.6').symlink_to(libc.name)
                index = write(reports / 'sysroot-files.sha256', hashlib.sha256(libc.read_bytes()).hexdigest() + '  ' + str(libc) + '\n')
                write(reports / 'sysroot-file-list.sha256', hashlib.sha256(index.read_bytes()).hexdigest() + '  ' + str(index) + '\n')
                write(reports / 'sysroot-symlinks.tsv', str(libc.parent / 'libc.so.6') + '\t' + libc.name + '\n')
                packages = write(reports / 'sysroot-packages.tsv', 'libc6:amd64\t2.23\tamd64\n')
                command = [sys.executable, str(ROOT / 'scripts' / ('verify-sysroot' + major + '.py')), '--sysroot', str(root), '--reports-dir', str(reports), '--arch', 'x64']
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0, result.stderr)
                packages.write_text('libc6:arm64\t2.23\tarm64\n')
                self.assertNotEqual(subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 0)
                packages.write_text('libc6:amd64\t2.23\tamd64\n'); libc.write_bytes(elf(183))
                self.assertNotEqual(subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 0)

    def test_omnisharp_x64_pin_is_separate_from_arm64(self):
        for major in ('6', '7'):
            helper = module('prepare-net' + major + '-test-tools.py')
            arm, native = helper.tool_input(), helper.tool_input('x64')
            self.assertEqual(native['machine'], 62); self.assertEqual(native['bytes'], 43149563)
            self.assertEqual(native['sha256'], 'c631cf552590ee8f00cbea441e99a94f689bf1832f1f8de2d5a00d5d5d18140c')
            self.assertIn('linux-x64', native['url']); self.assertNotEqual(native['sha256'], arm['sha256'])
            self.assertNotEqual(native['cacheName'], arm['cacheName'])

    def test_native_x64_seccomp_adds_only_the_resolved_fchmodat2_rule(self):
        class Call:
            def __init__(self, result): self.result=result
            def __call__(self, *args): return self.result
        for major in ('6','7'):
            helper=module('prepare-net'+major+'-seccomp.py');base=self.root/('seccomp'+major);base.mkdir()
            policy={'defaultAction':'SCMP_ACT_ERRNO','defaultErrnoRet':1,
                    'archMap':[{'architecture':'SCMP_ARCH_X86_64','subArchitectures':['SCMP_ARCH_X86','SCMP_ARCH_X32']}],
                    'syscalls':[{'names':['read','write'],'action':'SCMP_ACT_ALLOW'}]}
            original=write(base/'base.json',json.dumps(policy));output=base/'derived.json';report=base/'report.json'
            library=SimpleNamespace(seccomp_arch_native=Call(0xC000003E),seccomp_syscall_resolve_name=Call(452),
                                    seccomp_version=Call(SimpleNamespace(contents=SimpleNamespace(major=2,minor=5,micro=5))))
            argv=['seccomp','--source-policy',str(original),'--output-policy',str(output),'--report',str(report),'--arch','x64']
            with mock.patch.object(sys,'argv',argv),mock.patch.object(helper.platform,'machine',return_value='x86_64'),\
                    mock.patch.object(helper.ctypes.util,'find_library',return_value='fixture-libseccomp'),\
                    mock.patch.object(helper.ctypes,'CDLL',return_value=library),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(helper.main(),0)
            derived=json.loads(output.read_text());rule=derived['syscalls'].pop()
            self.assertEqual(rule,{'names':['fchmodat2'],'action':'SCMP_ACT_ALLOW'});self.assertEqual(derived,policy)
            receipt=json.loads(report.read_text());self.assertEqual(receipt['nativeArchitecture'],'x86_64')
            self.assertEqual(receipt['libseccomp']['nativeArchitectureToken'],'0xc000003e')
            self.assertTrue(receipt['allOtherRulesUnchanged']);self.assertFalse(receipt['seccompUnconfined'])


if __name__ == '__main__': unittest.main()
