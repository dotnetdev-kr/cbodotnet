"""Security boundaries used when admitting musl producer artifacts."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('musl_sdk_producer', ROOT / 'scripts/musl-sdk.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
INPUT_SPEC = importlib.util.spec_from_file_location('musl_input_recorder', ROOT / 'scripts/musl-sdk-inputs.py')
INPUTS = importlib.util.module_from_spec(INPUT_SPEC)
INPUT_SPEC.loader.exec_module(INPUTS)


def elf(loader='/lib/ld-musl-x86_64.so.1', machine=62):
    data = bytearray(120)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', data, 16, 3, machine)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<I', data, 64, 3)
    struct.pack_into('<Q', data, 72, 120)
    value = loader.encode() + b'\0'
    struct.pack_into('<Q', data, 96, len(value))
    return bytes(data) + value


class DeliveryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'producer-validation.json').write_text('{}')
        (self.root / 'payload').write_bytes(b'original bytes')
        self.row = dict(path='payload', **M.fingerprint(self.root / 'payload'))

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_byte_binding_accepts_original_and_rejects_tampering(self):
        M.delivery_index(self.root, [self.row])
        (self.root / 'payload').write_bytes(b'altered bytes')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            M.delivery_index(self.root, [self.row])

    def test_path_escape_absolute_duplicate_and_nonportable_paths_are_rejected(self):
        for name in ('../outside', '/outside', 'nested/../payload', './payload', 'C:/payload', 'a\\b'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                M.delivery_index(self.root, [dict(self.row, path=name)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            M.delivery_index(self.root, [self.row, self.row])

    def test_unbound_files_are_rejected(self):
        (self.root / 'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'Unbound'):
            M.delivery_index(self.root, [self.row])

    def test_symlink_alias_is_rejected(self):
        try:
            (self.root / 'alias').symlink_to('payload')
        except OSError:
            self.skipTest('Symlinks unavailable on this test filesystem')
        with self.assertRaises(ValueError):
            M.delivery_index(self.root, [self.row])

    def test_duplicate_json_properties_are_rejected(self):
        path = self.root / 'record.json'
        path.write_text('{"status":"failed","status":"passed"}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.load_json(path)

    def test_passed_label_without_required_stages_is_rejected(self):
        result = dict(schemaVersion=1, status='passed', kind='musl-sdk-producer-validation',
                      diagnosticPtrace=False,
                      libc='musl', sdkVersion=M.SDK, sourceCommit=M.SOURCE, sharedVmrCommit=M.SHARED,
                      architecture='x64', targetRid='linux-musl-x64', projectCommit='a' * 40,
                      runId='1', runAttempt='1', allRequiredStages=['build'], files=[self.row])
        (self.root / 'producer-validation.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'six required'):
            M.validate(self.root)


class DiagnosticPtraceTests(unittest.TestCase):
    def producer(self, root, diagnostic=True):
        producer = object.__new__(M.Producer)
        producer.args = SimpleNamespace(arch='aarch64',run_id='123',run_attempt='1',host_reports=None,build_id='20261107.8')
        producer.id = M.identity('aarch64')
        producer.project = 'a'*40
        producer.diagnostic_ptrace = diagnostic
        producer.workspace = root/'workspace'
        producer.output = root/'delivery'
        producer.reports = producer.output/'reports'
        producer.home = root/'home'
        producer.inputs = root/'inputs'
        producer.source = root/'source'
        producer.engine = M.container_engine(diagnostic)
        producer.commands = []
        producer.image = 'isolated-test-image'
        producer.run = lambda command, **kwargs: producer.commands.append(list(map(str,command)))
        return producer

    def test_only_opted_in_source_container_gets_effective_ptrace_request(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(M,'validate_default_container_policy') as policy:
            producer = self.producer(Path(temporary))
            producer.container(['source-probe'],source=True)
            producer.container(['consumer-probe'],source=False)
            source,consumer = producer.commands
            self.assertIn('--cap-add=SYS_PTRACE',source)
            self.assertIn('--security-opt=apparmor=unconfined',source)
            for command in (source,consumer):
                self.assertIn('--cap-drop=all',command)
                self.assertIn('--security-opt=no-new-privileges',command)
            self.assertFalse(any(value.startswith('--cap-add') for value in consumer))
            self.assertFalse(any(value.startswith('--security-opt=apparmor=') for value in consumer))
            policy.assert_not_called()
            producer.diagnostic_ptrace = False
            producer.engine = M.container_engine(False)
            producer.container(['ordinary-source'],source=True)
            self.assertFalse(any(value.startswith('--cap-add') for value in producer.commands[-1]))
            self.assertFalse(any(value.startswith('--security-opt=apparmor=') for value in producer.commands[-1]))
            policy.assert_called_once_with(producer.output,producer.commands[-1])

    def test_diagnostic_success_and_failure_stop_after_build_and_remain_unqualified(self):
        for failed in (False,True):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as temporary:
                producer = self.producer(Path(temporary))
                producer.prepare = mock.Mock()
                producer.build = mock.Mock(side_effect=ValueError('controlled build failure') if failed else None)
                for name in ('scan','test','collect','verify','seal'):
                    setattr(producer,name,mock.Mock())
                if failed:
                    with self.assertRaisesRegex(ValueError,'controlled build failure'):producer.execute()
                else:
                    producer.execute()
                producer.prepare.assert_called_once();producer.build.assert_called_once()
                for name in ('scan','test','collect','verify','seal'):getattr(producer,name).assert_not_called()
                result = M.load_json(producer.output/'producer-validation.json')
                self.assertEqual('diagnostic-only',result['status'])
                self.assertTrue(result['diagnosticPtrace']);self.assertFalse(result['productionQualification'])
                self.assertEqual('unconfined',result['sourceAppArmorPolicy'])
                self.assertEqual(['prepare','build'],[stage['stage'] for stage in result['stages']])
                self.assertEqual('failed' if failed else 'passed',result['stages'][-1]['status'])
                with self.assertRaisesRegex(ValueError,'Diagnostic ptrace'):M.validate(producer.output)

    def test_missing_true_or_nonboolean_mode_and_manual_diagnostic_seal_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);producer=self.producer(root)
            with self.assertRaisesRegex(ValueError,'never seal'):M.Producer.seal(producer)
            for marker in ({},{'diagnosticPtrace':True},{'diagnosticPtrace':0},{'diagnosticPtrace':'false'}):
                (root/'producer-validation.json').write_text(json.dumps(dict(status='passed',**marker)))
                with self.subTest(marker=marker),self.assertRaisesRegex(ValueError,'Diagnostic ptrace'):
                    M.validate(root)

    def test_normal_execution_still_runs_every_required_stage_and_seals(self):
        with tempfile.TemporaryDirectory() as temporary:
            producer=self.producer(Path(temporary),diagnostic=False)
            order=[]
            for name in ('prepare','build','scan','test','collect','verify','seal'):
                setattr(producer,name,lambda name=name:order.append(name))
            producer.execute()
            self.assertEqual(['prepare','build','scan','test','collect','verify','seal'],order)

    def test_diagnostic_build_exercises_restore_and_original_scan_without_full_sdk_compilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            producer = self.producer(Path(temporary))
            calls = []
            def container(command, **options):
                calls.append((command, options))
                if '--projects' in command:
                    target = producer.reports/'build/diagnostic-binaries/NewBinaries.txt'
                    target.parent.mkdir(parents=True)
                    target.write_bytes(b'')
            producer.container = container
            M.Producer.build(producer)
            self.assertEqual(2,len(calls))
            restore,scan = [command for command,options in calls]
            self.assertEqual(producer.build_command()+['/p:Build=false','/p:Publish=false'],restore)
            self.assertIn('--projects',scan)
            self.assertIn('/vmr/eng/init-detect-binaries.proj',scan)
            self.assertIn('/p:Publish=false',scan)
            self.assertNotIn('/p:Build=false',scan)
            for command in (restore,scan):
                self.assertIn('/m:2',command)
                self.assertFalse(any('SkipBinaryScan' in value or 'nodeReuse' in value for value in command))
            result = M.load_json(producer.reports/'build/diagnostic-controls.json')
            self.assertTrue(result['zeroNewBinaries'])
            self.assertFalse(result['fullSdkCompilation'])
            self.assertFalse(result['productionQualification'])
            producer = self.producer(Path(temporary)/'normal',diagnostic=False)
            producer.container = mock.Mock()
            M.Producer.build(producer)
            producer.container.assert_called_once_with(producer.build_command(),log=producer.reports/'build/build.log')


class DockerEngineAdmissionTests(unittest.TestCase):
    def documents(self):
        version=dict(Client=dict(Version='28.5.1'),Server=dict(Version='28.5.1'))
        info=dict(SecurityOptions=['name=apparmor','name=seccomp,profile=builtin','name=cgroupns'],
            Driver='overlay2',CgroupDriver='systemd',ServerVersion='28.5.1',KernelVersion='6.11.0-1018-azure',
            Architecture='aarch64',OSType='linux',DockerRootDir='/var/lib/docker')
        return version,info

    def prepared(self, root):
        version,info=self.documents()
        engine=M.engine_identity('docker',version,info,M.identity('aarch64'))
        engine['commandPrefix']=M.DOCKER_ENGINE
        for action,document in [('version',version),('info',info)]:
            name='reports/prepare/container-engine-'+action+'.json';path=root/name
            M.write(path,document)
            engine[action+'Report']=dict(path=name,**M.fingerprint(path))
        prepare=dict(containerEngine=engine,nativeKernelVersion=info['KernelVersion'],
            sourceAppArmorPolicy='engine-default',consumerAppArmorPolicy='engine-default',
            sourceSeccompPolicy='engine-default',consumerSeccompPolicy='engine-default')
        stages={'prepare':dict(commands=[M.DOCKER_ENGINE+['version','--format',M.ENGINE_JSON_FORMAT],
                                        M.DOCKER_ENGINE+['info','--format',M.DOCKER_INFO_FORMAT]])}
        for index,stage in enumerate(('build','verify'),1):
            name='container-'+str(index).zfill(4);directory=root/'reports/diagnostics'/name;directory.mkdir(parents=True)
            (directory/'process-status.txt').write_text('Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n'
                +'\n'.join(key+':\t0000000000000000' for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
                +'\nNoNewPrivs:\t1\nSeccomp:\t2\n')
            (directory/'apparmor-current.txt').write_text('docker-default (enforce)\n')
            stages[stage]=dict(commands=[M.DOCKER_ENGINE+['run','--rm','--user','1001:1001','--cap-drop=all',
                '--security-opt=no-new-privileges','--volume','/runner/reports/diagnostics/'+name+':/diag','sha256:'+'a'*64,'true']])
        return prepare,stages

    def test_normal_docker_and_diagnostic_podman_are_explicit_separate_backends(self):
        self.assertEqual(['sudo','-n','--','docker'],M.container_engine(False))
        self.assertEqual(['sudo','-n','--','podman','--cgroup-manager=cgroupfs','--events-backend=file'],M.container_engine(True))
        version,info=self.documents()
        self.assertEqual('docker',M.engine_identity('docker',version,info,M.identity('aarch64'))['name'])
        for change in [lambda d:d.update(Architecture='x86_64'),lambda d:d.update(ServerVersion='99.0.0'),
                       lambda d:d['SecurityOptions'].append('name=rootless'),
                       lambda d:d.update(SecurityOptions=['name=seccomp,profile=builtin']),
                       lambda d:d['SecurityOptions'].append('name=apparmor,profile=/custom-policy')]:
            altered=json.loads(json.dumps(info));change(altered)
            with self.assertRaises(ValueError):M.engine_identity('docker',version,altered,M.identity('aarch64'))

    def test_actual_engine_reports_and_both_observed_container_policies_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);prepare,stages=self.prepared(root)
            M.validate_container_engine(root,prepare,stages,M.identity('aarch64'))
            for field,value in [('sourceAppArmorPolicy','unconfined'),('consumerSeccompPolicy','unconfined'),
                                ('nativeKernelVersion','another-kernel')]:
                altered=dict(prepare,**{field:value})
                with self.subTest(field=field),self.assertRaises(ValueError):
                    M.validate_container_engine(root,altered,stages,M.identity('aarch64'))
            for stage in ('build','verify'):
                for extra in ('--cap-add=SYS_PTRACE','--privileged','--security-opt=apparmor=unconfined','--security-opt=seccomp=unconfined'):
                    altered=json.loads(json.dumps(stages));altered[stage]['commands'][0].insert(5,extra)
                    with self.subTest(stage=stage,extra=extra),self.assertRaisesRegex(ValueError,'default policies'):
                        M.validate_container_engine(root,prepare,altered,M.identity('aarch64'))
            stages['build']['commands'][0][3]='podman'
            with self.assertRaisesRegex(ValueError,'another container backend'):
                M.validate_container_engine(root,prepare,stages,M.identity('aarch64'))

    def test_process_evidence_rejects_actual_root_capability_or_lsm_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);prepare,stages=self.prepared(root)
            command=stages['verify']['commands'][0]
            path=root/'reports/diagnostics/container-0002/process-status.txt';raw=path.read_text()
            for change in [('Uid:\t1001','Uid:\t0'),('CapEff:\t0000000000000000','CapEff:\t0000000000080000'),
                           ('NoNewPrivs:\t1','NoNewPrivs:\t0'),('Seccomp:\t2','Seccomp:\t0')]:
                path.write_text(raw.replace(*change))
                with self.subTest(change=change),self.assertRaisesRegex(ValueError,'Actual Docker process'):
                    M.validate_default_container_policy(root,command)
            path.write_text(raw)
            (path.parent/'apparmor-current.txt').write_text('unconfined\n')
            with self.assertRaisesRegex(ValueError,'default enforced AppArmor'):
                M.validate_default_container_policy(root,command)

    def test_raw_version_bytes_and_independent_podman_schema_are_not_relabelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);prepare,stages=self.prepared(root)
            path=root/'reports/prepare/container-engine-version.json';path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'report bytes differ'):
                M.validate_container_engine(root,prepare,stages,M.identity('aarch64'))
        with tempfile.TemporaryDirectory() as temporary:
            producer=DiagnosticPtraceTests().producer(Path(temporary))
            version=dict(Client=dict(Version='3.4.4'))
            info=dict(host=dict(arch='arm64',kernel='6.18.54.1',cgroupManager='cgroupfs',security=dict(rootless=False)),
                      store=dict(graphDriverName='overlay'),version=dict(Version='3.4.4'))
            replies=iter([json.dumps(version),json.dumps(info)])
            producer.run=lambda *args,**kwargs:next(replies)
            producer.record_container_engine()
            self.assertEqual('podman',producer.engine_record['name'])
            self.assertEqual('3.4.4',producer.engine_record['serverVersion'])
            self.assertEqual(M.PODMAN_DIAGNOSTIC_ENGINE,producer.engine_record['commandPrefix'])


class ActualElfBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, bodies, hardlink=False):
        path = self.root / 'sdk.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, body in bodies:
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            if hardlink:
                info = tarfile.TarInfo('dotnet-link')
                info.type, info.linkname = tarfile.LNKTYPE, 'dotnet'
                archive.addfile(info)
        return path

    def test_header_loader_and_digest_are_bound_including_hardlinks(self):
        body = elf()
        found = M.sdk_elf_inventory(self.archive([('dotnet', body)], True), 62, '/lib/ld-musl-x86_64.so.1')
        self.assertEqual(set(found), {'dotnet', 'dotnet-link'})
        self.assertEqual(found['dotnet']['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(found['dotnet'], found['dotnet-link'])

    def test_relabelled_glibc_and_foreign_cpu_payloads_are_rejected(self):
        for body in (elf('/lib64/ld-linux-x86-64.so.2'), elf(machine=183)):
            with self.subTest(body=body[:24]), self.assertRaises(ValueError):
                M.sdk_elf_inventory(self.archive([('dotnet', body)]), 62, '/lib/ld-musl-x86_64.so.1')

    def test_duplicate_actual_payload_elf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            M.sdk_elf_inventory(self.archive([('dotnet', elf()), ('dotnet', elf())]),
                                62, '/lib/ld-musl-x86_64.so.1')


class ImportedInputObservationTests(unittest.TestCase):
    def test_actual_root_hook_preserves_embedded_project_xml_and_comments(self):
        original = b'''\xef\xbb\xbf<Project>
          <PropertyGroup><Generated><![CDATA[<Project><PropertyGroup /></Project>]]></Generated></PropertyGroup>
          <!-- An upstream example can also contain </Project> text. -->
        </Project>\n'''
        adjusted = M.instrument_input_recording(original)
        self.assertTrue(adjusted.startswith(b'\xef\xbb\xbf'))
        root = ET.fromstring(adjusted)
        self.assertEqual(root.find('PropertyGroup/Generated').text,
                         '<Project><PropertyGroup /></Project>')
        self.assertEqual(root[-1].get('Name'), 'RecordCommunityMuslImportedInputs')
        self.assertEqual(root[-1].get('BeforeTargets'), 'CleanupRepo')
        self.assertEqual(adjusted.count(b'</Project>'), original.count(b'</Project>'))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            M.instrument_input_recording(adjusted)

    def test_cleanup_does_not_destroy_recorded_actual_input_hashes_and_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'repository/artifacts/.packages'
            package = cache / 'upstream.package/1.0/upstream.package.1.0.nupkg'
            package.parent.mkdir(parents=True)
            package.write_bytes(b'actual immutable upstream package bytes')
            (package.parent / '.nupkg.metadata').write_text(json.dumps({'source': 'https://api.nuget.org/v3/index.json'}))
            output = root / 'evidence'
            INPUTS.record(cache, output, 'sdk')
            original = next(output.glob('*.json')).read_bytes()
            INPUTS.record(cache, output, 'sdk')
            self.assertEqual(len(list(output.glob('*.json'))), 1)
            package.unlink()
            record = json.loads(original)
            self.assertEqual(record['packages'][0]['source'], 'https://api.nuget.org/v3/index.json')
            self.assertEqual(record['packages'][0]['sha256'],
                             hashlib.sha256(b'actual immutable upstream package bytes').hexdigest())
            self.assertEqual(next(output.glob('*.json')).read_bytes(), original)


class FrozenApkInputTests(unittest.TestCase):
    def test_exact_stock_snapshots_are_copied_and_changed_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'scripts').mkdir()
            (root / 'scripts/seed-musl-apk-cache.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
            (root / 'inputs').mkdir()
            profile = {'apkIndexes': {}}
            for repository in ('main', 'community'):
                path = root / 'inputs' / (repository + '.tar.gz')
                path.write_bytes((repository + ' stock signed bytes').encode())
                profile['apkIndexes'][repository] = dict(snapshotPath='inputs/' + path.name,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            context = root / 'context'
            M.prepare_image_context(profile, context, root)
            self.assertEqual(sorted(p.name for p in context.iterdir()), ['apk-snapshots', 'seed-apk-cache.sh'])
            for repository in ('main', 'community'):
                self.assertEqual((context / 'apk-snapshots' / (repository + '-APKINDEX.tar.gz')).read_bytes(),
                                 (root / profile['apkIndexes'][repository]['snapshotPath']).read_bytes())
            (root / 'inputs/main.tar.gz').write_bytes(b'changed upstream bytes')
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                M.prepare_image_context(profile, root / 'changed-context', root)
            profile['apkIndexes']['main']['snapshotPath'] = '../outside'
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                M.prepare_image_context(profile, root / 'unsafe-context', root)


if __name__ == '__main__':
    unittest.main()

