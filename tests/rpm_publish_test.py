"""Keep RPM signing behind native admission and retries on frozen bytes."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rpm_publish as PUBLISH


class RpmPublishTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.received = self.root / 'received'
        self.received.mkdir()
        self.identity = dict(repository='dotnetdev-kr/cbodotnet', workflow='.github/workflows/distribution-release.yml',
                             commit='a' * 40, runId='123', runAttempt='2')
        self.environment = dict(GITHUB_REF='refs/heads/main', GITHUB_REPOSITORY='dotnetdev-kr/cbodotnet',
            GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_SHA='b' * 40,
            GITHUB_WORKFLOW_REF='dotnetdev-kr/cbodotnet/.github/workflows/distribution-release.yml@refs/heads/main')
        self.contract = {'operatingSystems': {'fedora-45': {'id': 'fedora', 'versionId': '45', 'dependencies': ['glibc']}}}
        self.policy = {'channels': {'rpm': {'candidateMatrix': [dict(variant='fedora-45', architecture=arch)
            for arch in ('x64', 'aarch64')], 'requiredChecks': ['dnf-install', 'package-signatures', 'repository-metadata']}}}
        self.items, self.plans = [], {}
        for public, architecture in [('x64', 'x86_64'), ('aarch64', 'aarch64')]:
            directory = self.received / public
            directory.mkdir()
            (directory / 'commands').mkdir()
            (directory / 'inputs').mkdir()
            plan = dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1, sourceManifestSha256='c' * 64,
                variant='fedora-45', architecture=dict(public=public, rpm=architecture),
                package=dict(name='cbodotnet-sdk-10.0', rpmRelease='1.cbot.fedora45'))
            self.plans[public] = plan
            packages = []
            for kind, name, version, release, arch in [
                ('sdk', 'cbodotnet-sdk-10.0', '10.0.403', '1.cbot.fedora45', architecture),
                ('host', 'cbodotnet-host', '1.0.0', '1.cbot.fedora45', 'noarch')]:
                path = directory / f'{name}-{version}-{release}.{arch}.rpm'
                path.write_bytes((kind + ('-' + public if kind == 'sdk' else '')).encode())
                row = dict(PUBLISH.descriptor(path), path=path.name, kind=kind)
                row.pop('name')
                packages.append(row)
            artifact = directory / packages[0]['path']
            packaged = dict(schemaVersion=1, contractVersion=2, identity=dict(channel='rpm', variant='fedora-45',
                sdkVersion='10.0.403', packageRevision=1), architecture=public, artifact=PUBLISH.descriptor(artifact),
                orchestration=self.identity, source={'qualified': True}, producer={'native': True},
                branding={'approved': True}, commands={'default': '/usr/bin/cbodotnet'}, extraFiles=[{'sha256': 'd' * 64}])
            report = {**copy.deepcopy(packaged), 'phase': 'prepublication', 'scope': 'channel-installation', 'status': 'passed',
                'checks': {name: 'passed' for name in PUBLISH.PREPUBLICATION_CHECKS | {'dnf-install'}},
                'target': dict(native=True, osId='fedora', versionId='45', architecture=public, dependencies={'glibc': 'glibc-2'})}
            for name, content in [('package.json', packaged), ('report.json', report), ('package-build.json',
                 dict(schemaVersion=1, channel='rpm', plan=plan, payloadPreserved=True, packages=packages))]:
                (directory / name).write_text(json.dumps(content))
            self.items.append(dict(package=packaged, packagePath=str(directory / 'package.json'),
                artifactPath=str(artifact), reportPath=str(directory / 'report.json'),
                commandsRoot=str(directory / 'commands'), inputsDirectory=str(directory / 'inputs')))

    def canonical(self, plan, artifact, identity, **kwargs):
        item = next(row for row in self.items if row['package']['architecture'] == plan['architecture']['public'])
        return {**copy.deepcopy(item['package']), 'artifact': PUBLISH.descriptor(artifact)}

    def execute(self, command, **kwargs):
        if command[0] == 'rpm' and '--queryformat' in command:
            path = Path(command[-1])
            header=re.fullmatch(r'(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm',path.name)
            return '\n'.join(header.groups())+'\n'
        if command[0] == 'rpmsign':
            path = Path(command[-1])
            path.write_bytes(path.read_bytes() + b'-signed-once')
            return ''
        raise AssertionError('Unexpected command: ' + str(command))

    def patches(self):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.dict(os.environ, self.environment))
        stack.enter_context(mock.patch.object(PUBLISH, 'source_identity', return_value=self.identity))
        stack.enter_context(mock.patch.object(PUBLISH.CORE, 'unpack_deliveries', return_value=self.items))
        stack.enter_context(mock.patch.object(PUBLISH, 'load_status', return_value=self.policy))
        stack.enter_context(mock.patch.object(PUBLISH, 'load_contract', return_value=self.contract))
        stack.enter_context(mock.patch.object(PUBLISH, 'local_intake', side_effect=lambda directory, channel, variant, arch, revision: self.plans[arch]))
        stack.enter_context(mock.patch.object(PUBLISH, 'package_record', side_effect=self.canonical))
        return stack

    def core3(self):
        for item in self.items:
            public=item['package']['architecture'];plan=self.plans[public];directory=Path(item['artifactPath']).parent
            plan.update(sdkVersion='3.0.103',package=dict(name='cbodotnet-sdk-3.0',rpmRelease='1.cbot.fedora45'))
            path=directory/'package-build.json';build=json.loads(path.read_bytes());build['plan']=plan
            sdk=build['packages'][0];old=directory/sdk['path'];new=directory/old.name.replace('10.0-10.0.403','3.0-3.0.103')
            old.rename(new);sdk['path']=new.name;item['artifactPath']=str(new)
            for kind,name in [('compatibility','cbodotnet-compat-rocky9'),('native-http-compatibility','cbodotnet-compat-curl-rocky8')]:
                package=directory/f'{name}-2026.11.4-1.cbot.fedora45.{plan["architecture"]["rpm"]}.rpm'
                package.write_bytes((kind+'-'+public).encode());row=dict(PUBLISH.descriptor(package),path=package.name,kind=kind);row.pop('name')
                build['packages'].append(row)
            for key,name in [('compatibilityAsset','base'),('nativeHttpCompatibilityAsset','curl')]:
                companion=directory/(public+'-'+name+'.tar.gz');companion.write_bytes((name+'-companion').encode())
                build[key]=dict(path=companion.name,size=companion.stat().st_size,sha256=PUBLISH.sha256_file(companion))
            path.write_text(json.dumps(build))
            item['package']['identity']['sdkVersion']='3.0.103';item['package']['artifact']=PUBLISH.descriptor(new)
            Path(item['packagePath']).write_text(json.dumps(item['package']))
            report=json.loads(Path(item['reportPath']).read_bytes());report.update(identity=item['package']['identity'],artifact=item['package']['artifact'])
            from native_curl_fixture import evidence, ca_evidence
            report.update(evidence('3.0.103', public, 'rpm'))
            report.update(ca_evidence())
            Path(item['reportPath']).write_text(json.dumps(report))

    def test_core3_requires_exact_fourth_package_before_any_signer_use(self):
        self.core3();item=self.items[0];path=Path(item['artifactPath']).parent/'package-build.json'
        with self.patches(),mock.patch('downstream_release.validate_legacy_evidence'),mock.patch.object(PUBLISH.CORE,'run',side_effect=self.execute) as commands:
            self.assertEqual(4,len(PUBLISH.preflight(item,self.received,self.identity,self.policy,self.contract)[3]['packages']))
            build=json.loads(path.read_bytes());build['packages'].pop();path.write_text(json.dumps(build))
            with self.assertRaisesRegex(ValueError,'ownership components'):
                PUBLISH.preflight(item,self.received,self.identity,self.policy,self.contract)
            self.assertFalse(any(call.args[0][0]=='rpmsign' for call in commands.call_args_list))

    def test_core3_signs_and_retains_native_http_kind_and_binds_second_companion(self):
        self.core3();seen=[]
        def repositories(builds,channel,output,signer,**kwargs):
            output.mkdir();assets=[];names=set()
            for path in builds:
                build=json.loads(path.read_bytes())
                for row in build['packages']:
                    if row['kind']=='sdk':continue
                    prefix='rpm-fedora-45--' if row['kind']=='host' else 'rpm-fedora-45-'+build['plan']['architecture']['public']+'--'
                    name=prefix+row['path']
                    if name in names:continue
                    names.add(name);assets.append(dict(assetName=name,kind=row['kind'],sourcePath=str(path.parent/row['path']),size=row['size'],sha256=row['sha256']))
            archive=output/'rpm-fedora-45.tar.gz';archive.write_bytes(b'repository')
            return dict(packageAssets=assets,archives=[dict(path=archive.name,variant='fedora-45')])
        def bundle(items,output,commit,signer,keyring,**kwargs):
            names=[Path(row['path']).name for row in kwargs['extra_assets']]
            self.assertEqual(2,sum('cbodotnet-compat-curl-rocky8-' in name for name in names))
            self.assertTrue({'rpm-fedora-45-x64--x64-curl.tar.gz','rpm-fedora-45-aarch64--aarch64-curl.tar.gz'}<=set(names))
            for item in items:
                report=json.loads(Path(item['reportPath']).read_bytes())
                self.assertEqual({'sdk','host','compatibility','native-http-compatibility'},set(report['rpmSignatures']))
            return dict(tag='distribution-rpm-sdk-3.0.103-r1')
        def report_signature(path,signer):
            signature=Path(str(path)+'.asc');signature.write_bytes(b'signature');return signature
        def retained(row,*args):seen.append(row['kind']);return None
        with self.patches(),mock.patch('downstream_release.validate_legacy_evidence'),mock.patch.object(PUBLISH.CORE,'run',side_effect=self.execute), \
                mock.patch.object(PUBLISH,'retained_shared_rpm',side_effect=retained),mock.patch.object(PUBLISH,'verify_rpm_signature',return_value=dict(status='passed')), \
                mock.patch.object(PUBLISH,'build_repositories',side_effect=repositories),mock.patch.object(PUBLISH,'verify_repository'), \
                mock.patch.object(PUBLISH.CORE,'sign_report',side_effect=report_signature),mock.patch.object(PUBLISH,'create_bundle',side_effect=bundle):
            self.assertEqual('signed-and-frozen',PUBLISH.stage(self.received,self.root/'promotion','A'*40,self.root/'key.gpg','123','2')['status'])
        self.assertEqual(2,seen.count('native-http-compatibility'))

    def test_companion_assets_preserve_different_same_named_bytes_from_both_distro_targets(self):
        builds = []
        for variant in ('fedora-45', 'rocky-9.8'):
            directory = self.root / variant; directory.mkdir()
            build = dict(plan=dict(sdkVersion='3.0.103', variant=variant, architecture=dict(public='x64')))
            for key, name in (('compatibilityAsset', 'cbodotnet-compat-rocky9.tar.gz'),
                              ('nativeHttpCompatibilityAsset', 'cbodotnet-compat-curl-rocky8.tar.gz')):
                source = directory / name; source.write_bytes((variant + key).encode())
                build[key] = dict(path=name, size=source.stat().st_size, sha256=PUBLISH.sha256_file(source))
            path = directory / 'package-build.json'; path.write_text(json.dumps(build)); builds.append(path)
        output = self.root / 'companions'; output.mkdir()
        assets = PUBLISH.companion_assets(builds, output)
        self.assertEqual(4, len(assets))
        for path in builds:
            build = json.loads(path.read_bytes())
            for key in ('compatibilityAsset', 'nativeHttpCompatibilityAsset'):
                name = 'rpm-' + build['plan']['variant'] + '-x64--' + build[key]['path']
                self.assertEqual((path.parent / build[key]['path']).read_bytes(), (output / name).read_bytes())
        bad = json.loads(builds[0].read_bytes()); bad['compatibilityAsset']['sha256'] = '0' * 64
        builds[0].write_text(json.dumps(bad))
        fresh = self.root / 'bad-companions'; fresh.mkdir()
        with self.assertRaisesRegex(ValueError, 'exact build descriptor'):
            PUBLISH.companion_assets(builds, fresh)

    def test_core3_native_handler_and_fedora_ca_are_required_before_rpm_signing(self):
        self.core3()
        item = self.items[0]; path = Path(item['reportPath']); original = path.read_bytes()
        for field in ('nativeCurlHandler', 'nativeCaBundle'):
            report = json.loads(original); report.pop(field); path.write_text(json.dumps(report))
            with self.subTest(field=field), self.patches(), mock.patch('downstream_release.validate_legacy_evidence'), \
                    mock.patch.object(PUBLISH.CORE, 'run', side_effect=self.execute) as commands:
                with self.assertRaises(ValueError):
                    PUBLISH.preflight(item, self.received, self.identity, self.policy, self.contract)
                self.assertFalse(any(call.args[0][0] == 'rpmsign' for call in commands.call_args_list))

    def test_signer_permission_guard_rejects_other_repository_branch_event_and_workflow(self):
        for key, value in [('GITHUB_REF', 'refs/heads/topic'), ('GITHUB_REPOSITORY', 'fork/cbodotnet'),
                           ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_WORKFLOW_REF', 'other-workflow@refs/heads/main')]:
            with self.subTest(key=key), mock.patch.dict(os.environ, self.environment | {key: value}):
                with self.assertRaisesRegex(ValueError, 'protected main'):
                    PUBLISH.protected()

    def test_common_inspection_retains_differences_before_failing_without_signing(self):
        path = Path(self.items[-1]['artifactPath']).parent / 'package-build.json'
        build = json.loads(path.read_bytes())
        host = next(row for row in build['packages'] if row['kind'] == 'host')
        package = path.parent / host['path']
        package.write_bytes(package.read_bytes() + b'native-header-difference')
        host.update(size=package.stat().st_size, sha256=PUBLISH.sha256_file(package))
        path.write_text(json.dumps(build))
        def query(command):
            architecture = Path(command[-1]).parent.name
            return '<rpmHeader><rpmTag name="Optflags"><string>' + architecture + '</string></rpmTag></rpmHeader>'
        def unpack(received, *, destination):
            self.assertEqual(self.received, received)
            self.assertNotEqual(received, destination)
            for arch in ('x64', 'aarch64'):
                shutil.copytree(received / arch, destination / arch)
            return [{key: (str(destination / Path(value).relative_to(received)) if key != 'package' else value)
                     for key, value in item.items()} for item in self.items]
        before = {file.relative_to(self.received): file.read_bytes() for file in self.received.rglob('*') if file.is_file()}
        output = self.root / 'inspection'
        with mock.patch.object(PUBLISH.CORE, 'unpack_deliveries', side_effect=unpack), \
             mock.patch.object(PUBLISH.CORE, 'run', side_effect=query) as commands, \
             mock.patch.object(PUBLISH.subprocess, 'check_output', return_value=b'identical-cpio-payload'):
            with self.assertRaisesRegex(ValueError, 'see common-inspection.json'):
                PUBLISH.inspect_common(self.received, output)
        report = json.loads((output / 'common-inspection.json').read_bytes())
        self.assertEqual('failed', report['status'])
        self.assertEqual(2, len(report['packages']))
        self.assertTrue(report['differences'][0]['payloadIdentical'])
        self.assertIn('Optflags', report['differences'][0]['headers'])
        self.assertEqual(2, len(list(output.glob('*.rpm'))))
        self.assertTrue(all(call.args[0][:4] == ['rpm', '--query', '--package', '--xml'] for call in commands.call_args_list))
        self.assertEqual(before, {file.relative_to(self.received): file.read_bytes()
                                 for file in self.received.rglob('*') if file.is_file()})

    def source_metadata(self):
        return dict(head_branch='main', event='workflow_dispatch', path='.github/workflows/distribution-release.yml',
            repository={'full_name': 'dotnetdev-kr/cbodotnet'}, head_repository={'full_name': 'dotnetdev-kr/cbodotnet'},
            head_sha=self.identity['commit'])

    def jobs(self):
        return [dict(name='Install RPM packages on native ' + arch, conclusion='success') for arch in ('x64', 'aarch64')]

    def test_source_run_requires_exact_main_origin_and_successful_unique_native_jobs(self):
        metadata, jobs = self.source_metadata(), self.jobs()
        with mock.patch.object(PUBLISH.CORE, 'run', side_effect=[json.dumps(metadata), json.dumps({'jobs': jobs})]):
            self.assertEqual(self.identity, PUBLISH.source_identity('123', '2'))
        for field, value in [('head_branch', 'topic'), ('event', 'pull_request'), ('path', 'another.yml'),
                             ('head_repository', {'full_name': 'fork/cbodotnet'}), ('head_sha', 'short')]:
            with self.subTest(field=field), mock.patch.object(PUBLISH.CORE, 'run', return_value=json.dumps(metadata | {field: value})):
                with self.assertRaisesRegex(ValueError, 'trusted main workflow'):
                    PUBLISH.source_identity('123', '2')
        for changed in (jobs[:1], jobs + [jobs[0]], [jobs[0], jobs[1] | {'conclusion': 'failure'}]):
            with self.subTest(jobs=changed), mock.patch.object(PUBLISH.CORE, 'run', side_effect=[json.dumps(metadata), json.dumps({'jobs': changed})]):
                with self.assertRaisesRegex(ValueError, 'matrix did not pass'):
                    PUBLISH.source_identity('123', '2')

    def test_all_native_reports_are_admitted_before_any_rpm_is_signed(self):
        for field, value in [('scope', 'private-prefix'), ('phase', 'postpublication'),
                             ('checks', {}), ('target', {'native': False})]:
            with self.subTest(field=field):
                path = Path(self.items[-1]['reportPath'])
                original = path.read_bytes()
                report = json.loads(original)
                path.write_text(json.dumps(report | {field: value}))
                with self.patches(), mock.patch.object(PUBLISH.CORE, 'run', side_effect=self.execute) as commands:
                    with self.assertRaises(ValueError):
                        PUBLISH.stage(self.received, self.root / 'promotion', 'A' * 40, self.root / 'key.gpg', '123', '2')
                    self.assertFalse(any(call.args[0][0] == 'rpmsign' for call in commands.call_args_list))
                self.assertFalse((self.root / 'promotion').exists())
                path.write_bytes(original)

    def test_substituted_canonical_source_and_header_are_rejected_before_signing(self):
        with self.patches(), mock.patch.object(PUBLISH, 'package_record', return_value={}):
            with self.assertRaisesRegex(ValueError, 'canonical qualified inputs'):
                PUBLISH.preflight(self.items[0], self.received, self.identity, self.policy, self.contract)
        with self.patches(), mock.patch.object(PUBLISH.CORE, 'run', return_value='wrong-header'):
            with self.assertRaisesRegex(ValueError, 'RPM header differs'):
                PUBLISH.preflight(self.items[0], self.received, self.identity, self.policy, self.contract)

    def test_conflicting_common_bytes_fail_before_signer_and_output_creation(self):
        path = Path(self.items[-1]['artifactPath']).parent / 'package-build.json'
        build = json.loads(path.read_bytes())
        host = next(row for row in build['packages'] if row['kind'] == 'host')
        package = path.parent / host['path']
        package.write_bytes(b'conflicting-common-selector')
        host.update(size=package.stat().st_size, sha256=PUBLISH.sha256_file(package))
        path.write_text(json.dumps(build))
        with self.patches(), mock.patch.object(PUBLISH.CORE, 'run', side_effect=self.execute) as commands:
            with self.assertRaisesRegex(ValueError, 'Common RPM differs'):
                PUBLISH.stage(self.received, self.root / 'promotion', 'A' * 40, self.root / 'key.gpg', '123', '2')
            self.assertFalse(any(call.args[0][0] == 'rpmsign' for call in commands.call_args_list))
        self.assertFalse((self.root / 'promotion').exists())

    def test_sign_common_once_rebind_every_signed_hash_and_freeze_before_publish(self):
        def repositories(builds, channel, output, signer, **kwargs):
            output.mkdir()
            package_assets = []
            for path in builds:
                build = json.loads(path.read_bytes())
                for row in build['packages']:
                    package = path.parent / row['path']
                    self.assertEqual(row['sha256'], PUBLISH.sha256_file(package))
                    self.assertEqual(row['size'], package.stat().st_size)
                    if row['kind'] == 'host' and not package_assets:
                        package_assets.append(dict(assetName='rpm-fedora-45--' + row['path'], kind='host',
                            sourcePath=str(package), size=row['size'], sha256=row['sha256']))
            archive = output / 'rpm-fedora-45.tar.gz'
            archive.write_bytes(b'signed-repository')
            return dict(packageAssets=package_assets, archives=[dict(path=archive.name, variant='fedora-45')])
        def sign_report(path, key):
            signature = Path(str(path) + '.sig')
            signature.write_bytes(b'signed-report')
            return signature
        def bundle(items, output, commit, signer, keyring, **kwargs):
            for item in items:
                self.assertEqual(PUBLISH.descriptor(item['artifactPath']), item['package']['artifact'])
                report = json.loads(Path(item['reportPath']).read_bytes())
                self.assertEqual('passed', report['checks']['package-signatures'])
                self.assertEqual('passed', report['checks']['repository-metadata'])
            self.assertEqual(2, len(kwargs['extra_assets']))
            return {'tag': 'distribution-rpm-sdk-10.0.403-r1'}
        with self.patches(), mock.patch.object(PUBLISH.CORE, 'run', side_effect=self.execute) as commands:
            with mock.patch.object(PUBLISH, 'verify_rpm_signature', return_value={'status': 'passed'}), \
                 mock.patch.object(PUBLISH, 'build_repositories', side_effect=repositories), \
                 mock.patch.object(PUBLISH, 'verify_repository'), \
                 mock.patch.object(PUBLISH.CORE, 'sign_report', side_effect=sign_report), \
                 mock.patch.object(PUBLISH, 'create_bundle', side_effect=bundle), \
                 mock.patch.object(PUBLISH, 'publish_bundle') as publish:
                result = PUBLISH.stage(self.received, self.root / 'promotion', 'A' * 40, self.root / 'key.gpg', '123', '2')
                self.assertEqual('signed-and-frozen', result['status'])
                publish.assert_not_called()
            signed = [call.args[0][-1] for call in commands.call_args_list if call.args[0][0] == 'rpmsign']
            self.assertEqual(3, len(signed))
            self.assertEqual(1, sum(Path(path).name.startswith('cbodotnet-host-') for path in signed))
        self.assertEqual((Path(self.items[0]['artifactPath']).parent / 'cbodotnet-host-1.0.0-1.cbot.fedora45.noarch.rpm').read_bytes(),
                         (Path(self.items[1]['artifactPath']).parent / 'cbodotnet-host-1.0.0-1.cbot.fedora45.noarch.rpm').read_bytes())

    def test_frozen_resume_uses_exact_rpm_artifact_and_never_resigns(self):
        manifest = dict(identity={'channel': 'rpm'}, targetCommit='a' * 40)
        with mock.patch.dict(os.environ, self.environment), mock.patch.object(PUBLISH.CORE, 'receive_frozen') as receive, \
             mock.patch.object(PUBLISH, 'validate_bundle', return_value=manifest), \
             mock.patch.object(PUBLISH, 'publish_bundle', return_value={'status': 'published-postverified'}) as publish, \
             mock.patch.object(PUBLISH.CORE, 'run') as command:
            self.assertEqual('published-postverified', PUBLISH.publish(self.root, self.root / 'key.gpg', '456', '3')['status'])
            self.assertEqual(('rpm',), receive.call_args.kwargs['channels'])
            self.assertEqual('downstream-rpm-frozen', receive.call_args.kwargs['artifact_prefix'])
            self.assertEqual('Freeze signed RPM publication bytes', receive.call_args.kwargs['freeze_step'])
            self.assertEqual('a' * 40, publish.call_args.args[2])
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
