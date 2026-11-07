#!/usr/bin/env python3
"""Build .NET 10.0.403 natively under pinned Alpine; never publishes or signs."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SOURCE = '5a2162bea6845eabc1fc721624a43568c65db3b1'
SHARED = '0427b9abbead3fa64c6655eb4290c537397131fa'
SDK = '10.0.403'
REPOSITORY = 'https://github.com/dotnet/dotnet'


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(block)
            for digest in hashes.values():
                digest.update(block)
    return dict(bytes=size, **{name: value.hexdigest() for name, value in hashes.items()})


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts
            and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary absolute path is required: ' + str(path))
    return path


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def identity(arch):
    return {'x64': dict(public='x64', machine='x86_64', image='amd64', rid='linux-musl-x64'),
            'aarch64': dict(public='aarch64', machine='aarch64', image='arm64', rid='linux-musl-arm64')}[arch]


class Producer:
    def __init__(self, args):
        self.args = args
        self.id = identity(args.arch)
        self.workspace = ordinary(args.workspace)
        self.output = ordinary(args.output_dir)
        require(self.workspace != self.output and self.workspace not in self.output.parents
                and self.output not in self.workspace.parents, 'Workspace and delivery must be separate')
        self.profile_path = ROOT / 'profiles' / ('dotnet-' + SDK + '-linux-musl-' + args.arch + '.json')
        self.profile = json.loads(self.profile_path.read_text())
        require(self.profile['source']['commit'] == SOURCE
                and self.profile['upstreamInputs']['sharedVmrCommit'] == SHARED
                and self.profile['target'] == dict(rid=self.id['rid'], libc='musl'),
                'Only the reviewed musl profile is accepted')
        self.source = self.workspace / 'source'
        self.shared = self.workspace / 'shared-source'
        self.home = self.workspace / 'home'
        self.inputs = self.workspace / 'inputs'
        self.reports = self.output / 'reports'
        self.image = None
        self.verify_image = None
        self.project = git(ROOT, 'rev-parse', 'HEAD')
        self.engine = ['sudo', '-n', '--', 'podman', '--cgroup-manager=cgroupfs', '--events-backend=file']
        self.commands = []

    def run(self, argv, log=None, capture=False):
        self.commands.append(list(map(str, argv)))
        print('Running: ' + json.dumps(self.commands[-1]), flush=True)
        if capture:
            return subprocess.check_output(argv, text=True).strip()
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open('x', encoding='utf-8') as stream:
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, encoding='utf-8', errors='replace')
                for line in process.stdout:
                    stream.write(line)
                    print(line, end='', flush=True)
                code = process.wait()
                require(code == 0, 'Command failed with exit code ' + str(code) + '; see ' + str(log))
        else:
            subprocess.run(argv, check=True)

    def container(self, command, *, network='host', source=True, image=None, log=None):
        argv = self.engine + ['run', '--rm', '--network=' + network, '--user', str(os.getuid()) + ':' + str(os.getgid()),
            '--cap-drop=all', '--security-opt=no-new-privileges',
            '--env', 'HOME=/home/build', '--env', 'DOTNET_CLI_HOME=/home/build',
            '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            '--env', 'DOTNET_GENERATE_ASPNET_CERTIFICATE=false', '--env', 'DOTNET_NOLOGO=1',
            '--env', 'DOTNET_PROCESSOR_COUNT=2', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', 'LANG=C.UTF-8', '--env', 'LC_ALL=C.UTF-8',
            '--volume', str(ROOT) + ':/project:ro', '--volume', str(self.output) + ':/delivery',
            '--volume', str(self.inputs) + ':/inputs:ro', '--volume', str(self.home) + ':/home/build']
        if source:
            argv += ['--volume', str(self.source) + ':/vmr', '--workdir', '/vmr']
        else:
            argv += ['--workdir', '/tmp']
        self.run(argv + [image or self.image] + command, log=log)

    def stage(self, name, action):
        target = self.reports / 'stages' / (name + '.json')
        start = dt.datetime.now(dt.timezone.utc).isoformat()
        count = len(self.commands)
        try:
            action()
        except Exception as error:
            write(target, dict(stage=name, status='failed', startedAtUtc=start,
                  finishedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(), error=str(error),
                  commands=self.commands[count:]))
            raise
        write(target, dict(stage=name, status='passed', startedAtUtc=start,
              finishedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(), commands=self.commands[count:]))

    def prepare(self):
        require(platform.system() == 'Linux' and platform.machine() == self.id['machine']
                and os.getuid() != 0, 'An unprivileged matching native Linux host is required')
        require(not git(ROOT, 'status', '--porcelain', '--untracked-files=all'),
                'The orchestration checkout must be pristine')
        require(not self.output.exists() and not self.source.exists()
                and not self.shared.exists(), 'Fresh source and delivery paths are required')
        self.output.mkdir(parents=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home.mkdir(mode=0o700)
        self.inputs.mkdir()
        (self.workspace / 'empty-context').mkdir()
        self.run(['git', 'clone', '--depth', '1', '--branch', 'v' + SDK, '--', REPOSITORY, str(self.source)],
                 self.reports / 'prepare/source.log')
        require(git(self.source, 'rev-parse', 'HEAD') == SOURCE, 'The fetched VMR tag changed')
        for command in (['git', 'init', str(self.shared)],
                        ['git', '-C', str(self.shared), 'remote', 'add', 'origin', REPOSITORY],
                        ['git', '-C', str(self.shared), 'fetch', '--no-tags', '--depth', '1', 'origin', SHARED],
                        ['git', '-C', str(self.shared), 'checkout', '--detach', 'FETCH_HEAD'],
                        ['git', '-C', str(self.shared), 'submodule', 'update', '--init', '--recursive', '--depth', '1']):
            self.run(command)
        require(git(self.shared, 'rev-parse', 'HEAD') == SHARED, 'The reused input sources changed')
        # These signed packages remain in the image and are copied into the evidence.
        recipe = ROOT / 'containers' / (self.args.arch + '-net10-musl.Containerfile')
        tag = 'localhost/cbodotnet-musl-build:' + self.args.run_id + '-' + self.args.arch
        self.run(self.engine + ['build', '--network=host', '--file', str(recipe), '--tag', tag,
                               str(self.workspace / 'empty-context')],
                 self.reports / 'prepare/image-build.log')
        inspect = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
        require(len(inspect) == 1 and inspect[0]['Architecture'] == self.id['image']
                and inspect[0]['Os'] == 'linux', 'A matching native image is required')
        self.image = inspect[0]['Id']
        write(self.reports / 'prepare/build-image.json', inspect)
        self.container(['sh', '-ec', 'cp -a /cbodotnet-apks /delivery/reports/prepare/apks; '
                        'apk --version > /delivery/reports/prepare/apk-version.txt; '
                        'apk info -vv > /delivery/reports/prepare/installed-packages.txt; '
                        'cp -a /etc/apk/keys /delivery/reports/prepare/apk-keys; '
                        'cp /etc/apk/repositories /delivery/reports/prepare/repositories; '
                        'test ! -e /lib/ld-linux-x86-64.so.2; test ! -e /lib/ld-linux-aarch64.so.1; '
                        '! apk info -e gcompat; ! apk info -e libc6-compat; '
                        'test "$(cat /etc/alpine-release)" = 3.24.4; '
                        '/usr/bin/clang-20 --version; cmake --version; ldd --version 2>&1 || test "$?" = 1'],
                       log=self.reports / 'prepare/native-tools.log')
        bootstrap = self.profile['bootstrap']
        archive = self.inputs / 'bootstrap-sdk.tar.gz'
        with urllib.request.urlopen(bootstrap['url'], timeout=120) as incoming, archive.open('xb') as out:
            shutil.copyfileobj(incoming, out, 1024 * 1024)
        fp = fingerprint(archive)
        require(fp['sha512'] == bootstrap['sha512'], 'Official bootstrap SDK SHA512 mismatch')
        dotnet = self.source / '.dotnet'
        dotnet.mkdir()
        with tarfile.open(archive, 'r:gz') as stream:
            stream.extractall(dotnet, filter='data')
        write(self.reports / 'prepare/bootstrap.json', dict(bootstrap, **fp))
        self.container(['/vmr/.dotnet/dotnet', '--info'], network='none',
                       log=self.reports / 'prepare/bootstrap-info.log')
        self.container(['python3', '/project/scripts/fetch-pinned-inputs.py',
                        '--profile', '/project/' + self.profile_path.relative_to(ROOT).as_posix(),
                        '--inputs-dir', '/delivery/pinned-inputs', '--reports-dir', '/delivery/reports/prepare'])
        # The feeder always uses /inputs/nuget, so preserve the fetched bytes in that mount.
        shutil.copytree(self.output / 'pinned-inputs/nuget', self.inputs / 'nuget')
        self.container(['python3', '/project/scripts/configure-feeds.py', '--source-dir', '/vmr',
                        '--reports-dir', '/delivery/reports/build'])
        write(self.reports / 'prepare/identity.json', dict(schemaVersion=1, sdkVersion=SDK,
              targetRid=self.id['rid'], libc='musl', sourceCommit=SOURCE, sharedVmrCommit=SHARED,
              projectCommit=self.project, runId=self.args.run_id, runAttempt=self.args.run_attempt,
              buildId=self.args.build_id, imageId=self.image, profile=dict(path=self.profile_path.name,
              **fingerprint(self.profile_path)), nativeArchitecture=platform.machine(), emulation=False))
        if self.args.host_reports:
            shutil.copytree(ordinary(self.args.host_reports), self.reports / 'ci-host')

    def build_command(self, test=False):
        arch = 'arm64' if self.args.arch == 'aarch64' else 'x64'
        args = ['./build.sh', '--configuration', 'Release', '--arch', arch, '--os', 'linux',
                '--rid', self.id['rid'], '--branding', 'release', '--official-build-id',
                self.args.build_id, '--clean-while-building', '--binaryLog',
                '/p:PortableBuild=true', '/p:CrossBuild=false', '/m:2']
        if test:
            args += ['--test', '/p:BinariesReportFile=/delivery/reports/scan/NewBinaries.txt']
        # No glibc sysroot, inherited compiler overrides, or global SDK lookup.
        return ['env', '-u', 'ROOTFS_DIR', '-u', 'CLR_CC', '-u', 'CLR_CXX',
                'CC=/usr/bin/clang-20', 'CXX=/usr/bin/clang++-20',
                'CLR_CC=/usr/bin/clang-20', 'CLR_CXX=/usr/bin/clang++-20'] + args

    def build(self):
        self.container(self.build_command(), log=self.reports / 'build/build.log')

    def scan(self):
        self.clean = self.workspace / 'clean-source'
        self.run(['git', 'clone', '--local', '--no-hardlinks', '--branch', 'v' + SDK,
                  '--', str(self.source), str(self.clean)])
        require(not git(self.clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'),
                'The independent scan checkout must be pristine')
        # Container does not mount the warm source writable during the actual scan.
        argv = self.engine + ['run', '--rm', '--network=none', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                '--env', 'HOME=/home/build', '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
                '--volume', str(self.home) + ':/home/build', '--volume', str(self.source) + ':/vmr:ro',
                '--volume', str(self.clean) + ':/clean:ro', '--volume', str(ROOT) + ':/project:ro',
                '--volume', str(self.output) + ':/delivery', self.image, '/vmr/.dotnet/dotnet', 'msbuild',
                '/project/scripts/scan-clean-source.proj', '/p:ScanReportDirectory=/delivery/reports/scan',
                '/verbosity:minimal', '/nologo', '/bl:/delivery/reports/scan/scan.binlog']
        self.run(argv, self.reports / 'scan/scan.log')
        report = self.reports / 'scan/NewBinaries.txt'
        require(report.is_file() and not report.read_bytes(), 'The original binary scan must report zero new binaries')
        require(not git(self.clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'),
                'The independent scan checkout changed')
        for name in ['eng/allowed-vmr-binaries.txt', 'eng/allowed-sb-binaries.txt']:
            require((self.clean / name).read_bytes() == subprocess.check_output(
                ['git', '-C', str(self.source), 'show', SOURCE + ':' + name]), 'Pinned upstream allowlist changed')

    def test(self):
        self.container(['python3', '/project/scripts/prepare-scenario-report-fence.py', 'apply',
                        '--version', '10', '--source-dir', '/vmr',
                        '--reports-dir', '/delivery/reports/test/scenario-report-fence'])
        self.container(self.build_command(True), log=self.reports / 'test/test.log')
        common = self.source / 'artifacts/TestResults/Release/Microsoft.DotNet.Tests.trx'
        scenarios = list((self.source / 'artifacts/TestResults/Release/scenario-tests').glob('*.xml'))
        require(len(scenarios) == 1, 'Exactly one fresh scenario suite result is required')
        # This pure parser enforces the pinned 13 common / 36 scenario test identities,
        # including the only two accepted upstream skips. It has no libc assumptions.
        tests = module('musl_upstream_tests', 'ci-net10-evidence.py').parse_tests(common, scenarios[0])
        write(self.reports / 'test/upstream-summary.json', tests)
        shutil.copyfile(common, self.reports / 'test/common.trx')
        shutil.copyfile(scenarios[0], self.reports / 'test/scenarios.xml')

    def collect(self):
        collector = module('musl_existing_collector', 'collect-artifacts.py')
        upstream, candidates, _ = collector.select_sdk(self.source, SDK, self.id['rid'], exact_name=True)
        fp = fingerprint(upstream)
        require(all({key: row[key] for key in fp} == fp for row in candidates), 'Conflicting SDK archives')
        name = 'cbodotnet-sdk-' + SDK + '-linux-musl-' + self.args.arch + '-build.' + self.args.run_id + '.tar.gz'
        self.archive = self.output / name
        shutil.copyfile(upstream, self.archive)
        require(fingerprint(self.archive) == fp, 'Archive bytes changed during collection')
        markers = {}
        with tarfile.open(self.archive, 'r:gz') as stream:
            for framework in ('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'):
                name_in_tar = 'shared/' + framework + '/10.0.14/.version'
                matches = [m for m in stream.getmembers() if m.name.lstrip('./') == name_in_tar]
                require(len(matches) == 1, 'Missing/ambiguous shared version marker: ' + framework)
                raw = stream.extractfile(matches[0]).read(4097)
                require(raw.decode('utf-8-sig').strip().splitlines() == [SHARED, '10.0.14'],
                        'Imported musl runtime must identify the retained shared source revision')
                markers[framework] = dict(path=name_in_tar, sha256=hashlib.sha256(raw).hexdigest())
        shared_source = module('musl_shared_source', 'ci-net10-shared-source.py')
        shared_identity = shared_source.checkout_identity(self.shared, SHARED)
        imported = []
        for package in sorted((self.home / '.nuget/packages').rglob('*.nupkg')):
            require(not package.is_symlink(), 'A restored package is redirected')
            metadata_path = package.parent / '.nupkg.metadata'
            metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
            imported.append(dict(path=package.relative_to(self.home).as_posix(),
                                 source=metadata.get('source'), **fingerprint(package)))
        require(imported, 'Actual restored upstream input inventory is required')
        write(self.reports / 'restored-inputs.json', dict(schemaVersion=1, packages=imported,
              scope='Actual restored package bytes and NuGet recorded origins; these are imported inputs.'))
        roots = self.reports / 'source-roots.json'
        write(roots, dict(schemaVersion=1, roots=[
            dict(name='vmr', path=str(self.source), kind='git', expectedCommit=SOURCE, role='built-sdk-vmr-source'),
            dict(name='shared-vmr', path=str(self.shared), kind='git', expectedCommit=SHARED,
                 role='source-for-reused-shared-input')]))
        packer = module('musl_source_packer', 'package-used-source.py')
        packer.pack(SimpleNamespace(project_root=ROOT, project_commit=self.project, output_dir=self.output / 'sources',
            roots_json=roots, sdk_version=SDK, target_rid=self.id['rid'], run_id=self.args.run_id,
            run_attempt=self.args.run_attempt))
        packer.verify(SimpleNamespace(release_dir=self.output, expected_project_commit=self.project,
            expected_run_id=self.args.run_id, expected_run_attempt=self.args.run_attempt,
            expected_target_rid=self.id['rid']))
        write(self.reports / 'construction.json', dict(sourceOnly=False, sdkSource=SOURCE,
              sharedSource=shared_identity, sharedFrameworkMarkers=markers,
              runtimeVersion='10.0.14', bootstrapSdk='10.0.401',
              sharedSdkPackage='10.0.114-servicing.26522.126',
              components=[dict(component='sdk-and-managed-tooling', origin='rebuilt', sourceCommit=SOURCE),
                          dict(component='shared-frameworks-and-runtime-packs', origin='imported-upstream-musl',
                               sourceCommit=SHARED)],
              note='Regular 4xx VMR build; shared frameworks are reused public musl inputs, not locally rebuilt.'))
        write(self.output / 'producer-sdk.json', dict(schemaVersion=1, kind='musl-sdk-build',
              sdkVersion=SDK, targetRid=self.id['rid'], libc='musl', architecture=self.args.arch,
              sourceCommit=SOURCE, sharedVmrCommit=SHARED, projectCommit=self.project,
              runId=self.args.run_id, runAttempt=self.args.run_attempt, producerRevision=1,
              sdk=dict(name=self.archive.name, **fp), imageId=self.image))

    def verify(self):
        # Brand/alias/APK/OCI qualification is separate; this checks the unchanged producer SDK.
        recipe = ROOT / 'containers' / (self.args.arch + '-net10-musl-runtime.Containerfile')
        tag = 'localhost/cbodotnet-musl-verify:' + self.args.run_id + '-' + self.args.arch
        self.run(self.engine + ['build', '--network=host', '--file', str(recipe), '--tag', tag,
                               str(self.workspace / 'empty-context')],
                 self.reports / 'verify/image-build.log')
        inspect = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
        require(len(inspect) == 1 and inspect[0]['Architecture'] == self.id['image'], 'Wrong verification image architecture')
        self.verify_image = inspect[0]['Id']
        write(self.reports / 'verify/image.json', inspect)
        arch = 'arm64' if self.args.arch == 'aarch64' else 'x64'
        self.container(['sh', '-ec', '! command -v dotnet; ! apk info -e gcompat; ! apk info -e libc6-compat; '
            'test "$(cat /etc/alpine-release)" = 3.24.4; '
            'bash /project/scripts/verify-sdk.sh --archive /delivery/' + self.archive.name +
            ' --output-dir /delivery/reports/verify/sdk --expected-version 10.0.403 --expected-rid ' +
            self.id['rid'] + ' --arch ' + arch +
            '; python3 /project/scripts/musl-sdk-audit.py --archive /delivery/' + self.archive.name +
            ' --output /delivery/reports/verify/elf.json --arch ' + self.args.arch],
            network='none', source=False, image=self.verify_image, log=self.reports / 'verify/native.log')

    def seal(self):
        required = ['prepare', 'build', 'scan', 'test', 'collect', 'verify']
        for stage in required:
            require(json.loads((self.reports / 'stages' / (stage + '.json')).read_text())['status'] == 'passed',
                    'Required stage did not pass: ' + stage)
        require(not any(p.is_symlink() for p in self.output.rglob('*')), 'Delivery may not contain external symlinks')
        rows = [dict(path=p.relative_to(self.output).as_posix(), **fingerprint(p))
                for p in sorted(self.output.rglob('*')) if p.is_file() and not p.is_symlink()]
        write(self.output / 'producer-validation.json', dict(schemaVersion=1, status='passed',
              kind='musl-sdk-producer-validation', sdkVersion=SDK, targetRid=self.id['rid'], libc='musl',
              architecture=self.args.arch, projectCommit=self.project, sourceCommit=SOURCE,
              sharedVmrCommit=SHARED, runId=self.args.run_id, runAttempt=self.args.run_attempt,
              allRequiredStages=required, files=rows,
              scope='Unchanged native musl SDK producer. Consumer branding, APK, OCI, HTTPS and installer admission require separate evidence.'))

    def execute(self):
        self.stage('prepare', self.prepare)
        monitor = None
        if self.args.host_reports:
            arch = 'arm64' if self.args.arch == 'aarch64' else 'x64'
            command = ['bash', str(ROOT / 'scripts/ci-net10-host.sh'), 'monitor', '--arch', arch,
                       '--workspace', str(self.workspace), '--reports-dir', str(self.reports / 'ci-host')]
            monitor = subprocess.Popen(command)
        try:
            for name in ['build', 'scan', 'test', 'collect', 'verify']:
                self.stage(name, getattr(self, name))
        finally:
            if monitor is not None:
                monitor.terminate()
                require(monitor.wait(timeout=60) == 0, 'Resource monitor failed')
        self.seal()


def validate(release):
    release = ordinary(release)
    result = json.loads((release / 'producer-validation.json').read_text())
    require(result['schemaVersion'] == 1 and result['status'] == 'passed' and result['libc'] == 'musl'
            and result['sdkVersion'] == SDK and result['sourceCommit'] == SOURCE
            and result['sharedVmrCommit'] == SHARED, 'Unexpected producer validation identity')
    require(result['targetRid'] == identity(result['architecture'])['rid'], 'Producer libc/RID mismatch')
    expected = {row['path']: row for row in result['files']}
    actual = {p.relative_to(release).as_posix() for p in release.rglob('*') if p.is_file() and not p.is_symlink()}
    require(actual == set(expected) | {'producer-validation.json'}, 'Unbound/missing delivery files')
    for name, row in expected.items():
        require(not (release / name).is_symlink()
                and all(row[key] == value for key, value in fingerprint(release / name).items()),
                'Bound producer bytes changed: ' + name)
    print('Native musl producer evidence and all bytes verified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    for name in ['workspace', 'output-dir']:
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--host-reports', type=Path)
    for name in ['build-id', 'run-id', 'run-attempt']:
        run.add_argument('--' + name, required=True)
    check = commands.add_parser('validate')
    check.add_argument('--release-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'run':
        require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id)
                and all(re.fullmatch(r'[1-9][0-9]*', item) for item in [args.run_id, args.run_attempt]),
                'Invalid build/run identity')
        Producer(args).execute()
    else:
        validate(args.release_dir)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
