#!/usr/bin/env python3
"""Build .NET 10.0.403 natively under pinned Alpine; never publishes or signs."""
import argparse
import datetime as dt
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import urllib.request
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SOURCE = '5a2162bea6845eabc1fc721624a43568c65db3b1'
SHARED = '0427b9abbead3fa64c6655eb4290c537397131fa'
SDK = '10.0.403'
SOURCE_CULTURES = ('cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant')
SOURCE_CULTURE_PROJECT = 'scripts/probe-source-cultures.proj'
SOURCE_CULTURE_REPORT = 'reports/prepare/source-cultures.json'
REPOSITORY = 'https://github.com/dotnet/dotnet'
DOCKER_ENGINE = ['sudo', '-n', '--', 'docker']
PODMAN_DIAGNOSTIC_ENGINE = ['sudo', '-n', '--', 'podman', '--cgroup-manager=cgroupfs', '--events-backend=file']
ENGINE_JSON_FORMAT = '{{json .}}'
DOCKER_INFO_FIELDS = ('SecurityOptions', 'Driver', 'CgroupDriver', 'ServerVersion', 'KernelVersion',
                      'Architecture', 'OSType', 'DockerRootDir')
DOCKER_INFO_FORMAT = '{' + ','.join('"' + name + '":{{json .' + name + '}}' for name in DOCKER_INFO_FIELDS) + '}'
INPUT_RECORDING_HOOK = '''
  <Target Name="RecordCommunityMuslImportedInputs" BeforeTargets="CleanupRepo"
          Condition="Exists('$(RepoArtifactsPackageCache)')">
    <Exec Command="python3 /project/scripts/musl-sdk-inputs.py --cache &quot;$(RepoArtifactsPackageCache)&quot; --output-dir /delivery/reports/restored-inputs --repository &quot;$(RepositoryName)&quot;" />
  </Target>
'''


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


def container_engine(diagnostic):
    return list(PODMAN_DIAGNOSTIC_ENGINE if diagnostic else DOCKER_ENGINE)


def engine_identity(name, version, info, architecture):
    """Normalize actual CLI JSON while retaining each engine's native schema."""
    require(isinstance(version, dict) and isinstance(info, dict), 'Actual engine JSON objects required')
    client = version.get('Client', {})
    if name == 'docker':
        server = version.get('Server', {})
        options = info.get('SecurityOptions', [])
        require(isinstance(server, dict) and server.get('Version') == info.get('ServerVersion')
            and info.get('OSType') == 'linux' and isinstance(options, list)
            and 'name=apparmor' in options and 'name=seccomp,profile=builtin' in options
            and not any(value.startswith('name=rootless') or (value.startswith('name=apparmor') and value != 'name=apparmor')
                        or (value.startswith('name=seccomp') and value != 'name=seccomp,profile=builtin') for value in options),
            'Normal Docker requires its actual rootful daemon and default AppArmor/seccomp policies')
        selected = dict(serverVersion=server.get('Version'), architecture=info.get('Architecture'),
            kernelVersion=info.get('KernelVersion'), driver=info.get('Driver'), cgroupDriver=info.get('CgroupDriver'),
            securityOptions=options, dockerRootDir=info.get('DockerRootDir'))
    else:
        require(name == 'podman', 'Unreviewed native container engine')
        host = info.get('host', {})
        require(host.get('security', {}).get('rootless') is False, 'Diagnostic Podman must remain rootful')
        selected = dict(serverVersion=info.get('version', {}).get('Version'), architecture=host.get('arch'),
            kernelVersion=host.get('kernel'), driver=info.get('store', {}).get('graphDriverName'),
            cgroupDriver=host.get('cgroupManager'), securityOptions=host.get('security'), dockerRootDir=None)
    require(isinstance(client, dict) and all(isinstance(value, str) and 0 < len(value) <= 256
        for value in (client.get('Version'), selected['serverVersion'], selected['kernelVersion'],
                      selected['driver'], selected['cgroupDriver']))
        and selected['architecture'] in {architecture['machine'], architecture['image']},
        'Actual engine version, native CPU, kernel or storage information is absent')
    return dict(name=name, rootful=True, clientVersion=client['Version'], **selected)


def validate_default_container_policy(release, command):
    """Check observed process security, not only command-line intent."""
    require(command[:len(DOCKER_ENGINE)] == DOCKER_ENGINE and command[len(DOCKER_ENGINE)] == 'run'
        and '--cap-drop=all' in command and '--security-opt=no-new-privileges' in command
        and not any(value.startswith(('--cap-add', '--privileged')) for value in command)
        and all(value == '--security-opt=no-new-privileges' for value in command if value.startswith('--security-opt')),
        'Qualified Docker containers require default policies, dropped capabilities and no diagnostic overrides')
    require(command.count('--user') == 1, 'One exact non-root Docker user required')
    user = command[command.index('--user') + 1]
    require(re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', user), 'Qualified Docker user must be non-root')
    mounts = [value for value in command if value.endswith(':/diag')]
    require(len(mounts) == 1, 'One actual Docker diagnostic mount required')
    name = Path(mounts[0][:-len(':/diag')]).name
    require(re.fullmatch(r'container-[0-9]{4,}', name), 'Unsafe Docker diagnostic evidence path')
    directory = release / 'reports/diagnostics' / name
    raw = (directory / 'process-status.txt').read_text()
    require(len(raw) <= 65536, 'Oversized process security report')
    status = dict(line.split(':', 1) for line in raw.splitlines() if ':' in line)
    uid, gid = user.split(':')
    require(status.get('Uid', '').split() == [uid] * 4 and status.get('Gid', '').split() == [gid] * 4
        and status.get('NoNewPrivs', '').strip() == '1' and status.get('Seccomp', '').strip() == '2'
        and all(re.fullmatch(r'0{16}', status.get(key, '').strip()) for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')),
        'Actual Docker process user, dropped capabilities, no-new-privileges or seccomp differs')
    require((directory / 'apparmor-current.txt').read_text().strip('\0\r\n ') == 'docker-default (enforce)',
            'Actual Docker process is not confined by its default enforced AppArmor profile')


def validate_container_engine(release, prepare, stages, architecture):
    engine = prepare.get('containerEngine', {})
    paths = {'versionReport': 'reports/prepare/container-engine-version.json',
             'infoReport': 'reports/prepare/container-engine-info.json'}
    actual = {}
    for field, name in paths.items():
        path = ordinary(release / name)
        require(engine.get(field) == dict(path=name, **fingerprint(path)), 'Actual engine report bytes differ')
        actual[field] = load_json(path)
    observed = engine_identity('docker', actual['versionReport'], actual['infoReport'], architecture)
    require(engine == dict(observed, commandPrefix=DOCKER_ENGINE, **{key: engine[key] for key in paths})
        and prepare.get('nativeKernelVersion') == observed['kernelVersion']
        and prepare.get('sourceAppArmorPolicy') == prepare.get('consumerAppArmorPolicy') == 'engine-default'
        and prepare.get('sourceSeccompPolicy') == prepare.get('consumerSeccompPolicy') == 'engine-default',
        'Producer engine identity or default source/consumer policy differs')
    commands = [command for stage in stages.values() for command in stage['commands']]
    for action, formatting in [('version', ENGINE_JSON_FORMAT), ('info', DOCKER_INFO_FORMAT)]:
        require(DOCKER_ENGINE + [action, '--format', formatting] in stages['prepare']['commands'],
                'Actual normal Docker version/info command is absent')
    for command in commands:
        if any(Path(value).name in {'docker', 'podman'} for value in command[:4]):
            require(command[:len(DOCKER_ENGINE)] == DOCKER_ENGINE, 'Normal producer used another container backend')
            if command[len(DOCKER_ENGINE)] == 'run':
                validate_default_container_policy(release, command)


def validate_source_cultures(report):
    require(report.get('schemaVersion') == 1 and report.get('kind') == 'native-bootstrap-source-cultures'
        and report.get('status') == 'observed' and report.get('msbuildRuntimeType') == 'Core'
        and re.fullmatch(r'18\.9\.11(?:\.[0-9]+)?', report.get('msbuildVersion', ''))
        and report.get('msbuildToolsPath', '').rstrip('/') == '/vmr/.dotnet/sdk/10.0.401',
        'Source culture readiness must use the actual exact private native bootstrap MSBuild')
    rows = report.get('resources', [])
    require(isinstance(rows, list) and len(rows) == len(SOURCE_CULTURES)
        and len({row.get('resource') for row in rows}) == len(SOURCE_CULTURES)
        and {row.get('culture') for row in rows} == set(SOURCE_CULTURES)
        and all(row.get('withCulture') is True and row == dict(resource='CommunityProbe.' + row['culture'] + '.resx',
                            culture=row['culture'], withCulture=True) for row in rows),
        'Full ICU data must let the bootstrap AssignCulture task recognize all 13 source translation cultures')
    return report


def source_culture_proof(release, profile):
    report_path = release / SOURCE_CULTURE_REPORT
    observation = validate_source_cultures(load_json(report_path))
    data = [row for row in profile['buildPackages'] if row['P'] == 'icu-data-full']
    require(len(data) == 1, 'Full ICU data must be an explicit source-builder input')
    installed = (release / 'reports/prepare/installed-packages.txt').read_text().splitlines()
    package = 'icu-data-full-' + data[0]['V']
    require(any(line == package or line.startswith(package + ' - ') for line in installed)
        and not any(line.startswith('icu-data-en-') for line in installed),
        'Actual source builder must install the pinned full ICU provider instead of English-only data')
    return dict(schemaVersion=1, kind='native-bootstrap-source-culture-proof', status='passed',
        bootstrapVersion=profile['bootstrap']['version'], bootstrapRid=profile['bootstrap']['rid'],
        bootstrapSha512=profile['bootstrap']['sha512'], msbuildToolsPath=observation['msbuildToolsPath'],
        sourceDataPackage=package, cultures=list(SOURCE_CULTURES),
        project=dict(path=SOURCE_CULTURE_PROJECT, **fingerprint(ROOT / SOURCE_CULTURE_PROJECT)),
        report=dict(path=SOURCE_CULTURE_REPORT, **fingerprint(report_path)))


def instrument_input_recording(original):
    """Append to the actual XML root; embedded Project XML belongs to its source text."""
    root = ET.fromstring(original)
    require(root.tag == 'Project', 'Unexpected pinned VMR targets XML root')
    require(not any(target.get('Name') == 'RecordCommunityMuslImportedInputs' for target in root.findall('Target')),
            'Input recording hook already exists')
    text = original.decode('utf-8-sig')
    closing = re.search(r'</Project>\s*\Z', text)
    require(closing is not None, 'Pinned VMR targets must end at their real Project root')
    prefix = b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b''
    adjusted = prefix + (text[:closing.start()] + INPUT_RECORDING_HOOK + text[closing.start():]).encode('utf-8')
    parsed = ET.fromstring(adjusted)
    require(parsed[-1].tag == 'Target' and parsed[-1].get('Name') == 'RecordCommunityMuslImportedInputs'
            and parsed[-1].get('BeforeTargets') == 'CleanupRepo', 'Input observation hook must be a real root child')
    return adjusted


def prepare_image_context(profile, context, root=ROOT):
    """Copy only the reviewed stock indexes and seeder into the build context."""
    context.mkdir()
    snapshots = context / 'apk-snapshots'
    snapshots.mkdir()
    for repository in ('main', 'community'):
        record = profile['apkIndexes'][repository]
        name = record['snapshotPath']
        path = PurePosixPath(name)
        require(isinstance(name, str) and name == path.as_posix() and not path.is_absolute()
                and '..' not in path.parts and '\\' not in name and ':' not in name,
                'Unsafe repository-relative APK index snapshot path')
        source = root / path
        require(not any(p.is_symlink() for p in [source, *source.parents]) and source.is_file(),
                'APK index snapshots must be ordinary checked-in files')
        require(fingerprint(source)['sha256'] == record['sha256'],
                'Pinned APK index snapshot SHA256 mismatch: ' + repository)
        shutil.copyfile(source, snapshots / (repository + '-APKINDEX.tar.gz'))
    seeder = root / 'scripts/seed-musl-apk-cache.sh'
    require(seeder.is_file() and not seeder.is_symlink(), 'An ordinary APK snapshot seeder is required')
    shutil.copyfile(seeder, context / 'seed-apk-cache.sh')


def capture_failure_logs(destination):
    """Preserve bounded ordinary MSBuild failures without following tmp links."""
    destination = ordinary(destination)
    output = destination / 'msbuild-failures'
    output.mkdir()
    result = dict(schemaVersion=1, kind='msbuild-failure-log-capture', files=[], skipped=[])
    total = 0
    for directory, prefix in [('/tmp', 'tmp'), ('/tmp/MSBuildTemproot', 'temproot')]:
        try:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        except OSError as error:
            result['skipped'].append(dict(directory=directory, reason=str(error)))
            continue
        try:
            for name in sorted(os.listdir(parent)):
                if not fnmatch.fnmatchcase(name, 'MSBuild*.failure.txt'):
                    continue
                entry = dict(directory=directory, name=name)
                try:
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
                    with os.fdopen(descriptor, 'rb') as incoming:
                        info = os.fstat(incoming.fileno())
                        require(stat.S_ISREG(info.st_mode), 'Not an ordinary file')
                        require(0 <= info.st_size <= 16 * 1024**2, 'Failure log exceeds 16 MiB')
                        require(len(result['files']) < 128 and total + info.st_size <= 64 * 1024**2,
                                'Failure log capture exceeds its total bound')
                        data = incoming.read(16 * 1024**2 + 1)
                        require(len(data) == info.st_size, 'Failure log changed size during capture')
                    filename = prefix + '--' + hashlib.sha256(name.encode()).hexdigest()[:16] + '.failure.txt'
                    with (output / filename).open('xb') as outgoing:
                        outgoing.write(data)
                    result['files'].append(dict(entry, path='msbuild-failures/' + filename,
                        bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
                    total += len(data)
                except (OSError, ValueError) as error:
                    result['skipped'].append(dict(entry, reason=str(error)))
        finally:
            os.close(parent)
    write(destination / 'msbuild-failure-capture.json', result)
    return result


class Producer:
    def __init__(self, args):
        self.args = args
        self.diagnostic_ptrace = getattr(args, 'diagnostic_ptrace', False)
        require(type(self.diagnostic_ptrace) is bool, 'Diagnostic ptrace mode must be an explicit boolean')
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
        self.image_context = self.workspace / 'image-context'
        self.reports = self.output / 'reports'
        self.image = None
        self.verify_image = None
        self.project = git(ROOT, 'rev-parse', 'HEAD')
        self.engine = container_engine(self.diagnostic_ptrace)
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
            *self.container_security_options(source=source),
            '--env', 'HOME=/home/build', '--env', 'DOTNET_CLI_HOME=/home/build',
            '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            '--env', 'DOTNET_GENERATE_ASPNET_CERTIFICATE=false', '--env', 'DOTNET_NOLOGO=1',
            '--env', 'DOTNET_PROCESSOR_COUNT=2', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', 'LANG=C.UTF-8', '--env', 'LC_ALL=C.UTF-8',
            '--volume', str(ROOT) + ':/project:ro', '--volume', str(self.output) + ':/delivery',
            '--volume', str(self.inputs) + ':/inputs:ro', '--volume', str(self.home) + ':/home/build']
        if source:
            argv += self.bootstrap_environment()
            argv += ['--volume', str(self.source) + ':/vmr', '--workdir', '/vmr']
        else:
            argv += ['--workdir', '/tmp']
        argv += self.diagnostic_options()
        argv += [image or self.image] + self.observed_command(command)
        self.run(argv, log=log)
        if not self.diagnostic_ptrace:
            validate_default_container_policy(self.output, list(map(str, argv)))

    def container_security_options(self, *, source):
        options = ['--cap-drop=all', '--security-opt=no-new-privileges']
        if source and self.diagnostic_ptrace:
            options += ['--cap-add=SYS_PTRACE', '--security-opt=apparmor=unconfined']
        return options

    def record_container_engine(self):
        name = 'podman' if self.diagnostic_ptrace else 'docker'
        formats = [('version', ENGINE_JSON_FORMAT), ('info', ENGINE_JSON_FORMAT if self.diagnostic_ptrace else DOCKER_INFO_FORMAT)]
        reports, values = {}, {}
        for action, formatting in formats:
            raw = self.run(self.engine + [action, '--format', formatting], capture=True)
            path = self.reports / 'prepare' / ('container-engine-' + action + '.json')
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('x', encoding='utf-8') as stream:
                stream.write(raw + '\n')
            values[action] = load_json(path)
            reports[action + 'Report'] = dict(path=path.relative_to(self.output).as_posix(), **fingerprint(path))
        self.engine_record = dict(engine_identity(name, values['version'], values['info'], self.id),
                                 commandPrefix=self.engine, **reports)

    def bootstrap_environment(self):
        architecture = 'ARM64' if self.args.arch == 'aarch64' else 'X64'
        return ['--env', 'DOTNET_ROOT=/vmr/.dotnet', '--env', 'DOTNET_ROOT_' + architecture + '=/vmr/.dotnet',
                '--env', 'DOTNET_HOST_PATH=/vmr/.dotnet/dotnet']

    def diagnostic_options(self):
        path = self.reports / 'diagnostics' / ('container-' + str(len(self.commands)).zfill(4))
        path.mkdir(parents=True)
        options = ['--volume', str(path) + ':/diag', '--env', 'MSBUILDDEBUGPATH=/diag', '--env', 'MSBUILDDEBUGCOMM=1',
                '--env', 'DOTNET_DbgEnableMiniDump=1', '--env', 'DOTNET_DbgMiniDumpType=1',
                '--env', 'DOTNET_DbgMiniDumpName=/diag/dotnet_%e_%p_%t.dmp']
        if self.diagnostic_ptrace:
            options += ['--env', 'DOTNET_EnableCrashReport=1', '--env', 'DOTNET_CreateDumpDiagnostics=1']
        return options

    @staticmethod
    def observed_command(command):
        # Keep /tmp short for Unix sockets; only failure diagnostics use the mount.
        script = ('if [ -r /sys/fs/cgroup/memory.events ]; then '
                  'cat /sys/fs/cgroup/memory.events > /diag/memory-before.events; fi; '
                  'cat /proc/self/limits > /diag/process-limits.txt; '
                  'cat /proc/self/status > /diag/process-status.txt; '
                  'if [ -r /proc/self/attr/current ]; then cat /proc/self/attr/current > /diag/apparmor-current.txt; fi; '
                  'uname -a > /diag/kernel.txt; '
                  'for policy in /proc/sys/kernel/core_pattern /proc/sys/fs/suid_dumpable /proc/sys/kernel/yama/ptrace_scope; do '
                  'if [ -r "$policy" ]; then printf "%s=" "$policy" >> /diag/kernel-core-policy.txt; '
                  'cat "$policy" >> /diag/kernel-core-policy.txt; fi; done; '
                  '"$@"; result=$?; '
                  'if [ -r /sys/fs/cgroup/memory.events ]; then '
                  'cat /sys/fs/cgroup/memory.events > /diag/memory-after.events; fi; '
                  'python3 /project/scripts/musl-sdk.py capture-failure-logs --destination /diag '
                  '> /diag/failure-collection.log 2>&1 || :; '
                  'printf "%s\\n" "$result" > /diag/exit-code.txt; exit "$result"')
        return ['sh', '-c', script, 'musl-sdk-observed-command', *command]

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
        self.record_container_engine()
        prepare_image_context(self.profile, self.image_context)
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
                               str(self.image_context)],
                 self.reports / 'prepare/image-build.log')
        inspect = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
        require(len(inspect) == 1 and inspect[0]['Architecture'] == self.id['image']
                and inspect[0]['Os'] == 'linux', 'A matching native image is required')
        self.image = inspect[0]['Id']
        write(self.reports / 'prepare/build-image.json', inspect)
        self.prepare_runtime_image()
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
        self.container(['/vmr/.dotnet/sdk/10.0.401/MSBuild', '-version'], network='none',
                       log=self.reports / 'prepare/bootstrap-msbuild-apphost.log')
        if not self.diagnostic_ptrace:
            self.container(['/vmr/.dotnet/dotnet', 'msbuild', '/project/' + SOURCE_CULTURE_PROJECT,
                '/p:SourceCultureReport=/delivery/' + SOURCE_CULTURE_REPORT, '/t:ProbeSourceCultures', '/nr:false', '/nologo'],
                network='none', log=self.reports / 'prepare/source-cultures.log')
            write(self.reports / 'prepare/source-culture-proof.json', source_culture_proof(self.output, self.profile))
        self.container(['python3', '/project/scripts/fetch-pinned-inputs.py',
                        '--profile', '/project/' + self.profile_path.relative_to(ROOT).as_posix(),
                        '--inputs-dir', '/delivery/pinned-inputs', '--reports-dir', '/delivery/reports/prepare'])
        # The feeder always uses /inputs/nuget, so preserve the fetched bytes in that mount.
        shutil.copytree(self.output / 'pinned-inputs/nuget', self.inputs / 'nuget')
        self.container(['python3', '/project/scripts/configure-feeds.py', '--source-dir', '/vmr',
                        '--reports-dir', '/delivery/reports/build'])
        # Pinned VMR cleans each inner repo's artifacts/.packages directory. Record
        # package bytes and origins before that existing cleanup target runs.
        targets = self.source / 'repo-projects/Directory.Build.targets'
        original = targets.read_bytes()
        require(original == subprocess.check_output(['git', '-C', str(self.source), 'show',
                    SOURCE + ':repo-projects/Directory.Build.targets']), 'Pinned VMR targets changed before instrumentation')
        adjusted = instrument_input_recording(original)
        targets.write_bytes(adjusted)
        write(self.reports / 'prepare/input-recording-hook.json', dict(path='repo-projects/Directory.Build.targets',
              sourceCommit=SOURCE, originalSha256=hashlib.sha256(original).hexdigest(),
              adjustedSha256=hashlib.sha256(adjusted).hexdigest(), beforeTarget='CleanupRepo',
              scope='Observe actual NuGet input bytes before existing cleanup; package versions and component sources unchanged.'))
        write(self.reports / 'prepare/identity.json', dict(schemaVersion=1, sdkVersion=SDK,
              targetRid=self.id['rid'], libc='musl', sourceCommit=SOURCE, sharedVmrCommit=SHARED,
              projectCommit=self.project, runId=self.args.run_id, runAttempt=self.args.run_attempt,
              diagnosticPtrace=self.diagnostic_ptrace,
              sourceAppArmorPolicy='unconfined' if self.diagnostic_ptrace else 'engine-default',
              consumerAppArmorPolicy='engine-default', sourceSeccompPolicy='engine-default', consumerSeccompPolicy='engine-default',
              nativeKernelVersion=platform.release(), containerEngine=self.engine_record,
              buildId=self.args.build_id, imageId=self.image, verificationImageId=self.verify_image,
              bootstrapRoot='/vmr/.dotnet', profile=dict(path=self.profile_path.name,
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
        if not self.diagnostic_ptrace:
            self.container(self.build_command(), log=self.reports / 'build/build.log')
            return
        # Exercise both observed crash contexts without compiling the full SDK.
        # Keep the original traversal graph, task host, concurrency and allowlist.
        self.container(self.build_command() + ['/p:Build=false', '/p:Publish=false'],
                       log=self.reports / 'build/diagnostic-restore.log')
        self.container(self.build_command() + ['--projects', '/vmr/eng/init-detect-binaries.proj',
            '/p:Publish=false', '/p:BinariesReportDir=/delivery/reports/build/diagnostic-binaries'],
            log=self.reports / 'build/build.log')
        report = self.reports / 'build/diagnostic-binaries/NewBinaries.txt'
        require(report.is_file() and not report.read_bytes(),
                'Diagnostic original upstream scan must report zero new binaries')
        write(self.reports / 'build/diagnostic-controls.json', dict(schemaVersion=1,
            status='diagnostic-only', productionQualification=False, fullGraphRestore='passed',
            originalTaskHostScan='passed', zeroNewBinaries=True,
            report=dict(path='reports/build/diagnostic-binaries/NewBinaries.txt', **fingerprint(report)),
            fullSdkCompilation=False, sourceAppArmorPolicy='unconfined'))

    def scan(self):
        self.clean = self.workspace / 'clean-source'
        self.run(['git', 'clone', '--local', '--no-hardlinks', '--branch', 'v' + SDK,
                  '--', str(self.source), str(self.clean)])
        require(not git(self.clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'),
                'The independent scan checkout must be pristine')
        # Container does not mount the warm source writable during the actual scan.
        argv = self.engine + ['run', '--rm', '--network=none', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                *self.container_security_options(source=True),
                '--env', 'HOME=/home/build', '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
                '--volume', str(self.home) + ':/home/build', '--volume', str(self.source) + ':/vmr:ro',
                '--volume', str(self.clean) + ':/clean:ro', '--volume', str(ROOT) + ':/project:ro',
                '--volume', str(self.output) + ':/delivery'] + self.bootstrap_environment() + self.diagnostic_options()
        argv += [self.image] + self.observed_command(['/vmr/.dotnet/dotnet', 'msbuild',
                '/project/scripts/scan-clean-source.proj', '/p:ScanReportDirectory=/delivery/reports/scan',
                '/verbosity:minimal', '/nologo', '/bl:/delivery/reports/scan/scan.binlog'])
        self.run(argv, self.reports / 'scan/scan.log')
        if not self.diagnostic_ptrace:
            validate_default_container_policy(self.output, list(map(str, argv)))
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
        recorded = sorted((self.reports / 'restored-inputs').glob('*.json'))
        require(recorded, 'Actual inner repository NuGet caches must be recorded before cleanup')
        for path in recorded:
            record = load_json(path)
            require(record.get('schemaVersion') == 1 and record.get('packages'), 'Invalid pre-cleanup input record')
            imported.extend(dict(repository=record['repository'], cache=record['cache'], **row)
                            for row in record['packages'])
        caches = [self.home / '.nuget/packages', self.source / '.packages',
                  *sorted((self.source / 'src').glob('*/artifacts/.packages'))]
        for cache in caches:
            for package in sorted(cache.rglob('*.nupkg')):
                require(not package.is_symlink(), 'A restored package is redirected')
                metadata_path = package.parent / '.nupkg.metadata'
                metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
                imported.append(dict(cache=str(cache), path=package.relative_to(cache).as_posix(),
                                     source=metadata.get('source'), **fingerprint(package)))
        require(imported, 'Actual restored upstream input inventory is required')
        write(self.reports / 'restored-inputs.json', dict(schemaVersion=1, packages=imported,
              scope='Actual restored package bytes and NuGet recorded origins; these are imported inputs.'))
        (self.reports / 'ci-inputs').mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.reports / 'restored-inputs', self.reports / 'ci-inputs/restored-inputs')
        shutil.copyfile(self.reports / 'prepare/input-recording-hook.json',
                        self.reports / 'ci-inputs/input-recording-hook.json')
        roots = self.reports / 'source-roots.json'
        write(roots, dict(schemaVersion=1, roots=[
            dict(name='vmr', path=str(self.source), kind='git', expectedCommit=SOURCE, role='built-sdk-vmr-source'),
            dict(name='shared-vmr', path=str(self.shared), kind='git', expectedCommit=SHARED,
                 role='source-for-reused-shared-input')]))
        packer = module('musl_source_packer', 'package-used-source.py')
        (self.reports / 'ci').mkdir(parents=True, exist_ok=True)
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

    def prepare_runtime_image(self):
        # Freeze both authenticated APK transactions before the long compilation.
        recipe = ROOT / 'containers' / (self.args.arch + '-net10-musl-runtime.Containerfile')
        tag = 'localhost/cbodotnet-musl-verify:' + self.args.run_id + '-' + self.args.arch
        self.run(self.engine + ['build', '--network=host', '--file', str(recipe), '--tag', tag,
                               str(self.image_context)],
                 self.reports / 'prepare/runtime-image-build.log')
        inspect = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
        require(len(inspect) == 1 and inspect[0]['Architecture'] == self.id['image'], 'Wrong verification image architecture')
        self.verify_image = inspect[0]['Id']
        write(self.reports / 'verify/image.json', inspect)
        self.container(['sh', '-ec', '! command -v dotnet; ! apk info -e gcompat; ! apk info -e libc6-compat; '
            'test "$(cat /etc/alpine-release)" = 3.24.4; '
            'cp -a /cbodotnet-apks /delivery/reports/prepare/runtime-apks; '
            'apk info -vv > /delivery/reports/prepare/runtime-installed-packages.txt; '
            'cp -a /etc/apk/keys /delivery/reports/prepare/runtime-apk-keys'],
            network='none', source=False, image=self.verify_image,
            log=self.reports / 'prepare/runtime-image-inventory.log')

    def verify(self):
        # The SDK-free image is already frozen; verification cannot refresh repositories.
        require(self.verify_image is not None, 'The runtime image must be frozen in prepare')
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
        require(not self.diagnostic_ptrace, 'Diagnostic ptrace runs may never seal a qualified producer')
        required = ['prepare', 'build', 'scan', 'test', 'collect', 'verify']
        for stage in required:
            require(json.loads((self.reports / 'stages' / (stage + '.json')).read_text())['status'] == 'passed',
                    'Required stage did not pass: ' + stage)
        require(not any(p.is_symlink() for p in self.output.rglob('*')), 'Delivery may not contain external symlinks')
        rows = [dict(path=p.relative_to(self.output).as_posix(), **fingerprint(p))
                for p in sorted(self.output.rglob('*')) if p.is_file() and not p.is_symlink()]
        write(self.output / 'producer-validation.json', dict(schemaVersion=1, status='passed',
              kind='musl-sdk-producer-validation', sdkVersion=SDK, targetRid=self.id['rid'], libc='musl',
              diagnosticPtrace=False,
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
            for name in (['build'] if self.diagnostic_ptrace else ['build', 'scan', 'test', 'collect', 'verify']):
                self.stage(name, getattr(self, name))
        finally:
            try:
                if monitor is not None:
                    monitor.terminate()
                    require(monitor.wait(timeout=60) == 0, 'Resource monitor failed')
            finally:
                if self.diagnostic_ptrace:
                    write(self.output / 'producer-validation.json', dict(schemaVersion=1, status='diagnostic-only',
                        kind='musl-sdk-producer-diagnostic', diagnosticPtrace=True, productionQualification=False,
                        sourceAppArmorPolicy='unconfined',
                        sdkVersion=SDK, targetRid=self.id['rid'], libc='musl', architecture=self.args.arch,
                        projectCommit=self.project, sourceCommit=SOURCE, sharedVmrCommit=SHARED,
                        runId=self.args.run_id, runAttempt=self.args.run_attempt,
                        plannedStages=['prepare', 'build'], stages=[load_json(self.reports / 'stages' / (name + '.json'))
                            for name in ['prepare', 'build'] if (self.reports / 'stages' / (name + '.json')).is_file()],
                        scope='Source-only full-graph restore and original TaskHost scan control with SYS_PTRACE and AppArmor unconfined. No full SDK compilation/test/collect/consumer qualification or admission.'))
        if self.diagnostic_ptrace:
            return
        self.seal()


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def delivery_index(release, rows):
    """Bind a complete ordinary tree without interpreting untrusted paths."""
    require(isinstance(rows, list) and rows, 'A nonempty delivery inventory is required')
    expected = {}
    for row in rows:
        name = row.get('path')
        require(isinstance(name, str) and name and '\\' not in name and '\0' not in name,
                'A portable relative delivery path is required')
        path = PurePosixPath(name)
        require(not path.is_absolute() and path.as_posix() == name
                and all(part not in ('.', '..') for part in path.parts)
                and ':' not in name and name not in expected and name != 'producer-validation.json',
                'Unsafe/duplicate delivery path: ' + name)
        ordinary(release.joinpath(*path.parts))
        expected[name] = row
    tree = list(release.rglob('*'))
    require(not any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in tree),
            'Delivery must contain ordinary files/directories without symlinks')
    actual = {p.relative_to(release).as_posix() for p in tree if p.is_file()}
    require(actual == set(expected) | {'producer-validation.json'}, 'Unbound/missing delivery files')
    for name, row in expected.items():
        require(all(row.get(key) == value for key, value in fingerprint(release / name).items()),
                'Bound producer bytes changed: ' + name)
    return expected


def sdk_elf_inventory(archive, machine, loader):
    """Independently bind native ELF headers/interpreters and all bytes to the SDK TAR."""
    result = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for entry in stream:
            if not (entry.isfile() or entry.islnk()):
                continue
            incoming = stream.extractfile(entry)
            header = incoming.read(64)
            if header[:4] != b'\x7fELF':
                continue
            name = entry.name.removeprefix('./')
            require(name not in result and len(header) == 64 and header[4:6] == b'\x02\x01',
                    'Duplicate/invalid/non-ELF64 native archive entry')
            require(entry.size <= 512 * 1024 * 1024, 'Oversized native ELF archive entry')
            body = header + incoming.read(512 * 1024 * 1024 + 1)
            require((entry.islnk() or len(body) == entry.size) and len(body) <= 512 * 1024 * 1024
                    and struct.unpack_from('<H', body, 18)[0] == machine,
                    'Foreign-machine/truncated actual SDK ELF: ' + name)
            offset = struct.unpack_from('<Q', body, 32)[0]
            width, count = struct.unpack_from('<HH', body, 54)
            require((count == 0 or width >= 56) and offset + width * count <= len(body),
                    'Invalid ELF program header table: ' + name)
            interpreters = []
            for index in range(count):
                position = offset + width * index
                if struct.unpack_from('<I', body, position)[0] != 3:
                    continue
                start = struct.unpack_from('<Q', body, position + 8)[0]
                length = struct.unpack_from('<Q', body, position + 32)[0]
                require(0 < length <= 4096 and start + length <= len(body), 'Invalid ELF interpreter')
                value = body[start:start + length]
                require(value.endswith(b'\0'), 'Non-terminated ELF interpreter')
                interpreters.append(value[:-1].decode('utf-8'))
            require(interpreters in ([], [loader]), 'Non-musl actual SDK ELF interpreter: ' + name)
            result[name] = dict(sha256=hashlib.sha256(body).hexdigest(),
                                interpreter=interpreters[0] if interpreters else None)
    return result


def validate(release):
    release = ordinary(release)
    result = load_json(release / 'producer-validation.json')
    require(result.get('diagnosticPtrace') is False, 'Diagnostic ptrace or unspecified diagnostic mode cannot qualify')
    required_stages = ['prepare', 'build', 'scan', 'test', 'collect', 'verify']
    require(result.get('schemaVersion') == 1 and result.get('status') == 'passed'
            and result.get('kind') == 'musl-sdk-producer-validation' and result.get('libc') == 'musl'
            and result.get('sdkVersion') == SDK and result.get('sourceCommit') == SOURCE
            and result.get('sharedVmrCommit') == SHARED, 'Unexpected producer validation identity')
    require(result.get('architecture') in ('x64', 'aarch64'), 'Unexpected producer architecture')
    arch = identity(result['architecture'])
    require(result.get('targetRid') == arch['rid'], 'Producer libc/RID mismatch')
    require(re.fullmatch(r'[a-f0-9]{40}', result.get('projectCommit', ''))
            and all(re.fullmatch(r'[1-9][0-9]*', result.get(k, '')) for k in ['runId', 'runAttempt']),
            'Invalid producer project/run identity')
    require(result.get('allRequiredStages') == required_stages, 'All six required producer stages are mandatory')
    delivery_index(release, result.get('files'))
    stages = {}
    for name in required_stages:
        stage = load_json(release / 'reports/stages' / (name + '.json'))
        require(stage.get('stage') == name and stage.get('status') == 'passed'
                and isinstance(stage.get('commands'), list) and (stage['commands'] or name == 'collect'),
                'Required actual stage did not pass: ' + name)
        start = dt.datetime.fromisoformat(stage['startedAtUtc'])
        finish = dt.datetime.fromisoformat(stage['finishedAtUtc'])
        require(start.tzinfo is not None and finish.tzinfo is not None and finish >= start,
                'Invalid stage timestamps: ' + name)
        stages[name] = stage
    for before, after in zip(required_stages, required_stages[1:]):
        require(dt.datetime.fromisoformat(stages[before]['finishedAtUtc']) <=
                dt.datetime.fromisoformat(stages[after]['startedAtUtc']), 'Producer stages are out of order')
    prepare = load_json(release / 'reports/prepare/identity.json')
    require(prepare.get('diagnosticPtrace') is False, 'Diagnostic ptrace source construction cannot qualify')
    require(prepare.get('sourceAppArmorPolicy') == 'engine-default', 'Diagnostic AppArmor source construction cannot qualify')
    validate_container_engine(release, prepare, stages, arch)
    sdk = load_json(release / 'producer-sdk.json')
    for record in [prepare, sdk]:
        for key in ['sdkVersion', 'targetRid', 'libc', 'sourceCommit', 'sharedVmrCommit',
                    'projectCommit', 'runId', 'runAttempt']:
            require(record.get(key) == result[key], 'Producer identity differs: ' + key)
    require(prepare.get('nativeArchitecture') == arch['machine'] and prepare.get('emulation') is False
            and sdk.get('architecture') == result['architecture'] and sdk.get('kind') == 'musl-sdk-build'
            and sdk.get('producerRevision') == 1 and prepare.get('imageId') == sdk.get('imageId'),
            'Native architecture/image/SDK construction identity differs')
    require(prepare.get('bootstrapRoot') == '/vmr/.dotnet', 'The private bootstrap root must remain explicit')
    architecture_variable = 'ARM64' if result['architecture'] == 'aarch64' else 'X64'
    required_bootstrap_environment = {'DOTNET_ROOT=/vmr/.dotnet',
        'DOTNET_ROOT_' + architecture_variable + '=/vmr/.dotnet', 'DOTNET_HOST_PATH=/vmr/.dotnet/dotnet'}
    for stage_name in ['build', 'scan', 'test']:
        source_commands = [c for c in stages[stage_name]['commands'] if '/vmr/.dotnet/dotnet' in c or './build.sh' in c]
        require(source_commands and all(required_bootstrap_environment <= set(c) for c in source_commands),
                'Source build/scan/test must resolve every native TaskHost to the exact private bootstrap SDK')
    for stage in stages.values():
        for command in stage['commands']:
            if 'run' in command and '--user' in command:
                require('--cap-drop=all' in command and '--security-opt=no-new-privileges' in command
                    and '--privileged' not in command and not any(str(value).startswith('--cap-add') for value in command),
                    'Qualified source and consumer containers must retain dropped capabilities without diagnostic ptrace')
                require(not any(str(value).startswith('--security-opt=apparmor=') for value in command),
                    'Diagnostic AppArmor policy overrides cannot qualify')
    profile_path = ROOT / 'profiles' / ('dotnet-' + SDK + '-linux-musl-' + result['architecture'] + '.json')
    require(prepare.get('profile', {}).get('path') == profile_path.name
            and all(prepare['profile'].get(k) == v for k, v in fingerprint(profile_path).items()),
            'The producer must use the reviewed pinned native musl profile')
    profile = load_json(profile_path)
    require(profile['source']['commit'] == SOURCE and profile['target'] == dict(rid=arch['rid'], libc='musl')
            and profile['build']['sourceOnly'] is False and profile['build']['crossBuild'] is False,
            'Unexpected producer profile route')
    bootstrap = load_json(release / 'reports/prepare/bootstrap.json')
    require(all(bootstrap.get(k) == v for k, v in profile['bootstrap'].items())
            and isinstance(bootstrap.get('bytes'), int) and bootstrap['bytes'] > 100000000
            and re.fullmatch('[a-f0-9]{64}', bootstrap.get('sha256', '')),
            'The exact original musl bootstrap identity and byte hashes are required')
    require(any('/vmr/.dotnet/sdk/10.0.401/MSBuild' in c and '-version' in c
                and required_bootstrap_environment <= set(c) for c in stages['prepare']['commands'])
            and 'MSBuild version' in (release / 'reports/prepare/bootstrap-msbuild-apphost.log').read_text(),
            'Actual native bootstrap apphost startup must pass using the private runtime before compilation')
    require(any(all(value in command for value in ['/vmr/.dotnet/dotnet', 'msbuild',
        '/project/' + SOURCE_CULTURE_PROJECT, '/p:SourceCultureReport=/delivery/' + SOURCE_CULTURE_REPORT,
        '/t:ProbeSourceCultures', '--network=none']) and required_bootstrap_environment <= set(command)
        for command in stages['prepare']['commands']), 'Actual offline native bootstrap source-culture preflight command is absent')
    require(load_json(release / 'reports/prepare/source-culture-proof.json') == source_culture_proof(release, profile),
        'Source culture readiness proof, probe bytes or exact bootstrap/full-ICU binding differs')
    image = load_json(release / 'reports/prepare/build-image.json')
    require(len(image) == 1 and image[0]['Id'] == prepare['imageId']
            and image[0]['Architecture'] == arch['image'] and image[0]['Os'] == 'linux',
            'Actual native build image differs')
    verification_image = load_json(release / 'reports/verify/image.json')
    require(len(verification_image) == 1 and verification_image[0]['Id'] == prepare.get('verificationImageId')
            and verification_image[0]['Architecture'] == arch['image'] and verification_image[0]['Os'] == 'linux',
            'The exact native SDK-free verification image must be frozen in prepare')
    require(any(prepare['verificationImageId'] in c and '--network=none' in c
                and not (required_bootstrap_environment & set(c)) for c in stages['verify']['commands'])
            and not any('build' in c and '--file' in c for c in stages['verify']['commands']),
            'Final SDK verification must use the frozen image without bootstrap ROOT or a new APK transaction')
    scan = release / 'reports/scan/NewBinaries.txt'
    require(scan.is_file() and not scan.read_bytes(), 'Original upstream binary scan did not report zero new binaries')
    require(any('/project/scripts/scan-clean-source.proj' in c and '--network=none' in c
                and any(str(a).endswith(':/clean:ro') for a in c) for c in stages['scan']['commands']),
            'The original scan must run on a separate read-only source checkout without network')
    tests = module('musl_validated_upstream', 'ci-net10-evidence.py').parse_tests(
        release / 'reports/test/common.trx', release / 'reports/test/scenarios.xml')
    require(load_json(release / 'reports/test/upstream-summary.json') == tests,
            'Upstream test summary differs from the actual pinned test results')
    source = load_json(release / 'sources/source-manifest.json')
    roots = {r['name']: r for r in source['roots']}
    require(roots.get('vmr', {}).get('commit') == SOURCE
            and roots.get('vmr', {}).get('role') == 'built-sdk-vmr-source'
            and roots.get('shared-vmr', {}).get('commit') == SHARED
            and roots.get('shared-vmr', {}).get('role') == 'source-for-reused-shared-input',
            'Both complete corresponding source trees and their construction roles are required')
    module('musl_validated_sources', 'package-used-source.py').verify(SimpleNamespace(
        release_dir=release, expected_project_commit=result['projectCommit'], expected_run_id=result['runId'],
        expected_run_attempt=result['runAttempt'], expected_target_rid=arch['rid']))
    name = sdk.get('sdk', {}).get('name', '')
    require(name == 'cbodotnet-sdk-' + SDK + '-linux-musl-' + result['architecture'] +
            '-build.' + result['runId'] + '.tar.gz', 'Unexpected SDK archive identity')
    fp = fingerprint(release / name)
    require(all(sdk['sdk'].get(k) == v for k, v in fp.items()), 'Original SDK archive byte binding differs')
    with tarfile.open(release / name, 'r:gz') as archive:
        for framework in ['Microsoft.NETCore.App', 'Microsoft.AspNetCore.App']:
            marker = 'shared/' + framework + '/10.0.14/.version'
            entries = [m for m in archive.getmembers() if m.name.lstrip('./') == marker]
            require(len(entries) == 1 and entries[0].size <= 4096,
                    'Missing/ambiguous actual shared framework version marker')
            require(archive.extractfile(entries[0]).read(4097).decode('utf-8-sig').strip().splitlines()
                    == [SHARED, '10.0.14'], 'Imported musl frameworks do not match corresponding sources')
    construction = load_json(release / 'reports/construction.json')
    require(construction.get('sourceOnly') is False and construction.get('sdkSource') == SOURCE
            and construction.get('sharedSource', {}).get('commit') == SHARED
            and construction.get('runtimeVersion') == '10.0.14'
            and construction.get('bootstrapSdk') == '10.0.401'
            and construction.get('sharedSdkPackage') == '10.0.114-servicing.26522.126',
            'Rebuilt/imported component provenance must remain explicit')
    imported = load_json(release / 'reports/restored-inputs.json').get('packages')
    require(isinstance(imported, list) and imported and all(
            p.get('bytes', 0) > 0 and re.fullmatch('[a-f0-9]{64}', p.get('sha256', ''))
            and re.fullmatch('[a-f0-9]{128}', p.get('sha512', '')) for p in imported),
            'Actual restored upstream input hashes are required')
    hook = load_json(release / 'reports/prepare/input-recording-hook.json')
    require(hook.get('sourceCommit') == SOURCE and hook.get('beforeTarget') == 'CleanupRepo'
            and hook.get('path') == 'repo-projects/Directory.Build.targets',
            'Actual inner-repository NuGet inputs must be recorded before upstream cleanup')
    input_records = sorted((release / 'reports/restored-inputs').glob('*.json'))
    require(input_records, 'Pre-cleanup repository input records are missing')
    imported_keys = {(p.get('repository'), p['cache'], p['path'], p['sha256']) for p in imported}
    for path in input_records:
        record = load_json(path)
        require(record.get('schemaVersion') == 1 and record.get('packages')
                and all((record['repository'], record['cache'], p['path'], p['sha256'])
                        in imported_keys for p in record['packages'])
                and path.read_bytes() == (release / 'reports/ci-inputs/restored-inputs' / path.name).read_bytes(),
                'Pre-cleanup input inventory must be retained, source-packaged and aggregated unchanged')
    with (release / 'sources' / source['index']['path']).open(encoding='utf-8') as index:
        target_records = [json.loads(line) for line in index if 'vmr/repo-projects/Directory.Build.targets' in line]
    require(len(target_records) == 1 and target_records[0]['path'] == 'vmr/repo-projects/Directory.Build.targets'
            and target_records[0]['sha256'] == hook.get('adjustedSha256'),
            'The retained actual VMR source must contain the recorded pre-cleanup observation hook')
    smoke = load_json(release / 'reports/verify/sdk/verification.json')
    required_checks = ['consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
                       'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp']
    require(smoke.get('verificationStatus') == 'passed' and smoke.get('smokeStatus') == 'passed'
            and smoke.get('sdkVersion') == SDK and smoke.get('reportedRid') == arch['rid']
            and smoke.get('hostArchitecture') == arch['machine']
            and all(smoke.get('functionalChecks', {}).get(k) == 'passed' for k in required_checks)
            and smoke.get('archive', {}).get('sha256') == fp['sha256']
            and smoke.get('archive', {}).get('sdkContentMatched') is True,
            'Actual console/apphost/HTTP/crypto/ICU tests must bind the unchanged musl SDK bytes')
    elf = load_json(release / 'reports/verify/elf.json')
    loader = '/lib/ld-musl-' + arch['machine'] + '.so.1'
    require(elf.get('status') == 'passed' and elf.get('libc') == 'musl'
            and elf.get('architecture') == result['architecture'] and elf.get('loader') == loader
            and elf.get('nativeArchitecture') == arch['machine'] and elf.get('uid', 0) > 0
            and elf.get('emulation') is False and elf.get('foreignTargetExceptions') == []
            and elf.get('elfCount', 0) == len(elf.get('files', [])) and elf['elfCount'] >= 10,
            'Complete native musl ELF audit evidence is mandatory')
    require(all(r.get('classification') == 'native-host' and r.get('interpreter') in (None, loader)
                and not any(n == 'libc.so.6' or n.startswith('ld-linux') for n in r.get('needed', []))
                and not re.search(r'not found|Error loading|Error relocating|symbol not found',
                                  r.get('dependencyClosure', ''), re.IGNORECASE) for r in elf['files']),
            'Unqualified glibc/foreign/unresolved ELF is forbidden')
    closure = elf.get('closure')
    require(isinstance(closure, dict) and closure.get('scope') == 'musl-complete-payload-elf-closure'
            and closure.get('status') == 'passed' and closure.get('native') is True
            and closure.get('architecture') == result['architecture'] and closure.get('libc') == 'musl'
            and closure.get('targetRid') == arch['rid'] and closure.get('nonHostElfCount') == 0
            and closure.get('hostElfCount') == elf['elfCount']
            and len(closure.get('elfFiles', [])) == elf['elfCount']
            and closure.get('stockLibraries'), 'Complete native stock-APK transitive dependency closure is mandatory')
    for provider in closure['stockLibraries']:
        require(provider.get('apkOwner') and re.fullmatch('[a-f0-9]{64}', provider.get('sha256', '')),
                'Every system dependency must identify its actual stock APK owner and bytes')
    gcc_providers = [p for p in closure['stockLibraries'] if p.get('apkOwner', '').endswith(
        ' is owned by libgcc-' + next(p['V'] for p in profile['runtimePackages'] if p['P'] == 'libgcc'))]
    closure_files = {r['path']: r for r in closure['elfFiles']}
    discovered_files = {r['path']: r for r in elf['files']}
    require(len(closure_files) == elf['elfCount'] and set(closure_files) == set(discovered_files)
            and all(all(row.get(key) == discovered_files[path].get(key)
                        for key in ['sha256', 'interpreter', 'machine', 'needed', 'versionNeeds'])
                    for path, row in closure_files.items()),
            'Qualified native dependency closure must bind the complete discovered SDK ELF inventory')
    sys.path.insert(0, str(ROOT / 'scripts'))
    import musl_archive
    for row in closure['elfFiles']:
        # This attribution parser is pure: it never treats arbitrary GLIBC labels
        # as musl-compatible and the native proof separately binds the provider.
        labels = musl_archive.reviewed_gcc_abi_labels(row)
        require(labels == row.get('reviewedAbiVersionLabels'), 'Unreviewed ELF ABI version label')
        if labels:
            require(any('GLIBC_2.0' in provider.get('versionDefinitions', []) for provider in gcc_providers),
                    'Reviewed GCC unwind label lacks its exact stock libgcc definition/owner')
    actual_elf = sdk_elf_inventory(release / name, 62 if result['architecture'] == 'x64' else 183, loader)
    bound_elf = {r['path']: r for r in elf['files']}
    require(len(bound_elf) == len(elf['files']) and set(bound_elf) == set(actual_elf)
            and all(all(bound_elf[p].get(k) == v for k, v in row.items()) for p, row in actual_elf.items()),
            'The complete native ELF audit must bind the actual SDK archive payload')
    require(any('--network=none' in c and '/tmp' in c for c in stages['verify']['commands']),
            'The native runtime qualification must run offline in a fresh SDK-free container')
    print('Native musl producer identity, actual tests, corresponding sources and every bound byte verified.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    for name in ['workspace', 'output-dir']:
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--host-reports', type=Path)
    run.add_argument('--diagnostic-ptrace', action='store_true',
                     help='Source-only crash capture; stops after build and is never admissible for qualification')
    for name in ['build-id', 'run-id', 'run-attempt']:
        run.add_argument('--' + name, required=True)
    check = commands.add_parser('validate')
    check.add_argument('--release-dir', type=Path, required=True)
    capture = commands.add_parser('capture-failure-logs')
    capture.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'run':
        require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id)
                and all(re.fullmatch(r'[1-9][0-9]*', item) for item in [args.run_id, args.run_attempt]),
                'Invalid build/run identity')
        Producer(args).execute()
    elif args.command == 'validate':
        validate(args.release_dir)
    else:
        capture_failure_logs(args.destination)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
