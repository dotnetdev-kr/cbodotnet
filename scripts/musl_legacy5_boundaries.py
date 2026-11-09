"""Exact SDK5 worker envelopes and original Reader provenance.

Private Podman observations can exercise the same parser but cannot establish
a normal producer boundary. No SDK, compiler, Reader or container is executed.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile

import musl_legacy5_component_evidence as CE

B = CE.B
require, portable = B.require, B.portable
ROOT = Path(__file__).resolve().parents[1]
READER_CONFIG = b'<configuration><packageSources><clear/></packageSources></configuration>\n'
BASE_ENVIRONMENT = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2',
    PYTHONDONTWRITEBYTECODE='1')


def worker_paths(manifest):
    roots = {row['name']: row for row in manifest['roots']}
    require(len(roots) == len(manifest['roots']), 'Unique SDK5 normal worker source roots required')
    sdk = roots['sdk']['originalPath']; workspace = str(PurePosixPath(sdk).parents[1])
    delivery = str(PurePosixPath(roots['actual-managed-package-inputs']['originalPath']).parent)
    project = roots['orchestration']['originalPath']
    require(all(isinstance(path, str) and path.startswith('/') and path == posixpath.normpath(path)
                and not any(c in path for c in '\\\0\r\n') for path in (workspace, delivery, project))
            and sdk == workspace + '/work/sdk'
            and all(roots[name]['originalPath'] == workspace + '/work/' + name for name in ('nuget', 'vstest', 'installer', 'runtime'))
            and roots['actual-managed-package-inputs'].get('kind') == 'tree'
            and roots['actual-managed-package-inputs'].get('role') == 'actual-imported-managed-inputs',
            'Exact SDK5 normal workspace, source and retained-input paths required')
    return workspace, delivery, project


def expected_source_worker(engine, uid, paths, image, diagnostics, inner, *, bootstrap, network='host', workdir='/tmp', environment=None):
    require(bootstrap in ('5', '6', None) and network in ('host', 'none') and re.fullmatch('[1-9][0-9]*:[1-9][0-9]*', uid),
            'Explicit SDK5 non-root worker bootstrap/network/user required')
    workspace, delivery, project = paths
    argv = list(engine) + ['run', '--rm', '--network=' + network, '--user', uid, '--cap-drop=all', '--security-opt=no-new-privileges']
    argv += [value for name, data in BASE_ENVIRONMENT.items() for value in ('--env', name + '=' + data)]
    argv += ['--volume', project + ':/project:ro', '--volume', workspace + ':/work', '--volume', delivery + ':/delivery',
        '--volume', workspace + '/home:/home/build', '--workdir', workdir]
    if bootstrap is not None:
        argv += ['--volume', workspace + '/inputs/bootstrap' + bootstrap + ':/bootstrap:ro', '--env', 'DOTNET_ROOT=/bootstrap']
    if bootstrap == '5':
        argv += ['--volume', workspace + '/inputs/bootstrap5:/work/work/sdk/.dotnet:ro',
                 '--volume', workspace + '/inputs/bootstrap5:/work/work/installer/.dotnet:ro']
    argv += [value for name, data in (environment or {}).items() for value in ('--env', name + '=' + data)]
    argv += ['--volume', diagnostics + ':/diag', '--env', 'MSBUILDDEBUGPATH=/diag', '--env', 'MSBUILDDEBUGCOMM=1', image]
    return argv + B.P.Producer.observed_command(inner)


def validate_source_worker(call, inner, record, prepare, manifest, *, bootstrap, network='host', workdir='/tmp', environment=None, diagnostic=False):
    require(record.get('sdkVersion') == CE.SDK and prepare.get('sdkVersion') == CE.SDK
            and prepare.get('diagnosticPodman') is diagnostic and prepare.get('diagnosticPtrace') is False,
            'Exact SDK5 normal or explicitly private diagnostic worker identity required')
    engine = ['sudo', '-n', '--', 'podman', '--cgroup-manager=cgroupfs', '--events-backend=file'] if diagnostic else B.P.DOCKER_ENGINE
    prefix = engine + ['run', '--rm', '--network=' + network, '--user']
    require(call[:len(prefix)] == prefix and len(call) > len(prefix), 'Exact SDK5 worker container engine and network required')
    paths = worker_paths(manifest); diagnostics = [call[i + 1] for i, value in enumerate(call[:-1]) if value == '--volume' and call[i + 1].endswith(':/diag')]
    require(len(diagnostics) == 1 and re.fullmatch(re.escape(paths[1]) + r'/reports/diagnostics/container-[0-9]{4,}:/diag', diagnostics[0]),
            'One exact SDK5 diagnostic report mount required')
    expected = expected_source_worker(engine, call[len(prefix)], paths, prepare['imageId'], diagnostics[0].removesuffix(':/diag'), inner,
        bootstrap=bootstrap, network=network, workdir=workdir, environment=environment)
    require(call == expected, 'Exact SDK5 image/network/source/bootstrap/workdir/environment/command envelope required')
    return dict(normalProducerBoundaryValidated=not diagnostic, diagnosticOnly=diagnostic, qualificationAllowed=False, sourceAdmissionAllowed=False)


def installer_command(record):
    require(record.get('sdkVersion') == CE.SDK and record.get('architecture') in ('aarch64', 'x64'), 'Exact SDK5 installer CPU identity required')
    cpu = 'arm64' if record['architecture'] == 'aarch64' else 'x64'; rid = 'linux-musl-' + cpu
    require(record.get('targetRid') == rid, 'Exact SDK5 installer RID required')
    return ['./build.sh', '--configuration', 'Release', '--restore', '--rebuild', '--pack', '--projects',
        '/work/work/installer/src/redist/redist.csproj', '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true',
        '/p:DotNetBuildOffline=true', '/p:MicrosoftDotnetToolsetInternalPackageVersion=5.0.214-ci', '/p:Version=5.0.214',
        '/p:Architecture=' + cpu, '/p:OSName=linux-musl', '/p:PortableOSName=linux-musl', '/p:Rid=' + rid,
        '/p:HostRid=' + rid, '/p:SharedFrameworkRid=' + rid, '/p:CoreSetupRid=' + rid,
        '/p:UsePortableLinuxSharedFramework=false', '/p:SkipBuildingInstallers=true',
        '/p:RestoreAdditionalProjectSources=/work/inputs/bootstrap-feed', '/p:UseSharedCompilation=false', '/m:2',
        '/bl:/delivery/reports/build/installer.binlog', '/p:CommunityMuslComponentRoot=/work/inputs/installer-components',
        '/p:CommunityMuslNativeTraceProvider=/work/inputs/installer-components/libcoreclrtraceptprovider.so',
        '/p:CommunityMuslNativeCrypto=/work/inputs/installer-components/libSystem.Security.Cryptography.Native.OpenSsl.so',
        '/p:CommunityMuslNativeRuntimeRoot=/work/inputs/installer-components/native-runtime', '/p:EmitCompilerGeneratedFiles=true',
        '/p:CommunityMuslNativeCrossgenPath=/work/inputs/installer-components/crossgen']


def installer_environment():
    return dict(DOTNET_INSTALL_DIR='/work/work/installer/.dotnet', NUGET_PACKAGES='/work/work/installer/.packages',
                _InitializeDotNetCli='/bootstrap', DotNetBuildFromSource='true')


def validate_installer(record, prepare, manifest, stages, *, diagnostic=False):
    calls = [call for call in stages['build']['commands'] if './build.sh' in call]
    require(len(calls) == 1, 'One exact original SDK5 installer build command required')
    return validate_source_worker(calls[0], installer_command(record), record, prepare, manifest, bootstrap='5',
        workdir='/work/work/installer', environment=installer_environment(), diagnostic=diagnostic)


def archived_reader_sources(release, manifest):
    wanted = {'orchestration/scripts/musl-legacy-reader/' + name for name in ('Program.cs', 'Reader.csproj')}
    wanted.add('orchestration/scripts/musl_legacy5_replay.py'); indexed, found = {}, {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in wanted:
                require(row['path'] not in indexed, 'Unique archived SDK5 Reader source required'); indexed[row['path']] = row
    require(indexed.keys() == wanted, 'Every actual SDK5 Reader and wrapper source must be archived')
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in wanted: continue
            require(entry.isfile() and entry.name not in found and entry.size == indexed[entry.name]['bytes'] and entry.size <= 1024**2,
                    'Ordinary bounded archived SDK5 Reader source required')
            raw = archive.extractfile(entry).read(); fp = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
            require(fp == {key: indexed[entry.name][key] for key in CE.FP},
                    'Actual archived SDK5 Reader source bytes differ'); found[entry.name] = raw
    require(found.keys() == wanted, 'Complete archived SDK5 Reader sources required')
    require(found['orchestration/scripts/musl_legacy5_replay.py'] == (ROOT / 'scripts/musl_legacy5_replay.py').read_bytes(),
            'Actual SDK5 replay wrapper differs from archived orchestration')
    return found


def validate_reader_sources(release, archived):
    directory = release / 'reports/build/reader'
    require(directory.is_dir() and all(not path.is_symlink() and path.name in {'Program.cs', 'Reader.csproj', 'NuGet.Config', 'bin', 'obj'} for path in directory.iterdir()),
            'Only copied original SDK5 Reader sources, clear configuration and build outputs are permitted')
    for parent in (directory, directory.parent, directory.parent.parent, release):
        require(not any((parent / name).exists() for name in ('Directory.Build.props', 'Directory.Build.targets', 'Directory.Packages.props', 'Directory.Build.rsp')),
                'An undeclared SDK5 Reader build input is present')
    for name in ('Program.cs', 'Reader.csproj'):
        require(CE.ordinary(directory / name).read_bytes() == archived['orchestration/scripts/musl-legacy-reader/' + name],
                'Copied SDK5 Reader source must equal archived orchestration: ' + name)
    require(CE.ordinary(directory / 'NuGet.Config').read_bytes() == READER_CONFIG, 'Exact clear-only SDK5 Reader configuration required')


def validate_reader(release, manifest, record, prepare, stages, replays, *, diagnostic=False):
    release = Path(release); validate_reader_sources(release, archived_reader_sources(release, manifest))
    calls = stages['build']['commands']; builds = [call for call in calls if '/delivery/reports/build/reader/Reader.csproj' in call]
    require(len(builds) == 1, 'One actual SDK5 Reader build is required')
    inner = ['/bootstrap/dotnet', 'build', '/delivery/reports/build/reader/Reader.csproj', '-c', 'Release',
        '/p:BootstrapMajor=6', '/p:BootstrapSdkDir=/bootstrap/sdk/6.0.135', '/p:UseSharedCompilation=false']
    validate_source_worker(builds[0], inner, record, prepare, manifest, bootstrap='6', network='none', diagnostic=diagnostic)
    expected = [('sdk', name) for name in ('sdk', 'redist')] + [('nuget', 'original-library-matrix'), ('installer', 'installer')]
    expected += [('vstest', name) for name in CE.VSTEST_REPLAYS]
    observed = [call for call in calls if '/project/scripts/musl_legacy5_replay.py' in call]
    require(len(observed) == len(expected) == 15 and set(replays) == {'sdk', 'nuget', 'vstest', 'installer'}, 'All fifteen separate SDK5 Reader invocations are required')
    selected = {}
    for component in replays:
        if component == 'installer': require([r['name'] for r in replays[component]] == ['installer'], 'One original installer replay required')
        else: CE.replay_names(component, replays[component])
        for replay in replays[component]: selected[(component, replay['name'])] = replay
    for call, (component, name) in zip(observed, expected):
        replay = selected[(component, name)]; require(replay['sourceMountRoot'] == '/work/work/' + component, 'Original SDK5 replay source mount differs')
        binlog = 'reports/build/installer.binlog' if component == 'installer' else 'reports/build/' + component + '/' + name + '.binlog'
        prefix = 'reports/build/' + component + '/replay/' + name
        inner = ['python3', '/project/scripts/musl_legacy5_replay.py', '--name', name, '--dotnet', '/bootstrap/dotnet',
            '--reader', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll', '--sdk-dir', '/bootstrap/sdk/6.0.135',
            '--binlog', '/delivery/' + binlog, '--prefix', '/delivery/' + prefix]
        validate_source_worker(call, inner, record, prepare, manifest, bootstrap='6', network='none', diagnostic=diagnostic)
        for field, local in [('binlog', binlog), ('status', prefix + '-status.json'), ('tasks', prefix + '-tasks.jsonl')]:
            require(CE.fingerprint(CE.ordinary(release / local)) == {key: replay[field][key] for key in CE.FP}
                    and CE.fingerprint(B.checked(release, replay[field])) == {key: replay[field][key] for key in CE.FP},
                    'Actual SDK5 Reader inputs/outputs must equal the retained copies consumed by compiler evidence')
        status = json.loads((release / (prefix + '-status.json')).read_bytes()); command = json.loads((release / (prefix + '-reader-command.json')).read_bytes())
        require(status.get('schemaVersion') == 1 and status.get('completedReplay') is True and status.get('buildSucceeded') is True
                and status.get('failure') is None and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0
                and type(status.get('completedSelectedTasks')) is int and status['completedSelectedTasks'] >= 0
                and status.get('inputSha256') == CE.fingerprint(release / binlog)['sha256'], 'Complete actual SDK5 Reader status required')
        empty = status['completedSelectedTasks'] == 0
        require(command == dict(replayName=name, command=['/bootstrap/dotnet', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll',
                    '/delivery/' + binlog, '/bootstrap/sdk/6.0.135', '/delivery/' + prefix], readerExitCode=1 if empty else 0,
                inputSha256=CE.fingerprint(release / binlog)['sha256'], selectedTasks=status['completedSelectedTasks'],
                emptyReplayHonestlyRetained=empty, contextsRenumbered=False, syntheticMergedReplay=False, qualificationAllowed=False, sourceAdmissionAllowed=False),
                'Original SDK5 Reader command/result identity differs')
        require(not empty or component == 'vstest' and name in CE.EMPTY_REPLAYS, 'An unreviewed SDK5 Reader invocation selected no tasks')
    return dict(status='passed-sdk5-reader-source-build-and-fifteen-replay-provenance', normalProducerBoundaryValidated=not diagnostic,
                diagnosticOnly=diagnostic, binaryReaderReexecutedByValidator=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
