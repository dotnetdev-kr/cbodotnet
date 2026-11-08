"""Version-isolated SDK6 normal producer.

Container isolation, image preparation and cold consumer primitives are shared.
SDK6's product graph, source inputs, evidence and final validator are separate.
The shared CLI must not dispatch this route before the complete contract passes.
"""
from pathlib import Path
import json
import os
import shutil
from types import SimpleNamespace
import zipfile

import importlib.util

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


L = module('sdk6_legacy_isolation_primitives', 'musl-legacy-sdk.py')
T = module('sdk6_original_tooling_graph', 'musl-legacy6-tooling.py')
P, require, fingerprint, write = L.P, L.require, L.fingerprint, L.write
SDK = '6.0.136'


class Producer(L.Producer):
    def __init__(self, args):
        require(args.sdk_version == SDK, 'The isolated SDK6 producer requires6.0.136')
        super().__init__(args)
        self.selected = dict(self.selected, vstestVersion='17.0.3-dev', vstestTfm='net6.0')

    def prepare(self):
        super().prepare()
        self.clone('msbuild-localization', 'https://github.com/dotnet/msbuild', self.selected['msbuild'])

    def source_worker(self, arguments, *, log):
        """Use the exact prepared SDK6 bootstrap through a read-only alias."""
        bootstrap = self.sdk_work / 'sdk/.dotnet'
        require(bootstrap.is_dir() and not any(path.is_symlink() for path in (bootstrap, *bootstrap.parents)),
            'Ordinary exact SDK6 bootstrap root required')
        log.parent.mkdir(parents=True, exist_ok=True)
        if os.getuid() == 0: os.chown(log.parent, self.uid, self.gid)
        argv = self.engine + ['run', '--rm', '--network=host', '--user', str(self.uid) + ':' + str(self.gid),
            '--cap-drop=all', '--security-opt=no-new-privileges',
            '--env', 'HOME=/home/build', '--env', 'DOTNET_CLI_HOME=/home/build',
            '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            '--env', 'DOTNET_MULTILEVEL_LOOKUP=0', '--env', 'DOTNET_PROCESSOR_COUNT=2',
            '--env', 'PYTHONDONTWRITEBYTECODE=1', '--volume', str(ROOT) + ':/project:ro',
            '--volume', str(self.output) + ':/delivery', '--volume', str(self.home) + ':/home/build',
            '--volume', str(self.workspace) + ':/work', '--volume', str(bootstrap) + ':/bootstrap:ro',
            '--workdir', '/tmp']
        diagnostics = self.diagnostic_options()
        if os.getuid() == 0: os.chown(Path(diagnostics[1].removesuffix(':/diag')), self.uid, self.gid)
        argv += diagnostics + [self.image] + self.observed_command(arguments)
        self.run(argv, log=log)
        if not self.diagnostic: P.validate_default_container_policy(self.output, list(map(str, argv)))

    def _run_component(self, name, worker, extra=()):
        destination = self.reports / 'build' / name
        self.source_worker(['python3', '/project/scripts/' + worker, '--sdk', SDK, '--arch', self.args.arch,
            '--source', '/work/work/' + name, '--dotnet', '/bootstrap/dotnet',
            '--output', '/delivery/reports/build/' + name, *extra], log=self.reports / 'build' / (name + '.log'))
        result = json.loads((destination / 'results.json').read_text())
        require(result.get('status') == 'passed', 'Original SDK6 component build failed: ' + name)
        return destination, result

    def build(self):
        arch = 'arm64' if self.args.arch == 'aarch64' else 'x64'; bootstrap = '/work/work/sdk-build/sdk/.dotnet'
        feed_rows = []
        for name, worker, commit, version in [
            ('nuget', 'musl-legacy6-nuget.py', self.selected['nuget'], '6.0.6-rc.4'),
            ('vstest', 'musl-legacy6-vstest.py', self.selected['vstest'], '17.0.3-dev'),
            ('msbuild-localization', 'musl-legacy6-localization.py', self.selected['msbuild'], '17.0.4-cbodotnet.1')]:
            directory, result = self._run_component(name, worker, ('--build-id', self.args.build_id) if name == 'msbuild-localization' else ())
            require(result['sourceCommit'] == commit, 'Original SDK6 component source differs')
            packages = sorted((directory / 'source-built-feed').glob('*.nupkg'))
            require(len(packages) == {'nuget': 19, 'vstest': 2, 'msbuild-localization': 1}[name], 'Complete SDK6 component package outputs required')
            for path in packages:
                require(path.name.endswith('.' + version + '.nupkg'), 'Genuine SDK6 component package version differs')
                shutil.copyfile(path, self.feed / path.name)
                feed_rows.append(dict(file=path.name, component=name, sourceCommit=commit, version=version,
                    origin='sdk6-genuine-original-source-build', retained=path.relative_to(self.output).as_posix(), **fingerprint(path)))
            if (directory / 'generated').is_dir():
                self.sources[name + '-generated'] = dict(name=name + '-generated', kind='tree', path=str(directory / 'generated'), role='generated-managed-component-source')
            binlog = directory / ('original-solution-build.binlog' if name == 'vstest' else 'original-library-matrix.binlog' if name == 'nuget' else 'localization.binlog')
            require(binlog.is_file(), 'Actual original SDK6 component binary log required: ' + name)
            shutil.copyfile(binlog, self.reports / 'build' / (name + '.binlog'))
        write(self.reports / 'build/bootstrap-feed.json', dict(schemaVersion=1, sdkVersion=SDK, packages=feed_rows))
        primer = module('sdk6_real_package_download_cache', 'musl_legacy6_source_cache.py')
        prime = self.inputs / 'component-cache-priming'; prime_rows = primer.prepare(self.feed, prime)
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(prime)])
        self.container([bootstrap + '/dotnet', 'restore', '/work/inputs/component-cache-priming/SourcePackageDownloads.csproj',
            '--configfile', '/work/inputs/component-cache-priming/NuGet.Config', '--packages', '/work/work/sdk-build/sdk/.packages',
            '/p:UseSharedCompilation=false', '/m:2', '/bl:/delivery/reports/build/source-cache-priming.binlog'], network='none',
            environment=dict(DOTNET_ROOT=bootstrap), log=self.reports / 'build/source-cache-priming.log')
        write(self.reports / 'build/source-cache-priming.json', primer.validate(self.sdk_work / 'sdk/.packages', prime_rows))
        translations = self.reports / 'build/nuget-translation-data'
        self.container(['python3', '/project/scripts/musl-legacy6-nuget-resources.py', '--sdk-archive',
            '/work/inputs/official-comparison-sdk.tar.gz', '--arch', self.args.arch, '--source', '/work/work/nuget',
            '--dotnet', bootstrap + '/dotnet', '--output', '/delivery/reports/build/nuget-translation-data'],
            log=self.reports / 'build/nuget-translation-data.log')
        self.sources['nuget-translation-data'] = dict(name='nuget-translation-data', kind='tree', path=str(translations),
            role='actual-imported-translation-data-and-generated-readable-source')
        T.M.ENGINE = self.engine
        T.build(SimpleNamespace(workspace=self.sdk_work, sdk=SDK, arch=arch, image=self.image.removeprefix('sha256:'),
            attempt='producer-source-graph', seconds=1200, component_source_build=True, rebuild=True,
            nuget_feed=self.feed, package_cache='.packages', vstest_tfm=None, vstest_source_version='17.0.3-dev',
            msbuild_localization_version='17.0.4-cbodotnet.1', scope_linux_host_tasks=False,
            nuget_resources=translations, wrap_command=self.wrap_tooling_command,
            engine_label='rootful-podman' if self.diagnostic else 'normal-rootful-docker'))
        tooling = self.sdk_work / 'evidence/producer-source-graph'
        require(json.loads((tooling / 'result.json').read_text())['exitCode'] == 0, 'Original SDK6 source-build graph failed')
        write(self.reports / 'build/source-cache-after-build.json', primer.validate(self.sdk_work / 'sdk/.packages', prime_rows))
        shutil.copytree(tooling, self.reports / 'build/sdk-tooling')
        shutil.copyfile(self.sdk_work / 'sdk/artifacts/log/Release/community-sdk-producer-source-graph.binlog', self.reports / 'build/sdk.binlog')
        native = self.reports / 'build/native-runtime'
        self.source_worker(['python3', '/project/scripts/musl-legacy6-coreclr.py', '--sdk', SDK, '--arch', self.args.arch,
            '--source', '/work/work/runtime', '--dotnet', '/bootstrap/dotnet', '--build-id', self.args.build_id,
            '--output', '/delivery/reports/build/native-runtime'], log=self.reports / 'build/native-runtime.log')
        require(json.loads((native / 'results.json').read_text())['status'] == 'passed', 'SDK6 five-product native source graph failed')
        self.sources['native-runtime-generated'] = dict(name='native-runtime-generated', kind='tree', path=str(native / 'generated'), role='generated-native-component-source')
        imports = self.inputs / 'installer-components'; imports.mkdir()
        toolset = self.sdk_work / 'sdk/artifacts/packages/Release/NonShipping' / ('dotnet-toolset-internal-' + SDK + '-ci.zip')
        require(toolset.is_file(), 'Genuine original SDK6 tooling ZIP is absent')
        shutil.copyfile(toolset, imports / toolset.name)
        for kind, path in self.framework_inputs.items():
            shutil.copyfile(path, imports / path.name)
            if kind == 'aspnetcore-runtime': shutil.copyfile(path, imports / ('aspnetcore-runtime-internal-' + self.selected['runtime'] + '-' + self.id['rid'] + '.tar.gz'))
        shutil.copyfile(native / 'libcoreclrtraceptprovider.so', imports / 'libcoreclrtraceptprovider.so')
        (imports / 'native-runtime').mkdir()
        for name in ('libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so'): shutil.copyfile(native / name, imports / 'native-runtime' / name)
        for name in ('0001-copy-local-source-built-components.patch', '0006-copy-matching-source-built-native-runtime.patch', '0007-honor-skip-installer-version-metadata.patch'):
            patch = ROOT / 'patches/net6-musl' / name
            self.run(['git', '-C', str(self.installer), 'apply', '--check', str(patch)])
            self.run(['git', '-C', str(self.installer), 'apply', str(patch)])
        command = ['./build.sh', '--configuration', 'Release', '--restore', '--build', '--pack', '--projects',
            '/work/work/installer/src/redist/redist.csproj', '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true',
            '/p:DotNetBuildOffline=true', '/p:PublicBaseURL=/work/inputs/installer-components/',
            '/p:MicrosoftDotnetToolsetInternalPackageVersion=' + SDK + '-ci', '/p:Version=' + SDK,
            '/p:Architecture=' + arch, '/p:OSName=linux-musl', '/p:PortableOSName=linux-musl', '/p:Rid=' + self.id['rid'],
            '/p:HostRid=' + self.id['rid'], '/p:SharedFrameworkRid=' + self.id['rid'], '/p:CoreSetupRid=' + self.id['rid'],
            '/p:Crossgen2Rid=' + self.id['rid'], '/p:UsePortableLinuxSharedFramework=false', '/p:SkipBuildingInstallers=true',
            '/p:RestoreAdditionalProjectSources=/work/inputs/bootstrap-feed', '/p:UseSharedCompilation=false', '/m:2',
            '/bl:/delivery/reports/build/installer.binlog', '/p:CommunityMuslComponentRoot=/work/inputs/installer-components',
            '/p:CommunityMuslNativeTraceProvider=/work/inputs/installer-components/libcoreclrtraceptprovider.so',
            '/p:CommunityMuslNativeRuntimeRoot=/work/inputs/installer-components/native-runtime', '/p:EmitCompilerGeneratedFiles=true']
        self.container(command, environment=dict(DOTNET_ROOT='/work/work/installer/.dotnet', DOTNET_INSTALL_DIR='/work/work/installer/.dotnet',
            NUGET_PACKAGES='/work/work/installer/.packages'), workdir='/work/work/installer', log=self.reports / 'build/installer.log')
        archive = self.installer / 'artifacts/packages/Release/Shipping' / ('dotnet-sdk-' + SDK + '-' + self.id['rid'] + '.tar.gz')
        require(archive.is_file(), 'The original SDK6 installer did not produce its SDK archive')
        self.archive = self.output / ('cbodotnet-sdk-' + SDK + '-linux-musl-' + self.args.arch + '-build.' + self.args.run_id + '.tar.gz')
        shutil.copyfile(archive, self.archive); require(fingerprint(archive) == fingerprint(self.archive), 'SDK6 installer archive changed during retention')
        write(self.reports / 'build/construction.json', dict(schemaVersion=1, sdkVersion=SDK, sourceOnly=False,
            sdkArchive=dict(name=self.archive.name, **fingerprint(self.archive)), toolingZip=dict(name=toolset.name, **fingerprint(toolset)),
            sourceGraph='sdk/source-build.slnf', originalFullSdkUsedAsPayload=False,
            localSourceComponents=['SDK tooling', 'NuGet original full library matrix', 'VSTest Core and thirteen cultures',
                'MSBuild localization original project graph', 'five native runtime products'],
            imports=[dict(name=p.relative_to(imports).as_posix(), **fingerprint(p)) for p in sorted(imports.rglob('*')) if p.is_file()]))
        self.replay_build_logs()

    def replay_build_logs(self):
        reader = self.reports / 'build/reader'; shutil.copytree(ROOT / 'scripts/musl-legacy-reader', reader)
        (reader / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>\n')
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(reader)])
        bootstrap = '/work/work/sdk-build/sdk/.dotnet'; sdk = bootstrap + '/sdk/6.0.135'
        self.container([bootstrap + '/dotnet', 'build', '/delivery/reports/build/reader/Reader.csproj', '--configuration', 'Release',
            '/p:BootstrapMajor=6', '/p:BootstrapSdkDir=' + sdk, '/p:UseSharedCompilation=false'],
            environment=dict(DOTNET_ROOT=bootstrap), log=self.reports / 'build/reader-build.log')
        for component in ('nuget', 'sdk', 'installer', 'vstest', 'msbuild-localization'):
            self.container([bootstrap + '/dotnet', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll',
                '/delivery/reports/build/' + component + '.binlog', sdk, '/delivery/reports/build/' + component + '-replay'],
                environment=dict(DOTNET_ROOT=bootstrap), log=self.reports / 'build' / (component + '-replay.log'))

    def test(self):
        self.container(['python3', '/project/scripts/musl-legacy-smoke.py', '--sdk-version', SDK, '--arch', self.args.arch,
            '--source-tests', '/work/work/installer/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests',
            '--sdk-archive', '/delivery/' + self.archive.name, '--official-archive', '/work/inputs/official-comparison-sdk.tar.gz',
            '--output', '/delivery/reports/test/original-smoke'], source=True, image=self.test_image, log=self.reports / 'test/original-smoke.log')
        self.container(['python3', '/project/scripts/musl-legacy6-lttng.py', '--sdk', SDK, '--arch', self.args.arch,
            '--archive', '/delivery/' + self.archive.name, '--output', '/delivery/reports/test/native-lttng'],
            source=False, image=self.tracing_image, network='none', log=self.reports / 'test/native-lttng.log')

    def collect(self):
        # Collection is installed only with the complete isolated source
        # registry, four compiler components and reviewed source leaves.
        module('sdk6_complete_collection', 'musl_legacy6_collection.py').collect(self)

    def seal(self):
        require(not self.diagnostic, 'Diagnostic SDK6 runs cannot seal a normal producer')
        for name in L.STAGES:
            require(json.loads((self.reports / 'stages' / (name + '.json')).read_text()).get('status') == 'passed',
                'Required SDK6 normal producer stage did not pass: ' + name)
        require((self.reports / 'legacy-construction.json').is_file(), 'Complete independently checked SDK6 construction proof required before sealing')
        files = [dict(path=p.relative_to(self.output).as_posix(), **fingerprint(p)) for p in sorted(self.output.rglob('*'))
            if p.is_file() and not p.is_symlink()]
        write(self.output / 'producer-validation.json', dict(schemaVersion=2, kind='musl-sdk-producer-validation', producerRevision=1,
            status='passed', diagnosticPtrace=False, diagnosticPodman=False, sdkVersion=SDK, architecture=self.args.arch,
            targetRid=self.id['rid'], libc='musl', sourceCommit=self.selected['installer'], sdkSourceCommit=self.selected['sdk'],
            runtimeSourceCommit=self.selected['runtimeCommit'], projectCommit=self.project, runId=self.args.run_id,
            runAttempt=self.args.run_attempt, buildId=self.args.build_id, allRequiredStages=L.STAGES, files=files,
            qualificationAllowed=False, sourceAdmissionAllowed=False, releaseAvailabilityAllowed=False))
        module('sdk6_complete_admission', 'musl_legacy6_admission.py').validate(self.output)
