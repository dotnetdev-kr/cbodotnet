#!/usr/bin/env python3
"""Reproduce bounded native Core3 F# source and SDK-free consumer experiments."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import subprocess
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile

import core3_musl_restore_inputs as CACHE
import musl_managed_metadata as PE

ROOT = Path(__file__).resolve().parents[1]
PROFILE = json.loads((ROOT / 'profiles/experimental/core3-musl-fsharp.json').read_text())
BOOT = json.loads((ROOT / 'profiles/experimental/core3-musl-source.json').read_text())


def require(value, message):
    if not value:
        raise ValueError('Core3 F# experiment: ' + message)


def fp(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def pinned(path, pin):
    actual = fp(path)
    require(all(actual[key] == pin[key] for key in ('bytes', 'sha256', 'sha512') if key in pin),
            'pinned bytes differ: ' + str(path))
    return actual


def save(path, value):
    CACHE.write_new(path, (json.dumps(value, indent=2) + '\n').encode())


def unpack_zip(package, destination):
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        require(len(set(names)) == len(names), 'ambiguous bootstrap ZIP entries')
        for name in names:
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,
                    'a ZIP member escapes its destination')
            if not name.endswith('/'):
                CACHE.write_new(destination / name, archive.read(name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['source', 'consumer'], required=True)
    for name in ['inputs-dir', 'bootstrap-inputs-dir', 'msbuild-run-dir', 'arcade-package',
                 'source-evidence-dir', 'work-dir', 'output-dir']:
        parser.add_argument('--' + name, type=Path, required=name in ['inputs-dir', 'bootstrap-inputs-dir', 'work-dir', 'output-dir'])
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() != 0 and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4' and not shutil.which('dotnet'),
            'matching native non-root SDK-free Alpine3.24.4 is required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, CACHE.ordinary(value))
    require(not args.work_dir.exists() and not args.output_dir.exists(), 'fresh work and evidence directories are required')
    work, output = args.work_dir, args.output_dir
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    require(not output.is_relative_to(work), 'evidence must be outside the worktree')
    records = []
    environment = dict(os.environ, HOME=str(work / 'home'), DOTNET_CLI_HOME=str(work / 'home'),
        DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_NOLOGO='1',
        DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='false',
        DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER='1', DOTNET_PROCESSOR_COUNT='2',
        MSBUILDDISABLENODEREUSE='1')

    def run(name, command, *, cwd=None, expected_text=None, timeout=900):
        command = list(map(str, command))
        log = output / (name + '.log')
        start = time.monotonic()
        with log.open('x') as stream:
            stream.write(json.dumps(command) + '\n')
            stream.flush()
            child = subprocess.Popen(command, cwd=cwd, env=environment, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, 15)
                child.wait(timeout=5)
                code = 124
        row = dict(name=name, command=command, cwd=str(cwd) if cwd else None,
                   exitCode=code, seconds=round(time.monotonic() - start, 2), log=log.name, **fp(log))
        records.append(row)
        # A failed later collection step cannot erase successful/failed command status.
        (output / 'command-progress.json').write_text(json.dumps(records, indent=2) + '\n')
        require(code == 0, 'command failed: ' + name)
        if expected_text is not None:
            require(expected_text in log.read_text(), 'expected output is absent: ' + name)

    runtime = work / 'runtime'
    runtime.mkdir()
    runtime_input = args.inputs_dir / BOOT['bootstrapRuntime']['name']
    pinned(runtime_input, BOOT['bootstrapRuntime'])
    with tarfile.open(runtime_input) as archive:
        archive.extractall(runtime, filter='data')
    framework = runtime / 'shared/Microsoft.NETCore.App/3.1.32'
    for kind, directory, name in [('crypto', 'candidate-verified', 'System.Security.Cryptography.Native.OpenSsl.so'),
                                   ('trace', 'trace-verified', 'libcoreclrtraceptprovider.so')]:
        pin = BOOT['nativeCandidates'][kind]
        source = args.inputs_dir / directory / pin['relativePath']
        pinned(source, pin)
        (framework / name).write_bytes(source.read_bytes())
    sdk_archive = args.bootstrap_inputs_dir / BOOT['bootstrapSdk']['name']
    pinned(sdk_archive, BOOT['bootstrapSdk'])

    if args.mode == 'consumer':
        require(args.source_evidence_dir is not None and not shutil.which('clang'),
                'source evidence and an SDK/compiler-free consumer image are required')
        report = json.loads((args.source_evidence_dir / 'results.json').read_text())
        require(report['mode'] == 'source' and report['sourceCommit'] == PROFILE['source']['commit'] and
                report['sourcePackageVersion'] == PROFILE['actualSourcePackageVersion'] and
                all(row['exitCode'] == 0 for row in report['records']), 'successful matching source evidence is required')
        package_row = report['package']
        package = args.source_evidence_dir / package_row['path']
        pinned(package, package_row)
        tool, refs, application = [work / name for name in ['tool', 'refs', 'application']]
        for path in [tool, refs, application]:
            path.mkdir()
        assemblies = []
        with zipfile.ZipFile(package) as archive:
            for name in archive.namelist():
                if not name.startswith('lib/netcoreapp3.1/') or name.endswith('/'):
                    continue
                relative = name.removeprefix('lib/netcoreapp3.1/')
                require('/' not in relative and '\\' not in relative, 'unexpected nested compiler package entry')
                raw = archive.read(name)
                require(not raw.startswith(b'\x7fELF'), 'a compiler package member is native')
                CACHE.write_new(tool / relative, raw)
                if raw.startswith(b'MZ'):
                    identity = PE.inspect(raw)
                    require(identity['managedNativeHeaderBytes'] == 0 and identity['cliFlags'] & 1,
                            'a compiler product is not IL-only')
                    assemblies.append(dict(path=relative, sha256=hashlib.sha256(raw).hexdigest(), identity=identity))
        with tarfile.open(sdk_archive, mode='r|gz') as archive:
            for member in archive:
                name = str(PurePosixPath(member.name))
                if member.isfile() and name.startswith('packs/Microsoft.NETCore.App.Ref/') and '/ref/netcoreapp3.1/' in name and name.endswith('.dll'):
                    CACHE.write_new(refs / PurePosixPath(name).name, archive.extractfile(member).read())
        require((refs / 'System.Runtime.dll').is_file() and len(list(refs.glob('*.dll'))) > 100,
                'the original targeting-reference closure is absent')
        save(output / 'targeting-inputs.json', [dict(path=path.name, **fp(path)) for path in sorted(refs.glob('*.dll'))])
        config = dict(runtimeOptions=dict(tfm='netcoreapp3.1', framework=dict(name='Microsoft.NETCore.App', version='3.1.32')))
        save(tool / 'fsharp.runtimeconfig.json', config)
        environment.update(DOTNET_ROOT=str(runtime), COMPlus_ReadyToRun='1')
        command = [runtime / 'dotnet', 'exec', '--runtimeconfig', tool / 'fsharp.runtimeconfig.json']
        run('source-fsc-help', command + [tool / 'fsc.exe', '--help'], expected_text='F#')
        source = application / 'Hello.fs'
        source.write_text('[<EntryPoint>]\nlet main _ =\n    let total = [1..20] |> List.sum\n    printfn "SOURCE_FSHARP_RESULT=%d" total\n    0\n')
        response = application / 'compile.rsp'
        response.write_text('\n'.join(['--nologo', '--target:exe', '--targetprofile:netcore', '--simpleresolution',
            '--noframework', '--nowin32manifest', '--out:' + str(application / 'Hello.dll'),
            '--reference:' + str(tool / 'FSharp.Core.dll'), *['--reference:' + str(path) for path in sorted(refs.glob('*.dll'))], str(source)]) + '\n')
        CACHE.write_new(output / 'compile.rsp', response.read_bytes())
        run('source-fsc-compile', command + [tool / 'fsc.exe', '@' + str(response)])
        save(application / 'Hello.runtimeconfig.json', config)
        shutil.copyfile(tool / 'FSharp.Core.dll', application / 'FSharp.Core.dll')
        run('source-fsharp-application', [runtime / 'dotnet', application / 'Hello.dll'], expected_text='SOURCE_FSHARP_RESULT=210')
        script = application / 'Hello.fsx'
        script.write_text('let total = [1I..20I] |> List.sum\nprintfn "SOURCE_FSI_RESULT=%A" total\n')
        run('source-fsi-script', command + [tool / 'fsi.exe', '--nologo', '--simpleresolution', '--exec', script], expected_text='SOURCE_FSI_RESULT=210')
        save(output / 'results.json', dict(mode='consumer', qualification=False, releaseAdmission=False,
            sourceSdkProduct=False, sourceCommit=PROFILE['source']['commit'], package=package_row,
            normalReadyToRunEnabled=True, sourceDeclaredSimpleResolution=True, assemblies=assemblies,
            records=records, all13CulturesQualified=False, completeUsedSourceAudit=False))
        return

    require(args.msbuild_run_dir is not None and args.arcade_package is not None,
            'source-built MSBuild evidence and the pinned private Arcade package are required')
    bootstrap = runtime  # Private imported SDK PE/data shares the pinned musl runtime.
    imported, excluded = [], []
    with tarfile.open(sdk_archive, mode='r|gz') as archive:
        for member in archive:
            name = str(PurePosixPath(member.name))
            require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                    'a bootstrap tar member escapes its destination')
            if not member.isfile():
                continue
            raw = archive.extractfile(member).read()
            row = dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            if raw.startswith(b'\x7fELF'):
                excluded.append(row)
            elif name.startswith(('sdk/', 'packs/', 'templates/')):
                CACHE.write_new(bootstrap / name, raw)
                imported.append(row)
    bundled = bootstrap / 'sdk/3.1.425/Microsoft.NETCoreSdk.BundledVersions.props'
    original = bundled.read_bytes()
    require(hashlib.sha256(original).hexdigest() == BOOT['privateBootstrapRidMetadata']['originalSha256'],
            'private SDK RID metadata differs')
    adapted = original.replace(b'<NETCoreSdkRuntimeIdentifier>linux-arm64</NETCoreSdkRuntimeIdentifier>',
                               b'<NETCoreSdkRuntimeIdentifier>linux-musl-arm64</NETCoreSdkRuntimeIdentifier>')
    require(hashlib.sha256(adapted).hexdigest() == BOOT['privateBootstrapRidMetadata']['adaptedSha256'],
            'private SDK RID adaptation differs')
    bundled.write_bytes(adapted)
    save(output / 'private-bootstrap.json', dict(qualification=False, importedPeData=imported,
        excludedEverySdkElf=excluded, readyToRunDisabledOnlyPrivateBootstrap=True,
        originalGlobalJsonModified=False, syntheticArchiveGitCommitCount=0))
    environment.update(DOTNET_ROOT=str(bootstrap), DOTNET_INSTALL_DIR=str(bootstrap),
        COMPlus_ReadyToRun='0', PATH=str(bootstrap) + ':' + environment['PATH'], DOTNET_ROLL_FORWARD='Major')
    source_archive = args.bootstrap_inputs_dir / PROFILE['source']['archive']
    source_build = args.inputs_dir / PROFILE['sourceBuild']['archive']
    pinned(source_archive, PROFILE['source'])
    pinned(source_build, PROFILE['sourceBuild'])
    source_parent = work / 'source'
    source_parent.mkdir()
    with tarfile.open(source_archive) as archive:
        archive.extractall(source_parent, filter='data')
    sources = list(source_parent.iterdir())
    require(len(sources) == 1 and sources[0].is_dir(), 'one original F# source root is required')
    source = sources[0]
    global_json = (source / 'global.json').read_bytes()
    require(json.loads(global_json)['tools']['dotnet'] == PROFILE['source']['originalToolsSdk'],
            'the original F# SDK pin differs')
    patch_rows = []
    with tarfile.open(source_build) as archive:
        patches = sorted([member for member in archive if member.isfile() and '/patches/fsharp/' in member.name], key=lambda member: member.name)
        require(len(patches) == 4, 'the complete original four-patch sequence is required')
        for member, pin in zip(patches, PROFILE['sourceBuild']['patches']):
            raw = archive.extractfile(member).read()
            require(PurePosixPath(member.name).name == pin['name'] and hashlib.sha256(raw).hexdigest() == pin['sha256'],
                    'an original source-build patch differs')
            patch = output / 'original-upstream-patches' / pin['name']
            CACHE.write_new(patch, raw)
            paths = re.findall(r'^diff --git a/(.*?) b/.*$', raw.decode('utf-8-sig'), re.M)
            before = {name: fp(source / name) for name in paths if (source / name).is_file()}
            run('check-' + patch.stem, ['git', 'apply', '--ignore-space-change', '--check', patch], cwd=source)
            run('apply-' + patch.stem, ['git', 'apply', '--ignore-space-change', '--whitespace=nowarn', patch], cwd=source)
            patch_rows.append(dict(path=str(patch.relative_to(output)), **fp(patch), before=before,
                after={name: fp(source / name) for name in paths if (source / name).is_file()}))
    save(output / 'original-source-build-patch-chain.json', dict(sourceBuild=PROFILE['sourceBuild'],
        source=PROFILE['source'], patches=patch_rows))
    resolver = work / 'resolver'
    resolver.mkdir()
    with tarfile.open(source_build) as archive:
        member = next(member for member in archive if member.name.endswith('/tools-local/tasks/SourceBuild.MSBuildSdkResolver/SourceBuiltSdkResolver.cs'))
        CACHE.write_new(resolver / 'SourceBuiltSdkResolver.cs', archive.extractfile(member).read())
    (resolver / 'Resolver.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netstandard2.0</TargetFramework><AssemblyName>SourceBuild.MSBuildSdkResolver</AssemblyName></PropertyGroup><ItemGroup><Reference Include="Microsoft.Build.Framework"><HintPath>' + str(bootstrap / 'sdk/3.1.425/Microsoft.Build.Framework.dll') + '</HintPath><Private>false</Private></Reference></ItemGroup></Project>')
    public_feed = 'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json'
    (resolver / 'NuGet.Config').write_text('<configuration><packageSources><clear/><add key="official-public" value="' + public_feed + '"/></packageSources></configuration>')
    run('resolver-restore', [bootstrap / 'dotnet', 'restore', resolver / 'Resolver.csproj'], cwd=resolver)
    run('resolver-build', [bootstrap / 'dotnet', 'build', resolver / 'Resolver.csproj', '--no-restore', '-c', 'Release', '-p:UseSharedCompilation=false'], cwd=resolver)
    resolver_product = resolver / 'bin/Release/netstandard2.0/SourceBuild.MSBuildSdkResolver.dll'
    installed = bootstrap / 'sdk/3.1.425/SdkResolvers/SourceBuild.MSBuildSdkResolver'
    installed.mkdir()
    shutil.copyfile(resolver_product, installed / resolver_product.name)
    pinned(args.arcade_package, PROFILE['privateBootstrapArcade'])
    arcade = work / 'private-arcade'
    unpack_zip(args.arcade_package, arcade)
    environment.update(SOURCE_BUILT_SDK_ID_BOOTSTRAP_ARCADE='Microsoft.DotNet.Arcade.Sdk',
        SOURCE_BUILT_SDK_VERSION_BOOTSTRAP_ARCADE=PROFILE['privateBootstrapArcade']['version'],
        SOURCE_BUILT_SDK_DIR_BOOTSTRAP_ARCADE=str(arcade))
    msbuild_report_path = args.msbuild_run_dir / 'results.json'
    msbuild_report = json.loads(msbuild_report_path.read_text())
    msbuild_command = next(row for row in msbuild_report['records'] if row['name'] == 'msbuild31-source-build')
    require(msbuild_command['exitCode'] == 0 and any(PROFILE['sourceBuiltMsbuild']['commit'] in argument for argument in msbuild_command['command']),
            'successful exact-source MSBuild component evidence is required')
    msbuild_feed = args.msbuild_run_dir / 'source-build-outputs/msbuild31/artifacts/packages/Release/Shipping'
    packages = []
    for path in sorted(msbuild_feed.glob('*.nupkg')):
        with zipfile.ZipFile(path) as archive:
            nuspec = ET.fromstring(archive.read(next(name for name in archive.namelist() if name.endswith('.nuspec'))))
            metadata = next(item for item in nuspec if item.tag.endswith('metadata'))
            fields = {item.tag.rsplit('}', 1)[-1]: item for item in metadata}
            require(fields['version'].text == '16.7.3' and fields['repository'].attrib.get('commit') == PROFILE['sourceBuiltMsbuild']['commit'],
                    'a source-built MSBuild input identity differs')
            packages.append(dict(id=fields['id'].text, name=path.name, **fp(path)))
    require(sorted(row['id'] for row in packages) == sorted(PROFILE['sourceBuiltMsbuild']['requiredPackageIds']),
            'the complete five-package source-built MSBuild feed is required')
    save(output / 'source-built-msbuild-inputs.json', dict(sourceCommit=PROFILE['sourceBuiltMsbuild']['commit'],
        report=dict(path=str(msbuild_report_path), **fp(msbuild_report_path)), packages=packages,
        scope='Actual native source-built component inputs. This descriptor is not a complete source or release admission.'))
    feeds = [str(msbuild_feed), 'https://api.nuget.org/v3/index.json'] + [
        'https://pkgs.dev.azure.com/dnceng/public/_packaging/' + name + '/nuget/v3/index.json'
        for name in ['dotnet-public', 'dotnet-tools', 'dotnet-eng', 'dotnet3.1', 'dotnet3.1-transport', 'nuget-build']]
    common = ['/p:Configuration=Release', '/p:NETCoreSdkRuntimeIdentifier=linux-musl-arm64',
        '/p:ToolsRID=linux-musl-arm64', '/p:DotNetBuildFromSource=true', '/p:EnableSourceLink=false',
        '/p:EnableSourceControlManagerQueries=false', '/p:DeterministicSourcePaths=false',
        '/p:UseSharedCompilation=false', '/m:2', '/nologo', '/p:RestoreSources=' + '%3B'.join(feeds),
        '/p:MicrosoftExtensionsFileSystemGlobbingPackageVersion=1.1.1', '/p:UseAppHost=false',
        '/p:LocalizedBuild=false', '/p:FSharpSourceBuild=true', '/p:EnableXlfLocalization=false',
        '/p:SystemTextJsonPackageVersion=4.7.2', '/p:MicrosoftBuildOverallPackagesVersion=16.7.3',
        '/p:MicrosoftBuildVersion=16.7.3', '/p:MicrosoftBuildTasksCoreVersion=16.7.3',
        '/p:RepositoryCommit=' + PROFILE['source']['commit'], '/p:GitCommitHash=' + PROFILE['source']['commit'],
        '/p:GitCommitCount=0', '/p:DisableSourceLink=true', '/p:NuGetPackagesDir=' + str(work / 'home/.nuget/packages')]

    def build(name, relative, target, configuration=None):
        run(name, [bootstrap / 'dotnet', 'msbuild', source / relative, *common,
            *(['/p:Configuration=' + configuration] if configuration else []), '/t:' + target,
            '/bl:' + str(output / (name + '.binlog'))], cwd=source)

    build('original-buildtools-proto', 'src/buildtools/buildtools.proj', 'Restore;Publish', 'Proto')
    bootstrap_tools = source / 'artifacts/Bootstrap'
    bootstrap_tools.mkdir(parents=True, exist_ok=True)
    for name in ['fslex', 'fsyacc']:
        shutil.copytree(source / ('artifacts/bin/' + name + '/Proto/netcoreapp3.1/publish'), bootstrap_tools / name)
    build('original-compiler-proto', 'proto.proj', 'Restore;Publish', 'Proto')
    shutil.copytree(source / 'artifacts/bin/fsc/Proto/netcoreapp3.1/publish', bootstrap_tools / 'fsc')
    for name in ['fsc', 'fsi', 'FSharp.Build', 'FSharp.Compiler.Interactive.Settings']:
        build('original-release-' + name, 'src/fsharp/' + name + '/' + name + '.fsproj', 'Restore;Build')
    build('original-release-pack', 'src/fsharp/FSharp.Compiler.nuget/Microsoft.FSharp.Compiler.csproj', 'Restore;Pack')
    require((source / 'global.json').read_bytes() == global_json, 'the original source SDK pin was changed')
    package = source / ('artifacts/packages/Release/Shipping/Microsoft.FSharp.Compiler.' + PROFILE['actualSourcePackageVersion'] + '.nupkg')
    require(package.is_file(), 'the genuine source-generated compiler package is absent')
    retained = output / 'source-outputs' / package.name
    CACHE.write_new(retained, package.read_bytes())
    closure = CACHE.snapshot(work, output)
    save(output / 'results.json', dict(mode='source', qualification=False, releaseAdmission=False,
        sourceSdkProduct=False, sourceCommit=PROFILE['source']['commit'],
        sourcePackageVersion=PROFILE['actualSourcePackageVersion'], publisherVersionEquivalenceClaimed=False,
        privateBootstrapReadyToRunDisabled=True, originalGlobalJsonUnchanged=True,
        archiveOnlySyntheticGitCommitCount=0, all13CulturesQualified=False, completeUsedSourceAudit=False,
        records=records, package=dict(path=retained.relative_to(output).as_posix(), **fp(retained)),
        restoreClosure=dict(assets=len(closure['assets']), packages=len(closure['packages']),
                            usedPackageBindings=len(closure['usedPackageBindings']))))


if __name__ == '__main__':
    main()
