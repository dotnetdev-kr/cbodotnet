#!/usr/bin/env python3
"""Build the exact SDK7 VSTest source graph and its genuine dev packages.

The original source-build graph supplies Core hosts. Publisher-only Full/Mono
test hosts and closed coverage binaries are outside this Linux CLI layout.
Source and byte-consumption admission remain independent of this worker.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

import musl_managed_metadata as MANAGED
import musl_legacy_xlf as XLF

SDK = '7.0.120'
COMMIT = '79d56b02b69a582cd90428878a5e9411ab7538f5'
VERSION = '17.4.1-dev'
FEEDS = ['https://api.nuget.org/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/test-tools/nuget/v3/index.json']


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and not any(p.is_symlink() for p in (path, *path.parents)),
            'An ordinary absolute source/output/bootstrap path is required')


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for path in [args.source, args.dotnet, args.output]: ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0 and platform.machine() ==
            {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Matching native non-root Alpine 3.24.4 is required')
    require(git(args.source, 'rev-parse', 'HEAD') == COMMIT and
            not git(args.source, 'status', '--porcelain', '--untracked-files=all'), 'The exact pristine VSTest source is required')
    require(not args.output.exists(), 'A fresh VSTest output directory is required')
    args.output.mkdir(parents=True)
    settings = ET.parse(args.source / 'scripts/build/TestPlatform.Settings.targets')
    namespace = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
    require(settings.find('.//m:TPVersionPrefix', namespace).text == '17.4.1' and
            settings.find('.//m:Version', namespace).text == '$(TPVersionPrefix)-dev', 'Original VSTest dev version policy changed')
    resources = XLF.generate(args.source, args.output / 'xlf-resource-generation.json', COMMIT)
    require(len(resources['rows']) == 247, 'The complete original SDK7 XLF set is required')
    generated = args.output / 'generated'; generated.mkdir()
    for row in resources['rows']:
        destination = generated / row['generated']; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source / row['generated'], destination)
    rid = 'linux-musl-' + ('arm64' if args.arch == 'aarch64' else 'x64')
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='2', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        NUGET_PACKAGES=str(args.source / '.packages'), MSBUILDDISABLENODEREUSE='1')
    common = ['/p:Configuration=Release', '/p:DotNetBuildFromSource=true', '/p:LocalizedBuild=true',
        '/p:UseSharedCompilation=false', '/p:UseAppHost=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:NETCoreSdkRuntimeIdentifier=' + rid, '/p:ToolsRID=' + rid,
        '/p:RepositoryCommit=' + COMMIT, '/p:SourceRevisionId=' + COMMIT,
        '/p:RestoreSources=' + '%3B'.join(FEEDS), '/m:2', '/nologo']
    commands = []

    def run(name, project, targets, extra=()):
        command = list(map(str, [args.dotnet, 'msbuild', project, *common, '/t:' + targets, *extra,
                                '/bl:' + str(args.output / (name + '.binlog'))]))
        started = datetime.now(timezone.utc).isoformat(); log = args.output / (name + '.log')
        with log.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(command) + '\n'); stream.flush()
            process = subprocess.run(command, cwd=args.source, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=900)
        row = dict(name=name, command=command, exitCode=process.returncode, startedAt=started,
            completedAt=datetime.now(timezone.utc).isoformat(), log=log.name, **fingerprint(log))
        commands.append(row); write(args.output / (name + '-command.json'), row)
        require(process.returncode == 0, 'An original VSTest source command failed: ' + name)

    solution = args.source / 'TestPlatform_BuildFromSource.sln'
    run('original-solution-restore', solution, 'Restore')
    run('original-solution-build', solution, 'Build')
    stage = args.source / 'artifacts/Release'; stage.mkdir(parents=True, exist_ok=True)
    layout = stage / 'net7.0'; layout.mkdir()
    for relative in ['src/package/package/package.csproj', 'src/vstest.console/vstest.console.csproj',
                     'src/datacollector/datacollector.csproj', 'src/testhost/testhost.csproj', 'src/testhost.x86/testhost.x86.csproj']:
        project = args.source / relative
        run(project.parent.name + '-publish', project, 'Publish', ['/p:TargetFramework=net7.0', '/p:PublishDir=' + str(layout) + '/'])
    testhost = layout / 'TestHost'; testhost.mkdir()
    for name in ['testhost', 'testhost.x86']:
        for original in (args.source / 'src' / name / 'bin/Release/net7.0').iterdir():
            if original.is_dir(): shutil.copytree(original, testhost / original.name, dirs_exist_ok=True)
            elif original.is_file(): shutil.copyfile(original, testhost / original.name)
    extensions = layout / 'Extensions'; extensions.mkdir()
    projects = {
        'Microsoft.TestPlatform.Extensions.TrxLogger': 'Microsoft.VisualStudio.TestPlatform.Extensions.Trx.TestLogger',
        'Microsoft.TestPlatform.Extensions.HtmlLogger': 'Microsoft.VisualStudio.TestPlatform.Extensions.Html.TestLogger',
        'Microsoft.TestPlatform.Extensions.BlameDataCollector': 'Microsoft.TestPlatform.Extensions.BlameDataCollector',
        'DataCollectors/Microsoft.TestPlatform.Extensions.EventLogCollector': 'Microsoft.TestPlatform.Extensions.EventLogCollector',
        'Microsoft.TestPlatform.TestHostProvider': 'Microsoft.TestPlatform.TestHostRuntimeProvider'}
    extension_resources = []
    for project, base in projects.items():
        built = args.source / 'src' / project / 'bin/Release/net7.0'
        for suffix in ['.dll', '.pdb']:
            original = built / (base + suffix)
            require(original.is_file(), 'An original source-built extension is absent')
            shutil.copyfile(original, extensions / original.name)
            if (layout / original.name).is_file(): (layout / original.name).unlink()
        for culture in sorted(XLF.CULTURES):
            original = built / culture / (base + '.resources.dll')
            if original.is_file():
                destination = extensions / culture / original.name; destination.parent.mkdir(exist_ok=True)
                shutil.copyfile(original, destination)
                extension_resources.append(dict(path=destination.relative_to(stage).as_posix(), **fingerprint(destination)))
                if (layout / culture / original.name).is_file(): (layout / culture / original.name).unlink()
    shutil.copytree(args.source / 'src/Microsoft.TestPlatform.Build/bin/Release', stage / 'Microsoft.TestPlatform.Build')
    nuspec = args.source / 'src/package/nuspec'
    for name in ['Microsoft.TestPlatform.CLI.csproj', 'Microsoft.TestPlatform.Build.csproj', 'TestPlatform.CLI.nuspec', 'TestPlatform.Build.nuspec']:
        shutil.copyfile(nuspec / name, stage / name)
    for name in ['ThirdPartyNotices.txt', 'Icon.png']: shutil.copyfile(args.source / 'src/package' / name, stage / name)
    shutil.copytree(args.source / 'src/package/licenses', stage / 'licenses')
    feed = args.output / 'source-built-feed'; feed.mkdir()
    for name in ['Microsoft.TestPlatform.CLI', 'Microsoft.TestPlatform.Build']:
        run(name + '-pack', stage / (name + '.csproj'), 'Restore;Pack', ['/p:Version=' + VERSION,
            '/p:BranchName=HEAD', '/p:CommitId=' + COMMIT, '/p:PackageOutputPath=' + str(feed)])
    packages, managed_count, source_count = [], 0, 0
    for package in sorted(feed.glob('*.nupkg')):
        with zipfile.ZipFile(package) as archive:
            for member in archive.namelist():
                if member.endswith('/'): continue
                raw = archive.read(member)
                require(raw[:4] != b'\x7fELF', 'A managed source VSTest package contains native ELF payload')
                if member.lower().endswith(('.dll', '.exe')):
                    info = MANAGED.inspect(raw)
                    require(info['cliFlags'] & 1 and not info['cliFlags'] & 16 and info['managedNativeHeaderBytes'] == 0,
                            'A VSTest managed package contains an unreviewed native/ReadyToRun member')
                    managed_count += 1
                    source_count += any(COMMIT in str(v) for v in info['attributes'].values())
        packages.append(dict(path=package.relative_to(args.output).as_posix(), **fingerprint(package)))
    require({p['path'] for p in packages} == {'source-built-feed/Microsoft.TestPlatform.CLI.' + VERSION + '.nupkg',
            'source-built-feed/Microsoft.TestPlatform.Build.' + VERSION + '.nupkg'}, 'Both original source package products are required')
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl-vstest-source-build', status='passed',
        sdkVersion=SDK, architecture=args.arch, sourceCommit=COMMIT, sourceGraph='TestPlatform_BuildFromSource.sln',
        version=VERSION, originalSourceBuildFramework='net7.0', commands=commands, packages=packages,
        xlfResourceReceipt=fingerprint(args.output / 'xlf-resource-generation.json'), originalXlfFiles=247,
        managedPackageMembers=managed_count, sourceCommitAttributedMembers=source_count,
        importedDependenciesRequireSeparateSourceAttribution=True, compiledResourceAssembliesImported=False,
        originalSourceBuildCoreHostScope=True, fullMonoNetFrameworkTestHostProvided=False,
        closedCoverageInputImported=False, originalShellUnconditionalClosedCoverageCopyNotUsed=True,
        extensionResourcePlacement=extension_resources, vendorVersionRelabeled=False, readyToRunDisabled=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', version=VERSION, managedPackageMembers=managed_count, qualificationAllowed=False)))


if __name__ == '__main__': main()
