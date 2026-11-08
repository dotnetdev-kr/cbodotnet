#!/usr/bin/env python3
"""Build the original SDK5 NuGet libraries and genuine rc packages.

Original library TFMs are preserved, including project-specific net40/net45.
The documented unmerged source-build Pack input also applies when the full
library matrix is selected. Compiler/source and actual consumption admission
remain separate independent checks.
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
from musl_legacy5_nuget_graph import prepare as prepare_original_xplat_graph, verify_original_raw_tree

ROOT = Path(__file__).resolve().parents[1]
SDK = '5.0.214'
COMMIT = 'd525b0e670f3b6cbd5c73a35f04730a9f658c852'
VERSION = '5.9.1-rc.8'
PROJECT = 'src/NuGet.Core/NuGet.Build.Tasks.Pack/NuGet.Build.Tasks.Pack.csproj'
ORIGINAL_BLOB = 'f11dd752beaf08c1548f1d70255d65122c3a2442'
PATCH = 'patches/net5-musl/0009-preserve-original-nuget-unmerged-pack-matrix.patch'
PATCH_SHA256 = '7820689e72944f2c608810ad59a93b27c1ddd8459830907a63358dc5c683f286'
EXPECTED_PACKAGES = {
    'Microsoft.Build.NuGetSdkResolver.5.9.1-rc.8.nupkg',
    'NuGet.Build.Tasks.5.9.1-rc.8.nupkg',
    'NuGet.Build.Tasks.Console.5.9.1-rc.8.nupkg',
    'NuGet.Build.Tasks.Pack.5.9.1-rc.8.nupkg',
    'NuGet.CommandLine.XPlat.5.9.1-rc.8.nupkg',
    'NuGet.Commands.5.9.1-rc.8.nupkg',
    'NuGet.Common.5.9.1-rc.8.nupkg',
    'NuGet.Configuration.5.9.1-rc.8.nupkg',
    'NuGet.Credentials.5.9.1-rc.8.nupkg',
    'NuGet.DependencyResolver.Core.5.9.1-rc.8.nupkg',
    'NuGet.Frameworks.5.9.1-rc.8.nupkg',
    'NuGet.LibraryModel.5.9.1-rc.8.nupkg',
    'NuGet.PackageManagement.5.9.1-rc.8.nupkg',
    'NuGet.Packaging.5.9.1-rc.8.nupkg',
    'NuGet.Packaging.Core.5.9.1-rc.8.nupkg',
    'NuGet.ProjectModel.5.9.1-rc.8.nupkg',
    'NuGet.Protocol.5.9.1-rc.8.nupkg',
    'NuGet.Resolver.5.9.1-rc.8.nupkg',
    'NuGet.Versioning.5.9.1-rc.8.nupkg',
}
FRAMEWORKS = {'net40', 'net45', 'net472', 'net5.0', 'netcoreapp2.1', 'netstandard2.0'}
FEEDS = ['https://api.nuget.org/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json']


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and
            not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary absolute source/output/bootstrap path required')
    return path


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def write(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2); stream.write('\n')


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
    for path in (args.source, args.dotnet, args.output): ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0 and platform.machine() ==
            {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Matching native non-root Alpine 3.24.4 required')
    original_tree = verify_original_raw_tree(args.source)
    require(git(args.source, 'rev-parse', COMMIT + ':' + PROJECT) == ORIGINAL_BLOB,
            'Original NuGet Pack source blob differs')
    patch = ordinary(ROOT / PATCH)
    require(fingerprint(patch)['sha256'] == PATCH_SHA256, 'Reviewed three-condition source-build Pack patch differs')
    require(not args.output.exists(), 'Fresh SDK5 NuGet output required')
    args.output.mkdir(parents=True)
    shutil.copyfile(patch, args.output / 'source.patch')
    original = subprocess.check_output(['git', '-c', 'safe.directory=' + str(args.source), '-C', str(args.source),
                                        'show', COMMIT + ':' + PROJECT])
    (args.output / 'original-Pack.csproj').write_bytes(original)
    write(args.output / 'original-raw-git-tree.json', original_tree)
    commands = []

    def run(name, command, environment=None, timeout=1800):
        command = list(map(str, command)); log = args.output / (name + '.log')
        started = datetime.now(timezone.utc).isoformat()
        with log.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(command) + '\n'); stream.flush()
            result = subprocess.run(command, cwd=args.source, env=environment,
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        row = dict(name=name, command=command, exitCode=result.returncode, startedAt=started,
            completedAt=datetime.now(timezone.utc).isoformat(), log=log.name, **fingerprint(log))
        commands.append(row); write(args.output / (name + '-command.json'), row)
        require(result.returncode == 0, 'Original SDK5 NuGet source command failed: ' + name)

    base = ['git', '-c', 'safe.directory=' + str(args.source), '-C', str(args.source), 'apply']
    run('source-patch-check', base + ['--check', str(patch)], timeout=60)
    run('source-patch-apply', base + [str(patch)], timeout=60)
    require(git(args.source, 'diff', '--ignore-submodules=dirty', '--name-only').splitlines() == [PROJECT],
            'Only the reviewed Pack input selection source edit is allowed')
    require(len(original_tree['submodules']) == 3 and all(child['allTrackedRawGitBlobsIdentical'] for child in original_tree['submodules']), 'All exact original Gitlink source bytes required')
    for child in original_tree['submodules']: verify_original_raw_tree(args.source / child['path'], child['commit'])
    driver, graph = prepare_original_xplat_graph(args.source, args.output / 'derived-xplat-graph')
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        NUGET_PACKAGES=str(args.source / 'artifacts/.packages'), MSBUILDDISABLENODEREUSE='1')
    run('original-library-matrix', [args.dotnet, 'msbuild', driver,
        '-t:RestoreXPLAT,BuildXPLAT,PackXPLAT', '/p:Configuration=Release', '/p:BuildNumber=8', '/p:ReleaseLabel=rc',
        '/p:IsXPlat=true', '/p:DotNetBuildFromSource=true', '/p:NetStandardVersion=netstandard2.0',
        '/p:IsBuildOnlyXPLATProjects=false', '/p:BuildProjectReferences=true', '/p:RepositoryCommit=' + COMMIT,
        '/p:SourceRevisionId=' + COMMIT, '/p:BUILD_SOURCEVERSION=' + COMMIT,
        '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:RestoreSources=' + '%3B'.join(FEEDS), '/m:1', '/bl:' + str(args.output / 'original-library-matrix.binlog'),
        '/nologo'], environment)
    feed = args.output / 'source-built-feed'; feed.mkdir()
    packages, managed, tfms = [], 0, set()
    for package in sorted((args.source / 'artifacts/nupkgs').glob('*.nupkg')):
        if package.name.endswith('.symbols.nupkg'): continue
        with zipfile.ZipFile(package) as archive:
            metadata = ET.fromstring(archive.read(next(n for n in archive.namelist() if n.endswith('.nuspec')))).find('{*}metadata')
            require(metadata.findtext('{*}version') == VERSION, 'Genuine original NuGet package version differs')
            for member in archive.namelist():
                if member.endswith('/'): continue
                raw = archive.read(member)
                require(raw[:4] != b'\x7fELF', 'NuGet managed source package contains an ELF payload')
                if not member.lower().endswith(('.dll', '.exe')): continue
                info = MANAGED.inspect(raw)
                require(info['cliFlags'] & 1 and not info['cliFlags'] & 16 and info['managedNativeHeaderBytes'] == 0 and
                        any(COMMIT in str(v) for v in info['attributes'].values()),
                        'Original NuGet package contains an unreviewed executable or source identity')
                managed += 1
                if member.startswith('lib/'): tfms.add(member.split('/')[1])
        destination = feed / package.name; shutil.copyfile(package, destination)
        require(fingerprint(package) == fingerprint(destination), 'Genuine package changed during retention')
        packages.append(dict(path=destination.relative_to(args.output).as_posix(), **fingerprint(destination)))
    require({Path(row['path']).name for row in packages} == EXPECTED_PACKAGES and managed == 76 and tfms == FRAMEWORKS,
            'Complete original SDK5 NuGet library/package matrix required')
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl5-nuget-source-build', status='passed',
        sdkVersion=SDK, architecture=args.arch, sourceCommit=COMMIT, version=VERSION, sourceGraph='original build/build.proj via retained downstream XPLAT selection driver',
        generatedGraph=graph,
        commands=commands, packages=packages, managedPackageMembers=managed, libraryFrameworks=sorted(tfms),
        originalLibraryDefaultsSelectedExplicitly=True, executableFramework='netcoreapp2.1', libraryFrameworksRemoved=False,
        sourcePatches=[dict(path=PATCH, **fingerprint(patch))], productCSharpEdited=False,
        vendorVersionRelabeled=False, qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', version=VERSION, packages=len(packages), managedPackageMembers=managed)))


if __name__ == '__main__': main()
