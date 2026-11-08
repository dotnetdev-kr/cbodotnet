#!/usr/bin/env python3
"""Build the original SDK6 NuGet libraries and genuine rc packages.

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

ROOT = Path(__file__).resolve().parents[1]
SDK = '6.0.136'
COMMIT = '451e9bc27184dc49d04e975122c9e7189d525872'
VERSION = '6.0.6-rc.4'
PROJECT = 'src/NuGet.Core/NuGet.Build.Tasks.Pack/NuGet.Build.Tasks.Pack.csproj'
ORIGINAL_BLOB = 'c94acffd885742b8c71f3e39818ca07ecdd08f4f'
PATCH = 'patches/net6-musl/0002-preserve-source-build-unmerged-pack-matrix.patch'
PATCH_SHA256 = '5e98dc1c81fd917017b48882fd71c9a731067b41a3e8d5280a832047f7a82fcd'
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
    require(git(args.source, 'rev-parse', 'HEAD') == COMMIT and
            not git(args.source, 'status', '--porcelain', '--untracked-files=all'), 'Exact pristine SDK6 NuGet source required')
    require(git(args.source, 'rev-parse', COMMIT + ':' + PROJECT) == ORIGINAL_BLOB,
            'Original NuGet Pack source blob differs')
    patch = ordinary(ROOT / PATCH)
    require(fingerprint(patch)['sha256'] == PATCH_SHA256, 'Reviewed three-condition source-build Pack patch differs')
    require(not args.output.exists(), 'Fresh SDK6 NuGet output required')
    args.output.mkdir(parents=True)
    shutil.copyfile(patch, args.output / 'source.patch')
    original = subprocess.check_output(['git', '-c', 'safe.directory=' + str(args.source), '-C', str(args.source),
                                        'show', COMMIT + ':' + PROJECT])
    (args.output / 'original-Pack.csproj').write_bytes(original)
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
        require(result.returncode == 0, 'Original SDK6 NuGet source command failed: ' + name)

    base = ['git', '-c', 'safe.directory=' + str(args.source), '-C', str(args.source), 'apply']
    run('source-patch-check', base + ['--check', str(patch)], timeout=60)
    run('source-patch-apply', base + [str(patch)], timeout=60)
    require(git(args.source, 'diff', '--name-only').splitlines() == [PROJECT],
            'Only the reviewed Pack input selection source edit is allowed')
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='2', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        NUGET_PACKAGES=str(args.source / 'artifacts/.packages'), MSBUILDDISABLENODEREUSE='1')
    run('original-library-matrix', [args.dotnet, 'msbuild', args.source / 'build/build.proj',
        '-t:RestoreXPLAT,BuildXPLAT,PackXPLAT', '/p:Configuration=Release', '/p:BuildNumber=4', '/p:ReleaseLabel=rc',
        '/p:IsXPlat=true', '/p:DotNetBuildFromSource=true', '/p:NetStandardVersion=netstandard2.0',
        '/p:IsBuildOnlyXPLATProjects=false', '/p:BuildProjectReferences=true', '/p:RepositoryCommit=' + COMMIT,
        '/p:SourceRevisionId=' + COMMIT, '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:RestoreSources=' + '%3B'.join(FEEDS), '/m:2', '/bl:' + str(args.output / 'original-library-matrix.binlog'),
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
                require(info['cliFlags'] & 1 and info['managedNativeHeaderBytes'] == 0 and
                        any(COMMIT in str(v) for v in info['attributes'].values()),
                        'Original NuGet package contains an unreviewed executable or source identity')
                managed += 1
                if member.startswith('lib/'): tfms.add(member.split('/')[1])
        destination = feed / package.name; shutil.copyfile(package, destination)
        require(fingerprint(package) == fingerprint(destination), 'Genuine package changed during retention')
        packages.append(dict(path=destination.relative_to(args.output).as_posix(), **fingerprint(destination)))
    require(len(packages) == 19 and managed == 72 and tfms == {'net40', 'net45', 'net472', 'net6.0', 'netstandard2.0'},
            'Complete original SDK6 NuGet library/package matrix required')
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl6-nuget-source-build', status='passed',
        sdkVersion=SDK, architecture=args.arch, sourceCommit=COMMIT, version=VERSION, sourceGraph='build/build.proj',
        commands=commands, packages=packages, managedPackageMembers=managed, libraryFrameworks=sorted(tfms),
        originalLibraryDefaultsSelectedExplicitly=True, executableFramework='net6.0', libraryFrameworksRemoved=False,
        sourcePatches=[dict(path=PATCH, **fingerprint(patch))], productCSharpEdited=False,
        vendorVersionRelabeled=False, qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', version=VERSION, packages=len(packages), managedPackageMembers=managed)))


if __name__ == '__main__': main()
