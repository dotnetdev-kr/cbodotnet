#!/usr/bin/env python3
"""Build SDK6 MSBuild localization from its exact source and reviewed Arcade.

This component worker does not qualify an SDK. Independent typed compiler,
original XLF, complete source and actual SDK consumption checks remain required.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

import musl_managed_metadata as MANAGED

ROOT = Path(__file__).resolve().parents[1]
SDK = '6.0.136'
COMMIT = '85d71072f8fa22cc761d6b65954da263364bee4d'
VERSION = '17.0.4-cbodotnet.1'
PROJECT = 'src/Package/Localization/Localization.csproj'
PATCH = 'patches/net6-musl/0005-build-localization-with-public-arcade.patch'
PATCH_SHA = '64dd84801b41370338cb32716cd129a443720a8730095761df4a16d8e0e3d9ed'
ORIGINAL_ARCADE = '6.0.0-beta.24176.9'
ARCADE = dict(version='6.0.0-beta.24204.4', bytes=1480019,
    sha256='229f0cde9a9a8f3dc919ed2b8cdfb093bb540c8eaa9e337e739c55316ed1fdf2',
    sha512='55cce6765b0c023a9b93dc25cb5080f4a23f5881f3ef84549c56cb886037c9c3981e29b0c99e799a2b990b72db47faea5cdbd477ddfa93d5dc2d990a7a468389',
    repository='https://github.com/dotnet/arcade', commit='bd9b4590681e602535ed414e98a17e6ba121dca4')
CULTURES = {'cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant'}


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and not any(p.is_symlink() for p in (path, *path.parents)),
            'Ordinary absolute SDK6 localization source/output/bootstrap path required')
    return path


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def git(source, *arguments):
    return ['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *map(str, arguments)]


def adjusted_global(raw):
    before = ('"Microsoft.DotNet.Arcade.Sdk": "' + ORIGINAL_ARCADE + '"').encode()
    after = ('"Microsoft.DotNet.Arcade.Sdk": "' + ARCADE['version'] + '"').encode()
    require(raw.count(before) == 1 and after not in raw, 'Exact original SDK6 localization Arcade declaration required')
    return raw.replace(before, after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--build-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for path in (args.source, args.dotnet, args.output):
        ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0
            and platform.machine() == {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch]
            and Path('/etc/alpine-release').read_text().strip() == '3.24.4',
            'Matching native non-root Alpine 3.24.4 execution required')
    require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id), 'Dated Community build identity required')
    require(subprocess.check_output(git(args.source, 'rev-parse', 'HEAD'), text=True).strip() == COMMIT
            and not subprocess.check_output(git(args.source, 'diff', '--name-only'))
            and not subprocess.check_output(git(args.source, 'ls-files', '--others', '--exclude-standard')),
            'Exact pristine tracked SDK6 MSBuild localization source required')
    require(args.dotnet.is_file() and not args.output.exists(), 'Fresh output and actual bootstrap required')
    original = subprocess.check_output(git(args.source, 'show', COMMIT + ':global.json'))
    require((args.source / 'global.json').read_bytes() == original, 'Original localization global.json bytes differ')
    adjusted = adjusted_global(original)
    patch = ordinary(ROOT / PATCH)
    require(fingerprint(patch)['sha256'] == PATCH_SHA, 'Reviewed localization build-only Arcade patch differs')
    args.output.mkdir(parents=True)
    (args.output / 'global.original.json').write_bytes(original)
    shutil.copyfile(patch, args.output / 'source.patch')
    commands = []

    def run(name, command, *, environment=None, timeout=1800):
        command = list(map(str, command))
        log = args.output / (name + '.log')
        started = datetime.now(timezone.utc).isoformat()
        with log.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(command) + '\n')
            stream.flush()
            result = subprocess.run(command, cwd=args.source, env=environment,
                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        row = dict(name=name, command=command, exitCode=result.returncode, log=log.name,
            startedAtUtc=started, completedAtUtc=datetime.now(timezone.utc).isoformat(), **fingerprint(log))
        commands.append(row)
        write(args.output / (name + '-command.json'), row)
        require(result.returncode == 0, 'Original localization command failed: ' + name)
        return log.read_text()

    run('patch-check', git(args.source, 'apply', '--check', patch))
    run('patch-apply', git(args.source, 'apply', patch))
    require((args.source / 'global.json').read_bytes() == adjusted
            and subprocess.check_output(git(args.source, 'diff', '--name-only'), text=True).splitlines() == ['global.json'],
            'Only the one reviewed build-only Arcade SDK declaration may change')
    run('source-diff-check', git(args.source, 'diff', '--check'))
    (args.output / 'source-changes.patch').write_bytes(subprocess.check_output(git(args.source, 'diff', '--binary')))
    cache = args.source / 'artifacts/.packages-localization'
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='2', NUGET_PACKAGES=str(cache), MSBUILDDISABLENODEREUSE='1')
    selected = run('bootstrap-sdk-version', [args.dotnet, '--version'], environment=environment)
    require(selected.partition('\n')[2].strip() == '6.0.135', 'Reviewed SDK6.0.135 bootstrap must be selected')
    text = run('build', [args.dotnet, 'msbuild', args.source / PROJECT, '/restore', '/t:Build,Pack',
        '/p:Configuration=Release', '/p:DotNetBuildFromSource=true', '/p:OfficialBuildId=' + args.build_id,
        '/p:ContinuousIntegrationBuild=true', '/p:PackageVersion=' + VERSION,
        '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true', '/m:2', '/nr:false',
        '/bl:' + str(args.output / 'localization.binlog')], environment=environment)
    require(not re.search(r'(?m)^.*: error [A-Za-z]+[0-9]+:', text), 'Original localization build emitted an error diagnostic')
    require((args.source / 'global.json').read_bytes() == adjusted, 'Localization build changed its reviewed SDK declaration')
    arcade = cache / ('microsoft.dotnet.arcade.sdk/' + ARCADE['version'] + '/microsoft.dotnet.arcade.sdk.' + ARCADE['version'] + '.nupkg')
    require(arcade.is_file() and all(fingerprint(arcade)[key] == ARCADE[key] for key in ('bytes', 'sha256', 'sha512')),
            'Actual restored public Arcade input bytes differ')
    with zipfile.ZipFile(arcade) as archive:
        metadata = ET.fromstring(archive.read('Microsoft.DotNet.Arcade.Sdk.nuspec')).find('{*}metadata')
        require(metadata.findtext('{*}version') == ARCADE['version']
                and metadata.find('{*}repository').get('commit') == ARCADE['commit']
                and metadata.find('{*}license').text == 'MIT', 'Actual Arcade publisher source/license differs')
    (args.output / 'bootstrap-inputs').mkdir()
    shutil.copyfile(arcade, args.output / 'bootstrap-inputs' / arcade.name)
    packages = list((args.source / 'artifacts/packages/Release/NonShipping').glob('Microsoft.Build.Localization.*.nupkg'))
    require(len(packages) == 1 and packages[0].name == 'Microsoft.Build.Localization.' + VERSION + '.nupkg',
            'One genuine downstream localization package required')
    feed = args.output / 'source-built-feed'
    feed.mkdir()
    target = feed / packages[0].name
    shutil.copyfile(packages[0], target)
    rows = []
    with zipfile.ZipFile(target) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), 'Duplicate localization package members forbidden')
        specs = [name for name in archive.namelist() if name.endswith('.nuspec')]
        require(len(specs) == 1, 'Original localization nuspec required')
        metadata = ET.fromstring(archive.read(specs[0])).find('{*}metadata')
        require(metadata.findtext('{*}id') == 'Microsoft.Build.Localization'
                and metadata.findtext('{*}version') == VERSION and metadata.find('{*}repository') is None
                and metadata.find('{*}license').text == 'MIT', 'Genuine localization package identity/license differs')
        names = [name for name in archive.namelist() if name.lower().endswith(('.dll', '.exe'))]
        require(len(names) == 52 and all(name.endswith('.resources.dll') for name in names),
                'Exactly 52 original source-built resource-only satellites required')
        for name in sorted(names):
            raw = archive.read(name)
            identity = MANAGED.inspect(raw)
            counts = identity['definitionCounts']
            require(identity['assemblyVersion'] == '15.1.0.0' and identity['publicKeyToken'] == 'b03f5f7f11d50a3a'
                    and identity['culture'] in CULTURES and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0
                    and counts['types'] == 1 and all(counts[key] == 0 for key in ('methods', 'fields', 'files', 'exportedTypes')),
                    'Resource-only localization ABI and unchanged culture are required')
            rows.append(dict(member=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                sha512=hashlib.sha512(raw).hexdigest(), metadata=identity))
    require({row['metadata']['culture'] for row in rows} == CULTURES, 'All thirteen original localization cultures required')
    write(args.output / 'results.json', dict(schemaVersion=1, kind='sdk6-source-msbuild-localization-build', status='passed',
        sdkVersion=SDK, architecture=args.arch, sourceCommit=COMMIT, packageVersion=VERSION,
        worker=fingerprint(Path(__file__)), sourcePatch=dict(path=PATCH, **fingerprint(patch)),
        originalGlobal=fingerprint(args.output / 'global.original.json'), actualGlobal=fingerprint(args.source / 'global.json'),
        originalRequestedArcade=ORIGINAL_ARCADE, actualArcade=ARCADE, buildId=args.build_id, bootstrapSdk='6.0.135',
        originalMissingPublisherPackageVersion='17.0.4-preview-24422-07', originalPublisherVersionReused=False,
        productCSharpChanged=False, targetFrameworksChanged=False, sourceChanges=['global.json'],
        package=dict(path='source-built-feed/' + target.name, **fingerprint(target)), satellites=rows, commands=commands,
        localizationBinlog=fingerprint(args.output / 'localization.binlog'), qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', packages=1, satellites=52, qualificationAllowed=False)))


if __name__ == '__main__':
    main()
