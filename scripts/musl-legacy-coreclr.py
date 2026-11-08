#!/usr/bin/env python3
"""Rebuild pinned legacy CoreCLR shared products on native stock Alpine.

This worker produces four native overlays, not a complete runtime or SDK. It
retains the original Release graph, the upstream native version producer,
generated sources, compiler commands and exact output identities. Container
policy, SDK construction and independent cold/functional/LTTng checks belong
to the calling producer and its admission validator.
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

ROOT = Path(__file__).resolve().parents[1]
SDK = '7.0.120'
COMMIT = '0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903'
RUNTIME_VERSION = '7.0.20'
PATCHES = [
    'patches/net7-musl/0004-guard-runtime-only-reflection-cache-mutations-in-dac.patch',
    'patches/net7-musl/0005-backport-metadata-local-allocation-marker.patch',
]
OUTPUTS = {
    'libcoreclr.so': 'dlls/mscoree/coreclr/libcoreclr.so',
    'libclrjit.so': 'jit/libclrjit.so',
    'libmscordaccore.so': 'dlls/mscordac/libmscordaccore.so',
    'libmscordbi.so': 'dlls/mscordbi/libmscordbi.so',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and
            not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary absolute path is required: ' + str(path))
    return path


def fingerprint(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                sha512=hashlib.sha512(data).hexdigest())


def write(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def git(source, *arguments):
    return ['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *arguments]


def execute(args, rows, name, command, *, environment=None, timeout=1800):
    command = list(map(str, command))
    started = datetime.now(timezone.utc).isoformat()
    log = args.output / (name + '.log')
    with log.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(command) + '\n')
        stream.flush()
        result = subprocess.run(command, cwd=args.source,
                                env=dict(os.environ, **(environment or {})),
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    row = dict(name=name, command=command, startedAt=started,
               completedAt=datetime.now(timezone.utc).isoformat(),
               exitCode=result.returncode, log=log.name, **fingerprint(log))
    rows.append(row)
    write(args.output / (name + '-command.json'), row)
    require(result.returncode == 0, 'Native source command failed: ' + name)
    return log.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--build-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for path in [args.source, args.dotnet, args.output]:
        ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0 and
            platform.machine() == {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4',
            'Matching native non-root Alpine 3.24.4 execution is required')
    require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id), 'A dated community build identity is required')
    require(subprocess.check_output(git(args.source, 'rev-parse', 'HEAD'), text=True).strip() == COMMIT,
            'The exact runtime source commit is required')
    require(not subprocess.check_output(git(args.source, 'status', '--porcelain', '--untracked-files=no'), text=True),
            'The native runtime worker requires pristine tracked source before its reviewed patches')
    require(not args.output.exists(), 'A fresh native runtime output directory is required')
    args.output.mkdir(parents=True)
    rows = []
    patches = []
    for index, relative in enumerate(PATCHES):
        patch = ROOT / relative
        execute(args, rows, 'patch-check-' + str(index), git(args.source, 'apply', '--check', patch))
        execute(args, rows, 'patch-apply-' + str(index), git(args.source, 'apply', patch))
        patches.append(dict(path=relative, **fingerprint(patch)))
    env = dict(DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
               NUGET_PACKAGES=str(args.source / '.packages'), DOTNET_PROCESSOR_COUNT='2')
    execute(args, rows, 'native-version', [args.dotnet, 'msbuild', args.source / 'eng/empty.csproj',
        '/restore', '/t:GenerateRuntimeVersionFile',
        '/p:NativeVersionFile=' + str(args.source / 'artifacts/obj/_version.c'),
        '/p:Version=' + RUNTIME_VERSION, '/p:OfficialBuildId=' + args.build_id,
        '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false',
        '/bl:' + str(args.output / 'native-version.binlog')], environment=env)
    header = args.source / 'artifacts/obj/runtime_version.h'
    require('#define RuntimeProductVersion ' + RUNTIME_VERSION in header.read_text(),
            'The upstream version producer did not emit the exact runtime product version')
    version_macros = dict(re.findall(r'^#define (Runtime(?:Assembly|File)(?:Major|Minor|Build|Revision)Version) ([0-9]+)$',
                                   header.read_text(), re.MULTILINE))
    def version(kind, parts):
        keys = ['Runtime' + kind + part + 'Version' for part in parts]
        require(all(key in version_macros for key in keys), 'The upstream generated version header is incomplete')
        return '.'.join(version_macros[key] for key in keys)
    assembly_version = version('Assembly', ['Major', 'Minor'])
    file_version = version('File', ['Major', 'Minor', 'Build', 'Revision'])
    require(assembly_version == '7.0', 'The upstream generated runtime assembly version differs')
    cpu = 'arm64' if args.arch == 'aarch64' else 'x64'
    configure = execute(args, rows, 'configure', [args.source / 'src/coreclr/build-runtime.sh',
        '-' + cpu, '-release', '-component', 'runtime', '-component', 'jit', '-numproc', '2',
        '-cmakeargs', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLIBGSS=/usr/lib/libgssapi_krb5.so.2 '
                      '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-configureonly'], environment=env)
    require('-- Generating done' in configure and 'CMake Error' not in configure,
            'The upstream configure wrapper did not complete CMake generation')
    obj = args.source / ('artifacts/obj/coreclr/Linux.' + cpu + '.Release')
    targets = ['coreclr', 'clrjit', 'mscordaccore', 'mscordbi', 'coreclrtraceptprovider']
    execute(args, rows, 'build', ['cmake', '--build', obj, '--target', *targets,
                                 '--parallel', '2', '--verbose'], environment=env)
    outputs = []
    for name, relative in OUTPUTS.items():
        original = obj / relative
        require(original.is_file() and not original.is_symlink(), 'A native source-built product is absent: ' + name)
        data = original.read_bytes()
        require(data[:4] == b'\x7fELF' and int.from_bytes(data[18:20], 'little') ==
                {'aarch64': 183, 'x64': 62}[args.arch], 'A source-built product has the wrong native ELF CPU')
        target = args.output / name
        shutil.copyfile(original, target)
        execute(args, rows, 'elf-' + name, ['readelf', '--wide', '--file-header', '--dynamic', '--version-info', target])
        outputs.append(dict(path=name, buildPath=str(original), **fingerprint(target)))
    generated = args.output / 'generated'
    generated.mkdir()
    extensions = {'.h', '.hpp', '.c', '.cpp', '.cc', '.inc', '.s', '.S', '.asm', '.cmake', '.txt', '.json'}
    for label, directory in [('coreclr', obj), ('external', args.source / 'artifacts/obj/external')]:
        for original in sorted(directory.rglob('*')):
            if original.is_file() and not original.is_symlink() and original.suffix in extensions:
                destination = generated / label / original.relative_to(directory)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)
    for name in ['_version.c', 'runtime_version.h']:
        shutil.copyfile(args.source / 'artifacts/obj' / name, generated / name)
    for name in ['CMakeCache.txt', 'compile_commands.json']:
        shutil.copyfile(obj / name, args.output / name)
    execute(args, rows, 'compiler-version', ['clang', '--version'])
    execute(args, rows, 'cmake-version', ['cmake', '--version'])
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl-native-runtime-build',
        status='passed', sdkVersion=SDK, runtimeVersion=RUNTIME_VERSION, architecture=args.arch,
        sourceCommit=COMMIT, sourcePatches=patches,
        upstreamMetadataBackport='35a39e97345abfda05e14f609759760b37ddeb4d',
        buildId=args.build_id, runtimeAssemblyVersion=assembly_version, nativeFileVersion=file_version,
        configuration='Release', targets=targets, shippingFiles=outputs,
        traceProviderBuiltButImportedFromSeparateMatchingSourceWorker=True,
        productVersionMetadataQualified=True, nativeVersionBinlog=fingerprint(args.output / 'native-version.binlog'),
        cmakeCache=fingerprint(args.output / 'CMakeCache.txt'),
        compileCommands=fingerprint(args.output / 'compile_commands.json'),
        generatedSourceFileCount=sum(p.is_file() for p in generated.rglob('*')),
        commands=rows, tracingDisabled=False, readyToRunDisabled=False, optimizationDisabled=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', output=str(args.output), qualificationAllowed=False)))


if __name__ == '__main__':
    main()
