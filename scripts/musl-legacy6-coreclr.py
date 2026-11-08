#!/usr/bin/env python3
"""Build SDK6's five native runtime products from its exact runtime source.

Release optimization, tracing and the normal runtime/JIT graph remain enabled.
Archive-only runtime, TLS, ReadyToRun and LTTng consumer checks are separate.
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
SDK = '6.0.136'
RUNTIME = '6.0.36'
COMMIT = 'f1dd57165bfd91875761329ac3a8b17f6606ad18'
BACKPORT = '35a39e97345abfda05e14f609759760b37ddeb4d'
PATCHES = {
    'patches/net6-musl/0003-guard-runtime-only-reflection-cache-mutations-in-dac.patch':
        '773dd9dae8c3e82d7f04831da915893210bc8cd71541cec6c98aed3918b84c34',
    'patches/net6-musl/0004-backport-metadata-local-allocation-marker.patch':
        '555f4aa0cd4cb67ce9b316081625dcb9893a812509c161ccfe06486438f37d5b'}
PRODUCTS = {
    'libcoreclr.so': 'dlls/mscoree/coreclr/libcoreclr.so',
    'libclrjit.so': 'jit/libclrjit.so',
    'libmscordaccore.so': 'dlls/mscordac/libmscordaccore.so',
    'libmscordbi.so': 'dlls/mscordbi/libmscordbi.so',
    'libcoreclrtraceptprovider.so': 'pal/src/eventprovider/lttngprovider/libcoreclrtraceptprovider.so'}
TARGETS = ['coreclr', 'clrjit', 'mscordaccore', 'mscordbi', 'coreclrtraceptprovider']
READABLE = {'.h', '.hpp', '.c', '.cpp', '.cc', '.inc', '.s', '.S', '.asm', '.cmake', '.txt', '.json'}


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and
            not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary absolute native build path required')
    return path


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def write(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2); stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True)
    parser.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-id', required=True)
    args = parser.parse_args()
    for path in (args.source, args.dotnet, args.output): ordinary(path)
    require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id), 'Exact native version build identity required')
    require(platform.system() == 'Linux' and os.getuid() != 0 and platform.machine() ==
            {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Matching native non-root Alpine 3.24.4 required')
    git = ['git', '-c', 'safe.directory=' + str(args.source), '-C', str(args.source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == COMMIT and
            not subprocess.check_output(git + ['status', '--porcelain', '--untracked-files=all'], text=True).strip(),
            'Exact pristine SDK6 runtime source required')
    require(not args.output.exists(), 'Fresh native runtime output required')
    args.output.mkdir(parents=True)
    write(args.output / 'invocation.json', dict(sdkVersion=SDK, runtimeVersion=RUNTIME, architecture=args.arch,
        sourceCommit=COMMIT, buildId=args.build_id, source=str(args.source), dotnet=str(args.dotnet), output=str(args.output),
        worker=fingerprint(Path(__file__)), qualificationAllowed=False, sourceAdmissionAllowed=False))
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='2', NUGET_PACKAGES=str(args.source / 'artifacts/.packages'), MSBUILDDISABLENODEREUSE='1')
    commands = []

    def run(name, command, timeout=1800):
        command = list(map(str, command)); log = args.output / (name + '.log')
        started = datetime.now(timezone.utc).isoformat()
        with log.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(command) + '\n'); stream.flush()
            result = subprocess.run(command, cwd=args.source, env=environment, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        row = dict(name=name, command=command, exitCode=result.returncode, startedAt=started,
            completedAt=datetime.now(timezone.utc).isoformat(), log=log.name, **fingerprint(log))
        commands.append(row); write(args.output / (name + '-command.json'), row)
        require(result.returncode == 0, 'Original native SDK6 runtime command failed: ' + name)
        return log.read_text()

    patches = args.output / 'patches'; patches.mkdir(); identities = []
    for index, (name, expected) in enumerate(PATCHES.items(), 1):
        patch = ordinary(ROOT / name); require(fingerprint(patch)['sha256'] == expected, 'Exact SDK6 native source patch required')
        retained = patches / patch.name; shutil.copyfile(patch, retained)
        run('source-patch-' + str(index) + '-check', git + ['apply', '--check', str(retained)], 60)
        run('source-patch-' + str(index) + '-apply', git + ['apply', str(retained)], 60)
        identities.append(dict(path=name, **fingerprint(retained)))
    changed = subprocess.check_output(git + ['diff', '--name-only'], text=True).splitlines()
    require(changed == ['src/coreclr/md/runtime/metamodel.cpp', 'src/coreclr/vm/comreflectioncache.hpp'],
            'Only the reviewed DAC cache guard and upstream metadata marker edits are allowed')
    write(args.output / 'source-adaptations.json', dict(sourceCommit=COMMIT, patches=identities,
        metadataUpstreamBackport=BACKPORT, metadataAdaptation='Original NET6 NumItems assertion with upstream local allocation marker',
        dacScope='Runtime-only cache mutator member definitions; no non-DAC behavior or object layout edit',
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    native_version = args.source / 'artifacts/obj/_version.c'
    run('native-version', [args.dotnet, 'msbuild', args.source / 'eng/empty.csproj', '/restore',
        '/t:GenerateRuntimeVersionFile', '/p:NativeVersionFile=' + str(native_version), '/p:Version=' + RUNTIME,
        '/p:OfficialBuildId=' + args.build_id, '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false',
        '/bl:' + str(args.output / 'native-version.binlog')])
    header = args.source / 'artifacts/obj/runtime_version.h'; text = header.read_text()
    require('#define RuntimeProductVersion ' + RUNTIME in text, 'Original runtime native product version differs')
    macros = dict(re.findall(r'^#define (Runtime(?:Assembly|File)(?:Major|Minor|Build|Revision)Version) ([0-9]+)$', text, re.M))
    assembly_version = '.'.join(macros['RuntimeAssembly' + name + 'Version'] for name in ('Major', 'Minor'))
    file_version = '.'.join(macros['RuntimeFile' + name + 'Version'] for name in ('Major', 'Minor', 'Build', 'Revision'))
    require(assembly_version == '6.0', 'Original runtime native assembly ABI differs')
    original_version, original_header = native_version.read_bytes(), header.read_bytes()
    arch = 'arm64' if args.arch == 'aarch64' else 'x64'
    configured = run('configure', [args.source / 'src/coreclr/build-runtime.sh', '-' + arch, '-release',
        '-component', 'runtime', '-component', 'jit', '-numproc', '2', '-cmakeargs',
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLIBGSS=/usr/lib/libgssapi_krb5.so.2 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-configureonly', '/p:Version=' + RUNTIME, '/p:OfficialBuildId=' + args.build_id,
        '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false'])
    require('-- Generating done' in configured and 'CMake Error' not in configured, 'Complete original native runtime configuration required')
    obj = args.source / ('artifacts/obj/coreclr/Linux.' + arch + '.Release')
    compiled_version = obj / 'version.c'
    compiled_header = obj.parent / 'runtime_version.h'
    require(compiled_version.read_bytes() == original_version and compiled_header.read_bytes() == original_header
            and file_version.encode() in original_version and COMMIT.encode() in original_version
            and b'42.42.42' not in original_version,
            'Original configure must compile the actual dated native version and matching header')
    run('build', ['cmake', '--build', obj, '--target', *TARGETS, '--parallel', '2', '--verbose'])
    products, debug = [], []
    for name, relative in PRODUCTS.items():
        built = ordinary(obj / relative); raw = built.read_bytes()
        require(raw[:4] == b'\x7fELF' and int.from_bytes(raw[18:20], 'little') ==
                {'aarch64': 183, 'x64': 62}[args.arch], 'Actual native product CPU/ELF differs')
        require(file_version.encode() in raw and COMMIT.encode() in raw and b'42.42.42.42424' not in raw,
                'Actual native product must embed its original dated version and source commit')
        target = args.output / name; shutil.copyfile(built, target); products.append(dict(path=name, **fingerprint(target)))
        run('elf-' + name, ['readelf', '--wide', '--file-header', '--dynamic', '--version-info', target])
        sidecar = built.with_name(built.name + '.dbg')
        if sidecar.is_file():
            require(not sidecar.is_symlink(), 'Ordinary native debug sidecar required')
            destination = args.output / 'debug' / sidecar.name; destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(sidecar, destination); debug.append(dict(path=destination.relative_to(args.output).as_posix(), **fingerprint(destination)))
    generated = args.output / 'generated'; generated.mkdir()
    for label, directory in [('coreclr', obj), ('external', args.source / 'artifacts/obj/external')]:
        for path in sorted(directory.rglob('*')):
            if path.is_file() and path.suffix in READABLE:
                require(not path.is_symlink() and path.stat().st_size <= 16 * 1024**2, 'Bounded ordinary generated native source required')
                destination = generated / label / path.relative_to(directory); destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
    for path in (native_version, header): shutil.copyfile(path, generated / path.name)
    shutil.copyfile(compiled_header, generated / 'compiled-runtime_version.h')
    for name in ('CMakeCache.txt', 'compile_commands.json'): shutil.copyfile(obj / name, args.output / name)
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl6-coreclr-source-build', status='passed',
        sdkVersion=SDK, runtimeVersion=RUNTIME, architecture=args.arch, sourceCommit=COMMIT, buildId=args.build_id,
        configuration='Release', targets=TARGETS, runtimeAssemblyVersion=assembly_version, nativeFileVersion=file_version,
        sourcePatches=identities, metadataUpstreamBackport=BACKPORT, shippingFiles=products, debugFiles=debug,
        commands=commands, nativeVersionBinlog=fingerprint(args.output / 'native-version.binlog'),
        cmakeCache=fingerprint(args.output / 'CMakeCache.txt'), compileCommands=fingerprint(args.output / 'compile_commands.json'),
        compiledVersionSource=dict(path='generated/coreclr/version.c', **fingerprint(compiled_version)),
        compiledVersionHeader=dict(path='generated/compiled-runtime_version.h', **fingerprint(compiled_header)),
        productVersionMetadataQualified=True,
        generatedSourceFileCount=sum(path.is_file() for path in generated.rglob('*')), readyToRunDisabled=False,
        tracingDisabled=False, optimizationDisabled=False, consumerRuntimeTestsProvedByNativeBuild=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', architecture=args.arch, shippingFiles=products, qualificationAllowed=False)))


if __name__ == '__main__': main()
