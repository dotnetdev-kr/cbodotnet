#!/usr/bin/env python3
"""Retain exact Core3 sources and run bounded, unpublished native musl probes.

This is an investigation tool, not an SDK producer or release admission tool.
The native command runs inside an SDK-free Alpine container supplied by the
caller. It does not install packages, alter loaders, acquire binaries or publish.
"""
import argparse
import concurrent.futures
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / 'profiles/experimental/core3-musl.json'
REVIEW_PATHS = {
    'source-build': ('global.json', 'eng/Version.Details.xml', 'repos/corefx.common.props',
                     'repos/core-setup.common.props', 'repos/aspnetcore.proj'),
    'coreclr': ('eng/common/cross/toolchain.cmake', 'src/pal/src/thread/context.cpp',
                'src/pal/src/exception/seh-unwind.cpp', 'src/corefx/System.Globalization.Native/pal_icushim.c'),
    'corefx': ('eng/common/cross/toolchain.cmake',
               'src/Native/Unix/System.Security.Cryptography.Native/opensslshim.c',
               'src/Native/Unix/System.Security.Cryptography.Native/opensslshim.h'),
    'core-setup': ('src/corehost/build.sh', 'eng/Build.props'),
    'aspnetcore': ('global.json', 'Directory.Build.props', 'eng/Dependencies.props'),
    'sdk': ('global.json',),
    'core-sdk': ('global.json', 'src/redist/targets/GenerateLayout.targets'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(data)
            size += len(data)
    return dict(bytes=size, sha256=digest.hexdigest())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def ordinary(path, create=False):
    path = path.absolute()
    require(path != Path(path.anchor) and '..' not in path.parts
            and not any(p.is_symlink() for p in (path, *path.parents)), 'An ordinary absolute path is required')
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def profile():
    record = json.loads(PROFILE.read_text(encoding='utf-8'))
    require(record['kind'] == 'core3-musl-source-investigation'
            and record['qualification'] is False and record['releaseAdmission'] is False,
            'An explicitly unqualified investigation profile is required')
    require(len(record['sourceInputs']) == 14, 'Both complete selected component sets are required')
    return record


def archive_path(inputs, pin):
    path = ordinary(inputs / (pin['name'] + '.tar.gz'))
    require(path.is_file() and fingerprint(path) == {k: pin[k] for k in ('bytes', 'sha256')},
            'Source archive identity differs: ' + pin['name'])
    return path


def source_members(stream):
    members = stream.getmembers()
    roots = {PurePosixPath(m.name).parts[0] for m in members}
    require(len(roots) == 1, 'One upstream archive root required')
    for member in members:
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and '..' not in path.parts and '\\' not in member.name,
                'Unsafe source archive path')
    return {m.name.split('/', 1)[-1]: m for m in members if m.isfile()}


def source_record(inputs, pin):
    path = archive_path(inputs, pin)
    notices = []
    with tarfile.open(path, mode='r|gz') as stream:
        for member in stream:
            if not member.isfile():
                continue
            name = member.name.split('/', 1)[-1]
            if any(word in PurePosixPath(name).name.lower() for word in ('license', 'notice', 'copying', 'copyright')):
                raw = stream.extractfile(member).read()
                notices.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    require(notices, 'The complete source archive must retain its licenses/notices')
    return dict(**pin, archive=str(path), licenseAndNoticeFiles=notices)


def acquire(args):
    selected = profile()
    pins = [*selected['sourceInputs'], selected['portDonor']]
    inputs = ordinary(args.inputs_dir, create=True)

    def fetch(pin):
        source = 'repository' in pin
        destination = inputs / (pin['name'] + '.tar.gz' if source else pin['name'])
        if not destination.exists():
            url = ('https://codeload.github.com/' + pin['repository'] + '/tar.gz/' + pin['commit']
                   if source else pin['url'])
            # Incomplete network responses are never installed as accepted inputs.
            with tempfile.NamedTemporaryFile(dir=inputs, delete=False) as output:
                temporary = Path(output.name)
                try:
                    with urllib.request.urlopen(url, timeout=90) as response:
                        shutil.copyfileobj(response, output)
                    output.close()
                    require(fingerprint(temporary) == {k: pin[k] for k in ('bytes', 'sha256')},
                            'Downloaded source archive hash differs: ' + pin['name'])
                    temporary.rename(destination)
                finally:
                    temporary.unlink(missing_ok=True)
        if source:
            return source_record(inputs, pin)
        require(fingerprint(destination) == {k: pin[k] for k in ('bytes', 'sha256')}, 'Imported bootstrap archive differs')
        require(hashlib.sha512(destination.read_bytes()).hexdigest() == pin['sha512'], 'Imported bootstrap SHA512 differs')
        return dict(**pin, archive=str(destination), kind='imported-upstream-bootstrap-input')

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        sources = list(pool.map(fetch, pins))
    write(inputs / 'source-inputs.json', dict(schemaVersion=1, qualification=False, sources=sources,
          retention='Complete original source archives including all license/notice files; no selected-file substitute.'))
    if args.bootstrap:
        imported = [fetch(pin) for pin in selected['bootstrapProbeInputs']]
        write(inputs / 'bootstrap-imports.json', dict(qualification=False, inputs=imported,
              retention='Complete original vendor archives including all licenses/notices; not source-built inputs.'))
    if args.bootstrap_core30:
        imported = [fetch(pin) for pin in selected['bootstrapCore30Inputs']]
        write(inputs / 'core30-bootstrap-imports.json', dict(qualification=False, inputs=imported,
              retention='Complete original NuGet/vendor archives including all licenses/notices; not source-built inputs.'))
    print(json.dumps(dict(status='source-inputs-retained', archives=len(sources), qualification=False)))


def review(args):
    inputs = ordinary(args.inputs_dir)
    out = ordinary(args.output_dir, create=True)
    records = []
    for pin in profile()['sourceInputs']:
        component = pin['name'][:-2]
        with tarfile.open(archive_path(inputs, pin), mode='r|gz') as stream:
            for member in stream:
                path = member.name.split('/', 1)[-1]
                if not member.isfile() or path not in REVIEW_PATHS[component]:
                    continue
                raw = stream.extractfile(member).read()
                lines = raw.decode('utf-8-sig').splitlines()
                matches = [dict(line=i, text=line) for i, line in enumerate(lines, 1) if re.search(
                    r'linux-musl|alpine|REQUIRED_FUNCTION|MAKELIB|ICU.*VERSION|VERSION.*ICU|dotnet.*[0-9]|'
                    r'Arcade.Sdk|OverrideTargetRid|RuntimeOS|aarch64|arm64', line, re.I)]
                records.append(dict(source=pin['name'], repository=pin['repository'], commit=pin['commit'],
                                    path=path, fileSha256=hashlib.sha256(raw).hexdigest(), matches=matches))
    write(out / 'source-review.json', dict(schemaVersion=1, qualification=False, files=records))
    write(out / 'used-source-inputs.json', dict(schemaVersion=1,
          sources=[source_record(inputs, pin) for pin in profile()['sourceInputs']]))
    print(json.dumps(dict(status='source-review-recorded', files=len(records), qualification=False)))


def run(out, name, command, timeout):
    log = out / (name + '.log')
    started = time.monotonic()
    with log.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(command) + '\n')
        stream.flush()
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            code = 124
    return dict(name=name, command=command, exitCode=code, seconds=round(time.monotonic() - started, 2),
                log=log.name, **fingerprint(log))


def crypto_driver(source, driver):
    driver.mkdir()
    shutil.copytree(source / 'src/Native/Unix/Common', driver / 'Common')
    (driver / 'version.c').write_text('/* Empty version metadata for an isolated diagnostic target, not a product. */\n')
    contents = '''cmake_minimum_required(VERSION 3.5)
project(Core3Crypto C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-fvisibility=hidden)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE")
set(VERSION_FILE_PATH "@DRIVER@/version.c")
include_directories("@SOURCE@/src/Native/Unix/Common" "${CMAKE_BINARY_DIR}/Common")
include("@SOURCE@/src/Native/Unix/configure.cmake")
function(install_library_and_symbols name)
endfunction()
add_subdirectory("@SOURCE@/src/Native/Unix/System.Security.Cryptography.Native" crypto)
'''.replace('@DRIVER@', driver.as_posix()).replace('@SOURCE@', source.as_posix())
    (driver / 'CMakeLists.txt').write_text(contents)


def apply_candidate(out, selected, component, source, timeout):
    pin = next(row for row in selected['candidatePatches'] if row['component'] == component)
    patch = ordinary(ROOT / pin['path'])
    require(fingerprint(patch)['sha256'] == pin['sha256'], 'Candidate source patch differs')
    targets = [line[len('--- a/'):] for line in patch.read_text().splitlines() if line.startswith('--- a/')]
    require(targets and all(not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                            for path in targets), 'Candidate patch targets must stay within the original source export')
    before = {path: fingerprint(source / path) for path in targets}
    result = run(out, source.parent.name + '-candidate-patch', ['patch', '--batch', '--forward', '--fuzz=0',
                 '-p1', '--directory', str(source), '--input', str(patch)], timeout)
    require(result['exitCode'] == 0, 'Candidate patch did not apply exactly')
    write(out / (source.parent.name + '-patch-receipt.json'), dict(patch=pin,
          originalFiles=before, patchedFiles={path: fingerprint(source / path) for path in targets}, command=result))
    return result


def crypto_smoke(path):
    library = ctypes.CDLL(str(path))
    random = library.CryptoNative_GetRandomBytes
    random.argtypes, random.restype = [ctypes.c_void_p, ctypes.c_int], ctypes.c_int
    output = (ctypes.c_ubyte * 32)()
    status = random(output, len(output))
    crypto = ctypes.CDLL('libcrypto.so.3')
    crypto.X509_STORE_CTX_new.restype = ctypes.c_void_p
    crypto.X509_STORE_CTX_set_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
    crypto.X509_STORE_CTX_free.argtypes = [ctypes.c_void_p]
    context = crypto.X509_STORE_CTX_new()
    require(context, 'Could not construct native X509 verification context')
    try:
        crypto.X509_STORE_CTX_set_error(context, 79)
        library.CryptoNative_X509StoreCtxGetError.argtypes = [ctypes.c_void_p]
        library.CryptoNative_X509VerifyCertErrorString.argtypes = [ctypes.c_int]
        library.CryptoNative_X509VerifyCertErrorString.restype = ctypes.c_char_p
        mapped = library.CryptoNative_X509StoreCtxGetError(context)
        description = library.CryptoNative_X509VerifyCertErrorString(24).decode()
        require(status == 1 and any(output) and mapped == 24 and 'invalid CA' in description,
                'Native RNG or bidirectional X509 ABI smoke failed')
        return dict(loaded=True, randomStatus=status, randomNonzero=any(output),
                    nativeInvalidCa=79, managedInvalidCa=mapped, invalidCaDescription=description, **fingerprint(path))
    finally:
        crypto.X509_STORE_CTX_free(context)


def native(args):
    selected = profile()
    require(platform.system() == 'Linux' and platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[args.arch],
            'The requested CPU must match the native Linux kernel; emulation is not accepted')
    require(os.geteuid() != 0 and Path('/etc/alpine-release').read_text().strip() == selected['candidateAlpine'],
            'Run as a non-root user inside the exact candidate Alpine user space')
    require(sys.version_info >= (3, 12), 'Safe source extraction requires Python 3.12 or newer')
    require(not shutil.which('dotnet'), 'The diagnostic container must be SDK-free')
    installed = subprocess.check_output(['apk', 'info', '-v'], text=True).splitlines()
    require(not any(re.match(r'(gcompat|libc6-compat)-', line) for line in installed), 'Compatibility libc packages are forbidden')
    for name, version in selected['probeDependencies'].items():
        require(name + '-' + version in installed, 'Missing exact native probe package: ' + name)
    inputs = ordinary(args.inputs_dir)
    out = ordinary(args.output_dir, create=True)
    require(not any(out.iterdir()), 'A new empty evidence directory is required')
    write(out / 'invocation.json', dict(schemaVersion=1, recordedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(),
          qualification=False, releaseAdmission=False, architecture=args.arch, profile=fingerprint(PROFILE),
          helper=fingerprint(Path(__file__)), installedPackages=installed, sourceRetentionRoot=str(inputs),
          candidatePort=args.candidate_port,
          scope='Isolated original native PAL/crypto targets only. Generated CMake driver/version metadata are diagnostic scaffolding.'))
    records = [run(out, 'host', ['sh', '-c', 'uname -a; cat /etc/alpine-release; clang --version; cmake --version; '
        'cat /proc/self/status; cat /proc/self/attr/current'], args.timeout)]
    generated = out / 'generated'
    generated.mkdir()
    architecture = {'x64': 'x64', 'aarch64': 'arm64'}[args.arch]
    # Ephemeral ordinary Linux filesystem; source archives remain immutable and retained.
    with tempfile.TemporaryDirectory(prefix='cbodotnet-core3-musl-') as temporary:
        workspace = Path(temporary)
        for suffix in ('31', '30'):
            for component in ('corefx', 'coreclr'):
                name = component + suffix
                pin = next(row for row in selected['sourceInputs'] if row['name'] == name)
                destination = workspace / name
                destination.mkdir()
                with tarfile.open(archive_path(inputs, pin)) as stream:
                    source_members(stream)
                    stream.extractall(destination, filter='data')
                source = next(destination.iterdir())
                if args.candidate_port:
                    records.append(apply_candidate(out, selected, component, source, args.timeout))
                build = workspace / ('build-' + name)
                build.mkdir()
                base = ['cmake', '-B', str(build / 'obj'), '-DCMAKE_BUILD_TYPE=Release',
                        '-DCMAKE_C_COMPILER=clang', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5']
                if component == 'corefx':
                    header = (source / 'src/Native/Unix/System.Security.Cryptography.Native/opensslshim.h').read_text()
                    block = header.split('#define FOR_ALL_OPENSSL_FUNCTIONS', 1)[1].split('// Declare pointers', 1)[0]
                    pairs = re.findall(r'(?:NEW_)?REQUIRED_FUNCTION\((\w+)\)|RENAMED_FUNCTION\((\w+),', block)
                    symbols = sorted({first or second for first, second in pairs})
                    library = ctypes.CDLL('libssl.so.3')
                    write(out / ('openssl-symbols' + suffix + '.json'), dict(source=name, checked=len(symbols),
                          missingRequiredSymbols=[symbol for symbol in symbols if not hasattr(library, symbol)],
                          scope='Unmodified shim requirements compared with actual Alpine OpenSSL3 exports; no loader override.'))
                    driver = build / 'driver'
                    crypto_driver(source, driver)
                    retained = generated / name
                    retained.mkdir()
                    for filename in ('CMakeLists.txt', 'version.c'):
                        shutil.copyfile(driver / filename, retained / filename)
                    command = base + ['-S', str(driver), '-DFEATURE_DISTRO_AGNOSTIC_SSL=' +
                                      ('OFF' if args.candidate_port else 'ON')]
                    target = 'System.Security.Cryptography.Native.OpenSsl'
                else:
                    command = base + ['-S', str(source / 'src/pal'), '-DCMAKE_CXX_COMPILER=clang++',
                        '-DCMAKE_PROJECT_INCLUDE=' + str(source / 'functions.cmake'),
                        '-DCLR_DIR=' + str(source), '-DCLR_CMAKE_TARGET_ARCH=' + architecture,
                        '-DCLR_CMAKE_HOST_ARCH=' + architecture, '-DCLR_CMAKE_TARGET_OS=Linux',
                        '-DCLR_CMAKE_PLATFORM_UNIX=1', '-DCLR_CMAKE_PLATFORM_LINUX=1',
                        '-DCLR_CMAKE_WARNINGS_ARE_ERRORS=OFF', '-DCLR_CMAKE_BUILD_TESTS=OFF',
                        '-DCLR_CMAKE_USE_SYSTEM_LIBUNWIND=ON', '-DFEATURE_EVENT_TRACE=0']
                    target = 'coreclrpal'
                record = run(out, name + '-configure', command, args.timeout)
                records.append(record)
                if record['exitCode'] == 0:
                    compiled = run(out, name + '-build', ['cmake', '--build', str(build / 'obj'),
                                   '--target', target, '--parallel', '1'], args.timeout)
                    records.append(compiled)
                    if args.candidate_port and compiled['exitCode'] == 0:
                        artifacts = out / 'candidate-native'
                        artifacts.mkdir(exist_ok=True)
                        if component == 'corefx':
                            library = build / 'obj/crypto/System.Security.Cryptography.Native.OpenSsl.so'
                            copied = artifacts / (name + '-OpenSsl.so')
                            shutil.copyfile(library, copied)
                            write(out / (name + '-native-smoke.json'), crypto_smoke(copied))
                        else:
                            libraries = list((build / 'obj').rglob('libcoreclrpal.a'))
                            require(len(libraries) == 1, 'One actual compiled PAL archive required')
                            shutil.copyfile(libraries[0], artifacts / (name + '-PAL.a'))
    write(out / 'used-source-inputs.json', dict(schemaVersion=1,
          sources=[source_record(inputs, pin) for pin in selected['sourceInputs']
                   if pin['name'] in ('corefx31', 'corefx30', 'coreclr31', 'coreclr30')]))
    if args.candidate_port:
        write(out / 'port-donor-source.json', source_record(inputs, selected['portDonor']))
    write(out / 'results.json', dict(schemaVersion=1, diagnosticOnly=True, qualification=False,
          releaseAdmission=False, architecture=args.arch, records=records,
          candidatePort=args.candidate_port, allRequestedTargetsPassed=all(row['exitCode'] == 0 for row in records),
          note='Probe completion is not build success. Inspect every target exit code. No SDK archive is produced.'))
    print(json.dumps(dict(status='probe-recorded', architecture=args.arch,
          targetExitCodes={row['name']: row['exitCode'] for row in records}, qualification=False)))


def trace(args):
    selected = profile()
    require(platform.system() == 'Linux' and platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[args.arch]
            and os.geteuid() != 0 and Path('/etc/alpine-release').read_text().strip() == selected['candidateAlpine']
            and not shutil.which('dotnet'), 'A matching native, non-root, SDK-free Alpine container is required')
    installed = subprocess.check_output(['apk', 'info', '-v'], text=True).splitlines()
    require(not any(re.match(r'(gcompat|libc6-compat)-', row) for row in installed), 'Compatibility libc is forbidden')
    for name, version in selected['traceDependencies'].items():
        require(name + '-' + version in installed, 'Exact stock tracing development package required')
    inputs, out = ordinary(args.inputs_dir), ordinary(args.output_dir, create=True)
    require(not any(out.iterdir()), 'A new empty evidence directory is required')
    records, artifacts = [], out / 'candidate-native'
    artifacts.mkdir()
    write(out / 'invocation.json', dict(qualification=False, architecture=args.arch, profile=fingerprint(PROFILE),
          helper=fingerprint(Path(__file__)), installedPackages=installed,
          scope='Original event manifest/generator and generated trace provider only; no runtime source substitution.'))
    with tempfile.TemporaryDirectory(prefix='cbodotnet-core3-trace-') as temporary:
        workspace = Path(temporary)
        for suffix in ('31', '30'):
            pin = next(row for row in selected['sourceInputs'] if row['name'] == 'coreclr' + suffix)
            destination = workspace / pin['name']
            destination.mkdir()
            with tarfile.open(archive_path(inputs, pin)) as stream:
                source_members(stream)
                stream.extractall(destination, filter='data')
            source = next(destination.iterdir())
            generated = out / ('generated-' + suffix)
            generated.mkdir()
            generator, manifest = source / 'src/scripts/genLttngProvider.py', source / 'src/vm/ClrEtwAll.man'
            require(generator.is_file() and manifest.is_file(), 'Exact original event generator/manifest required')
            record = run(out, 'coreclr' + suffix + '-generate-trace', [sys.executable, str(generator), '--man',
                         str(manifest), '--intermediate', str(generated)], args.timeout)
            records.append(record)
            if record['exitCode']:
                continue
            sources = sorted((generated / 'lttng').glob('traceptprov*.cpp'))
            require(sources, 'The original generator did not emit trace provider source')
            library = artifacts / ('coreclr' + suffix + '-traceptprovider.so')
            architecture = 'ARM64' if args.arch == 'aarch64' else 'AMD64'
            command = ['clang++', '-shared', '-fPIC', '-O2', '-DPAL_STDCPP_COMPAT=1', '-DPLATFORM_UNIX=1',
                '-DTARGET_' + architecture + '=1', '-DHOST_' + architecture + '=1', '-DTARGET_64BIT=1', '-DHOST_64BIT=1']
            command += ['-I' + str(source / 'src' / path) for path in ('pal/inc', 'pal/inc/rt', 'inc')]
            command += ['-I' + str(generated / 'lttng'), *map(str, sources), '-llttng-ust', '-ldl',
                        '-Wl,-soname,libcoreclrtraceptprovider.so', '-o', str(library)]
            compiled = run(out, 'coreclr' + suffix + '-build-trace', command, args.timeout)
            records.append(compiled)
            if compiled['exitCode'] == 0:
                ctypes.CDLL(str(library))
                write(out / ('coreclr' + suffix + '-trace-smoke.json'), dict(loaded=True, **fingerprint(library),
                      originalManifest=fingerprint(manifest), originalGenerator=fingerprint(generator)))
    write(out / 'used-source-inputs.json', dict(sources=[source_record(inputs, pin) for pin in selected['sourceInputs']
          if pin['name'] in ('coreclr31', 'coreclr30')]))
    write(out / 'results.json', dict(schemaVersion=1, qualification=False, releaseAdmission=False, architecture=args.arch,
          records=records, allRequestedTargetsPassed=all(row['exitCode'] == 0 for row in records)))
    print(json.dumps(dict(status='trace-source-probe-recorded', qualification=False,
                         targetExitCodes={row['name']: row['exitCode'] for row in records})))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('acquire', 'review', 'native', 'trace'):
        child = commands.add_parser(action)
        child.add_argument('--inputs-dir', type=Path, required=True)
        if action == 'acquire':
            child.add_argument('--bootstrap', action='store_true', help='Also retain the exact imported private-bootstrap inputs.')
            child.add_argument('--bootstrap-core30', action='store_true', help='Also retain the exact Core3.0 NuGet/managed bootstrap inputs.')
        if action != 'acquire':
            child.add_argument('--output-dir', type=Path, required=True)
        if action in ('native', 'trace'):
            child.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
            child.add_argument('--timeout', type=int, choices=range(10, 601), default=180)
        if action == 'native':
            child.add_argument('--candidate-port', action='store_true',
                               help='Apply the two pinned experimental source patches; direct-link Alpine OpenSSL3.')
    args = parser.parse_args()
    {'acquire': acquire, 'review': review, 'native': native, 'trace': trace}[args.action](args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
