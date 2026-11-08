#!/usr/bin/env python3
"""Reproduce the bounded native CoreCLR3.1 source/consumer experiment."""
import argparse
import ctypes
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
PROFILE = json.loads((ROOT / 'profiles/experimental/core3-musl-native.json').read_text())
BOOT = json.loads((ROOT / 'profiles/experimental/core3-musl-source.json').read_text())
MEMBERS = {'libcoreclr.so': 'src/dlls/mscoree/coreclr/libcoreclr.so',
    'libclrjit.so': 'src/jit/standalone/libclrjit.so',
    'libmscordaccore.so': 'src/dlls/mscordac/libmscordaccore.so',
    'libmscordbi.so': 'src/dlls/mscordbi/libmscordbi.so',
    'libcoreclrtraceptprovider.so': 'src/pal/src/eventprovider/lttngprovider/libcoreclrtraceptprovider.so',
    'crossgen': 'src/tools/crossgen/crossgen'}
COLD_PROGRAM = '''using System;using System.Collections.Generic;using System.Globalization;
using System.Numerics;using System.Reflection;using System.Runtime.InteropServices;
using System.Threading;using System.Threading.Tasks;
class Cold {static double Floating(double v){return v*2.0+0.5;} static int Main(){
var d=new Dictionary<int,string>();for(int i=1;i<=100;i++)d.Add(i,i.ToString(CultureInfo.InvariantCulture));
long total=0;for(int i=1;i<=100;i++)total+=long.Parse(d[i],CultureInfo.InvariantCulture);
if(total!=5050||Floating(10.0)!=20.5)return 2;
if((new Vector<int>(3)+new Vector<int>(4))[0]!=7)return 3;
long parallel=0;Parallel.For(0,1000,i=>Interlocked.Add(ref parallel,i));if(parallel!=499500)return 4;
var bytes=new List<byte[]>();for(int i=0;i<30000;i++){bytes.Add(new byte[1024]);if(bytes.Count>150)bytes.Clear();}
GC.Collect();GC.WaitForPendingFinalizers();var m=typeof(Cold).GetMethod("Floating",BindingFlags.Static|BindingFlags.NonPublic);
if((double)m.Invoke(null,new object[]{2.0})!=4.5)return 5;
if(!"İstanbul".ToLower(new CultureInfo("tr-TR")).StartsWith("i"))return 6;
Console.WriteLine("NATIVE_CLR31_COLD_PASS sum="+total+" parallel="+parallel+" arch="+RuntimeInformation.ProcessArchitecture);return 0;}}'''
GC_PROGRAM = '''using System;using System.Threading;class Events {static void Main(){
Console.WriteLine("READY");for(int i=0;i<80;i++){var a=new byte[100000];GC.Collect();Thread.Sleep(100);}Console.WriteLine("DONE");}}'''


def require(value, message):
    CACHE.require(value, 'native experiment: ' + message)


def fp(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def pinned(path, pin):
    actual = fp(path)
    require(all(actual[key] == pin[key] for key in ('bytes', 'sha256', 'sha512') if key in pin),
            'pinned input differs: ' + str(path))
    return actual


def save(path, value):
    CACHE.write_new(path, (json.dumps(value, indent=2) + '\n').encode())


def unpack(path, target):
    target.mkdir()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and
                    (member.isfile() or member.isdir() or member.issym()), 'unsafe source/runtime archive entry')
        archive.extractall(target, filter='data')


def capture_version_sdk(cache, output):
    """Account for the original MSBuild SDK resolver input outside assets roots."""
    pin = PROFILE['privateVersionSdk']
    name = pin['id'] + '.' + pin['version'] + '.nupkg'
    path = cache / pin['id'] / pin['version'] / name
    actual = pinned(path, pin)
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith('.nuspec')]
        require(len(names) == 1, 'one original SDK package identity required')
        raw = archive.read(names[0])
    metadata = ET.fromstring(raw).find('{*}metadata')
    repository = metadata.find('{*}repository')
    require(metadata.findtext('{*}id', '').lower() == pin['id'] and
        metadata.findtext('{*}version') == pin['version'] and repository is not None and
        repository.get('url') == pin['publisherRepository'] and repository.get('commit') == pin['publisherCommit'] and
        metadata.findtext('{*}license') == pin['license'], 'original SDK publisher source/license differs')
    CACHE.write_new(output / 'private-version-sdk' / name, path.read_bytes())
    record = dict(pin, **actual, retained='private-version-sdk/' + name,
        nuspecSha256=hashlib.sha256(raw).hexdigest(),
        projectAssetsBindingClaimed=False, signatureTrustClaimed=False, correspondingSourceAudit=False)
    save(output / 'private-version-sdk-input.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['source', 'consumer', 'lttng'], required=True)
    for name in ['source-archive', 'bootstrap-sdk', 'targeting-sdk', 'native-evidence-dir',
                 'runtime-archive', 'crypto-native', 'work-dir', 'output-dir']:
        parser.add_argument('--' + name, type=Path, required=name in ['work-dir', 'output-dir'])
    parser.add_argument('--official-build-id')
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == PROFILE['architecture'] and os.getuid() != 0
            and Path('/etc/alpine-release').read_text().strip() == PROFILE['alpine'] and not shutil.which('dotnet'),
            'native non-root SDK-free Alpine3.24.4/aarch64 required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, CACHE.ordinary(value))
    work, output = args.work_dir, args.output_dir
    require(not work.exists() and not output.exists() and not output.is_relative_to(work),
            'fresh separate work/evidence directories required')
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    env = dict(os.environ, HOME=str(work / 'home'), DOTNET_CLI_HOME=str(work / 'home'),
        DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_PROCESSOR_COUNT='2',
        DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='false', COMPlus_ReadyToRun='1')
    records = []

    def run(name, command, cwd=None, timeout=900):
        command = list(map(str, command))
        log = output / (name + '.log')
        start = time.monotonic()
        with log.open('x') as stream:
            stream.write(json.dumps(command) + '\n')
            stream.flush()
            child = subprocess.Popen(command, cwd=cwd or work, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, 15)
                child.wait(timeout=10)
                code = 124
        row = dict(name=name, command=command, exitCode=code, seconds=round(time.monotonic() - start, 2),
                   log=log.name, **fp(log))
        records.append(row)
        (output / 'command-progress.json').write_text(json.dumps(records, indent=2) + '\n')
        require(code == 0, 'command failed: ' + name)
        return log.read_text()

    if args.mode == 'source':
        require(all([args.source_archive, args.bootstrap_sdk, args.targeting_sdk, args.official_build_id])
                and re.fullmatch(r'20[0-9]{6}\.[0-9]{1,2}', args.official_build_id),
                'pinned source/private SDK/targeting inputs and dated community attempt required')
        source_input = pinned(args.source_archive, PROFILE['source'])
        sdk_input = pinned(args.bootstrap_sdk, PROFILE['privateBootstrap'])
        targeting_input = pinned(args.targeting_sdk, BOOT['bootstrapSdk'])
        unpack(args.source_archive, work / 'source')
        source = work / 'source' / ('coreclr-' + PROFILE['source']['commit'])
        require(source.is_dir(), 'source archive root differs')
        global_before = fp(source / 'global.json')
        for index, patch in enumerate(PROFILE['patches']):
            path = ROOT / patch['path']
            pinned(path, patch)
            run('patch-' + str(index) + '-check', ['git', 'apply', '--check', path], source)
            run('patch-' + str(index) + '-apply', ['git', 'apply', path], source)
            CACHE.write_new(output / 'patches' / path.name, path.read_bytes())
        unpack(args.bootstrap_sdk, work / 'bootstrap')
        sdk = work / 'bootstrap'
        env.update(DOTNET_ROOT=str(sdk), NUGET_PACKAGES=str(work / 'version-packages'))
        obj = source / 'bin/obj/Linux.arm64.Release'
        obj.mkdir(parents=True)
        product = source / 'bin/Product/Linux.arm64.Release'
        product.mkdir(parents=True)
        feeds = ['https://api.nuget.org/v3/index.json', *['https://pkgs.dev.azure.com/dnceng/public/_packaging/'
            + name + '/nuget/v3/index.json' for name in ['dotnet-public', 'dotnet-eng', 'dotnet-tools', 'dotnet3.1']]]
        run('original-native-version', [sdk / 'dotnet', 'msbuild', source / 'eng/empty.csproj', '/restore',
            '/t:GenerateNativeVersionFile', '/p:ArcadeBuild=true', '/p:NativeVersionFile=' + str(obj / 'version.c'),
            '/p:__BuildArch=arm64', '/p:__BuildType=Release', '/p:__BuildOS=Linux',
            '/p:Version=' + PROFILE['runtimeVersion'], '/p:OfficialBuildId=' + args.official_build_id,
            '/p:RepositoryCommit=' + PROFILE['source']['commit'], '/p:SourceRevisionId=' + PROFILE['source']['commit'],
            '/p:UseSharedCompilation=false', '/p:RestoreSources=' + '%3B'.join(feeds),
            '/bl:' + str(output / 'native-version.binlog')], source)
        require(PROFILE['source']['commit'] in (obj / 'version.c').read_text(), 'actual source native version absent')
        version_sdk = capture_version_sdk(work / 'version-packages', output)
        env.update(__CMakeBinDir=str(product), PYTHON='python3', CC=PROFILE['build']['compiler'],
                   CXX=PROFILE['build']['cxxCompiler'], CROSSCOMPILE='')
        run('original-release-configure', ['bash', source / 'src/pal/tools/gen-buildsys-clang.sh', source,
            '20', '1', 'arm64', source / 'src/pal/tools', 'Release', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCLR_CMAKE_TARGET_OS=Linux',
            '-DCLR_CMAKE_TARGET_ARCH=arm64', '-DCLR_CMAKE_HOST_ARCH=arm64'], obj)
        run('original-release-six-targets', ['cmake', '--build', obj, '--target', *PROFILE['build']['targets'],
            '--parallel', '2', '--verbose'], source, timeout=3600)
        artifacts = []
        for name, relative in MEMBERS.items():
            path = obj / relative
            raw = path.read_bytes()
            require(raw[:6] == b'\x7fELF\x02\x01' and int.from_bytes(raw[18:20], 'little') == 183,
                    'native output is not AArch64 ELF64')
            CACHE.write_new(output / 'native' / name, raw)
            run('readelf-' + name, ['readelf', '-h', '-d', '-n', path])
            artifacts.append(dict(path='native/' + name, name=name, **fp(path)))
        for name in ['version.c', 'CMakeCache.txt', 'compile_commands.json']:
            CACHE.write_new(output / name, (obj / name).read_bytes())
        compile_commands = (obj / 'compile_commands.json').read_text()
        require(all(value in compile_commands for value in ['-O3', '-Werror', '-DFEATURE_READYTORUN',
            '-DFEATURE_PERFTRACING', '-DFEATURE_PROFAPI_ATTACH_DETACH']), 'original Release feature/compiler graph differs')
        generated = []
        with tarfile.open(output / 'generated-source.tar.gz', 'w:gz') as archive:
            for path in sorted(obj.rglob('*')):
                if path.is_file() and not path.is_symlink() and path.suffix.lower() in {
                    '.c', '.cpp', '.h', '.hpp', '.inc', '.inl', '.s', '.asm', '.def', '.map', '.cmake'}:
                    relative = path.relative_to(obj).as_posix()
                    archive.add(path, arcname=relative)
                    generated.append(dict(path=relative, **fp(path)))
        save(output / 'generated-source-manifest.json', generated)
        refs = work / 'test-refs'
        refs.mkdir()
        with tarfile.open(args.targeting_sdk, mode='r|gz') as archive:
            for member in archive:
                name = str(PurePosixPath(member.name))
                if member.isfile() and name.startswith('packs/Microsoft.NETCore.App.Ref/') and '/ref/netcoreapp3.1/' in name and name.endswith('.dll'):
                    CACHE.write_new(refs / PurePosixPath(name).name, archive.extractfile(member).read())
        require((refs / 'System.Runtime.dll').is_file() and len(list(refs.glob('*.dll'))) > 100, 'original targeting references absent')
        for name, program in [('Cold', COLD_PROGRAM), ('Events', GC_PROGRAM)]:
            path = output / 'fixtures' / (name + '.cs')
            CACHE.write_new(path, program.encode())
            rsp = work / (name + '.rsp')
            rsp.write_text('\n'.join(['/nostdlib+', '/target:exe', '/out:' + str(path.with_suffix('.dll')),
                *['/r:' + str(ref) for ref in sorted(refs.glob('*.dll'))], str(path)]) + '\n')
            run('compile-own-fixture-' + name, [sdk / 'dotnet', sdk / 'sdk/8.0.131/Roslyn/bincore/csc.dll', '/noconfig', '@' + str(rsp)])
            save(path.with_suffix('.runtimeconfig.json'), dict(runtimeOptions=dict(tfm='netcoreapp3.1',
                framework=dict(name='Microsoft.NETCore.App', version=PROFILE['runtimeVersion']))))
        require(fp(source / 'global.json') == global_before, 'original global SDK/Arcade pins changed')
        closure = CACHE.snapshot(work, output)
        save(output / 'results.json', dict(mode='source', qualification=False, releaseAdmission=False,
            sourceSdkProduct=False, sourceCommit=PROFILE['source']['commit'], sourceArchive=source_input,
            privateBootstrap=sdk_input, testOnlyTargetingInput=targeting_input,
            privateVersionSdk=version_sdk,
            privateBootstrapProductUseClaimed=False, originalGlobalPins=global_before,
            officialBuildId=args.official_build_id, patches=PROFILE['patches'], native=artifacts,
            generatedSourceFiles=len(generated), fixtureCompilerScope='PrivateSDK8 test-only C# fixtures, not source SDK/compiler proof',
            normalReadyToRunEnabled=True, originalReleaseAndGlobalWarningsAsErrors=True,
            visibleGnuCxxVlaCompatibilityWarning=True, originalNativeVersionTarget=True,
            actualRestoreAssets=len(closure['assets']), actualRestorePackages=len(closure['packages']), records=records))
        return

    require(all([args.native_evidence_dir, args.runtime_archive, args.crypto_native]) and not shutil.which('clang'),
            'native source evidence, explicit diagnostic runtime/crypto inputs and compiler-free consumer required')
    evidence = args.native_evidence_dir
    report = json.loads((evidence / 'results.json').read_text())
    require(report['mode'] == 'source' and report['sourceCommit'] == PROFILE['source']['commit']
            and report['patches'] == PROFILE['patches'] and all(row['exitCode'] == 0 for row in report['records']),
            'successful matching native source experiment required')
    pinned(args.runtime_archive, BOOT['bootstrapRuntime'])
    pinned(args.crypto_native, BOOT['nativeCandidates']['crypto'])
    unpack(args.runtime_archive, work / 'runtime')
    runtime = work / 'runtime'
    native = runtime / 'shared/Microsoft.NETCore.App' / PROFILE['runtimeVersion']
    CACHE.write_new(work / 'crypto-input.json', json.dumps(fp(args.crypto_native)).encode())
    (native / 'System.Security.Cryptography.Native.OpenSsl.so').write_bytes(args.crypto_native.read_bytes())
    require({row['name'] for row in report['native']} == set(MEMBERS), 'exact six native outputs required')
    for row in report['native']:
        path = evidence / row['path']
        pinned(path, row)
        if row['name'] == 'crossgen':
            crossgen = work / 'crossgen'
            shutil.copyfile(path, crossgen)
            crossgen.chmod(0o755)
        else:
            (native / row['name']).write_bytes(path.read_bytes())
    env['DOTNET_ROOT'] = str(runtime)
    if args.mode == 'consumer':
        for path in sorted(runtime.rglob('*')):
            if path.is_file() and path.read_bytes()[:4] == b'\x7fELF':
                text = run('ldd-' + str(path.relative_to(runtime)).replace('/', '_'), ['ldd', path])
                require(not any(value in text for value in ['not found', 'Error loading', 'Error relocating', 'libc.so.6', 'ld-linux-aarch64.so.1']),
                        'native ELF load-time dependency closure failed')
        run('crossgen-ldd', ['ldd', crossgen])
        for name in ['Cold.dll', 'Cold.runtimeconfig.json']:
            shutil.copyfile(evidence / 'fixtures' / name, work / name)
        require('NATIVE_CLR31_COLD_PASS' in run('cold-managed', [runtime / 'dotnet', work / 'Cold.dll']), 'cold fixture result absent')
        run('source-crossgen-r2r', [crossgen, '/ReadyToRun', '/p', native, '/JITPath', native / 'libclrjit.so',
            '/out', work / 'Cold.ni.dll', work / 'Cold.dll'])
        identity = PE.inspect((work / 'Cold.ni.dll').read_bytes())
        require(identity['managedNativeHeaderBytes'] > 0, 'actual R2R header absent')
        shutil.copyfile(work / 'Cold.ni.dll', output / 'Cold.ni.dll')
        shutil.copyfile(work / 'Cold.ni.dll', work / 'Cold.dll')
        require('NATIVE_CLR31_COLD_PASS' in run('r2r-managed', [runtime / 'dotnet', work / 'Cold.dll']), 'R2R fixture result absent')
        observed = dict(readyToRunIdentity=identity, readyToRunOutput=fp(work / 'Cold.ni.dll'))
    else:
        control = 'CBODOTNET_CORECLR31_NATIVE_LTTNG_POSITIVE_CONTROL'
        env.update(COMPlus_EnableEventLog='1', COMPlus_LTTng='1', LTTNG_UST_REGISTER_TIMEOUT='5000')
        Path(env['HOME']).mkdir(exist_ok=True)
        os.environ.update(HOME=env['HOME'], LTTNG_UST_REGISTER_TIMEOUT='5000')
        run('sessiond', ['lttng-sessiond', '--daemonize', '--no-kernel'])
        run('create', ['lttng', 'create', 'coreclr31-source', '--output=' + str(output / 'session')])
        run('enable', ['lttng', 'enable-event', '--userspace', '--all'])
        run('start', ['lttng', 'start'])
        with (output / 'managed.stdout.log').open('x') as stdout, (output / 'managed.stderr.log').open('x') as stderr:
            child = subprocess.Popen([str(runtime / 'dotnet'), str(evidence / 'fixtures/Events.dll')], cwd=work,
                env=env, stdout=stdout, stderr=stderr)
            try:
                library = ctypes.CDLL('liblttng-ust.so.1', mode=ctypes.RTLD_GLOBAL)
                emit = library.lttng_ust__tracef
                emit.argtypes, emit.restype = [ctypes.c_char_p], None
                time.sleep(2)
                emit(control.encode())
                time.sleep(1)
                listing = run('tracepoints', ['lttng', 'list', '--userspace'])
                code = child.wait(timeout=45)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
        run('stop', ['lttng', 'stop'])
        run('destroy', ['lttng', 'destroy', 'coreclr31-source'])
        lines = run('decoded', ['babeltrace2', output / 'session']).splitlines()
        observed = dict(dotnetEvents=sum('DotNETRuntime:' in line for line in lines),
            gcStartEvents=sum('DotNETRuntime:GCStart' in line for line in lines),
            gcEndEvents=sum('DotNETRuntime:GCEnd' in line for line in lines),
            nativeControlEvents=sum(control in line for line in lines),
            listedTracepoints=sum('DotNETRuntime' in line for line in listing.splitlines()))
        require(code == 0 and (output / 'managed.stdout.log').read_text().splitlines() == ['READY', 'DONE'] and
            observed['gcStartEvents'] >= 80 and observed['gcEndEvents'] >= 80 and observed['nativeControlEvents'] == 1,
            'actual managed GC events and independent native control required')
    save(output / 'results.json', dict(mode=args.mode, qualification=False, releaseAdmission=False,
        sourceSdkProduct=False, sourceCommit=PROFILE['source']['commit'], nativeSourceEvidence=fp(evidence / 'results.json'),
        native=report['native'], runtimeInput=fp(args.runtime_archive), cryptoInput=fp(args.crypto_native),
        scope='Explicit diagnostic native overlay onto original host/managed runtime; complete source SDK admission remains closed',
        uid=os.getuid(), normalReadyToRunEnabled=True, sdkOrCompilerPresent=False, observed=observed, records=records))


if __name__ == '__main__':
    main()
