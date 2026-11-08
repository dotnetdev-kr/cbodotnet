#!/usr/bin/env python3
"""Exercise SDK5 EH alignment and contended synchronization from a final archive.

Run on the native CPU in the SDK-free Alpine test image. The candidate SDK
compiles its own fixture offline; only its unchanged runtime executes it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import signal
import subprocess
import tarfile
import tempfile
import time

SDK = '5.0.214'
RUNTIME = '5.0.17'
FIXTURE_SHA256 = '2692214626b3ff20d5c477094911ff581f82b8f1c1727d6870e9dcd610e18572'
CASES = {
    'identity': 'RUNTIME 5.0.17',
    'metadata': 'PASS metadata EH=6 residues=0,1,2,3',
    'residue2': 'RESULT 7 COUNTER 9',
    'normal': 'RESULT 13',
    'return': 'RESULT 7 COUNTER 8',
    'throw': 'CAUGHT probe COUNTER 9',
    'catch': 'RESULT 17',
    'loop': 'RESULT 10 COUNTER 10',
    'lock': 'PASS lock value=20000 count=0',
    'spinlock': 'PASS spinlock value=20000 count=0',
    'dictionary-same': 'PASS dictionary-same value=0 count=64',
    'dictionary-distinct': 'PASS dictionary-distinct value=0 count=20000',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    hashes = {name: hashlib.new(name) for name in ['sha256', 'sha512']}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in hashes.values(): value.update(block)
    return dict(bytes=path.stat().st_size, **{key: value.hexdigest() for key, value in hashes.items()})


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def extract(archive_path, destination):
    with tarfile.open(archive_path, 'r:gz') as archive:
        names = set()
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and
                    (member.isfile() or member.isdir()), 'Only ordinary safe SDK members are accepted')
            name = path.as_posix()
            require(name not in names, 'Duplicate SDK member')
            names.add(name)
        archive.extractall(destination, filter='data')


def run(command, name, output, environment, cwd, timeout):
    start = time.monotonic()
    timed_out = False
    path = output / (name + '.log')
    with path.open('x', encoding='utf-8') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
    return dict(name=name, command=command, exitCode=code, timedOut=timed_out,
                elapsedSeconds=time.monotonic() - start, log=path.name, **fingerprint(path))


def check_case(name, observation, text):
    require(name in CASES and observation['exitCode'] == 0 and not observation['timedOut'],
            'Runtime semantic command failed: ' + name)
    require(CASES[name] in text.splitlines(), 'Runtime semantic assertion was not observed: ' + name)
    if name == 'metadata':
        require(sum(line.startswith('EH ') for line in text.splitlines()) == 6,
                'All six actual reflected EH clauses are required')



def validate_environment(environment):
    allowed = {'DOTNET_ROOT', 'DOTNET_CLI_HOME', 'DOTNET_MULTILEVEL_LOOKUP',
               'DOTNET_PROCESSOR_COUNT', 'DOTNET_CLI_TELEMETRY_OPTOUT',
               'DOTNET_SKIP_FIRST_TIME_EXPERIENCE', 'DOTNET_INSTALL_DIR', 'DOTNET_NOLOGO'}
    for key, value in environment.items():
        if key.lower().startswith(('complus_', 'dotnet_')):
            require(key in allowed or key in {'COMPlus_ReadyToRun', 'DOTNET_ReadyToRun'} and value == '1',
                    'Unexpected runtime or execution override in semantic test: ' + key)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and platform.system() == 'Linux' and
            platform.machine() == {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4',
            'Matching native non-root Alpine3.24.4 is required')
    require(subprocess.run(['sh', '-c', 'command -v dotnet || command -v clang || command -v cc || command -v gcc'],
                           stdout=subprocess.DEVNULL).returncode != 0,
            'The test image must contain no SDK or compiler')
    require(args.archive.is_file() and not args.archive.is_symlink() and not args.output.exists(),
            'An ordinary completed SDK archive and fresh evidence directory are required')
    validate_environment(os.environ)
    fixture = Path(__file__).with_name('musl-runtime-semantics5.cs')
    require(fingerprint(fixture)['sha256'] == FIXTURE_SHA256, 'Reviewed semantic fixture bytes changed')
    args.output.mkdir(parents=True)
    (args.output / fixture.name).write_bytes(fixture.read_bytes())
    identity = dict(schemaVersion=1, kind='legacy-sdk5-runtime-semantic-proof', sdkVersion=SDK,
                    runtimeVersion=RUNTIME, architecture=args.arch, nativeArchitecture=platform.machine(),
                    uid=os.getuid(), worker=fingerprint(Path(__file__)), archive=fingerprint(args.archive), fixture=fingerprint(fixture),
                    readyToRun=True, runtimeOverlaysAccepted=False, hostSdkUsed=False,
                    qualificationAllowed=False, sourceAdmissionAllowed=False)
    write(args.output / 'identity.json', identity)
    rows = []
    try:
        with tempfile.TemporaryDirectory(prefix='cbodotnet-sdk5-semantics-') as temporary:
            work = Path(temporary)
            sdk, app, home = work / 'sdk', work / 'app', work / 'home'
            sdk.mkdir(); app.mkdir(); home.mkdir()
            extract(args.archive, sdk)
            require((sdk / 'sdk' / SDK / 'MSBuild.dll').is_file() and
                    (sdk / 'shared/Microsoft.NETCore.App' / RUNTIME / 'libcoreclr.so').is_file(),
                    'The exact SDK5 and runtime5 archive layout is required')
            require(sorted(path.name for path in (sdk / 'sdk').iterdir() if path.is_dir()) == [SDK] and
                    sorted(path.name for path in (sdk / 'shared/Microsoft.NETCore.App').iterdir() if path.is_dir()) == [RUNTIME],
                    'Only the exact SDK5/runtime5 version directories are accepted')
            write(args.output / 'runtime-files.json', {name: fingerprint(sdk / 'shared/Microsoft.NETCore.App' / RUNTIME / name)
                  for name in ['libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so']})
            (app / 'Program.cs').write_bytes(fixture.read_bytes())
            (app / 'Semantics.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<OutputType>Exe</OutputType><TargetFramework>net5.0</TargetFramework>'
                '<UseSharedCompilation>false</UseSharedCompilation><EmitCompilerGeneratedFiles>true</EmitCompilerGeneratedFiles>'
                '</PropertyGroup></Project>')
            (app / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
            environment = dict(os.environ, HOME=str(home), DOTNET_CLI_HOME=str(home), DOTNET_ROOT=str(sdk),
                DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2', COMPlus_ReadyToRun='1',
                DOTNET_CLI_TELEMETRY_OPTOUT='1', MSBUILDDISABLENODEREUSE='1')
            validate_environment(environment)
            for name, command, timeout in [
                    ('sdk-info', [str(sdk / 'dotnet'), '--info'], 30),
                    ('build', [str(sdk / 'dotnet'), 'build', str(app / 'Semantics.csproj'), '-c', 'Release',
                               '--configfile', str(app / 'NuGet.Config'), '/nr:false', '/p:UseSharedCompilation=false'], 120)]:
                row = run(command, name, args.output, environment, app, timeout); rows.append(row)
                require(row['exitCode'] == 0 and not row['timedOut'], 'Candidate SDK5 command failed: ' + name)
            assembly = app / 'bin/Release/net5.0/Semantics.dll'
            (args.output / assembly.name).write_bytes(assembly.read_bytes())
            write(args.output / 'compiled-fixture.json', fingerprint(assembly))
            for name in CASES:
                row = run([str(sdk / 'dotnet'), str(assembly), name], name, args.output, environment, app, 30)
                rows.append(row)
                check_case(name, row, (args.output / row['log']).read_text())
        require(fingerprint(args.archive) == identity['archive'], 'Candidate archive changed during verification')
    except Exception as error:
        write(args.output / 'results.json', dict(identity, status='failed', commands=rows, error=str(error)))
        raise
    write(args.output / 'results.json', dict(identity, status='passed', commands=rows,
          allExceptionHandlingAlignments=True, finallyExecuted=True, contendedThreads=2,
          monitorIncrements=20000, spinLockIncrements=20000, sameKeyDictionaryCount=64, distinctKeyDictionaryCount=20000))
    print(json.dumps(dict(status='passed', commands=len(rows), readyToRun=True, qualificationAllowed=False)))


if __name__ == '__main__': main()
