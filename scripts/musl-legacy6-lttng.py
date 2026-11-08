#!/usr/bin/env python3
"""Record real legacy .NET GC events and an independent native LTTng control.

Only a completed SDK archive is accepted. No runtime overlays, source cache,
host SDK, validation callback, R2R suppression or security override is used.
Run this in the separate SDK-free tracing test image, with network disabled.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tarfile
import tempfile
import time

PROGRAM = '''using System;using System.Threading;
class P { static void Main() { Console.WriteLine("READY");
for(int i=0;i<80;i++){var a=new byte[100000];GC.Collect();Thread.Sleep(100);}
Console.WriteLine("DONE"); }}
'''
CONTROL = 'CBODOTNET_NATIVE_LTTNG_POSITIVE_CONTROL'


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest())


def write(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=['6.0.136'], required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and platform.system() == 'Linux' and
            platform.machine() == {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4',
            'Matching native non-root Alpine 3.24.4 is required')
    require(subprocess.run(['sh', '-c', 'command -v dotnet || command -v clang || command -v cc'],
                           stdout=subprocess.DEVNULL).returncode != 0,
            'The tracing image must contain no SDK or compiler')
    require(args.archive.is_file() and not args.archive.is_symlink() and not args.output.exists(),
            'An ordinary completed SDK archive and fresh evidence directory are required')
    args.output.mkdir(parents=True)
    write(args.output / 'identity.json', dict(schemaVersion=1, kind='legacy-musl-lttng-session-proof',
        sdkVersion=args.sdk, architecture=args.arch, archive=dict(name=args.archive.name, **fingerprint(args.archive)),
        uid=os.getuid(), readyToRun=True, runtimeOverlaysAccepted=False, hostSdkUsed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    (args.output / 'Program.cs').write_text(PROGRAM)
    rows = []
    with tempfile.TemporaryDirectory(prefix='cbodotnet-legacy-lttng-') as tmp:
        work = Path(tmp)
        sdk, app, home = work / 'sdk', work / 'app', work / 'home'
        for directory in [sdk, app, home]:
            directory.mkdir()
        with tarfile.open(args.archive, 'r:gz') as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts and (member.isfile() or member.isdir()),
                        'Unsafe SDK archive member')
            archive.extractall(sdk, filter='data')
        (app / 'Program.cs').write_text(PROGRAM)
        (app / 'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<OutputType>Exe</OutputType><TargetFramework>net6.0</TargetFramework>'
            '<UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>')
        (app / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
        env = dict(os.environ, HOME=str(home), DOTNET_CLI_HOME=str(home), DOTNET_ROOT=str(sdk),
                   DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2', COMPlus_ReadyToRun='1',
                   COMPlus_EnableEventLog='1', COMPlus_LTTng='1', LTTNG_UST_REGISTER_TIMEOUT='5000')
        os.environ['HOME'] = str(home)
        os.environ['LTTNG_UST_REGISTER_TIMEOUT'] = '5000'

        def run(name, command, timeout=120):
            started = datetime.now(timezone.utc).isoformat()
            with (args.output / (name + '.log')).open('x') as log:
                process = subprocess.run(list(map(str, command)), cwd=work, env=env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            row = dict(name=name, command=list(map(str, command)), exitCode=process.returncode,
                       startedAt=started, completedAt=datetime.now(timezone.utc).isoformat(),
                       log=name + '.log', **fingerprint(args.output / (name + '.log')))
            rows.append(row)
            write(args.output / (name + '-command.json'), row)
            require(process.returncode == 0, 'Actual LTTng probe command failed: ' + name)
            return (args.output / (name + '.log')).read_text()

        run('cold-build', [sdk / 'dotnet', 'build', app / 'Probe.csproj', '-c', 'Release'])
        run('sessiond', ['lttng-sessiond', '--daemonize', '--no-kernel'])
        run('create', ['lttng', 'create', 'cbodotnet-legacy6', '--output=' + str(args.output / 'session')])
        run('enable', ['lttng', 'enable-event', '--userspace', '--all'])
        run('start', ['lttng', 'start'])
        command = [str(sdk / 'dotnet'), str(app / 'bin/Release/net6.0/Probe.dll')]
        with (args.output / 'managed.stdout.log').open('x') as stdout, (args.output / 'managed.stderr.log').open('x') as stderr:
            managed = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr)
            try:
                library = ctypes.CDLL('liblttng-ust.so.1', mode=ctypes.RTLD_GLOBAL)
                emit = library.lttng_ust__tracef
                emit.argtypes, emit.restype = [ctypes.c_char_p], None
                time.sleep(2)
                emit(CONTROL.encode())
                time.sleep(1)
                listing = run('tracepoints', ['lttng', 'list', '--userspace'])
                exit_code = managed.wait(timeout=45)
            finally:
                if managed.poll() is None:
                    managed.terminate()
                    managed.wait(timeout=10)
        run('stop', ['lttng', 'stop'])
        run('destroy', ['lttng', 'destroy', 'cbodotnet-legacy6'])
        decoded = run('decoded', ['babeltrace2', args.output / 'session'])
        events = decoded.splitlines()
        observed = dict(dotnetEvents=sum('DotNETRuntime:' in line for line in events),
            gcStartEvents=sum('DotNETRuntime:GCStart' in line for line in events),
            gcEndEvents=sum('DotNETRuntime:GCEnd' in line for line in events),
            controlEvents=sum(CONTROL in line for line in events), totalDecodedLines=len(events),
            listedDotnetTracepoints=sum('DotNETRuntime' in line for line in listing.splitlines()))
        require(exit_code == 0 and (args.output / 'managed.stdout.log').read_text().splitlines() == ['READY', 'DONE'],
                'The candidate runtime did not complete the real GC workload')
        require(observed['dotnetEvents'] > 0 and observed['gcStartEvents'] >= 80 and
                observed['gcEndEvents'] >= 80 and observed['controlEvents'] == 1,
                'Actual decoded .NET GC events and the independent native LTTng control are required')
        write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl-lttng-session-proof',
            status='passed', sdkVersion=args.sdk, architecture=args.arch,
            archive=fingerprint(args.archive), managedCommand=command, managedExitCode=exit_code,
            programSha256=hashlib.sha256(PROGRAM.encode()).hexdigest(), observed=observed,
            commands=rows, readyToRun=True, runtimeOverlaysAccepted=False, hostSdkUsed=False,
            qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', observed=observed, qualificationAllowed=False)))


if __name__ == '__main__':
    main()
