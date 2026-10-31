#!/usr/bin/env python3
"""Compile the bounded binlog reader using an isolated, verified analysis SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

VERSION = '9.0.121'
HASH = '2c8288568d9827371d8d0daf0578590a956d955bef783bf1403953f8a816851f03be7aa366b6649e7cda77a8e7359ac3fc46fac87f010d71b6e7415a9457add5'


def run(command, env, log):
    with log.open('xb') as stream:
        process = subprocess.run(list(map(str, command)), env=env, stdout=stream, stderr=subprocess.STDOUT)
    if process.returncode:
        raise ValueError('Analysis command failed; inspect ' + str(log))


def fp(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError('Ordinary analysis file required: ' + str(path))
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def environment(workspace):
    home = workspace / 'inputs/analysis-home'
    home.mkdir(exist_ok=True); os.chmod(home, 0o700)
    xdg = home / 'xdg'; xdg.mkdir(exist_ok=True); os.chmod(xdg, 0o700)
    sdk = workspace / 'inputs/analysis-sdk'
    env = dict(os.environ, HOME=str(home), DOTNET_CLI_HOME=str(home), XDG_RUNTIME_DIR=str(xdg),
               DOTNET_ROOT=str(sdk), DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_NOLOGO='1',
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1')
    return sdk, env


def prepare(args):
    reports = args.reports_dir; reports.mkdir(parents=True)
    inputs = args.workspace / 'inputs'; archive = inputs / ('dotnet-sdk-' + VERSION + '-linux-arm64.tar.gz')
    if archive.exists():
        raise ValueError('Analysis prepare requires fresh inputs')
    url = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + VERSION + '/' + archive.name
    h = hashlib.sha512()
    with urllib.request.urlopen(url, timeout=180) as source, archive.open('xb') as output:
        for block in iter(lambda: source.read(1048576), b''):
            h.update(block); output.write(block)
    if h.hexdigest() != HASH:
        raise ValueError('Official analysis SDK SHA512 differs')
    sdk, env = environment(args.workspace); sdk.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(sdk, filter='data')
    project = inputs / 'analysis-reader'; project.mkdir()
    code = Path(__file__).with_name('ci-legacy-binlog.cs')
    shutil.copyfile(code, project / 'Program.cs')
    sdkdir = sdk / 'sdk' / VERSION
    text = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup><ItemGroup>'
    for name in ('Microsoft.Build', 'Microsoft.Build.Framework', 'Microsoft.Build.Utilities.Core'):
        text += '<Reference Include="' + name + '"><HintPath>' + str(sdkdir / (name + '.dll')) + '</HintPath></Reference>'
    text += '</ItemGroup></Project>\n'
    (project / 'Reader.csproj').write_text(text)
    config = project / 'NuGet.config'; config.write_text('<configuration><packageSources><clear/></packageSources></configuration>\n')
    (project / 'global.json').write_text(json.dumps({'sdk': {'version': VERSION, 'rollForward': 'disable'}}))
    run([sdk / 'dotnet', 'restore', project / 'Reader.csproj', '--configfile', config], env, reports / 'restore.log')
    run([sdk / 'dotnet', 'build', project / 'Reader.csproj', '--no-restore', '-c', 'Release'], env, reports / 'compile.log')
    record = {'status': 'passed', 'sdkVersion': VERSION, 'archiveUrl': url, 'archiveSha512': HASH,
              'archive': fp(archive), 'source': fp(code), 'project': fp(project / 'Reader.csproj'),
              'reader': fp(project / 'bin/Release/net9.0/Reader.dll'),
              'msbuild': [fp(sdkdir / (name + '.dll')) for name in ('Microsoft.Build', 'Microsoft.Build.Framework', 'Microsoft.Build.Utilities.Core')],
              'scope': 'Analysis only. No product project is evaluated or built by this SDK.'}
    (reports / 'analysis.json').write_text(json.dumps(record, indent=2) + '\n')


def origins(args):
    source = args.workspace / 'source'; reports = args.output_dir / 'reports/construction'
    reports.mkdir(parents=True, exist_ok=True)
    sdk, env = environment(args.workspace)
    layout = 'bin' if args.family == 'core30' else 'artifacts'
    runtime = {'net5': '5.0.17', 'core31': '3.1.32', 'core30': '3.0.3'}[args.family]
    component = 'installer' if args.family == 'net5' else 'core-sdk'
    candidates = sorted((source / layout / 'src').glob(component + '.*'))
    if len(candidates) != 1:
        raise ValueError('Exactly one actual installer export is required')
    # This is the original top-level packaging binlog, not nested compiler or
    # duplicate log copies. Product completion precedes this read-only replay.
    logs = [candidates[0] / 'artifacts/log/Release/Build.binlog']
    if not logs[0].is_file() or logs[0].is_symlink():
        raise ValueError('The closed original installer Build.binlog is missing')
    rows = []
    for index, log in enumerate(logs):
        destination = reports / ('installer-' + str(index) + '.binlog')
        shutil.copyfile(log, destination)
        if fp(log)['sha256'] != fp(destination)['sha256']:
            raise ValueError('Closed installer binlog changed while preserving')
        prefix = reports / ('replay-' + str(index))
        run([sdk / 'dotnet', args.workspace / 'inputs/analysis-reader/bin/Release/net9.0/Reader.dll',
             destination, sdk / 'sdk' / VERSION, prefix, source, runtime], env, reports / ('replay-' + str(index) + '.log'))
        status = json.loads(Path(str(prefix) + '-status.json').read_text())
        if status.get('completedReplay') is not True:
            raise ValueError('Bounded installer replay did not complete')
        rows.append({'binlog': fp(destination), 'status': fp(Path(str(prefix) + '-status.json'))})
    (reports / 'replays.json').write_text(json.dumps({'status': 'passed', 'replays': rows}, indent=2) + '\n')
    subprocess.run([sys.executable, str(Path(__file__).with_name('ci-legacy-origin.py')), 'audit',
                    '--family', args.family, '--source-dir', str(source), '--workspace', str(args.workspace),
                    '--output-dir', str(args.output_dir)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'origins'])
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--reports-dir', type=Path)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--family', choices=['net5', 'core31', 'core30'])
    args = parser.parse_args()
    (prepare if args.action == 'prepare' else origins)(args)


if __name__ == '__main__':
    main()
