#!/usr/bin/env python3
"""Prepare and record a fresh SDK run of the pinned complete NET5 smoke suite."""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile


COMMIT = 'd414ecb2d997a9b3f38aaaeddace30ca097e546d'
SDK = '5.0.214'
RUNTIME = '5.0.17'
SUITE_FILES = ['smoke-test.sh', 'smoke-testNuGet.Config', 'ProdConFeed.txt', 'build.proj']
ASP = '02c6de4ba6022025fcda7581415f310f8c73cdc3'
TEST_PATCH = '0001-use-built-sdk-dev-certs.patch'
TEST_PATCH_SHA = '720a895304407dec0d1585370e10e4da1e1de9475d2976527719cd8acbdb1b85'
ORIGINAL_SUITE_SHA = 'ab8dbbbb0b1580e220767216cdb281e868ca8cc8bf874d376332c7199ffbe640'
ADAPTED_SUITE_SHA = '39fc79fe29e580b1579abdc28db98fcc779bef2a72be82d62dd760febca51272'


def fingerprint(path):
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def directory(path):
    if not path.is_absolute() or path == Path(path.anchor):
        raise ValueError('An absolute ordinary directory below the filesystem root is required')
    for parent in [path] + list(path.parents):
        if parent.is_symlink():
            raise ValueError('A control path is a symbolic link')
    if not path.is_dir():
        raise ValueError('Missing ordinary directory: ' + str(path))
    return path.resolve(strict=True)


def file(path):
    directory(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing ordinary file: ' + str(path))
    return path


def git(source, *args):
    result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false', '-C', str(source)] + list(args),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError('Pinned Git verification failed: ' + result.stderr.decode('utf-8', 'replace')[-2000:])
    return result.stdout


def write(path, record):
    with path.open('x', encoding='utf-8') as output:
        json.dump(record, output, indent=2, sort_keys=True)
        output.write('\n')


def identity(source):
    if git(source, 'rev-parse', 'HEAD').decode().strip() != COMMIT:
        raise ValueError('The NET5 source graph differs')
    records = []
    for relative in SUITE_FILES:
        path = file(source / relative)
        original = git(source, 'show', COMMIT + ':' + relative)
        adapted = relative == 'smoke-test.sh' and fingerprint(path)['sha256'] == ADAPTED_SUITE_SHA
        if relative == 'smoke-test.sh' and hashlib.sha256(original).hexdigest() != ORIGINAL_SUITE_SHA:
            raise ValueError('The pinned original smoke-script digest differs')
        if path.read_bytes() != original and not adapted:
            raise ValueError('The pinned upstream smoke suite differs: ' + relative)
        records.append(dict({'path': relative}, **fingerprint(path)))
    root_repo = file(source / 'artifacts/obj/rootrepo.txt')
    if root_repo.read_text().strip() != 'known-good':
        raise ValueError('The upstream suite would skip because the completed root graph is not known-good')
    return records


def dev_certs_tool(source, stage, reports):
    tools = list((stage / ('sdk/' + SDK + '/DotnetTools/dotnet-dev-certs')).glob('**/dotnet-dev-certs.dll'))
    if len(tools) != 1:
        raise ValueError('The fresh SDK does not contain one built-in dev-certs tool assembly')
    tool = file(tools[0])
    actual = fingerprint(tool)
    member = tool.relative_to(stage).as_posix()
    component = directory(source / ('artifacts/src/aspnetcore.' + ASP))
    if file(component / '.git/HEAD').read_text().strip() != ASP:
        raise ValueError('The ASP.NET source export identity differs')
    program_relative = 'src/Tools/dotnet-dev-certs/src/Program.cs'
    program = file(component / program_relative)
    original = git(source, '--git-dir=' + str(source / '.git/modules/src/aspnetcore.git'), 'show', ASP + ':' + program_relative)
    if program.read_bytes() != original:
        raise ValueError('The pinned dev-certs entry-point source differs')
    binaries, packages = [], []
    output = component / 'artifacts/bin/dotnet-dev-certs'
    if output.exists():
        directory(output)
        for path in sorted(output.glob('**/dotnet-dev-certs.dll')):
            row = dict({'path': str(file(path))}, **fingerprint(path))
            row['matchesSdkToolAssembly'] = row['sha256'] == actual['sha256']
            binaries.append(row)
    feed = directory(source / 'artifacts/obj/arm64/Release/blob-feed/packages')
    for package in sorted(feed.iterdir()):
        if (not package.name.lower().startswith('dotnet-dev-certs.') or not package.name.endswith('.nupkg')
                or package.name.endswith('.symbols.nupkg')):
            continue
        file(package)
        with zipfile.ZipFile(str(package)) as archive:
            for entry in archive.infolist():
                if entry.filename.endswith('/dotnet-dev-certs.dll'):
                    digest = hashlib.sha256(archive.read(entry)).hexdigest()
                    packages.append({'path': str(package), 'packageFingerprint': fingerprint(package),
                                     'member': entry.filename, 'memberSha256': digest,
                                     'matchesSdkToolAssembly': digest == actual['sha256']})
    command = [str(stage / 'dotnet'), 'dev-certs', 'https', '--help']
    process = subprocess.run(command, cwd=str(stage), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with (reports / 'sdk-dev-certs-help.log').open('xb') as output:
        output.write(process.stdout)
    if process.returncode:
        raise ValueError('The fresh SDK built-in dev-certs HTTPS command is not executable')
    return dict({'sdkArchiveMember': member, 'path': str(source / 'artifacts/builtCli' / member),
                 'commandProbe': command, 'commandProbeExitCode': process.returncode,
                 'commandProbeLog': fingerprint(reports / 'sdk-dev-certs-help.log'),
                 'sourceRepository': 'https://github.com/dotnet/aspnetcore', 'sourceCommit': ASP,
                 'sourceEntryPoint': dict({'path': str(program), 'repositoryPath': program_relative}, **fingerprint(program)),
                 'localBuildOutputs': binaries, 'localPackageMembers': packages,
                 'localAssemblyByteEqualityEstablished': any(row['matchesSdkToolAssembly'] for row in binaries) and any(row['matchesSdkToolAssembly'] for row in packages),
                 'scope': 'The tool comes from the verified fresh SDK archive. Pinned producer source and available local byte comparisons are recorded separately; source origin is established only when both local comparisons match.'}, **actual)


def adapt_certificate_setup(source, reports):
    patch = file(Path(__file__).resolve().parents[1] / 'patches/net5-tests' / TEST_PATCH)
    if fingerprint(patch)['sha256'] != TEST_PATCH_SHA:
        raise ValueError('The reviewed test-only certificate setup patch differs')
    if git(source, 'apply', '--numstat', str(patch)).decode().strip() != '2\t3\tsmoke-test.sh':
        raise ValueError('The test-only patch scope differs')
    original = git(source, 'show', COMMIT + ':smoke-test.sh')
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SUITE_SHA:
        raise ValueError('The original upstream smoke script differs')
    with (reports / 'upstream-smoke-test.original.sh').open('xb') as output:
        output.write(original)
    with tempfile.TemporaryDirectory(prefix='net5-test-patch-') as temporary:
        stage = Path(temporary)
        git(stage, 'init', '--quiet')
        path = stage / 'smoke-test.sh'
        path.write_bytes(original)
        git(stage, 'apply', '--check', str(patch))
        git(stage, 'apply', str(patch))
        adapted = path.read_bytes()
    if hashlib.sha256(adapted).hexdigest() != ADAPTED_SUITE_SHA:
        raise ValueError('The adapted smoke script differs')
    begin = original.index(b'function setupDevCerts() {')
    end = original.index(b'\n}\n', begin) + len(b'\n}\n')
    if not (adapted.startswith(original[:begin]) and adapted.endswith(original[end:])):
        raise ValueError('The test-only change extends outside certificate setup')
    with (reports / 'upstream-smoke-test.adapted.sh').open('xb') as output:
        output.write(adapted)
    target = file(source / 'smoke-test.sh')
    before = fingerprint(target)['sha256']
    if before not in (ORIGINAL_SUITE_SHA, ADAPTED_SUITE_SHA):
        raise ValueError('Refusing an unknown smoke-script modification')
    if before != ADAPTED_SUITE_SHA:
        target.write_bytes(adapted)
    return {'patch': str(patch), 'patchSha256': TEST_PATCH_SHA, 'target': str(target),
            'originalSha256': ORIGINAL_SUITE_SHA, 'adaptedSha256': ADAPTED_SUITE_SHA,
            'function': 'setupDevCerts', 'result': 'applied' if before == ORIGINAL_SUITE_SHA else 'already-present',
            'scope': 'Certificate tool setup only. Every test case and assertion remains byte-identical outside this function.'}


def prepare(source, inputs, reports, record):
    archive = file(source / ('artifacts/arm64/Release/dotnet-sdk-' + SDK + '-linux-arm64.tar.gz'))
    record['sdkArchive'] = dict({'path': str(archive)}, **fingerprint(archive))
    parent = inputs / 'test-runs'
    if parent.exists():
        directory(parent)
        owner = file(parent / 'owner.json')
        if json.loads(owner.read_text()) != {'sourceRoot': str(source), 'sourceCommit': COMMIT}:
            raise ValueError('An existing test-runs directory has a different owner')
    else:
        parent.mkdir()
        write(parent / 'owner.json', {'sourceRoot': str(source), 'sourceCommit': COMMIT})
    private = parent / reports.name
    private.mkdir()
    stage = private / 'fresh-sdk'
    stage.mkdir()
    module_path = Path(__file__).resolve().with_name('prepare-net5-bootstrap.py')
    spec = importlib.util.spec_from_file_location('net5_bootstrap_extraction', str(module_path))
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    # Reuse only the guarded extraction routine for the produced SDK version.
    bootstrap.extract_sdk(archive, stage, sdk_version=SDK)
    environment = os.environ.copy()
    environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    version = subprocess.check_output([str(stage / 'dotnet'), '--version'], cwd=str(stage), env=environment).decode().strip()
    runtimes = subprocess.check_output([str(stage / 'dotnet'), '--list-runtimes'], cwd=str(stage), env=environment).decode()
    if version != SDK or not all(name + ' ' + RUNTIME + ' [' in runtimes
                                 for name in ['Microsoft.NETCore.App', 'Microsoft.AspNetCore.App']):
        raise ValueError('The freshly extracted SDK/runtime identity differs')
    record.update({'freshSdkVersion': version, 'freshSdkRuntimes': runtimes,
                   'recoveryDirectory': str(private), 'preservedPreviousDirectories': []})
    record['certificateTool'] = dev_certs_tool(source, stage, reports)
    for relative, destination in [('artifacts/builtCli', 'previous-builtCli'), ('testing-smoke', 'previous-testing-smoke')]:
        target = source / relative
        if git(source, 'ls-files', '--', relative).strip():
            raise ValueError('The generated test path unexpectedly contains tracked files')
        if target.exists() or target.is_symlink():
            directory(target)
            saved = private / destination
            record['preservedPreviousDirectories'].append({'original': str(target), 'preserved': str(saved)})
    write(reports / 'net5-tests-setup-plan.json', record)
    for row in record['preservedPreviousDirectories']:
        Path(row['original']).rename(row['preserved'])
    stage.rename(source / 'artifacts/builtCli')
    record['testOnlyCertificateSetup'] = adapt_certificate_setup(source, reports)
    record.update({'status': 'passed', 'sdkDirectory': str(source / 'artifacts/builtCli'),
                   'scope': 'Fresh archive extraction, an empty test workspace and the recorded certificate-tool setup adaptation. No suite exclusions, assertions or SDK archive bytes changed.'})


def finalize(source, reports, code, record):
    setup = json.loads(file(reports / 'net5-tests-setup.json').read_text())
    if setup.get('status') != 'passed' or setup['sourceCommit'] != COMMIT:
        raise ValueError('The successful fresh test setup is absent')
    archive = file(Path(setup['sdkArchive']['path']))
    if fingerprint(archive) != {key: setup['sdkArchive'][key] for key in ('bytes', 'sha256')}:
        raise ValueError('The SDK archive changed during tests')
    console = file(reports / 'test.log').read_text(errors='replace')
    log = source / 'testing-smoke/smoke-test.log'
    text = file(log).read_text(errors='replace') if log.exists() else ''
    markers = ['LOCAL RESTORE SOURCE - ALL TESTS PASSED!', 'ONLINE RESTORE SOURCE - ALL TESTS PASSED!',
               'All expected xml docs are present', 'ALL TESTS PASSED!']
    console_lines = {line.strip() for line in console.splitlines()}
    started = sum(line.startswith('starting language ') for line in text.splitlines())
    finished = sum(line.startswith('finished language ') for line in text.splitlines())
    certificate_setups = text.count('Using the SDK built-in dotnet dev-certs to generate the HTTPS developer certificate')
    tool = setup['certificateTool']
    if fingerprint(file(Path(tool['path']))) != {key: tool[key] for key in ('bytes', 'sha256')}:
        raise ValueError('The SDK certificate tool assembly changed during tests')
    record.update({'upstreamExitCode': code, 'sdkArchive': setup['sdkArchive'],
                   'templateCasesStarted': started, 'templateCasesFinished': finished,
                   'expectedTemplateCases': 68, 'terminalMarkers': {marker: marker in console_lines for marker in markers},
                   'certificateSetupsCompleted': certificate_setups, 'expectedCertificateSetups': 2,
                   'suiteExclusions': [], 'certificateTool': setup['certificateTool'],
                   'testOnlyCertificateSetup': setup['testOnlyCertificateSetup'],
                   'testImplementation': 'Pinned upstream smoke suite with the reviewed certificate-tool setup adaptation, invoked by the unmodified RunSmokeTest target.'})
    selected = []
    workspace = source / 'testing-smoke'
    if workspace.exists():
        directory(workspace)
        for path in sorted(workspace.iterdir()):
            if path.is_file() and not path.is_symlink() and (path.suffix in ('.binlog', '.log', '.Config') or path.name.startswith('Directory.Build.')):
                selected.append(path)
    with tarfile.open(str(reports / 'upstream-smoke-outputs.tar.gz'), 'x:gz') as output:
        for path in selected:
            output.add(str(path), arcname='testing-smoke/' + path.name, recursive=False)
    record['retainedOutputs'] = dict({'files': len(selected), 'path': str(reports / 'upstream-smoke-outputs.tar.gz')},
                                     **fingerprint(reports / 'upstream-smoke-outputs.tar.gz'))
    record['status'] = 'passed' if code == 0 and started == finished == 68 and certificate_setups == 2 and all(record['terminalMarkers'].values()) else 'failed'
    if record['status'] != 'passed':
        record['error'] = 'The complete upstream smoke-suite evidence did not pass; inspect the retained exit code and logs.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'finalize'])
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--inputs-dir', required=True, type=Path)
    parser.add_argument('--reports-dir', required=True, type=Path)
    parser.add_argument('--upstream-exit-code', type=int)
    args = parser.parse_args()
    source, inputs, reports = [directory(path) for path in (args.source_dir, args.inputs_dir, args.reports_dir)]
    for left, right in [(source, inputs), (source, reports), (inputs, reports)]:
        if left == right or left in right.parents or right in left.parents:
            raise ValueError('Source, inputs and reports must be separate directories')
    destination = reports / ('net5-tests-setup.json' if args.action == 'prepare' else 'net5-tests-result.json')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Refusing a previous test report')
    record = {'schemaVersion': 1, 'action': args.action, 'sourceRoot': str(source), 'sourceCommit': COMMIT,
              'sdkVersion': SDK, 'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'failed'}
    try:
        record['suiteFiles'] = identity(source)
        if args.action == 'prepare':
            prepare(source, inputs, reports, record)
        else:
            if args.upstream_exit_code is None:
                raise ValueError('The actual upstream exit code is required')
            finalize(source, reports, args.upstream_exit_code, record)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        record['status'], record['error'] = 'failed', str(error)
    record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write(destination, record)
    print(json.dumps({'status': record['status'], 'report': str(destination), 'error': record.get('error')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
