#!/usr/bin/env python3
"""Prepare and record a fresh SDK run of the pinned complete Core 3.1 smoke suite."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import zipfile


COMMIT = 'ab8b115b5658237ee8916ae3586600b39fb2fd19'
SDK = '3.1.426'
RUNTIME = '3.1.32'
SUITE_FILES = ['smoke-test.sh', 'smoke-testNuGet.Config', 'ProdConFeed.txt', 'build.proj']
ASP = '3eeb12e106b9e913c3a4dec1a7d16da7b74149eb'
TEST_PATCH = '0001-use-built-sdk-dev-certs.patch'
TEST_PATCH_SHA = 'cef7bc0a1e67259b772091c389198b66ee24dc809dbfd37154e0d1fec6deec41'
ORIGINAL_SUITE_SHA = '7cb9d7b626314d2dcdf5838991c7e3179340e1ef392dd0d781e277dc6f1494fc'
ADAPTED_SUITE_SHA = '97b1b9591020b9f69272158aa48f4625f637dcae1769ecfc72ace281172497a7'


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


def extract_sdk(archive, stage):
    """Extract only ordinary files, directories and internal symbolic links."""
    seen, total = set(), 0
    with tarfile.open(str(archive), 'r:gz') as source:
        for member in source:
            name = member.name[2:] if member.name.startswith('./') else member.name
            if name in ('', '.') and member.isdir():
                continue
            # Python 3.8 retains the slash on a GNU long-name directory header.
            # Normalize that directory spelling only; files/links remain strict.
            if member.isdir() and name.endswith('/'):
                name = name[:-1]
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or str(relative) != name or name in seen:
                raise ValueError('Unsafe or duplicate SDK archive path: ' + repr(member.name))
            seen.add(name)
            total += member.size
            if len(seen) > 200000 or total > 16 * 1024 * 1024 * 1024:
                raise ValueError('The SDK archive exceeds the extraction bound')
            target = stage / name
            for parent in target.parents:
                if parent == stage:
                    break
                if parent.is_symlink():
                    raise ValueError('SDK member traverses a symbolic link')
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as original, target.open('xb') as output:
                    for block in iter(lambda: original.read(1024 * 1024), b''):
                        output.write(block)
                os.chmod(str(target), member.mode & 0o777)
            elif member.issym():
                resolved = (target.parent / member.linkname).resolve()
                if PurePosixPath(member.linkname).is_absolute() or not (resolved == stage or stage in resolved.parents):
                    raise ValueError('SDK symlink escapes its private tree')
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, str(target))
            else:
                raise ValueError('Unsupported SDK member type')
    if not {'dotnet', 'sdk/' + SDK + '/MSBuild.dll'}.issubset(seen):
        raise ValueError('The SDK archive lacks its pinned driver and SDK')


def sdk_inventory(root):
    root = directory(root)
    records = {}
    for current, directories, filenames in os.walk(str(root), followlinks=False):
        for name in sorted(directories + filenames):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                records[relative] = {'kind': 'symlink', 'target': os.readlink(str(path))}
            elif path.is_file():
                records[relative] = dict({'kind': 'file'}, **fingerprint(path))
            elif not path.is_dir():
                raise ValueError('An unexpected SDK file type was found')
    return records


def identity(source):
    if git(source, 'rev-parse', 'HEAD').decode().strip() != COMMIT:
        raise ValueError('The Core 3.1 source graph differs')
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


def dev_certs_tool(source, stage, reports, environment):
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
    process = subprocess.run(command, cwd=str(stage), env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with (reports / 'sdk-dev-certs-help.log').open('xb') as output:
        output.write(process.stdout)
    if process.returncode:
        raise ValueError('The fresh SDK built-in dev-certs HTTPS command is not executable')
    return dict({'sdkArchiveMember': member, 'path': str(source / 'testing-smoke/builtCli' / member),
                 'commandProbe': command, 'commandProbeExitCode': process.returncode,
                 'commandProbeLog': fingerprint(reports / 'sdk-dev-certs-help.log'),
                 'sourceRepository': 'https://github.com/dotnet/aspnetcore', 'sourceCommit': ASP,
                 'sourceEntryPoint': dict({'path': str(program), 'repositoryPath': program_relative}, **fingerprint(program)),
                 'localBuildOutputs': binaries, 'localPackageMembers': packages,
                 'localAssemblyByteEqualityEstablished': any(row['matchesSdkToolAssembly'] for row in binaries) and any(row['matchesSdkToolAssembly'] for row in packages),
                 'scope': 'The tool comes from the verified fresh SDK archive. Pinned producer source and available local byte comparisons are recorded separately; source origin is established only when both local comparisons match.'}, **actual)


def adapt_certificate_setup(source, reports):
    patch = file(Path(__file__).resolve().parents[1] / 'patches/core31-tests' / TEST_PATCH)
    if fingerprint(patch)['sha256'] != TEST_PATCH_SHA:
        raise ValueError('The reviewed test-only certificate setup patch differs')
    if git(source, 'apply', '--numstat', str(patch)).decode().strip() != '2\t3\tsmoke-test.sh':
        raise ValueError('The test-only patch scope differs')
    original = git(source, 'show', COMMIT + ':smoke-test.sh')
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SUITE_SHA:
        raise ValueError('The original upstream smoke script differs')
    with (reports / 'upstream-smoke-test.original.sh').open('xb') as output:
        output.write(original)
    with tempfile.TemporaryDirectory(prefix='core31-test-patch-') as temporary:
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
    if sorted(archive.parent.glob('dotnet-sdk-3.1*')) != [archive]:
        raise ValueError('The upstream wildcard must select exactly the expected SDK archive')
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
    stage = private / 'independently-verified-sdk'
    stage.mkdir()
    extract_sdk(archive, stage)
    environment = os.environ.copy()
    environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    probe_home = private / 'probe-home'
    probe_home.mkdir()
    probe_runtime = private / 'probe-runtime'
    probe_runtime.mkdir(mode=0o700)
    os.chmod(str(probe_runtime), 0o700)
    environment.update({'HOME': str(probe_home), 'DOTNET_CLI_HOME': str(probe_home),
                        'XDG_RUNTIME_DIR': str(probe_runtime), 'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false',
                        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1'})
    version = subprocess.check_output([str(stage / 'dotnet'), '--version'], cwd=str(stage), env=environment).decode().strip()
    runtimes = subprocess.check_output([str(stage / 'dotnet'), '--list-runtimes'], cwd=str(stage), env=environment).decode()
    if version != SDK or not all(name + ' ' + RUNTIME + ' [' in runtimes
                                 for name in ['Microsoft.NETCore.App', 'Microsoft.AspNetCore.App']):
        raise ValueError('The freshly extracted SDK/runtime identity differs')
    record.update({'freshSdkVersion': version, 'freshSdkRuntimes': runtimes,
                   'recoveryDirectory': str(private), 'preservedPreviousDirectories': []})
    record['certificateTool'] = dev_certs_tool(source, stage, reports, environment)
    inventory = sdk_inventory(stage)
    write(reports / 'core31-tests-sdk-members.json', inventory)
    record['expectedSdkMembers'] = dict({'path': str(reports / 'core31-tests-sdk-members.json'),
                                          'members': len(inventory)}, **fingerprint(reports / 'core31-tests-sdk-members.json'))
    for relative, destination in [('testing-smoke', 'previous-testing-smoke')]:
        target = source / relative
        if git(source, 'ls-files', '--', relative).strip():
            raise ValueError('The generated test path unexpectedly contains tracked files')
        if target.exists() or target.is_symlink():
            directory(target)
            saved = private / destination
            record['preservedPreviousDirectories'].append({'original': str(target), 'preserved': str(saved)})
    write(reports / 'core31-tests-setup-plan.json', record)
    for row in record['preservedPreviousDirectories']:
        Path(row['original']).rename(row['preserved'])
    record['testOnlyCertificateSetup'] = adapt_certificate_setup(source, reports)
    record.update({'status': 'passed', 'sdkDirectory': str(source / 'testing-smoke/builtCli'),
                   'independentlyVerifiedSdk': str(stage), 'upstreamWorkspaceAbsentBeforeRun': not (source / 'testing-smoke').exists(),
                   'scope': 'Independent fresh archive verification and an absent upstream test workspace force the unchanged upstream entry point to freshly extract its sole exact archive. Finalization verifies that actual SDK tree against this inventory. Certificate setup alone is adapted; no case, assertion or archive byte changes.'})


def finalize(source, reports, code, record):
    setup = json.loads(file(reports / 'core31-tests-setup.json').read_text())
    if setup.get('status') != 'passed' or setup['sourceCommit'] != COMMIT:
        raise ValueError('The successful fresh test setup is absent')
    archive = file(Path(setup['sdkArchive']['path']))
    if fingerprint(archive) != {key: setup['sdkArchive'][key] for key in ('bytes', 'sha256')}:
        raise ValueError('The SDK archive changed during tests')
    console = file(reports / 'test.log').read_text(errors='replace')
    log = source / 'testing-smoke/smoke-test.log'
    text = file(log).read_text(errors='replace') if log.exists() else ''
    markers = ['LOCAL RESTORE SOURCE - ALL TESTS PASSED!', 'ONLINE RESTORE SOURCE - ALL TESTS PASSED!', 'ALL TESTS PASSED!']
    console_lines = {line.strip() for line in console.splitlines()}
    started = sum(line.startswith('starting language ') for line in text.splitlines())
    finished = sum(line.startswith('finished language ') for line in text.splitlines())
    certificate_setups = text.count('Using the SDK built-in dotnet dev-certs to generate the HTTPS developer certificate')
    ready = sum('app ready for shutdown after ' in line for line in console.splitlines())
    inventory_report = file(Path(setup['expectedSdkMembers']['path']))
    if fingerprint(inventory_report) != {key: setup['expectedSdkMembers'][key] for key in ('bytes', 'sha256')}:
        raise ValueError('The prepared SDK member inventory changed')
    expected = json.loads(inventory_report.read_text())
    actual = sdk_inventory(source / 'testing-smoke/builtCli')
    if expected != actual:
        raise ValueError('The SDK actually used by the upstream suite differs from the prepared archive')
    tool = setup['certificateTool']
    if fingerprint(file(Path(tool['path']))) != {key: tool[key] for key in ('bytes', 'sha256')}:
        raise ValueError('The SDK certificate tool assembly changed during tests')
    record.update({'upstreamExitCode': code, 'sdkArchive': setup['sdkArchive'],
                   'templateCasesStarted': started, 'templateCasesFinished': finished,
                   'expectedTemplateCases': 52, 'terminalMarkers': {marker: marker in console_lines for marker in markers},
                   'webStartupReadyMarkers': ready, 'expectedWebStartupReadyMarkers': 28,
                   'sdkMemberComparison': {'matched': True, 'members': len(actual)},
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
    record['status'] = 'passed' if code == 0 and started == finished == 52 and ready == 28 and certificate_setups == 2 and all(record['terminalMarkers'].values()) else 'failed'
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
    destination = reports / ('core31-tests-setup.json' if args.action == 'prepare' else 'core31-tests-result.json')
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
