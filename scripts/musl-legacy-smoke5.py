#!/usr/bin/env python3
"""Execute the pinned NET5 shell smoke suite against a genuine musl candidate.

The original 68 template cases, both restore phases, HTTPS setup and XML-doc
assertions remain enabled. Only the already reviewed built-in dev-certs setup
patch is applied. This regular-producer harness does not claim execution of the
source-build root MSBuild graph or of its RunSmokeTest target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'd414ecb2d997a9b3f38aaaeddace30ca097e546d'
ORIGINAL_SHA = 'ab8dbbbb0b1580e220767216cdb281e868ca8cc8bf874d376332c7199ffbe640'
ADAPTED_SHA = '39fc79fe29e580b1579abdc28db98fcc779bef2a72be82d62dd760febca51272'
PATCH_SHA = '720a895304407dec0d1585370e10e4da1e1de9475d2976527719cd8acbdb1b85'
SUITE_FILES = ['smoke-test.sh', 'smoke-testNuGet.Config', 'ProdConFeed.txt', 'build.proj']


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    hashes = {name: hashlib.new(name) for name in ['sha256', 'sha512']}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in hashes.values():
                value.update(block)
    return dict(bytes=path.stat().st_size, **{key: value.hexdigest() for key, value in hashes.items()})


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def git(source, *arguments):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *arguments])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    parser.add_argument('--source-suite', type=Path, required=True)
    parser.add_argument('--sdk-archive', type=Path, required=True)
    parser.add_argument('--local-feed', type=Path, required=True)
    parser.add_argument('--build-identity', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and os.getuid() != 0 and
            platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4',
            'Matching native non-root Alpine3.24.4 original-suite worker required')
    require(not any(Path(name).exists() for name in ['/usr/bin/dotnet', '/usr/share/dotnet']) and
            subprocess.run(['sh', '-c', 'command -v clang || command -v cc || command -v gcc'],
                           stdout=subprocess.DEVNULL).returncode != 0, 'SDK-free/compiler-free test image required')
    require(not args.output.exists(), 'A fresh complete-suite evidence directory is required')
    require(args.workspace.is_absolute() and args.workspace != Path('/') and args.workspace.is_dir() and
            not any(args.workspace.iterdir()) and not any(path.is_symlink() for path in [args.workspace, *args.workspace.parents]),
            'Fresh ordinary dedicated test workspace required; preserve it for interrupted-worker recovery')
    require(args.local_feed.is_dir() and not args.local_feed.is_symlink(), 'Ordinary retained local input feed required')
    require(git(args.source_suite, 'rev-parse', 'HEAD').decode().strip() == COMMIT, 'Original source-build suite commit differs')
    identity = json.loads(args.build_identity.read_text())
    archive_identity = fingerprint(args.sdk_archive)
    require(identity.get('sdkVersion') == '5.0.214' and identity.get('architecture') == args.arch and
            identity.get('sdkSourceBuildSucceeded') is True and identity.get('installerBuildSucceeded') is True and
            all(identity.get('sdkArchive', {}).get(key) == value for key, value in archive_identity.items()),
            'The regular SDK/installer success and exact candidate archive must be bound before test eligibility')
    args.output.mkdir(parents=True)
    suite_rows = []
    originals = {}
    for relative in SUITE_FILES:
        data = git(args.source_suite, 'show', COMMIT + ':' + relative)
        require((args.source_suite / relative).read_bytes() == data, 'Original suite source changed: ' + relative)
        originals[relative] = data
        suite_rows.append(dict(path=relative, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
    require(hashlib.sha256(originals['smoke-test.sh']).hexdigest() == ORIGINAL_SHA, 'Pinned original shell assertions differ')
    patch = ROOT / 'patches/net5-tests/0001-use-built-sdk-dev-certs.patch'
    require(fingerprint(patch)['sha256'] == PATCH_SHA, 'Reviewed certificate setup patch differs')
    write(args.output / 'identity.json', dict(schemaVersion=1, kind='original-net5-musl-shell-smoke-candidate',
        sdkVersion='5.0.214', architecture=args.arch, sourceCommit=COMMIT, sourceFiles=suite_rows,
        sdkArchive=archive_identity, buildIdentity=fingerprint(args.build_identity),
        expectedTemplateCases=68, expectedHttpsSetups=2, suiteExclusions=[],
        runSmokeTestMsbuildTargetExecuted=False, rootSourceBuildGraphClaimed=False,
        localFeedOrigin='Exact retained rebuilt SDK packages and unchanged attributed managed/runtime package inputs',
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    with tempfile.TemporaryDirectory(prefix='cbodotnet-net5-original-smoke-', dir=args.workspace) as temporary:
        work = Path(temporary)
        sdk = work / 'candidate-sdk'
        sdk.mkdir()
        with tarfile.open(args.sdk_archive, 'r:gz') as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts and (member.isfile() or member.isdir()),
                        'Ordinary safe SDK archive members required')
            archive.extractall(sdk, filter='data')
        for relative, data in originals.items():
            (work / relative).write_bytes(data)
        (work / 'smoke-test.sh').chmod(0o755)
        subprocess.run(['git', 'init', '--quiet', str(work)], check=True)
        for option in ['--check', None]:
            subprocess.run(['git', '-C', str(work), 'apply', *([option] if option else []), str(patch)], check=True)
        require(fingerprint(work / 'smoke-test.sh')['sha256'] == ADAPTED_SHA, 'Only the reviewed dev-certs setup change is allowed')
        shutil.copyfile(work / 'smoke-test.sh', args.output / 'upstream-smoke-test.adapted.sh')
        (args.output / 'upstream-smoke-test.original.sh').write_bytes(originals['smoke-test.sh'])
        environment = dict(os.environ, HOME=str(work / 'initial-home'), DOTNET_CLI_HOME=str(work / 'initial-home'),
            DOTNET_ROOT=str(sdk), DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_CLI_TELEMETRY_OPTOUT='1',
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_PROCESSOR_COUNT='2',
            targetRid='linux-musl-' + ('arm64' if args.arch == 'aarch64' else 'x64'))
        (work / 'initial-home').mkdir()
        version = subprocess.check_output([str(sdk / 'dotnet'), '--version'], cwd=work, env=environment).decode().strip()
        require(version == '5.0.214', 'The extracted candidate SDK version differs')
        marker = work / 'artifacts/obj/rootrepo.txt'
        marker.parent.mkdir(parents=True)
        marker.write_text('known-good\n')
        feed = work / 'artifacts/obj' / ('arm64' if args.arch == 'aarch64' else 'x64') / 'Release/blob-feed/packages'
        feed.parent.mkdir(parents=True)
        feed.symlink_to(args.local_feed, target_is_directory=True)
        write(args.output / 'eligibility.json', dict(marker='known-good', createdBy='regular-musl-test-harness',
            meaning='Actual regular SDK and installer succeeded and the freshly extracted archive reports5.0.214',
            wholeSourceBuildRootGraphSucceededClaimed=False, candidateVersion=version,
            sourceBuildResultIdentity=fingerprint(args.build_identity), localFeedMount=str(args.local_feed)))
        command = ['bash', str(work / 'smoke-test.sh'), '--dotnetDir', str(sdk), '--projectOutput',
                   '--configuration', 'Release', '--archiveRestoredPackages']
        write(args.output / 'command.json', dict(command=command, targetRid=environment['targetRid'],
            assertionsChanged=False, localAndOnlinePhases=True, httpsAndXmlDocsEnabled=True, timeoutSeconds=2400))
        with (args.output / 'execution.log').open('x') as stream:
            try:
                code = subprocess.run(command, cwd=work, env=environment, stdout=stream,
                                      stderr=subprocess.STDOUT, timeout=2400).returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                code, timed_out = None, True
        testing = work / 'testing-smoke'
        if (testing / 'smoke-test.log').is_file():
            shutil.copyfile(testing / 'smoke-test.log', args.output / 'smoke-test.log')
        binlogs = args.output / 'binlogs'
        binlogs.mkdir()
        if testing.exists():
            for path in testing.glob('*.binlog'):
                shutil.copyfile(path, binlogs / path.name)
        text = (args.output / 'smoke-test.log').read_text(errors='replace') if (args.output / 'smoke-test.log').exists() else ''
        console = (args.output / 'execution.log').read_text(errors='replace')
        markers = ['LOCAL RESTORE SOURCE - ALL TESTS PASSED!', 'ONLINE RESTORE SOURCE - ALL TESTS PASSED!',
                   'All expected xml docs are present', 'ALL TESTS PASSED!']
        started = sum(line.startswith('starting language ') for line in text.splitlines())
        finished = sum(line.startswith('finished language ') for line in text.splitlines())
        certs = text.count('Using the SDK built-in dotnet dev-certs to generate the HTTPS developer certificate')
        result = dict(exitCode=code, timedOut=timed_out, templateCasesStarted=started,
            templateCasesFinished=finished, expectedTemplateCases=68, httpsSetups=certs, expectedHttpsSetups=2,
            terminalMarkers={value: value in console.splitlines() for value in markers}, suiteExclusions=[],
            runSmokeTestMsbuildTargetExecuted=False, rootSourceBuildGraphClaimed=False,
            qualificationAllowed=False, sourceAdmissionAllowed=False)
        passed = code == 0 and not timed_out and started == finished == 68 and certs == 2 and all(result['terminalMarkers'].values())
        result['status'] = 'passed' if passed else 'failed'
        write(args.output / 'summary.json', result)
        require(passed, 'The complete original NET5 shell smoke suite did not pass')
    print('All original68 NET5 template cases, both HTTPS setups and XML docs passed.')


if __name__ == '__main__':
    main()
