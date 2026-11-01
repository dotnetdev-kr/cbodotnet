#!/usr/bin/env python3
"""Bind the original Core 3.0 shell smoke suite to a fresh ARM64 SDK extraction.

The private adapter records feed routing and the fresh SDK certificate tool.
All 52 original local/online template cases and their commands remain enabled.
Requires Python 3.6 or newer. SDK identity and certificate-tool probes run here;
the complete original test commands run separately in the private suite.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import subprocess
import tarfile
import tempfile
import zipfile
import xml.etree.ElementTree as ET

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()


COMMIT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'
SDK_VERSION = '3.0.103'
RUNTIME_VERSION = '3.0.3'
ASP_COMMIT = 'bd1e14b7d16b798de8a874189c89afed755a266c'
TEST_MANIFEST_SHA256 = '2c3f5dc247b91268a89ed40888c27beb7c6a173d8bae004c2109284684fe1a93'
OFFICIAL_FEEDS = ['https://api.nuget.org/v3/index.json'] + [
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/' + name + '/nuget/v3/index.json'
    for name in ['dotnet-public', 'dotnet-eng', 'dotnet-tools', 'myget-legacy']]


def git(root, *arguments):
    result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                             '-c', 'core.autocrlf=false', '-C', str(root)] + list(arguments),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError('Git verification failed: ' + result.stderr.decode('utf-8', 'replace')[-2000:])
    return result.stdout


def indent_xml(element, depth=0):
    if len(element):
        element.text = '\n' + '  ' * (depth + 1)
        for child in element:
            indent_xml(child, depth + 1)
        element[-1].tail = '\n' + '  ' * depth
    if depth:
        element.tail = '\n' + '  ' * depth


def test_inputs(source, sdk, root, reports, helper):
    ordinary, fingerprint = helper['ordinary_file'], helper['fingerprint']
    control = reports / 'test-inputs'
    control.mkdir()
    patches = Path(__file__).resolve().parents[1] / 'patches/core30-tests'
    manifest_path = ordinary(patches / 'manifest.json')
    if fingerprint(manifest_path)['sha256'] != TEST_MANIFEST_SHA256:
        raise ValueError('The reviewed private test manifest changed')
    manifest = json.loads(manifest_path.read_text())
    original = git(source, 'show', COMMIT + ':smoke-test.sh')
    routed = ordinary(source / 'smoke-test.sh').read_bytes()
    digest = lambda data: hashlib.sha256(data).hexdigest()
    if (manifest['sourceCommit'] != COMMIT or digest(original) != manifest['originalScriptSha256'] or
            digest(routed) != manifest['routedScriptSha256']):
        raise ValueError('The original or architecture-routed upstream suite changed')
    patch = ordinary(patches / manifest['patch'])
    if fingerprint(patch)['sha256'] != manifest['patchSha256']:
        raise ValueError('The private test adapter bytes changed')
    with tempfile.TemporaryDirectory(prefix='core30-test-adapter-', dir=str(root)) as temporary:
        stage = Path(temporary)
        git(stage, 'init', '--quiet')
        script = stage / 'smoke-test.sh'
        script.write_bytes(routed)
        expected_stat = '{0}\t{1}\tsmoke-test.sh'.format(manifest['addedLines'], manifest['removedLines'])
        if git(stage, 'apply', '--numstat', str(patch)).decode().strip() != expected_stat:
            raise ValueError('The private test adapter scope changed')
        git(stage, 'apply', '--check', '--whitespace=error-all', str(patch))
        git(stage, 'apply', '--whitespace=error-all', str(patch))
        adapted = script.read_bytes()
    if digest(adapted) != manifest['adaptedScriptSha256']:
        raise ValueError('The private adapted suite differs')
    function_hashes = {}
    for name in ['doCommand', 'runAllTests', 'runWebTests']:
        pattern = rb'^function ' + name.encode() + rb'\(\) \{\n.*?^\}'
        before = re.search(pattern, routed, re.MULTILINE | re.DOTALL)
        after = re.search(pattern, adapted, re.MULTILINE | re.DOTALL)
        if before is None or after is None or before.group() != after.group():
            raise ValueError('An original test function changed: ' + name)
        function_hashes[name] = digest(before.group())
    private_script = root / 'smoke-test.sh'
    for path, contents in [(control / 'upstream-smoke-test.original.sh', original),
                           (control / 'upstream-smoke-test.routed.sh', routed),
                           (control / 'upstream-smoke-test.adapted.sh', adapted), (private_script, adapted)]:
        with path.open('xb') as output:
            output.write(contents)
    os.chmod(str(private_script), 0o755)
    template = git(source, 'show', COMMIT + ':smoke-testNuGet.Config')
    if ordinary(source / 'smoke-testNuGet.Config').read_bytes() != template:
        raise ValueError('The original upstream NuGet test template changed')
    with (control / 'upstream-nuget.original.Config').open('xb') as output:
        output.write(template)
    config = ET.fromstring(template)
    sources = config.find('packageSources')
    if sources is None:
        raise ValueError('The pinned upstream NuGet template lacks packageSources')
    original_sources = [{'key': row.get('key'), 'value': row.get('value')} for row in sources.findall('add')]
    for child in list(sources):
        sources.remove(child)
    ET.SubElement(sources, 'clear')
    ET.SubElement(sources, 'add', {'key': 'source-built-packages', 'value': 'SOURCE_BUILT_PACKAGES'})
    for index, feed in enumerate(OFFICIAL_FEEDS):
        ET.SubElement(sources, 'add', {'key': 'recorded-official-' + str(index), 'value': feed})
    ET.SubElement(sources, 'add', {'key': 'ProdCon', 'value': 'PRODUCT_CONTRUCTION_PACKAGES'})
    ET.SubElement(sources, 'add', {'key': 'smoke-test feed', 'value': 'SMOKE_TEST_PACKAGE_FEED'})
    indent_xml(config)
    config_path = control / 'NuGet.Config.template'
    ET.ElementTree(config).write(str(config_path), encoding='utf-8', xml_declaration=True)
    probe_home = root / 'probe-home'
    probe_home.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment.update({'HOME': str(probe_home), 'DOTNET_CLI_HOME': str(probe_home),
                        'XDG_RUNTIME_DIR': str(root / 'runtime'), 'DOTNET_MULTILEVEL_LOOKUP': '0'})
    version = subprocess.check_output([str(sdk / 'dotnet'), '--version'], cwd=str(sdk), env=environment).decode().strip()
    runtimes = subprocess.check_output([str(sdk / 'dotnet'), '--list-runtimes'], cwd=str(sdk), env=environment).decode()
    if version != SDK_VERSION or not all(name + ' ' + RUNTIME_VERSION + ' [' in runtimes
                                        for name in ['Microsoft.NETCore.App', 'Microsoft.AspNetCore.App']):
        raise ValueError('The fresh SDK/runtime identity differs')
    tool_candidates = list((sdk / ('sdk/' + SDK_VERSION + '/DotnetTools/dotnet-dev-certs')).glob('**/dotnet-dev-certs.dll'))
    if len(tool_candidates) != 1:
        raise ValueError('The fresh SDK must contain exactly one built-in dev-certs assembly')
    tool = ordinary(tool_candidates[0])
    tool_info = fingerprint(tool)
    component = helper['directory'](source / ('bin/src/AspNetCore.' + ASP_COMMIT))
    if ordinary(component / '.git/HEAD').read_text().strip() != ASP_COMMIT:
        raise ValueError('The certificate producer source identity differs')
    program_relative = 'src/Tools/dotnet-dev-certs/src/Program.cs'
    program = ordinary(component / program_relative)
    if program.read_bytes() != git(source, '--git-dir=' + str(source / '.git/modules/src/AspNetCore.git'),
                                  'show', ASP_COMMIT + ':' + program_relative):
        raise ValueError('The pinned certificate producer entry-point source changed')
    outputs, package_members = [], []
    for output_root in [component / 'artifacts/bin/dotnet-dev-certs', component / 'bin/dotnet-dev-certs']:
        if output_root.exists():
            helper['directory'](output_root)
            for path in sorted(output_root.glob('**/dotnet-dev-certs.dll')):
                row = dict({'path': str(ordinary(path))}, **fingerprint(path))
                row['matchesSdkToolAssembly'] = row['sha256'] == tool_info['sha256']
                outputs.append(row)
    feed = helper['directory'](source / ('bin/obj/' + ARCH['arch'] + '/Release/blob-feed/packages'))
    for package in sorted(feed.glob('dotnet-dev-certs.*.nupkg')):
        if package.name.endswith('.symbols.nupkg'):
            continue
        ordinary(package)
        package_info = fingerprint(package)
        local_packages = []
        for role in ['Shipping', 'NonShipping']:
            candidate = component / 'artifacts/packages/Release' / role / package.name
            if candidate.exists() or candidate.is_symlink():
                candidate_info = fingerprint(ordinary(candidate))
                if candidate_info == package_info:
                    local_packages.append(dict({'path': str(candidate)}, **candidate_info))
        with zipfile.ZipFile(str(package)) as archive:
            for entry in archive.infolist():
                if entry.filename.endswith('/dotnet-dev-certs.dll'):
                    member_hash = digest(archive.read(entry))
                    package_members.append({'path': str(package), 'packageFingerprint': package_info,
                                            'member': entry.filename, 'memberSha256': member_hash,
                                            'matchesSdkToolAssembly': member_hash == tool_info['sha256'],
                                            'matchingLocalPackageOutputs': local_packages,
                                            'wholePackageMatchesLocalProducer': bool(local_packages)})
    local_tool_proven = (any(row['matchesSdkToolAssembly'] for row in outputs) and
                        any(row['matchesSdkToolAssembly'] and row['wholePackageMatchesLocalProducer'] for row in package_members))
    if not local_tool_proven:
        raise ValueError('The SDK certificate tool must equal an actual local ASP build assembly and member of a byte-equal locally produced tool package')
    command = [str(sdk / 'dotnet'), 'dev-certs', 'https', '--help']
    result = subprocess.run(command, cwd=str(sdk), env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with (control / 'sdk-dev-certs-help.log').open('xb') as output:
        output.write(result.stdout)
    if result.returncode:
        raise ValueError('The actual fresh SDK dev-certs HTTPS command is not executable')
    return {'privateScript': dict({'path': str(private_script)}, **fingerprint(private_script)),
            'testManifest': dict({'path': str(manifest_path)}, **fingerprint(manifest_path)),
            'testPatch': dict({'path': str(patch)}, **fingerprint(patch)), 'unchangedTestFunctions': function_hashes,
            'originalNuGetSources': original_sources, 'officialNuGetSources': OFFICIAL_FEEDS,
            'privateNuGetTemplate': dict({'path': str(config_path)}, **fingerprint(config_path)),
            'prodConOverride': '', 'sdkVersion': version, 'sdkRuntimes': runtimes,
            'certificateTool': dict({'path': str(tool), 'sdkArchiveMember': tool.relative_to(sdk).as_posix(),
                                    'producerCommit': ASP_COMMIT, 'producerSource': dict({'path': str(program)}, **fingerprint(program)),
                                    'localBuildOutputs': outputs, 'localPackageMembers': package_members,
                                    'localAssemblyByteEqualityEstablished': local_tool_proven,
                                    'helpProbeCommand': command, 'helpProbeExitCode': result.returncode,
                                    'scope': 'Use the fresh SDK built-in tool. Producer identity and local byte comparisons are recorded separately; origin is not inferred from the archive alone.'}, **tool_info),
            'scope': 'All original local and online tests remain enabled. A private script copy routes the verified source/config and uses the SDK certificate command; source workspace and SDK bytes stay unchanged.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--sdk-archive', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--summarize', action='store_true')
    parser.add_argument('--upstream-exit-code', type=int)
    args = parser.parse_args()
    helper = runpy.run_path(str(Path(__file__).resolve().with_name('prepare-core30-bootstrap.py')))
    directory, ordinary, fingerprint = helper['directory'], helper['ordinary_file'], helper['fingerprint']
    source, inputs, reports = directory(args.source_dir), directory(args.inputs_dir), directory(args.reports_dir)
    archive = ordinary(args.sdk_archive)
    commit = subprocess.check_output(['git', '--no-optional-locks', '-C', str(source), 'rev-parse', 'HEAD']).decode().strip()
    if commit != COMMIT or ordinary(source / 'bin/obj/rootrepo.txt').read_text().strip() != 'core-sdk':
        raise ValueError('The actual completed source graph must be the pinned core-sdk root')
    root = args.test_root
    if (not root.is_absolute() or root.parent != inputs / 'core30-tests' or root.name != reports.name or
            not re.fullmatch(r'test-[A-Za-z0-9_-]+', root.name)):
        raise ValueError('Use an isolated test root selected by the new test report directory')
    for path in [root] + list(root.parents):
        if path.is_symlink():
            raise ValueError('Test control paths must not traverse symlinks')
    report_path = reports / 'core30-smoke-inputs.json'
    sdk = root / 'sdk'
    stable_paths = ['dotnet', 'sdk/' + SDK_VERSION + '/MSBuild.dll', 'sdk/' + SDK_VERSION + '/MSBuild.runtimeconfig.json']
    if args.summarize:
        if args.upstream_exit_code is None:
            raise ValueError('Summarizing requires the actual upstream exit code')
        prepared = json.loads(ordinary(report_path).read_text())
        if prepared['sourceCommit'] != commit or prepared['sdkArchive'] != dict({'path': str(archive)}, **fingerprint(archive)):
            raise ValueError('The tested SDK input binding changed')
        for row in prepared['stableSdkFiles']:
            if fingerprint(ordinary(sdk / row['path'])) != row['fingerprint']:
                raise ValueError('The extracted SDK changed during the test')
        console_path = ordinary(reports / 'test.log')
        console = console_path.read_text(encoding='utf-8', errors='replace')
        smoke_path = root / 'testing-smoke/smoke-test.log'
        smoke = ordinary(smoke_path).read_text(encoding='utf-8', errors='replace') if smoke_path.exists() else ''
        starts = re.findall(r'^starting language (.+), type (.+)$', smoke, re.MULTILINE)
        finishes = re.findall(r'^finished language (.+), type (.+)$', smoke, re.MULTILINE)
        succeeded = re.findall(r'^    (new|restore|run|build|test) succeeded$', smoke, re.MULTILINE)
        failures = re.findall(r'^.*failed with exit code.*$', smoke, re.MULTILINE)
        markers = ['LOCAL RESTORE SOURCE - ALL TESTS PASSED!', 'ONLINE RESTORE SOURCE - ALL TESTS PASSED!', 'ALL TESTS PASSED!']
        console_lines = {line.strip() for line in console.splitlines()}
        completion = all(marker in console_lines for marker in markers)
        certificate_setups = smoke.count('Using the SDK built-in dotnet dev-certs to generate the HTTPS developer certificate')
        inputs_record = prepared['testInputs']
        for key in ['privateScript', 'privateNuGetTemplate']:
            row = inputs_record[key]
            if fingerprint(ordinary(Path(row['path']))) != {name: row[name] for name in ('bytes', 'sha256', 'sha512')}:
                raise ValueError('A recorded private test input changed: ' + key)
        tool = inputs_record['certificateTool']
        if fingerprint(ordinary(Path(tool['path']))) != {name: tool[name] for name in ('bytes', 'sha256', 'sha512')}:
            raise ValueError('The SDK certificate tool changed during tests')
        passed = (args.upstream_exit_code == 0 and completion and len(starts) == 52 and
                  starts == finishes and len(succeeded) == 156 and certificate_setups == 2 and not failures)
        summary = {'schemaVersion': 1, 'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'sourceCommit': commit, 'suite': 'Original Core 3.0 smoke-test.sh local and online suite',
                   'status': 'passed' if passed else 'failed', 'upstreamExitCode': args.upstream_exit_code,
                   'sdkArchive': prepared['sdkArchive'], 'freshSdkDirectory': str(sdk),
                   'routingInput': fingerprint(report_path), 'testLog': fingerprint(console_path),
                   'upstreamSmokeLog': dict({'path': str(smoke_path)}, **fingerprint(smoke_path)) if smoke_path.exists() else None,
                   'casesStarted': len(starts), 'casesFinished': len(finishes), 'expectedCases': 52,
                   'commandsSucceeded': len(succeeded), 'expectedCommands': 156, 'failureLines': failures,
                   'certificateSetups': certificate_setups, 'expectedCertificateSetups': 2, 'suiteExclusions': [],
                   'terminalMarkers': {marker: marker in console_lines for marker in markers},
                   'certificateTool': tool, 'testInputs': inputs_record,
                   'completionMarkerPresent': completion, 'caseSequence': [{'language': a, 'template': b} for a, b in starts],
                   'scope': 'All original local/online non-web and HTTP/HTTPS web cases remain enabled, with recorded official feed and built-in certificate-tool adapters. This shell suite does not contain later source-build license/poison/provenance classes or the later XML-documentation assertion.'}
        if smoke_path.exists():
            with (reports / 'upstream-smoke-test.log').open('xb') as output:
                output.write(smoke_path.read_bytes())
        selected = []
        workspace = root / 'testing-smoke'
        if workspace.is_dir():
            for path in sorted(workspace.iterdir()):
                if path.is_file() and not path.is_symlink() and (path.suffix in ('.log', '.binlog', '.Config') or path.name.startswith('Directory.Build.')):
                    selected.append((path, 'testing-smoke/' + path.name))
        for path in sorted((reports / 'test-inputs').iterdir()):
            if path.is_file() and not path.is_symlink():
                selected.append((path, 'test-inputs/' + path.name))
        retained = reports / 'upstream-smoke-outputs.tar.gz'
        with tarfile.open(str(retained), 'x:gz') as output:
            for path, name in selected:
                output.add(str(path), arcname=name, recursive=False)
        summary['retainedOutputs'] = dict({'path': str(retained), 'files': len(selected),
                                            'scope': 'Only logs and recorded fixture files; no home directory, certificate private keys, SDK extraction or restored-package tree.'}, **fingerprint(retained))
        helper['write_json'](reports / 'core30-smoke-summary.json', summary)
        print(json.dumps({'status': summary['status'], 'casesFinished': len(finishes), 'commandsSucceeded': len(succeeded)}))
        return 0 if passed else 1
    if args.upstream_exit_code is not None:
        raise ValueError('--upstream-exit-code requires --summarize')
    if root.exists() or root.is_symlink() or report_path.exists() or report_path.is_symlink():
        raise ValueError('Refusing an existing SDK extraction, test directory or test report')
    directory(root.parent, create=True)
    root.mkdir(mode=0o700)
    os.chmod(str(root), 0o700)
    sdk.mkdir()
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    os.chmod(str(runtime), 0o700)
    archive_info = fingerprint(archive)
    seen = set()
    with tarfile.open(str(archive), 'r:gz') as stream:
        for member in stream:
            name = helper['safe_name'](member.name)
            if name == '.' and member.isdir():
                continue
            if name in seen:
                raise ValueError('Repeated SDK archive member: ' + name)
            seen.add(name)
            target = sdk / name
            for ancestor in target.parents:
                if ancestor == sdk:
                    break
                if ancestor.is_symlink():
                    raise ValueError('SDK archive member traverses a symbolic link')
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as original, target.open('xb') as output:
                    for block in iter(lambda: original.read(1024 * 1024), b''):
                        output.write(block)
                os.chmod(str(target), member.mode & 0o777)
            elif member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or not helper['contained']((target.parent / member.linkname).resolve(), sdk):
                    raise ValueError('The SDK archive link escapes the fresh SDK tree')
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, str(target))
            else:
                raise ValueError('Unsupported SDK archive member: ' + name)
    if any(relative not in seen for relative in stable_paths):
        raise ValueError('The archive lacks the selected SDK version or executable')
    if fingerprint(archive) != archive_info:
        raise ValueError('The SDK archive changed during its fresh extraction')
    fixture_inputs = test_inputs(source, sdk, root, reports, helper)
    record = {'schemaVersion': 1, 'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sourceCommit': commit, 'rootRepo': 'core-sdk', 'sdkVersion': SDK_VERSION,
              'sdkArchive': dict({'path': str(archive)}, **archive_info), 'freshSdkDirectory': str(sdk),
              'testRoot': str(root), 'stableSdkFiles': [{'path': p, 'fingerprint': fingerprint(ordinary(sdk / p))} for p in stable_paths],
              'environment': {'SOURCE_BUILD_SMOKE_ARCH': ARCH['arch'], 'SOURCE_BUILD_SMOKE_TEST_DIR': str(root / 'testing-smoke'),
                              'DOTNET_CLI_HOME': str(root / 'testing-smoke/home'), 'XDG_RUNTIME_DIR': str(runtime),
                              'SOURCE_BUILD_SMOKE_SOURCE_ROOT': str(source),
                              'SOURCE_BUILD_SMOKE_NUGET_CONFIG': fixture_inputs['privateNuGetTemplate']['path']},
              'arguments': ['--projectOutput', '--configuration', 'Release', '--archiveRestoredPackages', '--dotnetDir', str(sdk), '--prodConBlobFeedUrl', ''],
              'testInputs': fixture_inputs,
              'scope': 'Fresh unmodified SDK archive extraction and a guarded private test adapter for every original local/online case. No SDK product binaries, original source workspace script or test assertions are changed.'}
    helper['write_json'](report_path, record)
    print(json.dumps({'status': 'prepared', 'sdkDirectory': str(sdk), 'archiveSha256': record['sdkArchive']['sha256']}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
