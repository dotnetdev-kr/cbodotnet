"""SDK6 normal producer and cold consumer boundaries.

All version decisions are local: the original SDK6 42-case suite, net6.0 cold
workers, exact six-stage lifecycle and its own archive-only tracing worker.
Only neutral byte/ELF/source/engine parsers are imported from common modules.
No SDK7 construction, original test or native policy is selected at runtime.
"""
import datetime as dt
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import struct
import tarfile
import xml.etree.ElementTree as ET
from musl_source_archive import open_source_archive

ROOT = Path(__file__).resolve().parents[1]
SDK = '6.0.136'
SDK_SOURCE = '1d205826ddc14c8f868eb6373e7a6bafcb9fe5be'
STAGES = ('prepare', 'build', 'scan', 'test', 'collect', 'verify')
FP = {'bytes', 'sha256', 'sha512'}


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


B = module('sdk6_common_readonly_boundary_primitives', 'musl_legacy_admission.py')
P = B.P
require, load, fingerprint, portable = B.require, B.load, B.fingerprint, B.portable
source_member, elf_dynamic, native_command_records = B.source_member, B.elf_dynamic, B.native_command_records


def exact_sdk6(record):
    require(record['sdkVersion'] == SDK and record['architecture'] in ('x64', 'aarch64')
        and record['targetRid'] == P.identity(record['architecture'])['rid'], 'Exact independent SDK6 native identity required')


def validate_source_workers(record, prepare, stages, manifest):
    """Bind every source worker to its archived tree and exact private bootstrap."""
    exact_sdk6(record)
    roots = {row['name']: row for row in manifest['roots']}
    require(len(roots) == len(manifest['roots']) and roots['sdk'].get('commit') == SDK_SOURCE,
            'Unique actual SDK6 source/bootstrap root required')
    host = roots['sdk']['originalPath'] + '/.dotnet'
    project = roots['orchestration']['originalPath']
    require(all(path.startswith('/') and path == posixpath.normpath(path) for path in (host, project)),
            'Normalized actual SDK6 bootstrap/project paths required')
    workers = [('nuget', 'nuget', '451e9bc27184dc49d04e975122c9e7189d525872'),
        ('vstest', 'vstest', 'cc7fb0593127e24f55ce016fb3ac85b5b2857fec'),
        ('localization', 'msbuild-localization', '85d71072f8fa22cc761d6b65954da263364bee4d'),
        ('coreclr', 'runtime', 'f1dd57165bfd91875761329ac3a8b17f6606ad18')]
    for worker, source_root, commit in workers:
        script = '/project/scripts/musl-legacy6-' + worker + '.py'
        calls = [call for call in stages['build']['commands'] if script in call]
        require(len(calls) == 1 and roots[source_root].get('commit') == commit,
                'One exact original SDK6 source worker required: ' + worker)
        call = calls[0]; source = '/work/work/' + source_root
        require(call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run']
                and call.count(prepare['imageId']) == 1
                and [arg for arg in call if arg.startswith('--network')] == ['--network=host']
                and not any(arg.startswith(('--mount', '--volumes-from', '--volume=', '-v', '--device', '--entrypoint')) for arg in call),
                'SDK6 source worker engine/image/network or mount mechanism differs')
        volumes, mapped = {}, []
        for index, value in enumerate(call):
            if value != '--volume': continue
            require(index + 1 < len(call), 'Complete explicit SDK6 source volume required')
            fields = call[index + 1].split(':')
            require(len(fields) in (2, 3) and fields[1] not in volumes, 'Unique SDK6 source volume destination required')
            original, target = fields[:2]; mode = fields[2] if len(fields) == 3 else 'rw'
            require(all(path.startswith('/') and path == posixpath.normpath(path) for path in (original, target)),
                    'Normalized SDK6 source volume paths required')
            volumes[target] = (original, mode)
            require(not any(target.startswith(parent + '/') for parent in (source, '/bootstrap', '/project')),
                    'An additional SDK6 source/bootstrap/project volume shadows an archived input')
            if target == source or source.startswith(target.rstrip('/') + '/'):
                mapped.append(original.rstrip('/') + source[len(target.rstrip('/')):])
        require(mapped == [roots[source_root]['originalPath']] and volumes.get('/bootstrap') == (host, 'ro')
                and volumes.get('/project') == (project, 'ro'),
                'SDK6 worker must use its exact archived source and read-only bootstrap/orchestration roots')
        position = call.index(script)
        require(position > 0 and call[position - 1] == 'python3', 'Original SDK6 Python source worker required')
        args = call[position + 1:]
        require(len(args) % 2 == 0 and len({args[i] for i in range(0, len(args), 2)}) == len(args) // 2,
                'Unique complete SDK6 worker options required')
        output = 'native-runtime' if worker == 'coreclr' else source_root
        expected = {'--sdk': SDK, '--arch': record['architecture'], '--source': source,
            '--dotnet': '/bootstrap/dotnet', '--output': '/delivery/reports/build/' + output}
        if worker in ('localization', 'coreclr'): expected['--build-id'] = record['buildId']
        require(dict(zip(args[::2], args[1::2])) == expected, 'Exact SDK6 source worker arguments differ: ' + worker)


def validate_stages(release, record, prepare):
    exact_sdk6(record)
    stages = {}
    previous = None
    for name in STAGES:
        stage = load(release / 'reports/stages' / (name + '.json'))
        require(stage.get('stage') == name and stage.get('status') == 'passed'
                and isinstance(stage.get('commands'), list)
                and (stage['commands'] or name in {'scan', 'collect'}), 'Actual legacy stage commands are missing')
        start, finish = (dt.datetime.fromisoformat(stage[key]) for key in ('startedAtUtc', 'finishedAtUtc'))
        require(start.tzinfo is not None and finish.tzinfo is not None and finish >= start
                and (previous is None or start >= previous), 'Legacy stage chronology differs')
        previous = finish
        stages[name] = stage
    P.validate_container_engine(release, prepare, stages, P.identity(record['architecture']))
    return stages


def validate_scan_applicability(release, record, manifest):
    exact_sdk6(record)
    report = load(release / 'reports/scan-applicability.json')
    require(set(report) == {'status', 'reason', 'sourceOnly', 'importedInputsRequireInventory', 'sourceCommit', 'sourceGraph'}
            and report['status'] == 'not-applicable' and report['sourceOnly'] is False
            and report['importedInputsRequireInventory'] is True and isinstance(report['reason'], str) and report['reason']
            and report['sourceCommit'] == SDK_SOURCE,
            'Legacy binary-scan applicability must name its actual pinned SDK source graph')
    descriptor = report['sourceGraph']
    require(set(descriptor) == FP | {'path', 'projects'} and descriptor['path'] == 'sdk/source-build.slnf',
            'The actual original regular SDK solution filter is required')
    raw = source_member(release, manifest, descriptor['path'])
    require(all(descriptor[key] == value for key, value in dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            sha512=hashlib.sha512(raw).hexdigest()).items()), 'Original SDK solution filter bytes differ')
    rows = []
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] == descriptor['path']: rows.append(row)
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    require(len(rows) == 1 and rows[0].get('baseline', {}).get('blob') == blob,
            'SDK solution filter differs from its original pinned Git source')
    projects = json.loads(raw)['solution']['projects']
    require(isinstance(projects, list) and projects and len(set(projects)) == len(projects)
            and descriptor['projects'] == projects
            and all(isinstance(path, str) and path and 'BinaryToolKit' not in path for path in projects),
            'Actual legacy regular SDK source graph/scanner applicability differs')


def original_sdk6_cases():
    prefix = 'Microsoft.DotNet.SourceBuild.SmokeTests.'
    cases = {prefix + name for name in ('SdkContentTests.CompareMsftToSb', 'DotNetWatchTests.WatchTests',
                                       'DotNetFormatTests.FormatProject', 'PoisonTests.VerifyUsage')}
    def scenario(group, language, template, commands, no_https=False):
        return (prefix + group + '.VerifyScenario(scenario: TestScenario { Commands = ' + commands
            + ', Language = ' + language + ', NoHttps = ' + str(no_https) + ', ScenarioName = "' + group
            + '", Template = ' + template + ' })')
    for language in ('CSharp', 'FSharp', 'VB'):
        for template, commands in [('Console', 'Build | Run | PublishComplex | PublishR2R'), ('ClassLib', 'Build | Publish'),
                                   ('XUnit', 'Test'), ('NUnit', 'Test'), ('MSTest', 'Test')]:
            cases.add(scenario('BasicScenarioTests', language, template, commands))
    for language in ('CSharp', 'FSharp'):
        for template, commands, no_https in [('Web', 'Build | Run | PublishComplex', False),
                ('Mvc', 'Build | Run | Publish', True), ('WebApi', 'Build | Run | Publish', False)]:
            cases.add(scenario('WebScenarioTests', language, template, commands, no_https))
    for template in ('Razor', 'BlazorWasm', 'BlazorServer', 'Worker', 'Angular'):
        cases.add(scenario('WebScenarioTests', 'CSharp', template, 'None' if template in {'Worker', 'Angular'} else 'Build | Run | Publish'))
    for template in ('BlazorWasm', 'BlazorServer', 'ClassLib', 'Console', 'MSTest', 'Mvc', 'NUnit', 'Web', 'WebApp', 'WebApi', 'Worker', 'XUnit'):
        cases.add(prefix + 'OmniSharpTests.VerifyScenario(template: ' + template + ')')
    require(len(cases) == 42, 'Reviewed SDK6 original test universe differs')
    return cases


def validate_original_smoke(release, record, manifest):
    exact_sdk6(record)
    directory = release / 'reports/test/original-smoke'
    identity = load(directory / 'identity.json')
    require(identity.get('sdkVersion') == record['sdkVersion'] and identity.get('architecture') == record['architecture']
            and identity.get('upstreamCaseCount') == 42
            and all(identity.get('sdkArchive', {}).get(key) == record['sdk'][key] for key in ('bytes', 'sha256')),
            'Original smoke suite tested unrelated SDK bytes')
    prefix = 'installer/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests/'
    index = {}
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'].startswith(prefix):
                require(row.get('baseline') and row['mode'] in {'100644', '100755'}, 'Original smoke source has injected or linked test code')
                index[row['path'][len(prefix):]] = row
    installer = next(root for root in manifest['roots'] if root['name'] == 'installer')
    source_path = prefix.removeprefix('installer/')
    require(index and not any(row['path'].startswith(source_path) for row in installer.get('deleted', [])),
            'An original smoke assertion/source asset was removed')
    claimed = identity.get('sourceFiles', [])
    require(len(claimed) == len(index) and {row['path'] for row in claimed} == set(index)
            and all(set(row) == {'path', 'bytes', 'sha256'} and all(row[key] == index[row['path']][key]
                    for key in ('bytes', 'sha256')) for row in claimed), 'Actual original smoke source inventory differs')
    packer = module('legacy_original_smoke_pristine', 'package-used-source.py')
    config = None
    with open_source_archive(release, manifest) as archive:
        for entry in archive:
            if not entry.name.startswith(prefix):
                continue
            relative = entry.name[len(prefix):]
            require(entry.isfile() and entry.size <= 2 * 1024**2 and relative in index, 'Original smoke source archive member differs')
            raw = archive.extractfile(entry).read()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            require(packer.pristine_blob(index[relative], blob, raw, relative.endswith(('.cmd', '.bat', '.sln'))),
                    'Original smoke assertion/source bytes differ from the pinned installer Git tree')
            if relative == 'Config.cs':
                config = raw.decode('utf-8').replace('\r\n', '\n')
    require(config is not None and config.count("TargetRid.Split('-')[1]") == 1, 'Exact original RID test parser required')
    adjusted = config.replace("TargetRid.Split('-')[1]", "TargetRid.Split('-')[^1]")
    patch = ''.join(difflib.unified_diff(config.splitlines(True), adjusted.splitlines(True), fromfile='a/Config.cs', tofile='b/Config.cs'))
    require((directory / 'test-rid-parser.patch').read_text() == patch, 'Only the reviewed musl RID test-parser adjustment is allowed')
    trx = list((directory / 'trx').glob('*.trx'))
    require(len(trx) == 1, 'One complete original SDK6 smoke TRX required')
    rows = ET.parse(trx[0]).findall('.//{*}UnitTestResult')
    require(len(rows) == 42 and len({row.get('executionId') for row in rows}) == 42
            and {row.get('testName') for row in rows} == original_sdk6_cases(), 'Exact original SDK6 test universe differs')
    smoke = module('legacy_admission_original_smoke', 'ci-net67-evidence.py')
    require(smoke.smoke_results(trx[0]) == load(directory / 'summary.json'), 'Original SDK6 smoke outcomes/skip identity differ')
    fixtures = module('legacy_admission_omnisharp_fixture', 'prepare-net6-test-tools.py')
    expected = fixtures.tool_input('arm64' if record['architecture'] == 'aarch64' else 'x64')
    fixture = load(directory / 'fixture.json')
    archive = directory / 'fixture-inputs' / expected['cacheName']
    require(fixture.get('version') == '1.39.6' and fixture.get('nativeFixtureApphostExecuted') is False
            and all(fixture.get('archive', {}).get(key) == expected[key] == fingerprint(archive)[key] for key in ('bytes', 'sha256'))
            and fixture.get('originalMembers') == fixtures.archive_inventory(archive), 'Exact original managed OmniSharp fixture bytes differ')
    launcher = fixture.get('launcher', {}).get('text', '')
    require(re.fullmatch('#!/bin/sh\nexec "\\$DOTNET_ROOT/dotnet" "[^"\n]+/omnisharp/OmniSharp.dll" "\\$@"\n', launcher)
            and fixture['launcher']['bytes'] == len(launcher.encode())
            and fixture['launcher']['sha256'] == hashlib.sha256(launcher.encode()).hexdigest(),
            'The original OmniSharp fixture must use the exact tested musl host launcher')


def validate_functional(release, record, stages):
    exact_sdk6(record)
    sdk = load(release / 'reports/verify/sdk/verification.json')
    require(sdk.get('sdkVersion') == record['sdkVersion'] and sdk.get('reportedRid') == record['targetRid']
            and sdk.get('verificationStatus') == sdk.get('smokeStatus') == 'passed'
            and sdk.get('archive', {}).get('sha256') == record['sdk']['sha256']
            and all(sdk.get('functionalChecks', {}).get(name) == 'passed' for name in
                    ('consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
                     'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp')),
            'Complete archive-bound offline SDK verification required')
    functional = release / 'reports/verify/functional'
    candidate = load(functional / 'candidate.json')
    require(candidate.get('sdkVersion') == record['sdkVersion'] and candidate.get('architecture') == record['architecture']
            and all(candidate.get('archive', {}).get(k) == record['sdk'][k] for k in FP), 'Functional worker tested different SDK bytes')
    offline = load(functional / 'offline-summary.json')
    require(offline.get('status') == 'passed' and offline.get('network') == 'none'
            and offline.get('uid', 0) > 0 and offline.get('nativeArchitecture') == P.identity(record['architecture'])['machine']
            and offline.get('hostSdkUsed') is False and offline.get('compilerInstalled') is False,
            'Native SDK-free offline functional isolation differs')
    for name, marker in [('sdk-info', record['targetRid']), ('offline-build', None), ('icu', 'ICU 13 CULTURES OK'),
                         ('crypto', 'CRYPTO SHA256 RSA ECDSA AESGCM X509 OID OK'), ('aspnet', 'ASPNET HTTP OK'),
                         ('apphost', 'ICU 13 CULTURES OK'), ('tls', 'SYSTEM TRUST TLS OK')]:
        item = load(functional / (name + '.json'))
        require(item.get('exitCode') == 0 and (marker is None or marker in item.get('output', '')),
                'Legacy functional execution failed: ' + name)
    tls = load(functional / 'tls.json')
    require(tls.get('defaultTrust') is True and tls.get('certificateValidationBypass') is False,
            'Actual system TLS trust is required')
    negative = load(functional / 'negative-certificates.json')
    fixture_hash = '3c88ee9eab40b2e096b96c73316e8af8f3a58ea11b40fa72a84d6c5a4de647cc'
    require(negative.get('status') == 'passed' and negative.get('fixture') ==
            dict(path='negative-certificate-fixture.cs', sha256=fixture_hash)
            and fingerprint(functional / 'negative-certificate-fixture.cs')['sha256'] == fixture_hash
            and negative.get('readyToRun') is True and negative.get('defaultSslStream') is True
            and negative.get('certificateValidationCallback') is False and negative.get('ephemeralUserTrustStore') is True
            and negative.get('uid', 0) > 0 and negative.get('network') == 'none'
            and negative.get('nativeArchitecture') == P.identity(record['architecture'])['machine'],
            'Reviewed default-SslStream negative-certificate fixture required')
    observations = negative.get('commands', [])
    require(len(observations) == 2 and all(item.get('exitCode') == 0 for item in observations),
            'Negative certificate fixture compilation/execution failed')
    output = (functional / 'negative-execution.log').read_text()
    require(all(marker in output for marker in ('PASS trusted-control connects',
        'PASS untrusted-self-signed fails closed', 'PASS expired fails closed', 'PASS wrong-hostname fails closed',
        'PASS invalid-CA managed chain fails closed', 'PASS invalid-CA TLS fails closed',
        'PASS all certificate cases; no remote validation callback')), 'Negative certificate assertions are incomplete')
    calls = stages['verify']['commands']
    for mode, network in [('offline', '--network=none'), ('tls', '--network=host')]:
        require(any('/project/scripts/musl-legacy-functional.py' in call and mode in call and network in call for call in calls),
                'Actual functional network boundary is absent')


def validate_verification_boundary(release, record, prepare, stages):
    exact_sdk6(record)
    native = P.identity(record['architecture'])
    for name, field in [('image.json', 'imageId'), ('verify_image.json', 'verificationImageId')]:
        image = load(release / 'reports/prepare' / name)
        require(len(image) == 1 and image[0].get('Id') == prepare.get(field)
                and image[0].get('Architecture') == native['image'] and image[0].get('Os') == 'linux',
                'Prepared immutable native legacy image differs')
    calls = [call for call in stages['verify']['commands'] if call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run']]
    require(len(calls) == 4, 'Exactly four reviewed cold verification workers required')
    workers = {}
    allowed_environment = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2',
        PYTHONDONTWRITEBYTECODE='1', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1')
    for call in calls:
        require(call.count(prepare['verificationImageId']) == 1
                and not any(value.startswith(('--mount', '--volumes-from', '--volume=', '-v', '--device', '--entrypoint')) for value in call),
                'Every final SDK worker must use the frozen SDK-free image')
        mounts, environment = {}, {}
        for index, value in enumerate(call):
            require(not value.startswith('-e') and (not value.startswith('--env') or value == '--env'),
                    'Cold SDK6 worker may use only explicit reviewed --env options')
            if value == '--volume':
                fields = call[index + 1].split(':')
                require(len(fields) in {2, 3} and fields[1] not in mounts, 'Unexpected cold verifier mount syntax')
                mounts[fields[1]] = fields[2] if len(fields) == 3 else 'rw'
            if value == '--env':
                require(index + 1 < len(call), 'Complete cold SDK6 environment option required')
                key, separator, data = call[index + 1].partition('=')
                require(separator and key not in environment and allowed_environment.get(key) == data,
                        'Cold SDK6 worker inherited an unreviewed runtime/bootstrap environment override')
                environment[key] = data
        require(environment == allowed_environment, 'Complete original cold SDK6 worker environment required')
        require(mounts == {'/project': 'ro', '/delivery': 'rw', '/home/build': 'rw', '/diag': 'rw'},
                'Cold verification exposes a build/source/bootstrap workspace')
        scripts = [script for script in ('verify-sdk.sh', 'musl-sdk-audit.py', 'musl-legacy-functional.py')
                   if '/project/scripts/' + script in call]
        require(len(scripts) == 1 and call.count('--archive') == 1
                and call[call.index('--archive') + 1] == '/delivery/' + record['sdk']['name'],
                'Cold verification worker tested an unrelated archive')
        worker = scripts[0]
        if worker == 'musl-legacy-functional.py':
            modes = [mode for mode in ('offline', 'tls') if mode in call]
            require(len(modes) == 1, 'One exact functional worker mode required')
            worker += ':' + modes[0]
        require(worker not in workers, 'Duplicate cold verification worker')
        workers[worker] = call
        network = '--network=host' if worker.endswith(':tls') else '--network=none'
        require([value for value in call if value.startswith('--network')] == [network],
                'Cold verification network boundary differs')
    require(set(workers) == {'verify-sdk.sh', 'musl-sdk-audit.py', 'musl-legacy-functional.py:offline', 'musl-legacy-functional.py:tls'},
            'A required cold verification worker is missing')
    call = workers['verify-sdk.sh']
    for flag, expected in [('--expected-version', record['sdkVersion']), ('--expected-rid', record['targetRid']),
                           ('--framework', 'net6.0'), ('--arch', 'arm64' if record['architecture'] == 'aarch64' else 'x64')]:
        require(call.count(flag) == 1 and call[call.index(flag) + 1] == expected, 'Cold SDK verifier version/RID/framework differs')


def validate_lttng(release, record, prepare, stages):
    exact_sdk6(record)
    directory = release / 'reports/test/native-lttng'
    identity, results = load(directory / 'identity.json'), load(directory / 'results.json')
    for report in (identity, results):
        require(report.get('schemaVersion') == 1 and report.get('kind') == 'legacy-musl-lttng-session-proof'
                and report.get('sdkVersion') == record['sdkVersion'] and report.get('architecture') == record['architecture']
                and report.get('readyToRun') is True and report.get('runtimeOverlaysAccepted') is False
                and report.get('hostSdkUsed') is False and report.get('qualificationAllowed') is False
                and report.get('sourceAdmissionAllowed') is False,
                'Actual final-archive LTTng proof must retain normal ReadyToRun and no runtime overlays')
        require(all(report.get('archive', {}).get(key) == record['sdk'][key] for key in FP),
                'LTTng session tested different final SDK archive bytes')
    require(identity.get('archive', {}).get('name') == record['sdk']['name'] and identity.get('uid', 0) > 0
            and results.get('status') == 'passed' and results.get('managedExitCode') == 0,
            'Native non-root final archive LTTng workload must complete successfully')
    fixture = module('legacy_lttng_reviewed_fixture', 'musl-legacy6-lttng.py')
    raw = (directory / 'Program.cs').read_bytes()
    require(raw == fixture.PROGRAM.encode() and results.get('programSha256') == hashlib.sha256(raw).hexdigest(),
            'Reviewed GC workload source differs')
    commands = native_command_records(directory, results)
    require(set(commands) == {'cold-build', 'sessiond', 'create', 'enable', 'start', 'tracepoints', 'stop', 'destroy', 'decoded'},
            'The actual cold SDK build and complete LTTng session command sequence are required')
    build = commands['cold-build']['command']
    require(len(build) == 5 and build[1] == 'build' and build[3:] == ['-c', 'Release']
            and build[0].startswith('/tmp/cbodotnet-legacy-lttng-') and build[0].endswith('/sdk/dotnet'),
            'LTTng workload must compile with the freshly extracted final SDK')
    work = build[0].removesuffix('/sdk/dotnet')
    require(build[2] == work + '/app/Probe.csproj'
            and results.get('managedCommand') == [build[0], work + '/app/bin/Release/net6.0/Probe.dll']
            and (directory / 'managed.stdout.log').read_text().splitlines() == ['READY', 'DONE'],
            'The actual final runtime did not execute the reviewed GC workload to completion')
    expected = {'sessiond': ['lttng-sessiond', '--daemonize', '--no-kernel'],
        'create': ['lttng', 'create', 'cbodotnet-legacy6', '--output=/delivery/reports/test/native-lttng/session'],
        'enable': ['lttng', 'enable-event', '--userspace', '--all'], 'start': ['lttng', 'start'],
        'tracepoints': ['lttng', 'list', '--userspace'], 'stop': ['lttng', 'stop'],
        'destroy': ['lttng', 'destroy', 'cbodotnet-legacy6'],
        'decoded': ['babeltrace2', '/delivery/reports/test/native-lttng/session']}
    require(all(commands[name]['command'] == command for name, command in expected.items()),
            'Actual LTTng session observed an unrelated source or output')
    decoded = commands['decoded']['text'].splitlines()
    observed = dict(dotnetEvents=sum('DotNETRuntime:' in line for line in decoded),
        gcStartEvents=sum('DotNETRuntime:GCStart' in line for line in decoded),
        gcEndEvents=sum('DotNETRuntime:GCEnd' in line for line in decoded),
        controlEvents=sum(fixture.CONTROL in line for line in decoded), totalDecodedLines=len(decoded),
        listedDotnetTracepoints=sum('DotNETRuntime' in line for line in commands['tracepoints']['text'].splitlines()))
    require(results.get('observed') == observed and observed['dotnetEvents'] > 0 and observed['gcStartEvents'] >= 80
            and observed['gcEndEvents'] >= 80 and observed['controlEvents'] == 1 and observed['listedDotnetTracepoints'] > 0,
            'Actual decoded .NET GC events and the independent native tracing control must both be present')
    image = load(release / 'reports/prepare/tracing-image.json')
    require(len(image) == 1 and image[0].get('Id') == prepare.get('tracingImageId')
            and image[0].get('Architecture') == P.identity(record['architecture'])['image'] and image[0].get('Os') == 'linux',
            'Immutable native SDK-free tracing image identity differs')
    calls = [call for call in stages['test']['commands'] if '/project/scripts/musl-legacy6-lttng.py' in call]
    require(len(calls) == 1, 'One actual final-archive tracing test worker is required')
    call = calls[0]
    require(call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run']
            and call.count(prepare['tracingImageId']) == 1 and '--network=none' in call
            and [arg for arg in call if arg.startswith('--network')] == ['--network=none']
            and not any(arg.startswith(('--mount', '--volumes-from', '--volume=', '-v', '--device', '--entrypoint')) for arg in call),
            'Tracing test must run offline in the frozen SDK-free image without host overrides')
    mounts, environment = {}, {}
    allowed_environment = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2',
        PYTHONDONTWRITEBYTECODE='1', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1')
    for position, arg in enumerate(call):
        require(not arg.startswith('-e') and (not arg.startswith('--env') or arg == '--env'),
                'Tracing SDK6 worker may use only explicit reviewed --env options')
        if arg == '--volume':
            fields = call[position + 1].split(':')
            require(len(fields) in {2, 3} and fields[1] not in mounts, 'Unexpected tracing worker volume syntax')
            mounts[fields[1]] = fields[2] if len(fields) == 3 else 'rw'
        if arg == '--env':
            key, separator, value = call[position + 1].partition('=')
            require(separator and key not in environment and allowed_environment.get(key) == value,
                    'Tracing worker inherited an unreviewed SDK/library/runtime environment override')
            environment[key] = value
    require(environment == allowed_environment, 'Complete original tracing SDK6 worker environment required')
    require(mounts == {'/project': 'ro', '/delivery': 'rw', '/home/build': 'rw', '/diag': 'rw'},
            'Tracing worker exposes a build/source/bootstrap workspace')
    for flag, value in [('--sdk', record['sdkVersion']), ('--arch', record['architecture']),
                        ('--archive', '/delivery/' + record['sdk']['name']), ('--output', '/delivery/reports/test/native-lttng')]:
        require(call.count(flag) == 1 and call[call.index(flag) + 1] == value,
                'Tracing worker archive/native CPU/output identity differs')


def validate_elf_closure(release, record, profile, report):
    """Recompute dynamic imports from every actual ELF and close its graph."""
    exact_sdk6(record)
    native = P.identity(record['architecture'])
    loader = '/lib/ld-musl-' + native['machine'] + '.so.1'
    machine = 'AArch64' if record['architecture'] == 'aarch64' else 'Advanced Micro Devices X86-64'
    closure = report.get('closure', {})
    require(report.get('violations') == [] and report.get('emulation') is False
            and report.get('nativeArchitecture') == native['machine']
            and closure.get('schemaVersion') == 1 and closure.get('scope') == 'musl-complete-payload-elf-closure'
            and closure.get('native') is True and closure.get('libc') == 'musl'
            and closure.get('architecture') == record['architecture'] and closure.get('targetRid') == record['targetRid']
            and closure.get('symlinks') == report.get('symlinks') == [], 'Native complete ordinary ELF closure identity differs')
    outer = {row['path']: row for row in report['files']}
    actual = P.sdk_elf_inventory(release / record['sdk']['name'], 62 if record['architecture'] == 'x64' else 183, loader)
    require(len(outer) == len(report['files']) == len(actual) == report.get('elfCount') and outer.keys() == actual.keys()
            and all(all(outer[name].get(key) == value for key, value in row.items()) for name, row in actual.items()),
            'Every actual SDK6 ELF must bind its unchanged archive bytes, native CPU and interpreter')
    payload = {row['path']: row for row in closure.get('elfFiles', [])}
    require(len(payload) == len(closure.get('elfFiles', [])) == closure.get('hostElfCount') == len(outer)
            and set(payload) == set(outer), 'Inner/outer native ELF inventories differ')
    abi = module('legacy_actual_elf_abi_policy', 'musl_archive.py')
    found = set()
    with tarfile.open(release / record['sdk']['name'], 'r:gz') as archive:
        for entry in archive:
            name = entry.name.removeprefix('./')
            if name not in payload:
                continue
            require(entry.isfile() and entry.size <= 512 * 1024**2, 'One ordinary bounded actual ELF member required')
            raw = archive.extractfile(entry).read()
            dynamic = elf_dynamic(raw)
            require(not any(name == 'libc.so.6' or name.startswith('ld-linux') or 'gcompat' in name
                            for name in dynamic['needed']), 'Actual native ELF imports a forbidden glibc compatibility provider')
            labels = abi.reviewed_gcc_abi_labels(dynamic)
            elf_type = {1: 'REL', 2: 'EXEC', 3: 'DYN'}.get(struct.unpack_from('<H', raw, 16)[0])
            require(all(all(row.get(key) == value for key, value in dynamic.items())
                        and row.get('reviewedAbiVersionLabels') == labels and row.get('machine') == machine
                        and row.get('elfClass') == 'ELF64' and row.get('elfType') == elf_type
                        and row.get('interpreter') in (None, loader)
                        for row in (outer[name], payload[name])), 'Actual ELF dynamic dependency/version metadata differs')
            require(payload[name].get('disposition') == 'host-runtime-or-tool'
                    and payload[name].get('sha256') == outer[name]['sha256']
                    and payload[name].get('size') == len(raw)
                    and payload[name].get('interpreter') == actual[name]['interpreter']
                    and payload[name].get('dependencies') == outer[name].get('dependencies'), 'Actual native ELF payload fingerprint/disposition differs')
            found.add(name)
    require(found == set(payload), 'Actual native ELF dependency scan is incomplete')
    reference = profile['stockAlpine']
    expected_profile = 'profiles/dotnet-10.0.403-linux-musl-' + record['architecture'] + '.json'
    require(reference.get('referenceProfile') == expected_profile
            and fingerprint(ROOT / expected_profile)['sha256'] == reference.get('referenceProfileSha256'),
            'Reviewed frozen stock Alpine package profile differs')
    stock_profile = load(ROOT / expected_profile)
    packages = {row['P']: row['V'] for row in stock_profile['runtimePackages']}
    # The frozen base image and direct runtime APKs also bring stock providers
    # such as musl/zlib. Reuse the common reviewed transitive-provider pins and
    # authenticate every selected version against the frozen APK indexes.
    require(all(name not in packages or packages[name] == version for name, version in abi.RUNTIME_PACKAGES.items()),
            'Stock transitive provider versions conflict with the frozen runtime profile')
    packages.update(abi.RUNTIME_PACKAGES)
    available = set()
    for index in stock_profile['apkIndexes'].values():
        path = ROOT / index['snapshotPath']
        require(fingerprint(path)['sha256'] == index['sha256'], 'Frozen stock APK index bytes differ')
        with tarfile.open(path, 'r:gz') as archive:
            incoming = archive.extractfile('APKINDEX')
            raw = incoming.read(32 * 1024**2 + 1)
            require(len(raw) <= 32 * 1024**2, 'Frozen APK index exceeds its bound')
        for block in raw.decode().split('\n\n'):
            fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            if 'P' in fields and 'V' in fields:
                available.add((fields['P'], fields['V']))
    require(all((name, version) in available for name, version in packages.items()), 'Reviewed stock provider is absent from the frozen APK indexes')
    require(not packages.keys() & {'gcompat', 'glibc', 'libc6-compat'}, 'Glibc provider profiles are forbidden')
    libraries = {row['path']: row for row in closure.get('stockLibraries', [])}
    require(libraries and len(libraries) == len(closure['stockLibraries']) and loader in libraries,
            'Complete stock native provider inventory required')
    for path, row in libraries.items():
        require(path == posixpath.normpath(path) and path.startswith(('/lib/', '/usr/lib/', '/usr/local/lib/'))
                and row.get('machine') == machine and row.get('elfClass') == 'ELF64'
                and row.get('interpreter') in (None, loader) and row.get('elfType') in {'DYN', 'EXEC', 'REL'}
                and row.get('size', 0) > 0 and re.fullmatch('[a-f0-9]{64}', row.get('sha256', ''))
                and any(row.get('apkOwner') == path + ' is owned by ' + package + '-' + version for package, version in packages.items())
                and row.get('reviewedAbiVersionLabels') == abi.reviewed_gcc_abi_labels(row),
                'Native dependency is not attributed to an exact frozen stock APK provider')
    used = set()
    for row in list(payload.values()) + list(libraries.values()):
        for runpath in row.get('runpaths', []):
            require(isinstance(runpath, str) and runpath and '\0' not in runpath, 'Unsafe native loader search path')
            origin = str(PurePosixPath(row['path']).parent)
            if not origin.startswith('/'):
                origin = '/payload/' + origin
            expanded = runpath.replace('${ORIGIN}', origin).replace('$ORIGIN', origin)
            resolved = posixpath.normpath(expanded)
            require('$' not in expanded and expanded.startswith('/')
                    and (resolved in {'/lib', '/usr/lib', '/usr/local/lib'} or resolved == '/payload' or resolved.startswith('/payload/')),
                    'Native loader search path escapes reviewed stock/payload roots')
        dependencies = row.get('dependencies', [])
        require([dependency.get('needed') for dependency in dependencies] == row.get('needed')
                and len(set(row['needed'])) == len(row['needed']), 'Native dependency edges omit/duplicate an actual DT_NEEDED import')
        for dependency in dependencies:
            require(set(dependency) == {'needed', 'resolved', 'provider', 'sha256'}, 'Closed native dependency edge required')
            if dependency['provider'] == 'stock-system':
                target = libraries.get(dependency['resolved'])
                require(target is not None and target['sha256'] == dependency['sha256'], 'Stock provider hash/closure edge differs')
                used.add(dependency['resolved'])
            else:
                matches = [target for name, target in payload.items() if dependency['resolved'].endswith('/' + name)]
                require(dependency['provider'] == 'payload' and len(matches) == 1
                        and matches[0]['sha256'] == dependency['sha256'], 'Payload native provider hash/closure edge differs')
            if any(label['file'] == dependency['needed'] for label in row['reviewedAbiVersionLabels']):
                target = libraries.get(dependency['resolved'], {})
                require(dependency['provider'] == 'stock-system' and dependency['needed'] == 'libgcc_s.so.1'
                        and 'GLIBC_2.0' in target.get('versionDefinitions', [])
                        and target.get('apkOwner', '').endswith(' is owned by libgcc-' + packages['libgcc']),
                        'Reviewed GCC unwind ABI label has the wrong actual stock provider')
    require(used == set(libraries), 'Unreferenced/incomplete native system closure inventory')


