#!/usr/bin/env python3
"""Portable, fail-closed gates for fresh .NET 5 and Core 3.x CI deliveries."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

CONFIG = {
    'net5': ('5.0.214', '5.0.17', 'd414ecb2d997a9b3f38aaaeddace30ca097e546d'),
    'core31': ('3.1.426', '3.1.32', 'ab8b115b5658237ee8916ae3586600b39fb2fd19'),
    'core30': ('3.0.103', '3.0.3', '40de72d1087a1d05dfd39c87f888a0611ec6c60f'),
}
CHECKS = {'consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
          'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp'}
IDENTITY = ('projectCommit', 'sourceCommit', 'sdkVersion', 'buildId', 'buildRevision', 'runId', 'runAttempt')


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path] + list(path.parents)),
            'Ordinary absolute evidence file required: ' + str(path))
    return path


def member(root, name):
    parsed = PurePosixPath(name)
    require(isinstance(name, str) and parsed.parts and not parsed.is_absolute() and '..' not in parsed.parts
            and parsed.as_posix() == name and '\\' not in name and ':' not in name, 'Unsafe evidence path')
    return ordinary(root.joinpath(*parsed.parts))


def fp(path):
    ordinary(path); before = path.stat(); hashes = {key: hashlib.new(key) for key in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            for value in hashes.values():
                value.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Evidence changed during hashing')
    return dict(bytes=after.st_size, **{key: value.hexdigest() for key, value in hashes.items()})


def checked(root, row):
    path = member(root, row['path'])
    require(all(row.get(key) == value for key, value in fp(path).items()), 'Evidence digest differs: ' + row['path'])
    return path


def record(root, path):
    return dict(path=path.relative_to(root).as_posix(), **fp(path))


def load(path):
    require(ordinary(path).stat().st_size < 128 * 1024 * 1024, 'Oversized JSON evidence')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def snapshot_tree(release, rows):
    tree = {}; seen = set(); prefix = 'reports/ci-inputs/project/'
    for row in rows:
        require(row['path'].startswith(prefix), 'Frozen control escapes its root')
        name = row['path'][len(prefix):]; path = checked(release, row)
        require(name not in seen and row['gitMode'] in ('100644', '100755'), 'Duplicate/unsupported frozen control')
        seen.add(name); blob = git_hash('blob', path.read_bytes())
        require(blob == row['gitBlob'], 'Frozen control differs from its real Git blob')
        parent = tree; parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
            require(isinstance(parent, dict), 'Git tree/file collision')
        require(parts[-1] not in parent, 'Git tree/file collision')
        parent[parts[-1]] = (row['gitMode'], blob)
    def digest(entries):
        data = b''
        for name, value in sorted(entries.items(), key=lambda item: item[0].encode() + (b'/' if isinstance(item[1], dict) else b'')):
            mode, sha = ('40000', digest(value)) if isinstance(value, dict) else value
            data += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
        return git_hash('tree', data)
    return digest(tree)


def cold_feed_proof(cold, commit):
    require(cold['status'] == 'passed' and cold['sourceCommit'] == commit and cold['planOnly'] is False
            and cold['allowColdFeed'] is True and cold['feedInitiallyAbsent'] is True and cold['emptyFeed'] is True
            and cold['publishedPackagesProven'] == cold['publishedPackagesQuarantined'] == 0
            and cold['packages'] == cold['moved'] == [] and cold['recoveryDirectory'] is None
            and cold['feedCreated'] is False and cold['syntheticPackageOutputsCreated'] is False,
            'Fresh Core3.0 CI must begin with a genuinely absent feed and no historical package quarantine')


def test_report_path(family):
    filename = {'net5': 'net5-tests-result.json', 'core31': 'core31-tests-result.json', 'core30': 'core30-smoke-summary.json'}[family]
    directory = 'test-product' if family == 'core30' else 'product-test'
    return 'reports/test/' + directory + '/' + filename


def validate(release, family, expected):
    sdk, runtime, commit = CONFIG[family]
    require(release.is_absolute() and release.is_dir() and not any(p.is_symlink() for p in [release] + list(release.parents)), 'Ordinary release directory required')
    entries = list(release.rglob('*'))
    require(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in entries), 'Delivery links/special entries are forbidden')
    snapshot_path = member(release, 'reports/ci-inputs/snapshot.json'); snapshot = load(snapshot_path)
    require(snapshot['family'] == family and snapshot['sdkVersion'] == sdk and snapshot['sourceCommit'] == commit
            and snapshot['projectInitiallyPristine'] is True and snapshot['sourceInitiallyPristine'] is True, 'Fresh pinned source snapshot required')
    require(snapshot.get('executionContext') == 'github-actions' and snapshot.get('workflowRef', '').endswith('/.github/workflows/sdk-matrix.yml@refs/heads/main'),
            'Actual trusted main workflow identity is required')
    for key, value in expected.items():
        require(snapshot[key] == value, 'Unexpected delivery identity: ' + key)
    require(all(re.fullmatch(r'[1-9]\d*', str(snapshot[key])) for key in ('buildRevision', 'runId', 'runAttempt'))
            and re.fullmatch(r'20\d{6}\.[1-9]\d*', snapshot['buildId']), 'Actual positive run/build identities required')
    tree = snapshot_tree(release, snapshot['projectFiles'])
    commit_object = checked(release, snapshot['projectCommitObject']).read_bytes()
    require(git_hash('commit', commit_object) == snapshot['projectCommit'] and commit_object.startswith(('tree ' + tree + '\n').encode()),
            'Frozen orchestration does not bind the expected Git commit')
    original_profile = load(checked(release, snapshot['profile']))
    require(original_profile['source']['commit'] == commit and original_profile['sdkVersion'] == sdk, 'Pinned profile differs')
    manifest_path = member(release, 'build-manifest.json'); manifest = load(manifest_path)
    require(manifest['sdkVersion'] == sdk and manifest['targetRid'] == 'linux-arm64' and manifest['sourceOnly'] is True
            and manifest['buildRevision'] == snapshot['buildRevision']
            and manifest['source']['actualCommit'] == manifest['source']['expectedCommit'] == commit
            and manifest['source']['commitVerified'] is True and manifest['construction']['upstreamSharedRuntimeReused'] is False,
            'Final SDK/source/construction identity differs')
    archive = manifest['sdkArchive']; archive_path = checked(release, archive)
    require(archive['copiedWithoutModification'] is True and archive['bodyIdentity']['sdkVersion'] == sdk
            and archive['bodyIdentity']['runtimeVersion'] == runtime and archive['bodyIdentity']['targetRid'] == 'linux-arm64',
            'The actual SDK body identity differs')
    require(archive['path'] == 'cbodotnet-sdk-' + sdk + '-linux-arm64-build.' + snapshot['buildRevision'] + '.tar.gz', 'Unexpected final archive name')
    for name in ('SHA256SUMS', 'SHA512SUMS'):
        algorithm = 'sha256' if name == 'SHA256SUMS' else 'sha512'
        require(member(release, name).read_text() == archive[algorithm] + '  ' + archive['path'] + '\n', 'Checksum file differs')
    report_rows = manifest['reports']['files']; names = [row['path'] for row in report_rows]
    require(len(names) == len(set(names)), 'Duplicate final report inventory')
    actual = {p.relative_to(release / 'reports').as_posix() for p in entries if p.is_file() and (release / 'reports') in p.parents}
    require(actual == set(names), 'Final report membership changed after collection')
    for row in report_rows:
        checked(release / 'reports', row)
    stages = {}
    for name in ('prepare', 'build', 'scan', 'test', 'verify'):
        data = load(member(release, 'reports/ci/stages/' + name + '.json'))
        require(data['stage'] == name and data['status'] == 'passed' and data['exitCode'] == 0 and data['commands']
                and all(data.get(key) == snapshot[key] for key in IDENTITY), 'Actual stage did not pass: ' + name)
        require(data['environment']['nativeArchitecture'] == 'aarch64' and data['environment']['uid'] > 0, 'Native nonroot product execution required')
        stages[name] = data
    status = load(member(release, 'reports/build/product-build/build-status.json'))
    require(status['exitCode'] == 0 and status['sourceCommit'] == commit and status['sourceOnly'] is True,
            'Original upstream root graph did not complete')
    require(any('build' in command and any(str(v).endswith(('build-ci-net5.sh', 'build-core31.sh', 'build-core30.sh')) for v in command)
                for command in stages['build']['commands']), 'Normal upstream graph invocation is missing')
    image = load(member(release, 'reports/prepare/build-image.json'))
    require(len(image) == 1 and image[0]['Architecture'] == 'arm64' and image[0]['Os'] == 'linux'
            and stages['build']['imageId'] == manifest['buildImage']['id'] == image[0]['Id'], 'Actual native build image differs')
    policy = load(member(release, 'reports/prepare/seccomp.json'))
    require(policy['seccompUnconfined'] is False and policy['allOtherRulesUnchanged'] is True and policy['addedRuleCount'] in (0, 1),
            'Unreviewed build seccomp changes')
    for key, filename in (('basePolicy', 'seccomp-base-policy.json'), ('outputPolicy', 'seccomp-policy.json')):
        require(all(policy[key][name] == value for name, value in fp(member(release, 'reports/prepare/' + filename)).items()),
                'Actual bounded build policy bytes differ')
    sysroot = load(member(release, 'reports/sysroot/sysroot-provenance.json'))
    current = load(member(release, 'reports/sysroot/current-validation.json'))
    require(sysroot['sourceCommit'] == commit and sysroot['packageSignatureVerification'] is True and sysroot['emulation'] is False
            and current['status'] == 'passed' and current['files'] > 0 and current['symlinks'] > 0, 'Authenticated complete sysroot verification is absent')
    producer_log = member(release, 'reports/sysroot/' + Path(sysroot['logFile']).name).read_text(errors='replace')
    require(('Release signature verified' in producer_log or 'Valid Release signature' in producer_log)
            and '--no-check-gpg' not in producer_log and '--skipsigcheck' not in producer_log, 'Actual authenticated sysroot producer did not pass')
    keys = load(member(release, 'reports/sysroot/producer-inputs.json'))['keyrings']
    require(len(keys) == 3, 'All three producer signing keyrings must be retained')
    for key in keys:
        checked(release, key)
    analysis = load(member(release, 'reports/prepare/analysis/analysis.json'))
    require(analysis['status'] == 'passed' and analysis['sdkVersion'] == '9.0.121'
            and analysis['archiveSha512'] == '2c8288568d9827371d8d0daf0578590a956d955bef783bf1403953f8a816851f03be7aa366b6649e7cda77a8e7359ac3fc46fac87f010d71b6e7415a9457add5',
            'Pinned isolated analysis tool preparation is absent')
    tests = load(member(release, test_report_path(family)))
    require(tests['status'] == 'passed' and tests['upstreamExitCode'] == 0 and tests['suiteExclusions'] == []
            and tests['sdkArchive']['sha256'] == archive['sha256'], 'Complete upstream suite did not pass on the delivered SDK')
    if family == 'core30':
        require(status['postBuildOfflineSourceBundleDownloadsSkipped'] is True
                and '/p:CbodotnetSkipSourceBundleDownloads=true' in member(release, 'reports/build/product-build/build-command.txt').read_text()
                and manifest['profile']['contents']['build']['ciPostBuildSourceBundleStaging']['actualSkipped'] is True,
                'Explicit online SDK-only post-build staging command/effective profile proof is absent')
        cold = load(member(release, 'reports/build/product-build/retry-inputs/core30-retry-inputs.json'))
        cold_feed_proof(cold, commit)
        require(tests['casesStarted'] == tests['casesFinished'] == tests['expectedCases'] == 52
                and tests['commandsSucceeded'] == 156 and tests['certificateSetups'] == 2, 'Original Core3.0 suite coverage differs')
    else:
        cases = 68 if family == 'net5' else 52
        require(tests['templateCasesStarted'] == tests['templateCasesFinished'] == tests['expectedTemplateCases'] == cases
                and tests['certificateSetupsCompleted'] == 2 and all(tests['terminalMarkers'].values()), 'Original upstream suite coverage differs')
    prebuilt = load(member(release, 'reports/scan/prebuilt-report.json'))
    require(prebuilt['status'] == 'passed' and prebuilt['reports'] and prebuilt['scope'], 'Original prebuilt reports were not preserved')
    origin = load(member(release, 'reports/construction/origin-evidence.json'))
    require(origin['status'] == 'passed' and origin['sourceCommit'] == commit and origin['freshCurrentGenerationOnly'] is True
            and origin['sdkArchive']['sha256'] == archive['sha256'] and len(origin['components']) == 2, 'Fresh local framework origin proof is absent')
    for component, framework in zip(origin['components'], ('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App')):
        require(component['framework'] == framework and component['originVerified'] is True and component['allArchiveFingerprintsMatch'] is True
                and component['completedLocalCopy']['completed'] is True and component['sharedMembersCompared'] > 100
                and len(component['members']) == component['sharedMembersCompared'], 'Complete local framework evidence differs')
        require(all(component[key]['sha256'] == component['producerArchive']['sha256'] for key in ('producerArchive', 'localInputArchive')),
                'Producer/local archive identities differ')
        retained = member(release, 'reports/construction/retained-inputs/' + Path(component['capturedDestination']['retained']).name.split('-', 1)[1])
        require(fp(retained)['sha256'] == component['producerArchive']['sha256'], 'Captured genuine framework archive differs')
    if family != 'net5':
        split = load(member(release, 'reports/construction/native-component-origin.json'))
        require(split['status'] == 'passed' and split['sourceCommit'] == commit and split['freshCurrentGenerationOnly'] is True
                and split['finalSdkCompared'] is True and split['sdkArchive']['sha256'] == archive['sha256']
                and split['completeRuntimePayloadCoverage']['verified'] is True
                and split['counts'] == {'coreFxManagedPackageAssemblies': 164, 'coreFxNativeImageTransformations': 162,
                                        'nativeAndCoreLibPayloads': 13, 'coreSetupHostOutputs': 3, 'runtimeArchiveMembersVerified': 180},
                'Fresh split-runtime native construction is incomplete')
    native = {}
    for name in ('ubuntu22', 'ubuntu24', 'debian13'):
        data = load(member(release, 'reports/verify-' + name + '/verification.json'))
        rid = 'ubuntu.22.04-arm64' if family == 'core31' and name == 'ubuntu22' else 'linux-arm64'
        framework = 'net5.0' if family == 'net5' else 'netcoreapp' + ('3.1' if family == 'core31' else '3.0')
        require(data['verificationStatus'] == data['smokeStatus'] == 'passed' and data['sdkVersion'] == sdk and data['reportedRid'] == rid
                and data['framework'] == framework and data['functionalChecks'] == dict.fromkeys(CHECKS, 'passed')
                and data['archive']['sha256'] == archive['sha256'] and data['archive']['sdkContentMatched'] is True,
                'Native functional checks failed: ' + name)
        abi = data['abi']; version = lambda value: tuple(map(int, value.split('.')))
        require(abi['elfFileCount'] > 0 and abi['machines'] == {'AArch64': abi['elfFileCount']} and abi['glibcCeilingPassed'] is True
                and abi['glibcCeiling'] == '2.23' and version(abi['maximumRequiredVersions']['GLIBC']) <= (2, 23), 'Native ABI gate failed')
        native[name] = {'rid': rid, 'checks': 6, 'abi': abi['maximumRequiredVersions']}
    verification = load(member(release, 'reports/ci/legacy-verification.json'))
    require(verification['status'] == 'passed' and verification['family'] == family and verification['sdkVersion'] == sdk
            and verification['sdkArchiveUnchanged'] is True and verification['sdkArchive']['sha256'] == archive['sha256'],
            'Explicit legacy dependency/userland proof is absent')
    for key in ('commandJournal', 'log'):
        checked(release, verification[key])
    producer = load(checked(release, verification['producerImage']))
    require(len(producer) == 1 and producer[0]['Architecture'] == 'arm64' and producer[0]['Os'] == 'linux', 'Native compatibility producer required')
    producer_id = producer[0]['Id'].removeprefix('sha256:')
    if family != 'core30':
        require(producer_id == image[0]['Id'].removeprefix('sha256:'), 'Compatibility inputs came from another builder')
    exports = verification['compatibilityExports']
    require(set(exports) == ({'openssl11'} if family == 'net5' else {'openssl11', 'icu66'}), 'Unexpected legacy compatibility dependency set')
    for kind, row in exports.items():
        require(row['producerImageId'].removeprefix('sha256:') == producer_id, 'Exported dependency image binding differs')
        contract = load(checked(release, row['contract'])); owner = load(checked(release, row['owner']))
        export = load(checked(release, row['exportReport']))
        require(contract['producerImageId'] == owner['producerImageId'] == producer_id
                and export['status'] == 'passed' and export['sdkArchiveModified'] is False
                and export['adapter']['producerImageId'] == producer_id, 'Actual dependency export was not verified')
        prefix = 'reports/verification-inputs/' + kind + '/'
        require(all(file['path'].startswith(prefix) for file in row['files']), 'Compatibility files escaped the report inventory')
        for file in row['files']:
            checked(release, file)
        for file in contract['files']:
            path = member(release, prefix + file['path']); actual_file = fp(path)
            require(file['bytes'] == actual_file['bytes'] and file['sha256'] == actual_file['sha256'], 'Actual dependency library/config/license differs')
        if kind == 'openssl11':
            require(contract['packageCompatibility']['upstreamVersion'] == '1.1.1f'
                    and {file['path'] for file in contract['files']} == {'lib/libssl.so.1.1', 'lib/libcrypto.so.1.1', 'LICENSE.openssl.txt', 'openssl.cnf'},
                    'Explicit OpenSSL1.1 library, configuration and license inputs are required')
        else:
            require(contract['package']['name'] == 'libicu66' and contract['package']['architecture'] == 'arm64'
                    and contract['package']['version'].startswith('66.1-') and contract['package']['status'] == 'installed', 'Native Focal ICU66 identity differs')
    userlands = verification['userlands']
    require(set(userlands) == {'ubuntu22', 'ubuntu24', 'debian13'}, 'All three modern native user spaces are required')
    for name, distribution, os_version, icu, ssl in (('ubuntu22', 'ubuntu', '22.04', 'libicu70', 'libssl3'),
                                                   ('ubuntu24', 'ubuntu', '24.04', 'libicu74', 'libssl3t64'),
                                                   ('debian13', 'debian', '13', 'libicu76', 'libssl3t64')):
        row = userlands[name]; metadata = load(checked(release, row['userland']))
        checked(release, row['verification'])
        selected = ['openssl11'] + (['icu66'] if family != 'net5' and name == 'debian13' else [])
        environment = {'LD_LIBRARY_PATH': '/verification-compat/lib', 'OPENSSL_CONF': '/verification-compat/openssl.cnf'}
        if 'icu66' in selected:
            environment['LD_LIBRARY_PATH'] += ':/verification-icu/lib'; environment['CLR_ICU_VERSION_OVERRIDE'] = '66'
        require(row['compatibilityInputs'] == selected and row['consumerEnvironment'] == environment
                and row['sdkArchiveSha256'] == archive['sha256'] and row['osRelease'] == {'ID': distribution, 'VERSION_ID': os_version},
                'Controlled dependency/OS selection differs: ' + name)
        require(metadata['architecture'] == 'aarch64' and metadata['uid'] > 0 and metadata['osRelease'] == row['osRelease']
                and all(metadata['consumerEnvironment'][key] == value for key, value in environment.items()), 'Actual native verifier identity differs')
        for key in ('DOTNET_SYSTEM_GLOBALIZATION_INVARIANT', 'DOTNET_ROOT', 'DOTNET_EnableDiagnostics', 'COMPlus_EnableDiagnostics'):
            require(metadata['consumerEnvironment'][key] is None, 'Unreviewed runtime/globalization override')
        if 'icu66' not in selected:
            require(metadata['consumerEnvironment']['CLR_ICU_VERSION_OVERRIDE'] is None, 'Unexpected ICU override')
        installed = {key.split(':')[0]: value for key, value in metadata['installedPackages'].items()}
        require({icu, ssl, 'libc6', 'libstdc++6', 'zlib1g', 'libgssapi-krb5-2'} <= set(installed), 'Stock user-space dependency identities are incomplete')
        inspected = load(checked(release, row['imageInspection'])); base = load(checked(release, row['baseInspection']))
        require(len(inspected) == len(base) == 1 and inspected[0]['Architecture'] == base[0]['Architecture'] == 'arm64'
                and inspected[0]['Os'] == base[0]['Os'] == 'linux' and inspected[0]['Id'] == row['imageId'] == metadata['imageId']
                and row['baseManifest'] == 'docker.io/library/' + distribution + '@' + base[0]['Digest']
                and row['baseManifest'] in base[0]['RepoDigests'], 'Actual native image manifest binding differs')
        require(any(row['imageId'] in command and '--network=none' in command and '__verify' in command for command in verification['commands']),
                'Actual isolated native verifier invocation is missing')
    source_manifest = member(release, 'sources/source-manifest.json')
    require(source_manifest.read_bytes() == member(release, 'reports/ci/used-source.json').read_bytes(), 'Used-source controls differ')
    sources = load(source_manifest)
    require(sources['projectCommit'] == snapshot['projectCommit'] and sources['runId'] == snapshot['runId']
            and sources['runAttempt'] == snapshot['runAttempt'], 'Used-source run identity differs')
    collect = load(member(release, 'collect-receipt.json'))
    require(collect['status'] == 'passed' and collect['exitCode'] == 0 and all(collect.get(key) == snapshot[key] for key in IDENTITY), 'Final collector did not pass')
    require(checked(release, collect['manifest']) == manifest_path, 'Final collector manifest is unbound')
    for key in ('log', 'commandsFile'):
        checked(release, collect[key])
    allowed = {archive['path'], 'build-manifest.json', 'SHA256SUMS', 'SHA512SUMS', 'collect-receipt.json', collect['log']['path'], collect['commandsFile']['path']}
    if (release / 'ci-validation.json').exists():
        allowed.add('ci-validation.json')
    outer = {p.relative_to(release).as_posix() for p in entries if p.is_file() and p.relative_to(release).parts[0] not in ('reports', 'sources')}
    require(outer == allowed, 'Unbound outer delivery files')
    return dict(schemaVersion=1, status='passed', family=family, targetRid='linux-arm64', **{key: snapshot[key] for key in IDENTITY},
                sdkArchive=archive, sourceManifest=record(release, source_manifest), buildManifest=record(release, manifest_path),
                snapshot=record(release, snapshot_path), collectReceipt=record(release, release / 'collect-receipt.json'),
                tests={'cases': 68 if family == 'net5' else 52, 'exclusions': []}, native=native,
                scope='Fresh source-only online normal root graph, local framework construction and complete upstream smoke. Retained binary bootstrap/tool/reference inputs and explicit modern verification dependencies remain; no clean Stage2 assertion.')


def qualify(args):
    release = args.output_dir.absolute()
    snapshot = load(member(release, 'reports/ci-inputs/snapshot.json'))
    expected = {key: getattr(args, 'expected_' + key.replace('Commit', '_commit').replace('Id', '_id').replace('Attempt', '_attempt'), None)
                for key in ('projectCommit', 'runId', 'runAttempt')}
    if args.stage == 'validate':
        import subprocess
        require(args.project_root is not None, 'Trusted project root required')
        expected['projectCommit'] = subprocess.check_output(['git', '-C', str(args.project_root), 'rev-parse', 'HEAD']).decode().strip()
        import os
        expected['runId'] = os.environ.get('GITHUB_RUN_ID', snapshot['runId'])
        expected['runAttempt'] = os.environ.get('GITHUB_RUN_ATTEMPT', snapshot['runAttempt'])
    require(all(expected.values()), 'Expected project/run/attempt identities are required')
    result = validate(release, args.family, expected)
    destination = release / 'ci-validation.json'
    if args.stage == 'verify-release':
        require(load(destination) == result, 'Portable validation envelope differs')
    elif destination.exists():
        require(load(destination) == result, 'Existing validation envelope differs')
    else:
        with destination.open('x') as stream:
            json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': 'passed', 'sdkVersion': result['sdkVersion'], 'sdkSha256': result['sdkArchive']['sha256']}))
