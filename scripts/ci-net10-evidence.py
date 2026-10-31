#!/usr/bin/env python3
"""Freeze .NET 10 CI inputs and verify real test, scan and delivery evidence."""
import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import xml.etree.ElementTree as ET
from types import SimpleNamespace

SOURCE = '5a2162bea6845eabc1fc721624a43568c65db3b1'
SDK = '10.0.403'
PROFILE = 'profiles/dotnet-10.0.403-linux-arm64.json'
FUNCTIONS = {'consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
             'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp'}
SKIPS = {'VerifyWorkloadCmd', 'VerifyAspireTemplate'}
CRITICAL = {PROFILE, 'scripts/ci-net10-evidence.py', 'scripts/ci-net10.sh',
            '.github/workflows/net10-sdk.yml', 'containers/arm64-net10.Containerfile'}
SYSROOT_PRODUCERS = {'eng/common/cross/build-rootfs.sh': '3150ccac6fcd7859a55e10fa0742cfc4de5e3075',
                     'eng/common/cross/install-debs.py': '1d1dfabf7dc92d8e374d4304f36061c6e3e10b1b'}
USERLANDS = {'ubuntu22': ('ubuntu', '22.04', 'libicu70', 'libssl3'),
             'ubuntu24': ('ubuntu', '24.04', 'libicu74', 'libssl3t64'),
             'debian13': ('debian', '13', 'libicu76', 'libssl3t64')}
ENVIRONMENT_OVERRIDES = {'LD_LIBRARY_PATH', 'DOTNET_ROOT', 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT',
                         'CLR_ICU_VERSION_OVERRIDE', 'DOTNET_EnableDiagnostics', 'COMPlus_EnableDiagnostics'}


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path] + list(path.parents)),
            'An ordinary absolute file is required: ' + str(path))
    return path


def tree_files(root):
    require(root.is_dir() and not any(p.is_symlink() for p in [root] + list(root.parents)), 'An ordinary evidence directory is required')
    paths = list(root.rglob('*'))
    require(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in paths), 'Linked or special evidence entries are forbidden')
    return [p for p in paths if p.is_file()]


def member(root, name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and bool(p.parts) and not p.is_absolute() and '..' not in p.parts
            and p.as_posix() == name and chr(92) not in name and ':' not in name,
            'A portable relative evidence path is required: ' + name)
    return ordinary(root.joinpath(*p.parts))


def fingerprint(path):
    ordinary(path); before = path.stat(); hashes = {n: hashlib.new(n) for n in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for digest in hashes.values():
                digest.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Evidence changed while hashing')
    return dict(bytes=after.st_size, **{n: h.hexdigest() for n, h in hashes.items()})


def record(root, path):
    return dict(path=path.relative_to(root).as_posix(), **fingerprint(path))


def byte_fingerprint(data):
    return dict(bytes=len(data), **{name: hashlib.new(name, data).hexdigest() for name in ('sha256', 'sha512')})


def executed_input(name):
    return name in CRITICAL or name.startswith(('containers/', '.github/')) or (
        name.startswith('scripts/') and PurePosixPath(name).suffix in ('.py', '.sh', '.proj'))


def checkout_details(project, name, blob, canonical):
    raw = member(project, name).read_bytes()
    clean = subprocess.check_output(['git', '-C', str(project), 'hash-object', '--path=' + name, '--stdin'], input=raw).decode().strip()
    require(clean == blob and git_hash('blob', canonical) == blob, 'The checkout does not clean to its committed Git blob: ' + name)
    representation = 'git-blob'
    if raw != canonical:
        require(not executed_input(name) and name.lower().endswith(('.cmd', '.bat'))
                and raw == canonical.replace(b'\n', b'\r\n'), 'Unreviewed checkout transformation: ' + name)
        representation = 'crlf-checkout'
    return {'checkout': byte_fingerprint(raw), 'checkoutRepresentation': representation}


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def project_tree(release, rows):
    """Reconstruct Git trees so downloaded source bytes bind the real commit."""
    tree = {}; names = set(); prefix = 'reports/ci-inputs/project/'
    for row in rows:
        require(row['path'].startswith(prefix), 'Frozen source escapes the project snapshot')
        name = row['path'][len(prefix):]
        require(name not in names and row.get('gitMode') in ('100644', '100755'), 'Duplicate or unsupported Git source entry')
        names.add(name); path = checked(release, row)
        canonical = path.read_bytes(); blob = git_hash('blob', canonical)
        require(blob == row.get('gitBlobSha1'), 'Frozen source differs from its original Git blob')
        representation = row.get('checkoutRepresentation')
        require(representation in ('git-blob', 'crlf-checkout'), 'The original checkout representation must be recorded')
        checkout = canonical
        if representation == 'crlf-checkout':
            require(not executed_input(name) and name.lower().endswith(('.cmd', '.bat')), 'Executed CI inputs must match canonical Git bytes')
            checkout = canonical.replace(b'\n', b'\r\n')
        require(row.get('checkout') == byte_fingerprint(checkout), 'The recorded checkout bytes do not match the verified Git representation')
        parts = PurePosixPath(name).parts; parent = tree
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
            require(isinstance(parent, dict), 'Git tree/file collision')
        require(parts[-1] not in parent, 'Git tree/file collision')
        parent[parts[-1]] = (row['gitMode'], blob)
    require(CRITICAL <= names, 'Required current workflow/profile/tools are missing from the snapshot')

    def digest(entries):
        body = []
        for name, value in sorted(entries.items(), key=lambda item: item[0].encode('utf-8') + (b'/' if isinstance(item[1], dict) else b'')):
            mode, object_id = ('40000', digest(value)) if isinstance(value, dict) else value
            body.append(mode.encode() + b' ' + name.encode('utf-8') + b'\0' + bytes.fromhex(object_id))
        return git_hash('tree', b''.join(body))
    return digest(tree), names


def load(path):
    require(ordinary(path).stat().st_size <= 64 * 1024 * 1024, 'Oversized JSON evidence')
    return json.loads(path.read_text(encoding='utf-8'))


def checked(root, row):
    path = member(root, row['path']); actual = fingerprint(path)
    require(all(row.get(k) == v for k, v in actual.items()), 'Evidence digest mismatch: ' + row['path'])
    return path


def timestamp(value):
    value = re.sub(r'(\.\d{6})\d+(?=[Z+-])', r'\1', value)
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'UTC-offset timestamps are required')
    return parsed


def xml(path):
    data = ordinary(path).read_bytes()
    require(len(data) <= 64 * 1024 * 1024 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(),
            'Unsupported XML evidence')
    return ET.fromstring(data)


def parse_tests(trx, scenarios):
    root = xml(trx); ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    results = root.findall('./t:Results/t:UnitTestResult', ns)
    counters = root.find('./t:ResultSummary/t:Counters', ns)
    require(counters is not None and len(results) == 13 and len({r.get('executionId') for r in results}) == 13,
            'All 13 actual common test results are required')
    require(all(r.get('outcome') == 'Passed' for r in results)
            and all(int(counters.get(k, '-1')) == v for k, v in {'total': 13, 'executed': 13, 'passed': 13, 'failed': 0}.items()),
            'Common test results/counters must consistently pass')
    require(any('BinaryScanTest.ScanForBinaries' in r.get('testName', '') for r in results),
            'The actual BinaryScanTest result is required')
    assembly_root = xml(scenarios); assemblies = assembly_root.findall('./assembly')
    tests = assembly_root.findall('./assembly/collection/test')
    require(len(assemblies) == 1 and len(tests) == 36 and len({t.get('name') for t in tests}) == 36,
            'All 36 actual scenario results are required')
    counts = {name: sum(t.get('result') == value for t in tests) for name, value in
              [('passed', 'Pass'), ('failed', 'Fail'), ('skipped', 'Skip')]}
    require(counts == {'passed': 34, 'failed': 0, 'skipped': 2}, 'Unexpected scenario failures/skips/results')
    require({t.get('method') for t in tests if t.get('result') == 'Skip'} == SKIPS,
            'Only the pinned workload and Aspire scenario skips are permitted')
    a = assemblies[0]
    require(all(int(a.get(k, '-1')) == v for k, v in dict(total=36, passed=34, failed=0, skipped=2, errors=0).items())
            and not assembly_root.findall('./assembly/errors/error'), 'Scenario counters/errors disagree with results')
    return {'common': {'total': 13, 'passed': 13, 'failed': 0},
            'scenarios': dict(total=36, **counts, errors=0, skippedMethods=sorted(SKIPS))}


def validate_scan(release, scan):
    require(scan.get('exitCode') == 0 and scan.get('mode', scan.get('scanMode')) == 'Validate'
            and scan.get('sourceCommit') == SOURCE and scan.get('cleanSourceCommit') == SOURCE,
            'A successful original Validate scan of the pinned clean source is required')
    for key in ('sourceMountedReadOnly', 'originalAllowlistUsed', 'worktreeCleanBeforeScan',
                'worktreeCleanAfterScan', 'reportAbsentBefore'):
        require(scan.get(key) is True, 'Missing real scan producer guard: ' + key)
    for key in ('report', 'toolAssembly', 'allowedBinaries', 'allowedSourceBuildBinaries'):
        checked(release, scan[key])
        require(key == 'report' or scan[key]['bytes'] > 0, 'The real scanner tool and imported allowlists must be nonempty')
    for key in ('scanLog', 'scanBinlog'):
        require(checked(release, scan[key]).stat().st_size > 0, 'Actual nonempty scanner logs are required')
    require(scan['report']['bytes'] == 0, 'The actual generated binary report must be empty')
    require(scan.get('commands') and isinstance(scan['commands'], list), 'The actual scanner command is required')
    require(any(isinstance(command, list) and any(str(argument).endswith('/scripts/scan-clean-source.proj') for argument in command)
                for command in scan['commands']), 'The original scan task invocation is required')
    require(scan.get('allowlistsMatchPinnedGit') is True, 'Original imported allowlists must match pinned Git blobs')
    return {key: scan[key] for key in ('report', 'toolAssembly', 'allowedBinaries', 'allowedSourceBuildBinaries', 'scanLog', 'scanBinlog')}


def native_check(path, archive):
    data = load(path)
    require(data.get('verificationStatus') == 'passed' and data.get('smokeStatus') == 'passed'
            and data.get('sdkVersion') == SDK and data.get('reportedRid') == 'linux-arm64'
            and data.get('framework') == 'net10.0' and data.get('hostArchitecture') == 'aarch64',
            'Native SDK identity/verification must pass')
    require(data.get('functionalChecks') == dict.fromkeys(FUNCTIONS, 'passed'), 'All six native functional checks are required')
    a = data['archive']
    require(a.get('sdkContentMatched') is True and a.get('sha256') == archive['sha256']
            and a.get('sizeBytes') == archive['bytes'], 'Native tests must bind the exact collected SDK archive')
    abi = data['abi']; maxima = abi['maximumRequiredVersions']
    version = lambda s: tuple(int(n) for n in s.split('.'))
    require(abi.get('elfFileCount', 0) > 0 and abi.get('machines') == {'AArch64': abi['elfFileCount']}
            and abi.get('glibcCeilingPassed') is True and abi.get('glibcCeiling') == '2.27'
            and not abi.get('symbolicGlibcRequirements') and version(maxima['GLIBC']) <= version('2.27')
            and version(maxima['GLIBCXX']) <= version('3.4.22') and version(maxima['CXXABI']) <= version('1.3.7'),
            'Native ELF architecture/ABI policy failed')
    return {'reportedRid': data['reportedRid'], 'functionalChecks': data['functionalChecks'],
            'elfFileCount': abi['elfFileCount'], 'maximumRequiredVersions': maxima}


def sysroot_check(release, preparation):
    require(preparation.get('status') == 'passed' and preparation.get('signatureVerificationRequired') is True
            and preparation.get('sourceCommit') == SOURCE and preparation.get('files', 0) > 0
            and preparation.get('symlinks', 0) > 0 and preparation.get('signatureSuccessRecords', 0) > 0,
            'Authenticated complete sysroot preparation and independent validation are required')
    root = release / 'reports/prepare'
    require(preparation.get('producerInputsMatchPinnedGit') is True
            and len(preparation.get('producerInputs', [])) == len(SYSROOT_PRODUCERS), 'Pinned original sysroot producers are required')
    producers = {row['originalPath']: row for row in preparation['producerInputs']}
    require(set(producers) == set(SYSROOT_PRODUCERS), 'Unexpected sysroot producer inputs')
    for name, expected in SYSROOT_PRODUCERS.items():
        row = producers[name]; data = checked(release, row).read_bytes()
        require(row['gitBlobSha1'] == expected and git_hash('blob', data) == expected, 'A signed sysroot producer differs from pinned source')
    keyring = preparation['signingKeyring']; checked(release, keyring)
    require(keyring['bytes'] > 0 and keyring.get('originalPath') == '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
            and keyring.get('installedPackage'), 'The actual Ubuntu signing keyring/package identity is required')
    inventory = preparation['inventory']
    require(set(inventory) == {'sysroot-files.sha256', 'sysroot-file-list.sha256', 'sysroot-symlinks.tsv', 'sysroot-prepare.log'},
            'All actual sysroot extraction inventory controls are required')
    for name, row in inventory.items():
        require(checked(release, row) == root / name, 'The sysroot inventory points at another control')
    log = ordinary(root / 'sysroot-prepare.log').read_text()
    require('--force-check-gpg' in log and '--skipsigcheck' not in log
            and '--keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg' in log
            and log.count('Signature verified successfully.') == preparation['signatureSuccessRecords'],
            'Actual upstream signed-package verification evidence is absent')
    files = ordinary(root / 'sysroot-files.sha256').read_text().splitlines()
    require(len(files) == preparation['files'] and len(files) == len(set(files))
            and all(re.fullmatch(r'[a-f0-9]{64}  /inputs/arm64-bionic/.+', line) for line in files),
            'The complete current sysroot file inventory differs')
    links = ordinary(root / 'sysroot-symlinks.tsv').read_text().splitlines()
    require(len(links) == preparation['symlinks'] and len(links) == len(set(links)), 'The sysroot symlink inventory differs')
    control = ordinary(root / 'sysroot-file-list.sha256').read_text().strip().split('  ', 1)
    require(control == [fingerprint(root / 'sysroot-files.sha256')['sha256'], '/delivery/reports/prepare/sysroot-files.sha256'],
            'The authenticated extraction inventory control differs')


def image_check(path, expected):
    images = load(path)
    require(isinstance(images, list) and len(images) == 1, 'An exact actual container inspection is required')
    image = images[0]
    require(image['Id'].removeprefix('sha256:') == expected.removeprefix('sha256:')
            and image.get('Architecture') == 'arm64' and image.get('Os') == 'linux', 'Container identity/architecture differs')
    return image


def verification_base(image, distribution):
    digest = image.get('Digest'); references = image.get('RepoDigests')
    require(image.get('Architecture') == 'arm64' and image.get('Os') == 'linux'
            and isinstance(digest, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
            and isinstance(references, list) and references
            and all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*/[a-z0-9._/-]+@sha256:[a-f0-9]{64}', value)
                    for value in references) and len(references) == len(set(references)),
            'A valid immutable native verification base inspection is required')
    reference = 'docker.io/library/' + distribution + '@' + digest
    require(references.count(reference) == 1, 'The actual verification base Digest is not bound to the expected repository')
    return reference


def userland_check(release, name, stage):
    distribution, version, icu, ssl = USERLANDS[name]
    data = load(member(release, 'reports/ci/' + name + '-userland.json'))
    require(data.get('architecture') == 'aarch64' and data.get('uid', 0) > 0
            and data.get('osRelease') == {'ID': distribution, 'VERSION_ID': version}, 'Actual native user-space identity differs: ' + name)
    derived = image_check(member(release, 'reports/ci/' + name + '-verification-image.json'), data['imageId'])
    base = load(member(release, 'reports/ci/' + name + '-base-image.json'))
    require(isinstance(base, list) and len(base) == 1, 'An exact verification base inspection is required')
    reference = verification_base(base[0], distribution)
    tag = 'localhost/cbodotnet-net10-verify-' + name + ':' + str(stage['runId']) + '-' + str(stage['runAttempt'])
    require(tag in derived.get('RepoTags', []), 'The inspected derived verification image must carry this run/user-space tag')
    require(any(isinstance(command, list) and ('--build-arg', 'BASE_IMAGE=' + reference) in list(zip(command, command[1:]))
                and ('--tag', tag) in list(zip(command, command[1:]))
                and any(argument.endswith('/containers/verify-net10.Containerfile') and prior == '--file'
                        for prior, argument in zip(command, command[1:]))
                for command in stage['commands']), 'The actual verification build must bind the inspected base Digest and original recipe')
    packages = {key.split(':', 1)[0]: value for key, value in data['installedPackages'].items()}
    require(all(packages.get(key) for key in (icu, ssl, 'libc6', 'libstdc++6', 'zlib1g', 'libgssapi-krb5-2')),
            'Actual system ICU, OpenSSL and native dependency package versions are required')
    require(set(data.get('environmentOverrides', {})) == ENVIRONMENT_OVERRIDES
            and all(value is None for value in data['environmentOverrides'].values()),
            'Unreviewed diagnostic, globalization or native-library overrides are not permitted')
    require(any(isinstance(command, list) and data['imageId'] in command and '--network=none' in command
                for command in stage['commands']), 'The actual isolated native verification image invocation is required')
    return {'imageId': data['imageId'], 'osRelease': data['osRelease'], 'installedPackages': data['installedPackages'],
            'environmentOverrides': data['environmentOverrides'], 'baseImage': reference}


def freeze(args):
    project, source, release = args.project_root.absolute(), args.source_dir.absolute(), args.release_dir.absolute()
    git = lambda root, *tail: subprocess.check_output(['git', '-C', str(root), *tail]).decode().strip()
    require(re.fullmatch('[a-f0-9]{40}', args.project_commit) is not None and git(project, 'rev-parse', 'HEAD') == args.project_commit,
            'The actual orchestration commit must match')
    require(not git(project, 'status', '--porcelain', '--untracked-files=all'), 'Freeze requires a clean orchestration checkout')
    require(git(source, 'rev-parse', 'HEAD') == SOURCE and not git(source, 'status', '--porcelain', '--untracked-files=all'),
            'Freeze requires the initial pristine pinned VMR')
    for value in (args.run_id, args.run_attempt, args.build_revision):
        require(re.fullmatch('[1-9][0-9]*', value) is not None, 'Positive run/revision identifiers are required')
    require(re.fullmatch(r'20\d{6}\.[1-9]\d*', args.build_id) is not None, 'A supported fresh OfficialBuildId is required')
    require(not any(c in args.workflow_ref for c in '\r\n\0'), 'Invalid workflow reference')
    destination = release / 'reports/ci-inputs'
    require(not destination.exists() and not destination.is_symlink(), 'CI inputs must be new')
    destination.mkdir(parents=True)
    files = subprocess.check_output(['git', '-C', str(project), 'ls-files', '--stage', '-z']).decode().split('\0')
    inventory = []
    for entry in sorted(n for n in files if n):
        metadata, name = entry.split('\t', 1); mode, blob, stage = metadata.split()
        require(stage == '0' and mode in ('100644', '100755'), 'Only ordinary committed project files are supported')
        canonical = subprocess.check_output(['git', '-C', str(project), 'cat-file', 'blob', blob])
        checkout = checkout_details(project, name, blob, canonical)
        target = destination / 'project' / name
        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(canonical)
        inventory.append(dict(record(release, target), gitMode=mode, gitBlobSha1=blob, **checkout))
    for name in CRITICAL:
        ordinary(destination / 'project' / name)
    commit = subprocess.check_output(['git', '-C', str(project), 'cat-file', 'commit', args.project_commit])
    (destination / 'project-commit.txt').write_bytes(commit)
    tree, _ = project_tree(release, inventory)
    require(git_hash('commit', commit) == args.project_commit and commit.startswith(('tree ' + tree + '\n').encode()),
            'Frozen files do not reconstruct the original committed tree')
    original_profile = load(destination / 'project' / PROFILE)
    require(original_profile['source']['commit'] == SOURCE and original_profile['sdkVersion'] == SDK,
            'Unexpected selected original profile')
    effective = copy.deepcopy(original_profile); effective['build']['officialBuildId'] = args.build_id
    with (destination / 'effective-profile.json').open('x', encoding='utf-8') as stream:
        json.dump(effective, stream, indent=2); stream.write('\n')
    data = {'schemaVersion': 1, 'sourceCommit': SOURCE, 'projectCommit': args.project_commit,
            'runId': args.run_id, 'runAttempt': args.run_attempt, 'buildId': args.build_id,
            'buildRevision': args.build_revision, 'workflowRef': args.workflow_ref,
            'executionContext': 'github-actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local-unverified',
            'sourceRepository': 'https://github.com/dotnet/dotnet', 'sourceInitiallyPristine': True,
            'projectInitiallyPristine': True, 'projectFiles': inventory, 'sourceDeliveryRequired': True,
            'sharedSourceDeliveryRequired': True,
            'inputRepresentation': 'canonical-git-blobs-with-verified-checkout',
            'projectCommitObject': record(release, destination / 'project-commit.txt'),
            'effectiveProfile': record(release, destination / 'effective-profile.json'),
            'originalProfile': record(release, destination / 'project' / PROFILE)}
    with (destination / 'snapshot.json').open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': 'frozen', 'snapshot': str(destination / 'snapshot.json')}))


def validate_bundle(release, project=None):
    release_files = tree_files(release)
    manifest_path = member(release, 'build-manifest.json'); manifest = load(manifest_path)
    snapshot_path = member(release, 'reports/ci-inputs/snapshot.json'); snapshot = load(snapshot_path)
    require(snapshot.get('executionContext') == 'github-actions' and snapshot.get('sourceInitiallyPristine') is True
            and snapshot.get('projectInitiallyPristine') is True
            and snapshot.get('inputRepresentation') == 'canonical-git-blobs-with-verified-checkout',
            'Actual fresh GitHub Actions source/input snapshot required')
    require(snapshot['sourceCommit'] == SOURCE and re.fullmatch('[a-f0-9]{40}', snapshot['projectCommit']) is not None,
            'Unexpected CI source/orchestration identity')
    for key in ('runId', 'runAttempt', 'buildRevision'):
        require(re.fullmatch('[1-9][0-9]*', snapshot[key]) is not None, 'Positive actual CI run/revision identity required')
    require(re.fullmatch(r'20\d{6}\.[1-9]\d*', snapshot['buildId']) is not None
            and snapshot.get('workflowRef') and snapshot['workflowRef'] != 'local', 'Fresh actual workflow/build identity required')
    tree, names = project_tree(release, snapshot['projectFiles'])
    commit = checked(release, snapshot['projectCommitObject']).read_bytes()
    require(git_hash('commit', commit) == snapshot['projectCommit'] and commit.startswith(('tree ' + tree + '\n').encode()),
            'The frozen project tree does not belong to the expected real commit')
    frozen = release / 'reports/ci-inputs/project'
    require(names == {p.relative_to(frozen).as_posix() for p in tree_files(frozen)},
            'Complete frozen project membership differs')
    for row in snapshot['projectFiles']:
        path = checked(release, row)
        require(row['path'].startswith('reports/ci-inputs/project/'), 'Frozen source escapes the project snapshot')
        if project is not None:
            name = row['path'][len('reports/ci-inputs/project/'):]
            require(checkout_details(project, name, row['gitBlobSha1'], path.read_bytes()) ==
                    {key: row[key] for key in ('checkout', 'checkoutRepresentation')},
                    'Current checkout representation differs from the verified frozen input')
    original = load(checked(release, snapshot['originalProfile']))
    require(original.get('sdkVersion') == SDK and original.get('source', {}).get('commit') == SOURCE
            and original.get('build', {}).get('sourceOnly') is False, 'Only the selected regular .NET 10 profile is supported')
    effective_path = checked(release, snapshot['effectiveProfile']); effective = load(effective_path)
    expected = copy.deepcopy(original); expected['build']['officialBuildId'] = snapshot['buildId']
    require(effective == expected and manifest['profile']['contents'] == effective,
            'Only the explicit CI OfficialBuildId profile override is permitted')
    require(all(manifest['profile'].get(k) == v for k, v in fingerprint(effective_path).items()), 'Collected profile bytes differ')
    require(manifest['sdkVersion'] == SDK and manifest['targetRid'] == 'linux-arm64' and manifest['sourceOnly'] is False
            and manifest['source']['actualCommit'] == SOURCE and manifest['source']['commitVerified'] is True
            and manifest['buildRevision'] == snapshot['buildRevision'], 'Collected SDK/source/build identity differs')
    archive = manifest['sdkArchive']; checked(release, archive)
    require(archive['path'] == 'cbodotnet-sdk-' + SDK + '-linux-arm64-build.' + snapshot['buildRevision'] + '.tar.gz'
            and archive.get('copiedWithoutModification') is True, 'The delivery must retain the actual SDK bytes and version/revision name')
    require(manifest.get('construction', {}).get('upstreamSharedRuntimeReused') is True,
            'The regular 4xx construction must disclose upstream shared runtime reuse')
    sources = None
    if snapshot.get('sourceDeliveryRequired'):
        module_path = Path(__file__).parent / 'package-used-source.py'
        spec = importlib.util.spec_from_file_location('used_source', module_path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source_manifest = module.verify(SimpleNamespace(
            release_dir=release, expected_project_commit=snapshot['projectCommit'],
            expected_run_id=snapshot['runId'], expected_run_attempt=snapshot['runAttempt']))
        require(source_manifest['sdkVersion'] == SDK and source_manifest['targetRid'] == 'linux-arm64',
                'Source package targets another SDK')
        closure_path = release / 'reports/ci/shared-input-source.json'
        # Older source-only pilot snapshots did not yet declare corresponding
        # sources for the reused shared VMR. New source roots must bind both.
        if snapshot.get('sharedSourceDeliveryRequired') or closure_path.exists() or any(root.get('name') == 'shared-vmr' for root in source_manifest['roots']):
            closure = load(ordinary(closure_path))
            selected = [root for root in source_manifest['roots'] if root['name'] == 'shared-vmr']
            expected_shared = original['upstreamInputs']['sharedVmrCommit']
            require(len(selected) == 1 and selected[0]['kind'] == 'git' and selected[0]['commit'] == expected_shared
                    and selected[0].get('role') == 'source-for-reused-shared-input'
                    and selected[0]['tree'] == closure['sharedSource']['tree']
                    and closure.get('status') == 'passed' and closure.get('sourceCommit') == SOURCE
                    and closure.get('sharedVmrCommit') == expected_shared,
                    'Reused shared-framework sources are missing or have another revision')
            for key in ('bytes', 'sha256', 'sha512'):
                require(closure['sdkArchive'][key] == archive[key], 'Shared source proof belongs to another SDK archive')
            shared_spec = importlib.util.spec_from_file_location('shared_source', Path(__file__).parent / 'ci-net10-shared-source.py')
            shared_module = importlib.util.module_from_spec(shared_spec); shared_spec.loader.exec_module(shared_module)
            require(shared_module.archive_markers(checked(release, archive), original) == closure['sharedMarkers'],
                    'Actual delivered shared-framework source markers differ')
            preparation = load(member(release, 'reports/prepare/shared-source-checkout.json'))
            require(all(preparation[key] == closure['sharedSource'][key]
                        for key in ('repository', 'commit', 'tree', 'pristine', 'componentPaths', 'submodules'))
                    and preparation['pristine'] is True
                    and all(closure['prepareReport'][key] == value for key, value in fingerprint(release / 'reports/prepare/shared-source-checkout.json').items()),
                    'Shared source checkout/proof changed after acquisition')
        capture = timestamp(source_manifest['capturedAtUtc'])
        test_end = timestamp(load(member(release, 'reports/ci/stages/test.json'))['finishedAtUtc'])
        verify_start = timestamp(load(member(release, 'reports/ci/stages/verify.json'))['startedAtUtc'])
        require(test_end <= capture <= verify_start, 'Used sources must be captured after tests and before verification')
        sources = record(release, member(release, 'sources/source-manifest.json'))
    for algorithm in ('sha256', 'sha512'):
        expected_line = archive[algorithm] + '  ' + archive['path'] + '\n'
        require(member(release, algorithm.upper() + 'SUMS').read_text() == expected_line, 'SDK checksum file differs')
    report_root = release / 'reports'; rows = manifest['reports']['files']
    require(len(rows) == len({r['path'] for r in rows}), 'Duplicate report inventory entries')
    for row in rows:
        checked(report_root, row)
    actual_reports = {p.relative_to(report_root).as_posix() for p in tree_files(report_root)}
    require(actual_reports == {r['path'] for r in rows}, 'Complete report membership changed after collection')
    require(bool(manifest['rebuildInputs']), 'Current build-input inventory is required')
    require(len(manifest['rebuildInputs']) == len({r['path'] for r in manifest['rebuildInputs']}), 'Duplicate build-input inventory entries')
    for row in manifest['rebuildInputs']:
        checked(frozen, row)
    expected_inputs = {p.relative_to(frozen).as_posix() for folder in ('scripts', 'containers', 'patches')
                       for p in (frozen / folder).rglob('*') if p.is_file()}
    require(expected_inputs == {r['path'] for r in manifest['rebuildInputs']}, 'Complete current build-input membership differs')
    identities = ('sourceCommit', 'projectCommit', 'runId', 'runAttempt', 'buildId', 'buildRevision')
    stages = {}; prior_end = None
    for name in ('prepare', 'build', 'scan', 'test', 'verify'):
        path = member(release, 'reports/ci/stages/' + name + '.json'); data = load(path)
        require(data.get('stage') == name and data.get('status') == 'passed' and data.get('exitCode') == 0
                and data.get('commands') and all(str(data.get(k)) == str(snapshot[k]) for k in identities),
                'A fresh successful identity-bound stage receipt is required: ' + name)
        require(data.get('environment', {}).get('nativeArchitecture') == 'aarch64'
                and data['environment'].get('uid', 0) > 0, 'Actual nonroot native ARM64 stage environment required')
        start, end = timestamp(data['startedAtUtc']), timestamp(data['finishedAtUtc'])
        require(start <= end and (prior_end is None or prior_end <= start), 'CI stage timestamps/order disagree')
        prior_end = end; stages[name] = data
    image = manifest['buildImage']['id'].removeprefix('sha256:')
    require(re.fullmatch('[a-f0-9]{64}', image) is not None
            and all(s['imageId'].removeprefix('sha256:') == image for s in stages.values()), 'Actual build image identity differs')
    image_check(member(release, 'reports/prepare/build-image.json'), image)
    build = load(member(release, stages['build']['paths']['buildStatus']))
    require(build.get('exitCode') == 0 and build.get('sourceCommit') == SOURCE
            and build.get('officialBuildId') == snapshot['buildId'] and build.get('sourceOnly') is False,
            'The actual VMR build did not pass under the CI build ID')
    require(build.get('action') == 'build' and build.get('targetRid') == 'linux-arm64'
            and timestamp(stages['build']['startedAtUtc']) <= timestamp(build['startedAt']) <= timestamp(build['finishedAt'])
            <= timestamp(stages['build']['finishedAtUtc']), 'Fresh inner VMR build timestamps/action must belong to its outer stage')
    preparation = load(member(release, stages['prepare']['paths']['sysrootValidation']))
    sysroot_check(release, preparation)
    scan = load(member(release, stages['scan']['paths']['scanExecution']))
    scan_summary = validate_scan(release, scan)
    test = stages['test']['paths']; test_status = load(member(release, test['testStatus']))
    require(test_status.get('exitCode') == 0 and test_status.get('sourceCommit') == SOURCE
            and test_status.get('officialBuildId') == snapshot['buildId'], 'The actual upstream test command failed')
    require(test_status.get('action') == 'test' and test_status.get('targetRid') == 'linux-arm64'
            and timestamp(stages['test']['startedAtUtc']) <= timestamp(test_status['startedAt']) <= timestamp(test_status['finishedAt'])
            <= timestamp(stages['test']['finishedAtUtc']), 'Fresh inner upstream test timestamps/action must belong to its outer stage')
    tests = parse_tests(member(release, test['commonTrx']), member(release, test['scenarioXml']))
    native = {name: native_check(member(release, stages['verify']['paths'][name]), archive)
              for name in ('ubuntu22', 'ubuntu24', 'debian13')}
    require(len({json.dumps(n, sort_keys=True) for n in native.values()}) == 1, 'Native archive ABI results differ between user spaces')
    for name, data in native.items():
        data['userland'] = userland_check(release, name, stages['verify'])
    collect_path = member(release, 'collect-receipt.json'); collect = load(collect_path)
    require(collect.get('status') == 'passed' and collect.get('exitCode') == 0
            and all(str(collect.get(k)) == str(snapshot[k]) for k in identities), 'The final collection receipt differs')
    require(checked(release, collect['manifest']) == manifest_path, 'Final collection does not bind this manifest')
    require(timestamp(collect['startedAtUtc']) >= prior_end and timestamp(collect['finishedAtUtc']) >= timestamp(collect['startedAtUtc']),
            'Final collection must follow completed validation stages')
    outer = {archive['path'], 'build-manifest.json', 'SHA256SUMS', 'SHA512SUMS', 'collect-receipt.json'}
    for key in ('log', 'commandsFile'):
        path = checked(release, collect[key])
        require(path.parent == release and path.stat().st_size > 0, 'Actual final collector logs must be bound outside reports')
        outer.add(collect[key]['path'])
    if (release / 'ci-validation.json').exists():
        outer.add('ci-validation.json')
    if sources is not None:
        outer.update(p.relative_to(release).as_posix() for p in tree_files(release / 'sources'))
    actual_outer = {p.relative_to(release).as_posix() for p in release_files
                    if 'reports' not in p.relative_to(release).parts[:1]}
    require(actual_outer == outer, 'Unbound files exist outside the final report inventory')
    return {'schemaVersion': 1, 'status': 'passed', **{k: snapshot[k] for k in identities},
            'workflowRef': snapshot['workflowRef'], 'executionContext': snapshot['executionContext'],
            'sdkArchive': archive, 'buildManifest': record(release, manifest_path),
            'snapshot': record(release, snapshot_path), 'collectReceipt': record(release, collect_path),
            'reportFiles': len(rows), 'rebuildInputFiles': len(manifest['rebuildInputs']),
            'scan': scan_summary, 'tests': tests, 'native': native,
            **({'sources': sources} if sources is not None else {}),
            'scope': 'Actual current-run regular VMR build, original clean-source scan, raw upstream tests, three native user spaces and unchanged SDK delivery. No source-only, Stage 2, workload, universal Linux or cold-resource success claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('freeze')
    for name in ('project-root', 'source-dir', 'release-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('build-id', 'build-revision', 'run-id', 'run-attempt', 'project-commit', 'workflow-ref'):
        p.add_argument('--' + name, required=True)
    p = commands.add_parser('validate')
    for name in ('release-dir', 'project-root', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p = commands.add_parser('verify-release'); p.add_argument('--release-dir', type=Path, required=True)
    p.add_argument('--expected-project-commit', required=True); p.add_argument('--expected-run-id', required=True)
    p.add_argument('--expected-run-attempt')
    args = parser.parse_args()
    if args.command == 'freeze':
        freeze(args); return 0
    release = args.release_dir.absolute(); result = validate_bundle(release, args.project_root.absolute() if args.command == 'validate' else None)
    if args.command == 'validate':
        require(args.output.absolute() == release / 'ci-validation.json' and not args.output.exists(), 'Use a new validation envelope outside reports')
        for environment, key in (('GITHUB_SHA', 'projectCommit'), ('GITHUB_RUN_ID', 'runId'), ('GITHUB_RUN_ATTEMPT', 'runAttempt')):
            require(not os.environ.get(environment) or os.environ[environment] == result[key], 'Actual workflow environment differs: ' + environment)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2); stream.write('\n')
    else:
        require(load(member(release, 'ci-validation.json')) == result, 'The portable CI validation envelope differs')
        require(result['projectCommit'] == args.expected_project_commit and result['runId'] == args.expected_run_id
                and (args.expected_run_attempt is None or result['runAttempt'] == args.expected_run_attempt),
                'Release download belongs to another commit/run/attempt')
    print(json.dumps({'status': 'passed', 'command': args.command, 'projectCommit': result['projectCommit'],
                      'runId': result['runId'], 'sdkSha256': result['sdkArchive']['sha256']}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
