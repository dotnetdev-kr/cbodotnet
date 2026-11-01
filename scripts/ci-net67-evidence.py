#!/usr/bin/env python3
"""Portable gates for fresh .NET 6/7 generated-source ARM64 CI deliveries."""
import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import runpy
import subprocess
import xml.etree.ElementTree as ET

_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_arch.py')))
get_arch = _ARCH['get_arch']

VERSIONS = {
    '6': {'sdk': '6.0.136', 'runtime': '6.0.36', 'bootstrap': '6.0.135',
          'commit': 'd638663530d923adbe0442604b7a6562127321e9',
          'baselineSize': 171088243,
          'psbSize': 4149235810, 'psbSha256': '9b6befe3f7aab2bdb876940c89cc7bc738fa3e96effef619b701da9e8768fdb9',
          'baselineSha512': '516824d8272ade670fcc2dd0ee33154a00738b5eeab2de1532ee3e0529f670a6e5b30a55423ae75f02bd4aab9a75264bddecf735be0305d3b7e7fb6697ec8f17',
          'rids': ['ubuntu.22.04-arm64', 'ubuntu.24.04-arm64', 'linux-arm64']},
    '7': {'sdk': '7.0.120', 'runtime': '7.0.20', 'bootstrap': '7.0.118',
          'commit': '25b977658c06fd0217ec0bc0714398bb9d0a7bb0',
          'baselineSize': 190303803,
          'psbSize': 1019244017, 'psbSha256': '0a4e8447c72047bf7d73d0766abba315d64976fdc8aef7236ddee0bbb62dfa5d',
          'baselineSha512': 'f530f794afe3c3b9bd87b8ed509a1a13b1c8fe6f2bc6e6cce3e8cd6b56327c0ff27fc138122c2dad68770cc5015737e007ef5706599c189ef0cc7521cbf0b654',
          'rids': ['ubuntu.22.04-arm64', 'linux-arm64', 'linux-arm64']},
}


def version_config(major, arch='arm64'):
    selected = copy.deepcopy(VERSIONS[major])
    get_arch(arch)
    if arch == 'x64':
        pins = {
            '6': (177318505, 'bf9d5a4a8868f6806e7c4a2b13d081fc9c0a1475b52751ca211bc85faa2003fbf63e658e1158911ff1fe25fe3aab691e5a2181b14da919c9114ffdcb9b3c90be'),
            '7': (195141235, 'cb9faba83ab276c935ef35b31f016ca4617f0d967c5b4bf1e993c2159992fb59d1dd25dce09928915b9ff586ead7acf92ec1dd96937c93317a99ca0c92b616c9'),
        }
        selected['baselineSize'], selected['baselineSha512'] = pins[major]
        selected['rids'] = [rid.replace('-arm64', '-x64') for rid in selected['rids']]
    return selected
CHECKS = {'consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
          'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp'}


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary absolute file is required: ' + str(path))
    return path


def member(root, name):
    value = PurePosixPath(name)
    require(value.parts and not value.is_absolute() and '..' not in value.parts and value.as_posix() == name
            and '\\' not in name and ':' not in name, 'Unsafe evidence path: ' + name)
    return ordinary(root.joinpath(*value.parts))


def fingerprint(path):
    ordinary(path); before = path.stat(); hashes = {k: hashlib.new(k) for k in ['sha256', 'sha512']}
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024*1024), b''):
            for h in hashes.values(): h.update(data)
    after = path.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns),
            'A file changed during hashing')
    return dict(bytes=after.st_size, **{key: value.hexdigest() for key, value in hashes.items()})


def record(root, path):
    return dict(path=path.relative_to(root).as_posix(), **fingerprint(path))


def checked(root, row):
    path = member(root, row['path'])
    require(all(row.get(key) == value for key, value in fingerprint(path).items()), 'Evidence digest differs: ' + row['path'])
    return path


def load(path):
    require(ordinary(path).stat().st_size < 128*1024*1024, 'Oversized JSON evidence')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as out:
        json.dump(data, out, indent=2); out.write('\n')


def generated_relative(value, sdk):
    require(isinstance(value,str) and value.startswith('/') and '\0' not in value
            and '..' not in PurePosixPath(value).parts, 'Unsafe recorded generated-source path')
    prefix='/work/source-v'+sdk+'/'
    normalized=posixpath.normpath(value)
    require(normalized.startswith(prefix), 'Recorded copy path escaped the generated source')
    return normalized[len(prefix):]


def effective_profile(original, build_id):
    """Remove historical measurements; preserve source and construction policy."""
    result = copy.deepcopy(original)
    result.pop('verification', None); result.pop('status', None)
    for key in ['abiRequirementVerified', 'observedMaximumRequiredVersions']:
        result['target'].pop(key, None)
    result['container'].pop('observedDerivedImageId', None)
    for key in ['nativeSysrootForwardingVerified', 'note']:
        result['build'].pop(key, None)
    result['build']['ciBuildId'] = build_id
    result['build']['sharedComponents'] = 'Both shared frameworks must match this run\'s local producer archives and completed installer copy tasks; see reports/construction/origin.json.'
    result['construction'] = {'upstreamSharedRuntimeReused': False,
        'note': 'Current-run local framework construction and exact SDK payload identity require reports/construction/origin.json. Original/transformed PSB, bootstrap SDK, reference packages and online inputs remain; no clean-bootstrap, Stage 2 or zero-prebuilt claim is made.'}
    return result


def git_hash(kind, data):
    return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()


def snapshot_tree(release, rows):
    tree = {}; names = set(); prefix = 'reports/ci-inputs/project/'
    for row in rows:
        require(row['path'].startswith(prefix), 'Source snapshot escapes its root')
        name = row['path'][len(prefix):]; path = checked(release, row)
        require(name not in names and row['gitMode'] in ['100644', '100755'], 'Duplicate/unsupported source entry')
        names.add(name); blob = git_hash('blob', path.read_bytes())
        require(blob == row['gitBlobSha1'], 'Frozen source differs from original Git blob')
        parent = tree
        for part in PurePosixPath(name).parts[:-1]: parent = parent.setdefault(part, {})
        parent[PurePosixPath(name).name] = (row['gitMode'], blob)
    def digest(entries):
        data = b''
        for name, value in sorted(entries.items(), key=lambda v: v[0].encode() + (b'/' if isinstance(v[1], dict) else b'')):
            mode, sha = ('40000', digest(value)) if isinstance(value, dict) else value
            data += mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
        return git_hash('tree', data)
    return digest(tree)


def freeze(project, release, major, identity, arch='arm64'):
    selected = version_config(major, arch)
    architecture = get_arch(arch)
    git = lambda *args: subprocess.check_output(['git', '-C', str(project), *args])
    require(not git('status', '--porcelain', '--untracked-files=all').strip(), 'A pristine orchestration checkout is required')
    require(git('rev-parse', 'HEAD').decode().strip() == identity['projectCommit'], 'Project commit changed')
    destination = release / 'reports/ci-inputs'; destination.mkdir(parents=True)
    rows = []
    for entry in git('ls-files', '--stage', '-z').decode().split('\0'):
        if not entry: continue
        metadata, name = entry.split('\t', 1); mode, blob, stage = metadata.split()
        require(stage == '0' and mode in ['100644', '100755'], 'Unsupported tracked source')
        original = ordinary(project / name)
        actual = subprocess.check_output(['git', '-C', str(project), 'hash-object', '--path='+name, str(original)]).decode().strip()
        require(actual == blob, 'Worktree source differs from committed/filter-normalized bytes')
        data = git('cat-file', 'blob', blob); target = destination / 'project' / name
        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        if mode == '100755': target.chmod(0o755)
        rows.append(dict(record(release, target), gitMode=mode, gitBlobSha1=blob))
    commit = git('cat-file', 'commit', identity['projectCommit'])
    (destination / 'project-commit.txt').write_bytes(commit)
    require(commit.startswith(('tree '+snapshot_tree(release, rows)+'\n').encode()), 'Frozen Git tree differs')
    original = _ARCH['profile_path'](destination / 'project', selected['sdk'], arch)
    write(destination / 'effective-profile.json', effective_profile(load(original), identity['buildId']))
    snapshot = dict(schemaVersion=1, major=major, sdkVersion=selected['sdk'], sourceCommit=selected['commit'],
                    executionContext='github-actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local-diagnostic',
                    projectFiles=rows, projectCommitObject=record(release, destination / 'project-commit.txt'),
                    originalProfile=record(release, original), effectiveProfile=record(release, destination / 'effective-profile.json'), **identity)
    if arch == 'x64':
        snapshot.update(architecture=arch, targetRid=architecture['rid'], workflowRef=os.environ.get('GITHUB_WORKFLOW_REF'))
    write(destination / 'snapshot.json', snapshot)
    return snapshot


def xml(path):
    data = ordinary(path).read_bytes()
    require(len(data) < 64*1024*1024 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(), 'Unsupported XML')
    return ET.fromstring(data)


def smoke_results(trx):
    root = xml(trx); ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    tests = root.findall('./t:Results/t:UnitTestResult', ns)
    counters = root.find('./t:ResultSummary/t:Counters', ns)
    require(len(tests) == 42 and counters is not None, 'All original 42 smoke cases are required')
    # Pinned VSTest/xUnit TRX records the skipped Poison case as a NotExecuted
    # result but leaves Counters.notExecuted=0. Executed=41 and the individual
    # 42 result rows identify the real 41-pass/one-skip outcome independently.
    require(all(int(counters.get(k, '-1')) == v for k, v in
                {'total':42, 'executed':41, 'passed':41, 'failed':0, 'error':0,
                 'timeout':0, 'aborted':0, 'notExecuted':0}.items()), 'Unexpected upstream counters')
    skipped = [x for x in tests if x.get('outcome') == 'NotExecuted']
    require(len(skipped) == 1 and 'PoisonTests.VerifyUsage' in skipped[0].get('testName', ''), 'Only the original absent-poison-input skip is allowed')
    require(all(x.get('outcome') in ['Passed', 'NotExecuted'] for x in tests), 'A smoke test failed')
    omni = [x for x in tests if 'OmniSharp' in x.get('testName', '')]
    require(len(omni) == 12 and all(x.get('outcome') == 'Passed' for x in omni), 'All 12 OmniSharp cases are required')
    return {'total':42, 'passed':41, 'failed':0, 'skipped':1, 'omniSharpPassed':12,
            'scope':'Original suite and assertions; only absent poison-report input skipped. OmniSharp timed scenarios do not prove full editor functionality.'}


def x64_sysroot(release, provenance, major):
    """Authenticate the explicit native producer and its upstream package inputs."""
    producer_name = 'scripts/prepare-net67-x64-sysroot.sh'
    producer = member(release, 'reports/ci-inputs/project/' + producer_name)
    same = lambda row, expected: all(row.get(key) == expected[key] for key in ('bytes', 'sha256', 'sha512'))
    generators = {'6': 'efaddf18971de883465ef172297cbb9821b2568fc2f41f360a0ba2e74eaa3704',
                  '7': '515ca92a06354898bfff4edf524292595eb75bef3668325d381b4c4bcdc1d979'}
    arguments = ['--force-check-gpg', '--keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg',
                 '--arch=amd64', 'xenial', '/inputs/x64-xenial', 'https://archive.ubuntu.com/ubuntu']
    require(provenance.get('method') == 'explicit-native-amd64-debootstrap'
            and provenance.get('architecture') == 'amd64'
            and provenance.get('originalGeneratorVerified') is True
            and provenance.get('upstreamGeneratorInvoked') is False
            and provenance.get('qemuDebootstrapWrapper') is False
            and provenance['generator'] == 'src/runtime/eng/common/cross/build-rootfs.sh'
            and provenance['generatorSha256'] == generators[major]
            and provenance['generatorArguments'] == arguments
            and same(provenance['producer'], fingerprint(producer)), 'The actual signed amd64 sysroot producer differs')
    packages = ['build-essential','symlinks','libicu-dev','liblttng-ust-dev','libunwind8-dev',
                'libcurl4-openssl-dev','libkrb5-dev','libssl-dev','zlib1g-dev','libomp5','libomp-dev','liblldb-3.9-dev']
    require(provenance['packageList'] == packages, 'The pinned upstream Xenial package set differs')
    original = member(release, 'reports/sysroot/upstream-sources.list')
    applied = member(release, 'reports/sysroot/applied-sources.list')
    require(fingerprint(original)['sha256'] == '81da96b804b513d7b3b41291e02c2a1198a432a452d11fa4558f25cada1ab78a'
            and provenance['sourceList']['path'].endswith('/src/runtime/eng/common/cross/x86/sources.list.xenial')
            and same(provenance['sourceList'], fingerprint(original))
            and same(provenance['retainedSourceList'], fingerprint(original))
            and same(provenance['appliedSourceList'], fingerprint(applied))
            and same(provenance['retainedAppliedSourceList'], fingerprint(applied))
            and provenance['sourceListTransformation'] == 'archive-http-to-https'
            and applied.read_bytes() == original.read_bytes().replace(b'http://archive.ubuntu.com', b'https://archive.ubuntu.com'),
            'The pinned source list or exact HTTPS transport adaptation differs')
    tls = provenance['aptTls']; ca_info = '/etc/ssl/certs/cbodotnet-producer-ca.pem'
    ca = fingerprint(member(release, 'reports/sysroot/apt-tls-ca.pem'))
    require(tls['peerVerification'] is True and tls['hostVerification'] is True
            and tls['packageSignatureVerification'] is True and tls['caInfo'] == ca_info
            and tls['arguments'] == ['-o','Acquire::https::CaInfo='+ca_info,
                                     '-o','Acquire::https::Verify-Peer=true','-o','Acquire::https::Verify-Host=true']
            and tls['source']['path'] == '/etc/ssl/certs/ca-certificates.crt'
            and tls['retained']['path'] == '/delivery/reports/sysroot/apt-tls-ca.pem'
            and tls['target']['path'] == '/inputs/x64-xenial'+ca_info
            and all(same(row, ca) for row in (tls['source'], tls['retained'], tls['target'])),
            'The verified native apt TLS trust input or policy differs')
    for key, name in [('archiveRelease','archive-release'),('archiveSignature','archive-release.gpg'),
                      ('signatureStatus','archive-signature-status.txt')]:
        require(same(provenance[key], fingerprint(member(release, 'reports/sysroot/'+name))), 'Archive signature input differs')
    signature = member(release, 'reports/sysroot/archive-signature-status.txt').read_text()
    require(provenance.get('releaseSignatureLogVerified') is True
            and re.search(r'^\[GNUPG:\] VALIDSIG (790BC7277767219C42C86F933B4FE6ACC0B21F32|F6ECB3762474EDA9D21B7022871920D1991BC93C|630239CC130E1A7FD81A27B140976EAF437D05B5) ', signature, re.MULTILINE),
            'The native sysroot archive lacks an accepted Ubuntu signature')
    package_rows = [line.split('\t') for line in member(release, 'reports/sysroot/sysroot-packages.tsv').read_text().splitlines() if line]
    require(package_rows and all(len(row) == 3 and row[2] in ('amd64','all') for row in package_rows)
            and any(row[0] in ('libc6','libc6:amd64') and row[1].startswith('2.23') and row[2] == 'amd64' for row in package_rows),
            'The recorded native Xenial packages contain another architecture or libc baseline')


def validate(release, expected, arch='arm64'):
    architecture = get_arch(arch)
    snap = load(member(release, 'reports/ci-inputs/snapshot.json')); major = snap['major']; selected = version_config(major, arch)
    require(snap['executionContext'] == 'github-actions' and all(str(snap[k]) == str(v) for k,v in expected.items()), 'Wrong run/project identity')
    tree = snapshot_tree(release, snap['projectFiles']); commit = checked(release, snap['projectCommitObject']).read_bytes()
    require(git_hash('commit', commit) == snap['projectCommit'] and commit.startswith(('tree '+tree+'\n').encode()), 'Frozen source is not the expected Git commit')
    profile = load(checked(release, snap['effectiveProfile'])); original = load(checked(release, snap['originalProfile']))
    require(profile['host']['architecture'] == arch and profile['target']['rid'] == architecture['rid'], 'Wrong native architecture profile')
    if arch == 'x64':
        require(snap.get('architecture') == arch and snap.get('targetRid') == architecture['rid']
                and snap.get('workflowRef') == 'dotnetdev-kr/cbodotnet/.github/workflows/sdk-x64.yml@refs/heads/main',
                'The x64 producer workflow and target must be explicit')
    require(profile == effective_profile(original, snap['buildId']), 'Unapproved effective profile changes')
    require(profile['source']['commit'] == selected['commit'] and profile['build']['sourceOnly'] is True
            and profile['construction']['upstreamSharedRuntimeReused'] is False, 'Source/construction policy changed')
    manifest_path = member(release, 'build-manifest.json'); manifest = load(manifest_path)
    archive = manifest['sdkArchive']; checked(release, archive)
    if arch == 'x64':
        require(archive['path'] == 'cbodotnet-sdk-'+selected['sdk']+'-linux-x64-build.'+str(snap['buildRevision'])+'.tar.gz',
                'The x64 SDK filename must bind its target and build revision')
    require(manifest['sdkVersion'] == selected['sdk'] and manifest['targetRid'] == architecture['rid']
            and manifest['sourceOnly'] is True and manifest['profile']['contents'] == profile
            and manifest['source']['actualCommit'] == selected['commit'], 'Collected SDK identity differs')
    for algorithm,name in [('sha256','SHA256SUMS'),('sha512','SHA512SUMS')]:
        require(member(release,name).read_text() == archive[algorithm]+'  '+archive['path']+'\n', 'SDK checksum file differs')
    frozen={row['path'].removeprefix('reports/ci-inputs/project/'):row for row in snap['projectFiles']}
    for row in manifest['rebuildInputs']:
        require(row['path'] in frozen and all(row[k] == frozen[row['path']][k] for k in ['bytes','sha256','sha512']), 'Collected rebuild input differs from frozen source')
    reports = release / 'reports'; rows = manifest['reports']['files']
    actual = {p.relative_to(reports).as_posix() for p in reports.rglob('*') if p.is_file()}
    require(actual == {row['path'] for row in rows}, 'Report inventory membership changed')
    for row in rows:
        checked(release, dict(row, path='reports/'+row['path']))
    stages = {name: load(member(release, 'reports/ci/stages/'+name+'.json')) for name in ['prepare','build','scan','test','verify']}
    identities = ['projectCommit','runId','runAttempt','buildId','buildRevision']
    for name, stage in stages.items():
        require(stage['stage'] == name and stage['status'] == 'passed' and stage['exitCode'] == 0 and stage['commands']
                and all(str(stage[k]) == str(snap[k]) for k in identities), 'Missing successful fresh stage: '+name)
        require(stage['sourceCommit'] == selected['commit'] and stage['imageId'] == manifest['buildImage']['id'], 'Build image/source changed')
        if arch == 'x64':
            require(stage['environment']['architecture'] == architecture['uname'], 'A native x64 producer is required')
    applicability=load(member(release,'reports/scan/applicability.json'))
    require(applicability['status'] == 'not-applicable' and applicability['reason'], 'The absence of a legacy VMR source scanner must be explicit')
    policy=load(member(release,'reports/prepare/seccomp.json'))
    require(policy['seccompUnconfined'] is False and policy['allOtherRulesUnchanged'] is True and policy['addedRuleCount'] in [0,1], 'Unreviewed build seccomp changes')
    for key,name in [('basePolicy','seccomp-base-policy.json'),('outputPolicy','seccomp-policy.json')]:
        actual=fingerprint(member(release,'reports/prepare/'+name))
        require(all(policy[key][k] == v for k,v in actual.items()), 'Recorded syscall policy bytes differ')
    for name in ['build','test']:
        status = load(member(release, 'reports/'+name+'/'+name+'-status.json'))
        require(status['exitCode'] == 0 and status['action'] == name and status['installerCommit'] == selected['commit']
                and status['sourceOnly'] is True and status['portableBuild'] is True and status['crossBuild'] is True,
                'Original upstream action failed: '+name)
    generation = load(member(release, 'reports/generation/generation.json'))
    require(generation['installerCommit'] == selected['commit'] and generation['preserveTarballGitFolders'] is True,
            'Generated source provenance is missing')
    for component, pin in profile['generatedSource']['componentCommits'].items():
        require(generation['componentCommits'].get(component) == pin, 'Generated source pin changed: '+component)
    sysroot = load(member(release,'reports/sysroot/sysroot-provenance.json'))
    current = load(member(release,'reports/sysroot/current-validation.json'))
    require(sysroot['sourceCommit'] == selected['commit'] and sysroot['runtimeCommit'] == generation['componentCommits']['runtime']
            and sysroot['packageSignatureVerification'] is True and sysroot['emulation'] is False
            and current['status'] == 'passed' and current['files'] > 0 and current['symlinks'] > 0, 'Authenticated complete sysroot verification is required')
    if arch == 'x64':
        x64_sysroot(release, sysroot, major)
    log = member(release,'reports/sysroot/'+Path(sysroot['logFile']).name).read_text()
    require(('Valid Release signature' in log or (arch == 'x64' and 'Release signature verified' in log))
            and '--no-check-gpg' not in log and '--skipsigcheck' not in log,
            'Actual successful upstream Release signature verification is required')
    keyrings = load(member(release,'reports/sysroot/producer-inputs.json'))['keyrings']
    require(len(keyrings) == 3, 'All actual current/historical sysroot signing keyrings are required')
    for row in keyrings: checked(release,row)
    bootstrap = load(member(release,'reports/bootstrap/bootstrap-inputs.json'))
    require(bootstrap['installerCommit'] == selected['commit'] and bootstrap['bootstrapSdk'] == selected['bootstrap']
            and any(row['bytes'] == selected['psbSize'] and row['sha256'] == selected['psbSha256'] for row in bootstrap['originalInputs']),
            'The fixed original PSB and selected bootstrap SDK are required')
    if arch == 'arm64':
        require(bootstrap['finalInputs'] and bootstrap['arm64PackageEntries'], 'Transformed native bootstrap inputs are missing')
    else:
        require(bootstrap.get('targetArchitecture') == 'x64' and bootstrap.get('bootstrapMode') == 'native-original-inputs'
                and bootstrap['finalInputs'] and bootstrap['nativePackageEntries'], 'Original native x64 bootstrap inputs are required')
        native_rid, native_count = ('linux-x64', 14) if major == '6' else ('centos.8-x64', 12)
        require(bootstrap.get('nativePackageRid') == native_rid and len(bootstrap['nativePackageEntries']) == native_count
                and all(native_rid + '.' in name.lower() and name.lower().endswith('.nupkg')
                        for name in bootstrap['nativePackageEntries']), 'Pinned native x64 PSB package identities differ')
        identity = lambda row: (Path(row['path']).name, row['bytes'], row['sha256'], row['sha512'])
        require({identity(row) for row in bootstrap['finalInputs']} == {identity(row) for row in bootstrap['originalInputs']}
                and all('Bootstrap' not in Path(row['path']).name for row in bootstrap['finalInputs']),
                'The native x64 PSB inputs must remain byte-identical to the originals')
    origin = load(member(release, 'reports/construction/origin.json'))
    require(origin['status'] == 'passed' and origin['sdkArchive']['sha256'] == archive['sha256']
            and len(origin['components']) == 2 and all(x['originVerified'] and x['identicalEntryCount'] > 0 for x in origin['components']),
            'Fresh local framework origins did not pass')
    for row in origin['evidenceFiles']: checked(release, row)
    comparison = load(member(release,'reports/construction/identity/shared-framework-identity.json'))
    require(comparison['status'] == 'passed' and comparison['sdkArchive']['sha256'] == archive['sha256']
            and len(comparison['comparisons']) == 2 and all(row['identical'] and row['sdkEntries'] == row['inputEntries']
            and row['sdkEntryCount'] > 0 for row in comparison['comparisons']), 'Complete current shared-framework comparison is required')
    replay = load(member(release,'reports/origin-tools/replay.json'))
    require(replay['completedReplay'] and replay['eventsRead'] > 0
            and replay['inputSha256'] == fingerprint(member(release,'reports/origin-tools/installer.binlog'))['sha256'], 'Actual closed installer replay is required')
    observation_data = member(release, 'reports/build/installer-observations.jsonl').read_bytes()
    require(len(observation_data) <= 64 * 1024 * 1024, 'Installer observations exceed the bounded evidence size')
    raw_observations = [json.loads(line) for line in observation_data.decode('utf-8').splitlines() if line]
    for component in origin['components']:
        require(component['version'] == selected['runtime'] and component['completedLocalCopies'], 'A current local copy proof is missing')
        for copy in component['completedLocalCopies']:
            task = copy['task']; require(task in replay['tasks'] and task['Succeeded'] and task['Started'] < task['Finished']
                    and len(task['Attempts']) == 1 and task['Attempts'][0]['Kind'] == 'local-copy'
                    and task['Started'] < task['Attempts'][0]['Event'] < task['Finished'], 'Malformed completed local-copy task proof')
            attempt=task['Attempts'][0]
            feed='artifacts/obj/'+arch+'/Release/blob-feed/assets/'+component['localFeedArchive']['name']
            destination=generated_relative(attempt['Destination'],selected['sdk'])
            require(generated_relative(attempt['Source'],selected['sdk']) == feed and destination.startswith('src/installer/'), 'Completed task copied another input')
            require(copy['destinationObservations'] and all(all(row[key] == component['localFeedArchive'][key]
                    for key in ['bytes','sha256','sha512']) and row['feed'] == feed and row['destination'] == destination
                    for row in copy['destinationObservations']), 'Observed destination bytes differ from local framework input')
            require(all(row in raw_observations for row in copy['destinationObservations']),
                    'Inline destination observations are not present in the actual producer journal')
    tests = smoke_results(member(release, 'reports/test/upstream.trx'))
    tools = load(member(release, 'reports/test/net'+major+'-test-tools.json'))
    require(tools.get('status') == 'passed', 'Pinned OmniSharp fixture did not verify')
    if arch == 'x64':
        require(tools['url'] == 'https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.6/omnisharp-linux-x64-net6.0.tar.gz'
                and tools['expectedArchive'] == {'bytes': 43149563, 'sha256': 'c631cf552590ee8f00cbea441e99a94f689bf1832f1f8de2d5a00d5d5d18140c'}
                and tools['extractedMembersVerified'] is True, 'The pinned native x64 OmniSharp fixture is required')
        tool_members = member(release, 'reports/test/net'+major+'-test-tool-members.json')
        actual = fingerprint(tool_members)
        require(all(tools['memberReceipt'][key] == actual[key] for key in ('bytes', 'sha256')), 'OmniSharp inventory differs')
    official = load(member(release,'reports/test-inputs/official-sdk-baseline.json'))
    require(official['version'] == selected['sdk'] and official['bytes'] == selected['baselineSize']
            and official['sha512'] == selected['baselineSha512'], 'The exact official comparison baseline is required')
    if arch == 'x64':
        require(official['rid'] == architecture['rid'], 'Official comparison SDK architecture differs')
    content = load(member(release,'reports/test/comparison/summary.json'))
    require(content['warningMode'] is True, 'The original SDK content comparison policy must remain explicit')
    checked(release,content['actualDiff']); checked(release,content['baselineDiff'])
    prebuilt = load(member(release, 'reports/prebuilt/summary.json'))
    require(prebuilt['preservedRawReports'] and prebuilt['scope'], 'Actual prebuilt reports must be retained without a clean-bootstrap claim')
    native = {}
    for name, rid in zip(['ubuntu22','ubuntu24','debian13'], selected['rids']):
        data = load(member(release, 'reports/verify-'+name+'/verification.json'))
        require(data['verificationStatus'] == 'passed' and data['sdkVersion'] == selected['sdk'] and data['reportedRid'] == rid
                and data['framework'] == 'net'+major+'.0' and data['functionalChecks'] == dict.fromkeys(CHECKS, 'passed')
                and data['archive']['sha256'] == archive['sha256'] and data['archive']['sdkContentMatched'] is True,
                'Native checks failed: '+name)
        abi = data['abi']; version = lambda s: tuple(map(int, s.split('.')))
        if arch == 'x64':
            require(data.get('hostArchitecture') == architecture['uname'] and abi.get('symbolicGlibcRequirements') == [],
                    'The actual x64 verifier host and supported GLIBC symbols are required')
        require(abi['machines'] == {architecture['elf']:abi['elfFileCount']} and abi['elfFileCount'] > 0
                and abi['glibcCeilingPassed'] and abi['glibcCeiling'] == '2.23'
                and version(abi['maximumRequiredVersions']['GLIBC']) <= version('2.23')
                and version(abi['maximumRequiredVersions']['GLIBCXX']) <= version('3.4.21')
                and version(abi['maximumRequiredVersions']['CXXABI']) <= version('1.3.7'), 'Native ABI gate failed')
        native[name] = {'rid':rid, 'checks':6, 'abi':abi['maximumRequiredVersions']}
        userland = load(member(release,'reports/ci/'+name+'-userland.json'))
        os_id,os_version = ('ubuntu','22.04') if name == 'ubuntu22' else ('ubuntu','24.04') if name == 'ubuntu24' else ('debian','13')
        require(userland['architecture'] == architecture['uname'] and userland['uid'] > 0 and userland['osRelease'] == {'ID':os_id,'VERSION_ID':os_version}
                and all(value is None for value in userland['environmentOverrides'].values()), 'Actual native user-space identity/overrides differ')
        if arch == 'x64':
            require(set(userland['environmentOverrides']) == {'LD_LIBRARY_PATH','DOTNET_ROOT','DOTNET_SYSTEM_GLOBALIZATION_INVARIANT',
                    'CLR_ICU_VERSION_OVERRIDE','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics','DOTNET_ROOT_X64'}, 'Complete x64 ambient overrides are required')
        inspected = load(member(release,'reports/ci/'+name+'-verification-image.json'))[0]
        require(inspected['Id'] == userland['imageId'] and inspected['Architecture'] == architecture['image'] and inspected['Os'] == 'linux'
                and any(userland['imageId'] in command and '--network=none' in command and 'bash' in command
                        for command in stages['verify']['commands']), 'Actual native verifier image invocation is missing')
    source = member(release, 'sources/source-manifest.json')
    require(source.read_bytes() == member(release, 'reports/ci/used-source.json').read_bytes(), 'Used-source controls differ')
    if arch == 'x64':
        require(load(source)['targetRid'] == architecture['rid'], 'Source delivery architecture differs')
    collect = load(member(release, 'collect-receipt.json'))
    require(collect['status'] == 'passed' and collect['exitCode'] == 0 and all(str(collect[k]) == str(snap[k]) for k in identities), 'Final collector failed')
    require(checked(release, collect['manifest']) == manifest_path, 'Final manifest is not bound')
    for key in ['log','commandsFile']: checked(release, collect[key])
    require(not any(path.is_symlink() for path in release.rglob('*')), 'Delivery must not contain redirected files/directories')
    outer={archive['path'],'build-manifest.json','SHA256SUMS','SHA512SUMS','collect-receipt.json',collect['log']['path'],collect['commandsFile']['path']}
    if (release/'ci-validation.json').exists(): outer.add('ci-validation.json')
    actual={path.relative_to(release).as_posix() for path in release.rglob('*') if path.is_file() and path.relative_to(release).parts[0] not in ['reports','sources']}
    require(actual == outer, 'Unexpected unbound files outside report/source inventories')
    return dict(schemaVersion=1, status='passed', sdkVersion=selected['sdk'], targetRid=architecture['rid'],
                **{k:snap[k] for k in identities}, sdkArchive=archive, sourceManifest=record(release, source),
                buildManifest=record(release, manifest_path), tests=tests, native=native,
                constructionScope='Actual current-run source-only online graph, local framework copy/task and full-payload proof. External bootstrap/reference inputs remain; no Stage2 or zero-prebuilt claim.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, required=True)
    parser.add_argument('--expected-project-commit', required=True)
    parser.add_argument('--expected-run-id', required=True)
    parser.add_argument('--expected-run-attempt', required=True)
    parser.add_argument('--arch', type=_ARCH['canonical_arch'], choices=('arm64', 'x64'), metavar='{aarch64,x64}', default='arm64')
    args = parser.parse_args(); release = args.release_dir.absolute()
    result = validate(release, dict(projectCommit=args.expected_project_commit, runId=args.expected_run_id, runAttempt=args.expected_run_attempt), args.arch)
    path = release / 'ci-validation.json'
    if path.exists(): require(load(path) == result, 'Existing portable validation differs')
    else: write(path, result)
    print(json.dumps({'status':'passed','sdkVersion':result['sdkVersion'],'archiveSha256':result['sdkArchive']['sha256']}))


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: '+str(error))
