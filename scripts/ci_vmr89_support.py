#!/usr/bin/env python3
"""Evidence primitives for the pinned .NET 8/9 native ARM64 CI adapters."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ci10_primitives', HERE / 'ci-net10-evidence.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)
V = {'8': dict(sdk='8.0.133', commit='7d1bf90885cff22e7da72b27e9848e42fd3cb1ae', bootstrap='8.0.131', runtime='8.0.33', sourceOnly=True),
     '9': dict(sdk='9.0.123', commit='9f04b57d1366e21b3178648493d6edffeff2216e', bootstrap='9.0.121', runtime='9.0.22', sourceOnly=False)}
COMPONENTS={'8':{'runtime':'da7a9beabf4cccc624399d583f52f080a4c858c2','aspnetcore':'380bd0d498fbaa0a8ddd67c325aa748dd21f7596'},
            '9':{'runtime':'faaecba82df8933d7af60972138ce25f9c776cbd','aspnetcore':'5aeb916d29e761492c987f1c09895c3ba9cbe1ac'}}
require, fingerprint, record, checked, load = G.require, G.fingerprint, G.record, G.checked, G.load


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2); stream.write('\n')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def capture_consumer_binlog(source, release, version):
    # NET8 retains consumer source, so CleanupRepo never creates its buildLogs copy.
    # Capture the original SourceBuildArcadeBuild producer, rather than that copy.
    relative = ('src/installer/artifacts/source-build/self/src/artifacts/sourcebuild.binlog' if version == '8'
                else 'src/sdk/artifacts/buildLogs/log/Release/source-inner-build.binlog')
    require(version in V, 'Unsupported consumer binlog version')
    producer = G.ordinary(source / relative)
    require(producer.stat().st_size > 0, 'The original consumer binlog must be nonempty')
    target = release / 'reports/construction/consumer.binlog'
    require(not target.exists(), 'The preserved consumer binlog must be new')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(producer, target)
    require(fingerprint(producer) == fingerprint(target), 'The preserved consumer binlog changed')
    dump(release / 'reports/construction/binlog-input.json', dict(sourceRelativePath=relative,
         sourceCommit=V[version]['commit'], archive=record(release, target)))


def effective(original, version):
    result = copy.deepcopy(original)
    result['build']['cleanWhileBuilding'] = version != '8'
    result['build']['sharedComponents'] = ('Requires current-run proof of locally built runtime and ASP.NET inputs.' if version == '8'
                                         else 'Requires current-run proof of locally built runtime and the recorded upstream ASP.NET download.')
    result['construction']['note'] = 'Current-run component origins must pass the independent construction report. Historical local hashes and reports do not qualify this CI output. Bootstrap and other upstream binary inputs remain in scope.'
    return result


def scenario_fence(release, stage, helper):
    # Downloaded project bytes are evidence, never executable validator code.
    spec = importlib.util.spec_from_file_location('ci9_scenario_fence', HERE / 'prepare-scenario-report-fence.py')
    implementation = importlib.util.module_from_spec(spec); spec.loader.exec_module(implementation)
    directory = release / 'reports/test/scenario-report-fence'
    receipt = implementation.verify_report(directory, '9', helper)
    tail = ['python3', '/delivery/reports/ci-inputs/project/scripts/prepare-scenario-report-fence.py', 'apply',
            '--version', '9', '--source-dir', '/vmr', '--reports-dir', '/delivery/reports/test/scenario-report-fence']
    require(sum(command[-len(tail):] == tail for command in stage['commands']) == 1,
            'Exactly one actual pinned scenario completion-fence command is required')
    started = load(release / 'reports/test/test-status.json')['startedAt']
    # The existing wrapper records whole-second starts; only its rounding floor
    # is tolerated here, while the surrounding stage and helper use microseconds.
    require(G.timestamp(stage['startedAtUtc']) <= G.timestamp(receipt['completedAtUtc'])
            <= G.timestamp(started) + dt.timedelta(seconds=1),
            'Scenario completion fence must precede the actual test compilation')
    with G.member(release, 'sources/source-index.jsonl').open(encoding='utf-8') as stream:
        captured = [row for line in stream if (row := json.loads(line)).get('path') == 'vmr/' + implementation.TARGET]
    require(len(captured) == 1 and all(captured[0].get(key) == value for key, value in receipt['patched'].items()),
            'Captured actual scenario runner differs from the tested completion fence')
    return record(release, directory / 'scenario-report-fence.json')


def freeze(project, source, release, version, identity, workflow):
    require(git(project, 'rev-parse', 'HEAD') == identity['projectCommit'] and not git(project, 'status', '--porcelain', '--untracked-files=all'), 'A pristine committed orchestration checkout is required')
    require(git(source, 'rev-parse', 'HEAD') == V[version]['commit'] and not git(source, 'status', '--porcelain', '--untracked-files=all'), 'A fresh pinned VMR checkout is required')
    destination = release / 'reports/ci-inputs'; require(not destination.exists(), 'Refusing existing frozen inputs'); destination.mkdir(parents=True)
    rows = []
    entries = subprocess.check_output(['git', '-C', str(project), 'ls-files', '--stage', '-z']).decode().split('\0')
    for entry in sorted(x for x in entries if x):
        metadata, name = entry.split('\t', 1); mode, blob, stage = metadata.split()
        require(stage == '0' and mode in ('100644', '100755'), 'Only ordinary committed files are supported')
        data = subprocess.check_output(['git', '-C', str(project), 'cat-file', 'blob', blob])
        checkout = G.checkout_details(project, name, blob, data)
        path = destination / 'project' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        rows.append(dict(record(release, path), gitMode=mode, gitBlobSha1=blob, **checkout))
    commit = subprocess.check_output(['git', '-C', str(project), 'cat-file', 'commit', identity['projectCommit']])
    (destination / 'project-commit.txt').write_bytes(commit)
    tree, _ = G.project_tree(release, rows)
    require(G.git_hash('commit', commit) == identity['projectCommit'] and commit.startswith(('tree ' + tree + '\n').encode()), 'The frozen Git tree differs')
    profile = destination / 'project/profiles' / ('dotnet-' + V[version]['sdk'] + '-linux-arm64.json')
    original = load(profile)
    require(original['source']['commit'] == V[version]['commit'] and original['build']['sourceOnly'] is V[version]['sourceOnly'], 'Selected profile differs')
    dump(destination / 'effective-profile.json', effective(original, version))
    result = dict(identity, schemaVersion=1, scenarioReportFenceRequired=version == '9', executionContext='github-actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local-unverified',
                  workflowRef=workflow, sourceInitiallyPristine=True, projectInitiallyPristine=True,
                  inputRepresentation='canonical-git-blobs-with-verified-checkout', projectFiles=rows,
                  projectCommitObject=record(release, destination / 'project-commit.txt'), originalProfile=record(release, profile),
                  effectiveProfile=record(release, destination / 'effective-profile.json'))
    dump(destination / 'snapshot.json', result)


def verify_sysroot(root, reports, version, output):
    provenance = load(reports / 'sysroot-provenance.json')
    require(provenance['sourceCommit'] == V[version]['commit'] and provenance['packageSignatureVerification'] is True
            and provenance['emulation'] is False, 'Signed native sysroot provenance differs')
    expected = {}
    for line in (reports / 'sysroot-files.sha256').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (/inputs/arm64-xenial/.+)', line)
        require(match is not None and match[2] not in expected, 'Invalid sysroot inventory')
        expected[match[2]] = match[1]
    actual, links = {}, set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink(): links.add(str(path) + '\t' + os.readlink(path))
            elif path.is_file(): actual[str(path)] = fingerprint(path)['sha256']
    require(actual and actual == expected and links == set((reports / 'sysroot-symlinks.tsv').read_text().splitlines()), 'Complete sysroot bytes or symlinks changed')
    control = (reports / 'sysroot-file-list.sha256').read_text().strip().split('  ', 1)
    require(control == [fingerprint(reports / 'sysroot-files.sha256')['sha256'], str(reports / 'sysroot-files.sha256')], 'Sysroot checksum control differs')
    log = Path(provenance['logFile']); text = log.read_text()
    require('--skipsigcheck' not in text and 'Valid Release signature' in text, 'Actual authenticated debootstrap log required')
    require(all(fingerprint(Path(row['path']))['sha256'] == row['sha256'] for row in provenance['keyrings']), 'The actual signing-keyring inputs differ')
    record_value = dict(status='passed', sourceCommit=V[version]['commit'], files=len(actual), symlinks=len(links),
                        packageSignatureVerification=True, provenance=fingerprint(reports / 'sysroot-provenance.json'), log=fingerprint(log))
    dump(output, record_value)


def test_results(version, trx, scenario=None):
    root = G.xml(trx); ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    results = root.findall('./t:Results/t:UnitTestResult', ns); counters = root.find('./t:ResultSummary/t:Counters', ns)
    total, passed = (46, 44) if version == '8' else (500, 500)
    require(counters is not None and len(results) == total and len({r.get('executionId') for r in results}) == total,
            'Incomplete actual upstream TRX results')
    require(all(int(counters.get(k, '-1')) == v for k, v in dict(total=total, executed=passed, passed=passed, failed=0).items()), 'Unexpected upstream counters')
    skipped = [r for r in results if r.get('outcome') != 'Passed']
    expected = {'LicenseScanTests.ScanForLicenses', 'PoisonTests.VerifyUsage'} if version == '8' else set()
    require(len(skipped) == len(expected) and {'.'.join(r.get('testName', '').split('.')[-2:]) for r in skipped} == expected
            and all(r.get('outcome') == 'NotExecuted' for r in skipped), 'Unexpected upstream failures/skips')
    value = {'total': total, 'passed': passed, 'failed': 0, 'skipped': len(skipped), 'skippedTests': sorted(expected)}
    if version == '9':
        scenarios = G.xml(scenario); assemblies = scenarios.findall('./assembly'); tests = scenarios.findall('./assembly/collection/test')
        require(len(assemblies) == 1 and len(tests) == 34 and len({t.get('name') for t in tests}) == 34,
                'All 34 actual scenarios are required')
        counts = {key: sum(t.get('result') == label for t in tests) for key, label in [('passed', 'Pass'), ('failed', 'Fail'), ('skipped', 'Skip')]}
        require(counts == {'passed': 32, 'failed': 0, 'skipped': 2}
                and {t.get('method') for t in tests if t.get('result') == 'Skip'} == G.SKIPS
                and all(int(assemblies[0].get(k, '-1')) == v for k, v in dict(total=34, passed=32, failed=0, skipped=2, errors=0).items()), 'Scenario failures/skips/counters differ')
        value['scenarios'] = dict(total=34, **counts, skippedMethods=sorted(G.SKIPS))
    return value


class Observer:
    """Preserve completed component and consumed archives before upstream cleanup."""
    def __init__(self, source, release, version):
        self.source, self.release, self.version = source, release, version
        self.stop = threading.Event(); self.error = None; self.seen = set()
        self.thread = threading.Thread(target=self.watch, daemon=True)

    def watch(self):
        names = {'dotnet-runtime-' + V[self.version]['runtime'] + '-linux-arm64.tar.gz',
                 'aspnetcore-runtime-' + V[self.version]['runtime'] + '-linux-arm64.tar.gz'}
        report = self.release / 'reports/construction'; report.mkdir(parents=True, exist_ok=True)
        pending=report/'observed-inodes';pending.mkdir()
        retained=report/'retained';retained.mkdir()
        preservation_modes={}
        def candidates():
            # Inspect exact pinned producer/feed/consumer locations first. A
            # broad recursive walk can arrive after a component is cleaned.
            result=[]
            for name in names:
                for component in ('runtime','aspnetcore'):
                    for prefix in ('artifacts','artifacts/source-build/self/src/artifacts'):
                        base=self.source/'src'/component/prefix
                        result.extend([base/'packages/Release/Shipping'/name,base/'installers/Release'/name])
                result.extend([self.source/'artifacts/obj/arm64/Release/blob-feed/assets'/name,
                               self.source/'artifacts/arm64/Release'/name,
                               self.source/'artifacts/feed'/name,
                               self.source/'src/sdk/artifacts/obj/redist-installer/Release/downloads'/name,
                               self.source/'src/installer/artifacts/source-build/self/src/artifacts/obj/redist/Release/downloads'/name])
                result.extend(self.source.glob('artifacts/assets/Release/Runtime/*/'+name))
            return result
        try:
            with (report / 'observations.jsonl').open('x') as receipts:
                while True:
                    for path in candidates():
                        try:
                            if not path.is_file() or path.is_symlink():continue
                            info=path.stat();key=(str(path),info.st_dev,info.st_ino)
                            if key in self.seen or info.st_size==0:continue
                            temporary=pending/(hashlib.sha256(repr(key).encode()).hexdigest()+'.tar.gz')
                            mode=preservation_modes.get(key,'hardlink')
                            if not temporary.exists():
                                try:os.link(path,temporary)
                                except OSError as error:
                                    if error.errno!=18:raise
                                    mode='verified-copy'
                            preservation_modes[key]=mode
                            if mode=='verified-copy':shutil.copyfile(path,temporary)
                            time.sleep(.02)
                            with tarfile.open(temporary,'r:gz') as archive:
                                for _ in archive:pass
                            before=fingerprint(temporary)
                            if mode=='verified-copy':require(before==fingerprint(path),'Observed copy source changed')
                            else:require((temporary.stat().st_dev,temporary.stat().st_ino)==(info.st_dev,info.st_ino),'Observed hardlink inode differs')
                            destination=retained/(before['sha256']+'.tar.gz')
                            if not destination.exists():temporary.rename(destination)
                            else:
                                require(fingerprint(destination)==before,'Preserved archive differs');temporary.unlink()
                            receipts.write(json.dumps(dict(observedAtUtc=now(),recordedPath='/vmr/'+path.relative_to(self.source).as_posix(),
                                           archive=record(self.release,destination),stableCompleteArchive=True,preservationMode=mode,
                                           observedDevice=info.st_dev,observedInode=info.st_ino))+'\n');receipts.flush();self.seen.add(key)
                        except (OSError,EOFError,tarfile.TarError):continue
                    if self.stop.wait(.05):break
        except Exception as error: self.error = error

    def start(self):
        self.thread.start()

    def finish(self):
        self.stop.set(); self.thread.join(); require(self.error is None, 'Archive observer failed: ' + str(self.error))


def origin(release, version, write=True):
    root = release / 'reports/construction'
    replay = load(root / 'downloads-status.json')
    require(replay['completedReplay'] is True and replay['buildSucceeded'] is True and replay['completedDownloadTasks'] >= 2
            and replay.get('unfinishedTasks',0)==0,
            'A complete successful actual component binlog replay is required')
    require(fingerprint(root / 'consumer.binlog')['sha256'] == replay['inputSha256'], 'Replayed binlog fingerprint differs')
    tasks = [json.loads(line) for line in (root / 'downloads-tasks.jsonl').read_text().splitlines() if line]
    observations = [json.loads(line) for line in (root / 'observations.jsonl').read_text().splitlines() if line]
    comparison = load(root / 'comparison/shared-framework-identity.json')
    require(comparison['status'] == 'passed' and len(comparison['comparisons']) == 2, 'Full shared-framework byte identity is required')
    components = []
    source_manifest=load(root/'component-source-manifest.json')
    mapped={row['path']:row['commitSha'] for row in source_manifest['repositories'] if row['path'] in COMPONENTS[version]}
    require(mapped==COMPONENTS[version],'Pinned component source revisions differ')
    for framework, prefix, local in [('Microsoft.NETCore.App', 'dotnet-runtime-', True),
                                     ('Microsoft.AspNetCore.App', 'aspnetcore-runtime-', version == '8')]:
        basename = prefix + V[version]['runtime'] + '-linux-arm64.tar.gz'
        selected = []
        for task in tasks:
            if task.get('succeeded') is not True: continue
            require(task.get('taskName') == 'DownloadFile' and task.get('context') and len(task['events']) >= 3
                    and task['events'][0]['kind'] == 'task-started' and task['events'][-1]['kind'] == 'task-finished'
                    and task['events'][-1]['succeeded'] is True, 'Completed actual DownloadFile start/finish evidence is required')
            for event in task['events']:
                if event.get('kind') != ('local-copy-attempt' if local else 'network-download-attempt'): continue
                source, destination = event.get('source', ''), event.get('destination', '')
                if local and source.startswith('file:'): source = unquote(urlsplit(source).path)
                if not source.endswith('/' + basename) or not destination.endswith('/' + basename): continue
                require([row for row in task['events'] if row.get('kind') in ('local-copy-attempt','network-download-attempt')]==[event],
                        'A single unambiguous actual copy/download attempt is required')
                if local:
                    require(source.startswith('/vmr/artifacts/'), 'Local copy source is outside this VMR feed')
                else:
                    uri = urlsplit(source)
                    require(uri.scheme == 'https' and uri.hostname == 'ci.dot.net'
                            and uri.path.startswith('/public/aspnetcore/Runtime/' + V[version]['runtime'])
                            and not uri.username and not uri.password and not uri.query and not uri.fragment, 'Unexpected upstream ASP.NET source')
                def receipts(path):
                    path = posixpath.normpath(unquote(path))
                    return [row for row in observations if posixpath.normpath(row['recordedPath']) == path]
                destination_rows = receipts(destination)
                for received in destination_rows:
                    archive = checked(release, received['archive'])
                    require(received['stableCompleteArchive'] is True, 'A complete observed destination is required')
                    if local:
                        require(any(row['archive']['sha256'] == received['archive']['sha256'] for row in receipts(source)), 'Actual local-feed archive equality is missing')
                        component = 'runtime' if framework == 'Microsoft.NETCore.App' else 'aspnetcore'
                        require(any(row['recordedPath'].startswith('/vmr/src/' + component + '/artifacts/')
                                    and row['archive']['sha256'] == received['archive']['sha256'] for row in observations), 'Actual local component producer archive equality is missing')
                    selected.append((task['context'], received['archive'], event))
        require(selected, 'No completed consumed archive with byte-bound producer proof: ' + framework)
        unique = {(context, archive['sha256']) for context, archive, event in selected}
        require(len(unique) == 1, 'Ambiguous actual component input generation')
        context, archive, event = selected[0]
        component='runtime' if framework=='Microsoft.NETCore.App' else 'aspnetcore'
        marker_path='shared/'+framework+'/'+V[version]['runtime']+'/.version'
        with tarfile.open(checked(release,archive),'r:gz') as tar:
            markers=[member for member in tar if PurePosixPath(member.name).as_posix()==marker_path]
            require(len(markers)==1 and markers[0].isfile() and markers[0].size<=1024,'One ordinary component revision marker is required')
            marker=tar.extractfile(markers[0]).read().decode('utf-8').splitlines()
        require(marker==[mapped[component],V[version]['runtime']],'Consumed framework revision does not match delivered VMR component source')
        identity = next(row for row in comparison['comparisons'] if row['framework'] == framework)
        require(identity['identical'] is True and identity['inputArchive']['sha256'] == archive['sha256'], 'Framework identity does not bind the actual consumed archive')
        components.append(dict(framework=framework, origin='locally-built' if local else 'upstream-download', originVerified=True,
                               context=context, inputArchive=archive, actualAttempt=event, identicalEntries=identity['sdkEntryCount'],
                               sourceRevision=mapped[component],versionMarker=marker))
    result = dict(status='passed', sourceCommit=V[version]['commit'], sdkArchive=comparison['sdkArchive'], components=components,
                  replay=record(release, root / 'downloads-status.json'), observations=record(release, root / 'observations.jsonl'),
                  componentSourceManifest=record(release,root/'component-source-manifest.json'),
                  scope='Current-run consumed shared frameworks only; not every bootstrap or package input is source-built.')
    if write: dump(root / 'origin-evidence.json', result)
    return result


def construct(release, version, candidate):
    directory = release / 'reports/construction'
    observations = [json.loads(line) for line in (directory / 'observations.jsonl').read_text().splitlines() if line]
    inputs = []
    for basename in ['dotnet-runtime-' + V[version]['runtime'] + '-linux-arm64.tar.gz',
                     'aspnetcore-runtime-' + V[version]['runtime'] + '-linux-arm64.tar.gz']:
        rows = [row for row in observations if '/downloads/' in row['recordedPath'] and row['recordedPath'].endswith('/' + basename)]
        require(rows and len({row['archive']['sha256'] for row in rows}) == 1, 'One actually observed consumed input generation is required: ' + basename)
        inputs.append(checked(release, rows[0]['archive']))
    spec = importlib.util.spec_from_file_location('shared_identity', HERE / 'inspect-sdk-construction9.py')
    comparison = importlib.util.module_from_spec(spec); spec.loader.exec_module(comparison)
    manifest = load(release / 'reports/ci/candidate-build-manifest.json')
    sdk = candidate / manifest['sdkArchive']['path']
    pairs = [comparison.compare(sdk, archive, framework, V[version]['runtime']) for archive, framework in
             zip(inputs, ['Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'])]
    require(all(pair['identical'] for pair in pairs), 'Actual SDK shared frameworks differ from consumed inputs')
    dump(directory / 'comparison/shared-framework-identity.json', dict(status='passed', comparisons=pairs,
         sdkArchive=comparison.archive_record(sdk), originVerified=False,
         scope='Byte identity only; the separate completed-task origin report establishes input provenance.'))
    origin(release, version)


def verify_frozen(release, version, project=None):
    snapshot = load(release / 'reports/ci-inputs/snapshot.json')
    require(snapshot['sourceCommit'] == V[version]['commit'] and snapshot['sourceInitiallyPristine'] is True
            and snapshot['projectInitiallyPristine'] is True and snapshot['inputRepresentation'] == 'canonical-git-blobs-with-verified-checkout', 'Fresh pinned source and orchestration snapshot required')
    tree, names = G.project_tree(release, snapshot['projectFiles'])
    commit = checked(release, snapshot['projectCommitObject']).read_bytes()
    require(G.git_hash('commit', commit) == snapshot['projectCommit'] and commit.startswith(('tree ' + tree + '\n').encode()), 'Frozen source does not belong to the orchestration commit')
    frozen = release / 'reports/ci-inputs/project'
    require(names == {p.relative_to(frozen).as_posix() for p in G.tree_files(frozen)}, 'Frozen project membership differs')
    if project is not None:
        for row in snapshot['projectFiles']:
            name = row['path'][len('reports/ci-inputs/project/'):]
            require(G.checkout_details(project, name, row['gitBlobSha1'], checked(release, row).read_bytes()) ==
                    {key: row[key] for key in ('checkout', 'checkoutRepresentation')}, 'Live orchestration differs from the frozen input')
    original, selected = load(checked(release, snapshot['originalProfile'])), load(checked(release, snapshot['effectiveProfile']))
    require(selected == effective(original, version), 'Unreviewed effective-profile change')
    return snapshot


def consumer_roots(source, version):
    roots=[dict(name='vmr',path=str(source),kind='git',expectedCommit=V[version]['commit'])]
    ledger=[]
    generated=sorted(source.glob('src/*/artifacts/source-build/self/src'))
    if version=='8':require(generated,'Actual retained generated consumer source trees are required')
    for index,path in enumerate(generated):
        component=path.relative_to(source).parts[1];prefix='src/'+component+'/'
        tracked=subprocess.check_output(['git','-C',str(source),'ls-files','-z','--',prefix]).decode().split('\0')
        relative=[name[len(prefix):] for name in tracked if name]
        exclude=[]
        for candidate in ('artifacts','packages','.packages','.dotnet','.nuget','.tools','.npm','bin','obj','node_modules','.git','TestResults'):
            retained=any(name==candidate or name.startswith(candidate+'/') for name in relative)
            ledger.append(dict(consumer=component,prefix=candidate,excluded=not retained,originalTrackedSourcePresent=retained,
                               role='Generated build outputs, package/tool caches or source-control metadata; never exclude original tracked component source.'))
            if not retained:exclude.append(candidate)
        roots.append(dict(name='consumer-'+str(index)+'-'+component,path=str(path),kind='tree',exclude=exclude))
    return roots,ledger


def userland_script():
    return r'''set -euo pipefail
python3 - "$1" "$2" "$3" "$4" <<'PY'
import json,os,pathlib,platform,subprocess,sys
values={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key,value=line.split('=',1);values[key]=value.strip('"')
packages=[sys.argv[3],sys.argv[4],'libc6','libstdc++6','zlib1g','libgssapi-krb5-2']
text=subprocess.check_output(['dpkg-query','-W','-f=${binary:Package}'+chr(9)+'${Version}'+chr(10),*packages],text=True)
data={'imageId':sys.argv[1],'architecture':platform.machine(),'uid':os.getuid(),
      'osRelease':{'ID':values['ID'],'VERSION_ID':values['VERSION_ID']},
      'installedPackages':dict(row.split(chr(9),1) for row in text.splitlines()),
      'environmentOverrides':{key:os.environ.get(key) for key in ['LD_LIBRARY_PATH','DOTNET_ROOT','DOTNET_SYSTEM_GLOBALIZATION_INVARIANT','CLR_ICU_VERSION_OVERRIDE','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics']}}
with pathlib.Path('/delivery/reports/ci/'+sys.argv[2]+'-userland.json').open('x') as stream:json.dump(data,stream,indent=2)
PY
exec bash /delivery/reports/ci-inputs/project/scripts/verify-sdk.sh \
 --archive "/candidate/cbodotnet-sdk-$5-linux-arm64-build.$6.tar.gz" \
 --output-dir "/delivery/reports/verify-$2" --expected-version "$5" --expected-rid linux-arm64 --framework "net$7.0" --max-glibc 2.23
'''


def qualify(args):
    version, release = args.version, args.output_dir.absolute()
    snapshot = verify_frozen(release, version, args.project_root.absolute() if args.project_root is not None else None)
    require(snapshot['executionContext'] == 'github-actions', 'Only actual GitHub Actions evidence qualifies')
    require(all(isinstance(snapshot[key],str) and re.fullmatch('[1-9][0-9]*',snapshot[key]) for key in ('runId','runAttempt','buildRevision'))
            and re.fullmatch(r'20\d{6}\.[1-9]\d*',snapshot['buildId']), 'Valid actual CI build/run identity required')
    for supplied, key, environment in [(args.expected_project_commit, 'projectCommit', 'GITHUB_SHA'),
                                        (args.expected_run_id, 'runId', 'GITHUB_RUN_ID'), (args.expected_run_attempt, 'runAttempt', 'GITHUB_RUN_ATTEMPT')]:
        expected = supplied or os.environ.get(environment)
        require(expected is not None and str(snapshot[key]) == expected, 'Expected current commit/run/attempt is required: ' + key)
    manifest = load(release / 'build-manifest.json'); archive = manifest['sdkArchive']; checked(release, archive)
    require(manifest['sdkVersion'] == V[version]['sdk'] and manifest['source']['actualCommit'] == V[version]['commit']
            and manifest['source']['commitVerified'] is True and manifest['sourceOnly'] is V[version]['sourceOnly']
            and manifest['buildRevision'] == snapshot['buildRevision'] and manifest['targetRid'] == 'linux-arm64'
            and archive['copiedWithoutModification'] is True, 'Actual collected SDK identity/construction differs')
    require(archive['path']=='cbodotnet-sdk-'+V[version]['sdk']+'-linux-arm64-build.'+snapshot['buildRevision']+'.tar.gz', 'SDK filename must bind this version and run revision')
    require(manifest['profile']['contents'] == load(checked(release, snapshot['effectiveProfile']))
            and all(manifest['profile'][key] == value for key, value in fingerprint(checked(release, snapshot['effectiveProfile'])).items()), 'Collected effective profile differs')
    require(manifest['construction']['upstreamSharedRuntimeReused'] is (version == '9'), 'The version-specific shared component disclosure differs')
    for algorithm in ('sha256', 'sha512'):
        require((release / (algorithm.upper() + 'SUMS')).read_text() == archive[algorithm] + '  ' + archive['path'] + '\n', 'Actual SDK checksum sidecar differs')
    reports = release / 'reports'; rows = manifest['reports']['files']
    require(len(rows) == len({row['path'] for row in rows}) and {row['path'] for row in rows} == {p.relative_to(reports).as_posix() for p in G.tree_files(reports)}, 'Complete report inventory differs')
    for row in rows: checked(reports, row)
    frozen = release / 'reports/ci-inputs/project'; inputs = manifest['rebuildInputs']
    require(len(inputs) == len({row['path'] for row in inputs}) and {row['path'] for row in inputs} ==
            {p.relative_to(frozen).as_posix() for folder in ('scripts', 'containers', 'patches') for p in (frozen / folder).rglob('*') if p.is_file()}, 'Complete current rebuild inputs differ')
    for row in inputs: checked(frozen, row)
    identities = ('sourceCommit', 'projectCommit', 'buildId', 'buildRevision', 'runId', 'runAttempt')
    stages = {}; prior = None
    for name in ('prepare', 'build', 'scan', 'test', 'verify'):
        receipt = load(reports / ('ci/stages/' + name + '.json'))
        require(receipt['status'] == 'passed' and receipt['exitCode'] == 0 and receipt['stage'] == name and receipt['commands']
                and all(receipt[key] == snapshot[key] for key in identities) and receipt['nativeArchitecture'] == 'aarch64'
                and receipt['uid'] > 0 and receipt['imageId'].removeprefix('sha256:') == manifest['buildImage']['id'].removeprefix('sha256:'), 'Fresh successful actual stage required: ' + name)
        start, end = G.timestamp(receipt['startedAtUtc']), G.timestamp(receipt['finishedAtUtc'])
        require(start <= end and (prior is None or prior <= start), 'Stage chronology differs')
        prior = end; stages[name] = receipt
    G.image_check(reports / 'prepare/build-image.json', manifest['buildImage']['id'])
    provenance = load(reports / 'sysroot/sysroot-provenance.json')
    require(provenance['sourceCommit'] == V[version]['commit'] and provenance['packageSignatureVerification'] is True
            and provenance['emulation'] is False and len(provenance['keyrings']) == 3, 'Actual signed native sysroot producer provenance required')
    sysroot_log = reports / 'sysroot' / Path(provenance['logFile']).name
    require('Valid Release signature' in sysroot_log.read_text() and '--skipsigcheck' not in sysroot_log.read_text(), 'Actual authenticated debootstrap log required')
    sysroot_rows = (reports / 'sysroot/sysroot-files.sha256').read_text().splitlines()
    require(sysroot_rows and len(sysroot_rows) == len(set(sysroot_rows))
            and all(re.fullmatch(r'[a-f0-9]{64}  /inputs/arm64-xenial/.+', row) for row in sysroot_rows), 'Actual complete Xenial file inventory required')
    for action in ('prepare','build','test'):
        validation=load(reports/action/'sysroot-validation.json')
        require(validation['status']=='passed' and validation['files']==len(sysroot_rows) and validation['symlinks']>0
                and validation['sourceCommit']==V[version]['commit'] and validation['packageSignatureVerification'] is True
                and validation['provenance']==fingerprint(reports/'sysroot/sysroot-provenance.json')
                and validation['log']==fingerprint(sysroot_log), 'Independent actual sysroot validation differs')
    for name in ('build', 'test'):
        status = load(reports / name / (name + '-status.json'))
        require(status['exitCode'] == 0 and status['action'] == name and status['sourceCommit'] == V[version]['commit']
                and status['sourceOnly'] is V[version]['sourceOnly'], 'Actual upstream action failed')
        # Existing version wrappers record second-resolution starts. Permit only
        # that documented floor, while outer stage receipts retain microseconds.
        require(G.timestamp(stages[name]['startedAtUtc']) - dt.timedelta(seconds=1) <= G.timestamp(status['startedAt'])
                <= G.timestamp(status['finishedAt']) <= G.timestamp(stages[name]['finishedAtUtc']), 'Inner action times differ')
    if version == '9':
        helper = release / 'reports/ci-inputs/project/scripts/prepare-scenario-report-fence.py'
        # Old frozen runs predate this helper. New committed inputs must require it.
        if helper.exists() or 'scenarioReportFenceRequired' in snapshot:
            require(snapshot.get('scenarioReportFenceRequired') is True, 'The new scenario report completion fence is mandatory')
            scenario_fence(release, stages['test'], helper)
        scan = load(reports / 'scan/upstream/status.json')
        require(scan['status'] == 'passed' and scan['exitCode'] == scan['toolExitCode'] == scan['teeExitCode'] == 0
                and scan['sourceCommit'] == scan['cleanSourceCommit'] == V[version]['commit']
                and scan['cleanPristineBefore'] is True and scan['cleanPristineAfter'] is True and scan['allowlistsUnchanged'] is True,
                'The actual original clean-source BinaryToolKit validation must pass')
        result = scan['newBinariesReport']
        require(result['exists'] is False or result['isSymlink'] is False and result['bytes'] == 0, 'Unexpected source binaries reported')
    else:
        scan = load(reports / 'scan/pinned-source-inventory.json')
        require(scan['status'] == 'passed' and scan['sourceCommit'] == V[version]['commit'] and scan['pristineBefore'] is scan['pristineAfter'] is True and scan['files'], 'The actual pinned-source inventory is required')
        patches = load(reports / 'build/net8-patches-apply.json')
        require(patches['status'] == 'passed' and len(patches['patches']) == 2, 'The two guarded compatibility patches are required')
        bootstrap = load(reports / 'prepare/bootstrap/bootstrap-inputs.json')
        require(bootstrap['sourceCommit'] == V[version]['commit'] and bootstrap['bootstrapSdk'] == V[version]['bootstrap'], 'Actual successful ARM64 bootstrap proof required')
    upstream = reports / 'test/upstream-results'
    if version == '8':
        trx = list(upstream.glob('*.trx')); require(len(trx) == 1, 'One actual fresh smoke TRX required'); tests = test_results(version, trx[0])
    else:
        scenarios = list((upstream / 'scenario-tests').glob('*.xml')); require(len(scenarios) == 1, 'One actual scenario result required')
        tests = test_results(version, upstream / 'Microsoft.DotNet.UnifiedBuild.Tests.trx', scenarios[0])
    require(tests == load(reports / 'test/upstream-summary.json'), 'Raw upstream test results differ from summary')
    origins = load(reports / 'construction/origin-evidence.json')
    require(origins['status'] == 'passed' and origins['sourceCommit'] == V[version]['commit'] and origins['sdkArchive']['sha256'] == archive['sha256'], 'Actual current-run shared-framework provenance required')
    # Re-evaluate proof without writing any report during portable qualification.
    existing_origin = reports / 'construction/origin-evidence.json'
    parsed_origin = origin_value(release, version)
    require(parsed_origin == origins, 'The completed-task shared-framework origin proof differs')
    reader=load(reports/'construction/reader-inputs.json')
    require(reader['compilerSdk']==V[version]['bootstrap'] and reader['sourceCommit']==V[version]['commit']
            and len(reader['sourceFiles'])==2, 'Actual bounded reader compiler/source evidence required')
    for row in reader['sourceFiles']: checked(release,row)
    checked(release,reader['reader'])
    native = {}
    for name, (distribution, release_version, icu, ssl) in G.USERLANDS.items():
        verification = load(reports / ('verify-' + name + '/verification.json'))
        require(verification['verificationStatus'] == verification['smokeStatus'] == 'passed' and verification['sdkVersion'] == V[version]['sdk']
                and verification['reportedRid'] == 'linux-arm64' and verification['hostArchitecture'] == 'aarch64'
                and verification['framework'] == 'net' + version + '.0' and verification['functionalChecks'] == dict.fromkeys(G.FUNCTIONS, 'passed')
                and verification['archive']['sdkContentMatched'] is True and verification['archive']['sha256'] == archive['sha256']
                and verification['archive']['sizeBytes'] == archive['bytes'], 'All six actual native functions must bind the exact SDK')
        abi = verification['abi']; maxima = abi['maximumRequiredVersions']; numeric = lambda value: tuple(map(int, value.split('.')))
        require(abi['elfFileCount'] > 0 and abi['machines'] == {'AArch64': abi['elfFileCount']} and abi['glibcCeiling'] == '2.23'
                and abi['glibcCeilingPassed'] is True and not abi['symbolicGlibcRequirements'] and numeric(maxima['GLIBC']) <= (2,23)
                and numeric(maxima['GLIBCXX']) <= (3,4,21) and numeric(maxima['CXXABI']) <= (1,3,7), 'Actual native ABI policy failed')
        userland = load(reports / ('ci/' + name + '-userland.json'))
        require(userland['osRelease'] == {'ID': distribution, 'VERSION_ID': release_version} and userland['architecture'] == 'aarch64'
                and userland['uid'] > 0 and set(userland['environmentOverrides']) == G.ENVIRONMENT_OVERRIDES
                and all(value is None for value in userland['environmentOverrides'].values()), 'Actual unmodified native user-space policy differs')
        packages = {key.split(':',1)[0]: value for key,value in userland['installedPackages'].items()}
        require(all(packages.get(key) for key in (icu,ssl,'libc6','libstdc++6','zlib1g','libgssapi-krb5-2')), 'Actual native dependency versions missing')
        base = load(reports / ('ci/' + name + '-base-image.json')); require(len(base) == 1, 'One actual base inspection required')
        pinned = G.verification_base(base[0], distribution)
        derived = G.image_check(reports / ('ci/' + name + '-verification-image.json'), userland['imageId'])
        tag = 'localhost/cbodotnet-net' + version + '-verify-' + name + ':' + snapshot['runId'] + '-' + snapshot['runAttempt']
        require(tag in derived['RepoTags'] and any(('--build-arg','BASE_IMAGE='+pinned) in list(zip(command,command[1:]))
                and ('--tag',tag) in list(zip(command,command[1:])) for command in stages['verify']['commands'])
                and any(userland['imageId'] in command and '--network=none' in command for command in stages['verify']['commands']), 'Actual native base/build/execution chain differs')
        native[name] = dict(abi=abi, userland=userland)
    source = release / 'sources/source-manifest.json'
    require(load(source) == load(reports / 'ci/used-source.json'), 'Actual used-source manifest/control is required')
    roots=load(reports/'ci/source-roots.json')['roots']
    require(any(row['kind']=='git' and row['name']=='vmr' and row['expectedCommit']==V[version]['commit'] for row in roots)
            and (version!='8' or any(row['kind']=='tree' and row['name'].startswith('consumer-') for row in roots)), 'Actual VMR and generated consumer source roots must be delivered')
    collect = load(release / 'collect-receipt.json')
    require(collect['status'] == 'passed' and collect['exitCode'] == 0 and collect['stage']=='collect' and collect['commands']
            and collect['imageId'].removeprefix('sha256:')==manifest['buildImage']['id'].removeprefix('sha256:')
            and G.timestamp(collect['startedAtUtc'])>=prior and G.timestamp(collect['finishedAtUtc'])>=G.timestamp(collect['startedAtUtc'])
            and all(collect[key] == snapshot[key] for key in identities)
            and checked(release, collect['manifest']) == release / 'build-manifest.json', 'Actual final collection receipt differs')
    checked(release, collect['log'])
    outer={archive['path'],'build-manifest.json','SHA256SUMS','SHA512SUMS','collect-receipt.json','collect.log','ci-validation.json'}
    require(all(p.relative_to(release).parts[0] in ('reports','sources') or p.relative_to(release).as_posix() in outer
                for p in G.tree_files(release)), 'Unbound outer delivery files present')
    result = dict(schemaVersion=1, status='passed', sdkVersion=V[version]['sdk'], **{key:snapshot[key] for key in identities},
                  sdkArchive=archive, manifest=record(release, release/'build-manifest.json'), sourceManifest=record(release,source),
                  tests=tests, origin=record(release,existing_origin), native=native,
                  sourceScanScope=scan.get('scope','Original standalone BinaryToolKit validation'),
                  scope='Current native CI build, actual version-specific upstream tests, consumed framework origins and three user spaces. Used-source archive content validation is a separate required common gate. No Stage 2, zero-prebuilt or universal distribution claim.')
    envelope = release / 'ci-validation.json'
    if args.stage == 'verify-release': require(load(envelope) == result, 'Portable version evidence envelope differs')
    else: dump(envelope,result)
    print(json.dumps({'status':'passed','sdkVersion':V[version]['sdk'],'runId':snapshot['runId']})); return 0


def origin_value(release, version):
    # The producer proof function writes only when explicitly requested.
    return origin(release, version, write=False)


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('action',choices=['sysroot'])
    parser.add_argument('--version',choices=['8','9'],required=True); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    verify_sysroot(Path('/inputs/arm64-xenial'),Path('/reports'),args.version,args.output)
