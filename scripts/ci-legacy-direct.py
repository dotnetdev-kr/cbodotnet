#!/usr/bin/env python3
"""Fresh Linux CI orchestration for the pinned direct legacy source-build graphs."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.request

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

CONFIG = {
    'net5': ('5.0.214', 'd414ecb2d997a9b3f38aaaeddace30ca097e546d', '5.0.17', 'artifacts', 'build-ci-net5.sh'),
    'core31': ('3.1.426', 'ab8b115b5658237ee8916ae3586600b39fb2fd19', '3.1.32', 'artifacts', 'build-core31.sh'),
    'core30': ('3.0.103', '40de72d1087a1d05dfd39c87f888a0611ec6c60f', '3.0.3', 'bin', 'build-core30.sh'),
}
ANALYSIS_SDK = '9.0.121'
ANALYSIS_SHA512 = '2c8288568d9827371d8d0daf0578590a956d955bef783bf1403953f8a816851f03be7aa366b6649e7cda77a8e7359ac3fc46fac87f010d71b6e7415a9457add5'


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path, exists=False):
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts,
            'Absolute ordinary nonroot control paths are required: ' + str(path))
    require(not any(p.is_symlink() for p in [path] + list(path.parents)), 'Linked control path: ' + str(path))
    require(not exists or path.exists(), 'Missing control path: ' + str(path))
    return path


def fingerprint(path):
    ordinary(path, True)
    require(path.is_file(), 'An ordinary file is required: ' + str(path))
    before = path.stat(); hashes = {n: hashlib.new(n) for n in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in hashes.values():
                value.update(block)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Input changed while hashing')
    return dict(bytes=after.st_size, **{n: v.hexdigest() for n, v in hashes.items()})


def write(path, value):
    ordinary(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def git(root, *args):
    return subprocess.check_output(['git', '--no-optional-locks', '-C', str(root), *args]).decode().strip()


def download(url, target, expected, report):
    ordinary(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    require(not target.exists() and not target.with_suffix(target.suffix + '.part').exists(), 'Download must use a fresh destination')
    partial = target.with_suffix(target.suffix + '.part')
    with urllib.request.urlopen(url, timeout=180) as incoming, partial.open('xb') as output:
        shutil.copyfileobj(incoming, output, 1024 * 1024)
    actual = fingerprint(partial)
    require(all(actual.get(k) == v for k, v in expected.items()), 'Pinned download differs: ' + target.name)
    partial.rename(target)
    write(report, dict(status='passed', url=url, path=str(target), **actual))


def capture_component_logs(source, layout, reports):
    """Retain closed root component logs without altering any producer files."""
    require(layout in ('bin', 'artifacts'), 'Unknown legacy log layout')
    root = ordinary(source / layout / 'logs')
    destination = ordinary(reports / 'build/component-logs')
    receipt = ordinary(reports / 'build/component-log-capture.json')
    result = {'schemaVersion': 1, 'sourceLogRoot': str(root), 'files': [],
              'scope': 'Copies of completed root component .log/.binlog files only; no SDK/source/cache writes or product retry.'}
    require(not receipt.exists() and not receipt.is_symlink(), 'Component log receipt must be fresh')
    try:
        if not root.exists():
            result.update(status='not-produced', sourceLogRootExists=False,
                          reason='The product action ended before its root component log directory existed.')
            return result
        require(root.is_dir(), 'The root component log path is not a directory')
        entries = sorted(root.rglob('*'))
        require(all(not path.is_symlink() and (path.is_dir() or path.is_file()) for path in entries),
                'Component logs contain linked or special entries')
        require(not destination.exists() and not destination.is_symlink(), 'Component log copies must use a fresh destination')
        selected = [path for path in entries if path.is_file() and path.suffix.lower() in ('.log', '.binlog')]
        destination.mkdir(parents=True)
        for path in selected:
            relative = path.relative_to(root); before = fingerprint(path)
            target = destination / relative; target.parent.mkdir(parents=True, exist_ok=True)
            with path.open('rb') as incoming, target.open('xb') as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
            require(fingerprint(path) == before and fingerprint(target) == before,
                    'A component log changed during preservation: ' + str(path))
            result['files'].append(dict(path=target.relative_to(reports.parent).as_posix(), original=str(path), **before))
        result.update(status='captured' if selected else 'empty', sourceLogRootExists=True,
                      selectedFileCount=len(selected), sourceLogFilesUnchanged=True)
        return result
    except Exception as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        write(receipt, result)


class CI:
    def __init__(self, args):
        self.args = args
        self.family = args.family
        self.sdk, self.commit, self.runtime, self.layout, self.product = CONFIG[self.family]
        self.project = Path(__file__).resolve().parent.parent
        self.project_commit = git(self.project, 'rev-parse', 'HEAD')
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            require(os.environ.get('GITHUB_SHA') == self.project_commit, 'Workflow and checked-out orchestration commits differ')
        self.workspace, self.output = map(ordinary, (args.workspace, args.output_dir))
        require(self.workspace not in self.output.parents and self.output not in self.workspace.parents
                and self.workspace != self.output, 'Workspace and output must be separate')
        require(os.uname().sysname == 'Linux' and os.uname().machine == 'aarch64' and os.getuid() != 0,
                'A nonroot native Linux ARM64 host is required')
        require(re.fullmatch(r'20\d{6}\.[1-9]\d*', args.build_id), 'Invalid CI build identity')
        dt.datetime.strptime(args.build_id.split('.')[0], '%Y%m%d')
        require(re.fullmatch(r'[1-9]\d*', args.build_revision), 'Invalid build revision')
        require(not git(self.project, 'status', '--porcelain', '--untracked-files=all'), 'The orchestration checkout must be pristine')
        self.run_id = os.environ.get('GITHUB_RUN_ID', args.build_revision)
        self.attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
        require(all(re.fullmatch(r'[1-9]\d*', x) for x in (self.run_id, self.attempt)), 'Invalid run identity')
        self.source = self.workspace / 'source'
        self.inputs = self.workspace / 'inputs'
        self.home = self.workspace / 'home'
        self.candidate = self.workspace / 'candidate'
        self.reports = self.output / 'reports'
        self.snapshot = self.reports / 'ci-inputs/project'
        self.profile = self.reports / 'ci-inputs/profile.json'
        self.state = self.workspace / 'ci-legacy-state.json'
        self.engine = ['sudo', '-n', '--', 'podman', '--cgroup-manager=cgroupfs', '--events-backend=file']
        self.cpus = ','.join(map(str, sorted(os.sched_getaffinity(0))[:2]))
        require(len(self.cpus.split(',')) == 2, 'Two allowed CPUs are required')
        self.image = None

    def run(self, command, env=None, cwd=None):
        command = list(map(str, command))
        with self.commands.open('a') as stream:
            stream.write(json.dumps(command) + '\n')
        self.log.write('Running: ' + repr(command) + '\n'); self.log.flush()
        process = subprocess.Popen(command, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for block in iter(lambda: process.stdout.read(65536), b''):
            sys.stdout.buffer.write(block); sys.stdout.buffer.flush()
            self.log.buffer.write(block); self.log.flush()
        require(process.wait() == 0, 'Command failed: ' + command[0])

    def container(self, command, privileged=False, readonly=False, network='host', image=None, extra=()):
        options = self.engine + ['run', '--rm', '--interactive', '--network=' + network]
        if privileged:
            options += ['--privileged', '--user', '0:0', '--env', 'SUDO_UID=' + str(os.getuid()),
                        '--volume', str(self.source) + ':' + str(self.source) + ':ro',
                        '--volume', str(self.inputs) + ':' + str(self.inputs)]
        else:
            options += ['--user', '{}:{}'.format(os.getuid(), os.getgid()),
                        '--security-opt', 'seccomp=' + str(self.inputs / 'seccomp.json'),
                        '--volume', str(self.workspace) + ':' + str(self.workspace) + (':ro' if readonly else '')]
        options += ['--env', 'HOME=' + str(self.home), '--env', 'DOTNET_CLI_HOME=' + str(self.home),
                    '--env', 'XDG_RUNTIME_DIR=' + str(self.home / '.xdg'), '--env', 'DOTNET_PROCESSOR_COUNT=2',
                    '--env', 'DOTNET_GENERATE_ASPNET_CERTIFICATE=false', '--env', 'NUGET_XMLDOC_MODE=none',
                    '--env', 'PYTHONDONTWRITEBYTECODE=1',
                    '--env', 'LANG=C.UTF-8', '--env', 'LC_ALL=C.UTF-8',
                    '--volume', str(self.project) + ':' + str(self.project) + ':ro',
                    '--volume', str(self.output) + ':' + str(self.output),
                    '--volume', str(self.home) + ':' + str(self.home), '--workdir', str(self.source)]
        options += list(extra) + [image or self.image, 'taskset', '--cpu-list', self.cpus] + list(map(str, command))
        self.run(options)

    def image_inspect(self, reference, report):
        value = json.loads(subprocess.check_output(self.engine + ['image', 'inspect', reference]))
        require(len(value) == 1 and value[0]['Architecture'] == 'arm64' and value[0]['Os'] == 'linux', 'Native image required')
        write(report, value)
        return value[0]['Id']

    def identity(self):
        return dict(family=self.family, sdkVersion=self.sdk, sourceCommit=self.commit, projectCommit=self.project_commit,
                    workspace=str(self.workspace), output=str(self.output), buildId=self.args.build_id,
                    buildRevision=self.args.build_revision, runId=self.run_id, runAttempt=self.attempt)

    def freeze(self):
        require(not self.snapshot.exists(), 'A new source snapshot is required')
        self.snapshot.mkdir(parents=True)
        rows = []
        for entry in subprocess.check_output(['git', '-C', str(self.project), 'ls-files', '--stage', '-z']).split(b'\0'):
            if not entry:
                continue
            metadata, raw_name = entry.split(b'\t', 1)
            mode, blob, stage = metadata.decode().split()
            name = raw_name.decode()
            require(stage == '0' and mode in ('100644', '100755'), 'Only ordinary committed controls are accepted')
            data = subprocess.check_output(['git', '-C', str(self.project), 'cat-file', 'blob', blob])
            current = (self.project / name).read_bytes()
            require(current == data or (b'\r\n' not in data and current == data.replace(b'\n', b'\r\n')),
                    'Unexpected orchestration checkout transformation')
            target = self.snapshot / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            if mode == '100755':
                target.chmod(0o755)
            rows.append(dict(path=target.relative_to(self.output).as_posix(), gitMode=mode, gitBlob=blob, **fingerprint(target)))
        selected = json.loads((self.snapshot / ('profiles/dotnet-' + self.sdk + '-linux-arm64.json')).read_text())
        require(selected['source']['commit'] == self.commit and selected['build']['system'] == 'legacy-source-build-direct', 'Profile mismatch')
        # The committed profile retains historical local results. This run's
        # derived control must not present those measurements as new CI evidence.
        selected['status'] = 'Fresh CI inputs; actual stage and qualification receipts are authoritative.'
        for key in ('verification', 'testing'):
            selected.pop(key, None)
        for key in ('abiRequirementVerified', 'verifiedMaximumGlibcRequirement', 'observedMaximumRequiredVersions'):
            selected['target'].pop(key, None)
        for key in ('derivedImageId', 'observedDerivedImageId'):
            selected['container'].pop(key, None)
        selected['container']['status'] = 'Pinned base; this run records its own derived image.'
        selected['toolchain']['status'] = 'See this run\'s build command and compiler output.'
        selected['sysroot']['status'] = 'This run requires fresh authenticated preparation and full revalidation.'
        selected['build'].pop('portabilityStatus', None)
        selected['build']['sharedComponents'] = 'This run requires local producer, completed copy and final SDK payload proof.'
        selected['construction'] = {'upstreamSharedRuntimeReused': None, 'note': 'Qualification remains pending; retained binary bootstrap inputs are explicit.'}
        write(self.profile, selected)
        commit_object = self.reports / 'ci-inputs/project-commit.txt'
        commit_object.write_bytes(subprocess.check_output(['git', '-C', str(self.project), 'cat-file', 'commit', self.project_commit]))
        write(self.reports / 'ci-inputs/snapshot.json', dict(self.identity(), sourceInitiallyPristine=True,
              projectInitiallyPristine=True, projectFiles=rows, profile=dict(path=self.profile.relative_to(self.output).as_posix(), **fingerprint(self.profile)),
              projectCommitObject=dict(path=commit_object.relative_to(self.output).as_posix(), **fingerprint(commit_object)),
              executionContext='github-actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local-diagnostic',
              workflowRef=os.environ.get('GITHUB_WORKFLOW_REF', 'local'),
              scope='Canonical committed orchestration files; legacy buildId is CI identity, not an unproven upstream version override.'))

    def product_command(self, action, destination):
        destination = destination.with_name('product-' + action)
        destination.mkdir(parents=True, exist_ok=True)
        command = ['bash', self.snapshot / 'scripts' / self.product, '--source-dir', self.source,
                   '--inputs-dir', self.inputs, '--reports-dir', destination, '--profile', self.profile,
                   '--action', action, '--cpu-affinity', self.cpus, '--max-cpu-count', '2']
        command += ['--sysroot-reports-dir' if self.family == 'net5' else '--sysroot-reports', self.reports / 'sysroot']
        if self.family == 'net5':
            command += ['--root-pipeline-logger', 'true']
        if self.family == 'core30' and action == 'test':
            command += ['--sdk-archive', self.raw_sdk()]
        if self.family == 'core30' and action == 'build':
            command += ['--allow-cold-feed', 'true', '--skip-source-bundle-downloads', 'true']
        return command

    def raw_sdk(self):
        path = self.source / self.layout / 'arm64/Release' / ('dotnet-sdk-' + self.sdk + '-linux-arm64.tar.gz')
        ordinary(path, True)
        return path

    def sysroot_report_directory(self):
        """The privileged producer may create files, but the runner owns the directory."""
        path = ordinary(self.reports / 'sysroot')
        path.mkdir()
        require(path.stat().st_uid == os.getuid() and path.stat().st_gid == os.getgid(),
                'The current runner must own the new sysroot report directory')
        return path

    def prepare(self):
        self.run(['git', 'clone', '--no-checkout', 'https://github.com/dotnet/source-build.git', self.source])
        self.run(['git', '-C', self.source, 'checkout', '--detach', self.commit])
        self.freeze()
        recipe = self.snapshot / ('containers/arm64-' + self.family + '.Containerfile')
        profile = json.loads(self.profile.read_text())
        base = profile['container']['repository'] + '@' + profile['container']['digest']
        require(recipe.read_text().splitlines()[0] == 'FROM ' + base, 'Builder base differs from the pinned profile')
        tag = 'localhost/cbodotnet-ci-' + self.family + ':' + self.run_id + '-' + self.attempt
        self.run(self.engine + ['build', '--network=host', '--file', recipe, '--tag', tag, self.snapshot / 'containers'])
        self.image = self.image_inspect(tag, self.reports / 'prepare/build-image.json')
        self.run([sys.executable, self.snapshot / 'scripts/ci-legacy-seccomp.py', '--output-policy', self.inputs / 'seccomp.json',
                  '--report', self.reports / 'prepare/seccomp.json'])
        shutil.copyfile('/usr/share/containers/seccomp.json', self.reports / 'prepare/seccomp-base-policy.json')
        shutil.copyfile(self.inputs / 'seccomp.json', self.reports / 'prepare/seccomp-policy.json')
        self.run([sys.executable, self.snapshot / 'scripts/ci-legacy-analysis.py', 'prepare', '--workspace', self.workspace,
                  '--reports-dir', self.reports / 'prepare/analysis'])
        if self.family != 'core31':
            helper = runpy.run_path(str(self.snapshot / ('scripts/prepare-' + self.family.replace('net5', 'net5') + '-bootstrap.py')))
            download(profile['upstreamInputs']['sourceBuiltArtifactsUrl'], self.inputs / helper['PSB_NAME'],
                     {'bytes': helper['PSB_BYTES'], 'sha256': helper['PSB_SHA256']}, self.reports / 'prepare/psb-download.json')
        if self.family == 'net5':
            self.container(self.product_command('prepare', self.reports / 'prepare/product'))
        else:
            for action in ('acquire', 'prepare'):
                self.container(self.product_command(action, self.reports / 'prepare' / action))
        sysroot_reports = self.sysroot_report_directory()
        self.container(['bash', self.snapshot / ('scripts/prepare-sysroot' + ('5' if self.family == 'net5' else '-' + self.family) + '.sh'),
                        self.source, self.inputs, sysroot_reports, str(os.getuid()), str(os.getgid())], privileged=True)
        require(sysroot_reports.stat().st_uid == os.getuid() and sysroot_reports.stat().st_gid == os.getgid(),
                'The privileged producer changed sysroot report directory ownership')
        self.container(['python3', self.snapshot / 'scripts/ci-legacy-capture-sysroot.py', '--family', self.family,
                        '--inputs-dir', self.inputs, '--reports-dir', self.reports / 'sysroot'])
        write(self.state, dict(self.identity(), imageId=self.image,
                              snapshot=fingerprint(self.reports / 'ci-inputs/snapshot.json')))

    def build(self):
        observer = subprocess.Popen([sys.executable, str(self.snapshot / 'scripts/ci-legacy-origin.py'), 'observe',
                                     '--family', self.family, '--source-dir', str(self.source), '--output-dir', str(self.output),
                                     '--workspace', str(self.workspace)])
        failure = None; traceback = None; observer_failure = None
        try:
            self.container(self.product_command('build', self.reports / 'build/product'))
        except BaseException as error:
            failure, traceback = error, sys.exc_info()[2]
        finally:
            try:
                observer.terminate()
                require(observer.wait(timeout=30) == 0, 'The consumer observer failed')
            except Exception as error:
                observer_failure = error
            try:
                capture_component_logs(self.source, self.layout, self.reports)
            except Exception as error:
                # Diagnostic retention must never replace the producing command's
                # actual exception/exit status. Its separate receipt records failure.
                try:
                    self.log.write('Component log capture failed: ' + str(error) + '\n'); self.log.flush()
                except Exception:
                    pass
        if failure is not None:
            raise failure.with_traceback(traceback)
        if observer_failure is not None:
            raise observer_failure
        fingerprint(self.raw_sdk())

    def scan(self):
        # These generations use original prebuilt-usage reports, not BinaryToolTask.
        roots = [self.source / self.layout / 'prebuilt-report', self.source / self.layout / 'prebuilt-usage']
        found = [p for root in roots if root.is_dir() for p in root.rglob('*') if p.is_file() and not p.is_symlink()]
        require(any(p.name in ('prebuilt-usage.xml', 'annotated-usage.xml') for p in found),
                'The successful original graph did not produce its prebuilt-usage aggregate')
        records = []
        for index, path in enumerate(sorted(found)):
            destination = self.reports / 'scan/prebuilt' / str(index) / path.name
            destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
            require(fingerprint(path) == fingerprint(destination), 'A prebuilt report changed while preserving')
            records.append(dict(original=str(path), path=destination.relative_to(self.output).as_posix(), **fingerprint(destination)))
        write(self.reports / 'scan/prebuilt-report.json', dict(status='passed', reports=records,
              scope='Original upstream prebuilt reports preserved after a successful fresh root build. Baseline warnings/exclusions remain unchanged; not a zero-prebuilt or Stage2 assertion.'))

    def test(self):
        self.container(self.product_command('test', self.reports / 'test/product'))
        self.run([sys.executable, self.snapshot / 'scripts/ci-legacy-analysis.py', 'origins', '--workspace', self.workspace,
                  '--output-dir', self.output, '--family', self.family])
        self.source_roots()

    def source_roots(self):
        helper = runpy.run_path(str(self.snapshot / 'scripts/clone-legacy-sources.py'))
        args = types.SimpleNamespace(source_dir=str(self.source), profile=str(self.profile), repo=None, version=None, ignore_repos=[])
        _, _, _, _, _, dependencies, _, _ = helper['source_identity'](args)
        roots = [dict(name='source-build', path=str(self.source), kind='git', expectedCommit=self.commit)]
        seen = set()
        for dependency in dependencies:
            if dependency['ignoredByUpstreamClone']:
                continue
            name = helper['basename'](dependency['repository']); sha = dependency['commit']
            if (name, sha) in seen:
                continue
            seen.add((name, sha))
            path = self.source / self.layout / 'src' / (name + '.' + sha)
            store = self.source / '.git/modules/src' / (name + '.git')
            exclusions = ['artifacts', 'bin', 'obj', 'packages', '.nuget', '.dotnet', '.tools', '.paket',
                          'TestResults', 'testing-smoke', 'tools/bin', 'tools/obj', 'tools/.dotnet', 'Tools/bin', 'Tools/obj']
            root_record = dict(name=name + '-' + sha, path=str(path), kind='git-export', gitDir=str(store), expectedCommit=sha,
                               exclude=list(exclusions))
            roots.append(root_record)
            key = hashlib.sha256(str(path).encode()).hexdigest()
            receipt = json.loads((self.source / '.git/modules/src/.cbodotnet-legacy-exports' / (key + '.json')).read_text())
            def submodules(row, parent_record, parent_relative=''):
                for child in row.get('submodules', []):
                    relative = child['relativePath']; url = helper['canonical_url'](child['repository'])
                    owner, repository = url.rsplit('/', 2)[-2:]
                    bare = self.source / '.git/modules/src/.cbodotnet-submodules' / owner / (repository + '.git')
                    parent_record['exclude'].append(Path(relative).relative_to(parent_relative or '.').as_posix())
                    child_record = dict(name=name + '-' + sha[:12] + '-submodule-' + hashlib.sha256(relative.encode()).hexdigest()[:12],
                                        path=str(path / relative), kind='git-export', gitDir=str(bare), expectedCommit=child['commit'],
                                        exclude=list(exclusions))
                    roots.append(child_record)
                    submodules(child, child_record, relative)
            submodules(receipt['source'], root_record)
        # Include generated source/control files even when upstream ignores obj/bin.
        # Binary caches remain outside the source distribution.
        source_extensions = {'.cs', '.fs', '.vb', '.c', '.cpp', '.cc', '.h', '.hpp', '.S', '.s', '.inc', '.idl', '.props', '.targets', '.proj', '.csproj', '.fsproj', '.vbproj', '.cmake', '.def', '.rc', '.resx', '.rsp'}
        for row in roots:
            root = Path(row['path'])
            generated = []
            for directory in ('artifacts', 'bin', 'obj', 'testing-smoke'):
                start = root / directory
                if not start.is_dir() or start.is_symlink():
                    continue
                for current, directories, files in os.walk(start, followlinks=False):
                    current = Path(current)
                    directories[:] = [name for name in directories if name not in ('.git', 'packages', 'restored', '.nuget')
                                      and not (current / name).is_symlink()
                                      and not (root == self.source and current / name == self.source / self.layout / 'src')]
                    for name in files:
                        path = current / name
                        if path.is_file() and not path.is_symlink() and (path.suffix in source_extensions or path.name in ('CMakeCache.txt', 'CMakeLists.txt', 'NuGet.Config', 'NuGet.config')):
                            generated.append(path.relative_to(root).as_posix())
            if generated:
                row['include'] = sorted(generated)
        write(self.reports / 'ci/source-roots.json', {'schemaVersion': 1, 'roots': roots})

    def verify(self):
        self.run([sys.executable, self.snapshot / 'scripts/ci-legacy-verify.py', '--family', self.family,
                  '--workspace', self.workspace, '--output-dir', self.output, '--project-root', self.project])

    def collect(self):
        final_profile = self.reports / 'ci/effective-profile.json'
        require(final_profile.is_file(), 'Fresh origin/verification evidence must produce the final construction declaration')
        self.run([sys.executable, self.snapshot / 'scripts/collect-artifacts.py', '--source-dir', self.source,
                  '--profile', final_profile, '--output-dir', self.output, '--reports-dir', self.reports,
                  '--build-image-id', self.image, '--build-revision', self.args.build_revision])

    def execute(self):
        stage = self.args.stage
        if stage == 'prepare':
            for path in (self.workspace, self.output):
                require(not path.exists() or path.is_dir() and not list(path.iterdir()), 'Prepare requires fresh empty directories')
            for path in (self.inputs, self.home / '.xdg', self.reports / 'ci/stages', self.reports / 'ci/logs', self.reports / 'prepare'):
                path.mkdir(parents=True, exist_ok=True)
            os.chmod(self.home, 0o700); os.chmod(self.home / '.xdg', 0o700)
        else:
            state = json.loads(ordinary(self.state, True).read_text())
            require(all(state.get(k) == v for k, v in self.identity().items()), 'The CI run identity changed')
            require(state['snapshot'] == fingerprint(self.reports / 'ci-inputs/snapshot.json'), 'The frozen control changed')
            snapshot = json.loads((self.reports / 'ci-inputs/snapshot.json').read_text())
            for row in snapshot['projectFiles'] + [snapshot['profile']]:
                require(all(fingerprint(self.output / row['path'])[key] == row[key] for key in ('bytes', 'sha256', 'sha512')),
                        'A frozen control file changed')
            require(git(self.source, 'rev-parse', 'HEAD') == self.commit, 'Source HEAD changed')
            previous = {'build': 'prepare', 'scan': 'build', 'test': 'scan', 'verify': 'test', 'collect': 'verify'}[stage]
            require(json.loads((self.reports / 'ci/stages' / (previous + '.json')).read_text())['status'] == 'passed', 'Prior stage did not pass')
            self.image = state['imageId']
        receipt = self.output / 'collect-receipt.json' if stage == 'collect' else self.reports / 'ci/stages' / (stage + '.json')
        require(not receipt.exists(), 'Refusing an existing stage receipt')
        prefix = self.output if stage == 'collect' else self.reports / 'ci/logs'
        self.commands = prefix / (stage + '-commands.jsonl')
        log_path = prefix / (stage + '.log')
        require(not self.commands.exists() and not log_path.exists(), 'Stage logs must be new')
        self.commands.touch(); self.log = log_path.open('x')
        with self.commands.open('a') as stream:
            stream.write(json.dumps([sys.executable] + sys.argv) + '\n')
        for path in (self.reports / stage, self.reports / stage / 'product'):
            if stage != 'collect':
                path.mkdir(parents=True, exist_ok=True)
        started = now(); code = 1
        try:
            getattr(self, stage)(); code = 0
        finally:
            self.log.close()
            result = dict(self.identity(), schemaVersion=1, stage=stage, status='passed' if code == 0 else 'failed',
                          exitCode=code, startedAtUtc=started, finishedAtUtc=now(), imageId=self.image,
                          environment=dict(nativeArchitecture='aarch64', uid=os.getuid(), gid=os.getgid(), allowedCpuSelection=self.cpus),
                          commands=[json.loads(line) for line in self.commands.read_text().splitlines()])
            if stage == 'collect' and code == 0:
                result.update({key: dict(path=path.name, **fingerprint(path)) for key, path in
                               [('manifest', self.output / 'build-manifest.json'), ('log', log_path), ('commandsFile', self.commands)]})
            write(receipt, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=CONFIG, required=True)
    parser.add_argument('stage', choices=['prepare', 'build', 'scan', 'test', 'verify', 'collect', 'validate', 'verify-release', 'qualify'])
    for name in ('workspace', 'output-dir', 'project-root'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--build-id'); parser.add_argument('--build-revision')
    for name in ('expected-project-commit', 'expected-run-id', 'expected-run-attempt'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    if args.stage in ('validate', 'verify-release', 'qualify'):
        helper = runpy.run_path(str(Path(__file__).with_name('ci-legacy-evidence.py')))
        return helper['qualify'](args)
    require(all(getattr(args, name) is not None for name in ('workspace', 'output_dir', 'build_id', 'build_revision')),
            'Workspace, output, build ID and revision are required')
    CI(args).execute()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit('Legacy CI failed: ' + str(error))
