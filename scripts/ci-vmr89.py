#!/usr/bin/env python3
"""Run fresh pinned .NET 8/9 native Linux ARM64 CI stages."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import traceback
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
import ci_vmr89_support as S

PROJECT = Path(__file__).resolve().parents[1]


class Driver:
    def __init__(self, args):
        self.args, self.version, self.config = args, args.version, S.V[args.version]
        self.workspace, self.output = args.workspace.absolute(), args.output_dir.absolute()
        self.source, self.inputs = self.workspace / 'source', self.workspace / 'inputs'
        self.home, self.candidate = self.workspace / 'home', self.workspace / 'candidate'
        self.reports, self.frozen = self.output / 'reports', self.output / 'reports/ci-inputs/project'
        self.profile = self.output / 'reports/ci-inputs/effective-profile.json'
        self.state_path = self.workspace / 'ci-state.json'
        self.engine = ['sudo', '-n', '--', 'podman', '--cgroup-manager=cgroupfs', '--events-backend=file']
        self.identity = dict(sourceCommit=self.config['commit'], projectCommit=S.git(PROJECT, 'rev-parse', 'HEAD'),
                             buildId=args.build_id, buildRevision=args.build_revision,
                             runId=os.environ.get('GITHUB_RUN_ID', args.build_revision), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT', '1'))
        self.image, self.commands = None, []
        self.cpus = ','.join(map(str, sorted(os.sched_getaffinity(0))[:2]))

    def run(self, command, capture=False, stdin=None):
        command = list(map(str, command)); self.commands.append(command)
        print('Running: ' + repr(command), flush=True)
        with self.log.open('a', encoding='utf-8') as log:
            log.write('Running: ' + json.dumps(command) + '\n'); log.flush()
            process = subprocess.Popen(command, stdin=subprocess.PIPE if stdin is not None else None,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            if stdin is not None:
                process.stdin.write(stdin); process.stdin.close()
            lines = []
            for line in process.stdout:
                log.write(line); log.flush()
                if capture: lines.append(line)
                else: print(line, end='', flush=True)
            code = process.wait()
            if code: raise subprocess.CalledProcessError(code, command)
            return ''.join(lines) if capture else None

    def container(self, command, readonly=False, network='host', root=False, privileged=False):
        source = str(self.source) + ':/vmr' + (':ro' if readonly else '')
        args = self.engine + ['run', '--rm', '--interactive', '--network=' + network,
                             '--user', '0:0' if root else str(os.getuid()) + ':' + str(os.getgid()),
                             '--env', 'HOME=/root' if root else 'HOME=/home/build', '--env', 'DOTNET_CLI_HOME=/home/build',
                             '--env', 'XDG_RUNTIME_DIR=/home/build/.xdg', '--env', 'LANG=C.UTF-8', '--env', 'LC_ALL=C.UTF-8',
                             '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env', 'DOTNET_GENERATE_ASPNET_CERTIFICATE=false',
                             '--env', 'DOTNET_PROCESSOR_COUNT=2', '--volume', source,
                             '--env', 'PYTHONDONTWRITEBYTECODE=1',
                             '--volume', str(self.inputs) + ':/inputs',
                             '--volume', str(self.home) + ':/home/build', '--volume', str(self.output) + ':/delivery',
                             '--volume', str(self.reports / 'sysroot') + ':/reports' + ('' if root else ':ro'),
                             '--volume', str(self.candidate) + ':/candidate', '--workdir', '/vmr']
        if (self.workspace / 'clean-source').exists():
            args += ['--volume', str(self.workspace / 'clean-source') + ':/clean9:ro']
        if privileged: args += ['--privileged']
        args += [self.image, 'taskset', '--cpu-list', self.cpus, *command]
        return self.run(args)

    def inspect(self, reference, destination):
        text = self.run(self.engine + ['image', 'inspect', reference], capture=True)
        data = json.loads(text)
        S.require(len(data) == 1 and data[0]['Architecture'] == 'arm64' and data[0]['Os'] == 'linux'
                  and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', data[0]['Id']), 'An immutable native ARM64 image is required')
        destination.write_text(text); return data[0]

    def verify_prepared(self):
        self.container(['python3', '/delivery/reports/ci-inputs/project/scripts/ci_vmr89_support.py', 'sysroot',
                        '--version', self.version, '--output', '/delivery/reports/' + self.args.stage + '/sysroot-validation.json'], readonly=True, network='none')

    def prepare(self):
        self.run(['git', 'clone', '--depth', '1', '--branch', 'v' + self.config['sdk'], '--', 'https://github.com/dotnet/dotnet', self.source])
        S.freeze(PROJECT, self.source, self.output, self.version, self.identity, os.environ.get('GITHUB_WORKFLOW_REF', 'local'))
        self.run(self.engine + ['pull', 'mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4'])
        self.inspect('mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4', self.reports / 'prepare/base-image.json')
        tag = 'localhost/cbodotnet-net' + self.version + '-ci:' + self.identity['runId'] + '-' + self.identity['runAttempt']
        self.run(self.engine + ['build', '--network=host', '--file', self.frozen / ('containers/arm64-net' + self.version + '.Containerfile'), '--tag', tag, self.frozen])
        self.image = self.inspect(tag, self.reports / 'prepare/build-image.json')['Id']
        self.container(['bash', '/delivery/reports/ci-inputs/project/scripts/prepare-sysroot' + self.version + '.sh',
                        '/vmr', '/inputs', '/reports', str(os.getuid()), str(os.getgid())], readonly=True, root=True, privileged=True)
        if self.version == '8':
            tools = self.inputs / 'ci-tools'; (tools / 'scripts').mkdir(parents=True)
            original = (self.frozen / 'scripts/build-vmr8.sh').read_text()
            S.require(original.count('./build.sh --clean-while-building --online') == 1, 'The exact optional cleanup adaptation scope changed')
            adapted = original.replace('./build.sh --clean-while-building --online', './build.sh --online')
            (tools / 'scripts/build-vmr8.sh').write_text(adapted)
            for name in ('watch-bootstrap8.py', 'apply-net8-patches.py', 'restore-net8-symbol-inputs.py'):
                shutil.copyfile(self.frozen / 'scripts' / name, tools / 'scripts' / name)
            shutil.copytree(self.frozen / 'patches/net8', tools / 'patches/net8')
            preserved = self.reports / 'prepare/build-vmr8-preserve-source.sh'; shutil.copyfile(tools / 'scripts/build-vmr8.sh', preserved)
            S.dump(self.reports / 'prepare/source-preservation-adaptation.json', dict(original=S.record(self.output, self.frozen / 'scripts/build-vmr8.sh'),
                   adapted=S.record(self.output, preserved), removedOptionalArgument='--clean-while-building', productSourcesChanged=False,
                   reason='Retain actual generated source-build consumer trees for the used-source delivery.'))
            self.container(['bash', '/inputs/ci-tools/scripts/build-vmr8.sh', '--source-dir', '/vmr', '--sysroot', '/inputs/arm64-xenial',
                            '--reports-dir', '/delivery/reports/prepare/bootstrap', '--action', 'prepare'])
        self.verify_prepared()
        self.run([sys.executable, self.frozen / 'scripts/fetch-test-sdk.py', '--profile', self.profile,
                  '--inputs-dir', self.inputs, '--reports-dir', self.reports / 'prepare/test-inputs'])
        S.dump(self.state_path, dict(self.identity, imageId=self.image, workspace=str(self.workspace), output=str(self.output)))

    def product(self, action):
        self.verify_prepared()
        script = '/inputs/ci-tools/scripts/build-vmr8.sh' if self.version == '8' else '/delivery/reports/ci-inputs/project/scripts/build-vmr9.sh'
        args = ['bash', script, '--source-dir', '/vmr', '--sysroot', '/inputs/arm64-xenial', '--reports-dir', '/delivery/reports/' + action, '--action', action]
        if action == 'test': args += ['--official-sdk-archive', '/inputs/official-sdk/dotnet-sdk-' + self.config['sdk'] + '-linux-arm64.tar.gz']
        observer = S.Observer(self.source, self.output, self.version) if action == 'build' else None
        if observer: observer.start()
        try: self.container(args)
        finally:
            if observer: observer.finish()
        if action == 'build':
            source_manifest=self.source/'src/source-manifest.json'
            original_manifest=subprocess.check_output(['git','-C',str(self.source),'show','HEAD:src/source-manifest.json'])
            S.require(source_manifest.read_bytes()==original_manifest,'The original component source manifest changed')
            (self.reports/'construction/component-source-manifest.json').write_bytes(original_manifest)
            relative = ('src/installer/artifacts/buildLogs/source-build/self/src/artifacts/sourcebuild.binlog' if self.version == '8'
                        else 'src/sdk/artifacts/buildLogs/log/Release/source-inner-build.binlog')
            target = self.reports / 'construction/consumer.binlog'; shutil.copyfile(S.G.ordinary(self.source / relative), target)
            S.dump(self.reports / 'construction/binlog-input.json', dict(sourceRelativePath=relative, sourceCommit=self.config['commit'], archive=S.record(self.output, target)))
            return
        destination = self.reports / 'test/upstream-results'
        if self.version == '8':
            source = self.source / 'test/Microsoft.DotNet.SourceBuild.SmokeTests/TestResults'
            files = list(source.glob('*.trx')); S.require(len(files) == 1, 'Exactly one fresh .NET 8 smoke TRX is required')
            shutil.copytree(source, destination)
            summary = S.test_results('8', destination / files[0].name)
        else:
            source = self.source / 'artifacts/TestResults/Release'; shutil.copytree(source, destination)
            scenario = list((destination / 'scenario-tests').glob('*.xml')); S.require(len(scenario) == 1, 'One fresh scenario XML required')
            summary = S.test_results('9', destination / 'Microsoft.DotNet.UnifiedBuild.Tests.trx', scenario[0])
        S.dump(self.reports / 'test/upstream-summary.json', summary)
        prebuilt=self.reports/'prebuilt-usage';prebuilt.mkdir()
        generated_reports=self.source/'artifacts/prebuilt-report'
        preserved=[]
        if generated_reports.is_dir():
            shutil.copytree(generated_reports,prebuilt/'raw')
            preserved=[S.record(self.output,p) for p in S.G.tree_files(prebuilt/'raw')]
        S.dump(prebuilt/'coverage.json',dict(rawReports=preserved,sourceOnly=self.config['sourceOnly'],
               note='Preserved actual upstream reports when generated. Absence or counts do not establish zero binary inputs, a complete baseline or clean bootstrap.'))
        roots,ledger=S.consumer_roots(self.source,self.version)
        if self.version=='8':
            roots.append(dict(name='ci-executed-build-tools',path=str(self.inputs/'ci-tools'),kind='tree',exclude=[]))
        S.dump(self.reports/'ci/source-exclusions.json',dict(entries=ledger))
        S.dump(self.reports / 'ci/source-roots.json', dict(schemaVersion=1, roots=roots))

    def scan(self):
        clean = self.workspace / 'clean-source'
        self.run(['git', 'clone', '--local', '--no-hardlinks', '--branch', 'v' + self.config['sdk'], '--', self.source, clean])
        S.require(S.git(clean, 'rev-parse', 'HEAD') == self.config['commit'] and not S.git(clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'), 'A pristine separate scan target is required')
        if self.version == '9':
            self.container(['bash', '/delivery/reports/ci-inputs/project/scripts/scan-clean-source9.sh', '--source-dir', '/vmr',
                            '--clean-source-dir', '/clean9', '--reports-dir', '/delivery/reports/scan/upstream'])
        else:
            rows = []
            names = subprocess.check_output(['git', '-C', str(clean), 'ls-files', '-z']).decode().split('\0')
            for name in sorted(n for n in names if n):
                path = clean / name; value = dict(path=name, **S.fingerprint(path))
                with path.open('rb') as stream: signature = stream.read(4)
                value['binaryHeader'] = 'ELF' if signature == b'\x7fELF' else 'PE/DOS' if signature[:2] == b'MZ' else None
                rows.append(value)
            S.dump(self.reports / 'scan/pinned-source-inventory.json', dict(status='passed', sourceCommit=self.config['commit'],
                   pristineBefore=True, pristineAfter=not bool(S.git(clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching')),
                   files=rows, binaryHeaderFiles=sum(row['binaryHeader'] is not None for row in rows),
                   scope='Actual pristine pinned-source binary-header inventory. This tag has no standalone BinaryToolKit policy; no zero-binary or policy-scan pass is asserted.'))

    def collect_command(self, target):
        return ['python3', '/delivery/reports/ci-inputs/project/scripts/collect-artifacts.py', '--source-dir', '/vmr',
                '--output-dir', target, '--reports-dir', '/delivery/reports', '--profile', '/delivery/reports/ci-inputs/effective-profile.json',
                '--build-image-id', self.image, '--build-revision', self.identity['buildRevision']]

    def verify(self):
        S.require((self.output / 'sources/source-manifest.json').is_file(), 'Package actual used source after Test before Verify')
        self.container(self.collect_command('/candidate'), readonly=True, network='none')
        shutil.copyfile(self.candidate / 'build-manifest.json', self.reports / 'ci/candidate-build-manifest.json')
        analysis = self.inputs / 'analysis'; shutil.copytree(self.frozen / 'scripts/ci-vmr89-reader', analysis)
        (analysis / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
        sdk = '/vmr/.dotnet/sdk/' + self.config['bootstrap']
        self.container(['/vmr/.dotnet/dotnet', 'build', '/inputs/analysis/Reader.csproj', '--configuration', 'Release', '--configfile', '/inputs/analysis/NuGet.Config',
                        '/p:BootstrapMajor=' + self.version, '/p:BootstrapSdkDir=' + sdk], readonly=True, network='none')
        reader = '/inputs/analysis/bin/Release/net' + self.version + '.0/Reader.dll'
        self.container(['/vmr/.dotnet/dotnet', reader, '/delivery/reports/construction/consumer.binlog', sdk,
                        '/delivery/reports/construction/downloads', self.config['runtime']], readonly=True, network='none')
        reader_output = analysis / ('bin/Release/net' + self.version + '.0')
        shutil.copytree(reader_output, self.reports / 'construction/reader')
        S.dump(self.reports / 'construction/reader-inputs.json', dict(sourceFiles=[S.record(self.output, self.frozen / 'scripts/ci-vmr89-reader' / name)
               for name in ('Program.cs', 'Reader.csproj')], reader=S.record(self.output, self.reports / 'construction/reader/Reader.dll'),
               compilerSdk=self.config['bootstrap'], sourceCommit=self.config['commit']))
        S.construct(self.output, self.version, self.candidate)
        for name, (distribution, version, icu, ssl) in S.G.USERLANDS.items():
            reference = 'docker.io/library/' + distribution + ':' + version
            self.run(self.engine + ['pull', reference])
            base = self.inspect(reference, self.reports / ('ci/' + name + '-base-image.json'))
            pinned = S.G.verification_base(base, distribution)
            tag = 'localhost/cbodotnet-net' + self.version + '-verify-' + name + ':' + self.identity['runId'] + '-' + self.identity['runAttempt']
            self.run(self.engine + ['build', '--network=host', '--file', self.frozen / 'containers/verify-net10.Containerfile', '--build-arg', 'BASE_IMAGE=' + pinned,
                      '--build-arg', 'ICU_PACKAGE=' + icu, '--build-arg', 'SSL_PACKAGE=' + ssl, '--tag', tag, self.frozen])
            image = self.inspect(tag, self.reports / ('ci/' + name + '-verification-image.json'))['Id']
            script = S.userland_script()
            self.run(self.engine + ['run', '--rm', '--interactive', '--network=none', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                      '--env', 'LANG=C.UTF-8', '--env', 'LC_ALL=C.UTF-8', '--env', 'DOTNET_GENERATE_ASPNET_CERTIFICATE=false',
                      '--env', 'PYTHONDONTWRITEBYTECODE=1',
                      '--volume', str(self.candidate) + ':/candidate:ro', '--volume', str(self.output) + ':/delivery', '--workdir', '/tmp', image,
                      'taskset', '--cpu-list', self.cpus, 'bash', '-s', '--', image, name, icu, ssl, self.config['sdk'], self.identity['buildRevision'], self.version], stdin=script)

    def collect(self):
        self.container(self.collect_command('/delivery'), readonly=True, network='none')
        prior = S.load(self.candidate / 'build-manifest.json')['sdkArchive']; final = S.load(self.output / 'build-manifest.json')['sdkArchive']
        S.require(all(prior[k] == final[k] for k in ('bytes', 'sha256', 'sha512')), 'SDK changed after native verification')

    def execute(self):
        stage = self.args.stage
        S.require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() > 0, 'Use a nonroot native Linux ARM64 worker')
        S.require(len(os.sched_getaffinity(0)) >= 2, 'At least two allowed CPUs are required')
        for value in (self.workspace, self.output):
            S.require(value != Path('/') and '..' not in value.parts and not any(c in str(value) for c in ':\r\n\0')
                      and not any(p.is_symlink() for p in [value, *value.parents]), 'Ordinary absolute workspace/output paths required')
        S.require(self.workspace != self.output and self.workspace not in self.output.parents and self.output not in self.workspace.parents, 'Workspace and output must be separate')
        if stage == 'prepare':
            for path in (self.workspace, self.output):
                S.require(not path.exists() or path.is_dir() and not any(path.iterdir()), 'Fresh empty paths are required')
                path.mkdir(parents=True, exist_ok=True)
            S.require(shutil.disk_usage(self.workspace).free >= 90 * 1024**3, 'At least 90 GiB free is required for the fresh full-source CI attempt')
            for path in (self.inputs, self.home / '.xdg', self.candidate, self.reports / 'sysroot', self.reports / 'ci/stages', self.reports / 'prepare'):
                path.mkdir(parents=True, exist_ok=True)
            os.chmod(self.home, 0o700); os.chmod(self.home / '.xdg', 0o700)
        else:
            state = S.load(self.state_path)
            S.require(all(state.get(k) == v for k, v in self.identity.items()) and state['workspace'] == str(self.workspace) and state['output'] == str(self.output), 'Prepared run identity differs')
            self.image = state['imageId']
            prior = dict(build='prepare', scan='build', test='scan', verify='test', collect='verify')[stage]
            receipt = S.load(self.reports / ('ci/stages/' + prior + '.json'))
            S.require(receipt['status'] == 'passed' and receipt['exitCode'] == 0, 'The prior stage must pass')
            S.verify_frozen(self.output, self.version, PROJECT)
            S.require(S.git(self.source, 'rev-parse', 'HEAD') == self.config['commit'], 'Source revision changed')
        directory = self.reports / stage; directory.mkdir(parents=True, exist_ok=True)
        self.log = self.output / 'collect.log' if stage == 'collect' else directory / 'ci-driver.log'
        self.log.open('x').close(); started = S.now(); code = 1; error = None
        try:
            {'prepare': self.prepare, 'build': lambda: self.product('build'), 'scan': self.scan, 'test': lambda: self.product('test'), 'verify': self.verify, 'collect': self.collect}[stage]()
            code = 0
        except Exception as failure:
            code = failure.returncode if isinstance(failure, subprocess.CalledProcessError) else 1
            error = str(failure); traceback.print_exc()
        finally:
            receipt = dict(self.identity, schemaVersion=1, stage=stage, status='passed' if code == 0 else 'failed', exitCode=code,
                           startedAtUtc=started, finishedAtUtc=S.now(), imageId=self.image, commands=self.commands, error=error,
                           nativeArchitecture=platform.machine(), uid=os.getuid(), cpus=self.cpus, sdkVersion=self.config['sdk'])
            if stage == 'collect' and code == 0:
                receipt.update(manifest=S.record(self.output, self.output / 'build-manifest.json'), log=S.record(self.output, self.log))
            S.dump(self.output / 'collect-receipt.json' if stage == 'collect' else self.reports / ('ci/stages/' + stage + '.json'), receipt)
        return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare', 'build', 'scan', 'test', 'verify', 'collect', 'validate', 'verify-release'])
    parser.add_argument('--version', choices=['8', '9'], required=True)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--project-root', type=Path)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--build-id'); parser.add_argument('--build-revision')
    for name in ('project-commit', 'run-id', 'run-attempt'): parser.add_argument('--expected-' + name)
    args = parser.parse_args()
    if args.stage in ('validate', 'verify-release'):
        return S.qualify(args)
    S.require(args.workspace is not None and args.workspace.is_absolute() and args.output_dir.is_absolute()
              and re.fullmatch(r'20\d{6}\.[1-9]\d*', args.build_id or '') and re.fullmatch('[1-9][0-9]*', args.build_revision or ''), 'Explicit absolute paths and valid build identity required')
    return Driver(args).execute()


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error: raise SystemExit('error: ' + str(error))
