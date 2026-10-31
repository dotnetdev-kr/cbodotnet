#!/usr/bin/env python3
"""Fresh native Linux ARM64 orchestration for the pinned .NET 6/7 profiles."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

HELPERS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('net67_evidence', HELPERS / 'ci-net67-evidence.py')
E = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(E)


def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def ordinary_directory(path):
    E.require(path.is_absolute() and path != Path('/') and ':' not in str(path)
              and not any(p.is_symlink() for p in [path, *path.parents]), 'Ordinary absolute paths are required')
    return path.resolve()


class Run:
    def __init__(self, args):
        self.args = args; self.major = args.major; self.selected = E.VERSIONS[self.major]
        self.sdk = self.selected['sdk']; self.project = HELPERS.parent
        self.workspace = ordinary_directory(args.workspace); self.output = ordinary_directory(args.output_dir)
        E.require(self.workspace != self.output and self.workspace not in self.output.parents
                  and self.output not in self.workspace.parents, 'Workspace and output must be separate')
        E.require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() != 0,
                  'Run as the checkout owner on native ARM64 Linux')
        E.require(re.fullmatch(r'20\d{6}\.[1-9]\d*', args.build_id) and re.fullmatch(r'[1-9]\d*', args.build_revision), 'Invalid CI build identity')
        dt.datetime.strptime(args.build_id.split('.')[0], '%Y%m%d')
        for name in ['git', 'podman', 'sudo', 'taskset']: E.require(shutil.which(name), 'Missing host tool: '+name)
        self.project_commit = subprocess.check_output(['git','-C',str(self.project),'rev-parse','HEAD'], text=True).strip()
        E.require(not subprocess.check_output(['git','-C',str(self.project),'status','--porcelain','--untracked-files=all']), 'The orchestration checkout must be pristine')
        self.run_id = os.environ.get('GITHUB_RUN_ID', args.build_revision)
        self.attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
        E.require(all(re.fullmatch(r'[1-9]\d*', x) for x in [self.run_id, self.attempt]), 'Invalid run identity')
        self.identity = dict(projectCommit=self.project_commit, runId=self.run_id, runAttempt=self.attempt,
                             buildId=args.build_id, buildRevision=args.build_revision)
        cpus = sorted(os.sched_getaffinity(0)); E.require(len(cpus) >= 2, 'Two allowed CPUs are required')
        self.cpus = ','.join(map(str, cpus[:2])); self.uid = os.getuid(); self.gid = os.getgid()
        self.engine = ['sudo','-n','--','podman','--cgroup-manager=cgroupfs','--events-backend=file']
        self.work = self.workspace / 'work'; self.installer = self.work / ('installer-v'+self.sdk)
        self.source = self.work / ('source-v'+self.sdk); self.inputs = self.workspace / 'inputs'
        self.home = self.workspace / 'home'; self.candidate = self.workspace / 'candidate'
        self.reports = self.output / 'reports'; self.frozen = self.reports / 'ci-inputs/project'
        self.profile = self.reports / 'ci-inputs/effective-profile.json'; self.state = self.workspace / 'ci-state.json'
        self.stage = args.stage; self.commands = []; self.image = None; self.paths = {}; self.started = now()
        if self.stage == 'prepare':
            for path in [self.workspace, self.output]:
                E.require(not path.exists() or path.is_dir() and not any(path.iterdir()), 'Prepare requires fresh empty directories')
            for path in [self.work, self.inputs, self.home / '.xdg', self.candidate, self.reports / 'ci/stages']:
                path.mkdir(parents=True, exist_ok=True)
            self.home.chmod(0o700); (self.home / '.xdg').chmod(0o700)
        else:
            state = E.load(self.state)
            E.require(all(str(state[k]) == str(v) for k,v in self.identity.items()), 'The CI run identity changed')
            E.require(state['workspace'] == str(self.workspace) and state['output'] == str(self.output), 'CI paths changed')
            snapshot = E.load(self.reports / 'ci-inputs/snapshot.json')
            E.require(E.fingerprint(self.reports / 'ci-inputs/snapshot.json')['sha256'] == state['snapshotSha256'], 'Input snapshot changed')
            E.snapshot_tree(self.output, snapshot['projectFiles'])
            E.checked(self.output, snapshot['effectiveProfile']); E.checked(self.output, snapshot['originalProfile'])
            previous = {'build':'prepare','scan':'build','test':'scan','verify':'test','collect':'verify'}[self.stage]
            receipt = E.load(self.reports / 'ci/stages' / (previous+'.json'))
            E.require(receipt['status'] == 'passed' and receipt['exitCode'] == 0, 'Previous stage did not pass: '+previous)
            self.image = state['imageId']
            E.require(subprocess.check_output(['git','-C',str(self.installer),'rev-parse','HEAD'], text=True).strip() == self.selected['commit'], 'Installer pin changed')
        self.receipt = self.output / 'collect-receipt.json' if self.stage == 'collect' else self.reports / 'ci/stages' / (self.stage+'.json')
        E.require(not self.receipt.exists() and not self.receipt.is_symlink(), 'A stage receipt already exists')
        self.log_path = self.output / 'collect.log' if self.stage == 'collect' else self.reports / 'ci/logs' / (self.stage+'.log')
        self.command_path = self.output / 'collect-commands.jsonl' if self.stage == 'collect' else self.reports / 'ci/logs' / (self.stage+'-commands.jsonl')
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = self.log_path.open('x', encoding='utf-8'); self.journal = self.command_path.open('x', encoding='utf-8')

    def command(self, args, input=None, capture=False):
        args = list(map(str, args)); self.commands.append(args)
        self.journal.write(json.dumps(args)+'\n'); self.journal.flush()
        print('Running: '+json.dumps(args), flush=True)
        self.log.write('Running: '+json.dumps(args)+'\n'); self.log.flush()
        if capture:
            result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.log.write(result.stderr); self.log.flush()
            if result.returncode: raise subprocess.CalledProcessError(result.returncode, args, stderr=result.stderr)
            return result.stdout
        process = subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        if input is not None:
            process.stdin.write(input); process.stdin.close()
        for line in process.stdout:
            print(line, end='', flush=True); self.log.write(line); self.log.flush()
        code = process.wait()
        if code: raise subprocess.CalledProcessError(code, args)

    def inspect(self, reference, path):
        text = self.command(self.engine+['image','inspect',reference], capture=True)
        rows = json.loads(text); E.require(len(rows) == 1 and rows[0]['Architecture'] == 'arm64' and rows[0]['Os'] == 'linux', 'An exact native image is required')
        E.require(re.fullmatch(r'(sha256:)?[a-f0-9]{64}', rows[0]['Id']), 'An immutable image identity is required')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x') as out: out.write(text)
        return rows[0]

    def container(self, command, readonly=False, privileged=False, network='host', input=None, capture=False):
        suffix = ':ro' if readonly or privileged else ''
        args = self.engine+['run','--rm','--interactive','--network='+network]
        if privileged: args += ['--privileged','--user','0:0']
        else: args += ['--security-opt','seccomp='+str(self.inputs/'seccomp.json'),'--user',str(self.uid)+':'+str(self.gid)]
        args += ['--env','HOME=/home/build','--env','DOTNET_CLI_HOME=/home/build','--env','XDG_RUNTIME_DIR=/home/build/.xdg',
                 '--env','LANG=C.UTF-8','--env','LC_ALL=C.UTF-8','--env','DOTNET_PROCESSOR_COUNT=2',
                 '--env','DOTNET_CLI_TELEMETRY_OPTOUT=1','--env','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
                 '--env','DOTNET_GENERATE_ASPNET_CERTIFICATE=false','--env','NUGET_XMLDOC_MODE=none',
                 '--env','PYTHONDONTWRITEBYTECODE=1',
                 '--volume',str(self.project)+':/project:ro','--volume',str(self.work)+':/work'+suffix,
                 '--volume',str(self.installer)+':/installer'+suffix,'--volume',str(self.inputs)+':/inputs'+(':ro' if readonly else ''),
                 '--volume',str(self.home)+':/home/build','--volume',str(self.output)+':/delivery',
                 '--volume',str(self.candidate)+':/candidate','--workdir','/work/source-v'+self.sdk if self.source.exists() else '/installer',
                 self.image,'taskset','--cpu-list',self.cpus]+command
        return self.command(args, input=input, capture=capture)

    def script(self, name): return '/delivery/reports/ci-inputs/project/scripts/'+name

    def action(self, name):
        directory = self.reports / name; directory.mkdir(exist_ok=False)
        args = ['bash',self.script('build-source'+self.major+'.sh'),'--installer-dir','/installer',
                '--source-dir','/work/source-v'+self.sdk,'--reports-dir','/delivery/reports/'+name,
                '--generation-reports-dir','/delivery/reports/generation','--action',name,'--max-cpu-count','2']
        if name == 'test': args += ['--official-sdk-archive','/inputs/official-sdk/dotnet-sdk-'+self.sdk+'-linux-arm64.tar.gz']
        self.container(args)
        self.paths[name+'Status'] = 'reports/'+name+'/'+name+'-status.json'

    def verify_inputs(self):
        self.container(['python3',self.script('source'+self.major+'-provenance.py'),'verify','--installer-dir','/installer',
                        '--source-dir','/work/source-v'+self.sdk,'--reports-dir','/delivery/reports/generation'], readonly=True, network='none')
        text = self.container(['python3',self.script('verify-sysroot'+self.major+'.py'),'--sysroot','/inputs/arm64-xenial',
                               '--reports-dir','/delivery/reports/sysroot'], readonly=True, network='none',capture=True)
        current = json.loads(text); E.require(current['status'] == 'passed' and current['files'] > 0 and current['symlinks'] > 0, 'Complete sysroot verification failed')
        path = self.reports/'sysroot/current-validation.json'
        if path.exists(): E.require(E.load(path) == current, 'Complete sysroot inventory changed')
        else: E.write(path,current)

    def baseline(self):
        destination = self.inputs / 'official-sdk' / ('dotnet-sdk-'+self.sdk+'-linux-arm64.tar.gz')
        destination.parent.mkdir()
        url = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/'+self.sdk+'/'+destination.name
        with urllib.request.urlopen(url, timeout=120) as response, destination.open('xb') as out:
            shutil.copyfileobj(response, out, 1024*1024)
        actual = E.fingerprint(destination)
        E.require(actual['bytes'] == self.selected['baselineSize'] and actual['sha512'] == self.selected['baselineSha512'], 'Official comparison input differs from its fixed pin')
        E.write(self.reports / 'test-inputs/official-sdk-baseline.json', dict(version=self.sdk,rid='linux-arm64',url=url,
                purpose='Exact official SDK comparison baseline only; never a community product input',**actual))

    def prepare(self):
        self.command(['git','clone','--depth','1','--branch','v'+self.sdk,'--','https://github.com/dotnet/installer',self.installer])
        E.require(self.command(['git','-C',self.installer,'rev-parse','HEAD'], capture=True).strip() == self.selected['commit'], 'Fetched installer tag differs from selected commit')
        snapshot = E.freeze(self.project, self.output, self.major, self.identity)
        (self.reports/'prepare').mkdir()
        self.command([sys.executable,self.frozen/'scripts'/('prepare-net'+self.major+'-seccomp.py'),
                      '--output-policy',self.inputs/'seccomp.json','--report',self.reports/'prepare/seccomp.json'])
        shutil.copyfile(self.inputs/'seccomp.json',self.reports/'prepare/seccomp-policy.json')
        shutil.copyfile('/usr/share/containers/seccomp.json',self.reports/'prepare/seccomp-base-policy.json')
        profile = E.load(self.profile); base = profile['container']['repository']+'@'+profile['container']['digest']
        recipe = self.frozen / 'containers' / ('arm64-net'+self.major+'.Containerfile')
        E.require(next(line for line in recipe.read_text().splitlines() if line.startswith('FROM ')) == 'FROM '+base, 'Product image base differs from profile')
        self.command(self.engine+['pull',base]); self.inspect(base, self.reports / 'prepare/base-image.json')
        tag = 'localhost/cbodotnet-net'+self.major+'-ci:'+self.run_id+'-'+self.attempt
        self.command(self.engine+['build','--network=host','--file',recipe,'--tag',tag,self.frozen])
        self.image = self.inspect(tag, self.reports / 'prepare/build-image.json')['Id']
        self.action('generate')
        (self.reports / 'sysroot').mkdir()
        self.container(['bash',self.script('prepare-sysroot'+self.major+'.sh'),'/work/source-v'+self.sdk,
                        '/inputs','/delivery/reports/sysroot',str(self.uid),str(self.gid)], privileged=True)
        self.container(['python3','-'],readonly=True,network='none',input='''import hashlib,json,pathlib,shutil,subprocess
root=pathlib.Path('/delivery/reports/sysroot'); destination=root/'producer-inputs'; destination.mkdir()
paths=[pathlib.Path('/usr/share/keyrings')/name for name in ['ubuntu-archive-keyring.gpg','cbodotnet-current-ubuntu-archive.gpg','ubuntu-archive-removed-keys.gpg']]
records=[]
for path in paths:
    data=path.read_bytes(); target=destination/path.name; target.write_bytes(data)
    records.append({'path':'reports/sysroot/producer-inputs/'+path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'sha512':hashlib.sha512(data).hexdigest()})
text=subprocess.check_output(['dpkg-query','-W','-f=${binary:Package}\\t${Version}\\n','ubuntu-keyring','debootstrap','qemu-user-static'],text=True)
with (root/'producer-inputs.json').open('x') as out: json.dump({'keyrings':records,'installedPackages':text},out,indent=2)
''')
        self.verify_inputs()
        # The original helper calls this action "prepare"; its per-action reports
        # remain separate from the outer stage logs and authenticated sysroot.
        directory = self.reports / 'bootstrap'; directory.mkdir()
        self.container(['bash',self.script('build-source'+self.major+'.sh'),'--installer-dir','/installer',
                        '--source-dir','/work/source-v'+self.sdk,'--reports-dir','/delivery/reports/bootstrap',
                        '--generation-reports-dir','/delivery/reports/generation','--action','prepare','--max-cpu-count','2'])
        bootstrap=E.load(directory/'bootstrap-inputs.json')
        E.require(any(row['bytes'] == self.selected['psbSize'] and row['sha256'] == self.selected['psbSha256']
                      for row in bootstrap['originalInputs']), 'The fresh original PSB differs from its fixed upstream input pin')
        self.baseline()
        E.write(self.state, dict(**self.identity, workspace=str(self.workspace),output=str(self.output),imageId=self.image,
                               snapshotSha256=E.fingerprint(self.reports / 'ci-inputs/snapshot.json')['sha256']))
        self.paths.update(generation='reports/generation/generation.json', sysroot='reports/sysroot/sysroot-provenance.json',
                          bootstrap='reports/bootstrap/bootstrap-inputs.json')

    def observe(self, stopping, errors):
        names = ['dotnet-runtime-'+self.selected['runtime']+'-linux-arm64.tar.gz',
                 'aspnetcore-runtime-internal-'+self.selected['runtime']+'-linux-arm64.tar.gz']
        feed = self.source / 'artifacts/obj/arm64/Release/blob-feed/assets'; known = {}; seen = set()
        path = self.reports / 'build/installer-observations.jsonl'
        try:
            with path.open('x') as out:
                while not stopping.is_set():
                    for name in names:
                        if name not in known:
                            try: known[name] = E.fingerprint(feed / name)
                            except (OSError,ValueError): continue
                        root = self.source / 'src/installer/artifacts'
                        try: destinations=list(root.rglob(name))
                        except FileNotFoundError: continue
                        for destination in destinations:
                            if str(destination) in seen: continue
                            try: actual = E.fingerprint(destination)
                            except (OSError,ValueError): continue
                            if actual != known[name]: continue
                            row = dict(observedAtUtc=now(), destination=destination.relative_to(self.source).as_posix(),
                                       feed=(feed/name).relative_to(self.source).as_posix(), **actual)
                            out.write(json.dumps(row)+'\n'); out.flush(); seen.add(str(destination))
                    stopping.wait(0.5)
        except Exception as error: errors.append(str(error))

    def build(self):
        self.verify_inputs(); (self.reports / 'build').mkdir()
        stopping = threading.Event(); errors = []
        observer = threading.Thread(target=self.observe, args=(stopping,errors)); observer.start()
        try:
            # action() requires a fresh report directory; it was created above
            # exclusively so the observer can open its own evidence file.
            args = ['bash',self.script('build-source'+self.major+'.sh'),'--installer-dir','/installer',
                    '--source-dir','/work/source-v'+self.sdk,'--reports-dir','/delivery/reports/build',
                    '--generation-reports-dir','/delivery/reports/generation','--action','build','--max-cpu-count','2']
            self.container(args)
        finally:
            stopping.set(); observer.join()
        E.require(not errors, 'Installer observer failed: '+str(errors))
        logs = self.reports / 'build/component-logs'; logs.mkdir()
        for name in ['runtime','aspnetcore','installer']:
            source = self.source / 'artifacts/logs' / (name+'.log')
            E.ordinary(source); shutil.copyfile(source, logs / source.name)
        candidate = self.source / 'src/installer/artifacts/buildLogs/source-build/self/src/artifacts/sourcebuild.binlog'
        E.ordinary(candidate)
        tools = self.reports / 'origin-tools'; tools.mkdir()
        shutil.copyfile(candidate, tools / 'installer.binlog')
        self.reader(tools)
        self.paths['buildStatus'] = 'reports/build/build-status.json'

    def reader(self, tools):
        source = tools / 'reader'; source.mkdir()
        shutil.copyfile(self.frozen / 'scripts/ci-net67-reader.cs', source / 'Program.cs')
        project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net'+self.major+'.0</TargetFramework><UseAppHost>false</UseAppHost></PropertyGroup><ItemGroup>'
        for name in ['Microsoft.Build','Microsoft.Build.Framework']:
            project += '<Reference Include="'+name+'"><HintPath>$(BootstrapSdkDir)/'+name+'.dll</HintPath><Private>true</Private></Reference>'
        project += '</ItemGroup></Project>'
        (source / 'Reader.csproj').write_text(project)
        (source / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
        for name in ['Directory.Build.props','Directory.Build.targets']: (source / name).write_text('<Project/>')
        sdk_dir = '/work/source-v'+self.sdk+'/.dotnet/sdk/'+self.selected['bootstrap']
        dotnet = '/work/source-v'+self.sdk+'/.dotnet/dotnet'
        self.container([dotnet,'build','/delivery/reports/origin-tools/reader/Reader.csproj','--configuration','Release',
                        '--configfile','/delivery/reports/origin-tools/reader/NuGet.Config','-p:BootstrapSdkDir='+sdk_dir,'-nologo'], network='none')
        self.container([dotnet,'/delivery/reports/origin-tools/reader/bin/Release/net'+self.major+'.0/Reader.dll',
                        '/delivery/reports/origin-tools/installer.binlog',sdk_dir,'/delivery/reports/origin-tools/replay.json'], readonly=True,network='none')
        bootstrap = self.source / '.dotnet/sdk' / self.selected['bootstrap']
        E.write(tools / 'compiler-inputs.json', {name:E.fingerprint(bootstrap/name) for name in
                ['MSBuild.dll','Microsoft.Build.dll','Microsoft.Build.Framework.dll','Roslyn/bincore/csc.dll']})

    def scan(self):
        self.verify_inputs()
        E.write(self.reports / 'scan/applicability.json', dict(status='not-applicable',
                reason='The pinned generated .NET 6/7 graph has no VMR BinaryToolKit source scan. Original full upstream smoke tests and actual prebuilt reports are mandatory; no empty scanner report is manufactured.'))
        self.paths['applicability'] = 'reports/scan/applicability.json'

    def origin(self):
        sdk_archive = self.source / 'artifacts/arm64/Release' / ('dotnet-sdk-'+self.sdk+'-linux-arm64.tar.gz')
        feed = self.source / 'artifacts/obj/arm64/Release/blob-feed/assets'
        runtime_name = 'dotnet-runtime-'+self.selected['runtime']+'-linux-arm64.tar.gz'
        asp_name = 'aspnetcore-runtime-internal-'+self.selected['runtime']+'-linux-arm64.tar.gz'
        runtime = self.source / 'artifacts/arm64/Release/runtime' / runtime_name
        directory = self.reports / 'construction'; directory.mkdir()
        self.container(['python3',self.script('inspect-sdk-construction9.py'),'--sdk-archive','/work/source-v'+self.sdk+'/artifacts/arm64/Release/'+sdk_archive.name,
                        '--runtime-archive','/work/source-v'+self.sdk+'/artifacts/arm64/Release/runtime/'+runtime_name,
                        '--aspnetcore-archive','/work/source-v'+self.sdk+'/artifacts/obj/arm64/Release/blob-feed/assets/'+asp_name,
                        '--runtime-version',self.selected['runtime'],'--reports-dir','/delivery/reports/construction/identity'],readonly=True,network='none')
        identity = E.load(directory / 'identity/shared-framework-identity.json')
        replay = E.load(self.reports / 'origin-tools/replay.json')
        E.require(replay['completedReplay'] and replay['inputSha256'] == E.fingerprint(self.reports / 'origin-tools/installer.binlog')['sha256'], 'Replay does not bind the closed installer binlog')
        observations = [json.loads(line) for line in (self.reports / 'build/installer-observations.jsonl').read_text().splitlines()]
        components = []
        for comparison, name in zip(identity['comparisons'], [runtime_name,asp_name]):
            E.require(comparison['identical'] and comparison['sdkEntries'] == comparison['inputEntries'], 'Local framework payload differs')
            expected = E.fingerprint(feed/name)
            if name == runtime_name: E.require(E.fingerprint(runtime) == expected, 'Runtime producer and feed differ')
            source_alias = '/work/source-v'+self.sdk+'/'
            copies = []
            for task in replay['tasks']:
                if not task['Succeeded'] or not (task['Started'] < task['Finished']) or len(task['Attempts']) != 1: continue
                attempt = task['Attempts'][0]
                if attempt['Kind'] != 'local-copy': continue
                try:
                    copied_source=E.generated_relative(attempt['Source'],self.sdk)
                    relative=E.generated_relative(attempt['Destination'],self.sdk)
                except ValueError: continue
                if copied_source != (feed/name).relative_to(self.source).as_posix(): continue
                if not (task['Started'] < attempt['Event'] < task['Finished']): continue
                if not relative.startswith('src/installer/'): continue
                matches = [row for row in observations if row['destination'] == relative and row['feed'] == (feed/name).relative_to(self.source).as_posix()
                           and all(row[k] == v for k,v in expected.items())]
                if matches: copies.append(dict(context=task['Context'], task=task, destinationObservations=matches))
            E.require(copies, 'No completed local-copy task plus exact destination observation for '+name)
            components.append(dict(framework=comparison['framework'],version=self.selected['runtime'],originVerified=True,
                                   identicalEntryCount=comparison['sdkEntryCount'],localFeedArchive=dict(name=name,**expected),
                                   producerRole='independent-runtime-producer' if name == runtime_name else 'ASP.NET node archive published to the local feed',
                                   completedLocalCopies=copies))
        evidence = [self.reports / 'origin-tools/installer.binlog', self.reports / 'origin-tools/replay.json',
                    self.reports / 'origin-tools/compiler-inputs.json',self.reports / 'build/installer-observations.jsonl',
                    directory / 'identity/shared-framework-identity.json', self.reports / 'build/net'+self.major+'-patches-apply.json']
        E.write(directory / 'origin.json', dict(status='passed',sdkArchive=E.fingerprint(sdk_archive),components=components,
                evidenceFiles=[E.record(self.output,p) for p in evidence],
                sourceComponents=E.load(self.reports / 'generation/generation.json')['componentCommits'],
                scope='Fresh full source-build graph, actual completed local installer copies, stable during-build destination observations and exact entire shared-framework payloads. External bootstrap/reference inputs remain.'))

    def test(self):
        self.verify_inputs(); self.action('test')
        status = E.load(self.reports / 'test/test-status.json')
        text = (self.reports / 'test/test.log').read_text(errors='replace')
        aliases = re.findall(r'Results File:\s*(/work/source-v'+re.escape(self.sdk)+r'/[^\r\n]+?\.trx)', text)
        E.require(len(set(aliases)) == 1, 'One actual current-invocation TRX is required')
        relative = aliases[0].split('/work/source-v'+self.sdk+'/',1)[1]
        path = self.source / relative
        E.require(path.resolve().is_relative_to((self.source / 'test').resolve()), 'TRX escaped the original tests')
        shutil.copyfile(E.ordinary(path), self.reports / 'test/upstream.trx'); E.smoke_results(self.reports / 'test/upstream.trx')
        test_bin = self.source / 'test/Microsoft.DotNet.SourceBuild.SmokeTests/bin/Release' / ('net'+self.major+'.0')
        logs = self.reports / 'test/upstream-logs'; logs.mkdir()
        for path in (test_bin / 'logs').rglob('*'):
            if path.is_file() and not path.is_symlink():
                target = logs / path.relative_to(test_bin / 'logs'); target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path,target)
        for name in ['msftSdkFiles.txt','sbSdkFiles.txt','assets/SdkDiffExclusions.txt','assets/baselines/MsftToSbSdk.diff']:
            path = test_bin / name
            if path.is_file():
                target = self.reports / 'test/comparison' / name; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
        actual_diff = list(logs.rglob('UpdatedMsftToSbSdk.diff'))
        baseline_diff = self.reports / 'test/comparison/assets/baselines/MsftToSbSdk.diff'
        E.require(len(actual_diff) == 1 and baseline_diff.is_file(), 'Actual warning-mode layout comparison outputs are required')
        E.write(self.reports / 'test/comparison/summary.json', dict(method='SdkContentTests.CompareMsftToSb',
                warningMode=True, actualDiff=E.record(self.output,actual_diff[0]), baselineDiff=E.record(self.output,baseline_diff),
                baselineByteIdentical=actual_diff[0].read_bytes() == baseline_diff.read_bytes(),
                scope='Original full comparison outputs retained. A passed warning-mode method does not establish equal layout, binary identity or API compatibility.'))
        self.prebuilt(); self.origin(); self.source_roots()

    def prebuilt(self):
        root = self.source / 'artifacts/prebuilt-report'; output = self.reports / 'prebuilt'; output.mkdir()
        required = ['prebuilt-usage.xml','annotated-usage.xml','baseline-comparison.xml','generated-new-baseline.xml']
        for name in required:
            path = E.ordinary(root/name); E.xml(path); shutil.copyfile(path,output/name)
        baseline = self.source / 'tools-local/prebuilt-baseline.xml'
        if baseline.exists(): shutil.copyfile(E.ordinary(baseline),output/'declared-default-baseline.xml')
        usage = E.xml(output/'prebuilt-usage.xml'); comparison = E.xml(output/'baseline-comparison.xml')
        E.write(output/'summary.json', dict(preservedRawReports=[E.record(self.output,output/name) for name in required],
                usageRows=len(usage.findall('./Usages/Usage')),newBaselineEntries=len(comparison.findall('./New/Usage')),
                removedBaselineEntries=len(comparison.findall('./Removed/PackageIdentity')), declaredDefaultBaselinePresent=baseline.exists(),
                scope='Original aggregate reports preserved after the actual upstream suite. A missing declared baseline defaults to empty in upstream; bootstrap/reference exclusions and online inputs remain. Counts do not prove a zero-prebuilt or clean bootstrap.'))

    def source_roots(self):
        generation = E.load(self.reports / 'generation/generation.json')
        roots = [dict(name='installer-generator',path=str(self.installer),kind='git',expectedCommit=self.selected['commit']),
                 dict(name='generated-adapters',path=str(self.source),kind='tree',
                      exclude=['src','artifacts','.dotnet','.tools','packages','.nuget'])]
        for name, pin in generation['componentCommits'].items():
            component = self.source / 'src' / name
            if not component.is_dir(): continue
            E.require((component/'.git').exists(), 'A preserved component Git folder is required: '+name)
            roots.append(dict(name='component-'+name,path=str(component),kind='git',expectedCommit=pin))
        E.write(self.reports / 'ci/source-roots.json', dict(schemaVersion=1,roots=roots))

    def collect_command(self, output):
        self.container(['python3',self.script('collect-artifacts.py'),'--source-dir','/installer',
                        '--generated-source-dir','/work/source-v'+self.sdk,'--generation-report','/delivery/reports/generation/generation.json',
                        '--profile','/delivery/reports/ci-inputs/effective-profile.json','--output-dir',output,
                        '--reports-dir','/delivery/reports','--build-image-id',self.image,'--build-revision',self.args.build_revision],readonly=True,network='none')

    def verify(self):
        E.require((self.output/'sources/source-manifest.json').is_file(), 'Used sources must be packaged before native verification')
        self.verify_inputs(); self.collect_command('/candidate')
        candidate = E.load(self.candidate/'build-manifest.json')
        shutil.copyfile(self.candidate/'build-manifest.json', self.reports/'ci/candidate-manifest.json')
        for (name,distribution,version,icu,ssl),rid in zip([
            ('ubuntu22','ubuntu','22.04','libicu70','libssl3'),('ubuntu24','ubuntu','24.04','libicu74','libssl3t64'),
            ('debian13','debian','13','libicu76','libssl3t64')],self.selected['rids']):
            self.command(self.engine+['pull','docker.io/library/'+distribution+':'+version])
            base = self.inspect('docker.io/library/'+distribution+':'+version, self.reports/'ci'/(name+'-base-image.json'))
            digest = base.get('Digest'); E.require(isinstance(digest,str) and re.fullmatch(r'sha256:[a-f0-9]{64}',digest), 'Missing inspected manifest digest')
            pinned = 'docker.io/library/'+distribution+'@'+digest
            E.require(base.get('RepoDigests',[]).count(pinned) == 1, 'Inspected manifest lacks an exact repository binding')
            tag = 'localhost/cbodotnet-net'+self.major+'-verify-'+name+':'+self.run_id+'-'+self.attempt
            self.command(self.engine+['build','--network=host','--file',self.frozen/'containers/verify-net10.Containerfile',
                                     '--build-arg','BASE_IMAGE='+pinned,'--build-arg','ICU_PACKAGE='+icu,'--build-arg','SSL_PACKAGE='+ssl,'--tag',tag,self.frozen])
            image = self.inspect(tag,self.reports/'ci'/(name+'-verification-image.json'))
            metadata = '''import json,os,pathlib,platform,subprocess,sys
release={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key,value=line.split('=',1); release[key]=value.strip('"')
packages=subprocess.check_output(['dpkg-query','-W','-f=${binary:Package}\\t${Version}\\n',sys.argv[3],sys.argv[4],'libc6','libstdc++6','zlib1g','libgssapi-krb5-2'],text=True)
value={'imageId':sys.argv[1],'architecture':platform.machine(),'uid':os.getuid(),'osRelease':{'ID':release['ID'],'VERSION_ID':release['VERSION_ID']},'installedPackages':dict(line.split('\\t',1) for line in packages.splitlines()),'environmentOverrides':{key:os.environ.get(key) for key in ['LD_LIBRARY_PATH','DOTNET_ROOT','DOTNET_SYSTEM_GLOBALIZATION_INVARIANT','CLR_ICU_VERSION_OVERRIDE','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics']}}
with pathlib.Path('/delivery/reports/ci/'+sys.argv[2]+'-userland.json').open('x') as out: json.dump(value,out,indent=2)
'''
            self.command(self.engine+['run','--rm','--interactive','--network=none','--security-opt','seccomp='+str(self.inputs/'seccomp.json'),'--user',str(self.uid)+':'+str(self.gid),
                         '--volume',str(self.output)+':/delivery',image['Id'],'python3','-',image['Id'],name,icu,ssl],input=metadata)
            self.command(self.engine+['run','--rm','--network=none','--security-opt','seccomp='+str(self.inputs/'seccomp.json'),'--user',str(self.uid)+':'+str(self.gid),
                         '--env','LANG=C.UTF-8','--env','LC_ALL=C.UTF-8','--env','DOTNET_GENERATE_ASPNET_CERTIFICATE=false',
                         '--volume',str(self.output)+':/delivery','--volume',str(self.candidate)+':/artifacts:ro','--workdir','/tmp',image['Id'],
                         'taskset','--cpu-list',self.cpus,'bash',self.script('verify-sdk.sh'),'--archive','/artifacts/'+candidate['sdkArchive']['path'],
                         '--output-dir','/delivery/reports/verify-'+name,'--expected-version',self.sdk,'--expected-rid',rid,
                         '--framework','net'+self.major+'.0','--max-glibc','2.23'])
            self.paths[name] = 'reports/verify-'+name+'/verification.json'

    def collect(self):
        self.collect_command('/delivery')
        old = E.load(self.candidate/'build-manifest.json'); new = E.load(self.output/'build-manifest.json')
        E.require(all(old['sdkArchive'][key] == new['sdkArchive'][key] for key in ['bytes','sha256','sha512']), 'SDK changed after verification')

    def finish(self, code):
        self.log.flush(); self.journal.flush(); self.log.close(); self.journal.close()
        receipt = dict(schemaVersion=1,stage=self.stage,status='passed' if code == 0 else 'failed',exitCode=code,
                       sourceCommit=self.selected['commit'],imageId=self.image,startedAtUtc=self.started,finishedAtUtc=now(),
                       commands=self.commands,paths=self.paths,**self.identity,
                       environment=dict(architecture='aarch64',uid=self.uid,gid=self.gid,allowedCpuSelection=self.cpus,
                                        workspace=str(self.workspace),delivery=str(self.output)))
        if self.stage == 'collect' and code == 0:
            receipt.update(manifest=E.record(self.output,self.output/'build-manifest.json'),
                           log=E.record(self.output,self.log_path),commandsFile=E.record(self.output,self.command_path))
        E.write(self.receipt, receipt)


def main():
    if len(sys.argv) > 2 and sys.argv[2] in ['validate','verify-release']:
        parser = argparse.ArgumentParser(description='Validate a completed generated-source CI delivery')
        parser.add_argument('major',choices=['6','7']); parser.add_argument('command',choices=['validate','verify-release'])
        parser.add_argument('--output-dir',type=Path,required=True); parser.add_argument('--project-root',type=Path,required=True)
        parser.add_argument('--expected-project-commit'); parser.add_argument('--expected-run-id'); parser.add_argument('--expected-run-attempt')
        args = parser.parse_args(); release = args.output_dir.absolute()
        expected = dict(projectCommit=args.expected_project_commit or os.environ.get('GITHUB_SHA'),
                        runId=args.expected_run_id or os.environ.get('GITHUB_RUN_ID'),
                        runAttempt=args.expected_run_attempt or os.environ.get('GITHUB_RUN_ATTEMPT'))
        E.require(all(expected.values()), 'Explicit or actual GitHub run identity is required')
        result = E.validate(release,expected)
        E.require(result['sdkVersion'] == E.VERSIONS[args.major]['sdk'], 'The selected version gate differs')
        path = release / 'ci-validation.json'
        if args.command == 'verify-release': E.require(E.load(path) == result, 'Downloaded validation envelope differs')
        else: E.write(path,result)
        print(json.dumps({'status':'passed','sdkVersion':result['sdkVersion'],'archiveSha256':result['sdkArchive']['sha256']}))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('major',choices=['6','7']); parser.add_argument('stage',choices=['prepare','build','scan','test','verify','collect'])
    parser.add_argument('--workspace',type=Path,required=True); parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--build-id',required=True); parser.add_argument('--build-revision',required=True)
    args = parser.parse_args(); run = Run(args); code = 1
    try:
        getattr(run,args.stage)()
        code = 0
    except Exception as error:
        code = error.returncode if isinstance(error,subprocess.CalledProcessError) else 1
        print('error: '+str(error),file=sys.stderr)
    finally: run.finish(code)
    return code


if __name__ == '__main__': raise SystemExit(main())
