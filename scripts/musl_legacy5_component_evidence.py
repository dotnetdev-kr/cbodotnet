"""Independent SDK5 compiler/package evidence from separate original processes.

The replay name and the original MSBuild context jointly identify an output.
Nothing here combines binary logs, executes products, or admits imported sources.
Only neutral byte, archive and event parsers are shared with older contracts.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import shlex
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_neutral_compiler_bytes', ROOT / 'scripts/musl_legacy_admission.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
require, fingerprint, portable = B.require, B.fingerprint, B.portable
FP = ('bytes', 'sha256', 'sha512')
SDK = '5.0.214'
COMMITS = dict(sdk='3fdf76c35026e311b7edc245d4b3d9e812fe532e',
               nuget='d525b0e670f3b6cbd5c73a35f04730a9f658c852',
               vstest='99b911a57a02fc5d2eeef23e9ab8cbea4505678b')
VERSIONS = dict(sdk=SDK + '-ci', nuget='5.9.1-rc.8', vstest='16.9.4-dev')
BOOTSTRAPS = dict(sdk='5.0.401', nuget='5.0.401', vstest='6.0.135')
NUGET_PACKAGES = {'microsoft.build.nugetsdkresolver', 'nuget.build.tasks', 'nuget.build.tasks.console',
    'nuget.build.tasks.pack', 'nuget.commandline.xplat', 'nuget.commands', 'nuget.common',
    'nuget.configuration', 'nuget.credentials', 'nuget.dependencyresolver.core', 'nuget.frameworks',
    'nuget.librarymodel', 'nuget.packagemanagement', 'nuget.packaging', 'nuget.packaging.core',
    'nuget.projectmodel', 'nuget.protocol', 'nuget.resolver', 'nuget.versioning'}
VSTEST_PACKAGES = {'Microsoft.TestPlatform.CLI', 'Microsoft.TestPlatform.Build'}
VSTEST_REPLAYS = ('original-solution-restore', 'original-solution-build', 'package-publish',
    'vstest.console-publish', 'datacollector-publish', 'testhost-publish', 'testhost.x86-publish',
    'original-net451-reference-package-restore', 'original-eventlog-net451-build',
    'Microsoft.TestPlatform.CLI-pack', 'Microsoft.TestPlatform.Build-pack')
EMPTY_REPLAYS = {'original-solution-restore', 'original-net451-reference-package-restore',
                 'Microsoft.TestPlatform.CLI-pack', 'Microsoft.TestPlatform.Build-pack'}
IMPORT_POLICY_SHA256 = '7f05db8d8910040c78fa3fb4103bfb53d7ff80488b9aadcffd730a05837d27bb'


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK5 evidence file required')
    return path


def retain(release, source, name):
    source = ordinary(source); target = Path(release) / portable(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    require(not any(p.is_symlink() for p in (target, *target.parents)), 'Redirected SDK5 evidence')
    if target.exists(): require(fingerprint(target) == fingerprint(source), 'Retained SDK5 evidence differs')
    elif target != source: shutil.copyfile(source, target)
    return dict(path=name, **fingerprint(target))


def write(release, name, value):
    target = Path(release) / portable(name); target.parent.mkdir(parents=True, exist_ok=True)
    require(not any(p.is_symlink() for p in (target, *target.parents)), 'Redirected SDK5 record')
    raw = (json.dumps(value, indent=2) + '\n').encode()
    require(not target.exists() or target.read_bytes() == raw, 'Refusing to overwrite different SDK5 evidence')
    if not target.exists(): target.write_bytes(raw)
    return dict(path=name, **fingerprint(target))


def import_policy():
    path = ordinary(ROOT / 'scripts/musl-legacy5-vstest-inputs.json')
    require(fingerprint(path)['sha256'] == IMPORT_POLICY_SHA256, 'SDK5 VSTest import policy differs')
    policy = json.loads(path.read_bytes())
    require(policy['sdkVersion'] == SDK and policy['sourceCommit'] == COMMITS['vstest']
            and len(policy['imports']) == 38, 'Independent SDK5 import boundary required')
    return policy['imports']


def absolute(value, project, mount):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n'), 'Ordinary SDK5 compiler path required')
    result = posixpath.normpath(value if value.startswith('/') else posixpath.join(posixpath.dirname(project), value))
    require(result.startswith(mount + '/'), 'Actual SDK5 compiler output escaped its source mount')
    return result


def commands(task):
    found = list(dict.fromkeys(e['text'] for e in task['events'] if e['kind'] == 'command-line' and e.get('text')))
    require(len(found) == 1, 'One actual executed SDK5 compiler command required')
    return shlex.split(found[0])


def compiler_rows(tasks, mount, replay_name, component):
    """Keep original contexts; identical contexts in different processes stay distinct."""
    require(component in COMMITS and isinstance(mount, str) and mount.startswith('/') and mount != '/'
            and mount == posixpath.normpath(mount) and not any(c in mount for c in '\\\0\r\n'), 'Exact SDK5 source mount required')
    result = []
    for task in tasks.values():
        if task['taskName'] != 'Csc' or task['succeeded'] is not True: continue
        require(task['projectFile'].startswith(mount + '/'), 'SDK5 compiler project escaped its source mount')
        skipped = B.task_values(task, 'SkipCompilerExecution')
        if any(value.lower() == 'true' for value in skipped): continue
        require(all(value.lower() == 'false' for value in skipped), 'Unknown SDK5 compiler execution condition')
        if not B.task_values(task, 'Sources'): continue
        argv = commands(task); bootstrap = BOOTSTRAPS[component]
        suffix = '/sdk/' + bootstrap + '/Roslyn/bincore/csc.dll'
        require(len(argv) >= 3 and argv[1] == 'exec' and argv[2].endswith(suffix)
                and argv[0] == argv[2][:-len(suffix)] + '/dotnet', 'SDK5 compiler launch must use its exact independent bootstrap')
        sdk_root = argv[2][:-len('/Roslyn/bincore/csc.dll')]
        require(task['taskFile'] in {sdk_root + '/Roslyn/Microsoft.CSharp.Core.targets',
                    sdk_root + '/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.targets'},
                'SDK5 compiler targets and launched bootstrap disagree')
        primary = {absolute(p, task['projectFile'], mount) for p in B.task_values(task, 'OutputAssembly')}
        observed = {}
        for key, kind in [('out', 'assembly'), ('refout', 'reference-assembly')]:
            values = [t.split(':', 1)[1] for t in argv if t.lower().startswith(('/' + key + ':', '-' + key + ':'))]
            require(len(values) <= 1, 'Ambiguous actual SDK5 compiler output argument')
            if values: observed[kind] = (absolute(values[0], task['projectFile'], mount), '/' + key + ':' + values[0])
        require('assembly' in observed and primary == {observed['assembly'][0]}, 'SDK5 command and OutputAssembly disagree')
        refs = {absolute(p, task['projectFile'], mount) for p in B.task_values(task, 'OutputRefAssembly') if p}
        require(not refs or ('reference-assembly' in observed and refs == {observed['reference-assembly'][0]}),
                'SDK5 reference scalar and command disagree')
        for kind, (path, parameter) in observed.items():
            result.append(dict(replayName=replay_name, context=task['context'], outputPath=path,
                               outputKind=kind, commandParameter=parameter))
    return result


def replay_names(component, entries):
    names = [e['name'] for e in entries]
    expected = ['sdk', 'redist'] if component == 'sdk' else ['original-library-matrix'] if component == 'nuget' else list(VSTEST_REPLAYS)
    require(names == expected, 'Complete separate original SDK5 replay sequence required')


def read_replay(component, entry, release, *, retained):
    paths = {k: B.checked(release, entry[k]) if retained else ordinary(entry[k]) for k in ('status', 'tasks', 'binlog')}
    status = json.loads(paths['status'].read_bytes())
    require(status.get('schemaVersion') == 1 and status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0
            and status.get('failure') is None and status.get('inputSha256') == fingerprint(paths['binlog'])['sha256'],
            'Complete successful SDK5 replay bound to its original binary log required')
    if paths['tasks'].stat().st_size == 0:
        require(component == 'vstest' and entry['name'] in EMPTY_REPLAYS
                and status.get('completedSelectedTasks') == 0 and status.get('observedTaskNames', {}).get('Csc', 0) == 0,
                'Only the four original SDK5 VSTest empty selections are allowed')
        tasks = {}
    else:
        tasks = B.read_tasks(paths['tasks'])
        require(len(tasks) == status.get('completedSelectedTasks'), 'SDK5 replay selected-task count differs')
    return paths, tasks, compiler_rows(tasks, entry['sourceMountRoot'], entry['name'], component)


def expected_packages(component, packages, *, retained=False):
    result = []
    for package in packages:
        path = ordinary(package)
        if component == 'sdk':
            require(retained or path.name == 'dotnet-toolset-internal-' + VERSIONS['sdk'] + '.zip', 'Exact SDK5 tooling ZIP required')
            result.append((path, 'dotnet-toolset-internal')); continue
        metadata = B.nuspec_metadata(path); name = metadata.findtext('{*}id')
        repository = metadata.find('{*}repository'); license_node = metadata.find('{*}license')
        require(metadata.findtext('{*}version') == VERSIONS[component] and repository is not None
                and repository.get('commit') == COMMITS[component], 'Original SDK5 package source/version differs')
        if component == 'nuget':
            require(name.lower() in NUGET_PACKAGES and repository.get('url') == 'https://github.com/NuGet/NuGet.Client'
                    and license_node is not None and license_node.get('type') == 'expression' and license_node.text == 'Apache-2.0',
                    'Original NuGet5 package/license differs')
        else:
            require(name in VSTEST_PACKAGES and repository.get('url') == 'https://github.com/microsoft/vstest'
                    and license_node is not None and license_node.get('type') == 'file' and license_node.text == 'LICENSE_NET.txt',
                    'Original VSTest5 package/license differs')
        result.append((path, name))
    ids = [name.lower() for _, name in result]
    expected = {'dotnet-toolset-internal'} if component == 'sdk' else NUGET_PACKAGES if component == 'nuget' else {s.lower() for s in VSTEST_PACKAGES}
    require(len(ids) == len(expected) and set(ids) == expected, 'Complete unique original SDK5 package set required')
    return result


def output_key(row):
    return tuple(row[k] for k in ('replayName', 'context', 'outputPath', 'outputKind', 'commandParameter'))


def package_bindings(component, packages, snapshots):
    by_sha = {}
    for row in snapshots: by_sha.setdefault(row['fingerprint']['sha256'], []).append(row)
    compiled_names = {PurePosixPath(row['outputPath']).name for row in snapshots}
    outputs, imports = [], []; policy = import_policy() if component == 'vstest' else {}
    for path, record in packages:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'Duplicate SDK5 package archive members')
            for member in names:
                portable(member.rstrip('/'))
                if not member.lower().endswith(('.dll', '.exe')): continue
                raw = archive.read(member)
                if raw[:2] != b'MZ': continue
                identity = B.MANAGED.inspect(raw)
                fp = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
                if component == 'vstest' and member in policy:
                    require({k: fp[k] for k in ('bytes', 'sha256')} == policy[member], 'Original SDK5 VSTest imported bytes differ')
                    imports.append(dict(packagePath=record['path'], member=member, fingerprint=fp,
                                        embeddedSource=B.embedded_component_source(identity), separateSourceAttributionRequired=True))
                    continue
                matches = [r for r in by_sha.get(fp['sha256'], []) if r['fingerprint'] == fp
                           and PurePosixPath(r['outputPath']).name == PurePosixPath(member).name]
                if not matches:
                    require(component == 'sdk', 'SDK5 package member lacks actual compiler output: ' + member)
                    require(PurePosixPath(member).name not in compiled_names,
                            'SDK5 source compiler product cannot be reclassified as an unmatched import: ' + member)
                    continue
                row = sorted(matches, key=lambda r: (r['outputKind'] != 'assembly', output_key(r)))[0]
                outputs.append(dict(packagePath=record['path'], member=member, sourceRoot=component, sourceCommit=COMMITS[component],
                                    fingerprint=fp, **{k: row[k] for k in ('replayName', 'context', 'outputPath', 'outputKind', 'commandParameter')}))
    require(outputs, 'Actual SDK5 component compiler bindings required')
    if component == 'nuget': require(len(outputs) == 76 and not imports, 'All76 original NuGet5 members require compiler provenance')
    if component == 'vstest': require(len(outputs) == 301 and len(imports) == 38, 'Original VSTest5 requires301 own members and38 separate imports')
    return outputs, imports


def emit(component, context, release, roots):
    require(context['sdkVersion'] == SDK and component in COMMITS, 'Independent SDK5 compiler route required')
    release = Path(release).absolute(); root = roots[component]; source = Path(root['path']).absolute()
    require(root.get('kind', 'git') == 'git' and root['commit'] == COMMITS[component]
            and subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == COMMITS[component],
            'Exact SDK5 compiler source checkout required')
    entries = context[component + 'Replays']; replay_names(component, entries)
    replays, snapshots = [], []
    for entry in entries:
        paths, tasks, rows = read_replay(component, entry, release, retained=False)
        replays.append(dict(name=entry['name'], sourceMountRoot=entry['sourceMountRoot'],
            **{k: retain(release, path, 'reports/build/' + component + '/' + entry['name'] + '-' + path.name) for k, path in paths.items()}))
        for row in rows:
            local = ordinary(source.joinpath(*PurePosixPath(row['outputPath']).relative_to(entry['sourceMountRoot']).parts))
            fp = fingerprint(local)
            saved = retain(release, local, 'reports/build/' + component + '/compiler-outputs/' + fp['sha256'] + '.bin')
            snapshots.append(dict(**row, fingerprint=fp, file=saved))
    require(snapshots, 'Successful source-bearing SDK5 compiler tasks required')
    packages = []; records = []
    paths = [context['toolsetZip']] if component == 'sdk' else context[component + 'Packages']
    for path, package_id in expected_packages(component, paths):
        saved = retain(release, path, 'imported-inputs/' + fingerprint(path)['sha256'] + ('.zip' if component == 'sdk' else '.nupkg'))
        record = dict(id=package_id, version=VERSIONS[component], sourceCommit=COMMITS[component], **saved)
        records.append(record); packages.append((path, record))
    outputs, imports = package_bindings(component, packages, snapshots)
    proof = dict(schemaVersion=1, kind='sdk5-component-compiler-proof', sdkVersion=SDK, component=component,
        sourceCommit=COMMITS[component], bootstrapVersion=BOOTSTRAPS[component], replays=replays, packages=records,
        compilerOutputs=snapshots, compiledOutputs=outputs, importedMembers=imports, transformations=[],
        qualificationAllowed=False, sourceAdmissionAllowed=False, importedDependenciesRequireSeparateSourceAttribution=True)
    descriptor = write(release, 'reports/build/' + component + '-compiler-proof.json', proof)
    validate(release, descriptor, roots)
    return descriptor


def validate(release, descriptor, roots):
    release = Path(release); proof = json.loads(B.checked(release, descriptor).read_bytes()); component = proof['component']
    require(component in COMMITS and proof.get('schemaVersion') == 1 and proof.get('kind') == 'sdk5-component-compiler-proof'
            and proof.get('sdkVersion') == SDK and proof.get('sourceCommit') == COMMITS[component]
            and proof.get('bootstrapVersion') == BOOTSTRAPS[component]
            and roots[component].get('kind', 'git') in ('git', 'git-export') and roots[component]['commit'] == COMMITS[component]
            and proof.get('transformations') == [] and proof.get('qualificationAllowed') is False
            and proof.get('sourceAdmissionAllowed') is False and proof.get('importedDependenciesRequireSeparateSourceAttribution') is True,
            'Closed independent SDK5 compiler evidence required')
    replay_names(component, proof['replays']); observed = []
    for entry in proof['replays']:
        _, _, rows = read_replay(component, entry, release, retained=True); observed.extend(rows)
    actual = {}; wanted = {output_key(r) for r in observed}
    for row in proof['compilerOutputs']:
        require(set(row) == {'replayName', 'context', 'outputPath', 'outputKind', 'commandParameter', 'fingerprint', 'file'},
                'Original SDK5 compiler snapshot schema differs')
        key = output_key(row); path = B.checked(release, row['file'])
        require(key in wanted and key not in actual and fingerprint(path) == row['fingerprint'], 'SDK5 compiler output/context bytes differ')
        actual[key] = row
    require(set(actual) == wanted and actual, 'Complete separate-process SDK5 compiler output inventory required')
    originals = expected_packages(component, [B.checked(release, {k: r[k] for k in ('path', *FP)}) for r in proof['packages']], retained=True)
    packages = []
    for (path, package_id), record in zip(originals, proof['packages']):
        require(set(record) == {'id', 'version', 'sourceCommit', 'path', *FP} and record['id'] == package_id
                and record['version'] == VERSIONS[component] and record['sourceCommit'] == COMMITS[component], 'SDK5 package record differs')
        packages.append((path, record))
    outputs, imports = package_bindings(component, packages, proof['compilerOutputs'])
    require(proof['compiledOutputs'] == outputs and proof['importedMembers'] == imports,
            'Complete original SDK5 package/compiler bindings differ')
    return dict(proof=proof, packages={r['path']: r for r in proof['packages']},
                members={(r['packagePath'], r['member']): r['fingerprint'] for r in outputs}, imports=imports)


def validate_crossgen_task(row, replay, tasks, record):
    """Bind the original SDK5 Crossgen/JIT paths; native identities are external."""
    require(record['sdkVersion'] == SDK and replay['name'] == row['replayName'] == 'installer', 'Original SDK5 installer replay required')
    task = tasks[row['context']]; source = replay['sourceMountRoot']
    require(task['succeeded'] is True and task['taskName'] == row['task'] == 'Crossgen'
            and task['projectFile'] == source + '/src/redist/redist.csproj'
            and task['taskFile'] == source + '/src/redist/targets/Crossgen.targets', 'Original SDK5 installer Crossgen task required')
    expected = source + '/artifacts/bin/redist/Release/dotnet/' + portable(row['archivePath'])
    arch = 'arm64' if record['architecture'] == 'aarch64' else 'x64'
    require(record['architecture'] in ('aarch64', 'x64') and record['targetRid'] == 'linux-musl-' + arch
            and row['inputPath'] == row['outputPath'] == expected
            and B.task_values(task, 'SourceAssembly') == B.task_values(task, 'DestinationPath') == {expected}
            and B.task_values(task, 'ReadyToRun') == {'True'}
            and B.task_values(task, 'Architecture') in (set(), {arch}),
            'Actual SDK5 ReadyToRun input/output/architecture differs')
    compiler = record['crossgenPath']; jit = record['nativeRuntimeRoot'] + '/libclrjit.so'
    require(B.task_values(task, 'CrossgenPath') == {compiler} and B.task_values(task, 'JITPath') == {jit}, 'SDK5 native Crossgen/JIT task paths differ')
    expected_native = record['expectedNativeFingerprints']
    require(all(set(expected_native[k]) == set(FP) and isinstance(expected_native[k]['bytes'], int)
                and expected_native[k]['bytes'] > 0 and len(expected_native[k]['sha256']) == 64 and len(expected_native[k]['sha512']) == 128
                for k in ('crossgen', 'libclrjit.so')), 'Independent SDK5 native compiler/JIT fingerprints required')
    calls = [shlex.split(e['text'].removeprefix('> ')) for e in task['events'] if e['kind'] == 'command-line']
    compilations = [a for a in calls if a and a[0] == compiler and '-in' in a]
    require(len(compilations) == 1, 'One actual SDK5 source Crossgen compilation required')
    argv = compilations[0]
    require('-readytorun' in argv and '-MissingDependenciesOK' in argv and argv.count('-in') == argv.count('-out') == argv.count('-JITPath') == 1
            and argv[argv.index('-in') + 1] == expected and argv[argv.index('-JITPath') + 1] == jit
            and PurePosixPath(argv[argv.index('-out') + 1]).name == PurePosixPath(expected).name,
            'Actual SDK5 source Crossgen/JIT command differs')
    require(len(calls) == 2 and all(a and a[0] == compiler for a in calls)
            and sum('-createperfmap' in a for a in calls) == 1, 'Original SDK5 compilation and symbol commands required')
    platform = B.task_values(task, 'PlatformAssemblyPaths')
    framework = source + '/artifacts/bin/redist/Release/dotnet/shared/Microsoft.NETCore.App/5.0.17'
    sdk_root = source + '/artifacts/bin/redist/Release/dotnet/sdk/' + SDK
    require(len(platform) >= 2 and framework in platform and posixpath.dirname(expected) in platform
            and all(p == framework or p == sdk_root or p.startswith(sdk_root + '/') for p in platform)
            and all(p == posixpath.normpath(p) for p in platform) and B.task_values(task, 'CreateSymbols') == {'True'},
            'Original SDK5 framework resolution and symbol parameters required')
    for call in calls:
        require(call.count('-platform_assemblies_paths') == 1 and
                set(call[call.index('-platform_assemblies_paths') + 1].split(':')) == platform,
                'SDK5 source Crossgen framework arguments differ from its original task')
    symbol = next(a for a in calls if '-createperfmap' in a)
    require(symbol[-3:] == ['-createperfmap', posixpath.dirname(expected), expected] and '-readytorun' in symbol,
            'SDK5 symbols must bind the same actual transformed assembly')
    return dict(replayName=row['replayName'], context=row['context'], inputAssembly=expected,
                outputAssembly=row['outputPath'], crossgenPath=compiler, jitPath=jit, nativeFingerprints=expected_native, commands=calls)
