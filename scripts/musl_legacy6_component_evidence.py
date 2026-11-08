"""SDK6 compiler-to-package evidence, including real reference outputs.

Only neutral byte/ZIP/binlog parsers are shared with the older contract. SDK6
source pins, package versions, imported dependencies and output rules live here.
This module reads completed builds; it never executes a shipped assembly.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_neutral_binary_primitives', ROOT / 'scripts/musl_legacy_admission.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
require, fingerprint, portable = B.require, B.fingerprint, B.portable
FP = ('bytes', 'sha256', 'sha512')
SDK = '6.0.136'
COMMITS = dict(sdk='1d205826ddc14c8f868eb6373e7a6bafcb9fe5be',
               nuget='451e9bc27184dc49d04e975122c9e7189d525872',
               vstest='cc7fb0593127e24f55ce016fb3ac85b5b2857fec')
VERSIONS = dict(sdk=SDK + '-ci', nuget='6.0.6-rc.4', vstest='17.0.3-dev')
NUGET_PACKAGES = {'microsoft.build.nugetsdkresolver', 'nuget.build.tasks', 'nuget.build.tasks.console',
    'nuget.build.tasks.pack', 'nuget.commands', 'nuget.common', 'nuget.configuration', 'nuget.credentials',
    'nuget.dependencyresolver.core', 'nuget.frameworks', 'nuget.librarymodel', 'nuget.packaging',
    'nuget.packaging.core', 'nuget.projectmodel', 'nuget.protocol', 'nuget.versioning',
    'nuget.resolver', 'nuget.commandline.xplat', 'nuget.packagemanagement'}
VSTEST_PACKAGES = {'Microsoft.TestPlatform.CLI', 'Microsoft.TestPlatform.Build'}
VSTEST_IMPORTS = {
    'contentFiles/any/net6.0/TestHost/Newtonsoft.Json.dll': ('72cf291d4bab0edd08a9b07c6173e1e7ad1abb7ab727fd7044bf6305d7515661', 'ae9fe44e1323e91bcbd185ca1a14099fba7c021f'),
    'contentFiles/any/net6.0/Newtonsoft.Json.dll': ('72cf291d4bab0edd08a9b07c6173e1e7ad1abb7ab727fd7044bf6305d7515661', 'ae9fe44e1323e91bcbd185ca1a14099fba7c021f'),
    'contentFiles/any/net6.0/NuGet.Frameworks.dll': ('bdef879f0a4ab2ad97fe934f54e30aee0d06ad06a3ef292933308fca34906ef8', '42a8779499c1d1ed2488c2e6b9e2ee6ff6107766'),
    'contentFiles/any/net6.0/TestHost/NuGet.Frameworks.dll': ('bdef879f0a4ab2ad97fe934f54e30aee0d06ad06a3ef292933308fca34906ef8', '42a8779499c1d1ed2488c2e6b9e2ee6ff6107766'),
    'contentFiles/any/net6.0/Microsoft.Extensions.FileSystemGlobbing.dll': ('d485cef178eb4e1a64a2d13fae4c5744d99b4cc429b063e9cf39a6d66d12b713', '96bf83a6c1ab6f6801130150c27282c49030c8e1'),
    'contentFiles/any/net6.0/Microsoft.Extensions.DependencyModel.dll': ('6ef18888f38be6a6203819bd96fca64101a5176ad5e0cf803558a550272383cb', 'ee54d4cbd2b305eadf6f341bdc9d4abccdb50559')}


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 compiler evidence file required')
    return path


def retain(release, source, name):
    source = ordinary(source); target = Path(release) / portable(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    require(not any(p.is_symlink() for p in (target, *target.parents)), 'Redirected SDK6 retained evidence')
    if target.exists(): require(fingerprint(target) == fingerprint(source), 'Retained SDK6 compiler evidence differs')
    elif target != source: shutil.copyfile(source, target)
    return dict(path=name, **fingerprint(target))


def write(release, name, value):
    target = Path(release) / portable(name); target.parent.mkdir(parents=True, exist_ok=True)
    require(not any(p.is_symlink() for p in (target, *target.parents)), 'Redirected SDK6 compiler record')
    raw = (json.dumps(value, indent=2) + '\n').encode()
    require(not target.exists() or target.read_bytes() == raw, 'Refusing to overwrite different SDK6 compiler evidence')
    if not target.exists(): target.write_bytes(raw)
    return dict(path=name, **fingerprint(target))


def absolute(value, project, mount):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n'), 'Ordinary actual compiler path required')
    result = posixpath.normpath(value if value.startswith('/') else posixpath.join(posixpath.dirname(project), value))
    require(result.startswith(mount + '/'), 'Actual SDK6 compiler output escaped its source mount')
    return result


def commands(task):
    found = list(dict.fromkeys(e['text'] for e in task['events'] if e['kind'] == 'command-line' and e.get('text')))
    require(len(found) == 1, 'One actual executed SDK6 compiler command required')
    return shlex.split(found[0])


def compiler_rows(tasks, mount):
    require(isinstance(mount, str) and mount.startswith('/') and mount == posixpath.normpath(mount)
            and not any(c in mount for c in '\\\0\r\n'), 'Exact SDK6 compiler source mount required')
    result = []
    for task in tasks.values():
        if task['taskName'] not in {'Csc', 'Fsc'} or task['succeeded'] is not True or not task['projectFile'].startswith(mount + '/'): continue
        skipped = B.task_values(task, 'SkipCompilerExecution')
        if any(value.lower() == 'true' for value in skipped): continue
        require(all(value.lower() == 'false' for value in skipped), 'Unknown SDK6 compiler execution condition')
        # Source-less template sanity tasks do not establish a shipping product.
        if not B.task_values(task, 'Sources'): continue
        argv = commands(task)
        primary = {absolute(p, task['projectFile'], mount) for p in B.task_values(task, 'OutputAssembly')}
        observed = {}
        for key, kind in [('out', 'assembly'), ('refout', 'reference-assembly')]:
            values = [token.split(':', 1)[1] for token in argv if token.lower().startswith(('/' + key + ':', '-' + key + ':'))]
            require(len(values) <= 1, 'Ambiguous actual SDK6 compiler output argument')
            if values: observed[kind] = (absolute(values[0], task['projectFile'], mount), '/' + key + ':' + values[0])
        require('assembly' in observed and primary == {observed['assembly'][0]}, 'Actual SDK6 compiler command and OutputAssembly disagree')
        recorded_refs = {absolute(p, task['projectFile'], mount) for p in B.task_values(task, 'OutputRefAssembly') if p}
        require(not recorded_refs or ('reference-assembly' in observed and recorded_refs == {observed['reference-assembly'][0]}),
                'Actual SDK6 recorded reference scalar and command disagree')
        for kind, (path, argument) in observed.items():
            result.append(dict(context=task['context'], outputPath=path, outputKind=kind, commandParameter=argument))
    require(result, 'Successful source-bearing SDK6 compiler tasks required')
    return result


def validate_crossgen_task(row, replay, tasks, record):
    """SDK6's original installer must use native musl Crossgen2 6.0.36."""
    task = tasks[row['context']]; source = replay['sourceMountRoot']
    require(record['sdkVersion'] == SDK and task['succeeded'] is True and task['taskName'] == row['task'] == 'Crossgen'
            and task['projectFile'] == source + '/src/redist/redist.csproj'
            and task['taskFile'] == source + '/src/redist/targets/Crossgen.targets', 'Original SDK6 installer Crossgen task required')
    expected = source + '/artifacts/bin/redist/Release/dotnet/' + portable(row['archivePath'])
    arch = 'arm64' if record['architecture'] == 'aarch64' else 'x64'
    require(row['inputPath'] == row['outputPath'] == expected
            and B.task_values(task, 'SourceAssembly') == B.task_values(task, 'DestinationPath') == {expected}
            and B.task_values(task, 'ReadyToRun') == {'True'} and B.task_values(task, 'Architecture') == {arch},
            'Actual SDK6 ReadyToRun input/output/native architecture differs')
    compiler = B.task_values(task, 'CrossgenPath'); require(len(compiler) == 1, 'One actual SDK6 native Crossgen2 compiler required')
    compiler = next(iter(compiler)); pattern = re.escape(source) + r'/\.packages(?:/[^/]+)*//?microsoft\.netcore\.app\.crossgen2\.' + re.escape(record['targetRid'])
    require(re.fullmatch(pattern + r'/6\.0\.36/tools/crossgen2', compiler), 'SDK6 must consume its matching native musl6.0.36 Crossgen2 package')
    calls = [shlex.split(e['text'].removeprefix('> ')) for e in task['events'] if e['kind'] == 'command-line']
    require(len(calls) == 1 and calls[0][:2] == [compiler, expected] and calls[0].count('-o') == calls[0].count('--targetarch') == 1
            and calls[0][calls[0].index('--targetarch') + 1] == arch
            and PurePosixPath(calls[0][calls[0].index('-o') + 1]).name == PurePosixPath(expected).name,
            'Actual SDK6 Crossgen2 command does not bind its transformed input/output')


def expected_packages(component, packages, *, retained=False):
    require(component in COMMITS, 'Unreviewed SDK6 compiler component')
    result = []
    for package in packages:
        path = ordinary(package)
        if component == 'sdk':
            require(retained or path.name == 'dotnet-toolset-internal-' + VERSIONS['sdk'] + '.zip', 'Exact genuine SDK6 tooling ZIP required')
            result.append((path, 'dotnet-toolset-internal')); continue
        metadata = B.nuspec_metadata(path); name = metadata.findtext('{*}id'); version = metadata.findtext('{*}version')
        require(version == VERSIONS[component], 'Original SDK6 component package version differs')
        repository = metadata.find('{*}repository')
        if component == 'nuget':
            require(name.lower() in NUGET_PACKAGES and repository is not None
                    and repository.get('url') == 'https://github.com/NuGet/NuGet.Client'
                    and repository.get('commit') in (None, COMMITS[component]), 'Original NuGet6 package/source declaration differs')
            license_node = metadata.find('{*}license')
            require(license_node is not None and license_node.get('type') == 'expression' and license_node.text == 'Apache-2.0',
                    'Original NuGet6 package license differs')
        else:
            require(name in VSTEST_PACKAGES and repository is not None and repository.get('commit') == COMMITS[component],
                    'Original VSTest6 source package declaration differs')
        result.append((path, name))
    ids = [name.lower() for _, name in result]
    expected = {'dotnet-toolset-internal'} if component == 'sdk' else NUGET_PACKAGES if component == 'nuget' else {s.lower() for s in VSTEST_PACKAGES}
    require(len(ids) == len(expected) and set(ids) == expected, 'Complete unique original SDK6 component package set required')
    return result


def emit(component, context, release, roots):
    """Capture completed replay and bind only exact current compiler output bytes."""
    require(context['sdkVersion'] == SDK and component in COMMITS, 'Unreviewed SDK6 compiler evidence route')
    release = Path(release).absolute(); source = Path(roots[component]['path']).absolute()
    require(roots[component].get('kind', 'git') == 'git' and roots[component]['commit'] == COMMITS[component]
            and subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == COMMITS[component],
            'Exact SDK6 component compiler checkout required')
    entry = context[component + 'Replay']; status = json.loads(ordinary(entry['status']).read_bytes())
    require(status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks', 0) == 0, 'Complete successful original SDK6 replay required')
    binlog = retain(release, entry['binlog'], 'reports/build/' + component + '.binlog')
    require(status['inputSha256'] == binlog['sha256'], 'SDK6 replay differs from its completed binary log')
    tasks_desc = retain(release, entry['tasks'], 'reports/build/' + component + '-tasks.jsonl')
    rows = compiler_rows(B.read_tasks(release / tasks_desc['path']), entry['sourceMountRoot']); by_sha = {}
    for row in rows:
        local = ordinary(source.joinpath(*PurePosixPath(row['outputPath']).relative_to(entry['sourceMountRoot']).parts))
        by_sha.setdefault(fingerprint(local)['sha256'], []).append(row)
    paths = [context['toolsetZip']] if component == 'sdk' else context[component + 'Packages']
    outputs, imports, records = [], [], []
    for path, package_id in expected_packages(component, paths):
        descriptor = retain(release, path, 'imported-inputs/' + fingerprint(path)['sha256'] + ('.zip' if component == 'sdk' else '.nupkg'))
        records.append(dict(id=package_id, file=path.name, version=VERSIONS[component], sourceCommit=COMMITS[component], **descriptor))
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if not member.lower().endswith(('.dll', '.exe')): continue
                raw = archive.read(member)
                if raw[:2] != b'MZ': continue
                identity = B.MANAGED.inspect(raw); sha = hashlib.sha256(raw).hexdigest()
                matches = [r for r in by_sha.get(sha, []) if PurePosixPath(r['outputPath']).name == PurePosixPath(member).name]
                if component == 'vstest' and member in VSTEST_IMPORTS:
                    require((sha, B.embedded_component_commit(identity)) == VSTEST_IMPORTS[member], 'Original VSTest6 imported dependency differs')
                    imports.append(dict(packagePath=descriptor['path'], member=member, sha256=sha, sourceCommit=VSTEST_IMPORTS[member][1])); continue
                if not matches:
                    require(component == 'sdk', 'Source-built SDK6 component member has no actual compiler output: ' + member)
                    continue
                row = sorted(matches, key=lambda r: (r['outputKind'] != 'assembly', r['context']))[0]
                outputs.append(dict(packagePath=descriptor['path'], member=member, sourceRoot=component,
                    sourceCommit=COMMITS[component], fingerprint=dict(bytes=len(raw), sha256=sha, sha512=hashlib.sha512(raw).hexdigest()), **row))
    if component == 'nuget': require(len(outputs) == 72 and not imports, 'All72 original NuGet6 library members require compiler provenance')
    if component == 'vstest': require(len(outputs) == 304 and len(imports) == 6 and sum(r['outputKind'] == 'reference-assembly' for r in outputs) == 3,
        'Original Core VSTest6 requires304 compiler-bound members, including3 references, and6 original imports')
    if component == 'sdk': require(len(outputs) == 190 and sum(r['outputKind'] == 'reference-assembly' for r in outputs) == 9,
        'Original SDK6 tooling graph requires181 ordinary and9 real reference outputs')
    proof = dict(schemaVersion=1, kind='sdk6-component-compiler-proof', sdkVersion=SDK, component=component,
        sourceCommit=COMMITS[component], completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
        binlog=binlog, tasks=tasks_desc, sourceMountRoot=entry['sourceMountRoot'], packages=records,
        compiledOutputs=outputs, importedMembers=imports, transformations=[])
    descriptor = write(release, 'reports/build/' + component + '-compiler-proof.json', proof)
    validate(release, descriptor, roots)
    return descriptor


def validate(release, descriptor, roots):
    """Reparse original task events and package bytes independently of emitter rows."""
    release = Path(release); proof = json.loads(B.checked(release, descriptor).read_bytes()); component = proof['component']
    require(proof.get('schemaVersion') == 1 and proof.get('kind') == 'sdk6-component-compiler-proof'
            and proof.get('sdkVersion') == SDK and component in COMMITS and proof.get('sourceCommit') == COMMITS[component]
            and roots[component].get('kind', 'git') in ('git', 'git-export') and roots[component]['commit'] == COMMITS[component]
            and proof.get('completedReplay') is True and proof.get('buildSucceeded') is True and proof.get('unfinishedTasks') == 0
            and proof.get('transformations') == [], 'Closed SDK6 component compiler/source proof required')
    B.checked(release, proof['binlog']); tasks = B.read_tasks(B.checked(release, proof['tasks']))
    observed = compiler_rows(tasks, proof['sourceMountRoot']); by_key = {(r['context'], r['outputPath'], r['outputKind'], r['commandParameter']) for r in observed}
    packages = {}; wanted = {}; imported = {}
    originals = expected_packages(component, [B.checked(release, {k: row[k] for k in ('path', *FP)}) for row in proof['packages']], retained=True)
    for (path, package_id), record in zip(originals, proof['packages']):
        require(set(record) == {'id', 'file', 'version', 'sourceCommit', 'path', *FP}
                and record['id'] == package_id and record['version'] == VERSIONS[component] and record['sourceCommit'] == COMMITS[component]
                and record['file'] == ('dotnet-toolset-internal-' + VERSIONS['sdk'] + '.zip' if component == 'sdk'
                    else package_id + '.' + VERSIONS[component] + '.nupkg'), 'SDK6 package record/source differs')
        packages[record['path']] = record
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.lower().endswith(('.dll', '.exe')): continue
                raw = archive.read(name)
                if raw[:2] != b'MZ': continue
                metadata = B.MANAGED.inspect(raw); fp = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
                key = (record['path'], name)
                if component == 'vstest' and name in VSTEST_IMPORTS:
                    require((fp['sha256'], B.embedded_component_commit(metadata)) == VSTEST_IMPORTS[name], 'Original VSTest6 imported dependency/source differs')
                    imported[key] = fp['sha256']; continue
                if component != 'sdk' or B.embedded_component_commit(metadata) == COMMITS['sdk']:
                    wanted[key] = fp
                elif any(r['packagePath'] == record['path'] and r['member'] == name for r in proof['compiledOutputs']): wanted[key] = fp
    actual = {}
    for row in proof['compiledOutputs']:
        require(set(row) == {'packagePath', 'member', 'sourceRoot', 'sourceCommit', 'fingerprint', 'context', 'outputPath', 'outputKind', 'commandParameter'}
                and row['sourceRoot'] == component and row['sourceCommit'] == COMMITS[component]
                and (row['context'], row['outputPath'], row['outputKind'], row['commandParameter']) in by_key
                and PurePosixPath(row['outputPath']).name == PurePosixPath(row['member']).name,
                'SDK6 compiled product lacks its exact actual output command and source context')
        task = tasks[row['context']]
        expected_compiler = '/sdk/6.0.135/Roslyn/Microsoft.CSharp.Core.targets'
        resource_compiler = '/sdk/6.0.135/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.targets'
        require(task['taskFile'].endswith(expected_compiler)
                or (row['member'].endswith('.resources.dll') and task['taskFile'].endswith(resource_compiler)),
                'SDK6 compiler task must come from its exact trusted6.0.135 bootstrap targets')
        key = (row['packagePath'], portable(row['member']))
        require(key not in actual and wanted.get(key) == row['fingerprint'], 'SDK6 compiler output package/member bytes differ')
        actual[key] = row['fingerprint']
    require(actual == wanted and len(actual) == {'sdk': 190, 'nuget': 72, 'vstest': 304}[component], 'Complete original SDK6 compiled product coverage required')
    require(sum(r['outputKind'] == 'reference-assembly' for r in proof['compiledOutputs']) == {'sdk': 9, 'nuget': 0, 'vstest': 3}[component], 'Actual SDK6 reference-output coverage differs')
    rows = proof['importedMembers']
    require(len(rows) == len(imported) and {(r['packagePath'], r['member']): r['sha256'] for r in rows} == imported
            and all(r['sourceCommit'] == VSTEST_IMPORTS[r['member']][1] for r in rows), 'Original imported component scope differs')
    return dict(proof=proof, packages=packages, members=actual, imports=imported)
