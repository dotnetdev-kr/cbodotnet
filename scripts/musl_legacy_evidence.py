"""Construct legacy source evidence from observed builds and unchanged inputs.

The producer supplies ordinary source/input paths and completed private-SDK
binary-log replays. This module never executes the produced SDK. Unknown layout
or managed-source origins stay explicit and cannot pass the admission gate.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


A = module('legacy_evidence_pure_contract', 'musl_legacy_admission.py')
W = module('legacy_literal_manifest_contract', 'musl_legacy_manifest_inputs.py')
MS = module('legacy_msbuild_resource_contract', 'musl_legacy_msbuild_resources.py')
F = module('legacy_literal_facade_contract', 'musl_legacy_facade_inputs.py')
FI = module('legacy_framework_implementation_contract', 'musl_legacy_framework_il_inputs.py')
C = module('legacy_closed_component_contract', 'musl_legacy_attributed_components.py')
require, fingerprint, members = A.require, A.fingerprint, A.members


def load(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'Redirected construction evidence is forbidden')
    raw = (json.dumps(value, indent=2) + '\n').encode()
    require(not path.exists() or path.read_bytes() == raw, 'Refusing to overwrite different construction evidence')
    path.write_bytes(raw)


def scalar(task, name):
    values = []
    for event in task['events']:
        if event['kind'] == 'task-parameter' and event.get('field') == name:
            values.append(event['text'])
        if event['kind'] == 'message':
            match = re.fullmatch(r'Task Parameter:' + re.escape(name) + r'=(.*)', event.get('text') or '')
            if match: values.append(match.group(1))
    values = list(dict.fromkeys(values))
    require(len(values) <= 1, 'Ambiguous observed scalar task parameter: ' + name)
    return values[0] if values else None


def normalized(path):
    require(isinstance(path, str) and path.startswith('/') and not any(c in path for c in '\\\0\r\n'),
            'An absolute ordinary Linux build path is required')
    return posixpath.normpath(path)


def translated(path, mount, host):
    path, mount = normalized(path), normalized(mount)
    require(path.startswith(mount + '/'), 'Observed output escaped its source mount')
    relative = PurePosixPath(path).relative_to(mount)
    result = Path(host).joinpath(*relative.parts)
    require(result.is_file() and not any(item.is_symlink() for item in (result, *result.parents)),
            'Observed build output is missing or redirected')
    return result


def retained(release, source, relative):
    source = Path(source); target = release / A.portable(relative)
    require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)), 'Ordinary retained input required')
    target.parent.mkdir(parents=True, exist_ok=True)
    require(not any(item.is_symlink() for item in (target, *target.parents)), 'Redirected retained input is forbidden')
    if target.exists(): require(fingerprint(target) == fingerprint(source), 'Retained construction input differs')
    elif source != target: shutil.copyfile(source, target)
    return dict(path=relative, **fingerprint(target))


def snapshot(release, relative, layout, names):
    path = release / relative
    require(not path.exists(), 'Fresh construction snapshot required')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as archive:
        for name in sorted(names):
            source = Path(layout).joinpath(*PurePosixPath(name).parts)
            require(source.is_file() and not any(item.is_symlink() for item in (source, *source.parents)),
                    'Ordinary observed installer layout file required')
            info = tarfile.TarInfo(name); info.size = source.stat().st_size; info.mode = 0o644
            with source.open('rb') as data: archive.addfile(info, data)
    return dict(path=relative, **fingerprint(path))


def package_inputs(context, release, roots, needed, built_packages=()):
    if not context.get('restoredInputs'): return {}, {}, []
    source_index = Path(context['restoredInputs'])
    data = load(source_index)
    built = {row['sha256'] for row in built_packages}
    rebuilt_roots = {row['sha256']: ('vstest' if row.get('origin') == 'rebuilt-original-vstest-source-build-core-distribution' else 'nuget')
                     for row in built_packages}
    manifests = {row['fingerprint']['sha256']: row for row in W.policy()}
    commits = {root['commit']: name for name, root in roots.items() if root.get('kind', 'git') == 'git'}
    records, packages, index = [], {}, {}
    for record in data['packages']:
        relative = A.portable(record['retained'])
        original = release / relative
        if not original.is_file(): original = source_index.parent / relative
        fp = fingerprint(original)
        require(all(record[key] == fp[key] for key in fp), 'Actual retained package input differs')
        destination = 'imported-inputs/' + fp['sha256'] + '.nupkg'
        retained(release, original, destination)
        records.append(dict(record, retained=destination))
        if destination in packages: continue
        with zipfile.ZipFile(original) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith('.nuspec')]
            require(len(names) == 1, 'One actual package nuspec is required')
            raw = archive.read(names[0])
            require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe actual package metadata')
            metadata = ET.fromstring(raw).find('{*}metadata')
            repository = metadata.find('{*}repository')
            commit = repository.get('commit') if repository is not None else None
            source_root = commits.get(commit)
            source_kind = 'managed-package'
            if not commit and fp['sha256'] in built and repository is not None and repository.get('url', '').rstrip('/').removesuffix('.git') == 'https://github.com/NuGet/NuGet.Client':
                source_root = 'nuget'
            if fp['sha256'] in rebuilt_roots and rebuilt_roots[fp['sha256']] == 'vstest':
                source_root = 'vstest'
            if not source_root and fp['sha256'] == A.NETSTANDARD21['sha256']:
                matches = [name for name, root in roots.items() if root.get('commit') == A.NETSTANDARD21['packagingCommit']]
                if len(matches) == 1:
                    A.reviewed_netstandard_identity(original, A.NETSTANDARD21['packagingCommit'])
                    source_root = matches[0]
            if fp['sha256'] == A.CSS_PARSER['sha256']:
                A.reviewed_css_identity(original, A.CSS_PARSER['sourceCommit'])
                source_root = commits.get(A.CSS_PARSER['sourceCommit'])
            if fp['sha256'] == A.GLOBBING_INPUTS.PACKAGE_SHA:
                A.reviewed_globbing_identity(original, A.GLOBBING_INPUTS.COMMIT)
                source_root = commits.get(A.GLOBBING_INPUTS.COMMIT)
            if fp['sha256'] in C.policy()['packageSourceExceptions']:
                component_commit = C.package_source_commit(original)
                require(component_commit in commits, 'Reviewed original Elfie preferred Git source is required')
                source_root = commits[component_commit]
            if fp == MS.PACKAGE and MS.ROOT_NAME in roots:
                require(roots[MS.ROOT_NAME]['kind'] == 'tree' and roots[MS.ROOT_NAME].get('commit') is None
                        and roots[MS.ROOT_NAME].get('role') == MS.ROLE, 'Original MSBuild resource data source role differs')
                MS.inspect(original)
                source_root = commits.get(MS.COMMIT)
            if fp['sha256'] in manifests and W.ROOT_NAME in roots:
                W.inspect(original)
                require(roots[W.ROOT_NAME]['kind'] == 'tree' and roots[W.ROOT_NAME].get('commit') is None
                        and roots[W.ROOT_NAME].get('role') == W.ROLE, 'Literal manifest input source role differs')
                source_root, source_kind = W.ROOT_NAME, W.KIND
            package = dict(path=destination, id=metadata.findtext('{*}id'), version=metadata.findtext('{*}version'),
                sourceRoot=source_root, sourceCommit=roots[source_root].get('commit') if source_root else commit,
                kind=source_kind,
                rebuiltSourceRoot=rebuilt_roots.get(fp['sha256']),
                repository=repository.attrib if repository is not None else None,
                locallyRebuilt=fp['sha256'] in built, fingerprint=fp)
            packages[destination] = package
        inventory = members(original, 'managed-package')
        package['inventory'] = inventory
        for member, identity in inventory.items():
            if identity['sha256'] in needed:
                index.setdefault(identity['sha256'], []).append(dict(package=package, member=member, identity=identity))
        if fp['sha256'] in needed:
            index.setdefault(fp['sha256'], []).append(dict(package=package, member=None, identity=dict(fp, signature='504b0304')))
    target = release / 'reports/restored-inputs.json'
    if target.exists():
        require(load(target)['packages'] == records, 'Producer actual restored-input records must remain unchanged')
    else:
        write(target, dict(schemaVersion=1, packages=records,
              scope='Unchanged actual package cache inputs; original source/metadata retained without publisher relabeling'))
    return packages, index, built_packages


def retain_directory(release, source, relative):
    source = Path(source)
    require(source.is_dir() and not source.is_symlink(), 'Ordinary construction evidence directory required')
    for path in sorted(source.rglob('*')):
        require(not path.is_symlink(), 'Linked construction evidence is forbidden')
        if path.is_file():
            retained(release, path, relative + '/' + path.relative_to(source).as_posix())


def snapshot_files(release, relative, files):
    path = release / relative
    require(files and not path.exists(), 'Fresh nonempty construction input snapshot required')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as archive:
        for name, source in sorted(files.items()):
            source = Path(source)
            require(source.is_file() and not any(item.is_symlink() for item in (source, *source.parents)),
                    'Ordinary observed construction input required')
            info = tarfile.TarInfo(A.portable(name)); info.size = source.stat().st_size; info.mode = 0o644
            with source.open('rb') as data: archive.addfile(info, data)
    return dict(path=relative, **fingerprint(path))


def generated_outputs(actual, replay, tasks, context, roots):
    allowed = {'WriteLinesToFile', 'GenerateBundledVersions', 'GenerateRuntimeGraph', 'GenerateDepsFile',
               'GenerateRuntimeConfigurationFiles', 'GenerateSdkRuntimeIdentifierChain', 'CalculateTemplateVersions',
               'CollatePackageDownloads', 'UpdateRuntimeConfig', 'GenerateDefaultRuntimeFrameworkVersion',
               'GetDependencyInfo', 'ReplaceFileContents', 'ResolveAssemblyReference'}
    layout_mount = normalized(context['installerLayoutMount'])
    result, order = {}, {}
    for task in tasks.values():
        if task['taskName'] not in allowed or not task['succeeded']: continue
        if task['projectFile'] != replay['sourceMountRoot'] + '/src/redist/redist.csproj': continue
        if not task['taskFile'].startswith(replay['sourceMountRoot'] + '/src/redist/targets/'): continue
        fields = {event['field'] for event in task['events'] if event['kind'] == 'task-parameter'}
        fields.update(match.group(1) for event in task['events'] if event['kind'] == 'message'
                      for match in [re.fullmatch(r'Task Parameter:([^=\r\n]+)=([^\r\n]*)', event.get('text') or '')] if match)
        for field in fields:
            for path in A.task_values(task, field):
                if not isinstance(path, str) or not path.startswith(layout_mount + '/') or '\n' in path: continue
                path = normalized(path); name = path[len(layout_mount) + 1:]
                if name not in actual or name.lower().endswith(('.dll', '.exe', '.nupkg')): continue
                if actual[name]['signature'].startswith(('4d5a', '7f454c46', '504b0304')): continue
                source = translated(path, replay['sourceMountRoot'], roots['installer']['path'])
                if fingerprint(source)['sha256'] != actual[name]['sha256']: continue
                if task['taskName'] == 'ResolveAssemblyReference' and (field != 'AssemblyInformationCacheOutputPath'
                        or name != 'sdk/' + context['sdkVersion'] + '/SDKPrecomputedAssemblyReferences.cache'): continue
                end = task['events'][-1]['eventNumber']
                if name in order and order[name] >= end: continue
                result[name] = dict(archivePath=name, sha256=actual[name]['sha256'], task=task['taskName'],
                    sourceRoot='installer', sourceCommit=roots['installer']['commit'], context=task['context'], outputPath=path)
                order[name] = end
    return result


def emit(context):
    version, arch = context['sdkVersion'], context['architecture']
    require(version == '7.0.120' and arch in ('x64', 'aarch64'), 'Unreviewed legacy construction emitter route')
    release = Path(context['releaseDir']).absolute(); release.mkdir(parents=True, exist_ok=True)
    roots = context['sourceRoots']
    for name, root in roots.items():
        if root.get('kind', 'git') != 'git': continue
        actual = subprocess.check_output(['git', '-c', 'safe.directory=' + root['path'], '-C', root['path'], 'rev-parse', 'HEAD'], text=True).strip()
        require(actual == root['commit'], 'Construction source root commit differs: ' + name)
    sdk_path = Path(context['sdkArchive']); sdk_desc = retained(release, sdk_path, sdk_path.name)
    actual = members(release / sdk_desc['path'], 'sdk')
    prefix = 'sdk/' + version + '/'
    artifacts, inventories = {}, {}

    def add(name, kind, path, source_root, destination=None):
        require(name not in artifacts and roots[source_root].get('commit'), 'Unique Git-bound construction input required')
        descriptor = retained(release, path, destination or ('reports/construction-inputs/' + name + Path(path).suffix))
        artifacts[name] = dict(descriptor, kind=kind, sourceRoot=source_root, sourceCommit=roots[source_root]['commit'])
        inventories[name] = members(release / descriptor['path'], kind)

    for name, kind, field, source_root in [('toolset', 'sdk-toolset', 'toolsetZip', 'sdk'),
        ('runtime', 'official-runtime', 'runtimeArchive', 'runtime'), ('aspnet', 'official-aspnet', 'aspnetArchive', 'aspnetcore'),
        ('trace', 'native-trace', 'traceFile', 'runtime')]: add(name, kind, context[field], source_root)
    if context.get('nativeRuntimeDir'):
        native = Path(context['nativeRuntimeDir'])
        retain_directory(release, native, 'reports/build/native-runtime')
        native_result = load(native / 'results.json')
        require(native_result['status'] == 'passed' and native_result['sdkVersion'] == version
                and native_result['architecture'] == arch and native_result['sourceCommit'] == roots['runtime']['commit']
                and {row['path'] for row in native_result['shippingFiles']} == set(A.NATIVE_CORECLR),
                'Actual complete matching native runtime construction is required')
        for filename in A.NATIVE_CORECLR:
            add('native-coreclr-' + filename, 'native-coreclr', native / filename, 'runtime',
                'reports/build/native-runtime/' + filename)
    if context.get('originalSdkComparison'):
        add('original-sdk-comparison', 'official-sdk-comparison', context['originalSdkComparison'], 'installer',
            'reports/construction-inputs/original-sdk-comparison.tar.gz')
    unknowns = []
    replays, tasks = {}, {}
    for name in ('sdk', 'installer'):
        entry = context[name + 'Replay']; status = load(entry['status'])
        require(status['completedReplay'] is True and status['buildSucceeded'] is True
                and status['unfinishedTasks'] == status.get('unfinishedSelectedTasks', 0) == 0,
                'Actual complete successful binary-log replay required')
        log = retained(release, entry['binlog'], 'reports/build/' + name + '.binlog')
        require(status['inputSha256'] == log['sha256'], 'Replayed binary-log identity differs')
        raw = retained(release, entry['tasks'], 'reports/build/' + name + '-tasks.jsonl')
        tasks[name] = A.read_tasks(release / raw['path'])
        replays[name] = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
            inputSha256=log['sha256'], tasks=raw, sourceMountRoot=normalized(entry['sourceMountRoot']),
            compiledOutputs=[], transformations=[], generatedOutputs=[])
    toolset = inventories['toolset']
    compiled = {}
    for task in tasks['sdk'].values():
        if task['taskName'] not in ('Csc', 'Fsc') or not task['succeeded']: continue
        path = scalar(task, 'OutputAssembly')
        if not path or (scalar(task, 'SkipCompilerExecution') or '').lower() == 'true': continue
        if not task['projectFile'].startswith(replays['sdk']['sourceMountRoot'] + '/src/'): continue
        output = translated(path, replays['sdk']['sourceMountRoot'], roots['sdk']['path'])
        sha = fingerprint(output)['sha256']
        for name, identity in toolset.items():
            full = prefix + name
            if full in actual and identity['sha256'] == sha and PurePosixPath(name).name == output.name:
                row = dict(archivePath=full, member=name, sha256=sha, sourceRoot='sdk', sourceCommit=roots['sdk']['commit'],
                           context=task['context'], outputPath=path)
                require(full not in compiled or compiled[full]['sha256'] == sha, 'Conflicting original SDK compiler outputs')
                compiled[full] = row
    replays['sdk']['compiledOutputs'] = list(compiled.values())
    transformed = {}
    layout_mount = normalized(context['installerLayoutMount'])
    for task in tasks['installer'].values():
        if task['taskName'] != 'Crossgen' or not task['succeeded']: continue
        source, output = scalar(task, 'SourceAssembly'), scalar(task, 'DestinationPath')
        if not source or not output: continue
        source, output = normalized(source), normalized(output)
        require(source.startswith(layout_mount + '/') and output.startswith(layout_mount + '/'), 'Crossgen output escaped installer layout')
        name = output[len(layout_mount) + 1:]
        if not name.startswith(prefix): continue
        member = name[len(prefix):]
        require(member in toolset and name in actual, 'Crossgen lacks its exact source-built toolset member')
        if actual[name]['sha256'] == toolset[member]['sha256']: continue
        row = dict(archivePath=name, input='toolset', member=member, inputSha256=toolset[member]['sha256'],
            outputSha256=actual[name]['sha256'], task='Crossgen', context=task['context'], inputPath=source, outputPath=output)
        A.validate_crossgen_task(row, replays['installer'], tasks['installer'], dict(sdkVersion=version, architecture=arch,
            targetRid='linux-musl-' + ('arm64' if arch == 'aarch64' else 'x64')))
        require(name not in transformed, 'A final SDK member has multiple Crossgen producers')
        transformed[name] = row
    replays['installer']['transformations'] = list(transformed.values())
    if transformed:
        descriptor = snapshot(release, 'reports/construction-inputs/post-crossgen.tar.gz', context['installerLayout'], transformed)
        artifacts['post-crossgen'] = dict(descriptor, kind='post-crossgen-sdk', sourceRoot='installer', sourceCommit=roots['installer']['commit'])
        inventories['post-crossgen'] = members(release / descriptor['path'], 'post-crossgen-sdk')
    generated = generated_outputs(actual, replays['installer'], tasks['installer'], context, roots)
    replays['installer']['generatedOutputs'] = list(generated.values())
    if generated:
        descriptor = snapshot(release, 'reports/construction-inputs/generated-installer-data.tar.gz', context['installerLayout'], generated)
        artifacts['generated'] = dict(descriptor, kind='generated-installer-data', sourceRoot='installer', sourceCommit=roots['installer']['commit'])
        inventories['generated'] = members(release / descriptor['path'], 'generated-installer-data')
    translations = {}
    if context.get('translationDataDir'):
        directory = Path(context['translationDataDir'])
        origin = load(directory / 'origin.json')
        require(origin['sdkVersion'] == version and origin['architecture'] == arch
                and origin['sourceCommit'] == roots['nuget']['commit'], 'Translation input identity differs')
        retain_directory(release, directory, 'reports/build/nuget-translation-data')
        files = {}
        for row in origin['files']:
            source = directory / 'resources' / A.portable(row['path'])
            require(row['sdkMember'] == prefix + row['path'] and all(row[key] == fingerprint(source)[key] for key in A.FP),
                    'Actual imported resource-only input differs')
            if row['sdkMember'] not in actual: continue
            require(all(actual[row['sdkMember']][key] == row[key] for key in ('bytes', 'sha256')), 'Translation input was not consumed unchanged')
            files[row['sdkMember']] = source
            translations[row['sdkMember']] = row
        descriptor = snapshot_files(release, 'reports/construction-inputs/nuget-translation-data.tar.gz', files)
        artifacts['translations'] = dict(descriptor, kind='nuget-translation-data', sourceRoot='nuget', sourceCommit=roots['nuget']['commit'])
        inventories['translations'] = members(release / descriptor['path'], 'nuget-translation-data')
    nuget = module('legacy_nuget_product_evidence', 'musl_legacy_nuget_evidence.py').emit(context, release, roots)
    vstest = (module('legacy_vstest_product_evidence', 'musl_legacy_vstest_evidence.py').emit(context, release, roots)
              if context.get('vstestReplay') else None)
    vstest_products = ({(row['packagePath'], row['member']): row['sha256']
                       for row in load(release / vstest['replay']['path'])['compiledOutputs']} if vstest else {})
    needed = {row['sha256'] for row in actual.values()} | {row['inputSha256'] for row in transformed.values()}
    packages, package_index, _ = package_inputs(context, release, roots, needed,
        nuget['builtPackages'] + (vstest['builtPackages'] if vstest else []))
    facade_rows, facade_primary = {}, None
    if F.ROOT_NAME in roots:
        require(roots[F.ROOT_NAME]['kind'] == 'tree' and roots[F.ROOT_NAME].get('commit') is None
                and roots[F.ROOT_NAME].get('role') == F.ROLE, 'Literal type-forwarder source role differs')
        primary_fp = F.policy()['package']['fingerprint']
        primary = [row for row in packages.values() if row['fingerprint'] == primary_fp]
        require(len(primary) == 1, 'One actually restored immutable primary facade input required')
        facade_primary = primary[0]
        F.package_bodies(release / facade_primary['path'])
        facade_rows = {row['path']: row for row in F.policy()['layout']}
    framework_rows, framework_primary, framework_source = {}, None, None
    if FI.ROOT_NAME in roots:
        require(roots[FI.ROOT_NAME]['kind'] == 'tree' and roots[FI.ROOT_NAME].get('commit') is None
                and roots[FI.ROOT_NAME].get('role') == FI.ROLE, 'Preferred framework IL/resource input source role differs')
        primary = [row for row in packages.values() if row['fingerprint'] == FI.policy()['package']['fingerprint']]
        source = [name for name, row in roots.items() if row.get('kind') in ('git', 'git-export') and row.get('commit') == FI.COMMIT]
        require(len(primary) == len(source) == 1, 'Actual original SDK-copy package and preferred IL Git source required')
        framework_primary, framework_source = primary[0], source[0]
        framework_rows = {row['path']: row for row in FI.policy()['layout']}

    def candidates(name, sha):
        matches = [row for row in package_index.get(sha, []) if row['package']['sourceRoot']
                   and ((row['member'] is None and name.lower().endswith('.nupkg')) or
                        (row['member'] is not None and PurePosixPath(row['member']).name == PurePosixPath(name).name))]
        return sorted(matches, key=lambda row: (not row['package']['locallyRebuilt'], row['package']['path'], row['member'] or ''))

    def use_package(row):
        package = row['package']; key = 'package-' + package['fingerprint']['sha256']
        if key not in artifacts:
            artifacts[key] = dict(path=package['path'], **package['fingerprint'], kind=package['kind'],
                sourceRoot=package['sourceRoot'], sourceCommit=package['sourceCommit'])
            inventories[key] = dict(package['inventory'])
            if package['kind'] == 'managed-package':
                with (release / package['path']).open('rb') as stream: signature = stream.read(4).hex()
                inventories[key][''] = dict((field, package['fingerprint'][field]) for field in ('bytes', 'sha256'))
                inventories[key]['']['signature'] = signature
        return key

    component_roots = {}
    for key, root in roots.items():
        if root.get('kind', 'git') in ('git', 'git-export') and root.get('commit'):
            component_roots.setdefault(root['commit'], []).append(key)

    def shipping_row(name, match):
        package = match['package']
        origin = ('rebuilt-nuget' if package['rebuiltSourceRoot'] == 'nuget' else
                  'rebuilt-vstest' if vstest_products.get((package['path'], match['member'])) == match['identity']['sha256'] else
                  'imported-package')
        row = dict(path=name, origin=origin,
            sourceRoot=package['sourceRoot'], sourceCommit=package['sourceCommit'], packagePath=package['path'], packageMember=match['member'])
        if row['origin'] in {'rebuilt-nuget', 'rebuilt-vstest'} or not name.lower().endswith(('.dll', '.exe')): return row
        require(match['member'] is not None, 'Managed product requires an actual retained package member')
        with zipfile.ZipFile(release / package['path']) as archive: data = archive.read(match['member'])
        if name in C.policy()['products']:
            declared = C.declared_product(name, package['fingerprint']['sha256'], match['member'], data)
            require(declared['sourceCommit'] in component_roots, 'Reviewed original component full Git source is required')
            row['componentSource'] = dict(sourceRoot=sorted(component_roots[declared['sourceCommit']])[0],
                sourceCommit=declared['sourceCommit'], basis=declared['basis'])
            return row
        metadata = A.MANAGED.inspect(data)
        embedded_source = A.embedded_component_source(metadata)
        commit = embedded_source['sourceCommit'] if embedded_source else None
        if package['fingerprint']['sha256'] == A.CSS_PARSER['sha256']:
            # Candidate attribution follows the SDK's declared Gitlink. The
            # independent admission gate verifies the complete archived chain.
            require(commit is None and name == 'sdk/7.0.120/Sdks/Microsoft.NET.Sdk.Razor/tools/Microsoft.Css.Parser.dll'
                    and metadata['assemblyName'] == 'Microsoft.Css.Parser'
                    and A.CSS_PARSER['sourceCommit'] in component_roots, 'Reviewed CSS candidate source identity differs')
            row['componentSource'] = dict(sourceRoot=sorted(component_roots[A.CSS_PARSER['sourceCommit']])[0],
                sourceCommit=A.CSS_PARSER['sourceCommit'], basis='sdk-declared-source-gitlink')
            return row
        require(commit is not None, 'Imported managed component has no independently reviewed embedded source identity')
        if commit != row['sourceCommit']:
            require(commit in component_roots, 'Imported bundled component corresponding Git source is not retained: ' + commit)
            row['componentSource'] = dict(sourceRoot=sorted(component_roots[commit])[0], sourceCommit=commit,
                                          basis=embedded_source['basis'])
        metadata, commit = A.validate_imported_component(data, row, roots)
        family = A.shipping_family(name)
        separate = A.reviewed_testhost_nuget(name, data, metadata, row, dict(sdkVersion=version), package['fingerprint'],
            local_vstest=(dict(packages={row['sha256'] for row in vstest['builtPackages']},
                               importedMembers={(row['packagePath'], row['member']) for row in vstest['importedManagedMembers']}) if vstest else None))
        if family:
            expected = A.TESTHOST_NUGET_COMMIT if separate else A.SDK7_IMPORT_SOURCES[family][2]
            require(commit == expected, 'Imported managed component source differs from its declared SDK family: ' + family)
        require(family != 'nuget' or name.lower().endswith('.resources.dll') or separate,
                'Primary CLI NuGet must consume its genuinely rebuilt original package')
        return row

    layout = []
    for name, identity in actual.items():
        choices = []
        for artifact, inventory in inventories.items():
            if artifact == 'original-sdk-comparison' or artifacts[artifact]['kind'] in {'managed-package', W.KIND}: continue
            candidate = name[len(prefix):] if artifact == 'toolset' and name.startswith(prefix) else name
            if artifact == 'trace': candidate = '' if name == 'shared/Microsoft.NETCore.App/7.0.20/libcoreclrtraceptprovider.so' else None
            if artifacts[artifact]['kind'] == 'native-coreclr':
                candidate = '' if name == 'shared/Microsoft.NETCore.App/7.0.20/' + Path(artifacts[artifact]['path']).name else None
            if candidate in inventory and inventory[candidate] == identity: choices.append((artifact, candidate))
        if choices:
            order = {'trace': 0, 'runtime': 1, 'aspnet': 2, 'translations': 3, 'toolset': 4, 'post-crossgen': 5, 'generated': 6}
            order.update({key: 0 for key in artifacts if artifacts[key]['kind'] == 'native-coreclr'})
            artifact, member = min(choices, key=lambda row: order.get(row[0], 99))
            layout.append(dict(path=name, input=artifact, member=member))
        else:
            matches = candidates(name, identity['sha256'])
            if matches:
                row = matches[0]; layout.append(dict(path=name, input=use_package(row), member=row['member'] or ''))
            else: unknowns.append(dict(kind='unmapped-layout-member', path=name, sha256=identity['sha256']))
    for name in ('sdk', 'installer'):
        write(release / ('reports/build/' + name + '-replay.json'), replays[name])
    shipping = []
    for name in actual:
        if not name.startswith(prefix) or not name.lower().endswith(('.dll', '.exe', '.nupkg')): continue
        if name in compiled:
            shipping.append(dict(path=name, origin='rebuilt-sdk', sourceRoot='sdk', sourceCommit=roots['sdk']['commit'],
                packagePath=None, packageMember=None))
        elif name in translations:
            shipping.append(dict(path=name, origin='imported-official-translation-data', sourceRoot='nuget', sourceCommit=roots['nuget']['commit'],
                packagePath=None, packageMember=None))
        elif name in facade_rows:
            declared = facade_rows[name]
            require(name not in transformed and all(actual[name][key] == declared['fingerprint'][key] for key in ('bytes', 'sha256')),
                    'Literal type-forwarding product changed in the actual installer layout')
            shipping.append(dict(path=name, origin='derived-facade-metadata-source', sourceRoot=F.ROOT_NAME, sourceCommit=None,
                packagePath=facade_primary['path'], packageMember=declared['packageMember']))
        elif name in framework_rows:
            declared = framework_rows[name]
            require(name not in transformed and all(actual[name][key] == declared['fingerprint'][key] for key in ('bytes', 'sha256')),
                    'Preferred framework implementation bytes differ in the actual installer layout')
            shipping.append(dict(path=name, origin='upstream-framework-implementation-il', sourceRoot=framework_source,
                sourceCommit=FI.COMMIT, dataRoot=FI.ROOT_NAME, packagePath=framework_primary['path'],
                packageMember=declared['packageMember'], canonicalPrimaryPackagePath=framework_primary['path'],
                canonicalPrimaryMember=declared['packageMember']))
        else:
            sha = transformed[name]['inputSha256'] if name in transformed else actual[name]['sha256']
            matches = candidates(name, sha)
            if not matches:
                unknowns.append(dict(kind='unmapped-managed-source', path=name, sha256=sha)); continue
            reasons, accepted = [], None
            for match in matches:
                try:
                    accepted = shipping_row(name, match); break
                except ValueError as error:
                    reasons.append(str(error))
            if accepted is not None: shipping.append(accepted)
            else: unknowns.append(dict(kind='unmapped-managed-source', path=name, sha256=sha, reasons=sorted(set(reasons))))
    proof = dict(schemaVersion=1, kind='legacy-musl-construction-proof', sdkVersion=version, architecture=arch,
        targetRid='linux-musl-' + ('arm64' if arch == 'aarch64' else 'x64'), artifacts=artifacts, layout=layout,
        sdkBuildReplay=dict(path='reports/build/sdk-replay.json', **fingerprint(release / 'reports/build/sdk-replay.json')),
        installerBuildReplay=dict(path='reports/build/installer-replay.json', **fingerprint(release / 'reports/build/installer-replay.json')),
        nugetBuildReplay=nuget['replay'], managedShipping=shipping, unknowns=unknowns)
    if vstest: proof['vstestBuildReplay'] = vstest['replay']
    write(release / 'reports/legacy-construction.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args(); result = emit(load(args.context))
    print(json.dumps(dict(status='candidate-evidence-only', unknowns=len(result['unknowns']), layoutFiles=len(result['layout']),
        artifacts=len(result['artifacts']), qualificationAllowed=False, sourceAdmissionAllowed=False)))


if __name__ == '__main__': main()
