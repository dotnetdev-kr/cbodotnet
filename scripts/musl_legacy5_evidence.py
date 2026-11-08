"""Emit SDK5 byte origins without importing another SDK's source policy.

Completed component compiler processes remain separate. Imported package
metadata is retained unchanged; absent byte/source origins remain explicit
unknowns. This emitter neither executes the SDK nor grants admission.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_distinct_compiler_evidence', ROOT / 'scripts/musl_legacy5_component_evidence.py')
CE = importlib.util.module_from_spec(spec); spec.loader.exec_module(CE)
B = CE.B
require, fingerprint, members = B.require, B.fingerprint, B.members
SDK, RUNTIME = CE.SDK, '5.0.17'
COMMITS = dict(CE.COMMITS, runtime='6a984143635bde23e728abaaccbde52f5ea8fa3e',
    installer='430330f7c5428f031b4a835be3dcf5945f55a56a', aspnetcore='02c6de4ba6022025fcda7581415f310f8c73cdc3')
NATIVE = {'libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so', 'libcoreclrtraceptprovider.so'}


def load(path):
    return json.loads(CE.ordinary(path).read_bytes())


def normalized(path):
    require(isinstance(path, str) and path.startswith('/') and path != '/' and path == posixpath.normpath(path)
            and not any(c in path for c in '\\\0\r\n'), 'Exact ordinary SDK5 Linux mount required')
    return path


def scalar(task, field):
    values = B.task_values(task, field)
    require(len(values) <= 1, 'Ambiguous original SDK5 scalar: ' + field)
    return next(iter(values)) if values else None


def retain_directory(release, source, destination):
    source = Path(source).absolute()
    require(source.is_dir() and not any(p.is_symlink() for p in (source, *source.parents)), 'Ordinary SDK5 evidence directory required')
    for path in sorted(source.rglob('*')):
        require(not path.is_symlink(), 'Linked SDK5 evidence forbidden')
        if path.is_file(): CE.retain(release, path, destination + '/' + path.relative_to(source).as_posix())


def snapshot(release, destination, files):
    """Retain only observed ordinary files, without traversing archive links."""
    require(files, 'Nonempty SDK5 construction snapshot required')
    target = Path(release) / B.portable(destination)
    require(not any(p.is_symlink() for p in (target, *target.parents)), 'Ordinary SDK5 snapshot required')
    expected = {}
    for name, path in sorted(files.items()):
        path = CE.ordinary(path)
        with path.open('rb') as incoming: expected[B.portable(name)] = snapshot_identity(incoming)
    if target.exists():
        require(target.is_file(), 'Ordinary retained SDK5 snapshot required')
        actual = {}
        with tarfile.open(target, 'r:gz') as archive:
            for entry in archive:
                name = B.portable(entry.name)
                require(name not in actual and entry.type == tarfile.REGTYPE and entry.sparse is None
                        and entry.mode == 0o644 and entry.uid == entry.gid == entry.mtime == 0 and entry.uname == entry.gname == ''
                        and set(entry.pax_headers) <= {'path'} and all(v == name for v in entry.pax_headers.values()),
                        'Closed ordinary SDK5 snapshot member schema required')
                with archive.extractfile(entry) as incoming: actual[name] = snapshot_identity(incoming)
        require(actual == expected, 'Retained SDK5 snapshot bytes or member set differ')
        return dict(path=destination, **fingerprint(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, 'w:gz') as archive:
        for name, path in sorted(files.items()):
            path = CE.ordinary(path); info = tarfile.TarInfo(B.portable(name))
            info.size = path.stat().st_size; info.mode = 0o644
            with path.open('rb') as incoming: archive.addfile(info, incoming)
    return dict(path=destination, **fingerprint(target))


def snapshot_identity(incoming):
    """All three byte fingerprints plus the same four-byte archive signature."""
    total, signature = 0, b''; sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    for block in iter(lambda: incoming.read(1024 * 1024), b''):
        if not total: signature = block[:4]
        total += len(block); require(total <= 512 * 1024**2, 'Bounded SDK5 snapshot member required')
        sha256.update(block); sha512.update(block)
    return dict(bytes=total, sha256=sha256.hexdigest(), sha512=sha512.hexdigest(), signature=signature.hex())


def source_index(roots):
    commits = {}
    for name, root in roots.items():
        if root.get('kind', 'git') in ('git', 'git-export') and root.get('commit'):
            commits.setdefault(root['commit'], []).append(name)
    return {commit: sorted(names) for commit, names in commits.items()}


def nuspec_metadata(path):
    """Read the root package definition, preserving nested original definitions.

SDK5's genuine local FSharp bootstrap container retains its original nuspec
under cbodotnet-provenance/original-definitions. That file is payload evidence,
not a second root package identity. Both remain in the raw archive inventory.
"""
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if '/' not in n and '\\' not in n and n.lower().endswith('.nuspec')]
        require(len(names) == 1 and archive.getinfo(names[0]).file_size <= 1024 * 1024,
                'One bounded SDK5 root package definition required')
        raw = archive.read(names[0])
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe SDK5 root package XML')
    metadata = ET.fromstring(raw).find('{*}metadata')
    require(metadata is not None, 'SDK5 root package metadata absent')
    return metadata


def package_inputs(context, release, roots, needed, built):
    """Index actual restored raw packages; original repository metadata survives."""
    source = Path(context['restoredInputs']); observed = load(source)['packages']
    commits = source_index(roots)
    built_by_sha = {row['sha256']: name for name, proof in built.items() for row in proof['packages']}
    packages, index, records = {}, {}, []
    for row in observed:
        name = B.portable(row['retained']); candidates = [Path(release) / name, source.parent / name]
        if row.get('cache') and row.get('path'): candidates.append(Path(row['cache']) / B.portable(row['path']))
        found = [p for p in candidates if p.is_file()]
        require(found, 'Actual SDK5 restored raw package missing: ' + name)
        path = CE.ordinary(found[0]); fp = fingerprint(path)
        require(all(row.get(k) == fp[k] for k in CE.FP), 'Actual SDK5 restored package fingerprint differs')
        destination = 'imported-inputs/' + fp['sha256'] + '.nupkg'
        CE.retain(release, path, destination); records.append(dict(row, retained=destination))
        if destination in packages: continue
        metadata = nuspec_metadata(path); repository = metadata.find('{*}repository')
        commit = repository.get('commit') if repository is not None else None
        component = built_by_sha.get(fp['sha256']); basis = 'original-package-repository'
        if component:
            require(commit == CE.COMMITS[component], 'SDK5 actual source package repository differs from compiler proof')
            root = component; basis = 'actual-compiler-bound-source-package'
        else: root = commits[commit][0] if commit in commits else None
        package = dict(path=destination, id=metadata.findtext('{*}id'), version=metadata.findtext('{*}version'),
            sourceRoot=root, sourceCommit=commit, sourceBasis=basis, kind='managed-package',
            repository=dict(repository.attrib) if repository is not None else None,
            rebuiltSourceRoot=component, fingerprint=fp, inventory=members(path, 'managed-package'))
        packages[destination] = package
        for member, identity in package['inventory'].items():
            if identity['sha256'] in needed:
                index.setdefault(identity['sha256'], []).append(dict(package=package, member=member, identity=identity))
        if fp['sha256'] in needed:
            index.setdefault(fp['sha256'], []).append(dict(package=package, member=None,
                identity=dict(bytes=fp['bytes'], sha256=fp['sha256'], signature='504b0304')))
    descriptor = CE.write(release, 'reports/restored-inputs.json', dict(schemaVersion=1, packages=records,
        scope='Actual SDK5 restored inputs; archive membership alone is not a source-build claim'))
    return packages, index, descriptor


def read_installer(context, release):
    entries = context['installerReplays']
    require(len(entries) == 1 and entries[0]['name'] == 'installer', 'One separate original SDK5 installer replay required')
    entry = entries[0]; mount = normalized(entry['sourceMountRoot']); status = load(entry['status'])
    saved = {k: CE.retain(release, entry[k], 'reports/build/installer/' + Path(entry[k]).name) for k in ('binlog', 'status', 'tasks')}
    require(status.get('schemaVersion') == 1 and status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0 and status.get('failure') is None
            and status.get('inputSha256') == saved['binlog']['sha256'], 'Complete successful original SDK5 installer replay required')
    tasks = B.read_tasks(Path(release) / saved['tasks']['path'])
    require(len(tasks) == status.get('completedSelectedTasks'), 'SDK5 installer selected-task inventory differs')
    return dict(name='installer', sourceMountRoot=mount, **saved), tasks


def generated_outputs(actual, replay, tasks, context, roots):
    """Only explicit original write outputs establish generated data origins."""
    fields = {'WriteLinesToFile': 'File', 'GenerateDepsFile': 'DepsFilePath',
              'GenerateRuntimeConfigurationFiles': 'RuntimeConfigPath',
              'ResolveAssemblyReference': 'AssemblyInformationCacheOutputPath'}
    mount = normalized(context['installerLayoutMount']); result, order = {}, {}
    for task in tasks.values():
        field = fields.get(task['taskName'])
        if not field or task['succeeded'] is not True: continue
        if task['projectFile'] != replay['sourceMountRoot'] + '/src/redist/redist.csproj': continue
        if not task['taskFile'].startswith(replay['sourceMountRoot'] + '/src/redist/targets/'): continue
        value = scalar(task, field)
        if not value or not value.startswith(mount + '/'): continue
        value = normalized(value); name = value[len(mount) + 1:]
        if name not in actual or name.lower().endswith(('.dll', '.exe', '.nupkg')): continue
        if actual[name]['signature'].startswith(('4d5a', '7f454c46', '504b0304')): continue
        if task['taskName'] == 'ResolveAssemblyReference' and name != 'sdk/' + SDK + '/SDKPrecomputedAssemblyReferences.cache': continue
        path = CE.ordinary(Path(context['installerLayout']) / B.portable(name)); fp = fingerprint(path)
        require(all(actual[name][k] == fp[k] for k in ('bytes', 'sha256')), 'SDK5 generated data differs from final SDK')
        end = task['events'][-1]['eventNumber']
        if name in order and order[name] >= end: continue
        result[name] = dict(archivePath=name, task=task['taskName'], replayName='installer', context=task['context'],
            outputPath=value, outputParameter=field, fingerprint=fp, sourceRoot='installer', sourceCommit=COMMITS['installer'])
        order[name] = end
    return result


def emit(context):
    require(context.get('sdkVersion') == SDK and context.get('architecture') in ('aarch64', 'x64'), 'Independent SDK5 construction route required')
    release = Path(context['releaseDir']).absolute(); release.mkdir(parents=True, exist_ok=True)
    roots = context['sourceRoots']; commits = source_index(roots); arch = context['architecture']; prefix = 'sdk/' + SDK + '/'
    for name, pin in COMMITS.items():
        require(name in roots and roots[name].get('kind', 'git') == 'git' and roots[name].get('commit') == pin,
                'Exact independent SDK5 primary source root required: ' + name)
    for name, root in roots.items():
        if root.get('kind', 'git') != 'git': continue
        require(subprocess.check_output(['git', '-c', 'safe.directory=' + root['path'], '-C', root['path'], 'rev-parse', 'HEAD'], text=True).strip() == root['commit'],
                'SDK5 construction source checkout differs: ' + name)
    final = CE.retain(release, context['sdkArchive'], Path(context['sdkArchive']).name)
    actual = members(release / final['path'], 'sdk'); artifacts, inventories, unknowns = {}, {}, []

    def add(name, kind, path, source, destination=None, *, construction_only=False):
        require(name not in artifacts and source in roots and roots[source].get('commit'), 'Unique Git-bound SDK5 input artifact required')
        row = CE.retain(release, path, destination or 'reports/construction-inputs/' + name + Path(path).suffix)
        artifacts[name] = dict(row, kind=kind, sourceRoot=source, sourceCommit=roots[source]['commit'])
        if construction_only: artifacts[name]['constructionOnly'] = True
        inventories[name] = members(release / row['path'], 'native-coreclr' if kind.startswith('native-') else kind)

    add('toolset', 'sdk-toolset', context['toolsetZip'], 'sdk')
    add('runtime', 'official-runtime', context['runtimeArchive'], 'runtime')
    add('aspnet', 'official-aspnet', context['aspnetArchive'], 'aspnetcore')
    add('crypto', 'native-crypto', context['cryptoFile'], 'runtime',
        'reports/build/native-crypto/' + Path(context['cryptoFile']).name)
    if context.get('originalSdkComparison'):
        add('original-sdk-comparison', 'official-sdk-comparison', context['originalSdkComparison'], 'installer', construction_only=True)
    native = Path(context['nativeRuntimeDir']); result = load(native / 'results.json')
    records = {r['path']: r for r in result.get('shippingFiles', []) + result.get('auxiliaryFiles', [])}
    require(result.get('status') == 'passed' and result.get('sdkVersion') == SDK and result.get('runtimeVersion') == RUNTIME
            and result.get('architecture') == arch and result.get('sourceCommit') == COMMITS['runtime']
            and set(records) == NATIVE | {'crossgen'}, 'All six distinct SDK5 native source worker products required')
    for name, row in records.items():
        require(all(fingerprint(CE.ordinary(native / name))[k] == row.get(k) for k in CE.FP), 'Actual SDK5 native worker product bytes differ')
    retain_directory(release, native, 'reports/build/native-runtime')
    for name in sorted(NATIVE): add('native-' + name, 'native-coreclr', native / name, 'runtime', 'reports/build/native-runtime/' + name)
    add('source-crossgen', 'native-crossgen-construction-input', native / 'crossgen', 'runtime', 'reports/build/native-runtime/crossgen', construction_only=True)
    built, compiler_proofs = {}, {}
    for name in CE.COMMITS:
        descriptor = CE.emit(name, context, release, roots); validated = CE.validate(release, descriptor, roots)
        built[name] = validated['proof']; compiler_proofs[name] = descriptor
    replay, tasks = read_installer(context, release); mount = normalized(context['installerLayoutMount'])
    require(mount == replay['sourceMountRoot'] + '/artifacts/bin/redist/Release/dotnet', 'Exact original SDK5 installer layout mount required')
    crossgen_record = dict(sdkVersion=SDK, architecture=arch, targetRid='linux-musl-' + ('arm64' if arch == 'aarch64' else 'x64'),
        crossgenPath=normalized(context['crossgenPath']), nativeRuntimeRoot=normalized(context['nativeRuntimeRoot']),
        expectedNativeFingerprints={k: {f: records[k][f] for f in CE.FP} for k in ('crossgen', 'libclrjit.so')})
    transformed, crossgen_tasks = {}, []; toolset = inventories['toolset']
    for task in tasks.values():
        if task['taskName'] != 'Crossgen' or task['succeeded'] is not True: continue
        source, output = scalar(task, 'SourceAssembly'), scalar(task, 'DestinationPath')
        require(source and output and source.startswith(mount + '/') and output.startswith(mount + '/'), 'SDK5 Crossgen escaped its original layout')
        name = output[len(mount) + 1:]; require(name.startswith(prefix), 'SDK5 Crossgen must target its actual SDK layout')
        member = name[len(prefix):]
        require(member in toolset and name in actual, 'SDK5 Crossgen input/output member missing')
        row = dict(archivePath=name, input='toolset', member=member, inputSha256=toolset[member]['sha256'],
            outputSha256=actual[name]['sha256'], task='Crossgen', replayName='installer', context=task['context'], inputPath=source, outputPath=output)
        command = CE.validate_crossgen_task(row, replay, tasks, crossgen_record); crossgen_tasks.append(command)
        if actual[name]['sha256'] == toolset[member]['sha256']: continue
        require(name not in transformed, 'Multiple SDK5 source Crossgen transformations')
        path = CE.ordinary(Path(context['installerLayout']) / B.portable(name)); fp = fingerprint(path)
        require(all(fp[k] == actual[name][k] for k in ('bytes', 'sha256'))
                and B.MANAGED.inspect(path.read_bytes())['managedNativeHeaderBytes'] > 0,
                'Actual SDK5 source Crossgen output lacks its final ReadyToRun bytes')
        transformed[name] = row
    require(crossgen_tasks, 'Actual original SDK5 source Crossgen tasks required')
    if transformed:
        row = snapshot(release, 'reports/construction-inputs/post-crossgen.tar.gz', {n: Path(context['installerLayout']) / n for n in transformed})
        artifacts['post-crossgen'] = dict(row, kind='post-crossgen-sdk', sourceRoot='installer', sourceCommit=COMMITS['installer'])
        inventories['post-crossgen'] = members(release / row['path'], 'post-crossgen-sdk')
    generated = generated_outputs(actual, replay, tasks, context, roots)
    if generated:
        row = snapshot(release, 'reports/construction-inputs/generated-installer-data.tar.gz', {n: Path(context['installerLayout']) / n for n in generated})
        artifacts['generated'] = dict(row, kind='generated-installer-data', sourceRoot='installer', sourceCommit=COMMITS['installer'])
        inventories['generated'] = members(release / row['path'], 'generated-installer-data')
    translations = {}
    if context.get('translationDataDir'):
        directory = Path(context['translationDataDir']); origin = load(directory / 'origin.json')
        require(origin.get('sdkVersion') == SDK and origin.get('architecture') == arch and origin.get('sourceCommit') == COMMITS['nuget'], 'Original SDK5 translation data identity differs')
        retain_directory(release, directory, 'reports/build/nuget-translation-data'); files = {}
        for row in origin['files']:
            name = prefix + B.portable(row['path']); path = CE.ordinary(directory / 'resources' / row['path']); fp = fingerprint(path)
            require(row['sdkMember'] == name and all(row.get(k) == fp[k] for k in CE.FP), 'Original SDK5 translation input differs')
            if name not in actual: continue
            require(all(actual[name][k] == fp[k] for k in ('bytes', 'sha256')) and name not in translations, 'SDK5 translation not consumed unchanged')
            translations[name] = row; files[name] = path
        if files:
            row = snapshot(release, 'reports/construction-inputs/nuget-translation-data.tar.gz', files)
            artifacts['translations'] = dict(row, kind='nuget-translation-data', sourceRoot='nuget', sourceCommit=COMMITS['nuget'])
            inventories['translations'] = members(release / row['path'], 'nuget-translation-data')
    needed = {r['sha256'] for r in actual.values()} | {r['inputSha256'] for r in transformed.values()}
    packages, index, restored = package_inputs(context, release, roots, needed, built)

    def candidates(name, sha):
        return sorted([r for r in index.get(sha, []) if
            (r['member'] is None and name.endswith('.nupkg')) or (r['member'] and PurePosixPath(r['member']).name == PurePosixPath(name).name)],
            key=lambda r: (r['package']['rebuiltSourceRoot'] is None, r['package']['sourceRoot'] is None, r['package']['path'], r['member'] or ''))

    def use_package(match):
        package = match['package']; key = 'package-' + package['fingerprint']['sha256']
        if key not in artifacts:
            artifacts[key] = dict(path=package['path'], **package['fingerprint'], kind='managed-package',
                sourceRoot=package['sourceRoot'], sourceCommit=package['sourceCommit'], sourceBasis=package['sourceBasis'], repository=package['repository'])
            inventories[key] = dict(package['inventory']); inventories[key][''] = dict(bytes=package['fingerprint']['bytes'], sha256=package['fingerprint']['sha256'], signature='504b0304')
            if not package['sourceRoot']:
                unknowns.append(dict(kind='unmapped-package-source', artifact=key, id=package['id'], version=package['version'], originalRepository=package['repository']))
        return key

    layout = []
    for name, identity in actual.items():
        choices = []
        for key, inventory in inventories.items():
            artifact = artifacts[key]
            if artifact.get('constructionOnly') or artifact['kind'] == 'managed-package': continue
            member = name[len(prefix):] if key == 'toolset' and name.startswith(prefix) else name
            if artifact['kind'] in ('native-coreclr', 'native-crypto'):
                member = '' if name == 'shared/Microsoft.NETCore.App/' + RUNTIME + '/' + Path(artifact['path']).name else None
            if member in inventory and inventory[member] == identity: choices.append((key, member))
        if choices:
            order = {'runtime': 1, 'aspnet': 2, 'translations': 3, 'toolset': 4, 'post-crossgen': 5, 'generated': 6}
            key, member = min(choices, key=lambda r: 0 if artifacts[r[0]]['kind'].startswith('native-') else order.get(r[0], 99))
            layout.append(dict(path=name, input=key, member=member)); continue
        matches = candidates(name, identity['sha256'])
        if matches: layout.append(dict(path=name, input=use_package(matches[0]), member=matches[0]['member'] or ''))
        else: unknowns.append(dict(kind='unmapped-layout-member', path=name, sha256=identity['sha256']))
    sdk_own = {prefix + r['member']: r for r in built['sdk']['compiledOutputs']}
    own_packages = {name: {(r['packagePath'], r['member']): r for r in built[name]['compiledOutputs']} for name in ('nuget', 'vstest')}
    shipping = []
    for name, identity in actual.items():
        if not name.startswith(prefix) or not name.lower().endswith(('.dll', '.exe', '.nupkg')): continue
        if name in sdk_own:
            row = sdk_own[name]
            require(identity['sha256'] == row['fingerprint']['sha256'] or (name in transformed and transformed[name]['inputSha256'] == row['fingerprint']['sha256']), 'SDK5 own compiler product changed without its original Crossgen task')
            shipping.append(dict(path=name, origin='rebuilt-sdk', sourceRoot='sdk', sourceCommit=COMMITS['sdk'],
                replayName=row['replayName'], context=row['context'], packagePath=None, packageMember=None)); continue
        if name in translations:
            shipping.append(dict(path=name, origin='imported-official-translation-data', sourceRoot='nuget', sourceCommit=COMMITS['nuget'],
                packagePath=None, packageMember=None, separateResourceSourceProofRequired=True)); continue
        sha = transformed[name]['inputSha256'] if name in transformed else identity['sha256']; accepted, reasons = None, []
        for match in candidates(name, sha):
            package, member = match['package'], match['member']; use_package(match)
            row = dict(path=name, origin='imported-package', sourceRoot=package['sourceRoot'], sourceCommit=package['sourceCommit'],
                       packagePath=package['path'], packageMember=member)
            own = next((component for component, products in own_packages.items() if (package['path'], member) in products), None)
            if own:
                compiled = own_packages[own][(package['path'], member)]
                row.update(origin='rebuilt-' + own, sourceRoot=own, sourceCommit=COMMITS[own], replayName=compiled['replayName'], context=compiled['context'])
                accepted = row; break
            try:
                require(package['sourceRoot'], 'Original SDK5 package lacks a retained corresponding source root')
                if name.lower().endswith(('.dll', '.exe')):
                    require(member is not None, 'Managed SDK5 file needs its exact original package member')
                    with zipfile.ZipFile(release / package['path']) as archive: raw = archive.read(member)
                    component_source = B.embedded_component_source(B.MANAGED.inspect(raw))
                    require(component_source and component_source['sourceCommit'] in commits, 'Imported SDK5 member lacks independent retained embedded source')
                    row['componentSource'] = dict(sourceRoot=commits[component_source['sourceCommit']][0], **component_source)
                accepted = row; break
            except ValueError as error: reasons.append(str(error))
        if accepted: shipping.append(accepted)
        else: unknowns.append(dict(kind='unmapped-managed-source', path=name, sha256=sha, reasons=sorted(set(reasons))))
    installer = dict(schemaVersion=1, sdkVersion=SDK, replay=replay, sourceCrossgenRecord=crossgen_record,
        crossgenTasks=crossgen_tasks, transformations=list(transformed.values()), generatedOutputs=list(generated.values()))
    installer_descriptor = CE.write(release, 'reports/build/installer-replay.json', installer)
    proof = dict(schemaVersion=1, kind='sdk5-musl-construction-proof', sdkVersion=SDK, architecture=arch,
        targetRid=crossgen_record['targetRid'], sdkArchive=final, inventory=actual, artifacts=artifacts, layout=layout,
        managedShipping=shipping, componentCompilerProofs=compiler_proofs, installerBuildReplay=installer_descriptor,
        restoredInputs=restored, unknowns=unknowns, qualificationAllowed=False, sourceAdmissionAllowed=False,
        diagnosticOnly=context.get('diagnosticOnly') is True,
        constructionInputScope='diagnostic-byte-correspondence-only' if context.get('diagnosticOnly') is True else 'normal-producer-inputs',
        normalProducerInputConsumptionClaimed=False,
        diagnosticComparisonScope=context.get('diagnosticComparisonScope'))
    CE.write(release, 'reports/legacy-construction.json', proof)
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args(); result = emit(load(args.context))
    print(json.dumps(dict(unknowns=len(result['unknowns']), layout=len(result['layout']), sdkVersion=SDK)))
