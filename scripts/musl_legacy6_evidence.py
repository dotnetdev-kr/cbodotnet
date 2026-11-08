"""Construct SDK6 byte origins and corresponding-source candidates.

The emitter reports unresolved origins explicitly. Its output is independently
validated by the SDK6 contract before any normal producer may seal it.
"""
import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


CE = module('sdk6_component_compiler_evidence', 'musl_legacy6_component_evidence.py')
B = CE.B
# File retention, literal binlog scalars and archive snapshots carry no SDK7
# policy. The source/version decisions below are SDK6-specific.
U = module('sdk6_neutral_construction_utilities', 'musl_legacy_evidence.py')
F = module('sdk6_framework_correspondence', 'musl_legacy6_framework_inputs.py')
C = module('sdk6_closed_attributed_components', 'musl_legacy6_attributed_components.py')
G = module('sdk6_globbing_correspondence', 'musl_legacy6_globbing_inputs.py')
MS = module('sdk6_source_localization', 'musl_legacy6_localization_inputs.py')
APPHOST = module('sdk6_unindexed_original_debug_inputs', 'musl_legacy6_package_inventory.py')
BCL = module('sdk6_original_embedded_source_inputs', 'musl_legacy6_embedded_source_inputs.py')
LITERAL = module('sdk6_original_literal_source_inputs', 'musl_legacy6_literal_inputs.py')
require, fingerprint, members = B.require, B.fingerprint, B.members
SDK = '6.0.136'
RUNTIME = '6.0.36'
NATIVE = {'libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so', 'libcoreclrtraceptprovider.so'}


def source_commit_index(roots):
    commits = {}
    for name, row in roots.items():
        if row.get('kind', 'git') in ('git', 'git-export') and row.get('commit'):
            commits.setdefault(row['commit'], []).append(name)
    for commit, names in commits.items():
        preferred = [name for name in names if roots[name].get('role') == 'source-for-serviced-imported-package']
        require(len(preferred) <= 1, 'Ambiguous SDK6 pristine imported source commit')
        if preferred:
            commits[commit] = preferred
    return commits


def package_inputs(context, release, roots, needed, built):
    source_index = Path(context['restoredInputs']); observed = U.load(source_index)['packages']
    commits = source_commit_index(roots)
    built_by_sha = {row['sha256']: name for name, proof in built.items() for row in proof['packages']}
    packages, index, records = {}, {}, []
    canonical = F.policy()['package']['fingerprint']
    for row in observed:
        name = B.portable(row['retained']); path = release / name
        if not path.is_file(): path = source_index.parent / name
        if not path.is_file() and context.get('diagnosticOnly') is True and row.get('cache') and row.get('path'):
            path = Path(row['cache']) / B.portable(row['path'])
        fp = fingerprint(CE.ordinary(path)); require(all(row.get(k) == fp[k] for k in CE.FP), 'Actual SDK6 restored package bytes differ')
        destination = 'imported-inputs/' + fp['sha256'] + '.nupkg'; U.retained(release, path, destination)
        records.append(dict(row, retained=destination))
        if destination in packages: continue
        metadata = B.nuspec_metadata(path); repository = metadata.find('{*}repository')
        commit = repository.get('commit') if repository is not None else None
        source, basis, source_kind = None, 'original-package-repository', 'managed-package'
        if fp['sha256'] in built_by_sha:
            component = built_by_sha[fp['sha256']]; source = component
            commit = MS.COMMIT if component == MS.SOURCE_ROOT else CE.COMMITS[component]; basis = 'actual-compiler-bound-source-package'
        elif fp == canonical:
            source = next((n for n in commits.get(F.ASSETS_COMMIT, []) if n != 'msbuild-localization'), None)
            commit = F.ASSETS_COMMIT; basis = 'sdk6-direct-canonical-preferred-source'
        elif fp['sha256'] in C.policy()['packages']:
            C.inspect_package(path, fp['sha256'])
            # Byte-origin container and the component's underlying source are
            # independently declared. Do not overwrite its original nuspec.
            if commit in commits: source = sorted(commits[commit])[0]
            else:
                declared = [p for p in C.policy()['products'].values() if any(p['packageSha256'] == fp['sha256'] for p in p['allowedPackageMembers'])]
                sources = {C.policy()['sources'][p['canonical']['source']]['commit'] for p in declared}
                if len(sources) == 1:
                    commit = next(iter(sources)); source = sorted(commits.get(commit, []))[0] if commit in commits else None
                    basis = 'sdk6-closed-component-source-chain'
        elif fp['sha256'] == G.PACKAGE_SHA:
            G.inspect_package(path); commit = G.COMMIT; source = sorted(commits.get(commit, []))[0] if commit in commits else None
            basis = 'sdk6-original-CommitHash-and-preferred-source'
        elif fp['sha256'] in BCL.policy()['packages']:
            origin = BCL.package_origin(path, fp['sha256'])
            require(BCL.ROOT_NAME in roots and roots[BCL.ROOT_NAME].get('kind') == 'tree'
                    and roots[BCL.ROOT_NAME].get('commit') is None and roots[BCL.ROOT_NAME].get('role') == BCL.ROLE,
                    'Original embedded-source package input data role differs')
            source, commit, source_kind, basis = origin['sourceRoot'], origin['sourceCommit'], origin['kind'], origin['sourceBasis']
        elif fp['sha256'] in LITERAL.policy()['packages']:
            origin = LITERAL.package_origin(path, fp['sha256']); commit = origin['sourceCommit']; basis = origin['sourceBasis']
            require(len(commits.get(commit, [])) == 1, 'Unique exact SDK6 literal package source root required')
            source = commits[commit][0]
        elif commit in commits:
            source = sorted(commits[commit], key=lambda n: (n == 'msbuild-localization', n))[0]
        package = dict(path=destination, id=metadata.findtext('{*}id'), version=metadata.findtext('{*}version'),
            sourceRoot=source, sourceCommit=commit, sourceBasis=basis, kind=source_kind,
            repository=dict(repository.attrib) if repository is not None else None,
            rebuiltSourceRoot=built_by_sha.get(fp['sha256']), fingerprint=fp)
        if fp['sha256'] == APPHOST.SHA:
            reviewed = APPHOST.inspect(path, needed)
            package['inventory'] = reviewed.pop('inventory')
            U.write(release / 'reports/build/unindexed-original-apphost-symbols.json', reviewed)
        else: package['inventory'] = members(path, 'managed-package')
        packages[destination] = package
        for member, identity in package['inventory'].items():
            if identity['sha256'] in needed:
                index.setdefault(identity['sha256'], []).append(dict(package=package, member=member, identity=identity))
        if fp['sha256'] in needed:
            index.setdefault(fp['sha256'], []).append(dict(package=package, member=None, identity=dict(bytes=fp['bytes'], sha256=fp['sha256'], signature='504b0304')))
    output = release / 'reports/restored-inputs.json'
    if output.exists(): require(U.load(output)['packages'] == records, 'SDK6 actual restore observations may not be rewritten')
    else: U.write(output, dict(schemaVersion=1, packages=records, scope='All actual restored inputs; no source build inferred from container membership'))
    return packages, index


def emit(context):
    require(context.get('sdkVersion') == SDK and context.get('architecture') in ('x64', 'aarch64'), 'Unreviewed SDK6 construction route')
    release = Path(context['releaseDir']).absolute(); release.mkdir(parents=True, exist_ok=True)
    roots = context['sourceRoots']; arch = context['architecture']; prefix = 'sdk/' + SDK + '/'
    for name, row in roots.items():
        if row.get('kind', 'git') != 'git': continue
        require(subprocess.check_output(['git', '-c', 'safe.directory=' + row['path'], '-C', row['path'], 'rev-parse', 'HEAD'], text=True).strip() == row['commit'],
                'SDK6 construction checkout commit differs: ' + name)
    final = U.retained(release, context['sdkArchive'], Path(context['sdkArchive']).name); actual = members(release / final['path'], 'sdk')
    artifacts, inventories, unknowns = {}, {}, []

    def add(name, kind, path, source, destination=None, basis=None):
        require(name not in artifacts and roots[source].get('commit'), 'Unique Git-bound SDK6 artifact required')
        row = U.retained(release, path, destination or 'reports/construction-inputs/' + name + Path(path).suffix)
        artifacts[name] = dict(row, kind=kind, sourceRoot=source, sourceCommit=roots[source]['commit'])
        if basis: artifacts[name]['sourceBasis'] = basis
        inventories[name] = members(release / row['path'], kind)

    add('toolset', 'sdk-toolset', context['toolsetZip'], 'sdk')
    add('runtime', 'official-runtime', context['runtimeArchive'], 'runtime')
    add('aspnet', 'official-aspnet', context['aspnetArchive'], 'aspnetcore')
    if context.get('originalSdkComparison'):
        add('original-sdk-comparison', 'official-sdk-comparison', context['originalSdkComparison'], 'installer',
            'reports/construction-inputs/original-sdk-comparison.tar.gz')
    native = Path(context['nativeRuntimeDir']); U.retain_directory(release, native, 'reports/build/native-runtime')
    native_result = U.load(native / 'results.json')
    diagnostic_native = (context.get('diagnosticOnly') is True and native_result.get('kind') == 'net6-native-coreclr-prototype'
                         and native_result.get('runtimeVersion') == RUNTIME)
    require(native_result.get('status') == 'passed' and (native_result.get('sdkVersion') == SDK or diagnostic_native)
            and native_result.get('architecture') == arch and native_result.get('sourceCommit') == roots['runtime']['commit']
            and {r['path'] for r in native_result.get('shippingFiles', native_result.get('shippingCandidateFiles', []) if diagnostic_native else [])} == NATIVE,
            'SDK6 requires all five products from its distinct normal native source worker')
    for name in sorted(NATIVE): add('native-' + name, 'native-coreclr', native / name, 'runtime', 'reports/build/native-runtime/' + name)
    built, compiler_proofs = {}, {}
    for name in ('sdk', 'nuget', 'vstest'):
        descriptor = CE.emit(name, context, release, roots); validated = CE.validate(release, descriptor, roots)
        built[name] = validated['proof']; compiler_proofs[name] = descriptor
    localization_descriptor = MS.emit(context, release, roots)
    localization = MS.validate_compiler(release, localization_descriptor)
    built[MS.SOURCE_ROOT] = dict(packages=[localization['proof']['package']])
    sdk_outputs = {r['member']: r for r in built['sdk']['compiledOutputs']}
    compiled = {prefix + name: row for name, row in sdk_outputs.items() if prefix + name in actual}
    vstest_own = {(r['packagePath'], r['member']): r for r in built['vstest']['compiledOutputs']}
    nuget_own = {(r['packagePath'], r['member']): r for r in built['nuget']['compiledOutputs']}
    localization_own = {(localization['proof']['package']['path'], r['member']): r for r in localization['proof']['compiledOutputs']}
    entry = context['installerReplay']; status = U.load(entry['status'])
    require(status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks', 0) == 0, 'Complete SDK6 installer task replay required')
    log = U.retained(release, entry['binlog'], 'reports/build/installer.binlog')
    require(status['inputSha256'] == log['sha256'], 'SDK6 installer replay differs from its original log')
    task_desc = U.retained(release, entry['tasks'], 'reports/build/installer-tasks.jsonl'); tasks = B.read_tasks(release / task_desc['path'])
    installer = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
        inputSha256=log['sha256'], tasks=task_desc, sourceMountRoot=entry['sourceMountRoot'], compiledOutputs=[], transformations=[], generatedOutputs=[])
    transformed = {}; mount = U.normalized(context['installerLayoutMount']); toolset = inventories['toolset']
    for task in tasks.values():
        if task['taskName'] != 'Crossgen' or task['succeeded'] is not True: continue
        source, output = U.scalar(task, 'SourceAssembly'), U.scalar(task, 'DestinationPath')
        if not source or not output: continue
        source, output = U.normalized(source), U.normalized(output)
        require(source.startswith(mount + '/') and output.startswith(mount + '/'), 'SDK6 Crossgen output escaped actual layout')
        name = output[len(mount) + 1:]
        if not name.startswith(prefix): continue
        member = name[len(prefix):]; require(member in toolset and name in actual, 'SDK6 Crossgen lacks its exact input/output member')
        if actual[name]['sha256'] == toolset[member]['sha256']: continue
        row = dict(archivePath=name, input='toolset', member=member, inputSha256=toolset[member]['sha256'],
            outputSha256=actual[name]['sha256'], task='Crossgen', context=task['context'], inputPath=source, outputPath=output)
        CE.validate_crossgen_task(row, installer, tasks, dict(sdkVersion=SDK, architecture=arch,
            targetRid='linux-musl-' + ('arm64' if arch == 'aarch64' else 'x64')))
        require(name not in transformed, 'Multiple final SDK6 Crossgen producers'); transformed[name] = row
    installer['transformations'] = list(transformed.values())
    if transformed:
        row = U.snapshot(release, 'reports/construction-inputs/post-crossgen.tar.gz', context['installerLayout'], transformed)
        artifacts['post-crossgen'] = dict(row, kind='post-crossgen-sdk', sourceRoot='installer', sourceCommit=roots['installer']['commit'])
        inventories['post-crossgen'] = members(release / row['path'], 'post-crossgen-sdk')
    generated = U.generated_outputs(actual, installer, tasks, context, roots); installer['generatedOutputs'] = list(generated.values())
    if generated:
        row = U.snapshot(release, 'reports/construction-inputs/generated-installer-data.tar.gz', context['installerLayout'], generated)
        artifacts['generated'] = dict(row, kind='generated-installer-data', sourceRoot='installer', sourceCommit=roots['installer']['commit'])
        inventories['generated'] = members(release / row['path'], 'generated-installer-data')
    translations = {}; directory = Path(context['translationDataDir']); origin = U.load(directory / 'origin.json')
    require(origin['sdkVersion'] == SDK and origin['architecture'] == arch and origin['sourceCommit'] == CE.COMMITS['nuget'], 'SDK6 translation identity differs')
    U.retain_directory(release, directory, 'reports/build/nuget-translation-data'); translation_files = {}
    for row in origin['files']:
        path = directory / 'resources' / B.portable(row['path']); fp = fingerprint(CE.ordinary(path))
        require(row['sdkMember'] == prefix + row['path'] and all(row[k] == fp[k] for k in CE.FP), 'Actual SDK6 translation input differs')
        if row['sdkMember'] not in actual: continue
        require(all(actual[row['sdkMember']][k] == fp[k] for k in ('bytes', 'sha256')), 'SDK6 translation was not consumed unchanged')
        translations[row['sdkMember']] = row; translation_files[row['sdkMember']] = path
    require(len(translations) == 286, 'All286 original SDK6 resource-only translation products required')
    row = U.snapshot_files(release, 'reports/construction-inputs/nuget-translation-data.tar.gz', translation_files)
    artifacts['translations'] = dict(row, kind='nuget-translation-data', sourceRoot='nuget', sourceCommit=CE.COMMITS['nuget'])
    inventories['translations'] = members(release / row['path'], 'nuget-translation-data')
    needed = {r['sha256'] for r in actual.values()} | {r['inputSha256'] for r in transformed.values()}
    packages, index = package_inputs(context, release, roots, needed, built)
    framework = F.policy(); framework_rows = {prefix + r['path']: r for r in framework['layout']}
    primary = [p for p in packages.values() if p['fingerprint'] == framework['package']['fingerprint']]
    require(len(primary) == 1 and F.ROOT_NAME in roots, 'Actual direct canonical SDK6 framework input and readable source required')
    primary = primary[0]
    commits = source_commit_index(roots)

    def candidates(name, sha):
        matches = [r for r in index.get(sha, []) if r['package']['sourceRoot'] and
            ((r['member'] is None and name.endswith('.nupkg')) or (r['member'] and PurePosixPath(r['member']).name == PurePosixPath(name).name))]
        return sorted(matches, key=lambda r: (r['package']['rebuiltSourceRoot'] is None, r['package']['path'], r['member'] or ''))

    def use_package(match):
        p = match['package']; key = 'package-' + p['fingerprint']['sha256']
        if key not in artifacts:
            artifacts[key] = dict(path=p['path'], **p['fingerprint'], kind=p['kind'], sourceRoot=p['sourceRoot'],
                sourceCommit=p['sourceCommit'], sourceBasis=p['sourceBasis'])
            inventories[key] = dict(p['inventory']); inventories[key][''] = dict(bytes=p['fingerprint']['bytes'], sha256=p['fingerprint']['sha256'], signature='504b0304')
        return key

    layout = []
    for name, identity in actual.items():
        choices = []
        for artifact, inventory in inventories.items():
            if artifacts[artifact]['kind'] in {'managed-package', BCL.KIND, 'official-sdk-comparison'}: continue
            member = name[len(prefix):] if artifact == 'toolset' and name.startswith(prefix) else name
            if artifacts[artifact]['kind'] == 'native-coreclr': member = '' if name == 'shared/Microsoft.NETCore.App/' + RUNTIME + '/' + Path(artifacts[artifact]['path']).name else None
            if member in inventory and inventory[member] == identity: choices.append((artifact, member))
        if choices:
            order = {'runtime': 1, 'aspnet': 2, 'translations': 3, 'toolset': 4, 'post-crossgen': 5, 'generated': 6}
            key, member = min(choices, key=lambda r: 0 if artifacts[r[0]]['kind'] == 'native-coreclr' else order.get(r[0], 99))
            layout.append(dict(path=name, input=key, member=member)); continue
        matches = candidates(name, identity['sha256'])
        if matches: layout.append(dict(path=name, input=use_package(matches[0]), member=matches[0]['member'] or ''))
        else: unknowns.append(dict(kind='unmapped-layout-member', path=name, sha256=identity['sha256']))
    shipping = []
    for name, identity in actual.items():
        if not name.startswith(prefix) or not name.lower().endswith(('.dll', '.exe', '.nupkg')): continue
        if name in compiled:
            shipping.append(dict(path=name, origin='rebuilt-sdk', sourceRoot='sdk', sourceCommit=CE.COMMITS['sdk'], packagePath=None, packageMember=None)); continue
        if name in translations:
            shipping.append(dict(path=name, origin='imported-official-translation-data', sourceRoot='nuget', sourceCommit=CE.COMMITS['nuget'], packagePath=None, packageMember=None)); continue
        if name in framework_rows:
            declared = framework_rows[name]
            require(name not in transformed and all(identity[k] == declared['fingerprint'][k] for k in ('bytes', 'sha256')), 'SDK6 canonical framework product changed')
            shipping.append(dict(path=name, origin='sdk6-direct-canonical-framework-source', sourceRoot=primary['sourceRoot'], sourceCommit=F.ASSETS_COMMIT,
                dataRoot=F.ROOT_NAME, packagePath=primary['path'], packageMember=declared['packageMember'], sourceKind=declared['kind'])); continue
        sha = transformed[name]['inputSha256'] if name in transformed else identity['sha256']; matches = candidates(name, sha); accepted, reasons = None, []
        for match in matches:
            p, member = match['package'], match['member']; row = dict(path=name, origin='imported-package', sourceRoot=p['sourceRoot'],
                sourceCommit=p['sourceCommit'], packagePath=p['path'], packageMember=member)
            try:
                if (p['path'], member) in nuget_own: row['origin'] = 'rebuilt-nuget'
                elif (p['path'], member) in vstest_own: row['origin'] = 'rebuilt-vstest'
                elif (p['path'], member) in localization_own: row['origin'] = 'rebuilt-localization'
                elif name.lower().endswith(('.dll', '.exe')):
                    require(member is not None, 'Managed SDK6 product needs its actual package member')
                    with zipfile.ZipFile(release / p['path']) as archive: raw = archive.read(member)
                    if name in C.policy()['products']:
                        declared = C.declared_product(name, p['fingerprint']['sha256'], member, raw); commit, basis = declared['sourceCommit'], 'sdk6-closed-component-source-chain'
                    elif p['kind'] == BCL.KIND:
                        declared = BCL.declared_product(name, p['fingerprint']['sha256'], member, raw)
                        row['origin'] = 'imported-embedded-source-package'; commit, basis = declared['sourceCommit'], declared['basis']
                    else:
                        source = B.embedded_component_source(B.MANAGED.inspect(raw)); require(source, 'Imported SDK6 component lacks independently reviewed embedded identity')
                        commit, basis = source['sourceCommit'], source['basis']
                    require(commit in commits, 'Complete original SDK6 imported Git source missing: ' + commit)
                    row['componentSource'] = dict(sourceRoot=sorted(commits[commit])[0], sourceCommit=commit, basis=basis)
                accepted = row; break
            except ValueError as exc: reasons.append(str(exc))
        if accepted: shipping.append(accepted)
        else: unknowns.append(dict(kind='unmapped-managed-source', path=name, sha256=sha, reasons=sorted(set(reasons))))
    installer_desc = CE.write(release, 'reports/build/installer-replay.json', installer)
    proof = dict(schemaVersion=1, kind='sdk6-musl-construction-proof', sdkVersion=SDK, architecture=arch,
        targetRid='linux-musl-' + ('arm64' if arch == 'aarch64' else 'x64'), sdkArchive=final,
        artifacts=artifacts, layout=layout, managedShipping=shipping, componentCompilerProofs=compiler_proofs,
        installerBuildReplay=installer_desc, localizationBuildReplay=localization_descriptor,
        diagnosticOnly=context.get('diagnosticOnly') is True, unknowns=unknowns)
    U.write(release / 'reports/legacy-construction.json', proof)
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args(); result = emit(U.load(args.context)); print(json.dumps(dict(unknowns=len(result['unknowns']), layout=len(result['layout']))))
