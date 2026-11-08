"""Collect SDK6's actual package caches, source leaves and constructor proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def collect(producer):
    p = producer; primitives = module('sdk6_collection_secure_primitives', 'musl-sdk.py')
    require, fingerprint, write = primitives.require, primitives.fingerprint, primitives.write
    require(p.sdk == '6.0.136' and p.archive is not None and p.archive.is_file(), 'Actual SDK6 archive required before source collection')
    retained = p.output / 'imported-inputs'; retained.mkdir(); rows, known = [], {}
    for name, root in sorted(p.sources.items()):
        caches = [Path(root['path']) / '.packages', Path(root['path']) / 'artifacts/.packages']
        if name == 'msbuild-localization': caches.append(Path(root['path']) / 'artifacts/.packages-localization')
        for cache in caches:
            if not cache.is_dir(): continue
            for package in sorted(cache.rglob('*.nupkg')):
                require(package.is_file() and not any(x.is_symlink() for x in (package, *package.parents)), 'Redirected actual SDK6 restored package')
                fp = fingerprint(package); sha = fp['sha256']
                if sha not in known:
                    destination = retained / (sha + '.nupkg'); shutil.copyfile(package, destination)
                    require(fingerprint(destination) == fp, 'SDK6 restored package changed during retention'); known[sha] = destination
                meta_path = package.parent / '.nupkg.metadata'; meta = json.loads(meta_path.read_text()) if meta_path.is_file() else {}
                with zipfile.ZipFile(package) as archive:
                    licenses = [dict(path=n, sha256=hashlib.sha256(archive.read(n)).hexdigest()) for n in archive.namelist()
                        if not n.endswith('/') and any(s in Path(n).name.lower() for s in ('license', 'notice', '.nuspec'))]
                rows.append(dict(repository=name, cache=str(cache), path=package.relative_to(cache).as_posix(), source=meta.get('source'),
                    retained='imported-inputs/' + known[sha].name, licensesAndNuspec=licenses, **fp))
    require(rows, 'Actual SDK6 restored package observations are absent')
    write(p.reports / 'restored-inputs.json', dict(schemaVersion=1, packages=rows, scope='Actual unchanged SDK6 NuGet restore inputs and original metadata/licenses'))
    p.sources['actual-managed-package-inputs'] = dict(name='actual-managed-package-inputs', path=str(retained), kind='tree', role='actual-imported-managed-inputs')
    packer = module('sdk6_complete_used_source_packer', 'package-used-source.py')
    registry = module('sdk6_corresponding_source_registry', 'musl_legacy6_component_sources.py')
    registry.register(p.sdk, p.sources, p.clone, packer.expand_submodules, p.reports / 'prepare/component-source-materialization.json')
    F = module('sdk6_collected_framework_source', 'musl_legacy6_framework_inputs.py')
    C = module('sdk6_collected_attributed_source', 'musl_legacy6_attributed_components.py')
    G = module('sdk6_collected_globbing_source', 'musl_legacy6_globbing_inputs.py')
    embedded = module('sdk6_collected_original_embedded_sources', 'musl_legacy6_embedded_source_inputs.py')
    fp = F.policy()['package']['fingerprint']; require(fp['sha256'] in known and fingerprint(known[fp['sha256']]) == fp, 'Actual direct canonical SDK6 framework input required')
    assets = [r for r in p.sources.values() if r.get('expectedCommit') == F.ASSETS_COMMIT]
    require(len(assets) == 1, 'Complete original SDK6 preferred framework Git source required')
    descriptor = F.prepare(known[fp['sha256']], p.sdk_work / 'sdk', Path(assets[0]['path']), p.reports / 'build/sdk6-framework-corresponding-inputs')
    p.sources[descriptor['name']] = {k: descriptor[k] for k in ('name', 'kind', 'path', 'role')}
    packages = {sha: known[sha] for sha in C.policy()['packages'] if sha in known}
    descriptor = C.prepare(packages, p.reports / 'build/sdk6-attributed-component-inputs'); p.sources[descriptor['name']] = descriptor
    require(G.PACKAGE_SHA in known, 'Actual original SDK6 Globbing restore input required')
    cli = p.reports / 'build/vstest/source-built-feed/Microsoft.TestPlatform.CLI.17.0.3-dev.nupkg'
    descriptor = G.prepare(known[G.PACKAGE_SHA], cli, Path(p.sources['vstest']['path']), p.reports / 'build/sdk6-globbing-source-inputs'); p.sources[descriptor['name']] = descriptor
    descriptor = embedded.prepare({sha: known[sha] for sha in embedded.policy()['packages']}, Path(p.sources['vstest']['path']),
        p.reports / 'build/sdk6-embedded-origin-package-inputs'); p.sources[descriptor['name']] = descriptor
    localization = module('sdk6_collected_source_localization', 'musl_legacy6_localization_inputs.py')
    # The localization leaf owns its distinct actual original-project compiler
    # branch; this call never attributes it as an imported publisher package.
    local_package = p.reports / 'build/msbuild-localization/source-built-feed/Microsoft.Build.Localization.17.0.4-cbodotnet.1.nupkg'
    arcade = localization.policy()['actualArcade']; require(arcade['sha256'] in known, 'Exact actually restored public localization Arcade package required')
    descriptor = localization.prepare(local_package, known[arcade['sha256']], p.reports / 'build/sdk6-localization-source-inputs')
    p.sources[descriptor['name']] = descriptor
    compiler = module('sdk6_observed_managed_compiler_inputs', 'musl_legacy_compiler_inputs.py')
    components = {name: dict(sourceRoot=source, sourceMountRoot=mount, hostPath=str(path), tasks=p.reports / 'build' / (file + '-replay-tasks.jsonl'))
        for name, source, mount, path, file in [('sdk', 'sdk', '/source', p.sdk_work / 'sdk', 'sdk'),
            ('nuget', 'nuget', '/work/work/nuget', p.nuget, 'nuget'), ('vstest', 'vstest', '/work/work/vstest', p.work / 'vstest', 'vstest'),
            ('installer', 'installer', '/work/work/installer', p.installer, 'installer'),
            ('msbuild-localization', 'msbuild-localization', '/work/work/msbuild-localization', p.work / 'msbuild-localization', 'msbuild-localization')]}
    descriptor = compiler.prepare(components, p.reports / 'build/managed-compiler-inputs'); p.sources[descriptor['name']] = descriptor
    roots = {name: dict(path=r['path'], kind=r.get('kind', 'git'), commit=r.get('expectedCommit'), **({'role': r['role']} if r.get('role') else {})) for name, r in p.sources.items()}
    context = dict(sdkVersion=p.sdk, architecture=p.args.arch, releaseDir=str(p.output), sourceRoots=roots, sdkArchive=str(p.archive),
        originalSdkComparison=str(p.official), toolsetZip=str(p.inputs / 'installer-components' / ('dotnet-toolset-internal-' + p.sdk + '-ci.zip')),
        runtimeArchive=str(p.framework_inputs['runtime']), aspnetArchive=str(p.framework_inputs['aspnetcore-runtime']), nativeRuntimeDir=str(p.reports / 'build/native-runtime'),
        installerLayout=str(p.installer / 'artifacts/bin/redist/Release/dotnet'), installerLayoutMount='/work/work/installer/artifacts/bin/redist/Release/dotnet',
        translationDataDir=str(p.reports / 'build/nuget-translation-data'), restoredInputs=str(p.reports / 'restored-inputs.json'),
        nugetPackages=[str(f) for f in sorted((p.reports / 'build/nuget/source-built-feed').glob('*.nupkg'))],
        vstestPackages=[str(f) for f in sorted((p.reports / 'build/vstest/source-built-feed').glob('*.nupkg'))],
        localizationPackages=[str(f) for f in sorted((p.reports / 'build/msbuild-localization/source-built-feed').glob('*.nupkg'))])
    for name, file, mount in [('sdk', 'sdk', '/source'), ('nuget', 'nuget', '/work/work/nuget'), ('vstest', 'vstest', '/work/work/vstest'),
            ('installer', 'installer', '/work/work/installer'), ('localization', 'msbuild-localization', '/work/work/msbuild-localization')]:
        context[name + 'Replay'] = dict(status=str(p.reports / 'build' / (file + '-replay-status.json')), tasks=str(p.reports / 'build' / (file + '-replay-tasks.jsonl')),
            binlog=str(p.reports / 'build' / (file + '.binlog')), sourceMountRoot=mount)
    write(p.reports / 'build/evidence-context.json', context)
    proof = module('sdk6_observed_constructor', 'musl_legacy6_evidence.py').emit(context)
    require(not proof['unknowns'], 'Actual SDK6 construction has unresolved byte or corresponding-source origins')
    (p.reports / 'ci').mkdir(parents=True, exist_ok=True); write(p.reports / 'source-roots.json', dict(schemaVersion=1, roots=list(p.sources.values())))
    packer.pack(SimpleNamespace(project_root=ROOT, project_commit=p.project, output_dir=p.output / 'sources', roots_json=p.reports / 'source-roots.json',
        sdk_version=p.sdk, target_rid=p.id['rid'], run_id=p.args.run_id, run_attempt=p.args.run_attempt))
    packer.verify(SimpleNamespace(release_dir=p.output, expected_project_commit=p.project, expected_run_id=p.args.run_id, expected_run_attempt=p.args.run_attempt, expected_target_rid=p.id['rid']))
    write(p.output / 'producer-sdk.json', dict(schemaVersion=1, kind='musl-sdk-build', producerRevision=1, sdkVersion=p.sdk, architecture=p.args.arch,
        targetRid=p.id['rid'], libc='musl', sourceCommit=p.selected['installer'], sdkSourceCommit=p.selected['sdk'], runtimeSourceCommit=p.selected['runtimeCommit'],
        projectCommit=p.project, runId=p.args.run_id, runAttempt=p.args.run_attempt, imageId=p.image, sdk=dict(name=p.archive.name, **fingerprint(p.archive))))
