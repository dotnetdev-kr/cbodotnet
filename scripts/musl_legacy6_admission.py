"""Independent SDK6 construction/source contract.

SDK7 policies are never selected by this module. Neutral archive, PE, ELF and
binary-log parsers are shared; all source, package and product decisions use the
SDK6-specific policies. A diagnostic prefix review cannot seal a normal run.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


CE = module('sdk6_admission_component_contract', 'musl_legacy6_component_evidence.py')
B = CE.B
F = module('sdk6_admission_framework_contract', 'musl_legacy6_framework_inputs.py')
C = module('sdk6_admission_attributed_contract', 'musl_legacy6_attributed_components.py')
G = module('sdk6_admission_globbing_contract', 'musl_legacy6_globbing_inputs.py')
T = module('sdk6_admission_translation_contract', 'musl_legacy6_translation_inputs.py')
MS = module('sdk6_admission_localization_contract', 'musl_legacy6_localization_inputs.py')
APPHOST = module('sdk6_admission_unindexed_debug_inputs', 'musl_legacy6_package_inventory.py')
BCL = module('sdk6_admission_embedded_package_sources', 'musl_legacy6_embedded_source_inputs.py')
LITERAL = module('sdk6_admission_literal_package_sources', 'musl_legacy6_literal_inputs.py')
NUGET_SOURCE = module('sdk6_admission_original_nuget_source', 'musl_legacy6_nuget_source.py')
VSTEST_SOURCE = module('sdk6_admission_original_vstest_source', 'musl_legacy6_vstest_source.py')
NATIVE_INPUTS = module('sdk6_admission_original_native_source', 'musl_legacy6_native_inputs.py')
BOUNDARY = module('sdk6_normal_producer_boundaries', 'musl_legacy6_boundaries.py')
require, fingerprint, load, checked, portable, members = B.require, B.fingerprint, B.load, B.checked, B.portable, B.members
FP = {'bytes', 'sha256', 'sha512'}
SDK = '6.0.136'
RUNTIME = '6.0.36'
POLICY = dict(sdk=CE.COMMITS['sdk'], nuget=CE.COMMITS['nuget'], vstest=CE.COMMITS['vstest'],
    runtimeCommit='f1dd57165bfd91875761329ac3a8b17f6606ad18',
    installer='d638663530d923adbe0442604b7a6562127321e9', bootstrap='6.0.135',
    msbuild='85d71072f8fa22cc761d6b65954da263364bee4d', aspnetcore='64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc')
PREFIX = 'sdk/' + SDK + '/'
NATIVE = {'libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so', 'libcoreclrtraceptprovider.so'}
FRAMEWORK_SHA512 = {
    ('official-runtime', 'aarch64'): '0830715511ab602242487c5fae0dc7a5b75e0c9d7705e624181ec13cc4726a06d7935df952aeddda0dc2c46db95ab14af9d8229a2302b1e6d2fd7e892b42267b',
    ('official-runtime', 'x64'): '56c2161c52901706fd769d2c9168cff5959576bd1a72d89f7c27858f467f59970624ea9a0559368462bc178e7c9ef7d86d0fda08c7dbdb72dd3e9084280823eb',
    ('official-aspnet', 'aarch64'): 'cf3dbc687acd27220560baf52d52dd42f4773ddd642487ae84e7a298ac30d9640af86cd0c5ee28ecd0364b35892194dbdfd1df302451367d7472c3bd00202f26',
    ('official-aspnet', 'x64'): '18d33df408b7e21fcbda8e1c6d67e745a374062d195467a826032da679784fb30b55fdad2de75497dd0e917b213d788ceb3f1b3481276e26e103f991c7553a93'}


INSTALLER_PATCHES = {
    'patches/net6-musl/0001-copy-local-source-built-components.patch': '059270ddf0b8b814a5610ac82dfd38f0319e4c73d87e8349cd9bcf482f81c8b0',
    'patches/net6-musl/0006-copy-matching-source-built-native-runtime.patch': '2736a1939720edd7ac72317e5b6c732d31498c52cf980ec6f062da7ba1fc97f1',
    'patches/net6-musl/0007-honor-skip-installer-version-metadata.patch': '0538cb455394b4b06af6c1bf69ee8098156dd182059af7086a6404193516ec42'}
READER_CONFIG = b'<configuration><packageSources><clear/></packageSources></configuration>\n'
REPLAY_COMPONENTS = ('nuget', 'sdk', 'installer', 'vstest', 'msbuild-localization')


def roots_by_name(manifest):
    result = {}
    for row in manifest['roots']:
        require(row['name'] not in result, 'Unique SDK6 source root names required'); result[row['name']] = row
    for name, commit in [(n, POLICY[n]) for n in ('sdk', 'nuget', 'vstest', 'installer', 'aspnetcore')] + [('runtime', POLICY['runtimeCommit'])]:
        require(name in result and result[name].get('kind') in ('git', 'git-export') and result[name].get('commit') == commit,
                'Exact full original SDK6 source root required: ' + name)
    return result


def restored_packages(release):
    rows = load(release / 'reports/restored-inputs.json')['packages']; result = {}
    for row in rows:
        name = portable(row['retained']); path = CE.ordinary(release / name); fp = fingerprint(path)
        require(all(row.get(k) == fp[k] for k in FP), 'Actual restored SDK6 package size/SHA256/SHA512 differs')
        require(name == 'imported-inputs/' + fp['sha256'] + '.nupkg', 'Canonical actual SDK6 retained package path required')
        if fp['sha256'] in result: require(result[fp['sha256']]['path'] == name, 'Ambiguous SDK6 primary package descriptor')
        else: result[fp['sha256']] = dict(path=name, **fp)
    require(result, 'Actual SDK6 restored inputs are absent')
    return result


def input_identity(name, actual, transformed):
    return transformed[name]['inputSha256'] if name in transformed else actual[name]['sha256']


def source_roots(row, roots):
    if row.get('kind') == BCL.KIND or row.get('origin') == 'imported-embedded-source-package':
        require(row.get('sourceRoot') == BCL.ROOT_NAME and row.get('sourceCommit') is None
                and roots.get(BCL.ROOT_NAME, {}).get('kind') == 'tree' and roots[BCL.ROOT_NAME].get('role') == BCL.ROLE
                and roots[BCL.ROOT_NAME].get('commit') is None, 'Original no-repository package input must keep its typed non-Git role')
        return
    require(row.get('sourceRoot') in roots and roots[row['sourceRoot']].get('kind') in ('git', 'git-export')
            and re.fullmatch('[a-f0-9]{40}', row.get('sourceCommit') or '')
            and roots[row['sourceRoot']].get('commit') == row['sourceCommit'], 'SDK6 product source identity differs')


def source_archive_members(release, manifest, wanted):
    expected = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in wanted:
                require(row['path'] not in expected, 'Duplicate SDK6 source archive member'); expected[row['path']] = row
    require(expected.keys() == wanted, 'Complete SDK6 source member coverage required')
    found = {}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.name not in found and entry.isfile() and entry.size == expected[entry.name]['bytes']
                    and entry.size <= 64 * 1024**2, 'Ordinary bounded SDK6 source archive member required')
            raw = archive.extractfile(entry).read(); fp = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
            require(all(expected[entry.name].get(k) == fp[k] for k in FP), 'Archived SDK6 source bytes differ'); found[entry.name] = raw
    require(found.keys() == wanted, 'SDK6 source archive is incomplete')
    return found, expected


def validate_sdk_sources(release, manifest, roots):
    """Only the original SDK6 code and two exact declared build/layout hooks."""
    source = roots['sdk']
    require(source.get('commit') == POLICY['sdk'] and not source.get('deleted') and not source.get('exclude'),
            'Complete original SDK6 tooling Git source required')
    packer = module('sdk6_tooling_original_git_primitives', 'package-used-source.py')
    tooling = module('sdk6_exact_declared_tooling_hooks', 'musl-legacy6-tooling.py')
    restore = ('  # Diagnostic redist builds do not execute these historical test frameworks.\n'
        '  if [[ ${CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS:-} == true ]]; then\n'
        '    return\n  fi\n\n')
    hooks = {'eng/restore-toolset.sh': restore.encode(),
        'src/Layout/redist/targets/GenerateLayout.targets': tooling.TRANSLATION_HOOK.encode()}
    indexed, baseline = {}, {}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as incoming:
        for line in incoming:
            row = json.loads(line)
            if not row['path'].startswith('sdk/'): continue
            name = row['path'][len('sdk/'):]
            require(name not in indexed and row.get('baseline'), 'Unique complete original SDK6 source baseline required')
            indexed[name] = row; baseline[name] = row['baseline']
    for child in source.get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
    require(indexed and packer.baseline_tree(baseline) == source['tree'], 'Full original SDK6 tooling tree differs')
    seen, changed = set(), {}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if not entry.name.startswith('sdk/'): continue
            name = entry.name[len('sdk/'):]
            require(name in indexed and name not in seen and (entry.isfile() or entry.issym())
                    and entry.size <= 64 * 1024**2, 'Ordinary bounded complete SDK6 source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            fp = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
            require(all(indexed[name].get(key) == value for key, value in fp.items()), 'Actual SDK6 source archive bytes differ')
            original = raw
            if name in hooks:
                addition = hooks[name]
                require(raw.count(addition) == 1, 'Exactly one declared SDK6 build/layout hook required')
                if name.endswith('GenerateLayout.targets'):
                    require(raw.endswith(addition + b'</Project>\n'), 'SDK6 translation hook must be the final original project target')
                else:
                    require(addition + b'  # The following frameworks and tools are used only for testing.\n' in raw,
                            'SDK6 bootstrap hook may skip only the original test-runtime download block')
                original = raw.replace(addition, b'', 1)
                changed[name] = fp
            blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
            require(packer.pristine_blob(indexed[name], blob, original, name.lower().endswith(('.sln', '.cmd', '.bat'))),
                    'An undeclared SDK6 tooling source change is present: ' + name)
            seen.add(name)
    require(seen == indexed.keys() and changed.keys() == hooks.keys(), 'Complete original SDK6 source and both declared hooks required')
    return dict(sourceCommit=POLICY['sdk'], originalTree=source['tree'], sourceFiles=len(seen), declaredHooks=changed,
        productCSharpChanged=False, redundantTestFrameworkOverrideApplied=False, manualHostTaskPruningApplied=False)


def reverse_installer_patch(actual, patch, relative):
    """Reverse unique exact hunks; original Git blobs also verify all context.

    Git applies these reviewed patches with a line offset on SDK6. Hunk bytes,
    counts and unique placement remain exact; no fuzzy context is accepted.
    """
    lines = patch.decode('utf-8').splitlines(True)
    require(lines[:2] == ['--- a/' + relative + '\n', '+++ b/' + relative + '\n'], 'Exact SDK6 installer patch target required')
    position, hunks = 2, 0
    while position < len(lines):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', lines[position])
        require(match is not None, 'Exact SDK6 installer patch hunk required'); position += 1
        old, new = [], []
        while position < len(lines) and not lines[position].startswith('@@ '):
            line = lines[position]; require(line and line[0] in ' +-', 'Exact SDK6 installer patch body required')
            if line[0] in ' -': old.append(line[1:])
            if line[0] in ' +': new.append(line[1:])
            position += 1
        require(len(old) == int(match[2] or '1') and len(new) == int(match[4] or '1'), 'Exact SDK6 installer patch hunk counts required')
        before, after = ''.join(old).encode(), ''.join(new).encode()
        require(after and actual.count(after) == 1, 'Unique exact SDK6 installer patch result required')
        actual = actual.replace(after, before, 1); hunks += 1
    require(hunks > 0, 'Reviewed SDK6 installer patch cannot be empty')
    return actual


def validate_installer_tree(files, indexed, source, patches):
    """Recover every original installer blob after only three reviewed patches."""
    require(source.get('commit') == POLICY['installer'] and not source.get('deleted') and not source.get('exclude'),
            'Complete original SDK6 installer source without deletions/exclusions required')
    packer = module('sdk6_installer_pristine_git_primitives', 'package-used-source.py')
    baseline = {name: row['baseline'] for name, row in indexed.items() if row.get('baseline')}
    for child in source.get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
    require(files.keys() == indexed.keys() and len(baseline) == len(indexed) + len(source.get('submodules', []))
            and packer.baseline_tree(baseline) == source['tree'], 'Full original SDK6 installer Git tree differs')
    require(patches.keys() == INSTALLER_PATCHES.keys() and all(hashlib.sha256(patches[name]).hexdigest() == digest
            for name, digest in INSTALLER_PATCHES.items()), 'Exactly the three reviewed SDK6 installer patch bytes required')
    target = 'src/redist/targets/GenerateLayout.targets'; require(target in files, 'Original SDK6 installer layout target required')
    recovered = files[target]
    for name in reversed(INSTALLER_PATCHES): recovered = reverse_installer_patch(recovered, patches[name], target)
    for name, raw in files.items():
        original = recovered if name == target else raw
        blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
        require(packer.pristine_blob(indexed[name], blob, original, name.lower().endswith(('.sln', '.cmd', '.bat'))),
                'An undeclared SDK6 installer source change is present: ' + name)
    return dict(sourceCommit=POLICY['installer'], originalTree=source['tree'], sourceFiles=len(files),
        reviewedPatches={name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
            for name, raw in patches.items()}, productCSharpChanged=False, crossgenTargetsChanged=False)


def validate_installer_sources(release, manifest, roots):
    indexed = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as incoming:
        for line in incoming:
            row = json.loads(line)
            if not row['path'].startswith('installer/'): continue
            name = row['path'][len('installer/'):]
            require(name not in indexed, 'Unique full original SDK6 installer source required'); indexed[name] = row
    wanted = {'installer/' + name for name in indexed} | {'orchestration/' + name for name in INSTALLER_PATCHES}
    found, _ = source_archive_members(release, manifest, wanted)
    return validate_installer_tree({name: found['installer/' + name] for name in indexed}, indexed, roots['installer'],
        {name: found['orchestration/' + name] for name in INSTALLER_PATCHES})


def validate_snapshot_coverage(layout_rows, inventories, transformed, generated):
    layout = {row['path']: row for row in layout_rows}
    for role, outputs in [('post-crossgen', transformed), ('generated', generated)]:
        require(inventories.get(role, {}).keys() == outputs.keys(), 'Exact SDK6 ' + role + ' snapshot/task output coverage required')
        used = {name for name, row in layout.items() if row['input'] == role}
        require(used <= outputs.keys() and (role != 'post-crossgen' or used == outputs.keys())
                and all(layout[name]['member'] == name for name in used), 'SDK6 ' + role + ' layout/task output coverage differs')


def validate_installer_replay(release, descriptor, record, roots, artifacts, inventories, actual):
    replay = load(checked(release, descriptor)); tasks = B.read_tasks(checked(release, replay['tasks']))
    require(replay.get('schemaVersion') == 1 and replay.get('completedReplay') is True
            and replay.get('buildSucceeded') is True and replay.get('unfinishedTasks') == 0
            and replay.get('inputSha256') == fingerprint(release / 'reports/build/installer.binlog')['sha256'],
            'Complete original SDK6 installer replay required')
    transformed, generated = {}, {}
    for row in replay['transformations']:
        name = portable(row['archivePath']); require(name in actual and name not in transformed and row['input'] == 'toolset', 'Unique SDK6 Crossgen output required')
        CE.validate_crossgen_task(row, replay, tasks, record)
        require(row['member'] in inventories['toolset'] and row['inputSha256'] == inventories['toolset'][row['member']]['sha256']
                and row['outputSha256'] == actual[name]['sha256'] and name == PREFIX + row['member']
                and inventories.get('post-crossgen', {}).get(name) == actual[name], 'SDK6 Crossgen input/final snapshot correspondence differs')
        transformed[name] = row
    for row in replay.get('generatedOutputs', []):
        name = portable(row['archivePath']); require(name in actual and name not in generated and name not in transformed, 'Unique SDK6 installer data output required')
        require(row['sourceRoot'] == 'installer' and row['sourceCommit'] == POLICY['installer']
                and inventories.get('generated', {}).get(name) == actual[name]
                and not name.lower().endswith(('.dll', '.exe', '.nupkg'))
                and not actual[name]['signature'].startswith(('4d5a', '7f454c46', '504b0304'))
                and row['task'] in {'WriteLinesToFile', 'GenerateBundledVersions', 'GenerateRuntimeGraph', 'GenerateDepsFile',
                    'GenerateRuntimeConfigurationFiles', 'GenerateSdkRuntimeIdentifierChain', 'CalculateTemplateVersions',
                    'CollatePackageDownloads', 'UpdateRuntimeConfig', 'GenerateDefaultRuntimeFrameworkVersion',
                    'GetDependencyInfo', 'ReplaceFileContents', 'ResolveAssemblyReference'}, 'Original SDK6 generated data bytes/source differ')
        task = tasks.get(row['context']); require(task is not None and task['succeeded'] is True, 'Successful SDK6 generated task required')
        B.validate_generated_task(row, replay, task, SDK); generated[name] = row
    validate_snapshot_coverage(load(release / 'reports/legacy-construction.json')['layout'], inventories, transformed, generated)
    return replay, transformed, generated


def validate_managed_shipping(release, proof, roots, actual, transformed, compiler, restored, framework, attributed, globbing, translations, localization, embedded_policy):
    wanted = {name for name in actual if name.startswith(PREFIX) and name.lower().endswith(('.dll', '.exe', '.nupkg'))}
    sdk = {PREFIX + r['member']: r for r in compiler['sdk']['proof']['compiledOutputs']}
    own = {n: {(r['packagePath'], r['member']): r for r in compiler[n]['proof']['compiledOutputs']} for n in ('nuget', 'vstest')}
    observed, pkg_cache = set(), {}
    framework_rows = {PREFIX + r['path']: r for r in F.policy()['layout']}
    for row in proof['managedShipping']:
        name = row['path']; require(name in wanted and name not in observed, 'Every SDK6 managed member needs one source declaration')
        observed.add(name); source_roots(row, roots); sha = input_identity(name, actual, transformed)
        origin = row['origin']; required = {'path', 'origin', 'sourceRoot', 'sourceCommit', 'packagePath', 'packageMember'}
        require(required <= set(row) <= required | ({'dataRoot', 'sourceKind'} if origin == 'sdk6-direct-canonical-framework-source' else {'componentSource'}),
                'Closed SDK6 managed source declaration required')
        if origin == 'rebuilt-sdk':
            require(row['sourceRoot'] == 'sdk' and row['sourceCommit'] == POLICY['sdk'] and name in sdk
                    and sdk[name]['fingerprint']['sha256'] == sha and row['packagePath'] is row['packageMember'] is None,
                    'Shipping SDK6 product lacks an actual ordinary/reference compiler output')
            continue
        if origin == 'imported-official-translation-data':
            require(row['sourceRoot'] == 'nuget' and row['sourceCommit'] == POLICY['nuget'] and name in translations
                    and name not in transformed and translations[name] == actual[name] and row['packagePath'] is row['packageMember'] is None,
                    'SDK6 translation must retain its independent resource/source proof and original bytes')
            continue
        package_name = portable(row['packagePath']); package = CE.ordinary(release / package_name); fp = fingerprint(package)
        require(fp['sha256'] in restored and restored[fp['sha256']] == dict(path=package_name, **fp), 'SDK6 shipping input was not actually restored unchanged')
        if package_name not in pkg_cache: pkg_cache[package_name] = members(package, 'managed-package')
        member = row['packageMember']
        if member is None:
            require(origin == 'imported-package' and name.endswith('.nupkg') and name not in transformed
                    and actual[name]['bytes'] == fp['bytes'] and sha == fp['sha256'], 'Whole SDK6 shipping package changed')
            continue
        require(portable(member) in pkg_cache[package_name] and pkg_cache[package_name][member]['sha256'] == sha, 'SDK6 package/member and pre-Crossgen product differ')
        with zipfile.ZipFile(package) as archive: raw = archive.read(member)
        if origin == 'imported-embedded-source-package':
            require(name in embedded_policy['products'] and fp['sha256'] in BCL.policy()['packages'], 'Only the closed SDK6 original package set may use embedded member source attribution')
            declared = BCL.declared_product(name, fp['sha256'], member, raw); component = row.get('componentSource')
            require(component is not None and component['sourceRoot'] == embedded_policy['products'][name]['sourceRoot']
                    and component['sourceCommit'] == declared['sourceCommit'] and component['basis'] == declared['basis'],
                    'SDK6 no-repository input lacks its exact independent per-member original source')
            source_roots(component, roots)
            continue
        if origin in ('rebuilt-nuget', 'rebuilt-vstest'):
            component = origin.removeprefix('rebuilt-'); require(row['sourceRoot'] == component and row['sourceCommit'] == POLICY[component]
                and (package_name, member) in own[component] and own[component][(package_name, member)]['fingerprint']['sha256'] == sha,
                'SDK6 rebuilt component has no actual original compiler/package consumption proof')
            continue
        if origin == 'rebuilt-localization':
            local = compiler[MS.SOURCE_ROOT]['proof']
            require(row['sourceRoot'] == MS.SOURCE_ROOT and row['sourceCommit'] == MS.COMMIT and name not in transformed
                    and local['package']['path'] == package_name and member in localization['products']
                    and local['package']['sha256'] == fp['sha256'] and member in compiler[MS.SOURCE_ROOT]['members']
                    and name == PREFIX + member.removeprefix('lib/netstandard1.3/')
                    and localization['products'][member]['sha256'] == sha, 'SDK6 localization needs its actual compiler, original XLF and SDK-consumed package bytes')
            continue
        if origin == 'sdk6-direct-canonical-framework-source':
            require(name in framework['products'] and name not in transformed and row['sourceRoot'] == framework['sourceRoot']
                    and row['sourceCommit'] == F.ASSETS_COMMIT and row['dataRoot'] == F.ROOT_NAME
                    and roots[F.ROOT_NAME].get('kind') == 'tree' and roots[F.ROOT_NAME].get('role') == F.ROLE
                    and roots[F.ROOT_NAME].get('commit') is None and fp == F.policy()['package']['fingerprint']
                    and member == framework_rows[name]['packageMember'] and row['sourceKind'] == framework_rows[name]['kind']
                    and all(actual[name][k] == framework['products'][name][k] for k in ('bytes', 'sha256')), 'SDK6 canonical framework/literal source relationship differs')
            continue
        require(origin == 'imported-package' and name.lower().endswith(('.dll', '.exe')), 'Unreviewed SDK6 managed origin')
        component = row.get('componentSource'); require(component is not None, 'Underlying SDK6 imported component source declaration required')
        source_roots(component, roots)
        if name in attributed['products']:
            declared = C.declared_product(name, fp['sha256'], member, raw)
            require(component['sourceCommit'] == declared['sourceCommit'] == attributed['products'][name]['sourceCommit'], 'Closed SDK6 underlying source differs')
        elif name in globbing['products']:
            require(component['sourceCommit'] == G.COMMIT and sha == globbing['products'][name]['sha256']
                    and any(p['sha256'] == globbing['consumerPackageFingerprint']['sha256'] for p in compiler['vstest']['proof']['packages'])
                    and (package_name, member) in compiler['vstest']['imports'], 'SDK6 Globbing source/license consumer is not the actual source-built VSTest input')
        else:
            embedded = B.embedded_component_source(B.MANAGED.inspect(raw))
            require(embedded is not None and component['sourceCommit'] == embedded['sourceCommit'] and component['basis'] == embedded['basis'], 'Imported SDK6 embedded source identity differs')
        if '/TestHost/' in name and PurePosixPath(name).name == 'NuGet.Frameworks.dll':
            require(component['sourceCommit'] == '42a8779499c1d1ed2488c2e6b9e2ee6ff6107766'
                    and (package_name, member) in compiler['vstest']['imports'], 'Original SDK6 CoreTestHost NuGet5 dependency source differs')
        elif B.shipping_family(name) == 'nuget' and not name.endswith('.resources.dll'):
            raise ValueError('Every primary SDK6 CLI NuGet product must consume its genuinely rebuilt original package')
        if B.shipping_family(name) == 'vstest': raise ValueError('Every SDK6 VSTest product must consume its genuine original compiler output')
    require(observed == wanted, 'SDK6 source declarations omit actual shipping managed members')


def validate_final_sdk_archive(record, proof):
    """Construction must describe the same final archive as the outer gate."""
    sdk = record.get('sdk')
    require(isinstance(sdk, dict) and set(sdk) == FP | {'name'}
            and isinstance(sdk['name'], str) and type(sdk['bytes']) is int and sdk['bytes'] > 0
            and re.fullmatch('[a-f0-9]{64}', sdk.get('sha256', ''))
            and re.fullmatch('[a-f0-9]{128}', sdk.get('sha512', '')),
            'An explicit actual final SDK6 archive identity is required')
    expected = dict(path=portable(sdk['name']), **{key: sdk[key] for key in FP})
    require(proof.get('sdkArchive') == expected,
            'SDK6 construction must bind the exact final SDK archive path and all fingerprints')
    return expected


def validate_artifact_roles(artifacts, roots, restored, record):
    roles = {'toolset': ('sdk-toolset', 'sdk'), 'runtime': ('official-runtime', 'runtime'),
        'aspnet': ('official-aspnet', 'aspnetcore'), 'original-sdk-comparison': ('official-sdk-comparison', 'installer'),
        'post-crossgen': ('post-crossgen-sdk', 'installer'), 'generated': ('generated-installer-data', 'installer'),
        'translations': ('nuget-translation-data', 'nuget')}
    roles.update({'native-' + name: ('native-coreclr', 'runtime') for name in NATIVE})
    require(isinstance(artifacts, dict) and roles.keys() <= artifacts.keys(), 'All named SDK6 construction artifact roles required')
    paths = set()
    for name, row in artifacts.items():
        require(row.get('path') not in paths, 'Unique SDK6 artifact path/role required'); paths.add(row.get('path'))
        source_roots(row, roots)
        if name in roles:
            kind, source = roles[name]
            require(row.get('kind') == kind and row.get('sourceRoot') == source
                    and row.get('sourceCommit') == roots[source]['commit'], 'Exact named SDK6 artifact kind/source required: ' + name)
            require(set(row) == FP | {'path', 'kind', 'sourceRoot', 'sourceCommit'}, 'Closed named SDK6 artifact descriptor required')
            if kind in ('official-runtime', 'official-aspnet'):
                require(row['sha512'] == FRAMEWORK_SHA512[(kind, record['architecture'])], 'Exact independently pinned SDK6 official musl framework archive required')
            if kind == 'official-sdk-comparison':
                require(row['sha512'] == T.COMPARISON_SHA512[record['architecture']], 'Exact original SDK6 comparison archive required')
            if kind == 'native-coreclr':
                require(row['path'] == 'reports/build/native-runtime/' + name.removeprefix('native-'), 'Exact named SDK6 native artifact path required')
        else:
            require(name == 'package-' + row.get('sha256', '') and row.get('kind') in ('managed-package', BCL.KIND)
                    and set(row) == FP | {'path', 'kind', 'sourceRoot', 'sourceCommit', 'sourceBasis'}
                    and restored.get(row['sha256']) == {key: row[key] for key in ('path', *FP)},
                    'Only one canonical actually restored SDK6 package may add a named artifact role')
    return roles


def validate_toolset_binding(artifacts, compiler):
    packages = compiler['sdk']['proof']['packages']
    require(len(packages) == 1 and all(packages[0][key] == artifacts['toolset'][key] for key in FP),
            'SDK6 toolset must equal the actual SDK compiler proof package in all fingerprints')


def validate_package_artifact_sources(release, artifacts, compiler):
    built = {row['sha256']: name for name, item in compiler.items()
        for row in ([item['proof']['package']] if name == MS.SOURCE_ROOT else item['proof']['packages'])}
    for name, row in artifacts.items():
        if not name.startswith('package-'): continue
        path = checked(release, {key: row[key] for key in ('path', *FP)}); sha = row['sha256']
        if row['kind'] == BCL.KIND:
            origin = BCL.package_origin(path, sha)
            require(row['sourceRoot'] == origin['sourceRoot'] and row['sourceCommit'] is None
                    and row['sourceBasis'] == origin['sourceBasis'], 'Exact original SDK6 embedded package artifact source required')
            continue
        metadata = B.nuspec_metadata(path); repository = metadata.find('{*}repository')
        commit = repository.get('commit') if repository is not None else None
        basis = 'original-package-repository'
        if sha in built:
            component = built[sha]; commit = MS.COMMIT if component == MS.SOURCE_ROOT else CE.COMMITS[component]
            basis = 'actual-compiler-bound-source-package'
            require(row['sourceRoot'] == component, 'SDK6 built package artifact must use its actual compiler component source')
        elif {key: row[key] for key in FP} == F.policy()['package']['fingerprint']:
            commit, basis = F.ASSETS_COMMIT, 'sdk6-direct-canonical-preferred-source'
        elif sha in LITERAL.policy()['packages']:
            origin = LITERAL.package_origin(path, sha); commit, basis = origin['sourceCommit'], origin['sourceBasis']
        elif sha == G.PACKAGE_SHA: commit, basis = G.COMMIT, 'sdk6-original-CommitHash-and-preferred-source'
        elif not commit and sha in C.policy()['packages']:
            products = [p for p in C.policy()['products'].values() if any(p['packageSha256'] == sha for p in p['allowedPackageMembers'])]
            commits = {C.policy()['sources'][p['canonical']['source']]['commit'] for p in products}
            require(len(commits) == 1, 'Unique reviewed SDK6 package artifact source chain required')
            commit, basis = next(iter(commits)), 'sdk6-closed-component-source-chain'
        require(re.fullmatch('[a-f0-9]{40}', commit or '') and row['sourceCommit'] == commit and row['sourceBasis'] == basis,
                'SDK6 package artifact source must equal its original package or exact reviewed source policy')


def validate_layout(proof, actual, inventories):
    seen = set()
    for row in proof['layout']:
        require(set(row) == {'path', 'input', 'member'} and row['path'] in actual and row['path'] not in seen
                and row['input'] in inventories and row['member'] in inventories[row['input']]
                and row['input'] != 'original-sdk-comparison'
                and inventories[row['input']][row['member']] == actual[row['path']], 'Every SDK6 layout byte must match one actual unchanged construction input')
        seen.add(row['path'])
        if row['path'].startswith('shared/'):
            require(row['input'] in ('runtime', 'aspnet') and row['member'] == row['path']
                    or row['input'] == 'native-' + PurePosixPath(row['path']).name
                    and row['path'] == 'shared/Microsoft.NETCore.App/' + RUNTIME + '/' + PurePosixPath(row['path']).name
                    and PurePosixPath(row['path']).name in NATIVE and row['member'] == '',
                    'Every shared SDK6 framework member must use the pinned official archive or exact rebuilt native role')
    require(seen == actual.keys(), 'SDK6 layout origin coverage is incomplete')


def validate_construction(release, record, manifest, *, allow_diagnostic=False, stages=None, prepare=None):
    """Validate source/layout prefix; consumer/native/normal gates remain separate."""
    release = Path(release); require(record['sdkVersion'] == SDK, 'Only the reviewed SDK6 policy may be selected')
    proof = load(release / 'reports/legacy-construction.json')
    require(proof.get('schemaVersion') == 1 and proof.get('kind') == 'sdk6-musl-construction-proof'
            and proof.get('sdkVersion') == SDK and proof.get('architecture') == record['architecture']
            and proof.get('targetRid') == record['targetRid'] and proof.get('unknowns') == []
            and (proof.get('diagnosticOnly') is False or allow_diagnostic is True), 'Unresolved or diagnostic SDK6 construction cannot seal a normal producer')
    selected_sdk = validate_final_sdk_archive(record, proof)
    roots = roots_by_name(manifest); restored = restored_packages(release)
    sdk_sources = validate_sdk_sources(release, manifest, roots)
    installer_sources = validate_installer_sources(release, manifest, roots)
    actual = members(checked(release, selected_sdk), 'sdk')
    artifacts, inventories = proof['artifacts'], {}
    validate_artifact_roles(artifacts, roots, restored, record)
    for name, row in artifacts.items():
        path = checked(release, {k: row[k] for k in ('path', *FP)})
        inventories[name] = (APPHOST.inspect(path, {r['sha256'] for r in actual.values()})['inventory']
            if row['kind'] == 'managed-package' and row['sha256'] == APPHOST.SHA else members(path, row['kind']))
        if row['kind'] in {'managed-package', BCL.KIND}: inventories[name][''] = dict(bytes=row['bytes'], sha256=row['sha256'], signature='504b0304')
    validate_layout(proof, actual, inventories)
    compiler = {name: CE.validate(release, proof['componentCompilerProofs'][name], roots) for name in ('sdk', 'nuget', 'vstest')}
    validate_toolset_binding(artifacts, compiler)
    nuget_source = NUGET_SOURCE.validate(release, manifest, compiler['nuget'])
    vstest_source = VSTEST_SOURCE.validate(release, manifest, compiler['vstest'])
    compiler[MS.SOURCE_ROOT] = MS.validate_compiler(release, proof['localizationBuildReplay'])
    validate_package_artifact_sources(release, artifacts, compiler)
    localization_package = compiler[MS.SOURCE_ROOT]['proof']['package']; require(localization_package['sha256'] in restored,
        'Genuine SDK6 localization output must actually be restored by the product graph')
    localization = MS.validate(release, manifest, checked(release, localization_package))
    replay, transformed, generated = validate_installer_replay(release, proof['installerBuildReplay'], record, roots, artifacts, inventories, actual)
    if APPHOST.SHA in restored:
        needed = {r['sha256'] for r in actual.values()} | {r['inputSha256'] for r in transformed.values()}
        reviewed = APPHOST.inspect(release / restored[APPHOST.SHA]['path'], needed); reviewed.pop('inventory')
        require(load(release / 'reports/build/unindexed-original-apphost-symbols.json') == reviewed,
                'SDK6 original unindexed debug-input disposition differs from actual package/layout bytes')
    canonical = F.policy()['package']['fingerprint']; require(canonical['sha256'] in restored, 'SDK6 canonical framework input must actually be restored')
    framework = F.validate(release, manifest, release / restored[canonical['sha256']]['path'])
    component_packages = {}
    for sha, expected in C.policy()['packages'].items():
        require(sha in restored and all(restored[sha][k] == expected[k] for k in FP), 'Every closed SDK6 primary/canonical package must actually be restored')
        component_packages[sha] = release / restored[sha]['path']
    attributed = C.validate(release, manifest, component_packages)
    embedded_packages = {}
    for sha, expected in BCL.policy()['packages'].items():
        require(sha in restored and all(restored[sha][k] == expected['fingerprint'][k] for k in FP), 'All original SDK6 embedded-source canonical packages must actually be restored')
        embedded_packages[sha] = release / restored[sha]['path']
    embedded_policy = BCL.validate(release, manifest, embedded_packages)
    literal_packages = {}
    for sha, expected in LITERAL.policy()['packages'].items():
        require(sha in restored and all(restored[sha][k] == expected[k] for k in FP), 'Actual original SDK6 literal package required')
        literal_packages[sha] = release / restored[sha]['path']
    literal = LITERAL.validate(release, manifest, literal_packages); layout_by_path = {r['path']: r for r in proof['layout']}
    for name, expected in literal['products'].items():
        row = layout_by_path.get(name); require(row is not None and artifacts[row['input']]['sha256'] == expected['packageSha256']
            and row['member'] == (expected['member'] or '') and all(actual[name][k] == expected['fingerprint'][k] for k in ('bytes', 'sha256')),
            'SDK6 reference/manifest/template input must retain its actual original package/member and independently validated source')
    require(G.PACKAGE_SHA in restored, 'Original SDK6 Globbing package must actually be restored')
    globbing = G.validate(release, manifest, release / restored[G.PACKAGE_SHA]['path'])
    translation_source = T.validate_translation_data(release, record, manifest)
    translations = inventories.get('translations', {})
    require(len(translations) == 286 and translations.keys() == translation_source.keys()
            and all(all(translations[n][k] == fp[k] for k in ('bytes', 'sha256')) for n, fp in translation_source.items()),
            'All286 original SDK6 translations require independent source/resource and exact archive correspondence')
    validate_managed_shipping(release, proof, roots, actual, transformed, compiler, restored, framework, attributed, globbing, translations, localization, embedded_policy)
    mc = module('sdk6_complete_observed_compiler_inputs', 'musl_legacy_compiler_inputs.py')
    compiler_sources = mc.validate(release, manifest, dict({name: value['proof'] for name, value in compiler.items()}, installer=replay))
    native = NATIVE_INPUTS.validate(release, manifest, record, artifacts, actual=actual, stages=stages, prepare=prepare)
    return dict(actual=actual, roots=roots, proof=proof, compiler=compiler, transformed=transformed,
        framework=framework, attributed=attributed, globbing=globbing, localization=localization, literal=literal,
        embedded=embedded_policy, compilerSources=compiler_sources, generated=generated,
        nugetSource=nuget_source, vstestSource=vstest_source, native=native, sdkSources=sdk_sources, installerSources=installer_sources,
        stageIndependentPrefixOnly=True, qualificationAllowed=False, sourceAdmissionAllowed=False)


def validate_build_container(call, inner, record, prepare, manifest, *, environment, workdir='/tmp'):
    """Require the exact normal SDK6 worker envelope, without option aliases."""
    roots = {row['name']: row for row in manifest['roots']}
    workspace = str(PurePosixPath(roots['sdk']['originalPath']).parents[2])
    delivery = str(PurePosixPath(roots['actual-managed-package-inputs']['originalPath']).parent)
    project = roots['orchestration']['originalPath']
    require(all(path.startswith('/') and str(PurePosixPath(path)) == path for path in (workspace, delivery, project))
            and roots['sdk']['originalPath'] == workspace + '/work/sdk-build/sdk'
            and roots['installer']['originalPath'] == workspace + '/work/installer', 'Exact SDK6 normal workspace/source roots required')
    prefix = B.P.DOCKER_ENGINE + ['run', '--rm', '--network=host', '--user']
    require(call[:len(prefix)] == prefix and len(call) > len(prefix)
            and re.fullmatch('[1-9][0-9]*:[1-9][0-9]*', call[len(prefix)]), 'Exact SDK6 native normal container user/engine required')
    diagnostics = [call[i + 1] for i, value in enumerate(call[:-1]) if value == '--volume' and call[i + 1].endswith(':/diag')]
    require(len(diagnostics) == 1 and re.fullmatch(re.escape(delivery) + r'/reports/diagnostics/container-[0-9]{4,}:/diag', diagnostics[0]),
            'Exact SDK6 normal diagnostics mount required')
    base_environment = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2', PYTHONDONTWRITEBYTECODE='1')
    expected = prefix + [call[len(prefix)], '--cap-drop=all', '--security-opt=no-new-privileges']
    expected += [value for name, data in base_environment.items() for value in ('--env', name + '=' + data)]
    expected += ['--volume', project + ':/project:ro', '--volume', delivery + ':/delivery',
        '--volume', workspace + '/home:/home/build', '--workdir', workdir, '--volume', workspace + ':/work']
    expected += [value for name, data in environment.items() for value in ('--env', name + '=' + data)]
    expected += ['--volume', diagnostics[0], '--env', 'MSBUILDDEBUGPATH=/diag', '--env', 'MSBUILDDEBUGCOMM=1', prepare['imageId']]
    require(call == expected + B.P.Producer.observed_command(inner), 'Exact SDK6 normal image/network/source/bootstrap/environment/command envelope required')


def validate_reader_sources(release, archived):
    directory = release / 'reports/build/reader'
    require(directory.is_dir() and all(not path.is_symlink() and path.name in {'Program.cs', 'Reader.csproj', 'NuGet.Config', 'bin', 'obj'}
            for path in directory.iterdir()), 'Only the two copied SDK6 Reader sources, clear configuration and build outputs are permitted')
    for parent in (directory, directory.parent, directory.parent.parent, release):
        require(not any((parent / name).exists() for name in ('Directory.Build.props', 'Directory.Build.targets',
            'Directory.Packages.props', 'Directory.Build.rsp')), 'An undeclared SDK6 Reader build input is present')
    for name in ('Program.cs', 'Reader.csproj'):
        require(CE.ordinary(directory / name).read_bytes() == archived['orchestration/scripts/musl-legacy-reader/' + name],
                'Copied SDK6 Reader source must equal the archived orchestration source: ' + name)
    require(CE.ordinary(directory / 'NuGet.Config').read_bytes() == READER_CONFIG, 'Only the exact clear-only SDK6 Reader NuGet configuration is permitted')


def validate_replay_copies(release, proof):
    result = {}
    for component in REPLAY_COMPONENTS:
        original = release / 'reports/build' / (component + '-replay')
        status = load(Path(str(original) + '-status.json'))
        binlog = fingerprint(CE.ordinary(release / 'reports/build' / (component + '.binlog')))
        tasks = fingerprint(CE.ordinary(Path(str(original) + '-tasks.jsonl')))
        require(status.get('schemaVersion') == 1 and status.get('completedReplay') is True and status.get('buildSucceeded') is True
                and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0 and status.get('failure') is None
                and type(status.get('completedSelectedTasks')) is int and status['completedSelectedTasks'] > 0
                and status.get('inputSha256') == binlog['sha256'], 'Actual completed SDK6 Reader status must bind its original binlog: ' + component)
        descriptor = (proof['installerBuildReplay'] if component == 'installer' else proof['localizationBuildReplay']
            if component == MS.SOURCE_ROOT else proof['componentCompilerProofs'][component])
        consumed = load(checked(release, descriptor))
        require(consumed.get('completedReplay') is True and consumed.get('buildSucceeded') is True and consumed.get('unfinishedTasks') == 0
                and {key: consumed['tasks'][key] for key in FP} == tasks
                and all(fingerprint(checked(release, consumed['tasks']))[key] == tasks[key] for key in FP),
                'SDK6 compiler/installer proof must consume the exact original Reader task output: ' + component)
        if component == 'installer': require(consumed.get('inputSha256') == binlog['sha256'], 'SDK6 installer replay binlog differs from Reader input')
        else:
            require({key: consumed['binlog'][key] for key in FP} == binlog
                    and fingerprint(checked(release, consumed['binlog'])) == binlog, 'SDK6 compiler proof binlog differs from actual Reader input')
        result[component] = dict(status=dict(path=str(original.relative_to(release)) + '-status.json', **fingerprint(Path(str(original) + '-status.json'))),
            binlog=binlog, tasks=tasks)
    return result


def validate_reader_boundary(release, record, prepare, stages, manifest):
    wanted = {'orchestration/scripts/musl-legacy-reader/' + name for name in ('Program.cs', 'Reader.csproj')}
    archived, _ = source_archive_members(release, manifest, wanted); validate_reader_sources(release, archived)
    bootstrap = '/work/work/sdk-build/sdk/.dotnet'; sdk = bootstrap + '/sdk/6.0.135'
    build = [bootstrap + '/dotnet', 'build', '/delivery/reports/build/reader/Reader.csproj', '--configuration', 'Release',
        '/p:BootstrapMajor=6', '/p:BootstrapSdkDir=' + sdk, '/p:UseSharedCompilation=false']
    commands = [build] + [[bootstrap + '/dotnet', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll',
        '/delivery/reports/build/' + component + '.binlog', sdk, '/delivery/reports/build/' + component + '-replay'] for component in REPLAY_COMPONENTS]
    calls = [call for call in stages['build']['commands'] if '/delivery/reports/build/reader/Reader.csproj' in call
        or '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll' in call]
    require(len(calls) == 6, 'Exactly one SDK6 Reader build and five actual replay invocations required')
    for inner, call in zip(commands, calls):
        validate_build_container(call, inner, record, prepare, manifest, environment=dict(DOTNET_ROOT=bootstrap))
    return validate_replay_copies(release, load(release / 'reports/legacy-construction.json'))


def installer_command(record):
    arch = 'arm64' if record['architecture'] == 'aarch64' else 'x64'
    return ['./build.sh', '--configuration', 'Release', '--restore', '--build', '--pack', '--projects',
        '/work/work/installer/src/redist/redist.csproj', '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true',
        '/p:DotNetBuildOffline=true', '/p:PublicBaseURL=/work/inputs/installer-components/',
        '/p:MicrosoftDotnetToolsetInternalPackageVersion=' + SDK + '-ci', '/p:Version=' + SDK,
        '/p:Architecture=' + arch, '/p:OSName=linux-musl', '/p:PortableOSName=linux-musl', '/p:Rid=' + record['targetRid'],
        '/p:HostRid=' + record['targetRid'], '/p:SharedFrameworkRid=' + record['targetRid'], '/p:CoreSetupRid=' + record['targetRid'],
        '/p:Crossgen2Rid=' + record['targetRid'], '/p:UsePortableLinuxSharedFramework=false', '/p:SkipBuildingInstallers=true',
        '/p:RestoreAdditionalProjectSources=/work/inputs/bootstrap-feed', '/p:UseSharedCompilation=false', '/m:2',
        '/bl:/delivery/reports/build/installer.binlog', '/p:CommunityMuslComponentRoot=/work/inputs/installer-components',
        '/p:CommunityMuslNativeTraceProvider=/work/inputs/installer-components/libcoreclrtraceptprovider.so',
        '/p:CommunityMuslNativeRuntimeRoot=/work/inputs/installer-components/native-runtime', '/p:EmitCompilerGeneratedFiles=true']


def validate_installer_boundary(release, record, prepare, stages, manifest):
    calls = [call for call in stages['build']['commands'] if '/work/work/installer/src/redist/redist.csproj' in call]
    require(len(calls) == 1, 'Exactly one original SDK6 installer redist build required')
    validate_build_container(calls[0], installer_command(record), record, prepare, manifest,
        environment=dict(DOTNET_ROOT='/work/work/installer/.dotnet', DOTNET_INSTALL_DIR='/work/work/installer/.dotnet',
            NUGET_PACKAGES='/work/work/installer/.packages'), workdir='/work/work/installer')


def validate_tooling_boundary(release, record, prepare, stages, manifest):
    """Bind the actual SDK graph invocation to the frozen builder and inputs."""
    BOUNDARY.exact_sdk6(record)
    directory = release / 'reports/build/sdk-tooling'
    invocation, image = load(directory / 'invocation.json'), load(directory / 'image.json')
    call = invocation.get('command'); native = B.P.identity(record['architecture'])
    require(isinstance(call, list) and stages['build']['commands'].count(call) == 1
            and invocation.get('diagnosticEngine') == 'normal-rootful-docker'
            and invocation.get('cpu') == native['machine'] and invocation.get('network') == 'host'
            and invocation.get('qualificationAllowed') is invocation.get('sourceAdmissionAllowed') is False
            and len(image) == 1 and image[0].get('Id') == prepare['imageId']
            and image[0].get('Architecture') == native['image'] and image[0].get('Os') == 'linux',
            'Actual SDK6 tooling command and frozen native builder image required')
    image_arg = prepare['imageId'].removeprefix('sha256:')
    require(call[:len(B.P.DOCKER_ENGINE) + 1] == B.P.DOCKER_ENGINE + ['run'] and call.count(image_arg) == 1
            and [arg for arg in call if arg.startswith('--network')] == ['--network=host']
            and not any(arg.startswith(('--mount', '--volumes-from', '--volume=', '-v', '--device', '--entrypoint')) for arg in call),
            'SDK6 tooling must use the original native builder and explicit volumes')
    cpu = 'arm64' if record['architecture'] == 'aarch64' else 'x64'
    inner = ['./build.sh', '--configuration', 'Release', '--pack', '--projects', '/source/source-build.slnf',
        '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true', '/p:Architecture=' + cpu,
        '/p:OSName=linux-musl', '/p:Rid=' + record['targetRid'], '/p:PortableBuild=true', '/p:CrossBuild=false',
        '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true', '/m:2',
        '/bl:/source/artifacts/log/Release/community-sdk-producer-source-graph.binlog', '--rebuild',
        '/p:CommunityMuslNuGetTranslationRoot=/nuget-translation-data/resources', '/p:MicrosoftNETTestSdkPackageVersion=17.0.3-dev',
        '/p:MicrosoftTestPlatformCLIPackageVersion=17.0.3-dev', '/p:MicrosoftTestPlatformBuildPackageVersion=17.0.3-dev',
        '/p:MicrosoftBuildLocalizationPackageVersion=17.0.4-cbodotnet.1', '/p:RestoreAdditionalProjectSources=/bootstrap-feed']
    require(call[call.index(image_arg) + 1:] == B.P.Producer.observed_command(inner),
            'Exact original SDK6 source-build graph and source-package properties required')
    roots = {row['name']: row for row in manifest['roots']}
    sdk_host = roots['sdk']['originalPath']; project_host = roots['orchestration']['originalPath']
    delivery_host = str(PurePosixPath(roots['actual-managed-package-inputs']['originalPath']).parent)
    feed_host = str(PurePosixPath(sdk_host).parents[2] / 'inputs/bootstrap-feed')
    mounts, environment = {}, {}
    for index, arg in enumerate(call[:call.index(image_arg)]):
        require(not arg.startswith('-e') and (not arg.startswith('--env') or arg == '--env'),
                'SDK6 tooling requires explicit reviewed environment options')
        if arg == '--volume':
            fields = call[index + 1].split(':')
            require(len(fields) in (2, 3) and fields[1] not in mounts
                    and fields[0].startswith('/') and str(PurePosixPath(fields[0])) == fields[0],
                    'Unique normalized SDK6 tooling mount required')
            mounts[fields[1]] = (fields[0], fields[2] if len(fields) == 3 else 'rw')
        if arg == '--env':
            key, separator, value = call[index + 1].partition('=')
            require(separator and key not in environment, 'Unique explicit SDK6 tooling environment required'); environment[key] = value
    diagnostic = mounts.pop('/diag', (None, None))
    require(diagnostic[1] == 'rw' and isinstance(diagnostic[0], str)
            and re.fullmatch(re.escape(delivery_host) + r'/reports/diagnostics/container-[0-9]{4,}', diagnostic[0])
            and mounts == {'/source': (sdk_host, 'rw'), '/project': (project_host, 'ro'), '/delivery': (delivery_host, 'rw'),
                '/bootstrap-feed': (feed_host, 'ro'), '/nuget-translation-data': (roots['nuget-translation-data']['originalPath'], 'ro')},
            'SDK6 tooling source/bootstrap-feed/translation/orchestration mounts differ from archived inputs')
    require(environment == dict(HOME='/tmp', DOTNET_ROOT='/source/.dotnet', DOTNET_INSTALL_DIR='/source/.dotnet',
        DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', NUGET_PACKAGES='/source/.packages',
        CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS='true', DOTNET_PROCESSOR_COUNT='2', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1'),
        'SDK6 tooling inherited an unreviewed compiler/bootstrap/runtime environment override')


def validate(release):
    """Validate one SDK6 normal producer; publication remains a separate gate."""
    release = B.P.ordinary(release); record = load(release / 'producer-validation.json')
    require(record.get('schemaVersion') == 2 and record.get('producerRevision') == 1
            and record.get('kind') == 'musl-sdk-producer-validation' and record.get('status') == 'passed'
            and record.get('sdkVersion') == SDK and record.get('diagnosticPodman') is False
            and record.get('diagnosticPtrace') is False and record.get('qualificationAllowed') is False
            and record.get('sourceAdmissionAllowed') is False and record.get('releaseAvailabilityAllowed') is False,
            'Only an exact non-diagnostic SDK6 normal producer proof is accepted')
    BOUNDARY.exact_sdk6(record)
    require(record.get('libc') == 'musl' and record.get('allRequiredStages') == list(BOUNDARY.STAGES)
            and record.get('sourceCommit') == POLICY['installer'] and record.get('sdkSourceCommit') == POLICY['sdk']
            and record.get('runtimeSourceCommit') == POLICY['runtimeCommit']
            and re.fullmatch('[a-f0-9]{40}', record.get('projectCommit', ''))
            and re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', record.get('buildId', ''))
            and all(re.fullmatch('[1-9][0-9]*', record.get(key, '')) for key in ('runId', 'runAttempt')),
            'Exact native SDK6 source/build/run/stage identity required')
    B.P.delivery_index(release, record.get('files'))
    producer = load(release / 'producer-sdk.json')
    identity = ('sdkVersion', 'architecture', 'targetRid', 'libc', 'sourceCommit', 'sdkSourceCommit',
        'runtimeSourceCommit', 'projectCommit', 'runId', 'runAttempt', 'producerRevision')
    require(producer.get('schemaVersion') == 1 and producer.get('kind') == 'musl-sdk-build'
            and all(producer.get(key) == record[key] for key in identity), 'SDK6 producer archive identity differs')
    sdk = producer['sdk']; expected = 'cbodotnet-sdk-' + SDK + '-linux-musl-' + record['architecture'] + '-build.' + record['runId'] + '.tar.gz'
    require(set(sdk) == FP | {'name'} and sdk['name'] == expected and {k: sdk[k] for k in FP} == fingerprint(release / portable(expected)),
            'Actual final SDK6 archive name/bytes differ')
    record = dict(record, sdk=sdk)
    path = ROOT / 'profiles' / ('dotnet-' + SDK + '-linux-musl-' + record['architecture'] + '.json')
    profile = load(path); prepare = load(release / 'reports/prepare/identity.json')
    require(prepare.get('profile') == dict(path=path.name, **fingerprint(path))
            and all(prepare.get(key) == record[key] for key in identity if key != 'producerRevision')
            and prepare.get('buildId') == record['buildId'] and prepare.get('emulation') is False
            and prepare.get('nativeArchitecture') == B.P.identity(record['architecture'])['machine']
            and prepare.get('diagnosticPodman') is False and prepare.get('diagnosticPtrace') is False,
            'Actual native SDK6 preparation/profile identity differs')
    require(profile.get('sdkVersion') == SDK and profile.get('source', {}).get('commit') == POLICY['installer']
            and profile.get('target') == dict(rid=record['targetRid'], libc='musl')
            and profile.get('build', {}).get('sourceOnly') is False and profile['build'].get('crossBuild') is False
            and profile['build'].get('portableBuild') is True and profile.get('stockAlpine', {}).get('pointRelease') == '3.24.4'
            and profile.get('bootstrap', {}).get('version') == POLICY['bootstrap'], 'Original SDK6 source/import/platform policy differs')
    bootstrap = load(release / 'reports/prepare/bootstrap.json')
    require(all(bootstrap.get(key) == profile['bootstrap'][key] for key in ('version', 'rid', 'url', 'sha512')),
            'Exact original native SDK6 bootstrap identity differs')
    stages = BOUNDARY.validate_stages(release, record, prepare)
    require(producer.get('imageId') == prepare.get('imageId'), 'Actual SDK6 source builder image differs')
    BOUNDARY.validate_verification_boundary(release, record, prepare, stages)
    packer = module('sdk6_normal_used_source_contract', 'package-used-source.py')
    manifest = packer.verify(SimpleNamespace(release_dir=release, expected_project_commit=record['projectCommit'],
        expected_run_id=record['runId'], expected_run_attempt=record['runAttempt'], expected_target_rid=record['targetRid']))
    BOUNDARY.validate_source_workers(record, prepare, stages, manifest)
    validate_tooling_boundary(release, record, prepare, stages, manifest)
    validate_reader_boundary(release, record, prepare, stages, manifest)
    validate_installer_boundary(release, record, prepare, stages, manifest)
    BOUNDARY.validate_scan_applicability(release, record, manifest)
    validate_construction(release, record, manifest, stages=stages, prepare=prepare)
    BOUNDARY.validate_original_smoke(release, record, manifest)
    BOUNDARY.validate_lttng(release, record, prepare, stages)
    BOUNDARY.validate_functional(release, record, stages)
    report = load(release / 'reports/verify/elf.json'); native = B.P.identity(record['architecture'])
    loader = '/lib/ld-musl-' + native['machine'] + '.so.1'
    require(report.get('status') == 'passed' and report.get('libc') == 'musl' and report.get('architecture') == record['architecture']
            and report.get('loader') == loader and report.get('uid', 0) > 0 and report.get('foreignTargetExceptions') == []
            and report.get('closure', {}).get('status') == 'passed' and report['closure'].get('nonHostElfCount') == 0,
            'Complete native SDK6 stock-provider ELF closure required')
    BOUNDARY.validate_elf_closure(release, record, profile, report)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--release-dir', type=Path, required=True)
    args = parser.parse_args(); validate(args.release_dir)
