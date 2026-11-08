"""SDK6 source-built localization, original XLF and actual compiler proof.

The genuine downstream package keeps its own version. Its unavailable original
publisher package is never reconstructed. Shared helpers only parse bytes/tasks.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import zipfile

ROOT_NAME = 'sdk6-localization-source-inputs'
ROLE = 'sdk6-source-built-localization-package-and-build-sdk-inputs'
SOURCE_ROOT = 'msbuild-localization'
COMMIT = '85d71072f8fa22cc761d6b65954da263364bee4d'
ARCADE_COMMIT = 'bd9b4590681e602535ed414e98a17e6ba121dca4'
POLICY_SHA = '3163712f58a7e087c94df3597d4b3616f364c71b0b1a16842be042f59ffab7de'
VERSION = '17.0.4-cbodotnet.1'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 localization path required')
    return path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def policy():
    raw = Path(__file__).with_name('musl-legacy6-localization-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK6 localization policy bytes differ')
    p = json.loads(raw)
    require(p['schemaVersion'] == 1 and p['sdkVersion'] == '6.0.136' and p['packageVersion'] == VERSION
            and p['sources']['msbuild']['commit'] == COMMIT and p['sources']['arcade']['commit'] == ARCADE_COMMIT
            and p['originalPublisherVersionReused'] is p['sourceCSharpChanged'] is p['targetFrameworksChanged'] is False
            and len(p['resources']) == 52, 'Isolated SDK6 localization source/version contract required')
    return p


def original_global(raw):
    before, after = b'6.0.0-beta.24176.9', b'6.0.0-beta.24204.4'
    require(raw.count(before) == 1 and after not in raw, 'Exact original SDK6 Arcade declaration required')
    return raw.replace(before, after)


def package_members(raw):
    p = policy(); B = module('sdk6_localization_byte_primitives', 'musl_legacy_admission.py')
    X = module('sdk6_localization_xml_primitives', 'musl_legacy_msbuild_resources.py')
    require(len(raw) <= 8 * 1024**2, 'Bounded genuine SDK6 localization package required')
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and len(names) <= 80, 'Unique bounded localization ZIP required')
        for name in names: B.portable(name)
        specs = [name for name in names if name.endswith('.nuspec')]
        require(len(specs) == 1, 'One genuine localization nuspec required')
        node = X.xml(archive.read(specs[0])).find('{*}metadata'); license_node = node.find('{*}license')
        require(node.findtext('{*}id') == p['packageId'] and node.findtext('{*}version') == VERSION
                and node.find('{*}repository') is None and license_node is not None
                and license_node.get('type') == 'expression' and license_node.text == 'MIT',
                'Genuine downstream localization identity and original license required')
        actual = {name for name in names if name.lower().endswith(('.dll', '.exe'))}
        require(actual == p['resources'].keys(), 'All52 original localization satellites required')
        for name in sorted(actual):
            require(archive.getinfo(name).file_size <= 1024**2, 'Bounded localization satellite required')
            data = archive.read(name); identity = B.MANAGED.inspect(data); satellite = B.resource_only_pe(data)
            require(identity['assemblyVersion'] == '15.1.0.0' and identity['publicKeyToken'] == 'b03f5f7f11d50a3a'
                    and name == 'lib/netstandard1.3/' + satellite['culture'] + '/' + satellite['assemblyName'] + '.dll'
                    and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0,
                    'Original resource-only localization ABI/culture/layout differs')
            resources = {}
            for resource in satellite['resources']:
                require(resource['name'] not in resources, 'Duplicate satellite resource')
                values = B.resource_strings(resource['data']); expected = p['resources'][name].get(resource['name'])
                keys = sorted(values)
                require(expected is not None and len(keys) == expected['keyCount']
                        and hashlib.sha256(json.dumps(keys, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest() == expected['keysSha256'],
                        'Complete original localization resource key set required')
                resources[resource['name']] = values
            require(resources.keys() == p['resources'][name].keys(), 'Complete original resource stream set required')
            result[name] = dict(fingerprint=fingerprint(data), resources=resources)
    return result


def build_sdk(raw):
    p = policy(); expected = p['actualArcade']
    require(fingerprint(raw) == {k: expected[k] for k in FP}, 'Exact reviewed public Arcade build input required')
    X = module('sdk6_localization_arcade_xml', 'musl_legacy_msbuild_resources.py')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist(); specs = [name for name in names if name.endswith('.nuspec')]
        require(len(names) == len(set(names)) and len(specs) == 1, 'Unique original Arcade package required')
        node = X.xml(archive.read(specs[0])).find('{*}metadata'); repo = node.find('{*}repository')
        require(node.findtext('{*}id') == 'Microsoft.DotNet.Arcade.Sdk' and node.findtext('{*}version') == expected['version']
                and repo is not None and repo.get('commit') == ARCADE_COMMIT
                and node.findtext('{*}license') == 'MIT', 'Original public Arcade source/license declaration differs')


def bodies(package_raw, arcade_raw):
    package_members(package_raw); build_sdk(arcade_raw)
    origin = dict(schemaVersion=1, sdkVersion='6.0.136', policySha256=POLICY_SHA,
        package=fingerprint(package_raw), sourceCommit=COMMIT, buildSdk=fingerprint(arcade_raw), buildSdkCommit=ARCADE_COMMIT,
        packageVersion=VERSION, originalPublisherVersionReused=False, sourceCSharpChanged=False, targetFrameworksChanged=False,
        actualCompilerAndSdkConsumptionRequireIndependentGate=True)
    return {'packages/localization.nupkg': package_raw, 'build-inputs/arcade.nupkg': arcade_raw,
            'origin.json': (json.dumps(origin, indent=2) + '\n').encode()}


def prepare(package, arcade_package, destination):
    data = bodies(ordinary(package).read_bytes(), ordinary(arcade_package).read_bytes()); destination = ordinary(destination)
    require(not destination.exists(), 'Fresh SDK6 localization source input tree required')
    destination.mkdir(parents=True)
    for name, raw in data.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def emit(context, release, roots):
    C = module('sdk6_localization_compiler_primitives', 'musl_legacy6_component_evidence.py'); B = C.B
    entry = context['localizationReplay']; source = ordinary(roots[SOURCE_ROOT]['path']); release = ordinary(release)
    require(roots[SOURCE_ROOT]['commit'] == COMMIT and len(context['localizationPackages']) == 1, 'Exact original localization source/package required')
    status = json.loads(ordinary(entry['status']).read_bytes())
    require(status['completedReplay'] is status['buildSucceeded'] is True and status['unfinishedTasks'] == 0
            and status['observedTaskNames'].get('Csc') == 72, 'All72 original localization compilations require completed replay')
    log = C.retain(release, entry['binlog'], 'reports/build/msbuild-localization.binlog')
    require(status['inputSha256'] == log['sha256'], 'Localization replay differs from actual binlog')
    tasks_desc = C.retain(release, entry['tasks'], 'reports/build/msbuild-localization-tasks.jsonl')
    tasks = B.read_tasks(release / tasks_desc['path']); observed = C.compiler_rows(tasks, entry['sourceMountRoot']); by_sha = {}
    for row in observed:
        path = ordinary(source / PurePosixPath(row['outputPath']).relative_to(entry['sourceMountRoot']))
        by_sha.setdefault(fingerprint(path.read_bytes())['sha256'], []).append(row)
    package = ordinary(context['localizationPackages'][0]); products = package_members(package.read_bytes())
    descriptor = C.retain(release, package, 'imported-inputs/' + fingerprint(package.read_bytes())['sha256'] + '.nupkg')
    outputs = []
    for member, item in products.items():
        candidates = [row for row in by_sha.get(item['fingerprint']['sha256'], []) if PurePosixPath(row['outputPath']).name == PurePosixPath(member).name]
        require(candidates, 'Localization satellite has no actual compiler output: ' + member)
        row = sorted(candidates, key=lambda row: row['context'])[0]
        outputs.append(dict(member=member, fingerprint=item['fingerprint'], **row))
    proof = dict(schemaVersion=1, kind='sdk6-localization-compiler-proof', sdkVersion='6.0.136', sourceRoot=SOURCE_ROOT, sourceCommit=COMMIT,
        sourceMountRoot=entry['sourceMountRoot'], binlog=log, tasks=tasks_desc, package=descriptor, compiledOutputs=outputs,
        completedReplay=True, buildSucceeded=True, unfinishedTasks=0, transformations=[])
    return C.write(release, 'reports/build/msbuild-localization-compiler-proof.json', proof)


def validate_compiler(release, descriptor):
    C = module('sdk6_localization_validate_compiler', 'musl_legacy6_component_evidence.py'); B = C.B
    proof = json.loads(B.checked(release, descriptor).read_bytes())
    require(proof['schemaVersion'] == 1 and proof['kind'] == 'sdk6-localization-compiler-proof' and proof['sdkVersion'] == '6.0.136'
            and proof['sourceRoot'] == SOURCE_ROOT and proof['sourceCommit'] == COMMIT and proof['completedReplay'] is proof['buildSucceeded'] is True
            and proof['unfinishedTasks'] == 0 and proof['transformations'] == [], 'Closed SDK6 localization compiler proof required')
    B.checked(release, proof['binlog']); tasks = B.read_tasks(B.checked(release, proof['tasks']))
    observed = C.compiler_rows(tasks, proof['sourceMountRoot']); products = package_members(B.checked(release, proof['package']).read_bytes())
    keys = {(r['context'], r['outputPath'], r['outputKind'], r['commandParameter']) for r in observed}; actual = {}
    for row in proof['compiledOutputs']:
        require(set(row) == {'member', 'fingerprint', 'context', 'outputPath', 'outputKind', 'commandParameter'}
                and (row['context'], row['outputPath'], row['outputKind'], row['commandParameter']) in keys and row['outputKind'] == 'assembly'
                and PurePosixPath(row['outputPath']).name == PurePosixPath(row['member']).name
                and tasks[row['context']]['taskFile'].endswith('/sdk/6.0.135/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.targets'),
                'Localization member must bind its actual trusted satellite compiler command')
        require(row['member'] not in actual and row['member'] in products and row['fingerprint'] == products[row['member']]['fingerprint'],
                'Actual localization compiler/package member bytes differ')
        actual[row['member']] = row['fingerprint']
    require(actual.keys() == products.keys(), 'All52 actual satellite compiler bindings required')
    return dict(proof=proof, members=actual)


def validate(release, manifest, package):
    P = module('sdk6_localization_source_archive', 'package-used-source.py'); B = module('sdk6_localization_archive_bytes', 'musl_legacy_admission.py')
    X = module('sdk6_localization_source_xml', 'musl_legacy_msbuild_resources.py'); p = policy(); release = ordinary(release)
    roots = {}
    for key, expected in p['sources'].items():
        matches = [row for row in manifest['roots'] if row.get('kind') in ('git', 'git-export') and row.get('commit') == expected['commit']
                   and row.get('tree') == expected['tree'] and not row.get('deleted') and (key != 'msbuild' or row['name'] == SOURCE_ROOT)]
        require(len(matches) == 1, 'Complete exact SDK6 localization source root required: ' + key); roots[key] = matches[0]
    matches = [row for row in manifest['roots'] if row['name'] == ROOT_NAME]
    require(len(matches) == 1 and matches[0]['kind'] == 'tree' and matches[0].get('role') == ROLE and matches[0].get('commit') is None,
            'Actual localization/build input data requires separate non-Git role')
    prefixes = {row['name'] + '/': key for key, row in roots.items()}; indexed = {}; baselines = {key: {} for key in roots}
    with (release / 'sources' / B.portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = B.portable(row['path']); selected = next(((pre, key) for pre, key in prefixes.items() if name.startswith(pre)), None)
            if selected:
                prefix, key = selected; relative = name[len(prefix):]
                require(name not in indexed and row.get('baseline'), 'Unique original localization source baseline required')
                baselines[key][relative] = row['baseline']; indexed[name] = (key, relative, row)
            elif name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate localization data index'); indexed[name] = (None, name[len(ROOT_NAME) + 1:], row)
    for key, baseline in baselines.items():
        for sub in roots[key].get('submodules', []): baseline[sub['path']] = dict(mode='160000', blob=sub['commit'])
        require(P.baseline_tree(baseline) == p['sources'][key]['tree'], 'Full original localization/build SDK source tree differs')
    seen, data, sources = set(), {}, {key: {} for key in roots}
    with tarfile.open(release / 'sources' / B.portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            key, name, expected = indexed[entry.name]
            require(entry.name not in seen and entry.isfile() and entry.size <= 32 * 1024**2, 'Unique bounded localization source/data member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k: expected[k] for k in FP}, 'Archived localization source/input bytes differ')
            if key:
                anchor = p['sources'][key]['files'].get(name); blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                if key == 'msbuild' and name == 'global.json':
                    original = raw.replace(b'6.0.0-beta.24204.4', b'6.0.0-beta.24176.9')
                    require(original_global(original) == raw and fingerprint(original) == {k: anchor[k] for k in FP}
                            and expected['baseline']['blob'] == anchor['gitBlob'], 'Only reviewed build-only Arcade substitution is allowed')
                else:
                    require(P.pristine_blob(expected, blob, raw if name.lower().endswith(('.cmd', '.bat')) else None),
                            'Original SDK6 localization/build SDK source was changed')
                    if anchor:
                        require(fingerprint(raw) == {k: anchor[k] for k in FP} and expected['baseline']['blob'] == anchor['gitBlob'],
                                'Original localization XLF/project/license anchor differs')
                if anchor: sources[key][name] = raw
            else: data[name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and all(sources[k].keys() == p['sources'][k]['files'].keys() for k in roots),
            'Complete original localization/build source anchor coverage required')
    require(set(data) == {'packages/localization.nupkg', 'build-inputs/arcade.nupkg', 'origin.json'}
            and data['packages/localization.nupkg'] == ordinary(package).read_bytes()
            and data == bodies(data['packages/localization.nupkg'], data['build-inputs/arcade.nupkg']), 'Exact actual source-retained localization/build input set required')
    products = package_members(data['packages/localization.nupkg']); total = 0
    for member, product in products.items():
        for resource, values in product['resources'].items():
            source = p['resources'][member][resource]['sourceXlf']; tree = X.xml(sources['msbuild'][source]); translations = {}
            for unit in tree.iter():
                if unit.tag.rsplit('}', 1)[-1] != 'trans-unit': continue
                key = unit.get('id'); targets = unit.findall('{*}target')
                require(key and key not in translations and len(targets) == 1, 'Unique original XLF translation required')
                translations[key] = ''.join(targets[0].itertext())
            for key, value in values.items():
                require(key in translations and translations[key] == value['value'], 'Compiled localization differs from original XLF text')
                total += 1
    require(total == 19929, 'All19929 original translated resource strings required')
    return dict(kind='sdk6-source-built-msbuild-localization', sourceRoot=SOURCE_ROOT, sourceCommit=COMMIT,
        buildSdkSourceRoot=roots['arcade']['name'], buildSdkSourceCommit=ARCADE_COMMIT, dataRoot=ROOT_NAME,
        packageVersion=VERSION, packageFingerprint=fingerprint(data['packages/localization.nupkg']),
        products={name: value['fingerprint'] for name, value in products.items()}, sourceStrings=total,
        originalPublisherVersionReused=False, actualCompilerAndSdkConsumptionRequireIndependentGate=True)
