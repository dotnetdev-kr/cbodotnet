"""Reconstruct SDK5's three derived compiler inputs from archived originals.

This validates imported compiler inputs, not a local compiler or R2R build.
The complete pristine source trees, exact SDK archive and baseline packages
are checked before deterministic package reconstruction is compared.
"""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import musl_legacy5_compiler_inputs as C
import musl_legacy5_component_evidence as CE

B = CE.B
require, portable = B.require, B.portable
ROOT_NAME = 'derived-compiler-inputs'
ROLE = 'explicit-original-sdk-derived-compiler-inputs-and-preferred-source-definitions'
CONSTRUCTOR_SHA256 = '4ed1f6d7395588d76249a848511899a7e567f8d3ea6ff2d38cb99a7c6f95885e'


def constructor_policy():
    require(CE.fingerprint(CE.ordinary(Path(C.__file__)))['sha256'] == CONSTRUCTOR_SHA256
            and C.SDK == CE.SDK and set(C.SOURCES) == {'fsharp', 'roslyn', 'roslyn-codestyle', 'compiler-framework'},
            'Exact distinct SDK5 derived compiler constructor required')


def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def source_roots(manifest):
    selected = {}
    for name, (repository, commit) in C.SOURCES.items():
        matches = [row for row in manifest['roots'] if row.get('kind') in ('git', 'git-export') and row.get('commit') == commit]
        require(len(matches) == 1, 'One complete original SDK5 compiler source root required: ' + name)
        row = matches[0]
        require(not row.get('exclude') and not row.get('deleted') and row.get('role') in ('build-source', 'source-for-serviced-imported-package'),
                'Unexcluded complete SDK5 compiler corresponding source required')
        raw = base64.b64decode(row.get('commitObjectBase64', ''), validate=True)
        require(git_object('commit', raw) == commit and raw.splitlines()[0] == ('tree ' + row['tree']).encode(),
                'Authenticated original SDK5 compiler commit/tree required')
        selected[name] = row
    return selected


def archived_sources(release, manifest):
    selected = source_roots(manifest); prefixes = {row['name'] + '/': name for name, row in selected.items()}
    indexed, baselines = {}, {name: {} for name in selected}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); path = portable(row['path']); match = next(((prefix, name) for prefix, name in prefixes.items() if path.startswith(prefix)), None)
            if match is None: continue
            prefix, name = match; relative = portable(path[len(prefix):]); baseline = row.get('baseline')
            require(path not in indexed and isinstance(baseline, dict) and set(baseline) == {'blob', 'mode'}
                    and baseline['mode'] in ('100644', '100755') and row.get('mode') == baseline['mode'],
                    'Every original SDK5 compiler source file needs its original Git blob and mode')
            indexed[path] = (name, relative, row); baselines[name][relative] = baseline
    spec = importlib.util.spec_from_file_location('sdk5_compiler_source_git_tree_decoder', Path(__file__).with_name('package-used-source.py'))
    packer = importlib.util.module_from_spec(spec); spec.loader.exec_module(packer)
    for name, rows in baselines.items():
        require(len(rows) == selected[name]['files'], 'Full SDK5 compiler original tree cardinality required')
        for child in selected[name].get('submodules', []):
            require(child['path'] not in rows, 'Original SDK5 compiler Gitlink cannot replace a file')
            rows[child['path']] = dict(mode='160000', blob=child['commit'])
        require(packer.baseline_tree(rows) == selected[name]['tree'], 'Complete original SDK5 compiler Git tree differs')
    wanted = {name: set(C.SPECS[name][2]) if name in C.SPECS else set() for name in selected}
    for path, (name, relative, row) in indexed.items():
        if '/' not in relative and any(word in relative.lower() for word in ('license', 'notice')): wanted[name].add(relative)
        if name == 'roslyn' and relative.startswith('src/NuGet/Microsoft.Net.Compilers.Toolset/build/'): wanted[name].add(relative)
    found, sources = set(), {name: {} for name in selected}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            name, relative, row = indexed[entry.name]
            require(entry.isfile() and entry.name not in found and entry.size == row['bytes'] and entry.size <= 32 * 1024**2
                    and (entry.mode & 0o7777) == (0o755 if row['mode'] == '100755' else 0o644),
                    'Ordinary bounded original SDK5 compiler source member required')
            raw = archive.extractfile(entry).read()
            require(C.fp(raw) == {key: row[key] for key in CE.FP} and git_object('blob', raw) == row['baseline']['blob'],
                    'Actual archived SDK5 compiler source must equal the full pristine Git blob')
            found.add(entry.name)
            if relative in wanted[name]: sources[name][relative] = raw
    require(found == indexed.keys() and all(sources[name].keys() == wanted[name] for name in wanted), 'Complete SDK5 compiler/source definition archive required')
    return selected, sources, len(found)


def reconstruct(sdk_files, original_sdk, architecture, sources, baselines, destination):
    """Derive the closed package universe from original inputs, never claims."""
    records = []; rid = 'linux-musl-' + {'aarch64': 'arm64', 'x64': 'x64'}[architecture]
    for name in C.SPECS:
        commit = C.SOURCES[name][1]; originals = sources[name]
        definitions = {path: originals[path] for path in C.SPECS[name][2]}
        licenses = {path: raw for path, raw in originals.items() if '/' not in path and any(word in path.lower() for word in ('license', 'notice'))}
        require(licenses, 'Original compiler source licenses and notices required')
        contents, mapping, managed, frameworks = {}, [], [], []
        def add(target, relative):
            require(target not in contents, 'Unique original SDK5 compiler product input required')
            raw = sdk_files[relative]; contents[target] = raw
            mapping.append(dict(packageMember=target, sdkMember='sdk/' + C.SDK + '/' + relative, **C.fp(raw)))
            if raw.startswith(b'MZ'):
                filename = PurePosixPath(relative).name; separate = name == 'roslyn' and filename in C.BASELINES
                metadata = C.inspect_pe(raw, architecture, None if separate else commit, name == 'roslyn-codestyle')
                managed.append(dict(packageMember=target, sourceCommit=C.SOURCES['compiler-framework'][1] if separate else commit, metadata=metadata, **C.fp(raw)))
                if separate:
                    package_raw, record = C.baseline(baselines[filename], filename, raw)
                    contents['cbodotnet-provenance/actual-baseline-packages/' + record['id'] + '.5.0.0.nupkg'] = package_raw
                    frameworks.append(dict(packageMember=target, **record))
        if name == 'fsharp':
            for item in ET.fromstring(next(iter(definitions.values()))).iter():
                if item.tag.rsplit('}', 1)[-1] != 'file': continue
                original = item.attrib['src'].replace('\\', '/'); filename = PurePosixPath(original).name; target = item.attrib['target'].replace('\\', '/')
                require('**/' in original or '*' not in original, 'Exact original SDK5 FSharp asset recipe required')
                candidates = sorted(path for path in sdk_files if path.startswith('FSharp/') and
                    ((len(path.split('/')) == 3 and path.endswith('/' + filename)) if '**/' in original else path == 'FSharp/' + filename))
                require(candidates, 'Every original owned FSharp product must be present')
                for relative in candidates: add(target + '/' + (PurePosixPath(relative).parent.name + '/' if '**/' in original else '') + filename, relative)
        elif name == 'roslyn':
            for relative in sorted(path for path in sdk_files if path.startswith('Roslyn/')): add('tasks/netcoreapp3.1/' + relative[len('Roslyn/'):], relative)
            require(len(frameworks) == 3, 'All three actual SDK5 compiler framework baselines required')
            prefix = 'src/NuGet/Microsoft.Net.Compilers.Toolset/build/'
            for relative, raw in originals.items():
                if relative.startswith(prefix): contents['build/' + relative[len(prefix):]] = raw
        else:
            prefix = C.PREFIXES[2]
            for relative in sorted(path for path in sdk_files if path.startswith(prefix)): add('analyzers/dotnet/vb/' + relative[len(prefix):], relative)
            contents['build/Microsoft.CodeAnalysis.VisualBasic.CodeStyle.props'] = definitions[C.SPECS[name][2][0]]
        scope = {'fsharp': 'All original nuspec owned assets, dependency/content contract and cultures',
                 'roslyn': 'Complete original SDK CoreCLR compiler subtree; no desktop/net472 compiler payload',
                 'roslyn-codestyle': 'Exact VB/shared CodeStyle IL-only analyzers and cultures'}[name]
        records.append(C.package(name, contents, dict(originalSdk=dict(version=C.SDK, rid=rid, **original_sdk), architecture=architecture,
            filesFromSdk=mapping, managedInputs=managed, additionalFrameworkSources=frameworks, scope=scope), definitions, licenses, destination))
    result = dict(schemaVersion=1, sdkVersion=C.SDK, inputs=records, qualificationAllowed=False, sourceAdmissionAllowed=False)
    (destination / 'inputs.json').write_bytes(C.json_bytes(result)); return result


def validate(release, manifest, record, comparison):
    release = Path(release); constructor_policy()
    require(record.get('sdkVersion') == C.SDK and record.get('architecture') in C.SDK_HASHES, 'Exact SDK5 compiler source input identity required')
    roots = [row for row in manifest['roots'] if row['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0].get('role') == ROLE and roots[0].get('commit') is None
            and not roots[0].get('exclude') and not roots[0].get('deleted'), 'Distinct complete derived SDK5 compiler data root required')
    selected, sources, source_count = archived_sources(release, manifest)
    sdk_files, original_sdk = C.selected_sdk(B.checked(release, comparison), record['architecture'])
    data = release / 'reports/build' / ROOT_NAME
    with tempfile.TemporaryDirectory(prefix='cbodotnet-sdk5-compiler-validation-') as temporary:
        temporary = Path(temporary); baseline_dir = temporary / 'baselines'; baseline_dir.mkdir(); baselines = {}
        roslyn_name = C.SPECS['roslyn'][0] + '.' + C.SPECS['roslyn'][1] + '.nupkg'
        with zipfile.ZipFile(CE.ordinary(data / roslyn_name)) as archive:
            for filename, (identity, size, sha) in C.BASELINES.items():
                raw = archive.read('cbodotnet-provenance/actual-baseline-packages/' + identity + '.5.0.0.nupkg')
                require(len(raw) == size and C.fp(raw)['sha256'] == sha, 'Exact separate original SDK5 compiler baseline package required')
                target = baseline_dir / (identity + '.nupkg'); target.write_bytes(raw); baselines[filename] = target
        expected_dir = temporary / 'expected'; expected_dir.mkdir()
        reconstructed = reconstruct(sdk_files, original_sdk, record['architecture'], sources, baselines, expected_dir)
        expected = {path.name: CE.fingerprint(path) for path in expected_dir.iterdir()}
        actual = {}
        for path in data.iterdir(): actual[path.name] = CE.fingerprint(CE.ordinary(path))
        require(actual == expected and roots[0]['files'] == len(expected), 'Complete SDK5 derived compiler packages and receipts must equal original-input reconstruction')
    indexed = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); prefix = ROOT_NAME + '/'
            if row['path'].startswith(prefix):
                name = row['path'][len(prefix):]; require(name not in indexed, 'Unique archived SDK5 compiler data required'); indexed[name] = {key: row[key] for key in CE.FP}
    require(indexed == actual, 'All exact SDK5 derived compiler inputs must be source indexed')
    found = set()
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            prefix = ROOT_NAME + '/'
            if not entry.name.startswith(prefix): continue
            name = entry.name[len(prefix):]
            require(entry.isfile() and name in actual and name not in found and entry.size == actual[name]['bytes'] and entry.size <= 64 * 1024**2,
                    'Ordinary bounded actual SDK5 compiler data source member required')
            require(C.fp(archive.extractfile(entry).read()) == actual[name], 'Archived SDK5 derived compiler input bytes differ'); found.add(name)
    require(found == actual.keys(), 'Every derived SDK5 compiler input must be source archived')
    return dict(status='passed-sdk5-three-derived-compiler-original-input-source', dataRoot=ROOT_NAME, sourceRoots={name: row['name'] for name, row in selected.items()},
        sourceFiles=source_count, packages=[row['package'] for row in reconstructed['inputs']], deterministicPackageReconstruction=True,
        compilerLocallySourceBuiltClaimed=False, originalPublisherNupkg=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
