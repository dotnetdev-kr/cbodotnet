"""SDK5's closed constructor byte inputs, separate from source admission.

The outer archive, named artifact roles, original framework pins and complete
layout are checked before any imported source decision. Passing this leaf
does not admit a producer or establish an imported component's source.
"""
import re
from pathlib import Path

import musl_legacy5_bootstrap as BOOT
import musl_legacy5_compiler_inputs as COMPILERS
import musl_legacy5_component_evidence as CE
import musl_legacy5_native_inputs as NATIVE

B = CE.B
require, fingerprint, portable = B.require, B.fingerprint, B.portable
FP = set(CE.FP)
SDK = CE.SDK
COMMITS = dict(CE.COMMITS, runtime=NATIVE.COMMIT,
    installer='430330f7c5428f031b4a835be3dcf5945f55a56a',
    aspnetcore='02c6de4ba6022025fcda7581415f310f8c73cdc3')
ASPNET_SHA512 = {
    'aarch64': '26f8a30e246c5527f03023e203e44dea1842e23ac587bc9872e6e60bd5ac98f57f7962d7d46c816690cb42263e9deedd896d0d3ad538a2d9dd17a06ba6f47fbb',
    'x64': '7df763553f6438c51f23542412830686fef82b56f1e3330fa2dfd86b894eff7d830b5ff51468cfe6e88d2eceebc0a0a2352c8762f65a0ffc6ca9f5b02863b7a6'}


def validate_final_sdk_archive(record, proof):
    sdk = record.get('sdk')
    require(record.get('sdkVersion') == SDK and record.get('architecture') in ('aarch64', 'x64')
            and isinstance(sdk, dict) and set(sdk) == FP | {'name'}
            and isinstance(sdk['name'], str) and type(sdk['bytes']) is int and sdk['bytes'] > 0
            and re.fullmatch('[a-f0-9]{64}', sdk.get('sha256', ''))
            and re.fullmatch('[a-f0-9]{128}', sdk.get('sha512', '')),
            'An explicit actual final SDK5 archive identity is required')
    expected = dict(path=portable(sdk['name']), **{key: sdk[key] for key in FP})
    require(proof.get('sdkArchive') == expected,
            'SDK5 construction must bind the exact final archive path and every fingerprint')
    return expected


def validate_artifact_roles(artifacts, roots, restored, record, installer):
    roles = {'toolset': ('sdk-toolset', 'sdk'), 'runtime': ('official-runtime', 'runtime'),
        'aspnet': ('official-aspnet', 'aspnetcore'), 'crypto': ('native-crypto', 'runtime'),
        'original-sdk-comparison': ('official-sdk-comparison', 'installer'),
        'source-crossgen': ('native-crossgen-construction-input', 'runtime'),
        'translations': ('nuget-translation-data', 'nuget')}
    roles.update({'native-' + name: ('native-coreclr', 'runtime') for name in NATIVE.SHIPPING})
    for name, field, kind in [('post-crossgen', 'transformations', 'post-crossgen-sdk'),
                              ('generated', 'generatedOutputs', 'generated-installer-data')]:
        require(isinstance(installer.get(field), list), 'Explicit complete SDK5 installer output sets required')
        if installer[field]: roles[name] = (kind, 'installer')
    require(isinstance(artifacts, dict) and roles.keys() <= artifacts.keys(),
            'All named SDK5 construction artifact roles are required')
    paths = set()
    for name, row in artifacts.items():
        path = portable(row.get('path'))
        require(path not in paths, 'A SDK5 constructor artifact path cannot carry multiple roles'); paths.add(path)
        require(row.get('sourceRoot') in roots and roots[row['sourceRoot']].get('kind') in ('git', 'git-export')
                and row.get('sourceCommit') == roots[row['sourceRoot']].get('commit')
                and re.fullmatch('[a-f0-9]{40}', row.get('sourceCommit') or ''), 'Actual SDK5 artifact Git source required')
        if name in roles:
            kind, source = roles[name]
            require(row.get('kind') == kind and row.get('sourceRoot') == source
                    and row.get('sourceCommit') == COMMITS[source], 'Exact named SDK5 artifact kind/source required: ' + name)
            construction_only = name in ('source-crossgen', 'original-sdk-comparison')
            expected = FP | {'path', 'kind', 'sourceRoot', 'sourceCommit'} | ({'constructionOnly'} if construction_only else set())
            require(set(row) == expected and (not construction_only or row['constructionOnly'] is True),
                    'Closed named SDK5 artifact descriptor required')
            expected_sha = (BOOT.pin('runtime', record['architecture'])['sha512'] if name == 'runtime' else
                ASPNET_SHA512[record['architecture']] if name == 'aspnet' else
                COMPILERS.SDK_HASHES[record['architecture']] if name == 'original-sdk-comparison' else None)
            require(expected_sha is None or row.get('sha512') == expected_sha,
                    'Exact independently pinned SDK5 official framework/comparison archive required')
            if name.startswith('native-') or name == 'source-crossgen':
                filename = 'crossgen' if name == 'source-crossgen' else name[len('native-'):]
                require(path == 'reports/build/native-runtime/' + filename, 'Exact SDK5 native construction path required')
        else:
            require(name == 'package-' + row.get('sha256', '') and row.get('kind') == 'managed-package'
                    and set(row) == FP | {'path', 'kind', 'sourceRoot', 'sourceCommit', 'sourceBasis', 'repository'}
                    and restored.get(row['sha256']) == {key: row[key] for key in ('path', *CE.FP)},
                    'Only canonical actually restored SDK5 packages may add artifact roles')
    return roles


def validate_toolset_binding(artifacts, compiler):
    packages = compiler['sdk']['proof']['packages']
    require(len(packages) == 1 and all(packages[0].get(key) == artifacts['toolset'].get(key) for key in FP),
            'SDK5 toolset must equal the actual component compiler package in every fingerprint')


def validate_layout(proof, artifacts, inventories, actual, installer):
    layout = {}
    for row in proof['layout']:
        require(set(row) == {'path', 'input', 'member'}, 'Closed SDK5 layout mapping required')
        name = portable(row['path']); key = row['input']
        require(name in actual and name not in layout and key in artifacts and not artifacts[key].get('constructionOnly')
                and row['member'] in inventories[key] and inventories[key][row['member']] == actual[name],
                'Every SDK5 layout member needs one exact actual constructor input')
        if actual[name].get('signature', '').startswith('4d5a'):
            require(artifacts[key]['kind'] != 'generated-installer-data', 'Generated SDK5 data cannot impersonate managed code')
        layout[name] = row
    require(layout.keys() == actual.keys(), 'Complete one-to-one SDK5 layout coverage required')
    for name, field, path_key in [('post-crossgen', 'transformations', 'archivePath'),
                                  ('generated', 'generatedOutputs', 'archivePath')]:
        expected = {row[path_key] for row in installer[field]}
        require(len(expected) == len(installer[field]) and set(inventories.get(name, {})) == expected,
                'SDK5 installer snapshot must contain exactly its independently observed outputs')
    return layout


def validate_byte_inputs(release, record, proof, roots, compiler, restored, installer):
    """Read actual archives; callers must separately prove source and execution."""
    release = Path(release)
    final = validate_final_sdk_archive(record, proof)
    actual = B.members(B.checked(release, final), 'sdk')
    require(proof.get('inventory') == actual, 'Complete actual final SDK5 member inventory required')
    artifacts = proof['artifacts']
    roles = validate_artifact_roles(artifacts, roots, restored, record, installer)
    validate_toolset_binding(artifacts, compiler)
    inventories = {}
    for name, row in artifacts.items():
        path = B.checked(release, {key: row[key] for key in ('path', *CE.FP)})
        kind = 'native-coreclr' if row['kind'].startswith('native-') else row['kind']
        inventories[name] = B.members(path, kind)
        if row['kind'] == 'managed-package':
            inventories[name][''] = dict(bytes=row['bytes'], sha256=row['sha256'], signature='504b0304')
    layout = validate_layout(proof, artifacts, inventories, actual, installer)
    return dict(actual=actual, inventories=inventories, roles=roles, layout=layout,
                sourceAdmissionAllowed=False, qualificationAllowed=False)
