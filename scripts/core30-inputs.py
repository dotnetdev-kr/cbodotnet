#!/usr/bin/env python3
"""Verify pinned Core 3.0 source acquisition and record bootstrap fingerprints.

Receipts attest the initial Git exports. Current component contents are allowed
to contain recorded upstream or local patches and build outputs; this check
does not claim that the current tree equals a pristine Git export.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import runpy
import shlex
import subprocess
import types


SOURCE_COMMIT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'


def fingerprint(path):
    value, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk); size += len(chunk)
    return {'path': str(path), 'bytes': size, 'sha256': value.hexdigest()}


def ordinary_file(path):
    for part in [path] + list(path.parents):
        if part.is_symlink():
            raise ValueError('Symlinks are not allowed in input control paths: ' + str(path))
    if not path.is_absolute() or not path.is_file():
        raise ValueError('An absolute ordinary input file is required: ' + str(path))
    return path


def bootstrap_use(source, inputs, profile):
    """Verify immutable bootstrap inputs and record a later upstream reinstall.

    InitBuild may rebuild the original XPlat tasks and reinstall their DLL as
    the SDK resolver. Accept that exact upstream output explicitly; other
    original stable SDK files and the frozen environment contract stay fixed.
    """
    helper = runpy.run_path(str(Path(__file__).resolve().with_name('prepare-core30-bootstrap.py')))
    inputs = helper['directory'](inputs)
    state = helper['directory'](inputs / 'bootstrap-state')
    prepared_path = ordinary_file(state / 'prepared.json')
    prepared = json.loads(prepared_path.read_text(encoding='utf-8'))
    records = helper['identity'](source, profile)
    if prepared['sourceFiles'] != records:
        raise ValueError('The original bootstrap source files changed')
    ordinary_file(inputs / 'official-sdk' / helper['SDK_NAME'])
    ordinary_file(inputs / helper['PSB_NAME'])
    ordinary_file(inputs / 'bootstrap-packages' / helper['ARCADE_NAME'])
    helper['directory'](inputs / 'bootstrap-packages/microsoft.dotnet.arcade.sdk' / helper['ARCADE_VERSION'])
    helper['ordinary_file'](state / 'arcade-package.json')
    archive, sdk_info = helper['official_sdk_archive'](inputs)
    arcade, package, package_info, psb_info = helper['retained_arcade'](inputs, state)
    if (prepared['sdkArchive'] != sdk_info or prepared['psbArchive'] != psb_info or
            prepared['arcadePackage'] != package_info):
        raise ValueError('The retained bootstrap archive identities changed')
    sdk = helper['directory'](source / '.dotnet')
    contract = helper['environment_contract'](source, inputs, sdk, arcade)
    if prepared['contract'] != contract:
        raise ValueError('The bootstrap environment contract changed')
    contract_path, environment_path = state / 'core30-bootstrap-contract.json', state / 'core30-bootstrap-env.sh'
    expected_json = (json.dumps(contract, indent=2, sort_keys=True) + '\n').encode('utf-8')
    shell = '#!/usr/bin/env bash\n# Frozen .NET Core 3.0 bootstrap environment; product build flags are supplied separately.\n'
    shell += '\n'.join('export ' + key + '=' + shlex.quote(value) for key, value in sorted(contract['environment'].items())) + '\n'
    for path, expected in [(contract_path, expected_json), (environment_path, shell.encode('utf-8'))]:
        if ordinary_file(path).read_bytes() != expected:
            raise ValueError('The frozen bootstrap environment bytes differ: ' + str(path))
        if helper['fingerprint'](path) != prepared['contractFiles'][path.name]:
            raise ValueError('The frozen bootstrap environment receipt differs')
    installed = sdk / 'sdk/3.0.100/SdkResolvers/SourceBuild.MSBuildSdkResolver/SourceBuild.MSBuildSdkResolver.dll'
    resolver_path = installed.relative_to(sdk).as_posix()
    original_resolver = None
    stable = []
    for row in prepared['stableSdkFiles']:
        path = ordinary_file(sdk / row['path'])
        actual = helper['fingerprint'](path)
        if row['path'] == resolver_path:
            original_resolver = row['fingerprint']
        elif actual != row['fingerprint']:
            raise ValueError('An immutable original SDK file changed: ' + row['path'])
        stable.append({'path': row['path'], 'fingerprint': actual})
    if original_resolver is None:
        raise ValueError('The bootstrap receipt lacks its initial resolver identity')
    current_resolver = helper['fingerprint'](ordinary_file(installed))
    upstream = source / 'tools-local/tasks/Microsoft.DotNet.SourceBuild.Tasks.XPlat/bin/Debug/netstandard2.0/Microsoft.DotNet.SourceBuild.Tasks.XPlat.dll'
    same_initial = current_resolver == original_resolver
    same_upstream = upstream.is_file() and helper['fingerprint'](ordinary_file(upstream)) == current_resolver
    if not same_initial and not same_upstream:
        raise ValueError('The installed SDK resolver matches neither the prepared resolver nor the current upstream XPlat output')
    return {'preparedReceipt': fingerprint(prepared_path), 'contract': fingerprint(contract_path),
            'environment': fingerprint(environment_path), 'stableSdkFiles': stable,
            'resolverMatchesInitialBootstrap': same_initial, 'resolverMatchesCurrentUpstreamXPlatOutput': same_upstream,
            'currentUpstreamXPlatOutput': fingerprint(upstream) if same_upstream else None,
            'scope': 'Original pinned bootstrap sources, exact official/PSB/Arcade inputs and environment bytes. A subsequent resolver reinstall is accepted only when byte-equal to the current upstream XPlat output; that output is recorded separately.'}


def verify(source, profile, require_bootstrap=False):
    cloner = runpy.run_path(str(Path(__file__).resolve().with_name('clone-legacy-sources.py')))
    args = types.SimpleNamespace(source_dir=str(source), profile=str(profile), repo=None,
                                 version=None, ignore_repos=[])
    source, profile, selected, commit, manifest_hash, dependencies, ignored, _ = cloner['source_identity'](args)
    if commit != SOURCE_COMMIT or selected['sdkVersion'] != '3.0.103':
        raise ValueError('Only the pinned Core 3.0.103 graph is accepted')
    exports = source / 'bin/src'
    stores = source / '.git/modules/src'
    records, seen = [], set()
    for dependency in dependencies:
        if dependency['ignoredByUpstreamClone']:
            continue
        canonical, sha = dependency['canonicalRepository'], dependency['commit']
        if (canonical, sha) in seen:
            continue
        seen.add((canonical, sha))
        # The upstream layout retains the URI basename's original case. Only
        # receipt repository identities use the canonical lowercase URL.
        name = cloner['basename'](dependency['repository'])
        destination = cloner['ordinary_path'](exports / (name + '.' + sha), existing=True)
        store = cloner['ordinary_path'](stores / (name + '.git'), existing=True)
        cloner['git'](['--git-dir=' + str(store), 'cat-file', '-e', sha + '^{commit}'])
        key = hashlib.sha256(str(destination).encode()).hexdigest()
        receipt = ordinary_file(stores / '.cbodotnet-legacy-exports' / (key + '.json'))
        original = json.loads(receipt.read_text(encoding='utf-8'))
        identity = {'owner': cloner['OWNER'], 'sourceRootCommit': commit, 'manifestSha256': manifest_hash,
                    'repository': canonical, 'commit': sha, 'destination': str(destination)}
        if original.get('identity') != identity:
            raise ValueError('Initial export identity mismatch: ' + name)
        inventory = ordinary_file(Path(original['initialInventory']['path']))
        if fingerprint(inventory)['sha256'] != original['initialInventory']['sha256']:
            raise ValueError('Initial export inventory changed: ' + name)
        head = ordinary_file(destination / '.git/HEAD')
        if head.read_text().strip() != sha:
            raise ValueError('Component commit marker mismatch: ' + name)
        records.append({'repository': canonical, 'commit': sha, 'directory': str(destination),
                        'receipt': fingerprint(receipt), 'initialInventory': fingerprint(inventory),
                        'currentTreeContentRevalidated': False})
    bootstrap = source / '.dotnet'
    files = []
    for relative in ['dotnet', 'sdk/3.0.100/MSBuild.dll', 'sdk/3.0.100/.version']:
        path = bootstrap / relative
        if path.is_file():
            files.append(fingerprint(ordinary_file(path)))
        elif require_bootstrap:
            raise ValueError('Missing initialized bootstrap input: ' + str(path))
    if require_bootstrap:
        process = subprocess.run([str(bootstrap / 'dotnet'), '--version'], cwd=str(source),
                                 check=True, stdout=subprocess.PIPE, universal_newlines=True)
        if process.stdout.strip() != '3.0.100':
            raise ValueError('The source root does not select bootstrap SDK3.0.100')
    return {'schemaVersion': 1, 'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status': 'passed', 'sourceCommit': commit, 'sourceDirectory': str(source),
            'manifestSha256': manifest_hash, 'dependencyDeclarations': len(dependencies),
            'ignoredRepositories': ignored, 'exports': records, 'bootstrapVersion': '3.0.100',
            'bootstrapFiles': files, 'bootstrapExecutionVerified': require_bootstrap,
            'scope': 'Pinned source manifest, bare commit objects, initial-export receipts/inventories and current bootstrap files. Current component trees may contain subsequent build changes.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--require-bootstrap', action='store_true')
    parser.add_argument('--inputs-dir', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    record = verify(args.source_dir, args.profile, args.require_bootstrap)
    if args.inputs_dir:
        if not args.require_bootstrap:
            raise ValueError('--inputs-dir requires --require-bootstrap')
        record['bootstrapUse'] = bootstrap_use(Path(record['sourceDirectory']), args.inputs_dir, args.profile)
    if args.report:
        output = args.report
        if (not output.is_absolute() or output.is_symlink() or not output.parent.is_dir()
                or args.source_dir.resolve() in output.resolve().parents):
            raise ValueError('A new ordinary report outside the source tree is required')
        with output.open('x', encoding='utf-8') as stream:
            json.dump(record, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': 'passed', 'sourceCommit': record['sourceCommit'],
                      'exports': len(record['exports']), 'bootstrapVerified': args.require_bootstrap}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
