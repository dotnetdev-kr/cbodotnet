#!/usr/bin/env python3
"""Verify pinned Core 3.1 source acquisition and record bootstrap fingerprints.

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
import subprocess
import types


SOURCE_COMMIT = 'ab8b115b5658237ee8916ae3586600b39fb2fd19'


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


def verify(source, profile, require_bootstrap=False):
    cloner = runpy.run_path(str(Path(__file__).resolve().with_name('clone-legacy-sources.py')))
    args = types.SimpleNamespace(source_dir=str(source), profile=str(profile), repo=None,
                                 version=None, ignore_repos=[])
    source, profile, selected, commit, manifest_hash, dependencies, ignored, _ = cloner['source_identity'](args)
    if commit != SOURCE_COMMIT or selected['sdkVersion'] != '3.1.426':
        raise ValueError('Only the pinned Core 3.1.426 graph is accepted')
    exports = source / 'artifacts/src'
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
    for relative in ['dotnet', 'sdk/3.1.422/MSBuild.dll', 'sdk/3.1.422/.version']:
        path = bootstrap / relative
        if path.is_file():
            files.append(fingerprint(ordinary_file(path)))
        elif require_bootstrap:
            raise ValueError('Missing initialized bootstrap input: ' + str(path))
    if require_bootstrap:
        process = subprocess.run([str(bootstrap / 'dotnet'), '--version'], cwd=str(source),
                                 check=True, stdout=subprocess.PIPE, text=True)
        if process.stdout.strip() != '3.1.422':
            raise ValueError('The source root does not select bootstrap SDK3.1.422')
    return {'schemaVersion': 1, 'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status': 'passed', 'sourceCommit': commit, 'sourceDirectory': str(source),
            'manifestSha256': manifest_hash, 'dependencyDeclarations': len(dependencies),
            'ignoredRepositories': ignored, 'exports': records, 'bootstrapVersion': '3.1.422',
            'bootstrapFiles': files, 'bootstrapExecutionVerified': require_bootstrap,
            'scope': 'Pinned source manifest, bare commit objects, initial-export receipts/inventories and current bootstrap files. Current component trees may contain subsequent build changes.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--require-bootstrap', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    record = verify(args.source_dir, args.profile, args.require_bootstrap)
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
