#!/usr/bin/env python3
"""Apply or verify the fixed .NET 5 portable native ARM64 bring-up patches."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET


SOURCE = 'd414ecb2d997a9b3f38aaaeddace30ca097e546d'
RUNTIME = '6a984143635bde23e728abaaccbde52f5ea8fa3e'
ASP = '02c6de4ba6022025fcda7581415f310f8c73cdc3'
PATCHES = [
    {'name': '0001-run-native-arm64-corelib-crossgen.patch',
     'target': 'artifacts/src/runtime.' + RUNTIME + '/src/coreclr/crossgen-corelib.sh',
     'original': 'ae2e35d863114c5b7e3186509c7d19d381a644975a1b635c3a286c18a0660d21',
     'patched': 'b9dd2bbb7c0d77fea464c0b8802460e6469d7c215bee41726195a87b290dd180',
     'patch': '08e6d58bd7541ee1abceef8bea1c177c4e810cf0799cd1b499a044eb93430d07',
     'purpose': 'Run the main native ARM64 crossgen for CoreLib in same-system sysroot mode while retaining cross compilation.'},
    {'name': '0002-avoid-duplicate-portable-aspnet-runtime.patch',
     'target': 'patches/aspnetcore/0001-Use-non-portable-NETCoreAppRuntime-for-crossgen.patch',
     'original': 'b28bdbe148763707828b6e19584e3f8f2de0b14eef6dc1fe6ea42cbb7a1ea1e6',
     'patched': '0c5a57795bbd59fec847a270a26e89c5e03fa81a6df3e623d6acde0147c47d8b',
     'patch': '4084d484ea7a724662ebfddea32e83735147fe602a36d685091127e4548becc1',
     'purpose': 'Condition the upstream producer of the extra nonportable ASP.NET runtime reference; preserve the existing portable reference and native crossgen.'},
    {'name': '0003-preserve-explicit-source-clone-command.patch', 'target': 'Directory.Build.targets',
     'original': '190b4dbcd1a0793f4e60989c1dcafef6b4e13bf36bc14f415afbb94e7985ab63',
     'patched': 'b0ec2a7c1829b2f3d4ae18a7529b3ac5bab90f10087cde3ff7b6fbc72f3e90c5',
     'patch': 'b3c951cc23bd46061e642c7fc9e5d5a4aef3a27117c057972b798b45ad392d42',
     'purpose': 'Keep an explicit immutable source acquisition wrapper during target execution without bypassing FetchSources.'},
    {'name': '0004-use-public-dotnet-feed-for-legacy-mapping.patch', 'target': 'repos/Directory.Build.targets',
     'original': '846e2061822adb44924c4f652bd5987378e68fcf33f4a66efa91f9e013c94e0f',
     'patched': '0aba7f4afb1557737d098ee6950af6af7d974d849bd1d664ba627be518a1e65a',
     'patch': '644fd832aaf440ecf8a46d9537bee4f499228f798e87b5e5928f9ff7652c492e',
     'purpose': 'Keep online restore and exact requested versions while mapping the retired dotnet-core index to the current official dotnet-public feed.'},
    {'name': '0005-map-remaining-retired-service-indexes.patch', 'target': 'repos/Directory.Build.targets',
     'original': '0aba7f4afb1557737d098ee6950af6af7d974d849bd1d664ba627be518a1e65a',
     'patched': 'ae4fff51b6549a90d25f00782b7bce8f75ed39ffea1f18e86a464fbb84e63a40',
     'patch': '30d1fd9ecf175f4ac9364a8e7a39002c3e4a7e6b1753f93b9771c1d53295aa1f',
     'purpose': 'Extend the exact service-index mapping to retired tools and nuget-build feeds without changing versions, local feeds or archive URLs.'},
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(root, *arguments):
    process = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                              '-c', 'core.autocrlf=false', '-C', str(root)] + list(arguments),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('Git patch/identity operation failed: ' + process.stderr.decode('utf-8', 'replace')[-6000:])
    return process.stdout


def ordinary_directory(path):
    if not path.is_absolute() or path == Path(path.anchor):
        raise ValueError('An absolute ordinary directory is required')
    if any(item.is_symlink() for item in [path] + list(path.parents)):
        raise ValueError('A control directory or ancestor is a symbolic link')
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise ValueError('Missing control directory')
    return path


def fixed_file(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing ordinary pinned file: ' + relative)
    ordinary_directory(path.parent)
    return path


def identity(source):
    if Path(command(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != source:
        raise ValueError('Unexpected source-build Git top level')
    if command(source, 'rev-parse', 'HEAD').decode().strip() != SOURCE:
        raise ValueError('The source-build revision differs from the fixed SDK graph')
    manifest = fixed_file(source, 'eng/Version.Details.xml')
    if manifest.read_bytes() != command(source, 'show', SOURCE + ':eng/Version.Details.xml'):
        raise ValueError('The source dependency manifest changed')
    dependencies = ET.fromstring(manifest.read_bytes())
    for repository, revision in (('runtime', RUNTIME), ('aspnetcore', ASP)):
        matches = [item for item in dependencies.findall('./ProductDependencies/Dependency')
                   if item.findtext('Uri') == 'https://github.com/dotnet/' + repository]
        if len(matches) != 1 or matches[0].findtext('Sha') != revision:
            raise ValueError('Pinned component manifest mismatch: ' + repository)
        component = ordinary_directory(source / ('artifacts/src/' + repository + '.' + revision))
        if fixed_file(component, '.git/HEAD').read_text().strip() != revision:
            raise ValueError('Component source-export marker mismatch: ' + repository)
    bare = ordinary_directory(source / '.git/modules/src/runtime.git')
    if command(source, '--git-dir=' + str(bare), 'rev-parse', RUNTIME + '^{commit}').decode().strip() != RUNTIME:
        raise ValueError('The retained runtime Git object differs')
    original = command(source, '--git-dir=' + str(bare), 'show', RUNTIME + ':src/coreclr/crossgen-corelib.sh')
    if hashlib.sha256(original).hexdigest() != PATCHES[0]['original']:
        raise ValueError('The retained original runtime source differs')
    checked = set()
    for item in PATCHES[1:]:
        if item['target'] in checked:
            continue
        checked.add(item['target'])
        if hashlib.sha256(command(source, 'show', SOURCE + ':' + item['target'])).hexdigest() != item['original']:
            raise ValueError('The retained original source-build producer differs')
    return {'sourceCommit': SOURCE, 'runtimeCommit': RUNTIME, 'aspnetcoreCommit': ASP,
            'manifestSha256': digest(manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'verify'])
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--patches-dir', type=Path)
    parser.add_argument('--reports-dir', type=Path)
    args = parser.parse_args()
    source = ordinary_directory(args.source_dir)
    patches = ordinary_directory(args.patches_dir or Path(__file__).resolve().parents[1] / 'patches/net5')
    reports = None
    if args.reports_dir is not None:
        reports = ordinary_directory(args.reports_dir)
        try:
            reports.relative_to(source)
        except ValueError:
            pass
        else:
            raise ValueError('Patch reports must be outside the source tree')
        if (reports / 'net5-patches.json').exists() or (reports / 'net5-patches.json').is_symlink():
            raise ValueError('Refusing to overwrite a previous patch report')
    record = identity(source)
    groups = {}
    for item in PATCHES:
        patch = fixed_file(patches, item['name'])
        target = fixed_file(source, item['target'])
        if digest(patch) != item['patch']:
            raise ValueError('An authored patch differs from its fixed digest')
        chain = groups.setdefault(item['target'], [])
        if chain and chain[-1][0]['patched'] != item['original']:
            raise ValueError('A declared patch chain is not contiguous')
        expected_stat = command(source, 'apply', '--numstat', str(patch)).decode().strip().split('\t')
        if len(expected_stat) != 3 or expected_stat[2] != item['target']:
            raise ValueError('A patch affects an unexpected target')
        chain.append((item, patch, target))
    operations, chains = [], []
    # Preflight every complete chain from pinned Git bytes, including reviewed
    # intermediate states already present after an earlier build attempt.
    with tempfile.TemporaryDirectory(prefix='net5-patch-chain-') as temporary:
        stage = Path(temporary)
        command(stage, 'init', '--quiet')
        for relative, chain in groups.items():
            target = chain[0][2]
            states = [chain[0][0]['original']] + [item['patched'] for item, _, _ in chain]
            actual = digest(target)
            if actual not in states:
                raise ValueError('An unexpected source change affects: ' + relative)
            state = states.index(actual)
            if args.action == 'verify' and state != len(chain):
                raise ValueError('A required final compatibility patch state is absent')
            if relative.startswith('artifacts/src/runtime.'):
                original = command(source, '--git-dir=' + str(source / '.git/modules/src/runtime.git'),
                                   'show', RUNTIME + ':src/coreclr/crossgen-corelib.sh')
            else:
                original = command(source, 'show', SOURCE + ':' + relative)
            staged = stage / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(original)
            for index, (item, patch, _) in enumerate(chain):
                if digest(staged) != item['original']:
                    raise ValueError('Staged original patch-chain bytes differ')
                command(stage, 'apply', '--check', '--whitespace=nowarn', str(patch))
                command(stage, 'apply', '--whitespace=nowarn', str(patch))
                if digest(staged) != item['patched']:
                    raise ValueError('Staged patch-chain result differs')
                operations.append((item, patch, target, index >= state))
            chains.append({'target': relative, 'observedSha256': actual, 'acceptedSha256States': states,
                           'finalSha256': states[-1], 'pendingPatchCount': len(chain) - state})
    for chain in chains:
        if digest(source / chain['target']) != chain['observedSha256']:
            raise ValueError('Source changed after complete patch-chain preflight')
    results = []
    for item, patch, target, required in operations:
        if args.action == 'apply' and required:
            if digest(target) != item['original']:
                raise ValueError('Source changed during ordered patch application')
            command(source, 'apply', '--whitespace=nowarn', str(patch))
            if digest(target) != item['patched']:
                raise ValueError('A compatibility patch did not produce its exact expected bytes')
        results.append({'patch': str(patch), 'patchSha256': item['patch'], 'target': item['target'],
                        'originalSha256': item['original'], 'patchedSha256': item['patched'],
                        'purpose': item['purpose'], 'result': 'applied' if required else 'already-represented'})
    for chain in chains:
        if digest(source / chain['target']) != chain['finalSha256']:
            raise ValueError('The final compatibility patch-chain bytes differ')
    record.update({'schemaVersion': 2, 'action': args.action, 'status': 'passed', 'patchChains': chains,
                   'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'patches': results,
                   'scope': 'Five authored compatibility patches across four files. The normal upstream component patch chain remains active; later build/configuration injections are separate source changes.'})
    if reports is not None:
        with (reports / 'net5-patches.json').open('x', encoding='utf-8') as output:
            json.dump(record, output, indent=2)
            output.write('\n')
    print(json.dumps({'status': 'passed', 'action': args.action, 'patches': len(results)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        raise SystemExit('error: ' + str(error))
