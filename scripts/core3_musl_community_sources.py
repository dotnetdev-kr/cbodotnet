#!/usr/bin/env python3
"""Prepare exact Core3.1 community CLI/F# source; never edit compiled products."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'profiles/experimental/core3-musl-community.json'


def fingerprint(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked(path, pin):
    row = fingerprint(path)
    require(row['sha256'] == pin['sha256'], f'input SHA256 differs: {path}')
    if 'bytes' in pin:
        require(row['bytes'] == pin['bytes'], f'input length differs: {path}')
    return row


def apply_patch(source, patch):
    for option in ('--check', '--whitespace=nowarn'):
        subprocess.run(['git', 'apply', option, str(patch.resolve())], cwd=source, check=True)


def prepare(args):
    profile = json.loads(PROFILE.read_text(encoding='utf-8'))
    pin = profile['components'][args.component]
    require(re.fullmatch(r'\d{8}\.\d+', args.official_build_id), 'OfficialBuildId must be YYYYMMDD.sequence')
    # New directories are mandatory: a repeat cannot silently consume a stale same-ID output.
    work = args.work_dir.resolve()
    output = args.output_dir.resolve()
    require(work != output and not work.is_relative_to(output) and not output.is_relative_to(work),
            'work and evidence directories must be separate')
    require(not work.exists() and not output.exists(), 'use new work and evidence directories')
    source_input = checked(args.source_archive, pin['source'])
    graph_input = checked(args.source_build_archive, profile['sourceBuild'])
    community_patch = ROOT / pin['communityPatch']['path']
    checked(community_patch, pin['communityPatch'])
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    with tarfile.open(args.source_archive) as archive:
        archive.extractall(work, filter='data')
    source = work / pin['archiveRoot']
    require(source.is_dir(), 'original source root is missing')
    original_global = fingerprint(source / 'global.json')
    original_patches = []
    with tarfile.open(args.source_build_archive) as archive:
        candidates = {Path(member.name).name: member for member in archive
                      if member.isfile() and f"/patches/{pin['patchDirectory']}/" in member.name}
        for patch_pin in pin['originalPatches']:
            require(patch_pin['name'] in candidates, 'pinned original patch is missing')
            patch = output / 'original-upstream-patches' / patch_pin['name']
            patch.parent.mkdir(exist_ok=True)
            patch.write_bytes(archive.extractfile(candidates[patch_pin['name']]).read())
            original_patches.append(checked(patch, patch_pin))
            apply_patch(source, patch)
    for row in pin['files']:
        require(fingerprint(source / row['path'])['sha256'] == row['beforeSha256'],
                f"original source file differs: {row['path']}")
    apply_patch(source, community_patch)
    files = []
    for row in pin['files']:
        actual = fingerprint(source / row['path'])
        require(actual['sha256'] == row['afterSha256'], f"patched source differs: {row['path']}")
        files.append(actual)
    require(fingerprint(source / 'global.json') == original_global, 'original global.json changed')
    common = [f'/p:OfficialBuildId={args.official_build_id}', '/p:ContinuousIntegrationBuild=true',
              '/p:Company=.NET Dev', '/p:Product=' + profile['branding']]
    receipt = dict(qualification=False, releaseAdmission=False, sourceSdkProduct=False,
                   compilerExecuted=False, preparationOnly=True, component=args.component,
                   sourceCommit=pin['source']['commit'], sourceArchive=source_input,
                   sourceBuildArchive=graph_input, sourceDirectory=str(source),
                   originalPatches=original_patches, communityPatch=fingerprint(community_patch),
                   originalGlobalUnchanged=True, originalGlobal=original_global, files=files,
                   officialBuildId=args.official_build_id, commonMsbuildArguments=common,
                   assemblyVersionOverride=False, packageVersionOverride=False,
                   releaseAdditionalArguments=pin.get('releaseAdditionalArguments', []),
                   protoAdditionalArguments=pin.get('protoAdditionalArguments', []),
                   scope=profile['scope'])
    (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(sourceDirectory=str(source), files=len(files), compilerExecuted=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', required=True, choices=('cli31', 'fsharp31'))
    parser.add_argument('--source-archive', required=True, type=Path)
    parser.add_argument('--source-build-archive', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--official-build-id', required=True)
    prepare(parser.parse_args())


if __name__ == '__main__':
    main()
