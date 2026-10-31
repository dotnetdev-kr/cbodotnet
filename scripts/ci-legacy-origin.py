#!/usr/bin/env python3
"""Observe real installer inputs and audit their local producers without rebuilding."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import shutil
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True

CONFIG = {
    'net5': ('5.0.214', '5.0.17', 'artifacts', 'd414ecb2d997a9b3f38aaaeddace30ca097e546d'),
    'core31': ('3.1.426', '3.1.32', 'artifacts', 'ab8b115b5658237ee8916ae3586600b39fb2fd19'),
    'core30': ('3.0.103', '3.0.3', 'bin', '40de72d1087a1d05dfd39c87f888a0611ec6c60f'),
}
PINS = {
    'core31': {'coreclr': 'c17d273aa03d4b9d14c92248a91f0d0faa881b98', 'corefx': 'b58ef0a19eca6269799664d6288be14b7f0cef3e', 'core-setup': 'f94bb2c3ff432dcc4a6229eca2f978197bf06150'},
    'core30': {'coreclr': '259ce7d4619478cfefe7b0c0f6fa765f765f7e37', 'corefx': 'a4238c9819075be9bff74e009da802ce47233f38', 'core-setup': 'c03f2fe62663edec83d1bc12b4e9f11bd3de5d0e'},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path] + list(path.parents)),
            'Ordinary absolute input required: ' + str(path))
    return path


def digest(stream):
    size = 0; h = hashlib.sha256(); other = hashlib.sha512()
    for block in iter(lambda: stream.read(1048576), b''):
        size += len(block); h.update(block); other.update(block)
    return {'bytes': size, 'sha256': h.hexdigest(), 'sha512': other.hexdigest(),
            'sha512Base64': base64.b64encode(other.digest()).decode()}


def fp(path):
    ordinary(path); before = path.stat()
    with path.open('rb') as stream:
        result = digest(stream)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Input changed during hashing')
    return dict(path=str(path), **result)


def same(*rows):
    require(len({(r['bytes'], r['sha256']) for r in rows}) == 1, 'Required producer/consumer bytes differ: ' + repr(rows))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        json.dump(value, output, indent=2); output.write('\n')


def names(runtime):
    return ['dotnet-runtime-' + runtime + '-linux-arm64.tar.gz',
            'aspnetcore-runtime-internal-' + runtime + '-linux-arm64.tar.gz']


def observe(args):
    """Hard links retain the actual destination inode while upstream writes/deletes it."""
    _, runtime, layout, _ = CONFIG[args.family]
    root = args.workspace / 'inputs/observed-installer-inputs'; root.mkdir()
    report = args.output_dir / 'reports/build/installer-observations.jsonl'
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    seen = set()
    while not stop[0]:
        exports = args.source_dir / layout / 'src'
        for component in exports.glob(('installer' if args.family == 'net5' else 'core-sdk') + '.*'):
            downloads = component / 'artifacts/obj/redist/Release/downloads'
            for name in names(runtime):
                original = downloads / name
                if not original.is_file() or original.is_symlink():
                    continue
                stat = original.stat(); key = (str(original), stat.st_dev, stat.st_ino)
                if key in seen:
                    continue
                destination = root / (str(len(seen)) + '-' + name)
                try:
                    os.link(original, destination, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                seen.add(key)
                with report.open('a') as stream:
                    stream.write(json.dumps({'original': str(original), 'retained': str(destination),
                                              'device': stat.st_dev, 'inode': stat.st_ino,
                                              'observedAtUnixNs': time.time_ns(), 'method': 'hardlink-before-upstream-deletion'}) + '\n')
        time.sleep(0.005)
    write(args.output_dir / 'reports/build/installer-observer.json', {'status': 'passed', 'observations': len(seen),
          'scope': 'Destination inode capture only. Final archive hashes and completed task execution must be verified separately.'})


def tar_tree(path, prefix=None, payload_only=False):
    rows = {}; seen = set()
    with tarfile.open(ordinary(path), 'r|gz') as archive:
        for entry in archive:
            name = entry.name[2:] if entry.name.startswith('./') else entry.name
            if entry.isdir() and name.endswith('/'):
                name = name[:-1]
            parsed = PurePosixPath(name)
            require(not parsed.is_absolute() and '..' not in parsed.parts and '\\' not in name, 'Unsafe archive path')
            require(name not in seen, 'Duplicate archive path: ' + name); seen.add(name)
            if prefix is not None and not name.startswith(prefix):
                continue
            if payload_only and not (entry.isfile() and (name == 'dotnet' or name.endswith(('.dll', '.so')))):
                continue
            if entry.isdir():
                continue
            if entry.isfile():
                rows[name] = dict(type='file', mode=entry.mode, **digest(archive.extractfile(entry)))
            elif entry.issym():
                link = PurePosixPath(entry.linkname)
                require(not link.is_absolute() and '\\' not in entry.linkname, 'Unsafe link target')
                resolved = list(parsed.parent.parts)
                for part in link.parts:
                    if part == '..':
                        require(bool(resolved), 'Escaping archive link'); resolved.pop()
                    elif part != '.':
                        resolved.append(part)
                rows[name] = {'type': 'symlink', 'mode': entry.mode, 'target': entry.linkname}
            else:
                raise ValueError('Unexpected archive member type')
    return rows


def completed_copies(reports, source, runtime):
    tasks = []
    for log in sorted(reports.glob('replay-*-download-tasks.jsonl')):
        tasks.extend(json.loads(line) for line in log.read_text().splitlines())
    result = []
    for filename in names(runtime):
        selected = []
        for task in tasks:
            attempts = [row for row in task['events'] if row['kind'] in ('local-copy-attempt', 'network-download-attempt')]
            relevant = [row for row in attempts if (row.get('destination') or '').endswith('/' + filename)]
            if not relevant:
                continue
            require(task['succeeded'] is True and len(relevant) == 1 and relevant[0]['kind'] == 'local-copy-attempt',
                    'A framework task did not complete a sole local copy')
            row = relevant[0]
            require(row['sourceUri'].startswith('file://' + str(source) + '/'), 'Framework source escaped the local build')
            require(sum(e['kind'] == 'task-started' for e in task['events']) == 1
                    and sum(e['kind'] == 'task-finished' and e['succeeded'] is True for e in task['events']) == 1,
                    'Incomplete local task lifecycle')
            selected.append({'context': task['context'], 'source': row['sourceUri'][7:], 'destination': row['destination'],
                             'completed': True, 'task': task})
        require(len(selected) == 1, 'Exactly one completed local input task is required: ' + filename)
        result.append(selected[0])
    return result


def component_dir(source, layout, name):
    found = list((source / layout / 'src').glob(name + '.*'))
    require(len(found) == 1, 'Exactly one component export is required: ' + name)
    return found[0]


def compare_framework(expected, actual):
    require(expected and set(expected) == set(actual), 'Shared framework membership differs')
    adjustments = []
    for name, original in expected.items():
        before = dict(original); after = dict(actual[name])
        original_mode = before.pop('mode'); sdk_mode = after.pop('mode')
        require(before == after, 'Shared framework payload/type/link differs: ' + name)
        if original_mode != sdk_mode:
            require(original['type'] == 'file' and sdk_mode == original_mode & ~0o022,
                    'Unexpected shared framework mode transformation: ' + name)
            adjustments.append({'member': name, 'producerMode': oct(original_mode), 'sdkMode': oct(sdk_mode),
                                'scope': 'Normal archive extraction under umask022 removes only group/world write bits; payload bytes and executable bits are unchanged.'})
    return adjustments


def audit(args):
    sdk_version, runtime, layout, commit = CONFIG[args.family]
    source = args.source_dir; reports = args.output_dir / 'reports/construction'
    require(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD']).decode().strip() == commit, 'Root source pin differs')
    sdk = source / layout / 'arm64/Release' / ('dotnet-sdk-' + sdk_version + '-linux-arm64.tar.gz')
    tasks = completed_copies(reports, source, runtime)
    observations = [json.loads(line) for line in (args.output_dir / 'reports/build/installer-observations.jsonl').read_text().splitlines()]
    components = []
    for index, framework in enumerate(('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App')):
        filename = names(runtime)[index]; task = tasks[index]
        feed_archive = Path(task['source']); local = fp(feed_archive)
        if index == 0:
            producer = (source / 'artifacts/arm64/Release/runtime' / filename if args.family == 'net5' else
                        source / layout / 'obj/arm64/Release/blob-feed/assets' / filename)
        else:
            asp = component_dir(source, layout, 'AspNetCore' if args.family == 'core30' else 'aspnetcore')
            candidates = list((asp / 'artifacts/installers/Release').glob(filename))
            require(len(candidates) == 1, 'Exact ASP.NET producer archive is missing')
            producer = candidates[0]
        produced = fp(producer); same(produced, local)
        captured = []
        for row in observations:
            if row['original'] != task['destination']:
                continue
            retained = fp(Path(row['retained'])); same(local, retained)
            destination = reports / 'retained-inputs' / filename
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(row['retained'], destination)
            same(retained, fp(destination))
            captured.append(dict(row, file=fp(destination)))
        require(len(captured) == 1, 'Exactly one genuine captured destination is required: ' + filename)
        prefix = 'shared/' + framework + '/' + runtime + '/'
        before = fp(sdk); expected = tar_tree(producer, prefix); actual = tar_tree(sdk, prefix)
        metadata_adjustments = compare_framework(expected, actual)
        same(before, fp(sdk))
        components.append({'framework': framework, 'runtimeVersion': runtime, 'originVerified': True,
                           'producerArchive': produced, 'localInputArchive': local, 'capturedDestination': captured[0],
                           'completedLocalCopy': task, 'sharedPrefix': prefix, 'members': expected, 'sdkMembers': actual,
                           'metadataAdjustments': metadata_adjustments,
                           'allArchiveFingerprintsMatch': True, 'sharedMembersCompared': len(expected)})
    if args.family != 'net5':
        native(args, sdk, reports)
    profile = json.loads((args.output_dir / 'reports/ci-inputs/profile.json').read_text())
    profile['construction'] = {'upstreamSharedRuntimeReused': False,
                               'note': 'This fresh CI build proves both locally produced framework archives, completed sole local installer copies, and final SDK shared payload identity. Binary bootstrap inputs remain separate; no clean Stage 2 assertion.'}
    profile['build']['cpuAffinity'] = sorted(os.sched_getaffinity(0))[:2]
    profile['status'] = 'Fresh normal CI root build and local framework origins passed; ci-validation.json is the authoritative final qualification.'
    profile['container']['derivedImageId'] = json.loads((args.workspace / 'ci-legacy-state.json').read_text())['imageId']
    profile['sysroot']['status'] = 'Fresh authenticated sysroot preparation and full revalidation passed; see reports/sysroot.'
    profile['build']['sharedComponents'] = 'Both frameworks were built locally in this fresh graph; see reports/construction/origin-evidence.json.'
    if args.family == 'core30':
        build_status = json.loads((args.output_dir / 'reports/build/product-build/build-status.json').read_text())
        require(build_status['postBuildOfflineSourceBundleDownloadsSkipped'] is True,
                'The explicit CI post-build offline-bundle staging policy was not recorded')
        profile['build']['ciPostBuildSourceBundleStaging']['actualSkipped'] = True
    write(args.output_dir / 'reports/ci/effective-profile.json', profile)
    write(reports / 'origin-evidence.json', {'schemaVersion': 1, 'status': 'passed', 'sourceCommit': commit,
          'sdkArchive': fp(sdk), 'components': components, 'freshCurrentGenerationOnly': True,
          'scope': 'Actual producer bytes, captured destination inodes, completed local tasks and final SDK payloads. No binary-bootstrap-free or reproducible Stage 2 claim.'})


def native(args, sdk, reports):
    # The split-generation auditor is separate so unified .NET 5 cannot bypass it.
    import runpy
    helper = runpy.run_path(str(Path(__file__).with_name('ci-legacy-split-origin.py')))
    write(reports / 'native-component-origin.json', helper['audit'](args, sdk))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['observe', 'audit'])
    parser.add_argument('--family', required=True, choices=CONFIG)
    for option in ('source-dir', 'workspace', 'output-dir'):
        parser.add_argument('--' + option, required=True, type=Path)
    args = parser.parse_args()
    (observe if args.action == 'observe' else audit)(args)


if __name__ == '__main__':
    main()
