"""Retain original-matrix NuGet outputs and bind their DLLs to actual Csc tasks.

This producer-side helper reads completed binary-log replays and ordinary files.
It never executes an SDK or changes a package. Built outputs and actual restore
records remain separate; emitting an unused package is not a consumption claim.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import musl_legacy_admission as A

ORIGIN = 'rebuilt-exact-nuget-original-library-target-matrix'
VERSION = '6.4.3-rc.1'


def ordinary(path):
    path = Path(path).absolute()
    A.require(path.is_file() and not any(part.is_symlink() for part in (path, *path.parents)),
              'An ordinary unchanged NuGet evidence file is required')
    return path


def retain(release, source, relative):
    source = ordinary(source)
    target = release / A.portable(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    A.require(not any(part.is_symlink() for part in (target, *target.parents)), 'Redirected NuGet evidence destination')
    if target.exists():
        A.require(A.fingerprint(target) == A.fingerprint(source), 'Refusing to replace different retained NuGet evidence')
    elif target != source:
        shutil.copyfile(source, target)
    return dict(path=relative, **A.fingerprint(target))


def write(release, relative, value):
    target = release / A.portable(relative)
    raw = (json.dumps(value, indent=2) + '\n').encode()
    target.parent.mkdir(parents=True, exist_ok=True)
    A.require(not any(part.is_symlink() for part in (target, *target.parents)), 'Redirected NuGet evidence destination')
    A.require(not target.exists() or target.read_bytes() == raw, 'Refusing to replace different NuGet evidence')
    if not target.exists():
        target.write_bytes(raw)
    return dict(path=relative, **A.fingerprint(target))


def same_identity(row, actual):
    return all(row.get(key) == actual[key] for key in A.FP)


def feed_record(context, path, commit):
    value = A.load(path)
    if isinstance(value, dict):
        return value
    A.require(context.get('diagnosticOnly') is True and isinstance(value, list)
              and context.get('bootstrapFeedDir'), 'Only explicit diagnostic old-feed lists may be normalized')
    directory = Path(context['bootstrapFeedDir'])
    rows = []
    for row in value:
        A.require(isinstance(row.get('file'), str) and A.portable(row['file']) == PurePosixPath(row['file']).name,
                  'An ordinary original feed filename is required')
        matches = [file for file in directory.iterdir() if file.name.lower() == row['file'].lower()]
        A.require(len(matches) == 1, 'Exact immutable old diagnostic feed output is missing')
        file = ordinary(matches[0])
        fp = A.fingerprint(file)
        A.require(row.get('sha256') == fp['sha256'], 'Old diagnostic feed output differs from its original index')
        origin = row.get('origin')
        if origin == 'source-built-exact-nuget-original-library-matrix':
            A.require(row.get('sourceCommit') == commit, 'Old diagnostic NuGet source identity differs')
            origin = ORIGIN
        rows.append(dict(row, origin=origin, extraPath=str(file), **fp))
    return dict(diagnosticOnly=True, packages=rows)


def output_file(filename, mount, source):
    A.require(isinstance(filename, str) and filename.startswith(mount + '/')
              and filename == posixpath.normpath(filename) and not any(c in filename for c in '\\\0\r\n'),
              'Actual NuGet compiler output escaped its source mount')
    return ordinary(source.joinpath(*PurePosixPath(filename).relative_to(mount).parts))


def find_package(row, release, feed_path, restored_path, restored, source, directories):
    """Find exactly recorded bytes; a same-version freshly packed ZIP is insufficient."""
    candidates = []
    bases = [release, *feed_path.parents]
    if restored_path is not None:
        bases.extend(restored_path.parents)
    for record in [row, *[item for item in restored if same_identity(item, row)]]:
        for field in ('retained', 'extraPath'):
            if isinstance(record.get(field), str):
                value = Path(record[field])
                candidates.extend([value] if value.is_absolute() else [base / A.portable(str(value)) for base in bases])
        if record.get('cache') and record.get('path'):
            candidates.append(Path(record['cache']) / A.portable(record['path']))
    # Existing diagnostic releases can predate the feed's retained field.
    candidates.extend(base / 'imported-inputs' / (row['sha256'] + '.nupkg') for base in bases)
    for directory in [source / 'artifacts/nupkgs', *map(Path, directories)]:
        if directory.is_dir():
            candidates.extend(path for path in directory.iterdir() if path.name.lower() == row['file'].lower())
    for path in dict.fromkeys(candidates):
        if path.is_file() and same_identity(row, A.fingerprint(ordinary(path))):
            return path
    return None


def emit(context, release, roots):
    """Return replay FP, all 19 built-package records and actual restore subsets.

    Required context: sdkVersion, nugetReplay {status,tasks,binlog,
    sourceMountRoot}, bootstrapFeed (JSON path). restoredInputs is optional.
    roots['nuget'] supplies the original source path and exact commit. Optional
    nugetPackageDirectories only locates already fingerprinted unchanged files.
    diagnosticOnly permits a fresh *unused* wrapper when explicitly reported;
    it never changes an actual restore record or authorizes admission.
    """
    A.require(context.get('sdkVersion') == '7.0.120', 'Unreviewed NuGet source-build evidence route')
    root = roots['nuget']
    source = Path(root['path']).absolute()
    commit = A.POLICIES['7.0.120']['nuget']
    A.require(root.get('kind', 'git') == 'git' and root.get('commit') == commit, 'Exact original NuGet source is required')
    actual_commit = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source),
                                             'rev-parse', 'HEAD'], text=True).strip()
    A.require(actual_commit == commit, 'NuGet evidence source checkout commit differs')
    release = Path(release).absolute()
    replay_input = context['nugetReplay']
    status = A.load(ordinary(replay_input['status']))
    A.require(status.get('completedReplay') is True and status.get('buildSucceeded') is True
              and status.get('unfinishedTasks') == 0 and status.get('unfinishedSelectedTasks', 0) == 0,
              'A complete successful original NuGet build replay is required')
    binlog = retain(release, replay_input['binlog'], 'reports/build/nuget.binlog')
    A.require(status.get('inputSha256') == binlog['sha256'], 'NuGet replay does not bind its actual binary log')
    task_descriptor = retain(release, replay_input['tasks'], 'reports/build/nuget-tasks.jsonl')
    tasks = A.read_tasks(release / task_descriptor['path'])
    mount = replay_input['sourceMountRoot']
    A.require(isinstance(mount, str) and mount.startswith('/') and mount == posixpath.normpath(mount)
              and not any(c in mount for c in '\\\0\r\n'), 'Exact ordinary NuGet source mount required')
    compiled = {}
    for task in tasks.values():
        if task['taskName'] != 'Csc' or task['succeeded'] is not True:
            continue
        for filename in sorted(A.task_values(task, 'OutputAssembly')):
            output = output_file(filename, mount, source)
            compiled.setdefault(A.fingerprint(output)['sha256'], []).append((task['context'], filename))
    A.require(compiled, 'Actual original NuGet compiler outputs are absent')
    feed_path = ordinary(context['bootstrapFeed'])
    feed = feed_record(context, feed_path, commit)
    built = [row for row in feed['packages'] if row.get('origin') == ORIGIN]
    expected = {package + '.' + VERSION + '.nupkg' for package in A.NUGET7_PACKAGES}
    A.require(len(built) == 19 and {row['file'].lower() for row in built} == expected
              and all(row.get('sourceCommit') == commit for row in built), 'The exact nineteen original NuGet products are required')
    restored_path = ordinary(context['restoredInputs']) if context.get('restoredInputs') else None
    restored = A.load(restored_path)['packages'] if restored_path is not None else []
    rows, records, derivations, replacements = [], [], [], {}
    for row in sorted(built, key=lambda item: item['file'].lower()):
        actual_restores = [item for item in restored if same_identity(item, row)]
        directories = list(context.get('nugetPackageDirectories', []))
        if context.get('bootstrapFeedDir'):
            directories.append(context['bootstrapFeedDir'])
        original = find_package(row, release, feed_path, restored_path, restored, source, directories)
        if original is None:
            A.require(context.get('diagnosticOnly') is True and not actual_restores,
                      'Exact retained built NuGet package bytes are unavailable')
            matches = [path for path in (source / 'artifacts/nupkgs').iterdir() if path.name.lower() == row['file'].lower()]
            A.require(len(matches) == 1, 'One explicit fresh unused diagnostic NuGet wrapper is required')
            original = ordinary(matches[0])
            derivations.append(dict(file=row['file'], original=dict((key, row[key]) for key in A.FP),
                fresh=A.fingerprint(original), actualRestoreRecords=[],
                reason='Unused diagnostic output: unchanged primary library members are separately bound to actual Csc; ZIP wrapper is not an old consumed input'))
        fp = A.fingerprint(original)
        package = retain(release, original, 'imported-inputs/' + fp['sha256'] + '.nupkg')
        metadata = A.nuspec_metadata(original)
        package_id, version = metadata.findtext('{*}id'), metadata.findtext('{*}version')
        A.require(package_id.lower() + '.' + VERSION + '.nupkg' == row['file'].lower() and version == VERSION,
                  'Retained NuGet product package identity differs')
        count = 0
        for member, identity in A.members(original, 'managed-package').items():
            if not member.lower().endswith('.dll') or member.lower().endswith('.resources.dll') or A.shipping_family(member) != 'nuget':
                continue
            matches = [(context_id, filename) for context_id, filename in compiled.get(identity['sha256'], [])
                       if PurePosixPath(filename).name == PurePosixPath(member).name]
            A.require(matches, 'NuGet primary package DLL has no actual successful compiler output: ' + member)
            context_id, filename = matches[0]
            rows.append(dict(packagePath=package['path'], member=member, sha256=identity['sha256'], sourceRoot='nuget',
                             sourceCommit=commit, context=context_id, outputPath=filename))
            count += 1
        A.require(count, 'Original NuGet product package has no primary library')
        replacements[row['file'].lower()] = dict(row, retained=package['path'], **fp)
        records.append(dict(replacements[row['file'].lower()], id=package_id, version=version,
                            actualRestoreRecords=actual_restores))
    replay = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
        inputSha256=status['inputSha256'], tasks=task_descriptor, sourceMountRoot=mount,
        compiledOutputs=rows, transformations=[])
    descriptor = write(release, 'reports/build/nuget-replay.json', replay)
    target_feed = release / 'reports/build/bootstrap-feed.json'
    if target_feed.exists():
        A.require(not derivations and A.load(target_feed) == feed, 'An existing normal bootstrap-feed record may not be rewritten')
    else:
        output_feed = dict(feed, packages=[replacements.get(row['file'].lower(), row) for row in feed['packages']])
        if isinstance(A.load(feed_path), list):
            output_feed['originalIndex'] = retain(release, feed_path, 'reports/build/nuget-original-feed-index.json')
        if derivations:
            output_feed.update(diagnosticOnly=True, unusedWrapperDerivations=derivations)
        write(release, 'reports/build/bootstrap-feed.json', output_feed)
    # Independently reparse the retained packages/tasks with the admission
    # validator; all present primary DLL TFMs must be covered exactly once.
    proof = A.validate_nuget_build(release, dict(sdkVersion='7.0.120'), descriptor,
                                 dict(nuget=dict(kind='git', commit=commit)))
    return dict(replay=descriptor, builtPackages=records, primaryLibraryMembers=len(proof['members']),
                diagnosticUnusedWrapperDerivations=derivations)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True, type=Path)
    parser.add_argument('--release-dir', required=True, type=Path)
    args = parser.parse_args()
    context = A.load(args.context)
    print(json.dumps(emit(context, args.release_dir, context['sourceRoots'])))
