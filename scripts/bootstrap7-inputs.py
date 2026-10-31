#!/usr/bin/env python3
"""Preserve original .NET 7 bootstrap inputs and verify the transformed archive."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile


def fingerprint(path):
    sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            sha256.update(data)
            sha512.update(data)
            size += len(data)
    return {'path': str(path), 'bytes': size, 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}


def verify_files(records):
    for record in records:
        path = Path(record['path'])
        if path.is_symlink() or fingerprint(path) != record:
            raise ValueError('Recorded bootstrap input differs: ' + str(path))


def write_new(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['save-originals', 'finalize', 'verify'])
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    for path in [args.source_dir, args.inputs_dir, args.report]:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('Absolute ordinary input/output paths are required')
    source, inputs = args.source_dir.resolve(strict=True), args.inputs_dir.resolve(strict=True)
    archive_dir = source / 'packages/archive'
    marker = inputs / 'bootstrap7-prepared.json'
    originals = inputs / 'bootstrap7-originals.json'
    sdk = source / '.dotnet/dotnet'
    version = subprocess.check_output([str(sdk), '--version'], cwd=source, text=True).strip()
    if version != '7.0.118':
        raise ValueError('Expected the .NET 7.0.118 bootstrap SDK, got ' + version)
    if args.action == 'save-originals':
        archives = sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz'))
        expected = archive_dir / 'Private.SourceBuilt.Artifacts.7.0.118.centos.8-x64.tar.gz'
        if expected not in archives or any('Bootstrap' in path.name for path in archives):
            raise ValueError('The original untransformed source-built input is required')
        if originals.exists():
            record = json.loads(originals.read_text())
            verify_files(record['originalInputs'])
            saved = {Path(item['path']).name: {key: item[key] for key in ['bytes', 'sha256', 'sha512']}
                     for item in record['originalInputs']}
            current = {path.name: {key: value for key, value in fingerprint(path).items() if key != 'path'}
                       for path in archives}
            if current != saved:
                raise ValueError('Current original downloads differ from the preserved inputs; refusing transformation')
        else:
            destination = inputs / 'original-bootstrap7'
            destination.mkdir(exist_ok=False)
            records = []
            for archive in archives:
                if archive.is_symlink() or not archive.is_file():
                    raise ValueError('Bootstrap archives must be ordinary files')
                target = destination / archive.name
                before = fingerprint(archive)
                shutil.copyfile(archive, target)
                after = fingerprint(target)
                if any(before[key] != after[key] for key in ['bytes', 'sha256', 'sha512']):
                    raise ValueError('An original archive changed while being preserved')
                records.append(after)
            record = {'schemaVersion': 1, 'originalInputs': records,
                      'declaredUrls': (archive_dir / 'archiveArtifacts.txt').read_text().splitlines()}
            write_new(originals, record)
    elif args.action == 'finalize':
        original_record = json.loads(originals.read_text())
        verify_files(original_record['originalInputs'])
        archives = sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz'))
        candidates = [path for path in archives if path.name.startswith('Private.SourceBuilt.Artifacts.')]
        if len(candidates) != 1 or 'Bootstrap' not in candidates[0].name:
            raise ValueError('Expected the single explicitly bootstrapped PSB archive')
        with tarfile.open(candidates[0], 'r:gz') as archive:
            names = archive.getnames()
        arm64 = [name for name in names if 'linux-arm64' in name.lower() and name.lower().endswith('.nupkg')]
        if len(arm64) < 10 or not any(name.endswith('PackageVersions.props') for name in names):
            raise ValueError('Bootstrapped archive lacks the expected ARM64 packages/version metadata')
        record = {'schemaVersion': 1, 'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'installerCommit': '25b977658c06fd0217ec0bc0714398bb9d0a7bb0', 'bootstrapSdk': version,
                  **original_record, 'finalInputs': [fingerprint(path) for path in archives], 'arm64PackageEntries': arm64,
                  'bootstrapToolFiles': [fingerprint(path) for path in [source / '.dotnet/sdk/7.0.118/MSBuild.dll',
                                           source / '.dotnet/sdk/7.0.118/.version', source / '.dotnet/dotnet-install.sh'] if path.is_file()],
                  'observedBootstrapHost': fingerprint(sdk),
                  'bootstrapHostNote': 'Observed before the product build. Upstream tool initialization may install an additional pinned runtime and replace unversioned host files; the versioned SDK input files remain verified.',
                  'scope': 'Original downloads preserved before explicit upstream prep.sh --bootstrap; archive integrity is verified independently of final SDK construction.'}
        write_new(marker, record)
    else:
        record = json.loads(marker.read_text())
        if record['installerCommit'] != '25b977658c06fd0217ec0bc0714398bb9d0a7bb0' or record['bootstrapSdk'] != version:
            raise ValueError('Bootstrap marker identity mismatch')
        verify_files(record['originalInputs'])
        verify_files(record['finalInputs'])
        verify_files(record['bootstrapToolFiles'])
    write_new(args.report, record)
    print(json.dumps({'status': 'passed', 'action': args.action, 'report': str(args.report)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
