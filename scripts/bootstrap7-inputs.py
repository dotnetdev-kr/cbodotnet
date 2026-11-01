#!/usr/bin/env python3
"""Preserve original .NET 7 bootstrap inputs and verify the transformed archive."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile

NATIVE_PSB = {'bytes': 1019244017,
              'sha256': '0a4e8447c72047bf7d73d0766abba315d64976fdc8aef7236ddee0bbb62dfa5d',
              'sha512': '81855dca272361aa837a927d3cf40b899b84aebef73d9ea94082fa36b96d539d29bb8fa8781020b70778ea08672271e81f1d5b194214d1b0d035230eea8b72dc'}


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


def native_host(sdk):
    if sdk.is_symlink() or not sdk.is_file():
        raise ValueError('The native x64 bootstrap SDK host must be an ordinary file')
    with sdk.open('rb') as stream: header = stream.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 62:
        raise ValueError('The native x64 bootstrap SDK host must be ELF64 little-endian machine 62')


def native_inputs(source, archives, original_record, sdk, version):
    """Bind the unchanged original CentOS x64 PSB input on a native x64 host."""
    expected = 'Private.SourceBuilt.Artifacts.7.0.118.centos.8-x64.tar.gz'
    if original_record.get('targetArchitecture') != 'x64' or original_record.get('bootstrapMode') != 'native-original-inputs':
        raise ValueError('Preserved bootstrap inputs belong to another architecture/mode')
    if any(path.is_symlink() or not path.is_file() for path in archives):
        raise ValueError('Native x64 archives must remain ordinary files')
    candidates = [path for path in archives if path.name.startswith('Private.SourceBuilt.Artifacts.')]
    if len(candidates) != 1 or candidates[0].name != expected or any('Bootstrap' in path.name for path in archives):
        raise ValueError('Native x64 requires the unchanged original CentOS x64 PSB archive')
    saved = {Path(row['path']).name: {key: row[key] for key in ['bytes', 'sha256', 'sha512']}
             for row in original_record['originalInputs']}
    current = {path.name: {key: value for key, value in fingerprint(path).items() if key != 'path'} for path in archives}
    if saved != current:
        raise ValueError('Native x64 PSB inputs differ from the preserved original bytes')
    if current[expected] != NATIVE_PSB:
        raise ValueError('Native x64 PSB differs from the exact retained upstream input pin')
    with tarfile.open(candidates[0], 'r:gz') as archive:
        names = [item.name for item in archive if item.isfile()]
    entries = sorted(name for name in names if 'centos.8-x64' in name.lower() and name.lower().endswith('.nupkg'))
    if len(entries) != 12 or not any(name.endswith('PackageVersions.props') for name in names):
        raise ValueError('The original x64 PSB lacks native packages or version metadata')
    native_host(sdk)
    return {'schemaVersion': 1, 'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **original_record, 'installerCommit': '25b977658c06fd0217ec0bc0714398bb9d0a7bb0', 'bootstrapSdk': version,
            'targetArchitecture': 'x64', 'bootstrapMode': 'native-original-inputs',
            'nativePackageRid': 'centos.8-x64',
            'finalInputs': [fingerprint(path) for path in archives], 'nativePackageEntries': entries,
            'observedBootstrapHost': fingerprint(sdk),
            'bootstrapHostNote': 'Observed before the product build; versioned SDK input files remain verified after upstream host initialization.',
            'scope': 'Native x64 consumes the preserved original x64 PSB without ARM64 package substitution or prep.sh --bootstrap transformation.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['save-originals', 'finalize', 'verify'])
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    args = parser.parse_args()
    if args.arch == 'x64' and (platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        raise ValueError('A matching native Linux x64 preparation host is required')
    for path in [args.source_dir, args.inputs_dir, args.report]:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('Absolute ordinary input/output paths are required')
    source, inputs = args.source_dir.resolve(strict=True), args.inputs_dir.resolve(strict=True)
    archive_dir = source / 'packages/archive'
    marker = inputs / 'bootstrap7-prepared.json'
    originals = inputs / 'bootstrap7-originals.json'
    sdk = source / '.dotnet/dotnet'
    if args.arch == 'x64': native_host(sdk)
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
            if args.arch == 'x64':
                tools = [source / '.dotnet/sdk/7.0.118/MSBuild.dll', source / '.dotnet/sdk/7.0.118/.version']
                if any(path.is_symlink() or not path.is_file() for path in tools):
                    raise ValueError('The pinned versioned bootstrap SDK inputs are incomplete')
                if (source / '.dotnet/dotnet-install.sh').is_file(): tools.append(source / '.dotnet/dotnet-install.sh')
                record.update(targetArchitecture='x64', bootstrapMode='native-original-inputs',
                              bootstrapToolFiles=[fingerprint(path) for path in tools])
            write_new(originals, record)
    elif args.action == 'finalize':
        original_record = json.loads(originals.read_text())
        verify_files(original_record['originalInputs'])
        archives = sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz'))
        if args.arch == 'x64':
            verify_files(original_record['bootstrapToolFiles'])
            record = native_inputs(source, archives, original_record, sdk, version)
            write_new(marker, record); write_new(args.report, record)
            print(json.dumps({'status': 'passed', 'action': args.action, 'report': str(args.report)}))
            return
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
        if record.get('targetArchitecture', 'arm64') != args.arch:
            raise ValueError('Bootstrap marker belongs to another architecture')
        if args.arch == 'x64':
            if record.get('targetArchitecture') != 'x64' or record.get('bootstrapMode') != 'native-original-inputs':
                raise ValueError('Native x64 bootstrap marker architecture/mode differs')
            current = native_inputs(source, sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz')), record, sdk, version)
            if current['nativePackageEntries'] != record['nativePackageEntries']:
                raise ValueError('Native x64 package inventory differs')
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
