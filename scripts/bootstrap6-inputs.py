#!/usr/bin/env python3
"""Preserve original .NET 6 bootstrap inputs and verify the transformed archive."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET

INSTALLER = 'd638663530d923adbe0442604b7a6562127321e9'
RUNTIME = 'f1dd57165bfd91875761329ac3a8b17f6606ad18'
ARM64_PACKAGES = (
    'runtime.linux-arm64.Microsoft.NETCore.ILAsm',
    'runtime.linux-arm64.Microsoft.NETCore.ILDAsm',
    'runtime.linux-arm64.Microsoft.NETCore.TestHost',
    'runtime.linux-arm64.runtime.native.System.IO.Ports',
)


def source_identity(source):
    for name, expected in [('installer', INSTALLER), ('runtime', RUNTIME)]:
        metadata = source / 'git-info' / (name + '.props')
        if metadata.is_symlink() or not metadata.is_file():
            raise ValueError('Missing ordinary generated-source metadata: ' + str(metadata))
        values = ET.parse(metadata).getroot().findall('./PropertyGroup/GitCommitHash')
        if len(values) != 1 or values[0].text != expected:
            raise ValueError('Generated source identity mismatch: ' + name)
    project = source / 'scripts/bootstrap/buildBootstrapPreviouslySB.csproj'
    references = ET.parse(project).getroot().findall('./ItemGroup/PackageReference')
    actual = [item.get('Include') for item in references if 'linux-arm64' in item.get('Include', '')]
    if sorted(actual) != sorted(ARM64_PACKAGES):
        raise ValueError('Expected the four pinned .NET 6 ARM64 PackageReference replacements')
    return [fingerprint(path) for path in [source / 'prep.sh', project,
            source / 'scripts/bootstrap/OverrideBootstrapVersions.props',
            source / 'packages/archive/archiveArtifacts.txt']]


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
    if inputs == source or inputs.is_relative_to(source):
        raise ValueError('Bootstrap preservation inputs must be outside the generated source')
    if args.report.exists() or args.report.is_symlink():
        raise ValueError('Refusing a previous bootstrap attempt report')
    tool_sources = source_identity(source)
    archive_dir = source / 'packages/archive'
    marker = inputs / 'bootstrap6-prepared.json'
    originals = inputs / 'bootstrap6-originals.json'
    sdk = source / '.dotnet/dotnet'
    version = subprocess.check_output([str(sdk), '--version'], cwd=source, text=True).strip()
    if version != '6.0.135':
        raise ValueError('Expected the .NET 6.0.135 bootstrap SDK, got ' + version)
    versioned_tools = [source / '.dotnet/sdk/6.0.135/MSBuild.dll', source / '.dotnet/sdk/6.0.135/.version']
    if any(path.is_symlink() or not path.is_file() for path in versioned_tools):
        raise ValueError('The pinned versioned bootstrap SDK inputs are incomplete')
    if (source / '.dotnet/dotnet-install.sh').is_file():
        versioned_tools.append(source / '.dotnet/dotnet-install.sh')
    if args.action == 'save-originals':
        archives = sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz'))
        expected = archive_dir / 'Private.SourceBuilt.Artifacts.6.0.135.centos.7-x64.tar.gz'
        if expected not in archives or any('Bootstrap' in path.name for path in archives):
            raise ValueError('The original untransformed source-built input is required')
        if originals.exists():
            record = json.loads(originals.read_text())
            verify_files(record['originalInputs'])
            verify_files(record['bootstrapToolFiles'])
            verify_files(record['bootstrapSourceFiles'])
            saved = {Path(item['path']).name: {key: item[key] for key in ['bytes', 'sha256', 'sha512']}
                     for item in record['originalInputs']}
            current = {path.name: {key: value for key, value in fingerprint(path).items() if key != 'path'}
                       for path in archives}
            if current != saved:
                raise ValueError('Current original downloads differ from the preserved inputs; refusing transformation')
        else:
            destination = inputs / 'original-bootstrap6'
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
                      'installerCommit': INSTALLER, 'bootstrapSdk': version,
                      'bootstrapSourceFiles': tool_sources,
                      'bootstrapToolFiles': [fingerprint(path) for path in versioned_tools],
                      'declaredArm64PackageReferences': list(ARM64_PACKAGES),
                      'declaredUrls': (archive_dir / 'archiveArtifacts.txt').read_text().splitlines()}
            write_new(originals, record)
    elif args.action == 'finalize':
        original_record = json.loads(originals.read_text())
        verify_files(original_record['originalInputs'])
        verify_files(original_record['bootstrapToolFiles'])
        verify_files(original_record['bootstrapSourceFiles'])
        archives = sorted(archive_dir.glob('Private.SourceBuilt.*.tar.gz'))
        candidates = [path for path in archives if path.name.startswith('Private.SourceBuilt.Artifacts.')]
        if len(candidates) != 1 or 'Bootstrap' not in candidates[0].name:
            raise ValueError('Expected the single explicitly bootstrapped PSB archive')
        with tarfile.open(candidates[0], 'r:gz') as archive:
            names = [item.name for item in archive.getmembers() if item.isfile()]
        arm64 = [name for name in names if 'linux-arm64' in name.lower() and name.lower().endswith('.nupkg')]
        replacements = {package: [name for name in arm64 if Path(name).name.lower().startswith(package.lower() + '.')]
                        for package in ARM64_PACKAGES}
        if any(not matches for matches in replacements.values()) or not any(name.endswith('PackageVersions.props') for name in names):
            raise ValueError('Bootstrapped archive lacks the expected ARM64 packages/version metadata')
        record = {'schemaVersion': 1, 'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'installerCommit': 'd638663530d923adbe0442604b7a6562127321e9', 'bootstrapSdk': version,
                  **original_record, 'finalInputs': [fingerprint(path) for path in archives], 'arm64PackageEntries': arm64,
                  'arm64ReplacementEntries': replacements, 'declaredArm64PackageReferenceCount': 4,
                  'observedBootstrapHost': fingerprint(sdk),
                  'bootstrapHostNote': 'Observed before the product build. Upstream tool initialization may install an additional pinned runtime and replace unversioned host files; the versioned SDK input files remain verified.',
                  'scope': 'Original downloads preserved before explicit upstream prep.sh --bootstrap; archive integrity is verified independently of final SDK construction.'}
        write_new(marker, record)
    else:
        record = json.loads(marker.read_text())
        if record['installerCommit'] != 'd638663530d923adbe0442604b7a6562127321e9' or record['bootstrapSdk'] != version:
            raise ValueError('Bootstrap marker identity mismatch')
        verify_files(record['originalInputs'])
        verify_files(record['finalInputs'])
        verify_files(record['bootstrapToolFiles'])
        verify_files(record['bootstrapSourceFiles'])
    write_new(args.report, record)
    print(json.dumps({'status': 'passed', 'action': args.action, 'report': str(args.report)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, ET.ParseError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
