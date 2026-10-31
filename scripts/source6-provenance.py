#!/usr/bin/env python3
"""Record or verify the pinned installer-generated .NET 6 source inputs."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

INSTALLER = 'd638663530d923adbe0442604b7a6562127321e9'
RUNTIME = 'f1dd57165bfd91875761329ac3a8b17f6606ad18'


def fingerprint(path):
    sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            sha256.update(data)
            sha512.update(data)
            size += len(data)
    return {'path': str(path), 'bytes': size, 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}


def revision(path):
    return subprocess.check_output(['git', '--no-optional-locks', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()


def identity(installer, source):
    if revision(installer) != INSTALLER:
        raise ValueError('Installer checkout does not match the pinned revision')
    metadata = source / 'git-info'
    records = []
    components = {}
    for path in sorted(metadata.glob('*.props')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Generated metadata must be ordinary files')
        records.append(fingerprint(path))
        root = ET.parse(path).getroot()
        if path.name == 'AllRepoVersions.props':
            values = root.findall('./PropertyGroup/installerGitCommitHash')
            if len(values) != 1 or values[0].text != INSTALLER:
                raise ValueError('AllRepoVersions installer revision mismatch')
        else:
            values = root.findall('./PropertyGroup/GitCommitHash')
            if len(values) == 1:
                components[path.stem] = values[0].text
    if components.get('installer') != INSTALLER or components.get('runtime') != RUNTIME:
        raise ValueError('Generated installer/runtime revisions do not match')
    if not any(Path(record['path']).name == 'AllRepoVersions.props' for record in records):
        raise ValueError('Missing generated aggregate Git metadata')
    for name, expected in components.items():
        repository = source / 'src' / name
        if (repository / '.git').exists() and revision(repository) != expected:
            raise ValueError('Preserved component Git revision mismatch: ' + name)
    return records, components


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['snapshot', 'verify'])
    parser.add_argument('--installer-dir', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    for path in [args.installer_dir, args.source_dir, args.reports_dir]:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('Absolute ordinary directory paths are required')
    installer, source = args.installer_dir.resolve(strict=True), args.source_dir.resolve(strict=True)
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    reports = args.reports_dir.resolve(strict=True)
    if reports == source or reports.is_relative_to(source) or reports == installer or reports.is_relative_to(installer):
        raise ValueError('Reports must be outside both source trees')
    metadata, components = identity(installer, source)
    path = reports / 'generation.json'
    if args.action == 'verify':
        record = json.loads(path.read_text())
        if record['installerCommit'] != INSTALLER or record['gitInfoFiles'] != metadata:
            raise ValueError('Generated source metadata differs from its snapshot')
        archive = Path(record['sourceArchive']['path'])
        if archive.is_symlink() or fingerprint(archive) != record['sourceArchive']:
            raise ValueError('Source archive differs from its snapshot')
    else:
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing to overwrite an existing generation snapshot')
        archive = args.archive
        if archive is None:
            candidates = list((installer / 'artifacts/packages').glob('**/Shipping/dotnet-sdk-source-6.0.136*.tar.gz'))
            if len(candidates) != 1:
                raise ValueError('Expected one generated .NET 6 source archive; specify --archive explicitly')
            archive = candidates[0]
        if not archive.is_absolute() or archive.is_symlink() or not archive.is_file():
            raise ValueError('The source archive must be an absolute ordinary file')
        record = {'schemaVersion': 1, 'recordedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'installerCommit': INSTALLER, 'installerDirectory': str(installer), 'generatedSourceDirectory': str(source),
                  'sourceArchive': fingerprint(archive.resolve(strict=True)), 'gitInfoFiles': metadata,
                  'componentCommits': components, 'preserveTarballGitFolders': True,
                  'scope': 'Pinned generator checkout, generated component revision metadata and source archive integrity. The build may modify generated configuration and apply recorded patches; this is not a claim that the final working tree equals the archive.'}
        with path.open('x', encoding='utf-8') as output:
            json.dump(record, output, indent=2)
            output.write('\n')
    print(json.dumps({'status': 'passed', 'action': args.action, 'report': str(path), 'componentCount': len(components)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, ET.ParseError) as error:
        raise SystemExit('error: ' + str(error))
