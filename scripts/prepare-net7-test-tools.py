#!/usr/bin/env python3
"""Prepare a pinned external OmniSharp fixture for the unmodified .NET 7 tests.

The selected official net6.0 build can use the tested .NET 7 runtime. A single
recorded run -> OmniSharp symlink adapts the historical test launcher name.
This is a test input adaptation, not the upstream default download behavior.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET


VERSION = '1.39.6'
URL = 'https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.6/omnisharp-linux-arm64-net6.0.tar.gz'
SIZE = 41382979
SHA256 = '6e097febba7dc2a1422f1cb992e358a063412c05a08eb6719388561e3a75c734'
INSTALLER = '25b977658c06fd0217ec0bc0714398bb9d0a7bb0'
DESTINATION = 'test/Microsoft.DotNet.SourceBuild.SmokeTests/bin/Release/net7.0/omnisharp'
CACHE_NAME = 'omnisharp-v1.39.6-linux-arm64-net6.0.tar.gz'
ARCH_SPEC = importlib.util.spec_from_file_location('ci_arch_test_tools', Path(__file__).with_name('ci_arch.py'))
ARCH = importlib.util.module_from_spec(ARCH_SPEC); ARCH_SPEC.loader.exec_module(ARCH)


def tool_input(arch='arm64'):
    identity = ARCH.get_arch(arch)
    if arch == 'arm64':
        return dict(url=URL, bytes=SIZE, sha256=SHA256, cacheName=CACHE_NAME, machine=identity['machine'])
    return dict(url='https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.6/omnisharp-linux-x64-net6.0.tar.gz',
                bytes=43149563, sha256='c631cf552590ee8f00cbea441e99a94f689bf1832f1f8de2d5a00d5d5d18140c',
                cacheName='omnisharp-v1.39.6-linux-x64-net6.0.tar.gz', machine=identity['machine'])


def fingerprint(path):
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(data)
            size += len(data)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def ordinary_directory(path, create=False):
    if not path.is_absolute():
        raise ValueError('An absolute directory path is required: ' + str(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in ('.', '..'):
            raise ValueError('Directory traversal is not allowed')
        current = current / part
        if current.is_symlink():
            raise ValueError('A directory ancestor is a symlink: ' + str(current))
        if create:
            current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError('An ordinary directory is required: ' + str(current))
    return path.resolve(strict=True)


def write_identical_or_new(path, contents):
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != contents:
            raise ValueError('Refusing a different existing input receipt: ' + str(path))
        return
    with path.open('xb') as stream:
        stream.write(contents)


def cached_archive(directory, arch='arm64'):
    pin = tool_input(arch)
    target = directory / pin['cacheName']
    downloaded = False
    if not target.exists() and not target.is_symlink():
        staged = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, prefix='.omnisharp-download-', delete=False) as output:
                staged = Path(output.name)
                with urllib.request.urlopen(pin['url'], timeout=120) as response:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('The official download redirected outside HTTPS')
                    size = 0
                    for data in iter(lambda: response.read(1024 * 1024), b''):
                        size += len(data)
                        if size > pin['bytes']:
                            raise ValueError('OmniSharp download exceeds the pinned byte count')
                        output.write(data)
            if fingerprint(staged) != {'bytes': pin['bytes'], 'sha256': pin['sha256']}:
                raise ValueError('Downloaded OmniSharp archive differs from the pinned input')
            # Publish without replacing a concurrent or pre-existing cache entry.
            try:
                os.link(staged, target)
                downloaded = True
            except FileExistsError:
                pass
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
    if target.is_symlink() or not target.is_file() or fingerprint(target) != {'bytes': pin['bytes'], 'sha256': pin['sha256']}:
        raise ValueError('Existing OmniSharp archive differs; preserve it and select a clean input cache')
    return target, downloaded


def member_name(name):
    if name.startswith('/') or '\\' in name or '..' in PurePosixPath(name).parts:
        raise ValueError('Unsafe archive path: ' + name)
    normalized = str(PurePosixPath(name))
    if normalized == 'run' or normalized.startswith('run/'):
        raise ValueError('The pinned archive unexpectedly contains the local launcher name')
    return normalized


def archive_inventory(archive_path, staging=None):
    records = {}
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        # This pinned archive contains only ordinary files/directories. Reject
        # links and special entries before creating any extracted content.
        for member in members:
            name = member_name(member.name)
            if name in records or not (member.isfile() or member.isdir()) or member.mode & 0o7000:
                raise ValueError('Duplicate or unsupported archive entry: ' + member.name)
            if name == '.' and not member.isdir():
                raise ValueError('The archive root must be a directory')
            records[name] = {'path': name, 'type': 'directory' if member.isdir() else 'file',
                             'mode': member.mode & 0o777}
        for name, record in records.items():
            parent = PurePosixPath(name).parent
            while str(parent) != '.':
                if str(parent) not in records or records[str(parent)]['type'] != 'directory':
                    raise ValueError('Archive parent is absent or not a directory: ' + name)
                parent = parent.parent
        for member in members:
            name = member_name(member.name)
            record = records[name]
            destination = staging / name if staging is not None else None
            if member.isdir():
                if destination is not None:
                    destination.mkdir(parents=True, exist_ok=True)
                continue
            digest, size = hashlib.sha256(), 0
            if destination is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
            output = destination.open('xb') if destination is not None else None
            try:
                with archive.extractfile(member) as stream:
                    for data in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(data)
                        size += len(data)
                        if output is not None:
                            output.write(data)
            finally:
                if output is not None:
                    output.close()
            if size != member.size:
                raise ValueError('Archive entry size changed: ' + name)
            record.update({'bytes': size, 'sha256': digest.hexdigest()})
            if destination is not None:
                destination.chmod(record['mode'])
        if staging is not None:
            for record in sorted(records.values(), key=lambda item: len(PurePosixPath(item['path']).parts), reverse=True):
                if record['type'] == 'directory':
                    (staging / record['path']).chmod(record['mode'])
    return sorted(records.values(), key=lambda item: item['path'])


def verify_extraction(destination, expected, arch='arm64'):
    pin = tool_input(arch)
    actual = {'.': {'path': '.', 'type': 'directory', 'mode': stat.S_IMODE(destination.stat().st_mode)}}
    for directory, directories, files in os.walk(destination, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            relative = path.relative_to(destination).as_posix()
            if path.is_symlink():
                if relative != 'run' or os.readlink(path) != 'OmniSharp':
                    raise ValueError('Unexpected test-tool symlink: ' + relative)
                continue
            mode = path.stat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('Unexpected test-tool entry: ' + relative)
            actual[relative] = {'path': relative, 'type': 'directory' if stat.S_ISDIR(mode) else 'file',
                                'mode': stat.S_IMODE(mode)}
            if stat.S_ISREG(mode):
                actual[relative].update(fingerprint(path))
    if sorted(actual.values(), key=lambda item: item['path']) != expected:
        raise ValueError('Existing OmniSharp extraction differs from pinned member hashes/modes; preserve it for inspection')
    launcher = destination / 'run'
    if not launcher.is_symlink() or os.readlink(launcher) != 'OmniSharp':
        raise ValueError('The recorded run -> OmniSharp launcher adapter is missing or different')
    config = json.loads((destination / 'OmniSharp.runtimeconfig.json').read_bytes())
    options = config.get('runtimeOptions', {})
    if (options.get('tfm') != 'net6.0' or options.get('rollForward') != 'LatestMajor'
            or options.get('framework') != {'name': 'Microsoft.NETCore.App', 'version': '6.0.0-preview.7.21317.1'}):
        raise ValueError('Unexpected OmniSharp runtime/roll-forward requirements')
    with (destination / 'OmniSharp').open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != pin['machine']:
        raise ValueError('Expected an ELF64 little-endian matching-architecture OmniSharp apphost')
    return config


def prepare(args, record):
    arch = getattr(args, 'arch', 'arm64'); pin = tool_input(arch)
    source = ordinary_directory(args.source_dir)
    inputs = ordinary_directory(args.inputs_dir)
    reports = ordinary_directory(args.reports_dir)
    if reports == source or reports.is_relative_to(source) or reports == inputs or reports.is_relative_to(inputs):
        raise ValueError('Reports must be outside the generated source and input directories')
    metadata = source / 'git-info/installer.props'
    ordinary_directory(metadata.parent)
    if metadata.is_symlink() or not metadata.is_file():
        raise ValueError('Expected generated installer revision metadata')
    revisions = ET.parse(metadata).getroot().findall('./PropertyGroup/GitCommitHash')
    if len(revisions) != 1 or revisions[0].text != INSTALLER:
        raise ValueError('Generated installer revision differs from the selected .NET 7 source')
    destination = source / DESTINATION
    parent = ordinary_directory(destination.parent, create=True)
    if not destination.is_relative_to(source) or destination.is_symlink():
        raise ValueError('The fixed test-tool destination must remain inside the generated source')
    if destination.exists() and not destination.is_dir():
        raise ValueError('The test-tool destination already exists as a non-directory')
    cache = ordinary_directory(inputs / 'test-tools', create=True)
    archive, downloaded = cached_archive(cache, arch)
    reused = destination.exists()
    if reused:
        members = archive_inventory(archive)
    else:
        with tempfile.TemporaryDirectory(dir=parent, prefix='.omnisharp-stage-') as temporary:
            staging = Path(temporary) / 'payload'
            staging.mkdir()
            members = archive_inventory(archive, staging)
            (staging / 'run').symlink_to('OmniSharp')
            verify_extraction(staging, members, arch)
            if destination.exists() or destination.is_symlink():
                raise ValueError('A concurrent test-tool destination appeared; preserve it for inspection')
            staging.rename(destination)
    config = verify_extraction(destination, members, arch)
    receipt = {'schemaVersion': 1, 'archiveSha256': pin['sha256'], 'archiveBytes': pin['bytes'], 'members': members,
               'extraEntries': [{'path': 'run', 'type': 'symlink', 'target': 'OmniSharp'}]}
    receipt_bytes = (json.dumps(receipt, indent=2) + '\n').encode('utf-8')
    cache_receipt = cache / pin['cacheName'].replace('.tar.gz', '.members.json')
    write_identical_or_new(cache_receipt, receipt_bytes)
    attempt_receipt = reports / 'net7-test-tool-members.json'
    write_identical_or_new(attempt_receipt, receipt_bytes)
    record.update({'status': 'passed', 'installerCommit': INSTALLER, 'archivePath': str(archive),
                   'downloaded': downloaded, 'extractionReused': reused, 'destination': str(destination),
                   'runtimeConfig': config, 'archiveEntryCount': len(members),
                   'memberReceipt': {'path': str(attempt_receipt), **fingerprint(attempt_receipt)},
                   'cachedMemberReceipt': str(cache_receipt), 'extractedMembersVerified': True,
                   'launcherAdapter': {'path': str(destination / 'run'), 'type': 'symlink', 'target': 'OmniSharp',
                                       'reason': 'The unchanged .NET 7 tests invoke run; the pinned net6.0 release names its apphost OmniSharp.'}})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--arch', choices=['arm64','x64'], default='arm64')
    args = parser.parse_args()
    pin = tool_input(args.arch)
    source = ordinary_directory(args.source_dir)
    inputs = ordinary_directory(args.inputs_dir)
    reports = ordinary_directory(args.reports_dir)
    if reports == source or reports.is_relative_to(source) or reports == inputs or reports.is_relative_to(inputs):
        raise ValueError('Reports must be outside the generated source and input directories')
    report = reports / 'net7-test-tools.json'
    record = {'schemaVersion': 1, 'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'failed', 'tool': 'OmniSharp', 'version': VERSION, 'url': pin['url'],
              'expectedArchive': {'bytes': pin['bytes'], 'sha256': pin['sha256']},
              'scope': 'Pinned external test fixture and one launcher-name adapter for the unmodified .NET 7 scenarios. This is not the upstream default download, an SDK/source patch, or a claim that the scenarios passed. Archive file contents are preserved; ownership and timestamps are not compared. No Mono installation or test exclusion is used.'}
    result = 0
    with report.open('x', encoding='utf-8') as output:
        try:
            prepare(args, record)
        except (OSError, ValueError, ET.ParseError, tarfile.TarError) as error:
            record['error'] = str(error)
            result = 1
        finally:
            record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            json.dump(record, output, indent=2)
            output.write('\n')
    print(json.dumps({'status': record['status'], 'report': str(report), 'error': record.get('error')}))
    return result


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        raise SystemExit('error: ' + str(error))
