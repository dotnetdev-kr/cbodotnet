#!/usr/bin/env python3
"""Verify and safely extract a run-specific SDK/source transport bundle."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download-dir', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--sdk-version', required=True)
    parser.add_argument('--expected-project-commit', required=True)
    parser.add_argument('--expected-run-id', required=True)
    parser.add_argument('--expected-run-attempt', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'net(?:5|6|7|8|9|10)|core3[01]', args.target)
            and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.sdk_version), 'Invalid pinned target')
    require(re.fullmatch('[a-f0-9]{40}', args.expected_project_commit)
            and all(re.fullmatch('[1-9][0-9]*', value) for value in (args.expected_run_id, args.expected_run_attempt)), 'Invalid run identity')
    name = 'cbodotnet-{}-linux-arm64-{}-{}.tar.gz'.format(args.target, args.expected_run_id, args.expected_run_attempt)
    download = args.download_dir.absolute(); destination = args.destination.absolute()
    require(download.is_dir() and not any(p.is_symlink() for p in [download, destination, *download.parents, *destination.parents]),
            'Ordinary download/destination paths are required')
    require(not destination.exists() and destination.parent.is_dir(), 'A fresh extraction destination is required')
    require({p.name for p in download.iterdir()} == {name, name + '.sha256', name + '.sha512'}
            and all(p.is_file() and not p.is_symlink() for p in download.iterdir()), 'Unexpected transport files')
    for algorithm, length in [('sha256', 64), ('sha512', 128)]:
        text = (download / (name + '.' + algorithm)).read_text()
        expected = re.fullmatch(r'([a-f0-9]{' + str(length) + r'})  ' + re.escape(name) + r'\n', text)
        digest = hashlib.new(algorithm)
        with (download / name).open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        require(expected and expected[1] == digest.hexdigest(), 'Transport checksum mismatch')
    root_name = args.sdk_version + '-linux-arm64'
    with tarfile.open(download / name, 'r:gz') as archive:
        entries = archive.getmembers(); seen = set(); total = 0
        for entry in entries:
            value = entry.name.rstrip('/') if entry.isdir() else entry.name
            path = PurePosixPath(value)
            require(value and not path.is_absolute() and path.parts[0] == root_name
                    and posixpath.normpath(value) == value and '..' not in path.parts
                    and not any(c in value for c in '\\:\0\n\r') and value not in seen
                    and (entry.isdir() or entry.isfile()), 'Unsafe or duplicate transport member')
            require(value != root_name or entry.isdir(), 'The delivery root must be a directory')
            seen.add(value); total += entry.size
        require(len(entries) <= 200000 and total + 512 * 1024**2 <= shutil.disk_usage(destination.parent).free,
                'Insufficient extraction capacity')
        destination.mkdir(mode=0o700)
        for entry in entries:
            path = destination / entry.name
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as incoming, path.open('xb') as output:
                    shutil.copyfileobj(incoming, output)
            os.chmod(path, entry.mode & 0o777)
    release = destination / root_name
    subprocess.run([sys.executable, str(Path(__file__).parent / 'ci-sdk.py'), 'verify-release',
                    '--target', args.target, '--release-dir', str(release),
                    '--expected-project-commit', args.expected_project_commit,
                    '--expected-run-id', args.expected_run_id, '--expected-run-attempt', args.expected_run_attempt], check=True)
    print(json.dumps({'status': 'passed', 'releaseDirectory': str(release), 'draftCreated': False}))


if __name__ == '__main__':
    main()
