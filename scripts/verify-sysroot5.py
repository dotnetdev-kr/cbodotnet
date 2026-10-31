#!/usr/bin/env python3
"""Verify the complete recorded .NET 5 ARM64 Xenial target sysroot."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


def within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    args = parser.parse_args()
    for path in (args.sysroot, args.reports_dir):
        if not path.is_absolute() or not path.is_dir() or any(p.is_symlink() for p in [path] + list(path.parents)):
            raise ValueError('Absolute ordinary sysroot/report directories are required')
    root, reports = args.sysroot.resolve(), args.reports_dir.resolve()
    provenance_path = reports / 'sysroot-provenance.json'
    if provenance_path.is_symlink():
        raise ValueError('Sysroot provenance must be an ordinary file')
    provenance = json.loads(provenance_path.read_text())
    if (provenance.get('sourceCommit') != 'd414ecb2d997a9b3f38aaaeddace30ca097e546d' or
            provenance.get('runtimeCommit') != '6a984143635bde23e728abaaccbde52f5ea8fa3e' or
            provenance.get('generatorSha256') != 'bd94cd8083b3b9ddcb7e3187181f296254e7c227e1a117a83940f29e5d8a61ef' or
            provenance.get('sourcesSha256') != '1faf6648c681e1eeae3a44ba3dd36e2175861898c0ce4f1329d5857d78dfdc8e' or
            provenance.get('sysroot') != str(root) or provenance.get('packageSignatureVerification') is not True or
            provenance.get('releaseSignatureLogVerified') is not True):
        raise ValueError('The target sysroot provenance does not match the .NET 5 producer')
    manifest = reports / 'sysroot-files.sha256'
    for name in ('sysroot-files.sha256', 'sysroot-file-list.sha256', 'sysroot-symlinks.tsv', 'sysroot-packages.tsv'):
        if (reports / name).is_symlink() or not (reports / name).is_file():
            raise ValueError('Missing ordinary sysroot inventory file')
    data = manifest.read_bytes()
    if (reports / 'sysroot-file-list.sha256').read_text() != hashlib.sha256(data).hexdigest() + '  ' + str(manifest) + '\n':
        raise ValueError('The sysroot inventory checksum differs')
    expected = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        if not match:
            raise ValueError('Unsupported sysroot checksum entry')
        path = Path(match.group(2))
        if not within(path, root) or path in expected:
            raise ValueError('Duplicate or out-of-root sysroot file')
        expected[path] = match.group(1)
    actual, links = set(), set()
    for current, directories, files in os.walk(str(root), followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            if path.is_symlink():
                links.add(str(path) + '\t' + os.readlink(str(path)))
            elif path.is_file():
                actual.add(path)
    if not expected or actual != set(expected) or links != set((reports / 'sysroot-symlinks.tsv').read_text().splitlines()):
        raise ValueError('The sysroot file or link membership differs')
    for path, expected_hash in expected.items():
        if digest(path) != expected_hash:
            raise ValueError('A sysroot file differs: ' + str(path))
    print(json.dumps({'status': 'passed', 'files': len(actual), 'symlinks': len(links), 'sysroot': str(root)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit('error: ' + str(error))
