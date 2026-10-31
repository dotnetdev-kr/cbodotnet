#!/usr/bin/env python3
"""Verify the complete recorded .NET 6 target sysroot file/link inventory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sysroot', type=Path, required=True)
parser.add_argument('--reports-dir', type=Path, required=True)
args = parser.parse_args()
for path in [args.sysroot, args.reports_dir]:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise SystemExit('Absolute ordinary sysroot/report directories are required')
root, reports = args.sysroot.resolve(strict=True), args.reports_dir.resolve(strict=True)
manifest = reports / 'sysroot-files.sha256'
data = manifest.read_bytes()
expected_index = hashlib.sha256(data).hexdigest() + '  ' + str(manifest) + '\n'
if (reports / 'sysroot-file-list.sha256').read_text() != expected_index:
    raise SystemExit('Sysroot inventory checksum differs')
expected = {}
for line in data.decode().splitlines():
    match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
    if not match:
        raise SystemExit('Unsupported sysroot checksum entry')
    path = Path(match.group(2))
    if not path.is_relative_to(root) or path in expected:
        raise SystemExit('Duplicate or out-of-root sysroot entry')
    expected[path] = match.group(1)
actual, links = set(), set()
for directory, directories, files in os.walk(root, followlinks=False):
    for name in directories + files:
        path = Path(directory) / name
        if path.is_symlink():
            links.add(str(path) + '\t' + os.readlink(path))
        elif path.is_file():
            actual.add(path)
if not expected or actual != set(expected) or links != set((reports / 'sysroot-symlinks.tsv').read_text().splitlines()):
    raise SystemExit('Sysroot file or symlink inventory differs')
for path, digest in expected.items():
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(chunk)
    if hasher.hexdigest() != digest:
        raise SystemExit('Sysroot file checksum differs: ' + str(path))
print(json.dumps({'status': 'passed', 'files': len(actual), 'symlinks': len(links), 'sysroot': str(root)}))
