#!/usr/bin/env python3
"""Revalidate the complete signed native amd64 legacy target sysroot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=['net5', 'core31', 'core30'], required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    args = parser.parse_args()
    root, reports = args.sysroot, args.reports_dir
    for path in (root, reports):
        if not path.is_absolute() or not path.is_dir() or any(p.is_symlink() for p in [path] + list(path.parents)):
            raise ValueError('Ordinary absolute sysroot and report directories are required')
    provenance = json.loads((reports/'sysroot-provenance.json').read_text())
    if (provenance['family'] != args.family or provenance['architecture'] != 'amd64' or provenance['sysroot'] != str(root)
            or provenance['method'] != 'explicit-native-amd64-debootstrap' or provenance['originalGeneratorVerified'] is not True
            or provenance['packageSignatureVerification'] is not True or provenance['releaseSignatureLogVerified'] is not True
            or provenance['emulation'] is not False):
        raise ValueError('The native x64 sysroot producer contract differs')
    for key in ('producer', 'archiveRelease', 'archiveSignature', 'signatureStatus'):
        row = provenance[key]; path = Path(row['path'])
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('A signed sysroot producer input changed: ' + key)
    tls = provenance['aptTls']
    ca_info = '/etc/ssl/certs/cbodotnet-producer-ca.pem'
    tls_args = ['-o', 'Acquire::https::CaInfo='+ca_info,
                '-o', 'Acquire::https::Verify-Peer=true', '-o', 'Acquire::https::Verify-Host=true']
    if (tls['peerVerification'] is not True or tls['hostVerification'] is not True or tls['packageSignatureVerification'] is not True
            or tls['caInfo'] != ca_info or tls['arguments'] != tls_args
            or tls['retained']['path'] != str(reports/'apt-tls-ca.pem')
            or tls['target']['path'] != str(root/ca_info.lstrip('/'))):
        raise ValueError('The explicit verified apt TLS policy differs')
    for row in (tls['source'], tls['retained'], tls['target']):
        path = Path(row['path'])
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != row['bytes']
                or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']
                or row['sha256'] != tls['retained']['sha256'] or row['bytes'] != tls['retained']['bytes']):
            raise ValueError('The retained apt TLS trust bundle differs')
    manifest = reports/'sysroot-files.sha256'; data = manifest.read_bytes()
    if (reports/'sysroot-file-list.sha256').read_text() != hashlib.sha256(data).hexdigest()+'  '+str(manifest)+'\n':
        raise ValueError('The complete sysroot inventory digest differs')
    expected = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        if not match:
            raise ValueError('Unsupported sysroot index row')
        path = Path(match.group(2))
        if root not in path.parents or path in expected:
            raise ValueError('Duplicate or escaping sysroot row')
        expected[path] = match.group(1)
    actual, links = set(), set()
    for current, directories, files in os.walk(str(root), followlinks=False):
        for name in directories + files:
            path = Path(current)/name
            if path.is_symlink(): links.add(str(path)+'\t'+os.readlink(str(path)))
            elif path.is_file(): actual.add(path)
    if not expected or actual != set(expected) or links != set((reports/'sysroot-symlinks.tsv').read_text().splitlines()):
        raise ValueError('The full sysroot file/link membership differs')
    for path, expected_sha in expected.items():
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1048576), b''): digest.update(block)
        if digest.hexdigest() != expected_sha:
            raise ValueError('A sysroot member changed: '+str(path))
    package_lines = (reports/'sysroot-packages.tsv').read_text()
    if not re.search(r'^libc6(?::amd64)?\s+2\.23[^\s]*\s+amd64$', package_lines, re.MULTILINE):
        raise ValueError('The target libc package is not native amd64 Xenial')
    library = root/'lib/x86_64-linux-gnu/libc-2.23.so'
    if library.is_symlink() or not library.is_file():
        raise ValueError('The target sysroot lacks its ordinary native libc')
    with library.open('rb') as stream: header = stream.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 62:
        raise ValueError('The target libc is not ELF64 x86-64')
    print(json.dumps({'status':'passed','files':len(actual),'symlinks':len(links),'sysroot':str(root)}))


if __name__ == '__main__':
    main()
