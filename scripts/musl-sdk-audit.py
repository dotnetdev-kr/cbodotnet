#!/usr/bin/env python3
"""Audit every ELF in a native musl SDK, including the loader's dependency closure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile

def require(value, message):
    if not value:
        raise ValueError(message)

def command(args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.returncode, result.stdout

def audit(archive, arch):
    # Shared with final archive qualification: provider-attributed symbol versions,
    # stock-APK ownership and transitive DT_NEEDED closure have one implementation.
    from musl_archive import audit_elf, inspect_elf
    machine, elf_machine, loader = {
        'x64': ('x86_64', 'Advanced Micro Devices X86-64', '/lib/ld-musl-x86_64.so.1'),
        'aarch64': ('aarch64', 'AArch64', '/lib/ld-musl-aarch64.so.1')}[arch]
    require(platform.system() == 'Linux' and platform.machine() == machine and os.getuid() != 0,
            'The ELF audit requires an unprivileged matching native CPU')
    require(Path(loader).is_file() and not Path('/lib/ld-linux-x86-64.so.2').exists()
            and not Path('/lib/ld-linux-aarch64.so.1').exists(), 'A pristine musl loader is required')
    rows, violations, links, static_archives = [], [], [], []
    qualified = None
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-audit-') as temporary:
        root = Path(temporary) / 'sdk'
        root.mkdir()
        with tarfile.open(archive, 'r:gz') as stream:
            stream.extractall(root, filter='data')
        # Preserve complete discovery even when a later dependency disposition fails.
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                links.append(dict(path=relative, target=os.readlink(path)))
                continue
            if not path.is_file():
                continue
            with path.open('rb') as stream:
                magic = stream.read(8)
            if magic.startswith(b'!<arch>\n'):
                with path.open('rb') as stream:
                    static_archives.append(dict(path=relative,
                        sha256=hashlib.file_digest(stream, 'sha256').hexdigest(),
                        disposition='Retained unchanged; embedded objects and NativeAOT are not qualified.'))
            if not magic.startswith(b'\x7fELF'):
                continue
            observed = inspect_elf(path)
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            rows.append(dict(path=relative, sha256=digest, **observed,
                             classification='native-host' if observed['machine'] == elf_machine else 'unqualified-foreign'))
        try:
            qualified = audit_elf(root, arch)
        except Exception as error:
            violations.append(str(error))
        else:
            by_path = {row['path']: row for row in qualified['elfFiles']}
            require(set(by_path) == {row['path'] for row in rows}, 'Shared ELF qualification inventory differs')
            for row in rows:
                actual = by_path[row['path']]
                require(actual['sha256'] == row['sha256'], 'SDK bytes changed during native closure audit')
                row['dependencies'] = actual['dependencies']
                row['reviewedAbiVersionLabels'] = actual['reviewedAbiVersionLabels']
        if not (len(rows) >= 10 and any(r['path'] == 'dotnet' and r['interpreter'] == loader for r in rows)
                and any(r['path'].endswith('/libcoreclr.so') for r in rows)
                and any(r['path'].endswith('/libhostfxr.so') for r in rows)):
            violations.append('Complete SDK host/runtime ELF evidence is required')
    return dict(schemaVersion=1, status='failed' if violations else 'passed', libc='musl', architecture=arch, loader=loader,
                nativeArchitecture=platform.machine(), uid=os.getuid(), emulation=False,
                elfCount=len(rows), foreignTargetExceptions=[], files=rows, violations=violations,
                symlinks=links, staticArchives=static_archives, closure=qualified,
                scope='Every regular ELF and transitive DT_NEEDED provider audited; stock GCC unwind ABI labels require exact provider definitions/APK ownership. Links/static archives inventoried; embedded objects/ZIPs/NativeAOT/workloads unqualified.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    args = parser.parse_args()
    report = audit(args.archive, args.arch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(report, out, indent=2)
        out.write('\n')
    require(report['status'] == 'passed', 'Native ELF audit failed; complete inventory/errors preserved in ' + str(args.output))

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
