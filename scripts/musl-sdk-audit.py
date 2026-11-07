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
    machine, elf_machine, loader = {
        'x64': ('x86_64', 'Advanced Micro Devices X86-64', '/lib/ld-musl-x86_64.so.1'),
        'aarch64': ('aarch64', 'AArch64', '/lib/ld-musl-aarch64.so.1')}[arch]
    require(platform.system() == 'Linux' and platform.machine() == machine and os.getuid() != 0,
            'The ELF audit requires an unprivileged matching native CPU')
    require(Path(loader).is_file() and not Path('/lib/ld-linux-x86-64.so.2').exists()
            and not Path('/lib/ld-linux-aarch64.so.1').exists(), 'A pristine musl loader is required')
    rows, violations, links, static_archives = [], [], [], []
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-audit-') as temporary:
        root = Path(temporary) / 'sdk'
        root.mkdir()
        with tarfile.open(archive, 'r:gz') as stream:
            stream.extractall(root, filter='data')
        for path in sorted(root.rglob('*')):
            if path.is_symlink():
                links.append(dict(path=path.relative_to(root).as_posix(), target=os.readlink(path)))
                continue
            if not path.is_file():
                continue
            if path.suffix == '.a':
                with path.open('rb') as source:
                    static_archives.append(dict(path=path.relative_to(root).as_posix(),
                        sha256=hashlib.file_digest(source, 'sha256').hexdigest(),
                        disposition='Retained unchanged; embedded objects and NativeAOT are not qualified.'))
            with path.open('rb') as incoming:
                magic = incoming.read(4)
            if magic != b'\x7fELF':
                continue
            code, header = command(['readelf', '-hW', str(path)])
            require(code == 0, 'Cannot inspect ELF header: ' + str(path))
            code, program = command(['readelf', '-lW', str(path)])
            require(code == 0, 'Cannot inspect ELF program headers')
            code, dynamic = command(['readelf', '-dW', str(path)])
            require(code == 0, 'Cannot inspect ELF dependencies')
            code, versions = command(['readelf', '-VW', str(path)])
            require(code == 0, 'Cannot inspect ELF symbol versions')
            actual = re.search(r'Machine:\s*(.+)', header)
            native = actual is not None and actual.group(1).strip() == elf_machine
            if not native:
                violations.append('Foreign-machine ELF needs explicit qualification: ' + str(path.relative_to(root)))
            kind = re.search(r'Type:\s*(\S+)', header).group(1)
            interpreters = re.findall(r'Requesting program interpreter:\s*([^\]]+)', program)
            if interpreters not in ([], [loader]):
                violations.append('Non-musl/unknown ELF interpreter: ' + str(path.relative_to(root)))
            needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', dynamic)
            if re.search(r'\bGLIBC_[0-9]', versions) or any(
                    name == 'libc.so.6' or name.startswith('ld-linux') for name in needed):
                violations.append('glibc ELF dependency/version requirement: ' + str(path.relative_to(root)))
            closure = ''
            if native and kind in ('EXEC', 'DYN') and (needed or interpreters):
                code, closure = command(['ldd', str(path)])
                if code != 0 or re.search(r'not found|Error loading|Error relocating|symbol not found',
                                          closure, re.IGNORECASE):
                    violations.append('Unresolved native ELF dependency/symbol: ' + str(path.relative_to(root)) + '\n' + closure)
            rows.append(dict(path=path.relative_to(root).as_posix(), elfType=kind,
                        machine=actual.group(1).strip(), interpreter=interpreters[0] if interpreters else None,
                        needed=needed, dependencyClosure=closure,
                        classification='native-host' if native else 'unqualified-foreign',
                        sha256=hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()))
        if not (len(rows) >= 10 and any(r['path'] == 'dotnet' and r['interpreter'] == loader for r in rows)
                and any(r['path'].endswith('/libcoreclr.so') for r in rows)
                and any(r['path'].endswith('/libhostfxr.so') for r in rows)):
            violations.append('Complete SDK host/runtime ELF evidence is required')
    return dict(schemaVersion=1, status='failed' if violations else 'passed', libc='musl', architecture=arch, loader=loader,
                nativeArchitecture=platform.machine(), uid=os.getuid(), emulation=False,
                elfCount=len(rows), foreignTargetExceptions=[], files=rows, violations=violations,
                symlinks=links, staticArchives=static_archives,
                scope='All extracted regular ELF files audited; links and static archives inventoried. Embedded objects/ZIPs, NativeAOT and workloads are not qualified. No foreign/glibc exceptions admitted.')

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
