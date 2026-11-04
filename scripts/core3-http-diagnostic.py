#!/usr/bin/env python3
"""Observe qualified Core3 HTTP ELF loader requirements; never qualify or publish."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile

from aur_delivery import ARCH_BASE
from downstream_release import encoded, receive_release, require

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('3.0.103', '3.1.426')


def command(arguments, check=True):
    result = subprocess.run(list(map(str, arguments)), text=True, capture_output=True)
    if check:
        require(result.returncode == 0, 'Diagnostic command failed: ' + str(arguments[0]) + '\n' + result.stdout + result.stderr)
    return dict(exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def native(workspace):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0,
            'A native ordinary x64 Linux producer is required')
    workspace = workspace.resolve()
    require(not workspace.exists(), 'Fresh Core3 diagnostic workspace required')
    workspace.mkdir(parents=True); (workspace / 'inputs').mkdir(); (workspace / 'components').mkdir()
    sources = []
    for version in VERSIONS:
        inputs = workspace / 'inputs' / version
        plan = receive_release('sdk-' + version, inputs, 'aur', 'arch-rolling', 'x64', 1)
        destination = workspace / 'components' / version; destination.mkdir()
        selected = []
        with tarfile.open(inputs / plan['sdk']['name']) as archive:
            for member in archive:
                name = member.name.removeprefix('./')
                if name not in {'LICENSE.txt', 'ThirdPartyNotices.txt'} and not re.fullmatch(
                        r'shared/Microsoft\.NETCore\.App/[0-9.]+/(?:lib)?System\.Net\.Http\.Native\.so', name):
                    continue
                require(member.isfile() and 0 < member.size <= 2 * 1024**2, 'Ordinary bounded original component required')
                path = destination / Path(name).name
                with archive.extractfile(member) as stream:
                    data = stream.read()
                require(len(data) == member.size and not path.exists(), 'Duplicated or incomplete original component')
                path.write_bytes(data); path.chmod(member.mode & 0o777)
                selected.append(dict(path=name, local=path.relative_to(workspace).as_posix(), size=len(data),
                                     sha256=hashlib.sha256(data).hexdigest()))
        require(any(row['path'].endswith('.so') for row in selected), 'The exact shared HTTP native component is absent')
        sources.append(dict(sdkVersion=version, sourceManifestSha256=plan['sourceManifestSha256'], sdk=plan['sdk'], components=selected))
        # The diagnostic executes only the selected ELF loader inspection.
        (inputs / plan['sdk']['name']).unlink()
    (workspace / 'sources.json').write_bytes(encoded(sources))
    mounts = ['-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery']
    bootstrap = ('set -eu\n'
        'pacman -Syu --noconfirm --needed python binutils curl ca-certificates glibc libgcc libstdc++ zlib krb5 icu openssl\n')
    cid = image = None
    try:
        cid = command(['docker', 'create', *mounts, ARCH_BASE, 'sh', '-ec', bootstrap])['stdout'].strip()
        command(['docker', 'start', '--attach', cid])
        state = json.loads(command(['docker', 'inspect', cid])['stdout'])[0]['State']
        require(state['ExitCode'] == 0, 'Pinned Arch stock dependency preparation failed')
        image = command(['docker', 'commit', cid])['stdout'].strip()
        command(['docker', 'run', '--rm', '--network', 'none', *mounts, image, 'python',
                 '/repo/scripts/core3-http-diagnostic.py', 'inspect', '--workspace', '/delivery'])
    finally:
        if cid:
            command(['docker', 'rm', '--force', cid], check=False)
        if image:
            command(['docker', 'image', 'rm', image], check=False)


def inspect(workspace):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file()
            and {item.name for item in Path('/sys/class/net').iterdir()} == {'lo'},
            'Native disposable network-none x64 diagnostic container required')
    operating_system = Path('/etc/os-release').read_text()
    require('ID=arch\n' in operating_system, 'Pinned Arch diagnostic target required')
    sources = json.loads((workspace / 'sources.json').read_bytes())
    for source in sources:
        for row in source['components']:
            path = workspace / row['local']
            require(hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], 'Original selected ELF bytes changed')
            if row['path'].endswith('.so'):
                row['dynamic'] = command(['readelf', '--dynamic', path])
                row['symbolVersions'] = command(['readelf', '--version-info', path])
                row['ldd'] = command(['ldd', path], check=False)
    result = dict(schemaVersion=1, scope='core3-stock-http-loader-diagnostic', status='observed',
        sdkQualificationPerformed=False, sdkBuilds=0, sdkExecutionPerformed=False, publicationStatus='not-published',
        architecture='x64', startingImage=ARCH_BASE, operatingSystem=operating_system, networkForInspection='none',
        packages=command(['pacman', '-Q']), stockLibcurl=command(['pacman', '-Ql', 'curl']), sources=sources)
    (workspace / 'http-loader-diagnostic.json').write_bytes(encoded(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('native', 'inspect')); parser.add_argument('--workspace', type=Path, required=True)
    arguments = parser.parse_args()
    {'native': native, 'inspect': inspect}[arguments.phase](arguments.workspace)


if __name__ == '__main__':
    main()
