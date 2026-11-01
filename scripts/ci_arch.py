#!/usr/bin/env python3
"""Strict architecture identities shared by native Linux CI adapters."""
import argparse
import json
from pathlib import Path


ARCHES = {
    'arm64': {'arch': 'arm64', 'rid': 'linux-arm64', 'uname': 'aarch64',
              'image': 'arm64', 'elf': 'AArch64', 'machine': 183, 'deb': 'arm64'},
    'x64': {'arch': 'x64', 'rid': 'linux-x64', 'uname': 'x86_64',
            'image': 'amd64', 'elf': 'Advanced Micro Devices X86-64', 'machine': 62, 'deb': 'amd64'},
}


def get_arch(name='arm64'):
    """Return a fresh identity tuple; callers must select their expected target."""
    name = canonical_arch(name)
    if name not in ARCHES:
        raise ValueError('Unsupported native CI architecture: ' + str(name))
    return dict(ARCHES[name])


def canonical_arch(name):
    """Translate the public AArch64 spelling to the official .NET identity."""
    return 'arm64' if name == 'aarch64' else name


def public_arch(name):
    """Return the architecture spelling used by project files and downloads."""
    identity = get_arch(name)
    return 'aarch64' if identity['arch'] == 'arm64' else identity['arch']


def profile_path(root, sdk, arch='arm64'):
    """Resolve current project names and authenticated historical snapshots."""
    root = Path(root)
    current = root / 'profiles' / ('dotnet-' + sdk + '-linux-' + public_arch(arch) + '.json')
    legacy = root / 'profiles' / ('dotnet-' + sdk + '-' + get_arch(arch)['rid'] + '.json')
    return current if current.exists() or not legacy.exists() else legacy


def container_path(root, target, arch='arm64'):
    """Resolve a native build recipe without changing OCI architecture names."""
    root = Path(root)
    current = root / 'containers' / (public_arch(arch) + '-' + target + '.Containerfile')
    legacy = root / 'containers' / (get_arch(arch)['arch'] + '-' + target + '.Containerfile')
    return current if current.exists() or not legacy.exists() else legacy


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', type=canonical_arch, choices=sorted(ARCHES), metavar='{aarch64,x64}', default='arm64')
    print(json.dumps(get_arch(parser.parse_args().arch)))
