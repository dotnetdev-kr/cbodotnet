#!/usr/bin/env python3
"""Strict architecture identities shared by native Linux CI adapters."""
import argparse
import json


ARCHES = {
    'arm64': {'arch': 'arm64', 'rid': 'linux-arm64', 'uname': 'aarch64',
              'image': 'arm64', 'elf': 'AArch64', 'machine': 183, 'deb': 'arm64'},
    'x64': {'arch': 'x64', 'rid': 'linux-x64', 'uname': 'x86_64',
            'image': 'amd64', 'elf': 'Advanced Micro Devices X86-64', 'machine': 62, 'deb': 'amd64'},
}


def get_arch(name='arm64'):
    """Return a fresh identity tuple; callers must select their expected target."""
    if name not in ARCHES:
        raise ValueError('Unsupported native CI architecture: ' + str(name))
    return dict(ARCHES[name])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=sorted(ARCHES), default='arm64')
    print(json.dumps(get_arch(parser.parse_args().arch)))
