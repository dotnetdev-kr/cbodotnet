#!/usr/bin/env python3
"""Explicit native identities and official SDK pins for legacy CI adapters."""
import argparse
import os
from pathlib import Path
import runpy

_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_arch.py')))
get_arch = _ARCH['get_arch']
canonical_arch = _ARCH['canonical_arch']
profile_path = _ARCH['profile_path']
container_path = _ARCH['container_path']


def selected_arch(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    # Product MSBuild targets invoke several helpers themselves. The container
    # records this explicit adapter selection; it is never inferred from inputs.
    parser.add_argument('--arch', type=canonical_arch, choices=['arm64', 'x64'], metavar='{aarch64,x64}', default=os.environ.get('CBODOTNET_LEGACY_ARCH', 'arm64'))
    args, _ = parser.parse_known_args(argv)
    result = get_arch(args.arch)
    result['libdir'] = 'aarch64-linux-gnu' if args.arch == 'arm64' else 'x86_64-linux-gnu'
    result['seccomp'] = 'SCMP_ARCH_AARCH64' if args.arch == 'arm64' else 'SCMP_ARCH_X86_64'
    result['seccompToken'] = 0xC00000B7 if args.arch == 'arm64' else 0xC000003E
    return result


SDK_HASHES = {
    '3.0.100': {
        'arm64': '18c3bc07c4486381f54d4b40eb8401bf56c14fef5febc4639e3134d74ce66172d1e66c2dea9684ad727f08e9dd7e89d74535a8642fb2a2203445483293f3b3c3',
        'x64': '766da31f9a0bcfbf0f12c91ea68354eb509ac2111879d55b656f19299c6ea1c005d31460dac7c2a4ef82b3edfea30232c82ba301fb52c0ff268d3e3a1b73d8f7'},
    '3.1.422': {
        'arm64': '3eb7e066568dfc0135f2b3229d0259db90e1920bb413f7e175c9583570146ad593b50ac39c77fb67dd3f460b4621137f277c3b66c44206767b1d28e27bf47deb',
        'x64': '690759982b12cce7a06ed22b9311ec3b375b8de8600bd647c0257c866d2f9c99d7c9add4a506f4c6c37ef01db85c0f7862d9ae3de0d11e9bec60958bd1b3b72c'},
    '5.0.212': {
        'arm64': '5abdcda5a647d742664bfffe018d027bd3bc9dc5b3730472a86667a841aa5763b4c3b4f8f654912d170984b3a2d2d2074ba784a0795bad1174674e5e0ce624b9',
        'x64': 'c13eb20d2356374c266b983ec15c5b12e06d3c39b04839916affe758f757c64ce3854701cdb2c25b6e8ad3f2914f67e9dec3993e85e575d3085b32a6b9dd7f12'},
    '9.0.121': {
        'arm64': '2c8288568d9827371d8d0daf0578590a956d955bef783bf1403953f8a816851f03be7aa366b6649e7cda77a8e7359ac3fc46fac87f010d71b6e7415a9457add5',
        'x64': 'd66f2609b509a4eece4ad8efbac49e63cea58e07652f1daded72bbd100d70f6d5d58a9b95b9235e158cb7b1a77995311979ec4ddf2df4c6a3017d4a71f163778'}
}

FOCAL_IMAGES = {
    'arm64': 'sha256:a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52',
    'x64': 'sha256:1e34d3881f9e1da0b2e81de59656abc29be6993eef2362d9134d66530db8b6ba'
}


def sdk_pin(version, arch):
    identity = get_arch(arch)
    name = 'dotnet-sdk-' + version + '-' + identity['rid'] + '.tar.gz'
    return {'name': name, 'url': 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + version + '/' + name,
            'sha512': SDK_HASHES[version][identity['arch']]}
