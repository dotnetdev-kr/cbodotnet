#!/usr/bin/env python3
"""Build Debian packages or an OCI context from exact qualified release assets."""
import argparse
import json
from pathlib import Path

from channel_packages import build_aur_recipe, build_deb, build_oci_context, build_rpm
from downstream_release import local_intake


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--channel', choices=('deb', 'oci', 'rpm', 'aur'), required=True)
    parser.add_argument('--variant', required=True)
    parser.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    parser.add_argument('--revision', type=int, default=1)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-image', help='Required immutable base@sha256:digest for OCI')
    parser.add_argument('--compatibility-build', type=Path, help='Explicit verified separate provider-build.json for legacy SDKs')
    parser.add_argument('--native-http-build', type=Path, help='Explicit verified separate Core3 native HTTP provider-build.json')
    args = parser.parse_args()
    try:
        plan = local_intake(args.inputs, args.channel, args.variant, args.arch, args.revision)
        archive = args.inputs / plan['sdk']['name']
        if args.channel == 'deb':
            result = build_deb(plan, archive, args.output, args.compatibility_build, args.native_http_build)
        elif args.channel == 'oci':
            result = build_oci_context(plan, archive, args.output, args.base_image, args.compatibility_build, args.native_http_build)
        elif args.channel == 'rpm':
            plan['rpmDependencies'] = plan['dependencies']
            result = build_rpm(plan, archive, args.output, args.compatibility_build, args.native_http_build)
        else:
            plan['aurDependencies'] = plan['dependencies']
            result = build_aur_recipe(plan, archive, args.output)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Package preparation rejected: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
