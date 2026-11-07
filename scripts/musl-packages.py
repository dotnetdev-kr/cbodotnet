#!/usr/bin/env python3
"""Assemble or inspect musl package candidates; this command does not publish."""
import argparse
import json
from pathlib import Path

import musl_packages as packages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('apk', 'oci'):
        child = sub.add_parser(name)
        child.add_argument('--plan', type=Path, required=True)
        child.add_argument('--sdk-archive', type=Path, required=True)
        child.add_argument('--output', type=Path, required=True)
        if name == 'apk':
            child.add_argument('--private-key', type=Path, required=True)
            child.add_argument('--public-key', type=Path, required=True)
            child.add_argument('--fixture', action='store_true')
        else:
            child.add_argument('--base-image', required=True)
    child = sub.add_parser('verify-apk')
    child.add_argument('--package', type=Path, required=True)
    child.add_argument('--public-key', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'verify-apk':
        result = packages.verify_apk(args.package, args.public_key)
    else:
        plan = json.loads(args.plan.read_bytes())
        if args.command == 'apk':
            result = packages.build_apk(plan, args.sdk_archive, args.output, args.private_key, args.public_key, args.fixture)
        else:
            result = packages.build_oci_context(plan, args.sdk_archive, args.output, args.base_image)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
