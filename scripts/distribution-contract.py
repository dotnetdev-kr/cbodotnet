#!/usr/bin/env python3
"""Verify local qualified-release inputs and print a downstream preparation plan."""
import argparse
import json
from pathlib import Path

from distribution_contract import verified_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan',))
    parser.add_argument('--release-json', type=Path, required=True, help='GitHub API release response, including assets')
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--checksums', type=Path, required=True)
    parser.add_argument('--sdk-archive', type=Path, required=True)
    parser.add_argument('--channel', choices=('deb', 'oci', 'rpm', 'aur'), required=True)
    parser.add_argument('--variant', required=True, help='Exact OS ID, e.g. debian-13')
    parser.add_argument('--arch', required=True, help='Public architecture: x64 or aarch64')
    parser.add_argument('--revision', type=int, default=1)
    args = parser.parse_args()
    try:
        plan = verified_plan(json.loads(args.release_json.read_text(encoding='utf-8-sig')),
                             args.manifest.read_bytes(), args.checksums.read_bytes(), args.sdk_archive,
                             args.channel, args.variant, args.arch, args.revision)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Distribution contract rejected input: ' + str(error) + '\n')
    print(json.dumps(plan, indent=2))


if __name__ == '__main__':
    main()
