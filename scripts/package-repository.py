#!/usr/bin/env python3
"""Create fully signed project APT/RPM repository bundles from a complete matrix."""
import argparse
import json
from pathlib import Path

from channel_packages import build_repositories


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channel', choices=('deb', 'rpm'), required=True)
    parser.add_argument('--package-builds', nargs='+', type=Path, required=True)
    parser.add_argument('--signing-key', required=True)
    parser.add_argument('--gnupg-home', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_repositories(args.package_builds, args.channel, args.output, args.signing_key, args.gnupg_home)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Repository preparation rejected: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
