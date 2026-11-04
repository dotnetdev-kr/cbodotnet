#!/usr/bin/env python3
"""Sign a complete downstream channel bundle and publish/postverify its assets."""
import argparse
import json
from pathlib import Path

from downstream_publish import create_bundle, publish_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('bundle')
    command.add_argument('--items', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--target-commit', required=True)
    command.add_argument('--signing-key', required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--gnupg-home', type=Path)
    command.add_argument('--extra-assets', type=Path, help='JSON array of actual additional repository/archive file paths')
    command = commands.add_parser('publish')
    command.add_argument('--bundle', type=Path, required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--target-commit', required=True)
    command.add_argument('--gh', default='gh')
    args = parser.parse_args()
    try:
        if args.command == 'bundle':
            items = json.loads(args.items.read_bytes())
            for item in items:
                if 'packagePath' in item:
                    item['package'] = json.loads(Path(item.pop('packagePath')).read_bytes())
            extras = json.loads(args.extra_assets.read_bytes()) if args.extra_assets else []
            result = create_bundle(items, args.output, args.target_commit, args.signing_key,
                                   args.keyring, extras, gnupg_home=args.gnupg_home)
        else:
            result = publish_bundle(args.bundle, args.keyring, args.target_commit, gh=args.gh)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Downstream publication rejected: ' + str(error) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
