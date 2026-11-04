#!/usr/bin/env python3
"""Prepare, record, validate and locally stage qualified downstream deliveries."""
import argparse
import json
from pathlib import Path

from downstream_release import (encoded, local_intake, load_status, package_record,
                                publish, receive_release, stage_records, validate_record)


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'package'):
        command = commands.add_parser(name)
        command.add_argument('--inputs', type=Path, required=True)
        command.add_argument('--tag', help='Download the exact public release when provided')
        command.add_argument('--channel', choices=('deb', 'oci', 'rpm', 'aur'), required=True)
        command.add_argument('--variant', required=True)
        command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
        command.add_argument('--revision', type=int, default=1)
        if name == 'package':
            command.add_argument('--artifact', type=Path, required=True)
            command.add_argument('--orchestration', type=Path, required=True)
            command.add_argument('--commands-root', type=Path)
            command.add_argument('--commands-inventory', type=Path)
    command = commands.add_parser('validate')
    command.add_argument('--package', type=Path, required=True)
    command.add_argument('--artifact', type=Path, required=True)
    command.add_argument('--report', type=Path, required=True)
    command.add_argument('--signature', type=Path, required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--commands-root', type=Path, required=True)
    command.add_argument('--inputs', type=Path, required=True)
    command = commands.add_parser('stage')
    command.add_argument('--items', type=Path, required=True, help='JSON array with package and evidence paths')
    command.add_argument('--ledger', type=Path, required=True)
    command = commands.add_parser('publish')
    command.add_argument('--staged', type=Path, required=True)
    command.add_argument('--bundle', type=Path, required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--target-commit', required=True)
    command.add_argument('--gh', default='gh')
    args = parser.parse_args()
    try:
        if args.command in {'prepare', 'package'}:
            plan = (receive_release(args.tag, args.inputs, args.channel, args.variant, args.arch, args.revision)
                    if args.tag else local_intake(args.inputs, args.channel, args.variant, args.arch, args.revision))
            if args.command == 'prepare':
                result = plan
            else:
                if bool(args.commands_root) != bool(args.commands_inventory):
                    raise ValueError('Both --commands-root and --commands-inventory are required together')
                extras = ({'root': args.commands_root, 'inventory': read(args.commands_inventory)} if args.commands_root else None)
                result = package_record(plan, args.artifact, read(args.orchestration), extra_files=extras)
        elif args.command == 'validate':
            result = validate_record(read(args.package), args.artifact, args.report, args.signature, args.keyring,
                                     commands_root=args.commands_root, inputs_directory=args.inputs)
        elif args.command == 'stage':
            items = read(args.items)
            for item in items:
                item['package'] = read(item.pop('packagePath'))
            result = stage_records(items, args.ledger)
        else:
            result = publish(read(args.staged), load_status(), args.bundle, args.keyring, args.target_commit, args.gh)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, 'Downstream release rejected: ' + str(error) + '\n')
    print(encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
