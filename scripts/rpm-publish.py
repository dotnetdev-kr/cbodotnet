#!/usr/bin/env python3
"""Sign, freeze and publish complete RPM distributions from trusted native evidence."""
import argparse
import json
import os
from pathlib import Path

from rpm_publish import stage, publish, inspect_common

parser = argparse.ArgumentParser(description=__doc__)
commands = parser.add_subparsers(dest='command', required=True)
inspect = commands.add_parser('inspect-common')
inspect.add_argument('--received', type=Path, required=True)
inspect.add_argument('--output', type=Path, required=True)
prepare = commands.add_parser('stage')
prepare.add_argument('--received', type=Path, required=True)
prepare.add_argument('--output', type=Path, required=True)
prepare.add_argument('--signing-key', required=True)
prepare.add_argument('--keyring', type=Path, required=True)
prepare.add_argument('--source-run', default=os.environ.get('GITHUB_RUN_ID'))
prepare.add_argument('--source-attempt', default=os.environ.get('GITHUB_RUN_ATTEMPT', '1'))
resume = commands.add_parser('publish')
resume.add_argument('--promotion', type=Path, required=True)
resume.add_argument('--keyring', type=Path, required=True)
resume.add_argument('--frozen-run', default='')
resume.add_argument('--frozen-attempt', default='1')
args = parser.parse_args()
if args.command == 'inspect-common':
    result = inspect_common(args.received, args.output)
elif args.command == 'stage':
    result = stage(args.received, args.output, args.signing_key, args.keyring, args.source_run, args.source_attempt)
else:
    result = publish(args.promotion, args.keyring, args.frozen_run, args.frozen_attempt)
print(json.dumps(result, indent=2))
