#!/usr/bin/env python3
"""Authenticate publication receipts/native results and activate public availability."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from distribution_status import activate_status, update_repository_status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--channel', choices=('deb', 'oci', 'rpm'), action='append')
    parser.add_argument('--policy', type=Path, default=Path(__file__).resolve().parents[1] / 'releases/downstream-status.json')
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--run-attempt', default=os.environ.get('GITHUB_RUN_ATTEMPT', '1'))
    parser.add_argument('--gh', default='gh')
    parser.add_argument('--write', action='store_true', help='Commit status with an observed-SHA lease and dispatch Pages')
    args = parser.parse_args()
    try:
        channels = args.channel or ['deb', 'oci']
        receipts = [json.loads((args.publication_dir / (channel + '-publication.json')).read_bytes()) for channel in channels]
        reports = [json.loads((args.reports_dir / ('published-' + arch + '.json')).read_bytes()) for arch in ('x64', 'aarch64')]
        index = json.loads((args.publication_dir / 'oci-index.json').read_bytes()) if 'oci' in channels else None
        if args.write:
            result = update_repository_status(receipts, reports, index, args.run_id, args.run_attempt,
                                               args.gh, public_key=args.public_key)
        else:
            result = activate_status(json.loads(args.policy.read_bytes()), receipts, reports, index, public_key=args.public_key)
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Distribution availability rejected: ' + str(error) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
