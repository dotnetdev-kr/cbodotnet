#!/usr/bin/env python3
"""Select pinned CI profiles and dispatch version-specific validation gates."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

PROFILES = {'net10': ('10.0.403', 'ci-net10.sh'), 'net9': ('9.0.123', 'ci-net9.sh'),
            'net8': ('8.0.133', 'ci-net8.sh'), 'net7': ('7.0.120', 'ci-net7.sh'),
            'net6': ('6.0.136', 'ci-net6.sh'), 'net5': ('5.0.214', 'ci-net5.sh'),
            'core31': ('3.1.426', 'ci-core31.sh'), 'core30': ('3.0.103', 'ci-core30.sh')}
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['describe', 'validate', 'verify-release'])
    parser.add_argument('--target', choices=PROFILES, required=True)
    parser.add_argument('--release-dir', type=Path)
    parser.add_argument('--project-root', type=Path, default=ROOT)
    parser.add_argument('--expected-project-commit')
    parser.add_argument('--expected-run-id')
    parser.add_argument('--expected-run-attempt')
    args = parser.parse_args(); version, driver = PROFILES[args.target]
    if args.command == 'describe':
        values = {'sdk_version': version, 'driver': 'scripts/' + driver,
                  'minimum_free_gib': '30' if args.target == 'net10' else '90'}
        print(json.dumps(values))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                for key, value in values.items():
                    stream.write(key + '=' + value + '\n')
        return
    if args.release_dir is None:
        parser.error('--release-dir is required')
    release = args.release_dir.absolute(); project = args.project_root.absolute()
    if args.command == 'verify-release' and not all((args.expected_project_commit, args.expected_run_id, args.expected_run_attempt)):
        parser.error('Portable verification requires the expected commit, run ID and attempt')
    expected_commit = args.expected_project_commit or os.environ['GITHUB_SHA']
    run_id = args.expected_run_id or os.environ['GITHUB_RUN_ID']
    attempt = args.expected_run_attempt or os.environ['GITHUB_RUN_ATTEMPT']
    # Verify the complete source payload before a family gate seals its envelope.
    subprocess.run([sys.executable, str(project / 'scripts/package-used-source.py'), 'verify',
                    '--release-dir', str(release), '--expected-project-commit', expected_commit,
                    '--expected-run-id', run_id, '--expected-run-attempt', attempt], check=True)
    if args.target == 'net10':
        command = [sys.executable, str(project / 'scripts/ci-net10-evidence.py'), args.command,
                   '--release-dir', str(release)]
        if args.command == 'validate':
            command += ['--project-root', str(project), '--output', str(release / 'ci-validation.json')]
        else:
            command += ['--expected-project-commit', args.expected_project_commit,
                        '--expected-run-id', args.expected_run_id, '--expected-run-attempt', args.expected_run_attempt]
    else:
        # Family adapters declare their portable gate through this stable wrapper.
        command = ['bash', str(project / 'scripts' / driver), args.command,
                   '--output-dir', str(release), '--project-root', str(project)]
        if args.command == 'verify-release':
            command += ['--expected-project-commit', args.expected_project_commit,
                        '--expected-run-id', args.expected_run_id, '--expected-run-attempt', args.expected_run_attempt]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
