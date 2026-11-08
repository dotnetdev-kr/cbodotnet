#!/usr/bin/env python3
"""Dispatch reviewed native musl SDK expansion routes without changing SDK10."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

from downstream_release import ordinary_file, require

ROUTES = {'9.0.123': 'musl-modern-sdk.py', '8.0.133': 'musl-modern-sdk.py',
          '7.0.120': 'musl-legacy-sdk.py', '6.0.136': 'musl-legacy-sdk.py'}


def dispatch_identity(arguments):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('command', choices=['run', 'validate', 'capture-failure-logs'])
    parser.add_argument('--sdk-version')
    parser.add_argument('--release-dir', type=Path)
    options, remaining = parser.parse_known_args(arguments)
    if options.command == 'capture-failure-logs':
        return options.command, None, None
    if options.command == 'validate':
        require(not remaining and options.sdk_version is None and options.release_dir is not None,
                'Validation requires only the sealed delivery directory')
        path = ordinary_file(options.release_dir / 'producer-validation.json')
        require(path.stat().st_size <= 16 * 1024 * 1024, 'Producer identity record exceeds its size limit')
        record = json.loads(path.read_bytes())
        require(isinstance(record, dict), 'A sealed producer identity object is required')
        version = record.get('sdkVersion')
    else:
        version = options.sdk_version
    require(isinstance(version, str) and version in ROUTES, 'Unreviewed native musl expansion route')
    return options.command, version, options.release_dir


def module(filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location('expanded_native_' + path.stem.replace('-', '_'), path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    if not sys.argv[1:] or sys.argv[1] in ('-h', '--help'):
        module('musl-modern-sdk.py').main()
        return
    command, version, release = dispatch_identity(sys.argv[1:])
    if command == 'validate' and version in ('7.0.120', '6.0.136'):
        filename = 'musl_legacy6_admission.py' if version == '6.0.136' else 'musl_legacy_admission.py'
        result = module(filename).validate(release)
        require(result.get('status') == 'passed' and result.get('sdkVersion') == version,
                'Independent legacy producer validation did not pass')
        print(json.dumps({key: result[key] for key in ('status', 'sdkVersion', 'architecture', 'projectCommit',
                                                      'runId', 'runAttempt')}))
    else:
        module(ROUTES[version] if version else 'musl-modern-sdk.py').main()


if __name__ == '__main__':
    main()
