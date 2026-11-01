#!/usr/bin/env python3
"""Receive previously qualified GitHub artifacts using immutable producer identities."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import zipfile

REPOSITORY = 'dotnetdev-kr/cbodotnet'
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/' + endpoint], text=True))


def validate_producer(row, artifact, run, target, arch):
    """Reject failed, substituted, expired or cross-repository producer artifacts."""
    require(re.fullmatch('[a-f0-9]{40}', row['projectCommit']) and all(
        re.fullmatch('[1-9][0-9]*', str(row[k])) for k in ('runId', 'runAttempt', 'artifactId')), 'Invalid producer identity')
    rid_arch = 'arm64' if arch == 'aarch64' else arch
    allowed_names = {f'sdk-{target}-linux-{value}-{row["runId"]}-{row["runAttempt"]}'
                     for value in {arch, rid_arch}}
    require(artifact['id'] == int(row['artifactId']) and artifact['name'] in allowed_names
            and artifact['expired'] is False and re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', '')),
            'A unique unexpired artifact with an API digest is required')
    producer = artifact['workflow_run']
    require(producer['id'] == int(row['runId']) and producer['head_sha'] == row['projectCommit']
            and producer['head_branch'] == 'main' and producer['head_repository_id'] == producer['repository_id'],
            'Artifact producer does not match its qualification record')
    require(run['id'] == int(row['runId']) and run['run_attempt'] == int(row['runAttempt'])
            and run['head_sha'] == row['projectCommit'] and run['head_branch'] == 'main'
            and run['repository']['full_name'] == REPOSITORY and run['head_repository']['full_name'] == REPOSITORY
            and run['status'] == 'completed' and run['conclusion'] == 'success'
            and run['path'] in {'.github/workflows/sdk-matrix.yml', '.github/workflows/sdk-x64.yml',
                                '.github/workflows/net10-sdk.yml', '.github/workflows/upstream-sdk.yml'},
            'A successful trusted main-branch build run is required')


def extract_zip(path, output, expected_names):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        for entry in entries:
            relative = PurePosixPath(entry.filename)
            require(not relative.is_absolute() and len(relative.parts) == 1
                    and relative.name not in {'.', '..'} and not any(c in entry.filename for c in '\\:\0\r\n'),
                    'Unsafe artifact ZIP member')
        require(len(entries) == len(expected_names) and {e.filename for e in entries} == expected_names
                and all(not e.is_dir() and e.file_size > 0 and (e.external_attr >> 16) & 0o170000 != 0o120000
                        for e in entries), 'Unexpected artifact ZIP members')
        require(sum(e.file_size for e in entries) + 512 * 1024**2 < shutil.disk_usage(output.parent).free,
                'Insufficient artifact extraction capacity')
        output.mkdir()
        for entry in entries:
            with archive.open(entry) as incoming, (output / entry.filename).open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'releases/qualified-builds.json')
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding='utf-8-sig'))
    require(catalog['schemaVersion'] == 1 and catalog['repository'] == REPOSITORY, 'Unexpected qualification catalog')
    matches = [r for r in catalog['builds'] if r['target'] == args.target]
    require(len(matches) == 1 and set(matches[0]['architectures']) == {'aarch64', 'x64'}, 'An exact two-architecture target is required')
    record = matches[0]
    require(re.fullmatch(r'\d+\.\d+\.\d+', record['sdkVersion']) and re.fullmatch(r'net(?:[5-9]|10)|core3[01]', args.target),
            'Invalid qualification target')
    require(not args.workspace.exists() and args.workspace.parent.is_dir(), 'A fresh receive workspace is required')
    args.workspace.mkdir()
    for arch, row in record['architectures'].items():
        artifact = api('actions/artifacts/' + str(row['artifactId']))
        run = api('actions/runs/' + str(row['runId']) + '/attempts/' + str(row['runAttempt']))
        validate_producer(row, artifact, run, args.target, arch)
        archive = args.workspace / (arch + '.zip')
        with archive.open('xb') as output:
            subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{row["artifactId"]}/zip'], stdout=output, check=True)
        sha = hashlib.sha256()
        with archive.open('rb') as stream:
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                sha.update(block)
        require(archive.stat().st_size == artifact['size_in_bytes'] and 'sha256:' + sha.hexdigest() == artifact['digest'],
                'Artifact transport does not match the API digest')
        rid = 'linux-arm64' if arch == 'aarch64' else 'linux-x64'
        name = f'cbodotnet-{args.target}-{rid}-{row["runId"]}-{row["runAttempt"]}.tar.gz'
        download = args.workspace / (arch + '-download')
        extract_zip(archive, download, {name, name + '.sha256', name + '.sha512'})
        destination = args.workspace / (arch + '-verified')
        subprocess.run([sys.executable, str(ROOT / 'scripts/ci-delivery.py'), '--download-dir', str(download),
                        '--destination', str(destination), '--target', args.target, '--arch', arch,
                        '--sdk-version', record['sdkVersion'], '--expected-project-commit', row['projectCommit'],
                        '--expected-run-id', str(row['runId']), '--expected-run-attempt', str(row['runAttempt'])], check=True)
        row['releaseDirectory'] = str(destination / (record['sdkVersion'] + '-' + rid))
        print(json.dumps({'status': 'verified', 'target': args.target, 'architecture': arch}), flush=True)
    plan = dict(record, schemaVersion=1)
    (args.workspace / 'deliveries.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
