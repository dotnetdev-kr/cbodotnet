#!/usr/bin/env python3
"""Run and receive a generated, constrained SDK adapter on native CI runners."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

SPEC = importlib.util.spec_from_file_location('upstream_sdk', Path(__file__).with_name('upstream-sdk.py'))
UPSTREAM = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(UPSTREAM)


def run(command, env=None):
    subprocess.run(list(map(str, command)), env=env, check=True)


def build(args):
    attestation = UPSTREAM.load(args.attestation); candidate = attestation['candidate']
    root = args.generated_root; arch = 'arm64' if args.arch == 'aarch64' else args.arch; rid = 'linux-' + arch
    UPSTREAM.require(UPSTREAM.git(root, 'rev-parse', 'HEAD').decode().strip() == attestation['generatedProjectCommit'],
                     'The generated adapter identity changed')
    run_id = os.environ['GITHUB_RUN_ID']; attempt = os.environ['GITHUB_RUN_ATTEMPT']
    revision = run_id; build_id = os.environ['SDK_BUILD_ID']
    host_reports = args.workspace.with_name(args.workspace.name + '-host')
    environment = os.environ.copy(); environment['GITHUB_SHA'] = attestation['generatedProjectCommit']
    environment['GITHUB_WORKFLOW_REF'] = UPSTREAM.WORKFLOW
    host = root / 'scripts/ci-net10-host.sh'; driver = root / 'scripts/ci-net10.sh'
    common = ['--arch', arch, '--workspace', args.workspace, '--output-dir', args.release_dir,
              '--build-id', build_id, '--build-revision', revision]
    run(['bash', host, 'prepare', '--arch', arch, '--workspace', args.workspace,
         '--reports-dir', host_reports, '--minimum-free-gib', '30'], environment)
    run(['bash', driver, 'prepare', *common], environment)
    shutil.copytree(host_reports, args.release_dir / 'reports/ci-host')
    monitor = subprocess.Popen(['bash', str(host), 'monitor', '--arch', arch, '--workspace', str(args.workspace),
                                '--reports-dir', str(args.release_dir / 'reports/ci-host')], env=environment)
    try:
        for stage in ('build', 'scan', 'test'):
            run(['bash', driver, stage, *common], environment)
        run([sys.executable, root / 'scripts/package-used-source.py', '--roots-json',
             args.release_dir / 'reports/ci/source-roots.json', '--output-dir', args.release_dir / 'sources',
             '--project-root', root, '--project-commit', attestation['generatedProjectCommit'],
             '--sdk-version', candidate['sdkVersion'], '--target-rid', rid,
             '--run-id', run_id, '--run-attempt', attempt], environment)
        run(['bash', driver, 'verify', *common], environment)
    finally:
        monitor.terminate(); monitor.wait(timeout=60)
    shutil.copyfile(args.attestation, args.release_dir / 'reports/ci/upstream-attestation.json')
    run(['bash', driver, 'collect', *common], environment)
    run([sys.executable, root / 'scripts/ci-sdk.py', 'validate', '--arch', arch, '--target', 'net10',
         '--project-root', root, '--release-dir', args.release_dir], environment)
    args.bundle_dir.mkdir(parents=True, exist_ok=False)
    name = 'cbodotnet-net10-' + rid + '-' + run_id + '-' + attempt + '.tar.gz'
    destination = args.bundle_dir / name
    with tarfile.open(destination, 'w:gz', dereference=True) as archive:
        archive.add(args.release_dir, arcname=args.release_dir.name)
    for algorithm in ('sha256', 'sha512'):
        value = hashlib.new(algorithm)
        with destination.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                value.update(block)
        (args.bundle_dir / (name + '.' + algorithm)).write_text(value.hexdigest() + '  ' + name + '\n')


def receive(args):
    candidate = UPSTREAM.load(args.candidate); attestation = UPSTREAM.load(args.attestation)
    UPSTREAM.require(attestation['candidateSha256'] == UPSTREAM.digest(candidate), 'The regenerated candidate differs')
    run_id = os.environ['GITHUB_RUN_ID']; attempt = os.environ['GITHUB_RUN_ATTEMPT']
    artifacts = UPSTREAM.api(UPSTREAM.REPOSITORY + '/actions/runs/' + run_id + '/artifacts?per_page=100')['artifacts']
    args.output_dir.mkdir(parents=True, exist_ok=False)
    deliveries = dict(schemaVersion=1, sdkVersion=candidate['sdkVersion'], target='net10', architectures={}, generation=attestation)
    for arch, official in [('aarch64', 'arm64'), ('x64', 'x64')]:
        artifact_name = 'upstream-sdk-' + candidate['sdkVersion'] + '-' + arch + '-' + run_id + '-' + attempt
        matches = [row for row in artifacts if row['name'] == artifact_name and not row['expired']]
        UPSTREAM.require(len(matches) == 1, 'Exactly one current-run architecture artifact is required')
        bundle_name = 'cbodotnet-net10-linux-' + official + '-' + run_id + '-' + attempt + '.tar.gz'
        paths = list(args.downloads.rglob(bundle_name))
        UPSTREAM.require(len(paths) == 1, 'Exactly one downloaded architecture bundle is required')
        command = [sys.executable, args.generated_root / 'scripts/ci-delivery.py', '--target', 'net10', '--arch', arch,
                   '--sdk-version', candidate['sdkVersion'], '--download-dir', paths[0].parent,
                   '--destination', args.output_dir / arch, '--expected-project-commit', attestation['generatedProjectCommit'],
                   '--expected-run-id', run_id, '--expected-run-attempt', attempt]
        output = subprocess.check_output(list(map(str, command)))
        sys.stdout.buffer.write(output); sys.stdout.flush()
        result = json.loads(output.decode().splitlines()[-1]); release = Path(result['releaseDirectory'])
        UPSTREAM.require(UPSTREAM.load(release / 'reports/ci/upstream-attestation.json') == attestation,
                         'Build and independently regenerated adapter attestations differ')
        deliveries['architectures'][arch] = dict(releaseDirectory=str(release), projectCommit=attestation['generatedProjectCommit'],
                                                runId=run_id, runAttempt=attempt, artifactId=matches[0]['id'])
    UPSTREAM.write(args.plan, deliveries)


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('build'); p.add_argument('--arch', choices=('aarch64', 'x64'), required=True)
    for name in ('generated-root', 'attestation', 'workspace', 'release-dir', 'bundle-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    p = sub.add_parser('receive')
    for name in ('generated-root', 'candidate', 'attestation', 'downloads', 'output-dir', 'plan'):
        p.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    build(args) if args.command == 'build' else receive(args)


if __name__ == '__main__':
    main()
