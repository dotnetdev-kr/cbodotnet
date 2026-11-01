#!/usr/bin/env python3
"""Promote two independently verified native deliveries without changing payload bytes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
ARCHES = {'aarch64': 'linux-arm64', 'x64': 'linux-x64'}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def asset(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size < 2**31,
            'An ordinary nonempty release asset under 2 GiB is required: ' + str(path))
    return {'name': path.name, 'size': path.stat().st_size, 'sha256': digest(path)}


def ordinary_file(root, relative):
    value = PurePosixPath(relative)
    require(not value.is_absolute() and '..' not in value.parts
            and str(value) == relative and not any(c in relative for c in '\\:\0\r\n'),
            'Unsafe delivery member')
    path = root / relative
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary delivery file is required')
    return path


def copy_payload(source, destination, expected):
    require(source.stat().st_size == expected['bytes'] and digest(source) == expected['sha256'],
            'Qualified payload checksum mismatch: ' + str(source))
    # Copies keep staged uploads independent from immutable qualified delivery trees.
    shutil.copyfile(source, destination)
    copied = asset(destination)
    require(copied['size'] == expected['bytes'] and copied['sha256'] == expected['sha256'],
            'Copied payload differs from its qualified bytes')
    return copied


def pack_evidence(release, output, excluded):
    with output.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(release.rglob('*')):
                    require(not path.is_symlink(), 'Linked delivery evidence is forbidden')
                    if not path.is_file() or path in excluded:
                        continue
                    info = archive.gettarinfo(str(path), path.relative_to(release).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    info.mode = 0o644
                    with path.open('rb') as stream:
                        archive.addfile(info, stream)
    return asset(output)


def stage(args):
    plan = json.loads(args.deliveries.read_text(encoding='utf-8-sig'))
    require(plan.get('schemaVersion') == 1 and plan.get('sdkVersion') == args.sdk_version
            and plan.get('target') == args.target and set(plan.get('architectures', {})) == set(ARCHES),
            'A complete matching two-architecture delivery plan is required')
    require(re.fullmatch(r'\d+\.\d+\.\d+', args.sdk_version), 'A stable SDK version is required')
    project = args.project_root.resolve()
    described = json.loads(subprocess.check_output(
        [sys.executable, str(project / 'scripts/ci-sdk.py'), 'describe', '--target', args.target], text=True))
    require(described['sdk_version'] == args.sdk_version, 'The trusted adapter describes a different SDK version')
    require(not args.output.exists() and args.output.parent.is_dir(), 'A fresh staging directory is required')
    manifest = {'schemaVersion': 1, 'repository': REPOSITORY, 'sdkVersion': args.sdk_version,
                'tag': 'sdk-' + args.sdk_version, 'architectures': {}}
    args.output.mkdir()
    for arch, rid in ARCHES.items():
        row = plan['architectures'][arch]
        require(re.fullmatch('[a-f0-9]{40}', row['projectCommit'])
                and all(re.fullmatch(r'[1-9][0-9]*', str(row[key])) for key in ('runId', 'runAttempt', 'artifactId')),
                'Invalid immutable producer identity')
        release = Path(row['releaseDirectory']).resolve()
        subprocess.run([sys.executable, str(project / 'scripts/ci-sdk.py'), 'verify-release',
                        '--target', args.target, '--arch', 'arm64' if arch == 'aarch64' else arch,
                        '--release-dir', str(release), '--project-root', str(project),
                        '--expected-project-commit', row['projectCommit'], '--expected-run-id', str(row['runId']),
                        '--expected-run-attempt', str(row['runAttempt'])], check=True)
        validation = json.loads((release / 'ci-validation.json').read_text())
        source = json.loads((release / 'sources/source-manifest.json').read_text())
        require(validation['status'] == 'passed' and source['status'] == 'captured-used-source'
                and source['sdkVersion'] == args.sdk_version and source['targetRid'] == rid,
                'Only qualified matching SDK/source deliveries can be promoted')
        sdk_path = ordinary_file(release, validation['sdkArchive']['path'])
        source_path = ordinary_file(release / 'sources', source['archive']['path'])
        record = {}
        record['sdk'] = copy_payload(sdk_path, args.output / f'cbodotnet-sdk-{args.sdk_version}-linux-{arch}.tar.gz',
                                     validation['sdkArchive'])
        record['source'] = copy_payload(source_path, args.output / f'cbodotnet-source-{args.sdk_version}-linux-{arch}.tar.gz',
                                        source['archive'])
        record['evidence'] = pack_evidence(release, args.output / f'evidence-{arch}.tar.gz', {sdk_path, source_path})
        record['provenance'] = {key: row[key] for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')}
        record['provenance'].update({'targetRid': rid,
            'workflowUrl': f'https://github.com/{REPOSITORY}/actions/runs/{row["runId"]}',
            'originalSdkName': validation['sdkArchive']['path'], 'originalSourceName': source['archive']['path']})
        manifest['architectures'][arch] = record
    checksums = args.output / 'SHA256SUMS'
    checksums.write_text(''.join(f'{row[kind]["sha256"]}  {row[kind]["name"]}\n'
                                for row in manifest['architectures'].values()
                                for kind in ('sdk', 'source', 'evidence')), encoding='utf-8', newline='\n')
    manifest['checksums'] = asset(checksums)
    if 'generation' in plan:
        manifest['generation'] = plan['generation']
    (args.output / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    from release_catalog import validate_manifest
    validate_manifest(manifest, REPOSITORY)
    print(json.dumps({'status': 'staged', 'tag': manifest['tag'], 'directory': str(args.output)}), flush=True)


def gh(args, *arguments, allow_missing=False):
    command = [args.gh, *arguments]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        if allow_missing and 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError('GitHub CLI failed: ' + result.stderr.strip())
    return result.stdout


def cli_path(args, path):
    if sys.platform != 'win32' and args.gh.lower().endswith('.exe'):
        return subprocess.check_output(['wslpath', '-w', str(path.resolve())], text=True).strip()
    return str(path.resolve())


def publish(args):
    from release_catalog import validate_checksums, validate_manifest, validate_release
    require(re.fullmatch('[a-f0-9]{40}', args.target_commit), 'An immutable orchestration commit is required')
    manifest_path = args.staging / 'release-manifest.json'
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    validate_manifest(manifest, REPOSITORY)
    assets = [item for row in manifest['architectures'].values() for item in (row['sdk'], row['source'], row['evidence'])]
    assets += [manifest['checksums'], asset(manifest_path)]
    require({p.name for p in args.staging.iterdir()} == {a['name'] for a in assets}, 'Unexpected staged release files')
    for record in assets:
        require(asset(ordinary_file(args.staging, record['name'])) == record, 'A staged asset changed')
    # Check the complete local publication contract before creating any remote draft.
    validate_checksums(manifest, (args.staging / 'SHA256SUMS').read_bytes())
    tag = manifest['tag']
    endpoint = f'repos/{REPOSITORY}/releases/tags/{tag}'
    raw = gh(args, 'api', endpoint, allow_missing=True)
    if raw is None:
        # Never adopt an unrelated pre-existing tag, even when it has no release.
        tag_raw = gh(args, 'api', f'repos/{REPOSITORY}/git/ref/tags/{tag}', allow_missing=True)
        require(tag_raw is None, 'Refusing an existing tag without a matching release')
        notes = args.staging.parent / (tag + '-notes.md')
        notes.write_text(
            f'Community .NET SDK {manifest["sdkVersion"]} for glibc Linux x64 and AArch64.\n\n'
            'SDK and actual used source archives are unchanged qualified build payloads. Public AArch64 filenames '
            'map to the official .NET linux-arm64 RID. Each architecture has its own used sources and complete '
            'qualification evidence, including construction and dependency limits.\n\n'
            'Verify downloaded files with SHA256SUMS. release-manifest.json binds public names and digests to '
            'the original producer commits, workflow runs, artifacts and filenames. GitHub-generated repository '
            'source archives contain orchestration only; use the cbodotnet-source assets for used product sources.\n\n'
            'Native functional verification covers Ubuntu 22.04, Ubuntu 24.04 and Debian 13. Legacy versions '
            'retain their recorded OpenSSL/ICU dependencies. These are community builds independent of upstream '
            'support dates; source and framework origins remain described in the evidence.\n', encoding='utf-8')
        gh(args, 'release', 'create', tag, '--repo', REPOSITORY, '--draft', '--latest=false',
           '--target', args.target_commit, '--title', '.NET SDK ' + manifest['sdkVersion'],
           '--notes-file', cli_path(args, notes))
        raw = gh(args, 'api', endpoint)
    release = json.loads(raw)
    require(release['tag_name'] == tag and not release['prerelease'], 'Unexpected existing release identity')
    require(not release['draft'] or release.get('target_commitish') == args.target_commit,
            'Refusing an unrelated draft with a different orchestration commit')
    expected = {a['name']: a for a in assets}
    existing = {a['name']: a for a in release['assets']}
    require(len(existing) == len(release['assets']) and set(existing) <= set(expected), 'Unexpected existing release assets')
    for name, remote in existing.items():
        require(remote['size'] == expected[name]['size'] and remote.get('digest') == 'sha256:' + expected[name]['sha256'],
                'An existing release asset differs; overwrite is forbidden: ' + name)
    missing = [name for name in expected if name not in existing]
    require(release['draft'] or not missing, 'A published release cannot be partially amended')
    def upload(name):
        gh(args, 'release', 'upload', tag, cli_path(args, args.staging / name), '--repo', REPOSITORY)
        print(json.dumps({'status': 'uploaded', 'tag': tag, 'asset': name}), flush=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(upload, missing))
    release = json.loads(gh(args, 'api', endpoint))
    # Validate staged content against API digests before making the draft public.
    public_shape = dict(release, draft=False)
    validate_release(public_shape, manifest_bytes, (args.staging / 'SHA256SUMS').read_bytes(), REPOSITORY)
    if release['draft']:
        gh(args, 'release', 'edit', tag, '--repo', REPOSITORY, '--draft=false', '--latest=false')
    release = json.loads(gh(args, 'api', endpoint))
    require(not release['draft'], 'Release publication did not complete')
    validate_release(release, manifest_bytes, (args.staging / 'SHA256SUMS').read_bytes(), REPOSITORY)
    print(json.dumps({'status': 'published', 'url': release['html_url'], 'assets': len(release['assets'])}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('stage')
    prepare.add_argument('--target', required=True)
    prepare.add_argument('--sdk-version', required=True)
    prepare.add_argument('--deliveries', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--project-root', type=Path, default=ROOT)
    promote = commands.add_parser('publish')
    promote.add_argument('--staging', type=Path, required=True)
    promote.add_argument('--target-commit', required=True)
    promote.add_argument('--gh', default='gh')
    args = parser.parse_args()
    (stage if args.command == 'stage' else publish)(args)


if __name__ == '__main__':
    main()
