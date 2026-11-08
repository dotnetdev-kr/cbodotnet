"""Receive, independently rebuild and immutably sign native musl candidates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
from downstream_publish import GitHubReleases, verify_remote_assets
from downstream_release import descriptor, encoded, ordinary_file, require, verify_report_signature
from musl_release import (WORKFLOW, extract_artifact, load_signing_policy,
                          validate_artifact, validate_run, verify_release_tag)

REPOSITORY = CONTRACT.REPOSITORY
MANIFEST = 'distribution-manifest.json'
SIGNATURE = MANIFEST + '.asc'
MAX_JSON_BYTES = 32 * 1024**2


def load_json(path):
    raw = ordinary_file(path).read_bytes()
    require(0 < len(raw) <= MAX_JSON_BYTES, 'Musl candidate JSON exceeds its bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate musl candidate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def protected():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
        and os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
        and os.environ.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
        and os.environ.get('GITHUB_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
        and os.environ.get('GITHUB_JOB') in {'freeze_archive', 'publish_archive'},
        'Only protected main musl freeze/publish jobs may sign or promote candidates')
    origin = dict(repository=REPOSITORY, workflow=WORKFLOW, commit=os.environ.get('GITHUB_SHA', ''),
                  runId=os.environ.get('GITHUB_RUN_ID', ''), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT', ''))
    require(re.fullmatch(r'[a-f0-9]{40}', origin['commit'])
            and all(re.fullmatch(r'[1-9][0-9]*', origin[key]) for key in ('runId', 'runAttempt')),
            'Exact protected musl job commit/run identity is required')
    return origin


def validate_native_run(run, run_id, attempt, *, current=None):
    if run.get('status') == 'completed':
        return validate_run(run, workflow=WORKFLOW, run_id=run_id, attempt=attempt)
    require(current is not None and run.get('status') == 'in_progress' and run.get('conclusion') is None
        and current == dict(repository=REPOSITORY, workflow=WORKFLOW, commit=run.get('head_sha'),
                            runId=str(run_id), runAttempt=str(attempt))
        and run.get('id') == run_id and run.get('run_attempt') == attempt and run.get('path') == WORKFLOW
        and run.get('head_branch') == 'main' and run.get('event') == 'workflow_dispatch'
        and run.get('repository', {}).get('full_name') == REPOSITORY
        and run.get('head_repository', {}).get('full_name') == REPOSITORY,
        'An in-progress native source is allowed only in its exact protected current musl run')
    return run['head_sha']


def native_identity(api, run_id, attempt, *, current=None):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'Exact positive native run and attempt required')
    run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    require(isinstance(run, dict), 'Native musl run is absent')
    commit = validate_native_run(run, run_id, attempt, current=current)
    jobs = []
    for page in range(1, 11):
        result = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')
        require(isinstance(result, dict) and isinstance(result.get('jobs'), list), 'Invalid native musl job response')
        jobs.extend(result['jobs'])
        if len(result['jobs']) < 100:
            break
    else:
        raise ValueError('Native musl job listing exceeds its bound')
    selected = {}
    for arch in CONTRACT.ARCHITECTURES:
        matches = [row for row in jobs if row.get('name') == 'Qualify musl archive native ' + arch]
        require(len(matches) == 1 and matches[0].get('status') == 'completed' and matches[0].get('conclusion') == 'success',
                'Both exact native musl archive jobs must have completed successfully')
        selected[arch] = matches[0]
    return run, dict(repository=REPOSITORY, workflow=WORKFLOW, commit=commit, runId=str(run_id), runAttempt=str(attempt)), selected


def artifact_name(architecture, origin):
    require(architecture in CONTRACT.ARCHITECTURES, 'Unknown native musl architecture')
    return f'musl-native-archive-{architecture}-{origin["runId"]}-{origin["runAttempt"]}'


def receive_candidates(api, run_id, attempt, revision, output, *, current=None, downloader=None, sdk_version="10.0.403"):
    run, origin, jobs = native_identity(api, run_id, attempt, current=current)
    artifacts = []
    for page in range(1, 11):
        result = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100&page={page}')
        require(isinstance(result, dict) and isinstance(result.get('artifacts'), list), 'Invalid musl artifact listing')
        artifacts.extend(result['artifacts'])
        if len(result['artifacts']) < 100:
            break
    else:
        raise ValueError('Musl artifact listing exceeds its bound')
    output = ARCHIVE.fresh_directory(output)
    received = {}
    for arch in CONTRACT.ARCHITECTURES:
        name = artifact_name(arch, origin)
        matches = [row for row in artifacts if row.get('name') == name]
        require(len(matches) == 1, 'Exactly one native musl candidate artifact is required: ' + arch)
        artifact = validate_artifact(matches[0], run, name)
        archive = output / (arch + '.zip')
        if downloader is None:
            with archive.open('xb') as stream:
                subprocess.run([api.gh, 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'],
                               stdout=stream, check=True)
        else:
            downloader(artifact, archive)
        directory = extract_artifact(archive, output / arch,
            {CONTRACT.archive_name(sdk_version, arch, revision), 'package-build.json', 'qualification-report.json'},
            api_artifact=artifact)
        received[arch] = dict(directory=directory, transport=dict(artifact=artifact,
            artifactZip=descriptor(archive), jobId=jobs[arch]['id'], jobName=jobs[arch]['name']))
    return origin, received


def validate_elf_report(elf, payload, architecture):
    expected = CONTRACT.ARCHITECTURES[architecture]
    require(isinstance(elf, dict) and elf.get('status') == 'passed' and elf.get('native') is True
            and elf.get('libc') == 'musl' and elf.get('architecture') == architecture and elf.get('targetRid') == expected['rid'],
            'Native musl ELF proof identity differs')
    actual = {}
    for path in Path(payload).rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        actual[path.relative_to(payload).as_posix()] = descriptor(path)['sha256']
    rows = elf.get('elfFiles', [])
    require(isinstance(rows, list) and rows and len({row.get('path') for row in rows}) == len(rows)
            and {row.get('path'): row.get('sha256') for row in rows} == actual,
            'Native report omits or substitutes a regular SDK ELF')
    host = 0
    for row in rows:
        require(row.get('disposition') == 'host-runtime-or-tool',
                'Non-host target packs require a separately reviewed immutable publication policy')
        require(row.get('machine') == expected['elfMachine'] and row.get('elfClass') == 'ELF64'
                and row.get('interpreter') in {None, expected['interpreter']}, 'Native reported ELF architecture/loader differs')
        require(ARCHIVE.reviewed_gcc_abi_labels(row) == row.get('reviewedAbiVersionLabels'),
                'Native reported ABI labels differ from reviewed provider attribution')
        observed = ARCHIVE.inspect_elf(Path(payload) / row['path'])
        require(all(row.get(key) == value for key, value in observed.items()), 'Independent ELF inspection differs from native report')
        host += 1
    require(host > 0 and elf.get('hostElfCount') == host and elf.get('nonHostElfCount') == 0,
            'Native reported host ELF count differs')
    stock = elf.get('stockLibraries')
    require(isinstance(stock, list) and stock and all(isinstance(row, dict)
        and re.fullmatch(r'[a-f0-9]{64}', row.get('sha256', '')) and ' is owned by ' in row.get('apkOwner', '') for row in stock),
        'Stock native library bytes and APK ownership evidence are absent')


def validate_native_report(report, build, origin, *, payload=None):
    plan = build['plan']
    arch = ARCHIVE.plan_architecture(plan)
    require(report.get('schemaVersion') == 1 and report.get('scope') == 'musl-consumer-archive-installation'
        and report.get('status') == 'passed' and report.get('native') is True and report.get('architecture') == arch
        and report.get('libc') == 'musl' and report.get('targetRid') == plan['targetRid']
        and report.get('networkForBuild') == 'none' and report.get('identity') == ARCHIVE.identity(plan)
        and report.get('artifact') == build['artifact'] and report.get('orchestration') == origin,
        'Native musl report does not bind this exact build and trusted workflow')
    for name, required in [('checks', ARCHIVE.REPORT_CHECKS), ('functionalChecks', ARCHIVE.FUNCTIONAL_CHECKS)]:
        observed = report.get(name, {})
        require(isinstance(observed, dict) and required <= set(observed)
                and all(observed[key] == 'passed' for key in required), 'A mandatory native musl qualification check is missing')
    spaces = report.get('userSpaces', [])
    require(isinstance(spaces, list) and len(spaces) == 1, 'Exactly one reviewed Alpine native user space is required')
    space = spaces[0]
    require(space.get('variant') == 'alpine-3.24' and space.get('alpineVersion') == '3.24.4'
        and space.get('base') == ARCHIVE.BASES[arch] and space.get('uid') == space.get('gid') == 10001
        and space.get('status') == 'passed' and re.fullmatch(r'sha256:[a-f0-9]{64}', space.get('imageId', '')),
        'Native musl proof has another base/CPU/non-root account')
    ARCHIVE.validate_offline_report(space.get('offline'), build, arch, elf_audit=space.get('elfAudit'))
    trust = space.get('systemTrustHttps', {})
    require(trust.get('status') == 'passed' and trust.get('url') == ARCHIVE.trust_url(arch)
        and trust.get('network') == 'default-only-after-offline-build'
        and re.fullmatch(r'[a-f0-9]{64}', trust.get('outputSha256', '')),
        'Actual stock-system-trust HTTPS proof is absent')
    if payload is not None:
        validate_elf_report(space.get('elfAudit'), payload, arch)
    return report


def verify_candidate(directory, architecture, origin, source_inputs, revision=1, *, sdk_version="10.0.403"):
    directory = Path(directory)
    require({path.name for path in directory.iterdir()} == {CONTRACT.archive_name(sdk_version, architecture, revision),
        'package-build.json', 'qualification-report.json'}, 'Native candidate is not a closed three-file set')
    build, report = load_json(directory / 'package-build.json'), load_json(directory / 'qualification-report.json')
    require(build.get('kind') == 'musl-consumer-archive-build' and build.get('archiveLayoutVersion') == 1
            and build.get('status') == 'built-unpublished' and build.get('publicationAllowed') is False,
            'An unpublished native musl consumer build is required')
    require(ARCHIVE.plan_architecture(build['plan']) == architecture and build['plan']['packageRevision'] == revision and build['plan']['sdkVersion'] == sdk_version,
            'Native candidate architecture/revision differs')
    require(isinstance(build.get('artifact'), dict)
            and build['artifact'].get('name') == CONTRACT.archive_name(sdk_version, architecture, revision),
            'Native candidate artifact name differs from its closed expected filename')
    require(descriptor(directory / build['artifact']['name']) == build['artifact'], 'Native archive bytes changed after qualification')
    # Reconstruct every byte, mode and link independently. Compression libraries
    # can encode the same tar differently on different native workers.
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-rebuild-') as temporary:
        canonical = ARCHIVE.build_archive(source_inputs, architecture, revision, Path(temporary) / 'canonical')
        require(dict(build, artifact=canonical['artifact']) == canonical,
                'Native build differs from independently reconstructed qualified inputs')
        actual = Path(temporary) / 'received'
        ARCHIVE.tools().extract_sdk(directory / build['artifact']['name'], actual)
        require({path.name for path in actual.iterdir()} == {canonical['directory']}, 'Native consumer archive has an unexpected root')
        tree = Path(temporary) / 'canonical' / canonical['directory']
        require(ARCHIVE.tools().snapshot(actual / canonical['directory']) == ARCHIVE.tools().snapshot(tree),
                'Native archive tree differs from independently reconstructed qualified inputs')
        payload = tree / 'payload'
        validate_native_report(report, build, origin, payload=payload)
    return build, report


def publication_identity(plan):
    return {key: plan[key] for key in ('sdkVersion', 'producerRevision', 'packageRevision', 'libc',
                                      'channel', 'sourceReleaseTag', 'sourceManifestSha256')}


def active_signer(policy):
    matches = [fingerprint for fingerprint, row in policy.get('evidenceSigners', {}).items()
               if row.get('state') == 'active' and row.get('workflow') == WORKFLOW]
    require(len(matches) == 1 and re.fullmatch(r'[A-F0-9]{40,64}', matches[0]),
            'Exactly one active musl publication signer is required')
    return matches[0]


def create_bundle(candidates, origin, output, *, signing_key=None, keyring, gnupg_home=None,
                  target_commit=None, policy=None, source_receiver=None, sdk_version="10.0.403"):
    require(set(candidates) == set(CONTRACT.ARCHITECTURES), 'Both native musl candidates are required')
    policy = policy if policy is not None else load_signing_policy()
    signing_key = signing_key or active_signer(policy)
    require(signing_key == active_signer(policy), 'Unreviewed musl signing fingerprint')
    require(re.fullmatch(r'[a-f0-9]{40}', target_commit or ''), 'Exact protected publication commit required')
    if source_receiver is None:
        from musl_distribution import receive_source
        from functools import partial
        source_receiver = partial(receive_source, sdk_version=sdk_version)
    output = ARCHIVE.fresh_directory(output)
    records, assets, common = [], {}, None
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-source-recheck-') as temporary:
        for arch, item in candidates.items():
            directory = Path(item['directory'])
            inputs = source_receiver(arch, Path(temporary) / arch)
            revision = load_json(directory / 'package-build.json')['plan']['packageRevision']
            build, report = verify_candidate(directory, arch, origin, inputs, revision, sdk_version=sdk_version)
            identity = publication_identity(build['plan'])
            require(identity['channel'] == 'archive' and (common is None or common == identity),
                    'Native musl matrix mixes source/channel/version/revision')
            common = identity
            archive = ordinary_file(directory / build['artifact']['name'])
            report_name = 'qualification-' + arch + '.json'
            for source, name in ((archive, archive.name), (directory / 'qualification-report.json', report_name)):
                require(name not in assets, 'Duplicate musl publication asset')
                shutil.copyfile(source, output / name)
                assets[name] = descriptor(output / name)
            records.append(dict(architecture=arch, targetRid=build['plan']['targetRid'], artifactAsset=archive.name,
                qualificationReportAsset=report_name, build=build, orchestration=origin, transport=item['transport']))
    manifest = dict(schemaVersion=1, kind='musl-distribution-publication', repository=REPOSITORY,
        contractVersion=CONTRACT.load_contract()['schemaVersion'], tag=CONTRACT.distribution_tag('archive', common['sdkVersion'], common['packageRevision']),
        identity=common, targetCommit=target_commit, sourceOrchestration=origin, signingFingerprint=signing_key,
        status='validated-complete-matrix', records=sorted(records, key=lambda row: row['architecture']),
        assets=[assets[name] for name in sorted(assets)])
    (output / MANIFEST).write_bytes(encoded(manifest))
    command = ['gpg'] + (['--homedir', str(gnupg_home)] if gnupg_home is not None else [])
    subprocess.run(command + ['--batch', '--yes', '--armor', '--local-user', signing_key,
        '--output', str(output / SIGNATURE), '--detach-sign', str(output / MANIFEST)], check=True)
    validate_bundle(output, keyring, policy=policy)
    return manifest


def validate_bundle(directory, keyring, *, policy=None):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(path.is_symlink() for path in [directory, *directory.parents]),
            'Ordinary frozen musl bundle required')
    policy = policy if policy is not None else load_signing_policy()
    manifest = load_json(directory / MANIFEST)
    signer = verify_report_signature(directory / MANIFEST, directory / SIGNATURE, keyring, policy, WORKFLOW)
    require(manifest.get('schemaVersion') == 1 and manifest.get('kind') == 'musl-distribution-publication'
            and manifest.get('repository') == REPOSITORY and manifest.get('signingFingerprint') == signer,
            'Frozen musl manifest identity/signer differs')
    identity = manifest.get('identity', {})
    require(identity.get('channel') == 'archive' and identity.get('libc') == 'musl'
        and manifest.get('tag') == CONTRACT.distribution_tag('archive', identity.get('sdkVersion'), identity.get('packageRevision'))
        and re.fullmatch(r'[a-f0-9]{40}', manifest.get('targetCommit', '')), 'Frozen musl archive identity differs')
    catalog = CONTRACT.load_qualification_catalog()
    matches = [row for row in catalog['builds'] if row['sdkVersion'] == identity['sdkVersion']
               and row['producerRevision'] == identity.get('producerRevision')]
    require(len(matches) == 1 and matches[0]['sourceReleaseTag'] == identity.get('sourceReleaseTag')
            and matches[0]['sourceManifestSha256'] == identity.get('sourceManifestSha256'), 'Frozen musl source is no longer admitted')
    assets = manifest.get('assets', [])
    expected = {row.get('name'): row for row in assets}
    require(len(expected) == len(assets) and expected and all(isinstance(name, str)
        and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', name) for name in expected), 'Unsafe or duplicate frozen musl assets')
    require({path.name for path in directory.iterdir()} == set(expected) | {MANIFEST, SIGNATURE}, 'Frozen musl bundle is not a closed asset set')
    for name, row in expected.items():
        require(descriptor(directory / name) == row, 'Frozen musl asset bytes changed: ' + name)
    records = manifest.get('records', [])
    require(len(records) == 2 and {row.get('architecture') for row in records} == set(CONTRACT.ARCHITECTURES),
            'Frozen musl archive matrix is incomplete')
    used = set()
    for row in records:
        arch, build = row['architecture'], row['build']
        plan = build['plan']
        require(publication_identity(plan) == identity and plan['producer'] == matches[0]['architectures'][arch]
            and ARCHIVE.plan_architecture(plan) == arch and row.get('targetRid') == plan['targetRid']
            and row.get('artifactAsset') == CONTRACT.archive_name(identity['sdkVersion'], arch, identity['packageRevision'])
            and expected.get(row['artifactAsset']) == build['artifact'], 'Frozen musl build/source descriptor differs')
        name = row.get('qualificationReportAsset')
        require(name == 'qualification-' + arch + '.json' and name in expected, 'Frozen native report asset differs')
        report = load_json(directory / name)
        validate_native_report(report, build, manifest['sourceOrchestration'])
        used.update({row['artifactAsset'], name})
    require(used == set(expected), 'Frozen musl publication has unreferenced assets')
    return manifest


def freeze_archive(run_id, attempt, output, *, revision=1, keyring, signing_key=None, gnupg_home=None, api=None, sdk_version='10.0.403'):
    current = protected()
    api = api or GitHubReleases()
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-native-receive-') as temporary:
        origin, candidates = receive_candidates(api, run_id, attempt, revision, Path(temporary) / 'received', current=current, sdk_version=sdk_version)
        return create_bundle(candidates, origin, output, signing_key=signing_key, keyring=keyring,
                             gnupg_home=gnupg_home, target_commit=current['commit'], sdk_version=sdk_version)


def publication_metadata(manifest):
    identity = manifest['identity']
    title = f'Community Build musl SDK {identity["sdkVersion"]} {identity["channel"]} r{identity["packageRevision"]}'
    body = ('Community Build of .NET (built by .NET Dev), qualified natively on Alpine 3.24.4 for x64 and AArch64.\n\n'
        'Verify distribution-manifest.json and its detached OpenPGP signature before use. '
        'The manifest binds unchanged qualified SDK bytes, source provenance, both native reports and command branding.\n\n'
        'Public availability is activated only after anonymous native verification of the published bytes. '
        'NativeAOT, workloads and cbodotnetup musl admission require separate qualification.\n')
    return title, body


def publish_bundle(directory, keyring, *, api=None, policy=None):
    protected()
    directory = Path(directory).absolute()
    manifest = validate_bundle(directory, keyring, policy=policy)
    api = api or GitHubReleases()
    current = protected()
    source = manifest['sourceOrchestration']
    _, origin, _ = native_identity(api, int(source['runId']), int(source['runAttempt']), current=current)
    require(origin == source, 'Frozen musl native origin changed before promotion')
    expected = {row['name']: row for row in manifest['assets']}
    expected.update({name: descriptor(directory / name) for name in (MANIFEST, SIGNATURE)})
    tag = manifest['tag']
    title, body = publication_metadata(manifest)
    release = api.find(tag)
    if release is None:
        require(api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}') is None, 'Refusing an unrelated existing musl tag')
        release = api.api(f'repos/{REPOSITORY}/releases', 'POST', dict(tag_name=tag,
            target_commitish=manifest['targetCommit'], name=title, body=body, draft=True, prerelease=False, make_latest='false'))
    require(release.get('tag_name') == tag and release.get('name') == title and release.get('body') == body
        and release.get('target_commitish') == manifest['targetCommit'] and release.get('prerelease') is False,
        'Existing musl release has another immutable identity')
    verify_release_tag(api, tag, manifest['targetCommit'], allow_pending_draft=release.get('draft') is True)
    indexed = {row.get('name'): row for row in release.get('assets', [])}
    require(len(indexed) == len(release.get('assets', [])) and set(indexed) <= set(expected), 'Conflicting or duplicate remote musl assets')
    for name, wanted in expected.items():
        if name in indexed:
            require(indexed[name].get('size') == wanted['size'] and indexed[name].get('digest') == 'sha256:' + wanted['sha256'],
                    'Refusing to replace conflicting immutable musl asset: ' + name)
        else:
            require(release.get('draft') is True, 'A public musl release cannot gain or replace assets')
            api.upload(release, directory / name)
    release = api.get(release)
    verify_remote_assets(release, expected, api, public=False)
    if release['draft']:
        release = api.publish(release)
    release = api.get(release)
    verify_release_tag(api, tag, manifest['targetCommit'])
    verify_remote_assets(release, expected, api, public=True)
    base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    # Public-byte verification alone deliberately does not activate availability.
    return dict(schemaVersion=1, kind='musl-distribution-publication-receipt', status='published-public-bytes-verified',
        identity=manifest['identity'], tag=tag, releaseUrl=release['html_url'], releaseId=release['id'],
        manifestUrl=base + MANIFEST, signatureUrl=base + SIGNATURE, manifestSha256=expected[MANIFEST]['sha256'],
        signingFingerprint=manifest['signingFingerprint'], assets=[dict(row, url=base + row['name']) for row in manifest['assets']])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    freeze = commands.add_parser('freeze-archive')
    freeze.add_argument('--run-id', type=int, required=True)
    freeze.add_argument('--attempt', type=int, default=1)
    freeze.add_argument('--revision', type=int, default=1)
    freeze.add_argument('--sdk-version', choices=sorted(CONTRACT.SOURCES), default='10.0.403')
    freeze.add_argument('--output', type=Path, required=True)
    freeze.add_argument('--signing-key')
    freeze.add_argument('--gnupg-home', type=Path)
    publish = commands.add_parser('publish')
    publish.add_argument('--bundle', type=Path, required=True)
    publish.add_argument('--output', type=Path, required=True)
    for command in (freeze, publish):
        command.add_argument('--keyring', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'freeze-archive':
        result = freeze_archive(args.run_id, args.attempt, args.output, revision=args.revision, keyring=args.keyring,
                                signing_key=args.signing_key, gnupg_home=args.gnupg_home, sdk_version=args.sdk_version)
        print(json.dumps(dict(status='signed-and-frozen', tag=result['tag'])))
    else:
        require(args.output.parent.is_dir() and not args.output.exists(), 'A fresh musl publication receipt path is required')
        result = publish_bundle(args.bundle, args.keyring)
        args.output.write_bytes(encoded(result))
        print(json.dumps(dict(status=result['status'], tag=result['tag'])))


if __name__ == '__main__':
    main()
