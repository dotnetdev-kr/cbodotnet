"""Seal all six actual public musl executions before exposing availability."""
import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

import musl_contract as CONTRACT
from downstream_publish import GitHubReleases, verify_remote_assets
from downstream_release import descriptor, encoded, ordinary_file, require, verify_report_signature
from musl_promotion import active_signer, load_json
from musl_release import (WORKFLOW, extract_artifact, load_signing_policy,
    validate_artifact, validate_publication_metadata, validate_run, verify_publication_signature, verify_release_tag)
from release_catalog import get_bytes, release_assets, validate_api_asset

REPOSITORY = CONTRACT.REPOSITORY
CHANNELS = ('archive', 'apk', 'oci')
MANIFEST = 'verification-manifest.json'
SIGNATURE = MANIFEST + '.asc'
MAX_REPORT_BYTES = 32 * 1024**2
MAX_MANIFEST_BYTES = 16 * 1024**2
RUNNER_LABELS = {'x64': 'ubuntu-24.04', 'aarch64': 'ubuntu-24.04-arm'}


def protected():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
        and os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
        and os.environ.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
        and os.environ.get('GITHUB_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
        and os.environ.get('GITHUB_JOB') in {'freeze_verification', 'publish_verification'},
        'Only protected main musl verification freeze/publish jobs are authorized')
    result = dict(repository=REPOSITORY, workflow=WORKFLOW, commit=os.environ.get('GITHUB_SHA', ''),
                  runId=os.environ.get('GITHUB_RUN_ID', ''), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT', ''))
    require(re.fullmatch(r'[a-f0-9]{40}', result['commit']) and all(re.fullmatch(r'[1-9][0-9]*', result[key])
            for key in ('runId', 'runAttempt')), 'Exact protected verification commit/run identity required')
    return result


def verification_tag(revision, sdk_version='10.0.403'):
    require(sdk_version in CONTRACT.SOURCES, 'Unreviewed musl verification SDK version')
    CONTRACT.version_revision(sdk_version, revision)
    return f'verification-musl-sdk-{sdk_version}-r{revision}'


def asset_url(tag, name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}', name),
            'Unsafe public verification asset name')
    return f'https://github.com/{REPOSITORY}/releases/download/{tag}/{name}'


def listed(api, endpoint, key):
    rows = []
    for page in range(1, 11):
        value = api.api(endpoint + ('&' if '?' in endpoint else '?') + f'per_page=100&page={page}')
        require(isinstance(value, dict) and isinstance(value.get(key), list), 'Invalid bounded musl API listing')
        rows.extend(value[key])
        if len(value[key]) < 100:
            return rows
    raise ValueError('Musl API listing exceeds its explicit bound')


def timestamp(value):
    require(isinstance(value, str), 'An actual API timestamp is required')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ValueError('Invalid actual API timestamp') from error
    require(result.tzinfo is not None, 'An API timestamp must include its UTC offset')
    return result


def public_jobs(run, jobs, channel):
    require(channel in CHANNELS, 'Unknown public musl channel')
    selected = {}
    for arch, label in RUNNER_LABELS.items():
        matches = [job for job in jobs if job.get('name') == f'Verify public musl {channel} native {arch}']
        require(len(matches) == 1, 'Exactly one actual public native job is required per channel/CPU')
        job = matches[0]
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success'
            and job.get('head_sha') == run['head_sha'] and type(job.get('id')) is int and job['id'] > 0
            and type(job.get('runner_id')) is int and job['runner_id'] > 0
            and job.get('runner_group_name') == 'GitHub Actions'
            and job.get('runner_name') == 'GitHub Actions ' + str(job['runner_id'])
            and isinstance(job.get('labels'), list) and label in job['labels']
            and 'self-hosted' not in job['labels']
            and timestamp(job['started_at']) <= timestamp(job['completed_at']),
            'Public execution did not use the successful exact native GitHub-hosted CPU job')
        selected[arch] = job
    return selected


def source_origin(run, run_id, attempt):
    commit = validate_run(run, workflow=WORKFLOW, run_id=run_id, attempt=attempt)
    return dict(repository=REPOSITORY, workflow=WORKFLOW, commit=commit, runId=str(run_id), runAttempt=str(attempt))


def artifact_provenance(artifact, archive, origin, *, job=None):
    result = dict(orchestration=copy.deepcopy(origin), artifact=copy.deepcopy(artifact), artifactZip=descriptor(archive))
    if job is not None:
        created = timestamp(artifact.get('created_at'))
        require(timestamp(job['started_at']) <= created <= timestamp(job['completed_at']),
                'Actual native report artifact was not created during its matching native job')
        result['job'] = {key: copy.deepcopy(job[key]) for key in ('id', 'name', 'head_sha', 'labels', 'runner_id',
            'runner_name', 'runner_group_name', 'started_at', 'completed_at', 'status', 'conclusion')}
    return result


def receive_json_artifact(api, artifact, run, expected_name, filename, output, origin, *, job=None, downloader=None):
    artifact = validate_artifact(artifact, run, expected_name)
    require(artifact['size_in_bytes'] <= MAX_REPORT_BYTES + 1024**2, 'Public JSON artifact ZIP exceeds its size bound')
    output = Path(output)
    output.mkdir()
    archive = output / 'transport.zip'
    if downloader is None:
        with archive.open('xb') as stream:
            subprocess.run([api.gh, 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'], stdout=stream, check=True)
    else:
        downloader(artifact, archive)
    actual = descriptor(archive)
    require(actual['size'] == artifact['size_in_bytes'] and 'sha256:' + actual['sha256'] == artifact['digest'],
            'Public musl JSON transport differs from actual GitHub API digest')
    with zipfile.ZipFile(archive) as stream:
        rows = stream.infolist()
        require(len(rows) == 1 and rows[0].filename == filename and 0 < rows[0].file_size <= MAX_REPORT_BYTES,
                'A closed single bounded public JSON artifact is required')
    received = extract_artifact(archive, output / 'received', {filename}, api_artifact=artifact)
    path = ordinary_file(received / filename)
    value = load_json(path)
    require(isinstance(value, dict), 'Public musl JSON artifact must contain an object')
    return path.read_bytes(), value, artifact_provenance(artifact, archive, origin, job=job)


def receive_channel(api, channel, run_id, attempt, revision, output, *, downloader=None, sdk_version="10.0.403"):
    require(channel in CHANNELS and type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'Exact completed public channel run and attempt required')
    run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    require(isinstance(run, dict), 'Public musl source run is absent')
    origin = source_origin(run, run_id, attempt)
    jobs = public_jobs(run, listed(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs'), channel)
    artifacts = listed(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts', 'artifacts')
    output = Path(output)
    output.mkdir()
    def select(name):
        matches = [row for row in artifacts if row.get('name') == name]
        require(len(matches) == 1, 'An exact unique public musl artifact is required: ' + name)
        return matches[0]
    receipt_name = f'musl-{channel}-publication-{run_id}-{attempt}'
    receipt_raw, receipt, publication = receive_json_artifact(api, select(receipt_name), run, receipt_name,
        f'musl-{channel}-publication.json', output / 'publication', origin, downloader=downloader)
    publication['receipt'] = dict(name=f'musl-{channel}-publication.json',size=len(receipt_raw),
                                  sha256=hashlib.sha256(receipt_raw).hexdigest())
    publication['receiptCanonicalSha256'] = hashlib.sha256(encoded(receipt)).hexdigest()
    identity = receipt.get('identity', {})
    require(receipt.get('schemaVersion') == 1 and receipt.get('kind') == 'musl-distribution-publication-receipt'
        and receipt.get('status') == 'published-public-bytes-verified' and identity.get('channel') == channel
        and identity.get('sdkVersion') == sdk_version and identity.get('packageRevision') == revision
        and identity.get('libc') == 'musl' and 'verification' not in receipt and 'postVerification' not in receipt,
        'Original musl receipt is not an unactivated exact public-byte publication')
    reports, provenance = {}, {}
    for arch in CONTRACT.ARCHITECTURES:
        name = f'musl-public-{channel}-{arch}-{run_id}-{attempt}'
        raw, report, proof = receive_json_artifact(api, select(name), run, name, 'public-report.json', output / arch,
            origin, job=jobs[arch], downloader=downloader)
        require(report.get('orchestration') == origin and report.get('architecture') == arch
            and report.get('native') is True and report.get('targetRid') == CONTRACT.ARCHITECTURES[arch]['rid']
            and report.get('scope') == {'archive': 'musl-consumer-archive-installation',
                'apk': 'musl-apk-installation', 'oci': 'musl-oci-installation'}[channel],
            'Actual public musl report came from another workflow/CPU/native scope')
        reports[arch], provenance[arch] = raw, proof
    return dict(receipt=receipt, reports=reports, provenance=provenance, publication=publication, origin=origin)


def authenticate_channel(receipt, keyring, *, api=None, fetch=None):
    """Read actual anonymous small signed metadata; never fetch SDK payloads here."""
    api, fetch = api or GitHubReleases(), fetch or get_bytes
    identity = receipt.get('identity', {})
    channel, version, revision = identity.get('channel'), identity.get('sdkVersion'), identity.get('packageRevision')
    require(channel in CHANNELS and version in CONTRACT.SOURCES and identity.get('producerRevision') == 1
        and identity.get('libc') == 'musl', 'Unreviewed public musl channel source identity')
    tag = CONTRACT.distribution_tag(channel, version, revision)
    require(receipt.get('tag') == tag and receipt.get('manifestUrl') == asset_url(tag, 'distribution-manifest.json')
        and receipt.get('signatureUrl') == asset_url(tag, 'distribution-manifest.json.asc')
        and receipt.get('releaseUrl') == f'https://github.com/{REPOSITORY}/releases/tag/{tag}'
        and re.fullmatch(r'[a-f0-9]{64}', receipt.get('manifestSha256', '')),
        'Musl public receipt escaped its immutable channel identity')
    release = api.api(f'repos/{REPOSITORY}/releases/tags/{tag}')
    require(isinstance(release, dict) and release.get('tag_name') == tag and release.get('draft') is False
        and release.get('prerelease') is False and release.get('html_url') == receipt['releaseUrl']
        and type(receipt.get('releaseId')) is int and receipt['releaseId'] > 0 and release.get('id') == receipt['releaseId'],
        'An actual stable public channel release is required')
    remote = release_assets(release)
    raw = fetch(receipt['manifestUrl'], MAX_MANIFEST_BYTES)
    signature = fetch(receipt['signatureUrl'], 1024**2)
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MANIFEST_BYTES
        and isinstance(signature, bytes) and 0 < len(signature) <= 1024**2
        and hashlib.sha256(raw).hexdigest() == receipt['manifestSha256'], 'Actual anonymous channel manifest bytes differ')
    validate_api_asset(remote.get('distribution-manifest.json'), 'distribution-manifest.json', REPOSITORY, tag, content=raw)
    validate_api_asset(remote.get('distribution-manifest.json.asc'), 'distribution-manifest.json.asc', REPOSITORY, tag, content=signature)
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-channel-metadata-') as temporary:
        directory = Path(temporary)
        (directory/'manifest.json').write_bytes(raw)
        (directory/'manifest.json.asc').write_bytes(signature)
        fingerprint = verify_publication_signature(directory/'manifest.json', directory/'manifest.json.asc', keyring)
        manifest = load_json(directory/'manifest.json')
    require(manifest.get('kind') == 'musl-distribution-publication' and manifest.get('repository') == REPOSITORY
        and manifest.get('identity') == identity and manifest.get('tag') == tag
        and manifest.get('signingFingerprint') == fingerprint == receipt.get('signingFingerprint'),
        'Actual channel signature does not bind the exact public receipt')
    signed = manifest.get('assets', [])
    indexed = {row.get('name'): row for row in signed}
    require(len(indexed) == len(signed) and set(remote) == set(indexed) | {'distribution-manifest.json', 'distribution-manifest.json.asc'},
        'Actual public channel release is not its closed signed asset inventory')
    require(receipt.get('assets') == [dict(row, url=asset_url(tag, row['name'])) for row in signed],
        'Public channel receipt asset descriptors differ from signed actual metadata')
    for name, item in indexed.items():
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}', name)
            and type(item.get('size')) is int and item['size'] > 0
            and re.fullmatch(r'[a-f0-9]{64}', item.get('sha256', '')), 'Invalid signed public musl asset descriptor')
        validate_api_asset(remote.get(name), name, REPOSITORY, tag, descriptor=item)
    verify_release_tag(api, tag, manifest.get('targetCommit'))
    return manifest


def final_document(received, revision, target_commit, signer, *, sdk_version="10.0.403"):
    require(set(received) == set(CHANNELS), 'All three public musl delivery channels are required')
    tag, entries, assets, reports = verification_tag(revision, sdk_version), [], [], {}
    common = None
    for channel in CHANNELS:
        source = received[channel]
        entry = copy.deepcopy(source['receipt'])
        identity = entry['identity']
        require(identity.get('sdkVersion') == sdk_version, 'Final public source SDK differs from requested version')
        shared = {key: value for key, value in identity.items() if key != 'channel'}
        require(common is None or common == shared, 'Public musl channels mix qualified source/version/revision')
        common = shared
        entry['status'] = 'published-postverified'
        post = dict(publication=copy.deepcopy(source['publication']), reports=[])
        require(set(source['reports']) == set(CONTRACT.ARCHITECTURES), 'Each public channel needs both native reports')
        reports[channel] = {}
        for arch in CONTRACT.ARCHITECTURES:
            raw = source['reports'][arch]
            require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_REPORT_BYTES, 'Actual native report exceeds its bound')
            name = f'{channel}-{arch}-public-report.json'
            item = dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            assets.append(item)
            reports[channel][arch] = raw
            post['reports'].append(dict(architecture=arch, report=dict(item, url=asset_url(tag, name)),
                rawJsonSha256=item['sha256'], rawJsonSize=item['size'], provenance=copy.deepcopy(source['provenance'][arch])))
        entry['postVerification'] = post
        entries.append(entry)
    return dict(schemaVersion=1, kind='musl-public-verification', repository=REPOSITORY, libc='musl', sdkVersion=sdk_version,
        packageRevision=revision, tag=tag, targetCommit=target_commit, signingFingerprint=signer,
        status='validated-complete-matrix', entries=entries, assets=sorted(assets, key=lambda row: row['name'])), reports


def validate_public_evidence(document, manifests, reports):
    entries = document.get('entries', [])
    require(document.get('schemaVersion') == 1 and document.get('kind') == 'musl-public-verification'
        and document.get('repository') == REPOSITORY and document.get('libc') == 'musl'
        and document.get('sdkVersion') in CONTRACT.SOURCES
        and document.get('tag') == verification_tag(document.get('packageRevision'), document.get('sdkVersion'))
        and document.get('status') == 'validated-complete-matrix'
        and re.fullmatch(r'[a-f0-9]{40}', document.get('targetCommit', ''))
        and isinstance(entries, list) and len(entries) == 3
        and {entry.get('identity', {}).get('channel') for entry in entries} == set(CHANNELS)
        and set(manifests) == set(reports) == set(CHANNELS), 'A complete exact three-channel public verification matrix is required')
    actual_assets = {}
    common = None
    for entry in entries:
        identity = entry['identity']
        channel = identity['channel']
        shared = {key:value for key,value in identity.items() if key != 'channel'}
        require(common is None or common == shared, 'Final public verification mixes qualified source identities')
        common = shared
        require(identity.get('sdkVersion') == document['sdkVersion'] and identity.get('packageRevision') == document['packageRevision'] and 'verification' not in entry
            and set(reports[channel]) == set(CONTRACT.ARCHITECTURES), 'Final public verification has partial or redirected report identity')
        post = entry.get('postVerification', {})
        publication = post.get('publication', {})
        origin = publication.get('orchestration', {})
        require(origin.get('repository') == REPOSITORY and origin.get('workflow') == WORKFLOW
            and re.fullmatch(r'[a-f0-9]{40}', origin.get('commit', ''))
            and all(re.fullmatch(r'[1-9][0-9]*', origin.get(key, '')) for key in ('runId', 'runAttempt')),
            'Final public evidence has no exact main-workflow provenance')
        require(manifests[channel].get('sourceOrchestration') == origin
            and ('sourceOrchestration' not in entry or entry['sourceOrchestration'] == origin),
            'Channel signed publication originated in another workflow/commit/attempt')
        expected_run = dict(id=int(origin['runId']),head_sha=origin['commit'])
        expected_publication_name = f'musl-{channel}-publication-{origin["runId"]}-{origin["runAttempt"]}'
        validate_recorded_artifact(publication,origin,expected_run,expected_publication_name)
        original = {key:copy.deepcopy(value) for key,value in entry.items() if key != 'postVerification'}
        original['status'] = 'published-public-bytes-verified'
        original_raw = encoded(original)
        original_descriptor = publication.get('receipt',{})
        require(original_descriptor.get('name') == f'musl-{channel}-publication.json'
            and type(original_descriptor.get('size')) is int and 0 < original_descriptor['size'] <= MAX_REPORT_BYTES
            and re.fullmatch(r'[a-f0-9]{64}',original_descriptor.get('sha256',''))
            and publication.get('receiptCanonicalSha256') == hashlib.sha256(original_raw).hexdigest(),
            'Final receipt changed fields from the actual original publication receipt')
        rows = post.get('reports', [])
        require(isinstance(rows,list) and len(rows) == 2
            and {row.get('architecture') for row in rows} == set(CONTRACT.ARCHITECTURES), 'Final public evidence lacks both native reports')
        for row in rows:
            arch = row['architecture']
            raw = reports[channel][arch]
            name = f'{channel}-{arch}-public-report.json'
            item = dict(name=name,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            require(row.get('report') == dict(item,url=asset_url(document['tag'],name))
                and row.get('rawJsonSize') == len(raw) and row.get('rawJsonSha256') == item['sha256']
                and row.get('provenance',{}).get('orchestration') == origin,
                'Final native report descriptor or workflow provenance differs from actual bytes')
            validate_recorded_artifact(row['provenance'],origin,expected_run,
                f'musl-public-{channel}-{arch}-{origin["runId"]}-{origin["runAttempt"]}')
            report = json.loads(raw)
            require(report.get('orchestration') == origin, 'Final public report originated in another workflow run')
            actual_assets[name] = item
        public_jobs(expected_run,[row['provenance'].get('job',{}) for row in rows],channel)
        validate_publication_metadata(manifests[channel], entry, reports[channel], verification_manifest=document)
    require(document.get('assets') == [actual_assets[name] for name in sorted(actual_assets)],
            'Final verification manifest does not bind exactly six actual report assets')
    return document


def validate_recorded_artifact(proof, origin, run, name):
    """Recheck the signed API snapshot; freeze already verified its actual ZIP."""
    require(proof.get('orchestration') == origin, 'Recorded artifact has another workflow identity')
    artifact = validate_artifact(proof.get('artifact'),run,name)
    require(proof.get('artifactZip') == dict(name='transport.zip',size=artifact['size_in_bytes'],sha256=artifact['digest'].split(':')[1]),
            'Signed API artifact digest snapshot differs from actual received ZIP descriptor')
    if 'job' in proof:
        require(timestamp(proof['job']['started_at']) <= timestamp(artifact.get('created_at'))
                <= timestamp(proof['job']['completed_at']), 'Signed native artifact time is outside its source job')


def freeze(sources, revision, output, keyring, *, gnupg_home=None, api=None, fetch=None, downloader=None, sdk_version="10.0.403"):
    current = protected()
    require(set(sources) == set(CHANNELS), 'All three exact source runs are required')
    api = api or GitHubReleases()
    policy = load_signing_policy()
    signer = active_signer(policy)
    received, manifests = {}, {}
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-final-receive-') as temporary:
        for channel in CHANNELS:
            run_id, attempt = sources[channel]
            received[channel] = receive_channel(api, channel, run_id, attempt, revision, Path(temporary)/channel, downloader=downloader, sdk_version=sdk_version)
            manifests[channel] = authenticate_channel(received[channel]['receipt'], keyring, api=api, fetch=fetch)
        document, reports = final_document(received, revision, current['commit'], signer, sdk_version=sdk_version)
        validate_public_evidence(document, manifests, reports)
        output = Path(output).absolute()
        require(output.parent.is_dir() and not output.exists() and not any(path.is_symlink() for path in [output,*output.parents]),
                'A fresh ordinary final verification bundle is required')
        output.mkdir()
        for channel in CHANNELS:
            for arch, raw in reports[channel].items():
                (output/f'{channel}-{arch}-public-report.json').write_bytes(raw)
        (output/MANIFEST).write_bytes(encoded(document))
        command = ['gpg'] + (['--homedir',str(gnupg_home)] if gnupg_home is not None else [])
        subprocess.run(command+['--batch','--yes','--armor','--local-user',signer,'--output',str(output/SIGNATURE),
            '--detach-sign',str(output/MANIFEST)],check=True)
        require(verify_report_signature(output/MANIFEST,output/SIGNATURE,keyring,policy,WORKFLOW) == signer,
                'Final musl verification signature has an unexpected signer')
    return document


def validate_frozen(directory, keyring, *, api=None, fetch=None):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(path.is_symlink() for path in [directory,*directory.parents]),
            'An ordinary frozen musl verification bundle is required')
    document = load_json(directory/MANIFEST)
    signer = verify_report_signature(directory/MANIFEST,directory/SIGNATURE,keyring,load_signing_policy(),WORKFLOW)
    require(document.get('signingFingerprint') == signer, 'Frozen final verification signer differs')
    expected_names = {f'{channel}-{arch}-public-report.json' for channel in CHANNELS for arch in CONTRACT.ARCHITECTURES}
    require({path.name for path in directory.iterdir()} == expected_names|{MANIFEST,SIGNATURE},
            'Frozen final verification is not a closed eight-file bundle')
    assets = document.get('assets',[])
    indexed = {item.get('name'):item for item in assets}
    require(len(indexed) == len(assets) and set(indexed) == expected_names, 'Frozen final verification report inventory differs')
    for name,item in indexed.items():
        require(descriptor(directory/name) == item, 'Frozen public native report bytes changed')
    reports = {channel:{arch:ordinary_file(directory/f'{channel}-{arch}-public-report.json').read_bytes()
        for arch in CONTRACT.ARCHITECTURES} for channel in CHANNELS}
    manifests = {}
    for entry in document.get('entries',[]):
        channel = entry.get('identity',{}).get('channel')
        require(channel in CHANNELS and channel not in manifests, 'Duplicate final verification channel')
        manifests[channel] = authenticate_channel(entry,keyring,api=api,fetch=fetch)
    validate_public_evidence(document,manifests,reports)
    return document


def candidate_status(document, manifest_descriptor):
    tag = document['tag']
    pointer = dict(manifestUrl=asset_url(tag,MANIFEST),signatureUrl=asset_url(tag,SIGNATURE),
        manifestSha256=manifest_descriptor['sha256'],signingFingerprint=document['signingFingerprint'])
    publications = []
    for entry in document['entries']:
        receipt = copy.deepcopy(entry)
        receipt['verification'] = copy.deepcopy(pointer)
        publications.append(receipt)
    return dict(schemaVersion=1,kind='musl-distribution-availability',repository=REPOSITORY,libc='musl',
        status='published-postverified',installerAdmission='separate-issue-30',publications=publications)


def publish(directory, output, keyring, *, api=None, fetch=None):
    protected()
    api = api or GitHubReleases()
    directory, output = Path(directory).absolute(), Path(output).absolute()
    require(output.parent.is_dir() and not output.exists() and not any(path.is_symlink() for path in [output,*output.parents]),
            'A fresh ordinary musl status candidate output is required')
    document = validate_frozen(directory,keyring,api=api,fetch=fetch)
    expected = {item['name']:item for item in document['assets']}
    expected.update({name:descriptor(directory/name) for name in (MANIFEST,SIGNATURE)})
    tag = document['tag']
    title = f'Community Build musl SDK {document["sdkVersion"]} public verification r{document["packageRevision"]}'
    body = ('Signed actual public installation evidence for Community Build of .NET (built by .NET Dev).\n\n'
        'The six unchanged native reports cover archive, APK and OCI delivery on Alpine 3.24.4, '
        'each on x64 and AArch64. verification-manifest.json binds the exact signed channel receipts, '
        'actual API-authenticated workflow provenance and public report bytes. Verify its detached OpenPGP signature.\n\n'
        'NativeAOT, workloads and cbodotnetup musl admission remain separate qualification work.\n')
    release = api.find(tag)
    if release is None:
        require(api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}') is None,'Refusing an unrelated final verification tag')
        release = api.api(f'repos/{REPOSITORY}/releases','POST',dict(tag_name=tag,target_commitish=document['targetCommit'],
            name=title,body=body,draft=True,prerelease=False,make_latest='false'))
    require(release.get('tag_name') == tag and release.get('target_commitish') == document['targetCommit']
        and release.get('name') == title and release.get('body') == body and release.get('prerelease') is False,
        'Existing final verification release has another immutable identity')
    verify_release_tag(api,tag,document['targetCommit'],allow_pending_draft=release.get('draft') is True)
    remote = {row.get('name'):row for row in release.get('assets',[])}
    require(len(remote) == len(release.get('assets',[])) and set(remote) <= set(expected),
            'Unexpected or duplicate final verification release assets')
    for name,item in expected.items():
        if name in remote:
            require(remote[name].get('size') == item['size'] and remote[name].get('digest') == 'sha256:'+item['sha256'],
                    'Refusing to replace conflicting final verification asset')
        else:
            require(release.get('draft') is True,'A public verification release cannot gain or replace assets')
            api.upload(release,directory/name)
    release = api.get(release)
    verify_remote_assets(release,expected,api,public=False)
    if release['draft']:
        release = api.publish(release)
    release = api.get(release)
    verify_release_tag(api,tag,document['targetCommit'])
    verify_remote_assets(release,expected,api,public=True)
    status = candidate_status(document,expected[MANIFEST])
    output.write_bytes(encoded(status))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    freeze_command = commands.add_parser('freeze')
    for channel in CHANNELS:
        freeze_command.add_argument('--'+channel+'-run-id',type=int,required=True)
        freeze_command.add_argument('--'+channel+'-attempt',type=int,default=1)
    freeze_command.add_argument('--revision',type=int,default=1)
    freeze_command.add_argument('--sdk-version',choices=sorted(CONTRACT.SOURCES),default='10.0.403')
    freeze_command.add_argument('--output',type=Path,required=True)
    freeze_command.add_argument('--gnupg-home',type=Path)
    publish_command = commands.add_parser('publish')
    publish_command.add_argument('--bundle',type=Path,required=True)
    publish_command.add_argument('--output',type=Path,required=True)
    for command in (freeze_command,publish_command):
        command.add_argument('--keyring',type=Path,required=True)
    args = parser.parse_args()
    if args.command == 'freeze':
        sources = {channel:(getattr(args,channel+'_run_id'),getattr(args,channel+'_attempt')) for channel in CHANNELS}
        result = freeze(sources,args.revision,args.output,args.keyring,gnupg_home=args.gnupg_home,sdk_version=args.sdk_version)
        print(json.dumps(dict(status='signed-and-frozen',tag=result['tag'])))
    else:
        result = publish(args.bundle,args.output,args.keyring)
        print(json.dumps(dict(status=result['status'],channels=len(result['publications']))))


if __name__ == '__main__':
    main()
