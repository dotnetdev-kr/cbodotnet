#!/usr/bin/env python3
"""Activate only cryptographically authenticated and natively post-verified channels."""
import base64
import copy
import json
from pathlib import Path
import re
import tempfile
import time

from distribution_site import prepare_site
from downstream_publish import GitHubReleases, REPOSITORY, release_tag, read_leased_json
from downstream_release import PREPUBLICATION_CHECKS, encoded, require, validate_native_curl_evidence

STATUS_PATH = 'releases/downstream-status.json'
CONSISTENCY_MAX_SECONDS = 25 * 60
CONSISTENCY_DELAYS = (2, 4, 8, 16) + (20,) * 73 + (10,)
POST_CHECKS = {'anonymous-pull', 'native-config', 'non-root', 'command-aliases', 'cli-branding', 'offline-build-run'}
POST_CHECKS_V2 = POST_CHECKS | {'sdk-list-paths', 'image-labels', 'image-ownership',
                              'image-no-build-secrets', 'image-no-source-build-toolchain',
                              'console-apphost', 'http-crypto-globalization', 'sdk-info-root-rid'}
OCI_FUNCTIONAL_CHECKS = {'consoleDllExecution', 'consoleApphostExecution', 'aspNetCoreLoopbackHttp',
                         'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting', 'nonRootRuntimeRoot'}


def receipt_key(receipt):
    identity = receipt['identity']
    return identity['sdkVersion'], identity['packageRevision']


def receipt_order(receipt):
    version, revision = receipt_key(receipt)
    return tuple(map(int, version.split('.'))) + (revision,)


def validate_receipts(receipts):
    require(isinstance(receipts, list) and receipts, 'Published channel receipts are required')
    channels = []
    for receipt in receipts:
        require(receipt.get('schemaVersion') == 1 and receipt.get('repository') == REPOSITORY
                and receipt.get('status') == 'published-postverified', 'An actual post-verified publication receipt is required')
        identity = receipt['identity']
        channel = identity['channel']
        require(channel in {'deb', 'oci', 'rpm'}, 'Channel status automation requires an enabled native post-verifier')
        tag = release_tag(channel, identity['sdkVersion'], identity['packageRevision'])
        require(receipt.get('tag') == tag and identity['sourceReleaseTag'] == 'sdk-' + identity['sdkVersion'],
                'Publication tag differs from its source/version/revision')
        channels.append(channel)
    require(len(set(channels)) == len(channels), 'At most one incoming receipt per channel is allowed')
    first = receipts[0]['identity']
    require(all(all(receipt['identity'][key] == first[key] for key in ('sdkVersion', 'packageRevision', 'sourceManifestSha256', 'sourceReleaseTag'))
                for receipt in receipts), 'Incoming channel receipts describe different immutable source versions')


def validate_postverification(policy, receipts, reports, index=None):
    expected_arches = {row['architecture'] for receipt in receipts
                       for row in policy['channels'][receipt['identity']['channel']]['candidateMatrix']}
    require(isinstance(reports, list) and len(reports) == len(expected_arches)
            and {report.get('architecture') for report in reports} == expected_arches,
            'Both exact native post-publication reports are required')
    by_channel = {receipt['identity']['channel']: receipt for receipt in receipts}
    if 'oci' in by_channel:
        identity = by_channel['oci']['identity']
        require(isinstance(index, dict) and index.get('repository') == 'ghcr.io/dotnetdev-kr/cbodotnet-sdk'
                and re.fullmatch(r'sha256:[a-f0-9]{64}', index.get('digest', ''))
                and index.get('tag') == identity['sdkVersion'] + '-debian13-r' + str(identity['packageRevision']),
                'An immutable published OCI index is required')
        platforms = index.get('platforms', [])
        require(len(platforms) == 2 and {(row.get('os'), row.get('architecture')) for row in platforms}
                == {('linux', 'amd64'), ('linux', 'arm64')}, 'Published OCI index has an incomplete platform matrix')
        require(all(re.fullmatch(r'sha256:[a-f0-9]{64}', row.get('digest', ''))
                    and re.fullmatch(r'sha256:[a-f0-9]{64}', row.get('configDigest', '')) for row in platforms),
                'Published OCI platform/config digests are absent')
        versions = {row.get('metadataPolicyVersion') for row in platforms}
        require(versions == {None} or versions == {2}, 'OCI metadata policies cannot be mixed or silently downgraded')
        require(identity['packageRevision'] == 1 or versions == {2}, 'New OCI revisions require complete metadata policy 2')
    for report in reports:
        require(report.get('schemaVersion') == 1 and report.get('status') == 'passed', 'Native post-publication verification failed')
        arch = report['architecture']
        if 'oci' in by_channel:
            require(report.get('repository') == index['repository'] and report.get('digest') == index['digest']
                    and POST_CHECKS <= set(report.get('checks', [])), 'OCI post-verifier did not test this published digest and command surface')
            if versions == {2}:
                platform = next(row for row in platforms if row['architecture'] == {'x64': 'amd64', 'aarch64': 'arm64'}[arch])
                config, files = report.get('imageConfig', {}), report.get('imageFiles', {})
                root = '/opt/cbodotnet/' + '.'.join(identity['sdkVersion'].split('.')[:2])
                require(POST_CHECKS_V2 <= set(report.get('checks', [])) and platform.get('labels')
                        and config.get('architecture') == platform['architecture']
                        and config.get('labels') == platform['labels']
                        and config.get('sdkRoot') == platform.get('sdkRoot') == root
                        and config.get('user') in {'app', '1654', '1654:1654'} and config.get('workdir') == '/work'
                        and report.get('networkForBuild') == 'none'
                        and all(report.get('functionalChecks', {}).get(name) == 'passed' for name in OCI_FUNCTIONAL_CHECKS)
                        and files.get('ownership') == 'root:root:0755'
                        and files.get('sourceBuildToolchain') == files.get('credentialEnvironment') == 'absent',
                        'OCI public metadata, SDK listing, ownership or consumer configuration proof is incomplete')
            validate_native_curl_evidence(report, dict(sdkVersion=identity['sdkVersion'],
                channel='oci', variant='debian-13', architecture=dict(public=arch)))
        if 'deb' in by_channel:
            targets = report.get('aptTargets', [])
            expected = {row['variant'] for row in policy['channels']['deb']['candidateMatrix'] if row['architecture'] == arch}
            require(len(targets) == len(expected) and {row.get('variant') for row in targets} == expected,
                    'APT post-publication target matrix is incomplete or duplicated')
            assets = {row['name']: row for row in by_channel['deb']['assets']}
            checks = (PREPUBLICATION_CHECKS - {'upgrade'}) | set(policy['channels']['deb']['requiredChecks'])
            for target in targets:
                asset = assets.get('apt-' + target['variant'] + '.tar.gz', {})
                require(target.get('architecture') == arch and target.get('status') == 'passed'
                        and asset.get('sha256') and target.get('repositorySha256') == asset['sha256'],
                        'APT post-verifier tested another architecture or repository archive')
                require(all(target.get('checks', {}).get(name) == 'passed' for name in checks)
                        and target.get('checks', {}).get('upgrade') in {'passed', 'verified-before-publication'},
                        'APT installation, integrity, branding or lifecycle post-check failed')
                validate_native_curl_evidence(target, dict(sdkVersion=by_channel['deb']['identity']['sdkVersion'],
                    channel='deb', variant=target['variant'], architecture=dict(public=arch)))
        if 'rpm' in by_channel:
            targets = report.get('rpmTargets', [])
            expected = {row['variant'] for row in policy['channels']['rpm']['candidateMatrix'] if row['architecture'] == arch}
            require(len(targets) == len(expected) and {row.get('variant') for row in targets} == expected,
                    'RPM post-publication target matrix is incomplete or duplicated')
            assets = {row['name']: row for row in by_channel['rpm']['assets']}
            checks = (PREPUBLICATION_CHECKS - {'upgrade'}) | set(policy['channels']['rpm']['requiredChecks'])
            for target in targets:
                asset = assets.get('rpm-' + target['variant'] + '.tar.gz', {})
                require(target.get('architecture') == arch and target.get('status') == 'passed'
                        and asset.get('sha256') and target.get('repositorySha256') == asset['sha256'],
                        'RPM post-verifier tested another architecture or repository archive')
                require(all(target.get('checks', {}).get(name) == 'passed' for name in checks)
                        and target.get('checks', {}).get('upgrade') in {'passed', 'verified-before-publication'},
                        'RPM package signature, repository, integrity or installation post-check failed')
                validate_native_curl_evidence(target, dict(sdkVersion=by_channel['rpm']['identity']['sdkVersion'],
                    channel='rpm', variant=target['variant'], architecture=dict(public=arch)))


def activate_status(policy, receipts, reports, index=None, proof=None, public_key=None, verifier=None):
    """Authenticate current receipts, then preserve immutable channel history."""
    require(policy.get('schemaVersion') == 1 and policy.get('repository') == REPOSITORY,
            'Unsupported distribution availability policy')
    validate_receipts(receipts)
    verifier = verifier if verifier is not None else prepare_site
    # Authenticate incoming records in isolation; existing history is retained
    # below rather than being confused with the newly tested index.
    validation = copy.deepcopy(policy)
    for channel in validation['channels'].values():
        channel.update(status='not-published', publications=[], receipts=[])
    for receipt in receipts:
        channel = validation['channels'][receipt['identity']['channel']]
        channel.update(status='published', publications=receipt['publications'], receipts=[receipt])
    with tempfile.TemporaryDirectory(prefix='cbodotnet-status-verify-') as temporary:
        authenticated = verifier(validation, Path(temporary) / 'site', public_key)
    if any(receipt['identity']['channel'] == 'oci' for receipt in receipts):
        require(authenticated['channels']['oci'].get('image') == index,
                'Supplied OCI index differs from the authenticated signed descriptor')
    validate_postverification(policy, receipts, reports, index)
    merged = copy.deepcopy(policy)
    for receipt in receipts:
        name = receipt['identity']['channel']
        channel = merged['channels'][name]
        history = channel.setdefault('receipts', [])
        existing = [row for row in history if receipt_key(row) == receipt_key(receipt)]
        require(len(existing) <= 1, 'Existing publication history is ambiguous')
        if existing:
            original = {key: value for key, value in existing[0].items() if key != 'postVerification'}
            require(original == receipt, 'Conflicting receipt for an existing immutable SDK/revision')
        else:
            recorded = copy.deepcopy(receipt)
            recorded['postVerification'] = {'reports': sorted(copy.deepcopy(reports), key=lambda row: row['architecture'])}
            if proof:
                recorded['postVerification']['workflow'] = copy.deepcopy(proof)
            history.append(recorded)
        history.sort(key=receipt_order)
        channel.update(status='published', publisherConfigured=True,
                       publications=[row for entry in history for row in entry['publications']])
    merged['status'] = 'published-channels-available'
    return merged


def validate_workflow_run(api, run_id, attempt, channels=('deb', 'oci'), *,
                          retry_delays=CONSISTENCY_DELAYS, sleep=None):
    require(re.fullmatch(r'[1-9][0-9]*', str(run_id)) and re.fullmatch(r'[1-9][0-9]*', str(attempt)),
            'Exact successful publication run and attempt are required')
    required_jobs = (('Sign and publish RPM distributions',
                      'Verify public RPM repositories on native x64',
                      'Verify public RPM repositories on native aarch64') if set(channels) == {'rpm'} else
                     ('Sign, promote and post-verify immutable distributions',
                      'Anonymous digest pull and non-root smoke on x64',
                      'Anonymous digest pull and non-root smoke on aarch64'))
    require(set(channels) <= {'deb', 'oci'} or set(channels) == {'rpm'}, 'Unsupported publication job matrix')
    delays = tuple(retry_delays)
    require(all(type(delay) in {int, float} and 0 <= delay <= 20 for delay in delays)
            and sum(delays) <= CONSISTENCY_MAX_SECONDS,
            'Workflow consistency retry must remain bounded to 25 minutes with at most 20 seconds per wait')
    sleep = sleep or time.sleep
    deadline = time.monotonic() + CONSISTENCY_MAX_SECONDS
    expected_head = None
    for poll in range(len(delays) + 1):
        run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}')
        require(isinstance(run, dict) and run.get('repository', {}).get('full_name') == REPOSITORY
                and run.get('head_repository', {}).get('full_name') == REPOSITORY
                and run.get('head_branch') == 'main' and run.get('event') == 'workflow_dispatch'
                and run.get('path') == '.github/workflows/distribution-release.yml'
                and isinstance(run.get('head_sha'), str)
                and re.fullmatch(r'[a-f0-9]{40}', run.get('head_sha', '')),
                'Status updates require the trusted main publication workflow')
        expected_head = expected_head or run['head_sha']
        require(run['head_sha'] == expected_head, 'Publication run source commit changed while waiting for job metadata')
        response = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
        require(isinstance(response, dict) and isinstance(response.get('jobs'), list)
                and all(isinstance(row, dict) for row in response['jobs']), 'Malformed publication job API response')
        pending = []
        for name in required_jobs:
            matched = [row for row in response['jobs'] if row.get('name') == name]
            require(len(matched) <= 1, 'Duplicate publication or native post-verification job: ' + name)
            if not matched:
                pending.append(name)
                continue
            job = matched[0]
            require(('run_id' not in job or job['run_id'] == int(run_id))
                    and ('run_attempt' not in job or job['run_attempt'] == int(attempt))
                    and ('head_sha' not in job or job['head_sha'] == expected_head),
                    'Publication job belongs to another exact run, attempt or source commit')
            state, conclusion = job.get('status'), job.get('conclusion')
            require(conclusion in {None, 'success'} and state in {'queued', 'in_progress', 'waiting', 'pending', 'requested', 'completed'},
                    'Publication or native post-verification job did not pass: ' + name)
            if state != 'completed' or conclusion != 'success':
                pending.append(name)
        if not pending:
            return {'runId': str(run_id), 'runAttempt': str(attempt), 'commit': expected_head,
                    'url': f'https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}'}
        require(poll < len(delays), 'Publication jobs did not reach actual terminal success within the bounded consistency window: ' + ', '.join(pending))
        require(time.monotonic() + delays[poll] <= deadline,
                'Publication jobs did not reach actual terminal success within the bounded consistency window: ' + ', '.join(pending))
        sleep(delays[poll])


def update_repository_status(receipts, reports, index, run_id, attempt, gh='gh', api=None, verifier=None, public_key=None):
    """Use the observed content SHA as a lease, then explicitly refresh Pages."""
    api = api if api is not None else GitHubReleases(gh)
    proof = validate_workflow_run(api, run_id, attempt, [receipt['identity']['channel'] for receipt in receipts])
    policy, content = read_leased_json(api, STATUS_PATH)
    activated = activate_status(policy, receipts, reports, index, proof, public_key, verifier)
    changed = activated != policy
    commit = None
    if changed:
        updated = api.api(f'repos/{REPOSITORY}/contents/{STATUS_PATH}', 'PUT', {
            'message': 'Publish verified cbodotnet distribution availability', 'branch': 'main',
            'sha': content['sha'], 'content': base64.b64encode(encoded(activated)).decode('ascii')})
        require(updated and updated.get('commit', {}).get('sha'), 'Status commit was not acknowledged')
        commit = updated['commit']['sha']
    # Commits created with GITHUB_TOKEN do not trigger a second workflow run.
    api.api(f'repos/{REPOSITORY}/actions/workflows/pages.yml/dispatches', 'POST', {'ref': 'main'})
    return {'status': 'availability-updated' if changed else 'availability-already-current',
            'commit': commit, 'channels': [receipt['identity']['channel'] for receipt in receipts],
            'verificationRun': proof['url'], 'pagesDispatched': True}
