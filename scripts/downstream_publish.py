#!/usr/bin/env python3
"""Publish signed, complete downstream channel matrices without replacing bytes."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from downstream_release import (REPOSITORY, descriptor, encoded, load_status, ordinary_file,
                                require, stage_records, verify_report_signature)
from distribution_contract import load_contract

MANIFEST = 'distribution-manifest.json'
SIGNATURE = MANIFEST + '.asc'
PUBLIC_KEY = 'distribution-signing-key.gpg'


def load_catalog():
    return json.loads((Path(__file__).resolve().parents[1] / 'releases/qualified-builds.json').read_bytes())


def safe_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}', value),
            'Unsafe publication asset name')
    return value


def release_tag(channel, version, revision):
    require(channel in {'deb', 'rpm', 'oci', 'aur'} and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version)
            and type(revision) is int and revision > 0, 'Invalid downstream publication identity')
    return f'distribution-{channel}-sdk-{version}-r{revision}'


def create_bundle(items, output, target_commit, signing_key, keyring, extra_assets=(), policy=None,
                  contract=None, catalog=None, gnupg_home=None):
    """Revalidate all native evidence and sign one immutable channel manifest."""
    require(re.fullmatch(r'[a-f0-9]{40}', target_commit), 'A full publication commit is required')
    require(re.fullmatch(r'[A-Fa-f0-9]{40,64}', signing_key), 'A full signing fingerprint is required')
    keyring = ordinary_file(keyring)
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(p.is_symlink() for p in [output, *output.parents]), 'A fresh ordinary bundle directory is required')
    policy = policy if policy is not None else load_status()
    with tempfile.TemporaryDirectory(prefix='cbodotnet-promotion-') as temporary:
        staged = stage_records(items, Path(temporary), policy, contract, catalog)
    require(all(record['orchestration']['commit'] == target_commit for record in staged['records']),
            'Evidence does not describe the publication commit')
    identity = staged['identity']
    tag = release_tag(identity['channel'], identity['sdkVersion'], identity['packageRevision'])
    output.mkdir(mode=0o700)
    assets = {}

    def copy(source, name):
        name = safe_name(name)
        source = ordinary_file(source)
        original = descriptor(source)
        expected = dict(original, name=name)
        if name in assets:
            require(assets[name] == expected, 'Conflicting asset names in one publication: ' + name)
            return name
        shutil.copyfile(source, output / name)
        require(descriptor(output / name) == expected, 'Publication copy differs from verified bytes')
        assets[name] = expected
        return name

    records = []
    by_target = {(item['package']['identity']['variant'], item['package']['architecture']): item for item in items}
    for record in staged['records']:
        variant, arch = record['identity']['variant'], record['architecture']
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]*', variant), 'Unsafe OS variant')
        item = by_target[(variant, arch)]
        prefix = identity['channel'] + '-' + variant + '-' + arch + '--'
        artifact = copy(item['artifactPath'], prefix + Path(item['artifactPath']).name)
        report = copy(item['reportPath'], prefix + 'installation-report.json')
        signature = copy(item['signaturePath'], prefix + 'installation-report.json.asc')
        records.append({'record': record, 'artifactAsset': artifact, 'reportAsset': report, 'signatureAsset': signature})
    repositories = []
    for extra in extra_assets:
        specification = extra if isinstance(extra, dict) else {'path': extra}
        path = Path(specification['path'])
        name = copy(path, path.name)
        if 'kind' in specification:
            allowed = {'deb': 'apt-repository', 'rpm': 'rpm-repository', 'aur': 'aur-recipe', 'oci': 'oci-descriptor'}
            require(specification['kind'] == allowed[identity['channel']], 'Repository kind differs from its channel')
            variants = specification.get('variants', sorted({row['record']['identity']['variant'] for row in records}))
            require(isinstance(variants, list) and variants and set(variants) <= {row['record']['identity']['variant'] for row in records},
                    'Repository metadata advertises an unverified OS variant')
            repositories.append({'asset': name, 'kind': specification['kind'], 'variants': sorted(variants),
                                 'websitePath': 'packages/' + identity['channel']})
            if specification.get('delivery') is not None:
                from apt_release import release_tag as flat_tag, flat_asset_descriptors
                require(identity['channel'] == 'deb' and len(variants) == 1
                        and specification['delivery'] == 'github-release-flat', 'Unsupported repository delivery adapter')
                expected_tag = flat_tag(variants[0], identity['sdkVersion'], identity['packageRevision'])
                require(specification.get('releaseTag') == expected_tag, 'Noncanonical flat repository release tag')
                repositories[-1].update(delivery='github-release-flat', releaseTag=expected_tag)
                repositories[-1]['flatAssets'] = flat_asset_descriptors(path)
    copy(keyring, PUBLIC_KEY)
    manifest = {'schemaVersion': 1, 'contractVersion': staged['contractVersion'], 'repository': REPOSITORY,
                'tag': tag, 'identity': identity, 'targetCommit': target_commit,
                'signingFingerprint': signing_key.upper(), 'status': 'validated-complete-matrix',
                'records': records, 'repositories': repositories, 'assets': [assets[name] for name in sorted(assets)]}
    (output / MANIFEST).write_bytes(encoded(manifest))
    command = ['gpg'] + (['--homedir', str(gnupg_home)] if gnupg_home else [])
    subprocess.run(command + ['--batch', '--yes', '--armor', '--local-user', signing_key,
                              '--output', str(output / SIGNATURE), '--detach-sign', str(output / MANIFEST)], check=True)
    verified = verify_report_signature(output / MANIFEST, output / SIGNATURE, keyring, policy,
                                       staged['records'][0]['orchestration']['workflow'])
    require(verified == signing_key.upper(), 'Manifest was signed by an unexpected key')
    return manifest


def validate_bundle(directory, keyring, target_commit=None, policy=None):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(p.is_symlink() for p in [directory, *directory.parents]),
            'An ordinary publication bundle is required')
    policy = policy if policy is not None else load_status()
    manifest_path = ordinary_file(directory / MANIFEST)
    data = manifest_path.read_bytes()
    require(len(data) <= 16 * 1024**2, 'Publication manifest exceeds its size limit')
    manifest = json.loads(data)
    require(manifest.get('schemaVersion') == 1 and manifest.get('repository') == REPOSITORY
            and manifest.get('status') == 'validated-complete-matrix', 'Invalid downstream manifest')
    identity = manifest['identity']
    require(manifest['tag'] == release_tag(identity['channel'], identity['sdkVersion'], identity['packageRevision']),
            'Manifest tag differs from immutable channel identity')
    require(re.fullmatch(r'[a-f0-9]{40}', manifest['targetCommit'])
            and (target_commit is None or manifest['targetCommit'] == target_commit), 'Publication commit changed')
    records = manifest.get('records')
    require(isinstance(records, list) and records, 'The signed publication matrix is empty')
    contract = load_contract()
    admitted = contract['releases'].get(identity['sdkVersion'], {})
    channel_policy = contract['channels'].get(identity['channel'], {})
    require(manifest.get('contractVersion') == contract['schemaVersion']
            and admitted.get('manifestSha256') == identity['sourceManifestSha256']
            and identity['sourceReleaseTag'] == 'sdk-' + identity['sdkVersion']
            and channel_policy.get('status') == 'preparation-only',
            'Frozen publication source or contract is no longer admitted')
    catalog = load_catalog()
    qualified = [row for row in catalog.get('builds', []) if row.get('sdkVersion') == identity['sdkVersion']]
    require(catalog.get('repository') == REPOSITORY and len(qualified) == 1
            and qualified[0].get('target') == admitted['target'], 'Frozen source producer is no longer qualified')
    workflow = records[0]['record']['orchestration']['workflow']
    signature_bytes = ordinary_file(directory / SIGNATURE).read_bytes()
    require(len(signature_bytes) <= 1024**2, 'Publication signature exceeds its size limit')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-manifest-check-') as temporary:
        snapshot = Path(temporary) / MANIFEST
        signature_snapshot = Path(temporary) / SIGNATURE
        snapshot.write_bytes(data)
        signature_snapshot.write_bytes(signature_bytes)
        fingerprint = verify_report_signature(snapshot, signature_snapshot, keyring, policy, workflow)
    require(fingerprint == manifest['signingFingerprint'], 'Publication signer mismatch')
    require(manifest_path.read_bytes() == data, 'Publication manifest changed during signature verification')
    expected = policy['channels'].get(identity['channel'], {}).get('candidateMatrix', [])
    observed = [(row['record']['identity']['variant'], row['record']['architecture']) for row in records]
    require(expected and len(set(observed)) == len(observed)
            and set(observed) == {(row['variant'], row['architecture']) for row in expected}, 'Incomplete publication matrix')
    descriptors = manifest.get('assets')
    require(isinstance(descriptors, list) and descriptors, 'Publication assets are absent')
    names = [safe_name(item['name']) for item in descriptors]
    require(len(names) == len(set(names)) and set(names).isdisjoint({MANIFEST, SIGNATURE}), 'Duplicate publication assets')
    require({path.name for path in directory.iterdir()} == set(names) | {MANIFEST, SIGNATURE},
            'Unexpected or missing bundle assets')
    indexed = {item['name']: item for item in descriptors}
    for item in descriptors:
        require(descriptor(directory / item['name']) == item, 'Publication asset size/digest changed: ' + item['name'])
    for row in records:
        record = row['record']
        require(record['status'] == 'validated-unpublished' and record['contractVersion'] == manifest['contractVersion']
                and record['orchestration']['commit'] == manifest['targetCommit']
                and record['orchestration']['workflow'] == workflow,
                'Publication records have inconsistent provenance')
        arch = record['architecture']
        producer = qualified[0].get('architectures', {}).get(arch, {})
        require(record['identity']['variant'] in channel_policy['variants']
                and arch in contract['architectures']
                and record['identity']['targetRid'] == contract['architectures'][arch]['rid']
                and record.get('branding') == contract['branding']
                and producer and all(str(record['producer'].get(key)) == str(producer.get(key))
                                     for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')),
                'Frozen source target, branding or producer is no longer admitted')
        require(all(record['identity'][key] == value for key, value in identity.items()),
                'Publication mixes immutable channel identities')
        for field, asset_field in [('artifact', 'artifactAsset'), ('report', 'reportAsset'), ('signature', 'signatureAsset')]:
            item = indexed.get(row[asset_field], {})
            require(item.get('sha256') == record[field]['sha256'] and item.get('size') == record[field]['size'],
                    'Publication record does not bind its actual bytes')
    return manifest


class GitHubReleases:
    """Minimal GitHub CLI transport; writes never clobber existing release assets."""
    def __init__(self, gh='gh'):
        self.gh = gh

    def api(self, endpoint, method='GET', body=None):
        command = [self.gh, 'api', endpoint, '--method', method]
        with tempfile.TemporaryDirectory(prefix='cbodotnet-gh-request-') as temporary:
            if body is not None:
                path = Path(temporary) / 'request.json'
                path.write_bytes(encoded(body))
                command += ['--input', str(path)]
            result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            if method == 'GET' and 'HTTP 404' in result.stderr:
                return None
            raise RuntimeError('GitHub release request failed (' + method + ' ' + endpoint.partition('?')[0] + '): ' + result.stderr.strip())
        return json.loads(result.stdout) if result.stdout.strip() else None

    def find(self, tag):
        result = subprocess.run([self.gh, 'api', f'repos/{REPOSITORY}/releases?per_page=100', '--paginate', '--slurp'],
                                capture_output=True, text=True, check=True)
        pages = json.loads(result.stdout)
        require(isinstance(pages, list) and all(isinstance(page, list) for page in pages), 'Invalid release listing response')
        releases = [entry for page in pages for entry in page if entry.get('tag_name') == tag]
        require(len(releases) <= 1, 'Ambiguous downstream release tag')
        if releases:
            return releases[0]
        # Pending draft tags can be missing from the REST listing cache. Resolve
        # their stable database ID before deciding that creating a draft is safe.
        owner, name = REPOSITORY.split('/')
        query = ('query($owner:String!,$name:String!,$tag:String!){'
                 'repository(owner:$owner,name:$name){release(tagName:$tag){databaseId}}}')
        result = self.api('graphql', 'POST', {'query': query, 'variables': {'owner': owner, 'name': name, 'tag': tag}})
        require(result and not result.get('errors') and isinstance(result.get('data', {}).get('repository'), dict),
                'Pending downstream release lookup failed')
        row = result['data']['repository'].get('release')
        if row is None:
            return None
        require(type(row.get('databaseId')) is int and row['databaseId'] > 0, 'Invalid pending release database identity')
        return self.get({'id': row['databaseId']})

    def create(self, manifest):
        # An unrelated tag may never be adopted merely because its release is absent.
        require(self.api(f'repos/{REPOSITORY}/git/ref/tags/{manifest["tag"]}') is None,
                'Refusing an existing tag without a matching distribution release')
        return self.api(f'repos/{REPOSITORY}/releases', 'POST', {
            'tag_name': manifest['tag'], 'target_commitish': manifest['targetCommit'],
            'name': 'cbodotnet ' + manifest['identity']['channel'] + ' distribution ' + manifest['identity']['sdkVersion'],
            'body': 'Signed downstream artifacts made from unchanged qualified SDK release bytes. '
                    'Verify distribution-manifest.json.asc with the independently trusted project signing fingerprint. '
                    'The manifest binds the full native installation matrix, source SDK provenance and generated commands.',
            'draft': True, 'prerelease': False, 'make_latest': 'false'})

    def get(self, release):
        for attempt in range(4):
            current = self.api(f'repos/{REPOSITORY}/releases/{release["id"]}')
            if current is not None:
                require(current.get('id') == release['id'], 'Downstream release database identity changed')
                return current
            if attempt < 3:
                time.sleep(2**attempt)
        raise ValueError('Downstream release remained unreadable after bounded retries')

    def upload(self, release, path):
        subprocess.run([self.gh, 'release', 'upload', release['tag_name'], str(path), '--repo', REPOSITORY], check=True)

    def download(self, asset, destination, public=False):
        if public:
            for attempt in range(4):
                try:
                    source = urllib.request.urlopen(asset['browser_download_url'], timeout=60)
                except urllib.error.HTTPError as error:
                    if error.code not in {404, 500, 502, 503, 504} or attempt == 3:
                        raise
                    time.sleep(2**attempt)
                    continue
                with source, Path(destination).open('xb') as target:
                    shutil.copyfileobj(source, target)
                break
        else:
            with Path(destination).open('xb') as target:
                subprocess.run([self.gh, 'api', f'repos/{REPOSITORY}/releases/assets/{asset["id"]}',
                                '-H', 'Accept: application/octet-stream'], stdout=target, check=True)

    def publish(self, release):
        return self.api(f'repos/{REPOSITORY}/releases/{release["id"]}', 'PATCH', {'draft': False, 'make_latest': 'false'})


def verify_remote_assets(release, expected, transport, public=False):
    assets = release.get('assets', [])
    require(isinstance(assets, list) and len({item.get('name') for item in assets}) == len(assets),
            'Malformed remote release asset list')
    by_name = {item['name']: item for item in assets}
    require(set(by_name) == set(expected), 'Remote downstream release has missing or unexpected assets')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-postverify-') as temporary:
        for name, wanted in expected.items():
            item = by_name[name]
            require(item.get('state') == 'uploaded' and item.get('size') == wanted['size'], 'Remote asset state/size mismatch')
            require(item.get('digest') in (None, 'sha256:' + wanted['sha256']), 'Conflicting remote artifact digest')
            if public:
                require(item.get('browser_download_url') == f'https://github.com/{REPOSITORY}/releases/download/{release["tag_name"]}/{name}',
                        'Unexpected public artifact URL')
            path = Path(temporary) / safe_name(name)
            transport.download(item, path, public=public)
            require(descriptor(path) == wanted, 'Re-downloaded remote artifact differs from verified publication bytes')


def publish_bundle(directory, keyring, target_commit=None, policy=None, gh='gh', transport=None):
    """Keep the exact verified local bytes private until remote postverification finishes."""
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(p.is_symlink() for p in [directory, *directory.parents]),
            'An ordinary publication bundle is required')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-publish-snapshot-') as temporary:
        snapshot = Path(temporary)
        for path in directory.iterdir():
            source = ordinary_file(path)
            shutil.copyfile(source, snapshot / safe_name(source.name))
        return _publish_snapshot(snapshot, keyring, target_commit, policy, gh, transport)


def publication_rows(manifest, manifest_digest, base=None):
    """Derive public target records only from the signed matrix and its asset map."""
    base = base or f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
    rows = []
    for entry in manifest['records']:
        record = entry['record']
        rows.append({
            'channel': manifest['identity']['channel'], 'variant': record['identity']['variant'], 'architecture': record['architecture'],
            'sdkVersion': record['identity']['sdkVersion'], 'packageRevision': record['identity']['packageRevision'],
            'sourceManifestSha256': record['identity']['sourceManifestSha256'],
            'artifactUrl': base + entry['artifactAsset'], 'artifactSha256': record['artifact']['sha256'],
            'verificationReportUrl': base + entry['reportAsset'], 'verificationReportSha256': record['report']['sha256'],
            'manifestUrl': base + MANIFEST, 'manifestSha256': manifest_digest,
            'signatureUrl': base + SIGNATURE, 'signingFingerprint': manifest['signingFingerprint'],
            'status': 'published-postverified'})
    return rows


def _publish_snapshot(directory, keyring, target_commit=None, policy=None, gh='gh', transport=None):
    policy = policy if policy is not None else load_status()
    directory = Path(directory).absolute()
    manifest = validate_bundle(directory, keyring, target_commit, policy)
    channel = manifest['identity']['channel']
    configuration = policy['channels'][channel]
    require(configuration.get('publisherConfigured') is True
            and configuration.get('publisher', {}).get('type') == 'github-release', 'GitHub Release publisher is not configured')
    transport = transport if transport is not None else GitHubReleases(gh)
    expected = {item['name']: item for item in manifest['assets']}
    expected.update({name: descriptor(directory / name) for name in (MANIFEST, SIGNATURE)})
    release = transport.find(manifest['tag'])
    if release is None:
        release = transport.create(manifest)
    require(release.get('tag_name') == manifest['tag'] and release.get('target_commitish') == manifest['targetCommit']
            and release.get('prerelease') is False, 'An unrelated downstream release already uses this identity')
    remote = {item['name']: item for item in release.get('assets', [])}
    require(set(remote) <= set(expected), 'Unexpected existing downstream release asset')
    for name, item in remote.items():
        require(item.get('size') == expected[name]['size'] and item.get('digest') in (None, 'sha256:' + expected[name]['sha256']),
                'Refusing to replace a conflicting published digest')
        with tempfile.TemporaryDirectory(prefix='cbodotnet-existing-') as temporary:
            path = Path(temporary) / name
            transport.download(item, path, public=not release['draft'])
            require(descriptor(path) == expected[name], 'Refusing changed existing release bytes')
    missing = set(expected) - set(remote)
    require(not missing or release.get('draft') is True, 'An incomplete public distribution release cannot be repaired in place')
    for name in sorted(missing):
        transport.upload(release, directory / name)
    for attempt in range(4):
        release = transport.get(release)
        observed_names = {item['name'] for item in release.get('assets', [])}
        require(observed_names <= set(expected), 'Unexpected asset appeared during staging')
        if observed_names == set(expected):
            break
        if attempt < 3:
            time.sleep(2**attempt)
    verify_remote_assets(release, expected, transport)
    if release['draft']:
        release = transport.publish(release)
    for attempt in range(4):
        release = transport.get(release)
        if release.get('draft') is False and release.get('html_url') == f'https://github.com/{REPOSITORY}/releases/tag/{manifest["tag"]}':
            break
        require(attempt < 3, 'Downstream release did not become publicly readable')
        time.sleep(2**attempt)
    verify_remote_assets(release, expected, transport, public=True)
    base = f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
    publications = publication_rows(manifest, expected[MANIFEST]['sha256'], base)
    return {'schemaVersion': 1, 'status': 'published-postverified', 'repository': REPOSITORY,
            'identity': manifest['identity'], 'releaseUrl': release['html_url'], 'tag': manifest['tag'],
            'manifestUrl': base + MANIFEST, 'signatureUrl': base + SIGNATURE, 'publicKeyUrl': base + PUBLIC_KEY,
            'manifestSha256': expected[MANIFEST]['sha256'], 'signingFingerprint': manifest['signingFingerprint'],
            'assets': [dict(item, url=f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/{item["name"]}')
                       for item in expected.values()], 'repositories': manifest.get('repositories', []),
            'publications': publications, 'publicationAllowed': True}
