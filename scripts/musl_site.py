"""Render Alpine downloads only after both signed publication and public proof."""
import copy
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import tempfile

from downstream_release import ordinary_file, require
from musl_contract import (ARCHITECTURES, REPOSITORY, distribution_tag, load_contract,
                           producer_tag, version_revision)
from release_catalog import get_bytes

ROOT = Path(__file__).resolve().parents[1]
MAX_METADATA_BYTES = 16 * 1024**2
MAX_SIGNATURE_BYTES = 1024**2
CHANNELS = {'archive', 'apk', 'oci'}


def decoded(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate musl public metadata key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def load_status(path=None):
    path = Path(path) if path is not None else ROOT / 'releases/musl-status.json'
    value = decoded(ordinary_file(path).read_bytes())
    require(value.get('schemaVersion') == 1 and value.get('kind') == 'musl-distribution-availability'
            and value.get('repository') == REPOSITORY and value.get('libc') == 'musl'
            and value.get('installerAdmission') == 'separate-issue-30'
            and isinstance(value.get('publications'), list), 'Invalid separate musl availability policy')
    return value


def asset_url(tag, name):
    require(isinstance(tag, str) and isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', name),
            'Unsafe musl publication asset name')
    return f'https://github.com/{REPOSITORY}/releases/download/{tag}/{name}'


def bound_bytes(url, fetch, *, item=None, sha256=None, maximum=MAX_METADATA_BYTES):
    require(isinstance(url, str) and re.fullmatch(r'https://github\.com/' + REPOSITORY
        + r'/releases/download/(?:distribution-musl-(?:archive|apk|oci)-sdk-|verification-musl-sdk-)[1-9][0-9]*\.[0-9]+\.[0-9]+-r[1-9][0-9]*/[A-Za-z0-9][A-Za-z0-9._+-]*', url),
        'Untrusted musl metadata URL')
    if item is not None:
        require(isinstance(item, dict) and type(item.get('size')) is int and 0 < item['size'] <= maximum
                and re.fullmatch(r'[a-f0-9]{64}', item.get('sha256', '')) and item.get('url') == url,
                'Invalid bounded musl public asset descriptor')
    if sha256 is not None:
        require(re.fullmatch(r'[a-f0-9]{64}', sha256), 'Invalid musl metadata SHA256 pin')
    raw = fetch(url, item['size'] if item is not None else maximum)
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, 'Musl public metadata exceeds its size bound')
    digest = hashlib.sha256(raw).hexdigest()
    require((item is None or (len(raw) == item['size'] and digest == item['sha256']))
            and (sha256 is None or digest == sha256), 'Public musl metadata bytes differ from receipt')
    return raw


def authenticate_receipt(receipt, *, fetch=None, keyring=None):
    """Never turn an unsigned availability assertion into a download link."""
    from musl_release import validate_publication_metadata, verify_publication_signature
    fetch = fetch or get_bytes
    require(isinstance(receipt, dict) and receipt.get('schemaVersion') == 1
            and receipt.get('kind') == 'musl-distribution-publication-receipt'
            and receipt.get('status') == 'published-postverified', 'Musl availability requires a public verified receipt')
    identity = receipt.get('identity', {})
    version, revision = identity.get('sdkVersion'), identity.get('packageRevision')
    version_revision(version, revision)
    channel = identity.get('channel')
    tag = distribution_tag(channel, version, revision)
    require(identity.get('libc') == 'musl' and identity.get('sourceReleaseTag') == producer_tag(version, identity.get('producerRevision'))
            and version in load_contract()['releases'] and receipt.get('tag') == tag
            and receipt.get('releaseUrl') == f'https://github.com/{REPOSITORY}/releases/tag/{tag}'
            and receipt.get('manifestUrl') == asset_url(tag, 'distribution-manifest.json')
            and receipt.get('signatureUrl') == asset_url(tag, 'distribution-manifest.json.asc'),
            'Public musl identity or immutable source URL differs')
    require(re.fullmatch(r'[a-f0-9]{64}', receipt.get('manifestSha256', '')),
            'An exact musl publication manifest SHA256 is required')
    assets = receipt.get('assets')
    require(isinstance(assets, list) and assets and all(isinstance(item, dict) for item in assets),
            'Musl receipt asset descriptors are absent')
    indexed = {item.get('name'): item for item in assets}
    require(len(indexed) == len(assets) and all(isinstance(name, str) and item.get('url') == asset_url(tag, name)
            for name, item in indexed.items()), 'Duplicate or redirected musl receipt asset')
    manifest_raw = bound_bytes(receipt['manifestUrl'], fetch, item=indexed.get('distribution-manifest.json'),
                               sha256=receipt.get('manifestSha256'))
    signature = bound_bytes(receipt['signatureUrl'], fetch, item=indexed.get('distribution-manifest.json.asc'),
                            maximum=MAX_SIGNATURE_BYTES)
    verification = receipt.get('verification', {})
    verification_tag = f'verification-musl-sdk-{version}-r{revision}'
    require(verification.get('manifestUrl') == asset_url(verification_tag, 'verification-manifest.json')
            and verification.get('signatureUrl') == asset_url(verification_tag, 'verification-manifest.json.asc')
            and re.fullmatch(r'[a-f0-9]{64}', verification.get('manifestSha256', '')),
            'A separate immutable signed public-verification manifest is required')
    verification_raw = bound_bytes(verification['manifestUrl'], fetch, sha256=verification.get('manifestSha256'))
    verification_signature = bound_bytes(verification['signatureUrl'], fetch, maximum=MAX_SIGNATURE_BYTES)
    manifest, verified = decoded(manifest_raw), decoded(verification_raw)
    reports = receipt.get('postVerification', {}).get('reports', [])
    require(isinstance(reports, list) and len(reports) == 2
            and {row.get('architecture') for row in reports} == set(ARCHITECTURES),
            'Both native public musl report descriptors are required')
    raw_reports = {}
    for row in reports:
        item = row.get('report', {})
        require(item.get('url') == asset_url(verification_tag, item.get('name'))
                and row.get('rawJsonSize') == item.get('size') and row.get('rawJsonSha256') == item.get('sha256'),
                'Public musl report bytes are not bound to the immutable verification tag')
        raw = bound_bytes(item['url'], fetch, item=item)
        require(isinstance(decoded(raw), dict), 'Public musl report is not an object')
        raw_reports[row['architecture']] = raw
    entries = verified.get('entries') if isinstance(verified, dict) else None
    expected = {key: value for key, value in receipt.items() if key != 'verification'}
    require(isinstance(verified, dict) and verified.get('repository') == REPOSITORY and isinstance(entries, list)
            and sum(entry == expected for entry in entries) == 1,
            'Signed public verification manifest does not bind this exact receipt and reports')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-musl-site-') as temporary:
        temporary = Path(temporary)
        if keyring is None:
            keyring = temporary / 'trusted.gpg'
            subprocess.run(['gpg', '--batch', '--yes', '--dearmor', '--output', str(keyring),
                            str(ROOT / 'releases/downstream-signing-key.asc')], check=True, capture_output=True)
        for name, raw, detached, expected_fingerprint in (
            ('distribution-manifest.json', manifest_raw, signature, receipt.get('signingFingerprint')),
            ('verification-manifest.json', verification_raw, verification_signature, verification.get('signingFingerprint'))):
            path = temporary / name
            path.write_bytes(raw)
            signature_path = temporary / (name + '.asc')
            signature_path.write_bytes(detached)
            require(verify_publication_signature(path, signature_path, keyring) == expected_fingerprint,
                    'Musl receipt signer differs from actual independently verified GPG signer')
        validate_publication_metadata(manifest, receipt, raw_reports, verification_manifest=verified)
        signed_assets = {item['name']: item for item in manifest['assets']}
        for record in manifest['records']:
            name = record['qualificationReportAsset']
            item = dict(signed_assets[name], url=asset_url(tag, name))
            require(isinstance(decoded(bound_bytes(item['url'], fetch, item=item)), dict),
                    'Published prepublication musl report is not an object')
    return manifest


def public_rows(status=None, *, authenticator=None):
    status = status if status is not None else load_status()
    require(status.get('schemaVersion') == 1 and status.get('kind') == 'musl-distribution-availability'
            and status.get('repository') == REPOSITORY and status.get('libc') == 'musl'
            and status.get('installerAdmission') == 'separate-issue-30', 'Invalid separate musl status source')
    publications = status.get('publications')
    require(isinstance(publications, list), 'Invalid musl publication history')
    if status.get('status') == 'not-published':
        require(not publications, 'Unpublished musl status must not advertise candidate assets')
        return []
    require(status.get('status') == 'published-postverified' and publications, 'Unsupported musl availability state')
    authenticator = authenticator or authenticate_receipt
    seen, latest = set(), {}
    for receipt in publications:
        identity = receipt.get('identity', {})
        version, revision, channel = identity.get('sdkVersion'), identity.get('packageRevision'), identity.get('channel')
        version_revision(version, revision)
        key = (version, revision, channel)
        require(channel in CHANNELS and identity.get('libc') == 'musl' and key not in seen,
                'Duplicate or ambiguous musl availability identity')
        seen.add(key)
        manifest = authenticator(receipt)
        require(manifest.get('identity') == identity and manifest.get('tag') == receipt.get('tag'),
                'Musl authenticated manifest differs from availability identity')
        records = manifest.get('records', [])
        require(len(records) == 2 and {row.get('architecture') for row in records} == set(ARCHITECTURES)
                and all(row.get('targetRid') == ARCHITECTURES[row['architecture']]['rid'] for row in records),
                'Musl availability requires the complete two-CPU RID matrix')
        source_key = (version, channel)
        if source_key not in latest or revision > latest[source_key]['identity']['packageRevision']:
            latest[source_key] = dict(identity=copy.deepcopy(identity), tag=receipt['tag'], releaseUrl=receipt['releaseUrl'],
                manifestUrl=receipt['manifestUrl'], signatureUrl=receipt['signatureUrl'], manifestSha256=receipt['manifestSha256'],
                signingFingerprint=receipt['signingFingerprint'], verification=copy.deepcopy(receipt['verification']),
                assets=copy.deepcopy(receipt['assets']), records=copy.deepcopy(records),
                **({'ociIndex': copy.deepcopy(manifest['ociIndex'])} if 'ociIndex' in manifest else {}))
    return [latest[key] for key in sorted(latest, key=lambda item: (tuple(map(int, item[0].split('.'))), item[1]), reverse=True)]


def render(rows):
    if not rows:
        return ''
    escape = html.escape
    sections = []
    for row in rows:
        identity = row['identity']
        channel = identity['channel']
        assets = {item['name']: item for item in row['assets']}
        links = []
        for record in row['records']:
            label = 'Alpine x64' if record['architecture'] == 'x64' else 'Alpine AArch64'
            if channel == 'archive':
                item = assets[record['artifactAsset']]
                links.append('<a class="download-button" href="' + escape(item['url'], quote=True) + '">' + label + '</a>')
            elif channel == 'apk':
                repository = record.get('repository', {})
                expected_repository = (f'https://github.com/{REPOSITORY}/releases/download/musl-apk-repo-'
                    + identity['sdkVersion'] + '-alpine324-' + record['architecture'] + '-r' + str(identity['packageRevision']) + '/')
                require(repository.get('url') == expected_repository,
                        'Verified APK repository URL is absent')
                links.append('<a class="download-button" href="' + escape(repository['url'] + 'APKINDEX.tar.gz', quote=True)
                    + '">' + label + ' APK repository index</a>')
        if channel == 'oci':
            index = row.get('ociIndex', {})
            require(index.get('repository') == 'ghcr.io/' + REPOSITORY + '-sdk'
                    and re.fullmatch(r'sha256:[a-f0-9]{64}', index.get('digest', '')),
                    'Verified musl OCI index digest is absent')
            links.append('<pre><code>docker pull ' + escape(index['repository'] + '@' + index['digest']) + '</code></pre>')
        title = {'archive': 'SDK archives', 'apk': 'Signed APK repositories', 'oci': 'Alpine OCI image'}[channel]
        sections.append('<div class="archive-verification"><h3>' + escape(identity['sdkVersion']) + ' · ' + title + '</h3>'
            + '<div class="download-buttons">' + ''.join(links) + '</div><p class="link-list">'
            + '<a href="' + escape(row['manifestUrl'], quote=True) + '">Manifest</a>'
            + '<a href="' + escape(row['signatureUrl'], quote=True) + '">Signature</a>'
            + '<a href="' + escape(row['verification']['manifestUrl'], quote=True) + '">Public verification</a>'
            + '</p></div>')
    return ('<section id="alpine" class="panel" aria-labelledby="alpine-title">'
        '<div class="section-heading"><p class="eyebrow">Native musl Linux</p>'
        '<h2 id="alpine-title">Alpine Linux</h2></div>'
        '<p class="section-description">SDKs independently verified on Alpine 3.24.4 for x64 and AArch64. '
        'Choose the musl archive, signed APK repository or explicit Alpine container variant. '
        '<a href="https://github.com/' + REPOSITORY + '/blob/main/docs/alpine-musl.md">Alpine installation guide</a>. '
        'NativeAOT, workloads and cbodotnetup support require separate qualification.</p>'
        '<div class="verification-grid">' + ''.join(sections) + '</div></section>')


def prepare(output=None, *, status=None, fetch=None, keyring=None, authenticator=None):
    if authenticator is None:
        authenticator = lambda receipt: authenticate_receipt(receipt, fetch=fetch, keyring=keyring)
    rows = public_rows(status, authenticator=authenticator)
    feed = dict(schemaVersion=1, kind='musl-download-catalog', repository=REPOSITORY, libc='musl',
        status='published-postverified' if rows else 'not-published', installerAdmission='separate-issue-30', publications=rows)
    if output is not None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / 'musl-status.json').write_text(json.dumps(feed, indent=2) + '\n', encoding='utf-8')
    return render(rows), feed
