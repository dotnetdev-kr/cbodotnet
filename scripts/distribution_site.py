"""Render only signed, post-verified downstream publication records on Pages."""
import hashlib
import html
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from distribution_contract import load_contract
from downstream_release import verify_report_signature
from downstream_publish import publication_rows, release_tag

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'


def require(value, message):
    if not value:
        raise ValueError(message)


def download(url, target, maximum, expected=None):
    require(isinstance(url, str) and url.startswith(f'https://github.com/{REPOSITORY}/releases/download/distribution-'),
            'Untrusted distribution asset URL')
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(url, timeout=60) as incoming, Path(target).open('xb') as output:
        for block in iter(lambda: incoming.read(4 * 1024**2), b''):
            count += len(block)
            require(count <= maximum, 'Distribution download exceeds its size bound')
            digest.update(block)
            output.write(block)
    if expected:
        require(count == expected['size'] and digest.hexdigest() == expected['sha256'],
                'Distribution asset digest mismatch')
    return digest.hexdigest()


def extract_repository(archive_path, destination):
    require(not destination.exists() and destination.parent.is_dir(), 'Fresh repository destination required')
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries = archive.getmembers()
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.name)
            require(str(path) == entry.name and not path.is_absolute() and '..' not in path.parts
                    and entry.name not in names and not any(c in entry.name for c in '\\:\0\r\n')
                    and (entry.isfile() or entry.isdir()) and not entry.mode & 0o7000,
                    'Unsafe repository archive member')
            names.add(entry.name)
        members = {entry.name: entry for entry in entries}
        for entry in entries:
            require(all(str(parent) not in members or members[str(parent)].isdir()
                        for parent in PurePosixPath(entry.name).parents), 'Non-directory repository archive parent')
        require(len(entries) <= 200000 and sum(entry.size for entry in entries) + 256 * 1024**2
                < shutil.disk_usage(destination.parent).free, 'Insufficient repository extraction capacity')
        destination.mkdir()
        for entry in entries:
            path = destination / entry.name
            path.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                path.mkdir(exist_ok=True)
            else:
                with archive.extractfile(entry) as incoming, path.open('xb') as output:
                    shutil.copyfileobj(incoming, output)
            path.chmod(0o755 if entry.isdir() else 0o644)


def prepare_site(policy, output, public_key=None):
    """Authenticate manifests before serving package repositories or image commands."""
    require(policy.get('schemaVersion') == 1 and policy.get('repository') == REPOSITORY
            and set(policy.get('channels', {})) == {'deb', 'rpm', 'oci', 'aur'}, 'Invalid downstream status')
    output = Path(output)
    for configuration in policy['channels'].values():
        state = configuration.get('status')
        require(state in {'published', 'not-published', 'deferred'}, 'Invalid downstream channel state')
        if state == 'published':
            require(configuration.get('publications') and configuration.get('receipts'),
                    'Published channels require verified publication adapters and receipts')
    output.mkdir(parents=True, exist_ok=True)
    status = {'schemaVersion': 1, 'repository': REPOSITORY, 'status': policy['status'], 'channels': {}}
    contract = load_contract()
    public_key = Path(public_key or ROOT / 'releases/downstream-signing-key.asc')
    for channel, configuration in policy['channels'].items():
        state = configuration.get('status')
        publications = configuration.get('publications', [])
        if state in {'not-published', 'deferred'}:
            require(publications == [], 'Unpublished channel advertises publications')
            status['channels'][channel] = {'status': state, 'publications': []}
            continue
        require(state == 'published' and publications and configuration.get('receipts'),
                'Published channels require verified publication adapters and receipts')
        verified_publications = []
        hosted_variants = set()
        receipts = sorted(configuration['receipts'], key=lambda row: (
            tuple(int(part) for part in row['identity']['sdkVersion'].split('.')), row['identity']['packageRevision']), reverse=True)
        for receipt in receipts:
            require(receipt.get('status') == 'published-postverified' and receipt.get('repository') == REPOSITORY
                    and receipt['identity']['channel'] == channel, 'Invalid public distribution receipt')
            identity = receipt['identity']
            tag = release_tag(channel, identity['sdkVersion'], identity['packageRevision'])
            base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
            require(receipt.get('tag') == tag and receipt['manifestUrl'] == base + 'distribution-manifest.json'
                    and receipt['signatureUrl'] == base + 'distribution-manifest.json.asc', 'Noncanonical distribution receipt URL')
            with tempfile.TemporaryDirectory(prefix='cbodotnet-pages-') as temporary:
                temporary = Path(temporary)
                keyring = temporary / 'keyring.gpg'
                subprocess.run(['gpg', '--batch', '--yes', '--dearmor', '--output', str(keyring), str(public_key)],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                manifest_path, signature = temporary / 'manifest.json', temporary / 'manifest.asc'
                observed = download(receipt['manifestUrl'], manifest_path, 16 * 1024**2)
                require(observed == receipt['manifestSha256'], 'Pinned distribution manifest changed')
                download(receipt['signatureUrl'], signature, 1024**2)
                manifest = json.loads(manifest_path.read_bytes())
                require(manifest.get('schemaVersion') == 1 and manifest.get('repository') == REPOSITORY
                        and manifest.get('identity') == receipt['identity'] and manifest.get('tag') == tag
                        and manifest.get('contractVersion') == contract['schemaVersion']
                        and manifest.get('status') == 'validated-complete-matrix',
                        'Distribution manifest identity mismatch')
                signer = verify_report_signature(manifest_path, signature, keyring, policy,
                                                   '.github/workflows/distribution-release.yml', historical=True)
                require(signer == receipt['signingFingerprint'] == manifest['signingFingerprint'], 'Distribution signer mismatch')
                identity = manifest['identity']
                require(contract['releases'].get(identity['sdkVersion'], {}).get('manifestSha256')
                        == identity['sourceManifestSha256'], 'Distribution source is not admitted')
                expected = {(row['variant'], row['architecture']) for row in configuration['candidateMatrix']}
                actual = [(row['record']['identity']['variant'], row['record']['architecture']) for row in manifest['records']]
                require(len(set(actual)) == len(actual) and set(actual) == expected, 'Distribution matrix is incomplete')
                assets = {row['name']: row for row in manifest['assets']}
                require(len(assets) == len(manifest['assets']), 'Duplicate signed asset names')
                expected_assets = dict(assets)
                for name, path in [('distribution-manifest.json', manifest_path), ('distribution-manifest.json.asc', signature)]:
                    expected_assets[name] = {'name': name, 'size': path.stat().st_size,
                                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                observed_assets = {row['name']: {key: row[key] for key in ('name', 'size', 'sha256')}
                                   for row in receipt['assets']}
                require(len(observed_assets) == len(receipt['assets']) and observed_assets == expected_assets
                        and all(row['url'] == base + row['name'] for row in receipt['assets']),
                        'Receipt assets differ from signed publication bytes')
                require(receipt['publications'] == publication_rows(manifest, observed, base),
                        'Receipt publications are not derived from signed records')
                for repository in manifest.get('repositories', []):
                    name = repository['asset']
                    require(re.fullmatch(r'[A-Za-z0-9._+-]+', name) and name in assets, 'Invalid signed repository asset')
                    if repository['kind'] == 'apt-repository':
                        require(channel == 'deb' and len(repository['variants']) == 1, 'Ambiguous APT repository variant')
                        variant = repository['variants'][0]
                        require(variant in contract['channels']['deb']['variants']
                                and name == 'apt-' + variant + '.tar.gz', 'Unverified APT variant')
                        if variant in hosted_variants:
                            continue
                        archive = temporary / name
                        download(base + name, archive, 2**31 - 1, assets[name])
                        parent = output / 'packages/deb'
                        parent.mkdir(parents=True, exist_ok=True)
                        destination = parent / variant
                        extract_repository(archive, destination)
                        subprocess.run(['gpgv', '--keyring', str(keyring), str(destination / 'Release.gpg'),
                                        str(destination / 'Release')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        subprocess.run(['gpgv', '--keyring', str(keyring), str(destination / 'InRelease')],
                                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        hosted_variants.add(variant)
                    elif repository['kind'] == 'oci-descriptor':
                        require(channel == 'oci', 'OCI descriptor in another channel')
                        descriptor = temporary / name
                        download(base + name, descriptor, 1024**2, assets[name])
                        image = json.loads(descriptor.read_bytes())
                        require(image.get('repository') == 'ghcr.io/dotnetdev-kr/cbodotnet-sdk'
                                and re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('digest', '')),
                                'Invalid pinned OCI descriptor')
                        status['channels'].setdefault(channel, {}).setdefault('image', image)
                verified_publications.extend(receipt['publications'])
        require(sorted(verified_publications, key=lambda row: json.dumps(row, sort_keys=True))
                == sorted(publications, key=lambda row: json.dumps(row, sort_keys=True)),
                'Status publications differ from verified receipts')
        status['channels'].setdefault(channel, {}).update(status='published', publications=verified_publications)
    if any(row['status'] == 'published' for row in status['channels'].values()):
        shutil.copyfile(public_key, output / 'distribution-signing-key.asc')
        subprocess.run(['gpg', '--batch', '--yes', '--dearmor', '--output', str(output / 'cbodotnet-archive-keyring.gpg'), str(public_key)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return status


def render_channels(status):
    rows = []
    for channel, data in status.get('channels', {}).items():
        if data.get('status') != 'published':
            continue
        if channel == 'deb':
            for variant in sorted({row['variant'] for row in data['publications']}):
                command = ('curl -fsSLo /tmp/cbodotnet-archive-keyring.gpg https://dotnetdev.kr/cbodotnet/cbodotnet-archive-keyring.gpg\n'
                           'sudo install -m 0644 /tmp/cbodotnet-archive-keyring.gpg /usr/share/keyrings/cbodotnet-archive-keyring.gpg\n'
                           "echo 'deb [signed-by=/usr/share/keyrings/cbodotnet-archive-keyring.gpg] https://dotnetdev.kr/cbodotnet/packages/deb/" + variant +
                           " ./' | sudo tee /etc/apt/sources.list.d/cbodotnet.list\nsudo apt-get update\nsudo apt-get install cbodotnet-sdk-10.0\ncbodotnet --info")
                rows.append('<h3>' + html.escape(variant) + ' APT</h3><pre><code>' + html.escape(command) + '</code></pre>')
        if channel == 'oci' and data.get('image'):
            image = data['image']['repository'] + '@' + data['image']['digest']
            command = 'docker pull ' + image + '\ndocker run --rm ' + image + ' cbodotnet --info'
            rows.append('<h3>OCI SDK image</h3><pre><code>' + html.escape(command) + '</code></pre>')
    if not rows:
        return '<p>APT, RPM, AUR and consumer OCI channels are in preparation. Use the verified archive downloads above.</p>'
    rows.insert(0, '<p>Project-operated distribution channels. Verify the signing fingerprint using the '
                '<a href="https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/distribution-signing.md">signing policy</a> before trusting a key. '
                'RPM and AUR remain deferred until their own target qualification.</p>')
    return '\n'.join(rows)
