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
from rpm_repository import asset_base as rpm_asset_base, verify_repository as verify_rpm_repository

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'


def require(value, message):
    if not value:
        raise ValueError(message)


def download(url, target, maximum, expected=None):
    require(isinstance(url, str) and any(url.startswith(f'https://github.com/{REPOSITORY}/releases/download/' + prefix)
                                       for prefix in ('distribution-', 'repository-deb-')),
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
                        if repository.get('delivery') == 'github-release-flat':
                            from apt_release import release_tag as flat_tag, repository_url
                            expected_tag = flat_tag(variant, identity['sdkVersion'], identity['packageRevision'])
                            require(repository.get('releaseTag') == expected_tag, 'Unverified flat APT repository tag')
                            flat_base = repository_url(variant, identity['sdkVersion'], identity['packageRevision'])
                            flat_assets = {row['name']: row for row in repository.get('flatAssets', [])}
                            require(len(flat_assets) == len(repository.get('flatAssets', []))
                                    and {'InRelease', 'Release', 'Release.gpg', 'Packages', 'Packages.gz',
                                         'repository-manifest.json', 'cbodotnet-archive-keyring.gpg'} <= set(flat_assets),
                                    'Incomplete signed flat APT asset map')
                            metadata = temporary / expected_tag
                            metadata.mkdir()
                            for filename, asset in flat_assets.items():
                                require(re.fullmatch(r'[A-Za-z0-9._+-]+', filename), 'Unsafe flat APT asset name')
                                if filename.endswith('.deb'):
                                    continue
                                download(flat_base + filename, metadata / filename, 16 * 1024**2, asset)
                            subprocess.run(['gpgv', '--keyring', str(keyring), str(metadata / 'InRelease')],
                                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            subprocess.run(['gpgv', '--keyring', str(keyring), str(metadata / 'Release.gpg'),
                                            str(metadata / 'Release')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            from published_apt import verify_packages_index
                            verify_packages_index((metadata / 'Release').read_text(), (metadata / 'Packages').read_bytes())
                            status['channels'].setdefault(channel, {}).setdefault('repositories', []).append(dict(
                                variant=variant, sdkVersion=identity['sdkVersion'], packageRevision=identity['packageRevision'],
                                repositoryUrl=flat_base, delivery='github-release-flat'))
                            # Retain the original SDK10 APT URL for installed clients,
                            # serving only its latest revision within the Pages budget.
                            if identity['sdkVersion'].startswith('10.0.') and variant not in hosted_variants:
                                archive = temporary / name
                                download(base + name, archive, 2**31 - 1, assets[name])
                                parent = output / 'packages/deb'
                                parent.mkdir(parents=True, exist_ok=True)
                                extract_repository(archive, parent / variant)
                                hosted_variants.add(variant)
                            continue
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
                        status['channels'].setdefault(channel, {}).setdefault('repositories', []).append(dict(
                            variant=variant, sdkVersion=identity['sdkVersion'], packageRevision=identity['packageRevision'],
                            repositoryUrl='https://dotnetdev.kr/cbodotnet/packages/deb/' + variant + '/'))
                    elif repository['kind'] == 'rpm-repository':
                        require(channel == 'rpm' and len(repository['variants']) == 1, 'Ambiguous RPM repository variant')
                        variant = repository['variants'][0]
                        require(variant in contract['channels']['rpm']['variants'] and name == 'rpm-' + variant + '.tar.gz',
                                'Unverified RPM variant')
                        target_key = (variant, identity['sdkVersion'], identity['packageRevision'])
                        if target_key in hosted_variants:
                            continue
                        archive = temporary / name
                        download(base + name, archive, 64 * 1024**2, assets[name])
                        parent = output / 'packages/rpm'
                        parent.mkdir(parents=True, exist_ok=True)
                        versioned = 'sdk-' + identity['sdkVersion'] + '-r' + str(identity['packageRevision'])
                        destination = parent / variant / versioned
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        extract_repository(archive, destination)
                        require(not list(destination.rglob('*.rpm')), 'RPM packages must use immutable Release asset URLs')
                        repository_identity = verify_rpm_repository(destination, keyring, assets,
                                              rpm_asset_base(identity['sdkVersion'], identity['packageRevision']))
                        require(repository_identity.get('variant') == variant
                                and repository_identity.get('sourceManifestSha256') == identity['sourceManifestSha256']
                                and repository_identity.get('signingFingerprint') == signer,
                                'RPM repository identity differs from its signed publication and hosted variant')
                        hosted_variants.add(target_key)
                        status['channels'].setdefault(channel, {}).setdefault('repositories', []).append(dict(
                            variant=variant, sdkVersion=identity['sdkVersion'], packageRevision=identity['packageRevision'],
                            repositoryUrl='https://dotnetdev.kr/cbodotnet/packages/rpm/' + variant + '/' + versioned + '/'))
                        if variant not in hosted_variants:
                            alias = parent / variant
                            for path in destination.iterdir():
                                if path.is_dir():
                                    shutil.copytree(path, alias / path.name)
                                else:
                                    shutil.copyfile(path, alias / path.name)
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
                        images = status['channels'][channel].setdefault('images', [])
                        if not any(row['sdkVersion'] == identity['sdkVersion'] for row in images):
                            images.append(dict(sdkVersion=identity['sdkVersion'], packageRevision=identity['packageRevision'], **image))
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
    packages, containers = [], []
    labels = {'ubuntu-24.04': 'Ubuntu 24.04', 'debian-13': 'Debian 13',
              'fedora-45': 'Fedora 45', 'rocky-9.8': 'Rocky Linux 9.8'}
    for channel, data in status.get('channels', {}).items():
        if data.get('status') != 'published':
            continue
        if channel == 'deb':
            for variant in sorted({row['variant'] for row in data['publications']}):
                current = max((row for row in data['publications'] if row['variant'] == variant),
                              key=lambda row: (tuple(map(int, row['sdkVersion'].split('.'))), row['packageRevision']))
                package = 'cbodotnet-sdk-' + '.'.join(current['sdkVersion'].split('.')[:2])
                version = current['sdkVersion'] + '-' + str(current['packageRevision'])
                repositories = {}
                for repository in data.get('repositories', []):
                    if repository['variant'] != variant:
                        continue
                    previous = repositories.get(repository['sdkVersion'])
                    if previous is None or previous['packageRevision'] < repository['packageRevision']:
                        repositories[repository['sdkVersion']] = repository
                urls = ' '.join(row['repositoryUrl'] for _, row in sorted(repositories.items(),
                                key=lambda item: tuple(map(int, item[0].split('.'))), reverse=True))
                urls = urls or 'https://dotnetdev.kr/cbodotnet/packages/deb/' + variant + '/'
                command = ('sudo apt-get update\nsudo apt-get install -y ca-certificates curl gnupg\n'
                           'curl -fsSLo /tmp/cbodotnet-archive-keyring.gpg https://dotnetdev.kr/cbodotnet/cbodotnet-archive-keyring.gpg\n'
                           'test "$(gpg --show-keys --with-colons /tmp/cbodotnet-archive-keyring.gpg | '
                           "awk -F: '$1==\"pub\" {primary=1} $1==\"fpr\" && primary {print $10; primary=0}')\" = D7D154B4B33C19A82B95B13688135410ACD9C0EA || exit 1\n"
                           'sudo install -m 0644 /tmp/cbodotnet-archive-keyring.gpg /usr/share/keyrings/cbodotnet-archive-keyring.gpg\n'
                           'sudo rm -f /etc/apt/sources.list.d/cbodotnet.list\n'
                           'sudo tee /etc/apt/sources.list.d/cbodotnet.sources > /dev/null <<EOF\n'
                           'Types: deb\nURIs: ' + urls + '\n'
                           'Suites: ./\nArchitectures: $(dpkg --print-architecture)\n'
                           'Signed-By: /usr/share/keyrings/cbodotnet-archive-keyring.gpg\nEOF\n'
                           'sudo apt-get update\nsudo apt-get install ' + package + '=' + version + '\ncbodotnet --info')
                available_packages = sorted({'cbodotnet-sdk-' + '.'.join(row['sdkVersion'].split('.')[:2])
                                   for row in data['publications'] if row['variant'] == variant},
                                  key=lambda value: tuple(map(int, value.removeprefix('cbodotnet-sdk-').split('.'))), reverse=True)
                available = '<p class="available-packages">Available SDK packages: ' + ', '.join(
                    '<code>' + html.escape(name) + '</code>' for name in available_packages) + '.</p>'
                packages.append('<details class="install-details"><summary><span>' + html.escape(labels.get(variant, variant))
                    + '</span><span class="method-label">APT</span></summary><div class="details-content">'
                    + available + '<pre><code>' + html.escape(command) + '</code></pre></div></details>')
        if channel == 'oci' and data.get('image'):
            for record in sorted(data.get('images', [data['image']]),
                                 key=lambda row: tuple(map(int, row.get('sdkVersion', '0').split('.'))), reverse=True):
                image = record['repository'] + '@' + record['digest']
                command = 'docker pull ' + image + '\ndocker run --rm ' + image + ' cbodotnet --info'
                label = 'SDK ' + record['sdkVersion'] if record.get('sdkVersion') else 'SDK image'
                containers.append('<details class="install-details"><summary><span>' + html.escape(label)
                    + '</span><span class="method-label">OCI</span></summary><div class="details-content">'
                    + '<p>Pull the verified multi-architecture image by its immutable digest.</p><pre><code>'
                    + html.escape(command) + '</code></pre></div></details>')
        if channel == 'rpm':
            for variant in sorted({row['variant'] for row in data['publications']}):
                repositories = {}
                for repository in data.get('repositories', []):
                    if repository['variant'] != variant:
                        continue
                    previous = repositories.get(repository['sdkVersion'])
                    if previous is None or previous['packageRevision'] < repository['packageRevision']:
                        repositories[repository['sdkVersion']] = repository
                if not repositories:
                    repositories['10.0.403'] = dict(repositoryUrl='https://dotnetdev.kr/cbodotnet/packages/rpm/' + variant + '/')
                sections = []
                for version, repository in sorted(repositories.items(), key=lambda item: tuple(map(int, item[0].split('.'))), reverse=True):
                    sections.append('[cbodotnet-sdk-' + '.'.join(version.split('.')[:2]) + ']\nname=Community Build of .NET SDK\n'
                        + 'baseurl=' + repository['repositoryUrl'] + '\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n'
                        + 'gpgkey=https://dotnetdev.kr/cbodotnet/distribution-signing-key.asc\n')
                preferred = max(repositories, key=lambda value: tuple(map(int, value.split('.'))))
                command = ('sudo dnf install -y ca-certificates gnupg2\n'
                           'command -v curl >/dev/null || sudo dnf install -y curl\n'
                           'curl -fsSLo /tmp/cbodotnet-signing-key.asc https://dotnetdev.kr/cbodotnet/distribution-signing-key.asc\n'
                           'test "$(gpg --show-keys --with-colons /tmp/cbodotnet-signing-key.asc | '
                           "awk -F: '$1==\"pub\" {primary=1} $1==\"fpr\" && primary {print $10; primary=0}')\" = D7D154B4B33C19A82B95B13688135410ACD9C0EA || exit 1\n"
                           'sudo rpm --import /tmp/cbodotnet-signing-key.asc\n'
                           "cat <<'EOF' | sudo tee /etc/yum.repos.d/cbodotnet.repo\n"
                           + '\n'.join(sections) + 'EOF\n'
                           'sudo dnf makecache --refresh\nsudo dnf install cbodotnet-sdk-' + '.'.join(preferred.split('.')[:2]) + '\ncbodotnet --info')
                packages.append('<details class="install-details"><summary><span>' + html.escape(labels.get(variant, variant))
                    + '</span><span class="method-label">DNF</span></summary><div class="details-content">'
                    + '<pre><code>' + html.escape(command) + '</code></pre></div></details>')
    trust = ('<p class="section-description">Choose your distribution to view installation commands. Verify the project identity using the '
             '<a href="https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/distribution-signing.md">signing policy</a> before trusting a key. '
             'Only the displayed targets have passed complete channel verification.</p>')
    package_markup = '\n'.join(packages) if packages else '<p class="empty-state">Package repositories are in preparation. Use a verified SDK archive.</p>'
    container_markup = '\n'.join(containers) if containers else '<p class="empty-state">Container images are in preparation. Use a verified SDK archive.</p>'
    return ('<section id="packages" class="panel" aria-labelledby="packages-title"><div class="section-heading">'
            '<p class="eyebrow">System installation</p><h2 id="packages-title">Package repositories</h2></div>' + trust
            + '<div class="installation-list">' + package_markup + '</div></section>\n'
            + '<section id="containers" class="panel" aria-labelledby="containers-title"><div class="section-heading">'
            '<p class="eyebrow">Isolated environment</p><h2 id="containers-title">OCI containers</h2></div>'
            '<p class="section-description">Choose an SDK version. Images provide <code>cbodotnet</code>, '
            '<code>cbodotnet-X.Y</code> and <code>dotnet</code> for the same SDK.</p>'
            + '<div class="installation-list">' + container_markup + '</div></section>')
