"""Keep multi-SDK APT pools on immutable Release assets rather than Pages."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import time

from channel_packages import deterministic_tar, SOURCE_DATE_EPOCH
from downstream_release import descriptor, encoded, require
from downstream_publish import GitHubReleases, verify_remote_assets, validate_bundle

REPOSITORY = 'dotnetdev-kr/cbodotnet'


def release_tag(variant, sdk, revision):
    require(variant in {'ubuntu-24.04', 'debian-13'}
            and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', sdk)
            and type(revision) is int and revision > 0, 'Invalid flat APT repository identity')
    return f'repository-deb-{variant}-sdk-{sdk}-r{revision}'


def repository_url(variant, sdk, revision):
    return f'https://github.com/{REPOSITORY}/releases/download/{release_tag(variant, sdk, revision)}/'


def flat_asset_descriptors(archive):
    """Bind individual asset names and bytes to the signed enclosing tar archive."""
    rows = {}
    with tarfile.open(archive, 'r:gz') as incoming:
        for member in incoming:
            if member.isdir() and member.name in {'.', './'}:
                continue
            name = member.name.removeprefix('./')
            require(member.isfile() and re.fullmatch(r'[A-Za-z0-9._+-]+', name)
                    and name not in rows and 0 < member.size < 2**31 and not member.mode & 0o7000,
                    'Unsafe flat APT release archive member')
            digest = hashlib.sha256()
            with incoming.extractfile(member) as stream:
                for block in iter(lambda: stream.read(4 * 1024**2), b''):
                    digest.update(block)
            rows[name] = dict(name=name, size=member.size, sha256=digest.hexdigest())
    require(rows and len(rows) <= 32, 'Unexpected flat APT asset count')
    return [rows[name] for name in sorted(rows)]


def prepare_flat_repositories(root, signing_key, keyring):
    """Reindex verified native packages before the enclosing bundle is frozen."""
    root = Path(root)
    build = json.loads((root / 'repository-build.json').read_bytes())
    require(build['channel'] == 'deb', 'Only APT repositories have a flat Release adapter')
    for archive in build['archives']:
        variant = archive['variant']
        directory = root / variant
        manifest_path = directory / 'repository-manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        tag = release_tag(variant, build['sdkVersion'], build['packageRevision'])
        require(manifest['sdkVersion'] == build['sdkVersion']
                and manifest['packageRevision'] == build['packageRevision']
                and manifest['variant'] == variant and manifest['channel'] == 'deb',
                'APT repository source identity differs')
        pool = directory / 'pool'
        for path in pool.iterdir():
            require(path.is_file() and not path.is_symlink() and path.suffix == '.deb'
                    and manifest['packages'].get(path.name) == descriptor(path)['sha256'],
                    'Flat APT package differs from its verified native build')
            require(not (directory / path.name).exists(), 'Conflicting flat APT package identity')
            path.rename(directory / path.name)
        pool.rmdir()
        for name in ('Packages', 'Packages.gz', 'Release', 'Release.gpg', 'InRelease'):
            (directory / name).unlink()
        indexes = subprocess.check_output(['apt-ftparchive', 'packages', '.'], cwd=directory)
        (directory / 'Packages').write_bytes(indexes)
        with (directory / 'Packages.gz').open('xb') as stream:
            with gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=int(SOURCE_DATE_EPOCH)) as compressed:
                compressed.write(indexes)
        manifest.update(delivery='github-release-flat', releaseTag=tag,
                        repositoryUrl=repository_url(variant, build['sdkVersion'], build['packageRevision']))
        manifest_path.write_bytes(encoded(manifest))
        release = subprocess.check_output(['apt-ftparchive',
            '-o', 'APT::FTPArchive::Release::Origin=cbodotnet',
            '-o', 'APT::FTPArchive::Release::Label=Community Build of .NET',
            '-o', 'APT::FTPArchive::Release::Architectures=amd64 arm64 all',
            '-o', 'APT::FTPArchive::Release::Description=Community Build of .NET (built by .NET Dev)',
            'release', '.'], cwd=directory)
        (directory / 'Release').write_bytes(release)
        for option, name in [('--clearsign', 'InRelease'), ('--detach-sign', 'Release.gpg')]:
            subprocess.run(['gpg', '--batch', '--yes', '--armor', '--local-user', signing_key,
                '--digest-algo', 'SHA256', '--output', str(directory / name), option, str(directory / 'Release')], check=True)
        subprocess.run(['gpgv', '--keyring', str(keyring), str(directory / 'InRelease')], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        path = root / archive['path']
        path.unlink()
        replacement = deterministic_tar(directory, path)
        archive.update(replacement)
    (root / 'repository-build.json').write_bytes(encoded(build))
    return build


class FlatReleases(GitHubReleases):
    def create(self, manifest):
        require(self.api(f'repos/{REPOSITORY}/git/ref/tags/{manifest["tag"]}') is None,
                'Refusing an existing flat repository tag without its release')
        return self.api(f'repos/{REPOSITORY}/releases', 'POST', {
            'tag_name': manifest['tag'], 'target_commitish': manifest['targetCommit'],
            'name': f'cbodotnet APT {manifest["variant"]} SDK {manifest["sdkVersion"]}',
            'body': 'Immutable flat APT repository for Community Build of .NET (built by .NET Dev). '
                    'APT verifies InRelease with the independently trusted project key. '
                    'The enclosing signed distribution manifest binds every file and the complete native installation matrix: '
                    + manifest['parentManifestUrl'],
            'draft': True, 'prerelease': False, 'make_latest': 'false'})


def publish_flat_repositories(bundle, keyring, transport=None):
    """Only publish files authenticated by a complete frozen parent distribution."""
    bundle = Path(bundle)
    parent = validate_bundle(bundle, keyring)
    require(parent['identity']['channel'] == 'deb', 'Flat APT requires a signed DEB parent')
    from distribution_site import extract_repository
    transport = transport or FlatReleases()
    receipts = []
    for row in parent['repositories']:
        if row.get('delivery') != 'github-release-flat':
            continue
        require(row['kind'] == 'apt-repository' and len(row['variants']) == 1, 'Ambiguous flat APT target')
        variant = row['variants'][0]
        identity = parent['identity']
        tag = release_tag(variant, identity['sdkVersion'], identity['packageRevision'])
        require(row['releaseTag'] == tag, 'Flat repository tag differs from signed parent')
        with tempfile.TemporaryDirectory(prefix='cbodotnet-flat-apt-') as temporary:
            directory = Path(temporary) / 'repository'
            extract_repository(bundle / row['asset'], directory)
            expected = {}
            for path in directory.iterdir():
                require(path.is_file() and not path.is_symlink()
                        and re.fullmatch(r'[A-Za-z0-9._+-]+', path.name), 'Unsafe flat repository asset')
                expected[path.name] = descriptor(path)
            require(row.get('flatAssets') == [expected[name] for name in sorted(expected)],
                    'Flat repository files differ from signed individual asset bindings')
            require({'Packages', 'Packages.gz', 'Release', 'InRelease', 'Release.gpg',
                     'repository-manifest.json', 'cbodotnet-archive-keyring.gpg'} <= set(expected),
                    'Incomplete signed flat repository')
            repository = json.loads((directory / 'repository-manifest.json').read_bytes())
            require(repository.get('releaseTag') == tag and repository.get('delivery') == 'github-release-flat'
                    and repository.get('sourceManifestSha256') == identity['sourceManifestSha256'],
                    'Flat repository content identity differs from signed parent')
            manifest = dict(tag=tag, targetCommit=parent['targetCommit'], variant=variant,
                sdkVersion=identity['sdkVersion'], parentManifestUrl=
                f'https://github.com/{REPOSITORY}/releases/download/{parent["tag"]}/distribution-manifest.json')
            release = transport.find(tag) or transport.create(manifest)
            require(release.get('tag_name') == tag and release.get('target_commitish') == parent['targetCommit']
                    and release.get('prerelease') is False, 'Unrelated flat repository release already exists')
            remote = {asset['name']: asset for asset in release.get('assets', [])}
            require(set(remote) <= set(expected), 'Unexpected existing flat repository asset')
            for name, asset in remote.items():
                require(asset['size'] == expected[name]['size']
                        and asset.get('digest') in (None, 'sha256:' + expected[name]['sha256']),
                        'Refusing changed existing flat repository bytes')
            missing = set(expected) - set(remote)
            require(not missing or release['draft'], 'Incomplete public flat repository cannot be repaired in place')
            for name in sorted(missing):
                transport.upload(release, directory / name)
            for attempt in range(4):
                release = transport.get(release)
                if {asset['name'] for asset in release.get('assets', [])} == set(expected):
                    break
                require(attempt < 3, 'Flat repository upload did not become readable')
                time.sleep(2 ** attempt)
            verify_remote_assets(release, expected, transport)
            if release['draft']:
                release = transport.publish(release)
            release = transport.get(release)
            require(not release['draft'], 'Flat repository did not become public')
            verify_remote_assets(release, expected, transport, public=True)
            receipts.append(dict(tag=tag, variant=variant, repositoryUrl=repository_url(variant,
                identity['sdkVersion'], identity['packageRevision']), assets=list(expected.values())))
    return receipts
