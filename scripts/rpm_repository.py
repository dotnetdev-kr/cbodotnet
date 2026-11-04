"""Authenticate metadata-only RPM repositories bound to immutable release assets."""
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

from downstream_release import require
from legacy_compat import PACKAGE_NAME as COMPAT_NAME, VERSION as COMPAT_VERSION, required as compatibility_required

REPO = '{http://linux.duke.edu/metadata/repo}'
COMMON = '{http://linux.duke.edu/metadata/common}'
XML_BASE = '{http://www.w3.org/XML/1998/namespace}base'


def asset_base(version, revision):
    require(isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version)
            and type(revision) is int and revision > 0, 'Invalid immutable RPM release identity')
    return f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-rpm-sdk-{version}-r{revision}/'


def validate_metadata(directory, assets, base):
    """Check every metadata digest and exact public package URL/size/SHA-256."""
    directory = Path(directory)
    manifest = json.loads((directory / 'repository-manifest.json').read_bytes())
    require(manifest.get('schemaVersion') == 1 and manifest.get('channel') == 'rpm'
            and manifest.get('assetBaseUrl') == base,
            'RPM repository uses another public asset origin')
    version, revision, variant = (manifest.get(key) for key in ('sdkVersion', 'packageRevision', 'variant'))
    require(base == asset_base(version, revision)
            and isinstance(variant, str) and re.fullmatch(r'[a-z][a-z0-9]*-[1-9][0-9]*(?:\.[0-9]+)?', variant)
            and manifest.get('architectures') == ['x64', 'aarch64'], 'Invalid RPM repository matrix identity')
    packages = manifest.get('packages', {})
    legacy = compatibility_required({'sdkVersion': version})
    native_http = version.startswith(('3.0.', '3.1.'))
    require(isinstance(packages, dict) and len(packages) == (7 if native_http else 5 if legacy else 3),
            'Both RPM architectures, one common host and required separate provider architectures are required')
    series = '.'.join(version.split('.')[:2])
    release = str(revision) + '.cbot.' + variant.replace('-', '')
    identities = {}
    for public_arch, rpm_arch in (('x64', 'x86_64'), ('aarch64', 'aarch64')):
        name = f'rpm-{variant}-{public_arch}--cbodotnet-sdk-{series}-{version}-{release}.{rpm_arch}.rpm'
        identities[name] = ('cbodotnet-sdk-' + series, rpm_arch, version, release)
        if legacy:
            compat_release = '1.cbot.' + variant.replace('-', '')
            name = f'rpm-{variant}-{public_arch}--{COMPAT_NAME}-{COMPAT_VERSION}-{compat_release}.{rpm_arch}.rpm'
            identities[name] = (COMPAT_NAME, rpm_arch, COMPAT_VERSION, compat_release)
        if native_http:
            import legacy_curl
            name = f'rpm-{variant}-{public_arch}--{legacy_curl.PACKAGE_NAME}-{legacy_curl.VERSION}-{compat_release}.{rpm_arch}.rpm'
            identities[name] = (legacy_curl.PACKAGE_NAME, rpm_arch, legacy_curl.VERSION, compat_release)
    common = [name for name in packages if re.fullmatch(
        r'rpm-' + re.escape(variant) + r'--cbodotnet-host-([1-9][0-9]*(?:\.[0-9]+)*)-([1-9][0-9]*\.cbot\.'
        + re.escape(variant.replace('-', '')) + r')\.noarch\.rpm', name)]
    require(len(common) == 1 and set(packages) == set(identities) | set(common),
            'RPM repository must contain the canonical native architectures and common host')
    host = re.fullmatch(r'.*--cbodotnet-host-(.+)-([^-]+)\.noarch\.rpm', common[0])
    identities[common[0]] = ('cbodotnet-host', 'noarch', host[1], host[2])
    for name, row in packages.items():
        expected = assets.get(name, {})
        require(re.fullmatch(r'rpm-[A-Za-z0-9._+-]+\.rpm', name)
                and row.get('url') == base + name and row.get('size') == expected.get('size')
                and row.get('sha256') == expected.get('sha256') and row.get('size', 0) > 0,
                'RPM repository package differs from its signed release asset')
    root = ET.fromstring((directory / 'repodata/repomd.xml').read_bytes())
    primary = None
    for row in root.findall(REPO + 'data'):
        location = row.find(REPO + 'location')
        require(location is not None, 'RPM metadata location is absent')
        href = location.get('href', '')
        relative = PurePosixPath(href)
        require(str(relative) == href and not relative.is_absolute() and '..' not in relative.parts
                and relative.parts[0] == 'repodata' and not any(c in href for c in '\\:\0\r\n'),
                'Unsafe RPM metadata location')
        path = directory / href
        checksum, size = row.find(REPO + 'checksum'), row.find(REPO + 'size')
        require(checksum is not None and checksum.get('type') == 'sha256' and size is not None
                and path.is_file() and not any(item.is_symlink() for item in [path, *path.parents])
                and 0 < path.stat().st_size < 16 * 1024**2 and path.stat().st_size == int(size.text)
                and hashlib.sha256(path.read_bytes()).hexdigest() == checksum.text, 'RPM metadata digest mismatch')
        if row.get('type') == 'primary':
            require(primary is None and path.suffix == '.gz', 'A single gzip primary RPM index is required')
            require(path.stat().st_size < 16 * 1024**2, 'RPM primary metadata exceeds its bound')
            with gzip.open(path, 'rb') as incoming:
                primary = incoming.read(16 * 1024**2 + 1)
            require(len(primary) <= 16 * 1024**2, 'RPM primary metadata exceeds its bound')
            opened, opened_size = row.find(REPO + 'open-checksum'), row.find(REPO + 'open-size')
            require(opened is not None and opened.get('type') == 'sha256' and opened_size is not None
                    and int(opened_size.text) == len(primary) and hashlib.sha256(primary).hexdigest() == opened.text,
                    'Uncompressed RPM metadata digest mismatch')
    require(primary is not None, 'Primary RPM metadata is absent')
    observed = set()
    primary_root = ET.fromstring(primary)
    require(primary_root.tag == COMMON + 'metadata' and primary_root.get('packages') == str(len(identities)),
            'Primary RPM metadata declares another package matrix')
    for row in primary_root.findall(COMMON + 'package'):
        location, checksum, size = row.find(COMMON + 'location'), row.find(COMMON + 'checksum'), row.find(COMMON + 'size')
        require(location is not None and checksum is not None and size is not None, 'Incomplete RPM package metadata')
        url = urljoin(location.get(XML_BASE, base), location.get('href', ''))
        require(url.startswith(base), 'RPM package URL escapes its immutable release')
        name = url[len(base):]
        expected = packages.get(name, {})
        version = row.find(COMMON + 'version')
        identity = (row.findtext(COMMON + 'name'), row.findtext(COMMON + 'arch'),
                    version.get('ver') if version is not None else None,
                    version.get('rel') if version is not None else None)
        require(name not in observed and expected.get('url') == url and checksum.get('type') == 'sha256'
                and checksum.text == expected.get('sha256') and int(size.get('package', '0')) == expected.get('size')
                and identity == identities.get(name) and version.get('epoch', '0') == '0',
                'RPM primary index differs from authenticated packages')
        observed.add(name)
    require(observed == set(packages), 'RPM primary index has a partial or duplicate package matrix')
    return manifest


def verify_repository(directory, keyring, assets, base):
    directory = Path(directory)
    subprocess.run(['gpgv', '--keyring', str(keyring), str(directory / 'repodata/repomd.xml.asc'),
                    str(directory / 'repodata/repomd.xml')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return validate_metadata(directory, assets, base)
