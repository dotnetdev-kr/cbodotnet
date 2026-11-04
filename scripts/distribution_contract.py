#!/usr/bin/env python3
"""Preparation rules for independently qualified downstream channels."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex

from release_catalog import validate_release

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
ARCHITECTURES = {
    'x64': dict(public='x64', rid='linux-x64', deb='amd64', rpm='x86_64', aur='x86_64', oci='linux/amd64'),
    'aarch64': dict(public='aarch64', rid='linux-arm64', deb='arm64', rpm='aarch64', aur='aarch64', oci='linux/arm64'),
}
INSTALLATION = {
    'rootTemplate': '/opt/cbodotnet/{series}',
    'launcherTemplate': '/usr/bin/cbodotnet-{series}',
    'packageTemplate': 'cbodotnet-sdk-{series}',
    'aurPackageTemplate': 'cbodotnet-sdk-{series}-bin',
    'selection': 'one-complete-sdk-per-major-minor',
    'defaultLauncher': '/usr/bin/cbodotnet',
    'commonPackage': 'cbodotnet-host',
    'defaultSelection': 'highest-installed-major-minor',
    'containerCommandDirectory': '/usr/local/bin',
    'additionalDirectories': ['metadata'],
    'modifySystemDotnet': False,
    'registerAlternatives': False,
}
BRANDING = {
    'displayName': 'Community Build of .NET (built by .NET Dev)',
    'implementation': 'distribution-wrapper',
    'versionStdout': 'unchanged-numeric-sdk-version',
    'versionBrandingStream': 'stderr',
    'informationCommand': '--cbodotnet-info',
    'modifyQualifiedPayload': False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_file(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def validate_contract(contract):
    require(isinstance(contract, dict) and type(contract.get('schemaVersion')) is int
            and contract['schemaVersion'] == 2 and contract.get('repository') == REPOSITORY,
            'Unsupported distribution contract version or repository')
    require(contract.get('installation') == INSTALLATION,
            'Installation namespace collision or unsupported installation policy')
    require(contract.get('branding') == BRANDING, 'Unsupported CLI branding or version-output policy')
    require(contract.get('architectures') == ARCHITECTURES, 'Unknown architecture mapping')
    require(isinstance(contract.get('releases'), dict) and contract['releases'], 'Missing admitted releases')
    for version, release in contract['releases'].items():
        require(re.fullmatch(r'[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version)
                and isinstance(release, dict) and re.fullmatch(r'[a-f0-9]{64}', release.get('manifestSha256', '')),
                'Invalid pinned release identity')
        require(release.get('additionalDirectories', INSTALLATION['additionalDirectories'])
                in ([], INSTALLATION['additionalDirectories']), 'Unreviewed SDK payload directory addition')
        targets = release.get('channelTargets')
        if targets is not None:
            require(isinstance(targets, dict) and set(targets) <= {'deb', 'rpm', 'oci', 'aur'},
                    'Invalid per-SDK candidate target admission')
            for channel, variants in targets.items():
                require(isinstance(variants, list) and len(variants) == len(set(variants))
                        and set(variants) <= set(contract.get('channels', {}).get(channel, {}).get('variants', [])),
                        'Unreviewed per-SDK candidate target')
    channels = contract.get('channels', {})
    require(set(channels) == {'deb', 'oci', 'rpm', 'aur'}, 'Unknown channel mapping')
    for name, channel in channels.items():
        require(isinstance(channel, dict) and channel.get('status') in {'preparation-only', 'deferred'}
                and isinstance(channel.get('variants'), list), 'Invalid channel policy: ' + name)
        architectures = channel.get('architectures', list(ARCHITECTURES))
        require(isinstance(architectures, list) and architectures and len(architectures) == len(set(architectures))
                and set(architectures) <= set(ARCHITECTURES), 'Invalid channel architecture admission')
        for variant in channel['variants']:
            os_record = contract.get('operatingSystems', {}).get(variant, {})
            require(os_record.get('libc') == 'glibc' and os_record.get('dependencies'),
                    'Unsupported distro/version combination: ' + str(variant))
    require(channels['oci'].get('repository') == 'ghcr.io/' + REPOSITORY + '-sdk', 'OCI namespace collision')
    require(contract.get('qualification', {}).get('publishedChannels') == []
            and contract['qualification'].get('packageInstallTargets') == []
            and contract['qualification'].get('containerBases') == [],
            'Contract v2 does not authorize publication or package/container compatibility claims')
    return contract


def candidate_target(contract, version, channel, variant, arch):
    """Candidate admission permits native testing; signed reports permit publication."""
    admitted = contract['releases'].get(version)
    require(admitted is not None, 'Release is not admitted by the reviewed distribution contract')
    policy = contract['channels'].get(channel, {})
    require(policy.get('status') == 'preparation-only' and variant in policy.get('variants', [])
            and arch in policy.get('architectures', ARCHITECTURES), 'Unsupported or deferred channel/variant/architecture')
    require(variant in admitted.get('channelTargets', {channel: policy['variants']}).get(channel, []),
            'SDK target is not admitted for candidate qualification')
    if version.startswith(('3.', '5.')):
        require(admitted.get('compatibilityProvider') == 'rocky9-20261104',
                'Legacy SDK requires a separately recorded compatibility provider')
    return admitted


def load_contract(path=None):
    path = Path(path) if path is not None else ROOT / 'releases/distribution-contract.json'
    return validate_contract(json.loads(path.read_text(encoding='utf-8-sig')))


def launcher_text(root, arch, contract=None, plan=None):
    """Render the same launcher for package staging and private-prefix smoke tests."""
    contract = validate_contract(contract if contract is not None else load_contract())
    require(arch in ARCHITECTURES, 'Unknown architecture; use public x64 or aarch64')
    root = str(root)
    path = PurePosixPath(root)
    require(path.is_absolute() and str(path) == root and '..' not in path.parts
            and root != '/' and not any(c in root for c in '\\:\0\r\n'), 'Unsafe SDK root')
    if plan is None:
        require(len(contract['releases']) == 1, 'An exact preparation plan is required for a multi-release launcher')
        version, admitted = next(iter(contract['releases'].items()))
        plan = dict(sdkVersion=version, sourceReleaseTag='sdk-' + version,
                    sourceManifestSha256=admitted['manifestSha256'], packageRevision=1)
    identity = dict(schemaVersion=1, contractVersion=contract['schemaVersion'], distributionBrand=BRANDING['displayName'],
                    sdkVersion=plan['sdkVersion'], targetRid=ARCHITECTURES[arch]['rid'],
                    sdkRoot=root, sourceReleaseTag=plan['sourceReleaseTag'],
                    sourceManifestSha256=plan['sourceManifestSha256'],
                    packageRevision=plan['packageRevision'], brandingScope='distribution-wrapper',
                    qualifiedPayloadModified=False)
    replacements = {
        '@ROOT@': shlex.quote(root),
        '@ARCH_ROOT@': 'DOTNET_ROOT_X64' if arch == 'x64' else 'DOTNET_ROOT_ARM64',
        '@BRAND@': shlex.quote(BRANDING['displayName']),
        '@BRANDING_JSON@': shlex.quote(json.dumps(identity, separators=(',', ':'))),
    }
    from legacy_compat import launcher_environment
    replacements['@COMPATIBILITY_ENV@'] = launcher_environment(plan)
    template = (ROOT / 'scripts/cbodotnet-launcher.sh.in').read_text(encoding='utf-8')
    return re.sub(r'@(?:ROOT|ARCH_ROOT|BRAND|BRANDING_JSON|COMPATIBILITY_ENV)@', lambda match: replacements[match[0]], template)


def validate_qualified_producers(record, target, catalog=None):
    """Reject unqualified producers before any SDK payload download or use."""
    if catalog is None:
        catalog = json.loads((ROOT / 'releases/qualified-builds.json').read_text(encoding='utf-8-sig'))
    require(isinstance(catalog, dict) and type(catalog.get('schemaVersion')) is int
            and catalog['schemaVersion'] == 1 and catalog.get('repository') == REPOSITORY,
            'Invalid qualification catalog')
    rows = catalog.get('builds')
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), 'Invalid qualification catalog builds')
    builds = [row for row in rows if row.get('sdkVersion') == record['sdkVersion']]
    require(len(builds) == 1 and builds[0].get('target') == target, 'Unqualified or ambiguous SDK version')
    producers = builds[0].get('architectures', {})
    require(isinstance(producers, dict) and set(producers) == set(ARCHITECTURES), 'Qualification requires both architectures')
    require(set(record.get('architectures', {})) == set(ARCHITECTURES), 'Qualified release requires both architectures')
    for public, row in record['architectures'].items():
        expected = producers[public]
        require(isinstance(expected, dict) and all(str(row['provenance'].get(key)) == str(expected.get(key))
                    for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')),
                'Release producer does not match qualified catalog: ' + public)


def verified_plan(release, manifest_bytes, checksum_bytes, sdk_path, channel, variant, arch,
                  revision=1, contract=None, catalog=None):
    """Bind a candidate package identity to qualified release bytes; never promote it."""
    contract = validate_contract(contract if contract is not None else load_contract())
    require(isinstance(arch, str) and arch in ARCHITECTURES,
            'Unknown architecture; use public x64 or aarch64')
    require(type(revision) is int and 1 <= revision <= 2147483647, 'Package revision must be a positive integer')
    require(isinstance(channel, str) and channel in contract['channels'], 'Unsupported channel')
    policy = contract['channels'][channel]
    require(policy['status'] == 'preparation-only', 'Channel is deferred pending independent qualification: ' + channel)
    require(arch in policy.get('architectures', ARCHITECTURES), 'Architecture is not admitted for this channel')
    require(isinstance(variant, str) and variant in policy['variants'],
            'Unsupported distro/version combination for ' + channel + ': ' + str(variant))
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    record = validate_release(release, manifest_bytes, checksum_bytes, REPOSITORY)
    version = record['sdkVersion']
    admitted = candidate_target(contract, version, channel, variant, arch)
    require(admitted is not None,
            'SDK version is not admitted for downstream packaging; legacy/unknown versions require separate qualification')
    require(manifest_digest == admitted['manifestSha256'], 'Pinned release manifest digest mismatch')
    validate_qualified_producers(record, admitted['target'], catalog)
    path = Path(sdk_path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary SDK archive file is required')
    sdk = record['architectures'][arch]['sdk']
    require(path.name == sdk['name'], 'SDK asset filename does not match selected architecture')
    require(path.stat().st_size == sdk['size'] and sha256_file(path) == sdk['sha256'], 'SDK asset size or digest mismatch')
    series = '.'.join(version.split('.')[:2])
    installation = {key: value.format(series=series) for key, value in INSTALLATION.items() if key.endswith('Template')}
    package = dict(name=installation['packageTemplate'], version=f'{version}-{revision}',
                   root=installation['rootTemplate'], launcher=installation['launcherTemplate'])
    if channel == 'oci':
        package['image'] = contract['channels']['oci']['repository'] + ':' + version + '-' + variant.replace('-', '') + '-r' + str(revision)
    entry = record['architectures'][arch]
    result = {
        'schemaVersion': 1, 'contractVersion': contract['schemaVersion'], 'status': 'prepared-unqualified',
        'sdkVersion': version, 'targetRid': ARCHITECTURES[arch]['rid'], 'architecture': dict(ARCHITECTURES[arch]),
        'channel': channel, 'variant': variant, 'packageRevision': revision, 'package': package,
        'commands': {'versioned': package['launcher'], 'default': INSTALLATION['defaultLauncher'],
                     'defaultOwner': INSTALLATION['commonPackage'],
                     'defaultSelection': INSTALLATION['defaultSelection'],
                     'containerDirectory': INSTALLATION['containerCommandDirectory'],
                     'containerDotnet': INSTALLATION['containerCommandDirectory'] + '/dotnet'},
        'branding': dict(BRANDING),
        'sourceReleaseTag': record['tag'], 'sourceManifestSha256': manifest_digest,
        'sourceManifestUrl': record['manifestUrl'], 'source': entry['source'], 'sdk': sdk,
        'evidence': entry['evidence'], 'producer': entry['provenance'],
        'dependencies': list(contract['operatingSystems'][variant]['dependencies']),
        'additionalDirectories': list(admitted.get('additionalDirectories', INSTALLATION['additionalDirectories'])),
        'licensePaths': list(admitted['licensePaths']), 'securitySupport': admitted['securitySupport'],
        'publicationAllowed': False,
    }
    if version.startswith(('3.', '5.')):
        result['dependencies'].append('cbodotnet-compat-rocky9')
    if channel == 'rpm':
        result['rpmDependencies'] = list(result['dependencies'])
        result['package']['rpmRelease'] = f'{revision}.cbot.' + variant.replace('-', '')
    if channel == 'aur':
        result['aurDependencies'] = list(result['dependencies'])
        result['package']['aurName'] = installation['aurPackageTemplate']
    return result
