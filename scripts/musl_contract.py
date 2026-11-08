"""Separate musl identities and source admission; glibc feed schemas stay intact."""
import hashlib
import json
from pathlib import Path
import re

from distribution_contract import BRANDING, sha256_file
from release_catalog import (asset_descriptor, positive_id, release_assets,
                             require, validate_api_asset)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
ARCHITECTURES = {
    'x64': dict(public='x64', rid='linux-musl-x64', apk='x86_64', oci='linux/amd64',
                elfMachine='Advanced Micro Devices X86-64', interpreter='/lib/ld-musl-x86_64.so.1'),
    'aarch64': dict(public='aarch64', rid='linux-musl-arm64', apk='aarch64', oci='linux/arm64',
                    elfMachine='AArch64', interpreter='/lib/ld-musl-aarch64.so.1'),
}
INSTALLATION = dict(rootTemplate='/opt/cbodotnet/{series}', launcherTemplate='/usr/bin/cbodotnet-{series}',
    packageTemplate='cbodotnet-sdk-{series}', commonPackage='cbodotnet-host', defaultLauncher='/usr/bin/cbodotnet',
    defaultSelection='highest-installed-major-minor', containerCommandDirectory='/usr/local/bin',
    modifySystemDotnet=False, registerAlternatives=False)
QUALIFICATION = dict(matchingNativeCpuRequired=True, completePayloadElfAuditRequired=True,
    explicitNonHostTargetClassificationRequired=True, stockDependenciesOnly=True,
    glibcCompatibilityLayerAllowed=False, nativeAot='not-qualified', workloads='not-qualified',
    installerAdmission='separate-issue-30')
SOURCE = dict(sourceCommit='5a2162bea6845eabc1fc721624a43568c65db3b1',
    sharedVmrCommit='0427b9abbead3fa64c6655eb4290c537397131fa', bootstrapSdk='10.0.401',
    sharedSdk='10.0.114-servicing.26522.126', runtimeVersion='10.0.14')
EXPANSION_WORKFLOW = '.github/workflows/musl-sdk-expand.yml'
# Reviewed candidate routes are not source or delivery qualification.
SOURCES = {
    '10.0.403': SOURCE,
    '9.0.123': dict(sourceCommit='9f04b57d1366e21b3178648493d6edffeff2216e',
        bootstrapSdk='9.0.121', runtimeVersion='9.0.22',
        runtimeSourceCommit='faaecba82df8933d7af60972138ce25f9c776cbd',
        aspnetSourceCommit='5aeb916d29e761492c987f1c09895c3ba9cbe1ac'),
    '8.0.133': dict(sourceCommit='7d1bf90885cff22e7da72b27e9848e42fd3cb1ae',
        bootstrapSdk='8.0.131', runtimeVersion='8.0.33',
        runtimeSourceCommit='da7a9beabf4cccc624399d583f52f080a4c858c2',
        aspnetSourceCommit='380bd0d498fbaa0a8ddd67c325aa748dd21f7596'),
    '7.0.120': dict(sourceCommit='25b977658c06fd0217ec0bc0714398bb9d0a7bb0',
        sdkSourceCommit='a06803c09702777c6550fede13c8bdc52d780191',
        bootstrapSdk='7.0.118', runtimeVersion='7.0.20',
        runtimeSourceCommit='0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903',
        aspnetSourceCommit='d9ba962869d1b1c410ea476b02de2f8e27eec762'),
    '6.0.136': dict(sourceCommit='d638663530d923adbe0442604b7a6562127321e9',
        sdkSourceCommit='1d205826ddc14c8f868eb6373e7a6bafcb9fe5be',
        bootstrapSdk='6.0.135', runtimeVersion='6.0.36',
        runtimeSourceCommit='f1dd57165bfd91875761329ac3a8b17f6606ad18',
        aspnetSourceCommit='64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc'),
}


def producer_workflow(version):
    require(version in SOURCES, 'Unreviewed musl producer SDK version')
    return '.github/workflows/musl-sdk.yml' if version == '10.0.403' else EXPANSION_WORKFLOW


def producer_artifact_name(version, architecture, run_id, attempt):
    require(version in SOURCES and architecture in ARCHITECTURES, 'Unreviewed native musl artifact route')
    prefix = 'net10' if version == '10.0.403' else 'sdk' + version
    return f'sdk-musl-{prefix}-{architecture}-{run_id}-{attempt}'


def producer_script(version):
    require(version in SOURCES, 'Unreviewed native musl producer validator')
    return 'musl-sdk.py' if version == '10.0.403' else 'musl-sdk-expand.py'
NATIVE_DEPENDENCIES = ['musl', 'ca-certificates', 'libgcc', 'libstdc++', 'libssl3', 'libcrypto3',
                       'icu-libs', 'icu-data-full', 'tzdata', 'krb5-libs', 'zlib', 'brotli-libs', 'lttng-ust']
KINDS = ('sdk', 'source', 'evidence')
PRODUCER_FIELDS = ('projectCommit', 'runId', 'runAttempt', 'artifactId')
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024


def version_revision(version, revision):
    require(isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version)
            and type(revision) is int and 0 < revision < 2**31, 'Exact SDK version and positive revision required')


def producer_tag(version, revision=1):
    version_revision(version, revision)
    # The existing release catalog intentionally discovers every sdk- prefix.
    return f'musl-sdk-{version}-r{revision}'


def distribution_tag(channel, version, revision=1):
    version_revision(version, revision)
    require(channel in {'archive', 'apk', 'oci'}, 'Unsupported musl distribution channel')
    return f'distribution-musl-{channel}-sdk-{version}-r{revision}'


def archive_name(version, architecture, revision=1):
    version_revision(version, revision)
    require(architecture in ARCHITECTURES, 'Unknown public musl architecture')
    return f'cbodotnet-sdk-{version}-linux-musl-{architecture}-r{revision}.tar.gz'


def producer_asset_name(kind, version, architecture, revision=1):
    require(kind in KINDS, 'Unknown musl producer asset kind')
    sdk = archive_name(version, architecture, revision)
    if kind == 'sdk':
        return sdk
    if kind == 'source':
        return f'cbodotnet-used-source-{version}-linux-musl-{architecture}-r{revision}.tar.gz'
    return f'cbodotnet-musl-sdk-{version}-linux-musl-{architecture}-r{revision}-evidence.tar.gz'


def oci_tag(version, revision=1):
    version_revision(version, revision)
    return f'{version}-alpine324-musl-r{revision}'


def validate_contract(contract):
    require(isinstance(contract, dict) and type(contract.get('schemaVersion')) is int
            and contract['schemaVersion'] == 1 and contract.get('kind') == 'musl-distribution-contract'
            and contract.get('repository') == REPOSITORY and contract.get('libc') == 'musl',
            'Unsupported musl distribution contract')
    require(contract.get('architectures') == ARCHITECTURES, 'Musl architecture/RID/libc mapping changed')
    require(contract.get('installation') == INSTALLATION, 'Musl installation namespace changed')
    require(contract.get('branding') == BRANDING, 'Musl branding policy changed')
    require(contract.get('producerWorkflow') == '.github/workflows/musl-sdk.yml', 'Unreviewed musl producer workflow')
    require(contract.get('channels') == ['archive', 'apk', 'oci']
            and contract.get('ociRepository') == 'ghcr.io/' + REPOSITORY + '-sdk', 'Musl delivery namespace changed')
    require(contract.get('qualification') == QUALIFICATION and contract.get('publicationAllowed') is False,
            'Candidate musl contract cannot authorize publication or installer admission')
    releases = contract.get('releases', {})
    require(set(releases) == set(SOURCES), 'Unreviewed musl SDK candidate')
    for version, source in SOURCES.items():
        release = releases[version]
        require(release.get('target') == 'net' + version.split('.')[0] + '-musl'
                and release.get('source') == source
                and release.get('producerRevisions') == [1] and release.get('candidateVariants') == ['alpine-3.24']
                and release.get('licensePaths') == ['LICENSE.txt', 'ThirdPartyNotices.txt']
                and release.get('securitySupport') == 'community-build-no-additional-security-maintenance',
                'Unreviewed musl SDK source or candidate identity')
        if version != '10.0.403':
            require(release.get('producerWorkflow') == producer_workflow(version), 'Unreviewed expansion workflow')
    require(contract.get('operatingSystems') == {'alpine-3.24': dict(distribution='alpine', branch='3.24',
            pointRelease='3.24.4', libc='musl', status='candidate-only', dependencies=NATIVE_DEPENDENCIES)},
            'Unreviewed musl user space or native dependencies')
    return contract


def load_contract(path=None):
    path = Path(path) if path is not None else ROOT / 'releases/musl-distribution-contract.json'
    return validate_contract(json.loads(path.read_bytes()))


def validate_provenance(provenance, architecture, contract=None, *, version='10.0.403'):
    contract = contract if contract is not None else load_contract()
    require(architecture in ARCHITECTURES and isinstance(provenance, dict), 'Missing musl producer provenance')
    require(provenance.get('libc') == 'musl' and provenance.get('targetRid') == ARCHITECTURES[architecture]['rid'],
            'Producer libc or target RID does not match musl architecture')
    require(version in contract['releases'], 'Unreviewed producer SDK version')
    require(provenance.get('workflow') == producer_workflow(version)
            and isinstance(provenance.get('projectCommit'), str)
            and re.fullmatch(r'[a-f0-9]{40}', provenance['projectCommit']), 'Unreviewed musl producer workflow or commit')
    for field in ('runId', 'runAttempt', 'artifactId'):
        positive_id(provenance.get(field), field)
    require(provenance.get('workflowUrl') == f'https://github.com/{REPOSITORY}/actions/runs/{provenance["runId"]}',
            'Musl producer workflow URL differs from exact run')
    require(all(provenance.get(key) == value for key, value in SOURCES[version].items())
            and not (version != '10.0.403' and ('sharedVmrCommit' in provenance or 'sharedSdk' in provenance)),
            'Musl producer source/bootstrap/shared SDK identity differs from reviewed candidate')
    return provenance


def validate_producer_manifest(manifest, *, release=None, contract=None):
    contract = validate_contract(contract if contract is not None else load_contract())
    require(isinstance(manifest, dict) and type(manifest.get('schemaVersion')) is int
            and manifest['schemaVersion'] == 1 and manifest.get('kind') == 'musl-sdk-producer-release'
            and manifest.get('repository') == REPOSITORY and manifest.get('libc') == 'musl',
            'Unsupported musl producer release manifest')
    version, revision = manifest.get('sdkVersion'), manifest.get('producerRevision')
    version_revision(version, revision)
    admitted = contract['releases'].get(version, {})
    require(revision in admitted.get('producerRevisions', []) and manifest.get('tag') == producer_tag(version, revision),
            'Unreviewed musl source release identity')
    architectures = manifest.get('architectures')
    require(isinstance(architectures, dict) and set(architectures) == set(ARCHITECTURES),
            'Musl source release requires both native architectures')
    for arch, identity in ARCHITECTURES.items():
        entry = architectures[arch]
        require(isinstance(entry, dict) and entry.get('targetRid') == identity['rid'], 'Musl source entry target RID differs')
        for kind in KINDS:
            asset_descriptor(entry.get(kind), producer_asset_name(kind, version, arch, revision))
        validate_provenance(entry.get('provenance'), arch, contract, version=version)
    asset_descriptor(manifest.get('checksums'), 'SHA256SUMS')
    if release is not None:
        require(release.get('tag_name') == manifest['tag'] and release.get('draft') is False
                and release.get('prerelease') is False
                and release.get('html_url') == f'https://github.com/{REPOSITORY}/releases/tag/{manifest["tag"]}',
                'Public musl source release identity differs')
    return manifest


def validate_producer_release(release, manifest_bytes, checksum_bytes, *, contract=None):
    require(isinstance(manifest_bytes, bytes) and 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES
            and isinstance(checksum_bytes, bytes) and 0 < len(checksum_bytes) <= MAX_CHECKSUM_BYTES,
            'Musl source metadata exceeds its bounds')
    manifest = validate_producer_manifest(json.loads(manifest_bytes), release=release, contract=contract)
    assets = release_assets(release)
    expected = {entry[kind]['name']: entry[kind] for entry in manifest['architectures'].values() for kind in KINDS}
    require(set(assets) == set(expected) | {'release-manifest.json', 'SHA256SUMS'},
            'Musl producer release asset list is incomplete or unexpected')
    validate_api_asset(assets['release-manifest.json'], 'release-manifest.json', REPOSITORY, manifest['tag'], content=manifest_bytes)
    for name, item in expected.items():
        validate_api_asset(assets[name], name, REPOSITORY, manifest['tag'], item)
    validate_api_asset(assets['SHA256SUMS'], 'SHA256SUMS', REPOSITORY, manifest['tag'], manifest['checksums'], checksum_bytes)
    observed = {}
    for line in checksum_bytes.decode('ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *]([A-Za-z0-9._-]+)', line)
        require(match is not None and match[2] not in observed, 'Malformed or duplicate musl checksum entry')
        observed[match[2]] = match[1]
    require(observed == {name: item['sha256'] for name, item in expected.items()}, 'Musl checksum inventory differs')
    return manifest


def validate_qualification_catalog(catalog, *, contract=None):
    contract = validate_contract(contract if contract is not None else load_contract())
    require(isinstance(catalog, dict) and type(catalog.get('schemaVersion')) is int and catalog['schemaVersion'] == 1
            and catalog.get('kind') == 'qualified-musl-sdk-producers' and catalog.get('repository') == REPOSITORY
            and catalog.get('libc') == 'musl' and isinstance(catalog.get('builds'), list), 'Invalid musl qualification catalog')
    seen = set()
    for row in catalog['builds']:
        require(isinstance(row, dict) and row.get('libc') == 'musl', 'Invalid musl qualification row')
        version, revision = row.get('sdkVersion'), row.get('producerRevision')
        version_revision(version, revision)
        admitted = contract['releases'].get(version, {})
        identity = (version, 'musl', revision)
        require(identity not in seen and row.get('target') == admitted.get('target')
                and revision in admitted.get('producerRevisions', [])
                and row.get('sourceReleaseTag') == producer_tag(version, revision)
                and isinstance(row.get('sourceManifestSha256'), str)
                and re.fullmatch(r'[a-f0-9]{64}', row['sourceManifestSha256']), 'Duplicate or unreviewed musl qualification identity')
        seen.add(identity)
        producers = row.get('architectures')
        require(isinstance(producers, dict) and set(producers) == set(ARCHITECTURES),
                'Musl qualification requires both native architectures')
        for arch, provenance in producers.items():
            validate_provenance(provenance, arch, contract, version=version)
    return catalog


def load_qualification_catalog(path=None, *, contract=None):
    path = Path(path) if path is not None else ROOT / 'releases/qualified-musl-builds.json'
    return validate_qualification_catalog(json.loads(path.read_bytes()), contract=contract)


def require_qualified_producer(manifest_bytes, *, catalog=None, contract=None):
    contract = validate_contract(contract if contract is not None else load_contract())
    require(isinstance(manifest_bytes, bytes) and 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES,
            'Musl source manifest exceeds its bounds')
    manifest = validate_producer_manifest(json.loads(manifest_bytes), contract=contract)
    catalog = validate_qualification_catalog(catalog if catalog is not None else load_qualification_catalog(), contract=contract)
    rows = [row for row in catalog['builds'] if (row['sdkVersion'], row['producerRevision'])
            == (manifest['sdkVersion'], manifest['producerRevision'])]
    require(len(rows) == 1 and rows[0]['sourceManifestSha256'] == hashlib.sha256(manifest_bytes).hexdigest(),
            'Musl source producer is not independently qualified at these exact manifest bytes')
    for arch, entry in manifest['architectures'].items():
        require(entry['provenance'] == rows[0]['architectures'][arch], 'Musl source producer differs from qualified native run')
    return manifest


def verified_plan(release, manifest_bytes, checksum_bytes, sdk_path, channel, variant, arch,
                  revision=1, *, contract=None, catalog=None):
    """Authenticate exact musl producer bytes before preparing any delivery channel."""
    contract = validate_contract(contract if contract is not None else load_contract())
    require(channel in contract['channels'] and arch in ARCHITECTURES, 'Unsupported musl channel or architecture')
    manifest = validate_producer_release(release, manifest_bytes, checksum_bytes, contract=contract)
    require_qualified_producer(manifest_bytes, catalog=catalog, contract=contract)
    version_revision(manifest['sdkVersion'], revision)
    version = manifest['sdkVersion']
    admitted = contract['releases'][version]
    require(variant in admitted['candidateVariants'], 'Unreviewed musl candidate variant')
    path = Path(sdk_path).absolute()
    require(path.is_file() and not any(item.is_symlink() for item in [path, *path.parents]),
            'An ordinary musl SDK archive file is required')
    entry = manifest['architectures'][arch]
    sdk = entry['sdk']
    require(path.name == sdk['name'] and path.stat().st_size == sdk['size'] and sha256_file(path) == sdk['sha256'],
            'Musl SDK archive name, size or digest differs from qualified source')
    series = '.'.join(version.split('.')[:2])
    package = dict(name=INSTALLATION['packageTemplate'].format(series=series), version=f'{version}-r{revision}',
        root=INSTALLATION['rootTemplate'].format(series=series), launcher=INSTALLATION['launcherTemplate'].format(series=series))
    if channel == 'oci':
        package['image'] = contract['ociRepository'] + ':' + oci_tag(version, revision)
    return dict(schemaVersion=1, kind='musl-distribution-plan', status='prepared-unqualified', publicationAllowed=False,
        contractVersion=contract['schemaVersion'], libc='musl', sdkVersion=version, producerRevision=manifest['producerRevision'],
        sourceReleaseTag=manifest['tag'], sourceManifestSha256=hashlib.sha256(manifest_bytes).hexdigest(),
        sourceManifestUrl=f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/release-manifest.json',
        targetRid=ARCHITECTURES[arch]['rid'], architecture=dict(ARCHITECTURES[arch]), channel=channel, variant=variant,
        packageRevision=revision, package=package, sdk=dict(sdk), source=dict(entry['source']), evidence=dict(entry['evidence']),
        producer=dict(entry['provenance']), branding=dict(BRANDING), dependencies=list(NATIVE_DEPENDENCIES),
        licensePaths=list(admitted['licensePaths']), securitySupport=admitted['securitySupport'], additionalDirectories=['metadata'],
        commands=dict(versioned=package['launcher'], default=INSTALLATION['defaultLauncher'],
            defaultOwner=INSTALLATION['commonPackage'], defaultSelection=INSTALLATION['defaultSelection'],
            containerDirectory=INSTALLATION['containerCommandDirectory'],
            containerDotnet=INSTALLATION['containerCommandDirectory'] + '/dotnet'))
