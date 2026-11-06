"""Authenticate immutable per-user legacy companions without changing SDK payloads.

The installer catalog owns admission. This producer closes that admission over
the existing reviewed vendor policies and postverified consumer publications;
it never searches a host installation or downloads a distribution package.
"""
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

from consumer_archive_site import authenticate_receipt, load_archive_status, postverified_receipt
from downstream_release import encoded, require
from release_catalog import get_bytes
import legacy_compat as BASE
import legacy_curl as CURL


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/cbodotnetup-provider-policy.json'
FINGERPRINT = 'D7D154B4B33C19A82B95B13688135410ACD9C0EA'
SECURITY = 'community-build-no-additional-security-maintenance'
ARCHITECTURES = {'linux-x64': 'x64', 'linux-arm64': 'aarch64'}
VARIANTS = ('ubuntu-24.04', 'debian-13', 'fedora-45', 'rocky-9.8')
PROVIDERS = {
    'rocky9-20261104': ('compatibility', '5.0.214', BASE.POLICY,
        '6fcae0b9ebe497240f99a93d031fc73b57a0f26c9353c199b2faca34e197f776', '2.34'),
    'rocky8-curl-20261104': ('nativeHttpCompatibility', '3.1.426', CURL.POLICY,
        'f24a14a825101f2f1045d1a1573ff72b08903704729e5574b9e17c1f3186a02c', '2.17'),
}
VERSIONS = {'5.0.214', '3.1.426', '3.0.103'}
CPU_FLAGS = ['cx16', 'lahf_lm', 'popcnt', 'pni', 'ssse3', 'sse4_1', 'sse4_2']


def _asset(value):
    return {key: value[key] for key in ('url', 'size', 'sha256')}


def _receipt(version, revision=2):
    rows = [row for row in load_archive_status()['publications']
            if row['identity']['sdkVersion'] == version and row['identity']['packageRevision'] == revision]
    require(len(rows) == 1 and rows[0]['status'] == 'published-postverified'
            and rows[0]['signingFingerprint'] == FINGERPRINT,
            'Exactly one project-signed postverified provider source publication is required')
    return rows[0]


def _source_asset(receipt, name):
    rows = [item for item in receipt['assets'] if item['name'] == name]
    require(len(rows) == 1, 'Provider source publication omits or duplicates an asset')
    return _asset(rows[0])


def _source_policy(provider_id):
    path, expected = PROVIDERS[provider_id][2:4]
    require(hashlib.sha256(path.read_text().replace('\r\n', '\n').encode()).hexdigest() == expected,
            'The independently reviewed native provider policy changed')
    return BASE.load_policy() if provider_id == 'rocky9-20261104' else CURL.load_policy()


def load_policy(path=None):
    value = json.loads(Path(path or POLICY).read_bytes())
    validate_policy(value)
    return value


def validate_policy(value):
    require(set(value) == {'schemaVersion', 'kind', 'reviewedAt', 'signingFingerprint', 'consentOption',
            'libc', 'securitySupport', 'targets', 'sdkSources', 'providers', 'maintenance'}
            and value['schemaVersion'] == 1 and value['kind'] == 'cbodotnetup-legacy-provider-admission'
            and re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}', value['reviewedAt'])
            and value['signingFingerprint'] == FINGERPRINT
            and value['consentOption'] == '--with-legacy-providers'
            and value['libc'] == 'glibc' and value['securitySupport'] == SECURITY
            and value['targets'] == list(VARIANTS) and set(value['sdkSources']) == VERSIONS
            and set(value['providers']) == set(PROVIDERS), 'Invalid closed legacy provider admission policy')
    maintenance = value['maintenance']
    require(maintenance['additionalSecurityMaintenance'] is False
            and maintenance['upstreamDotnetSupportRestored'] is False
            and maintenance['preinstalledProvidersAccepted'] is False
            and isinstance(maintenance['decision'], str) and maintenance['decision']
            and isinstance(maintenance['references'], list) and maintenance['references'],
            'Legacy provider maintenance and ownership decision is required')
    for version, row in value['sdkSources'].items():
        receipt = _receipt(version)
        require(set(row) == {'revision', 'sourceManifestSha256', 'archives'} and row['revision'] == 2
                and row['sourceManifestSha256'] == receipt['identity']['sourceManifestSha256']
                and set(row['archives']) == set(ARCHITECTURES), 'Legacy SDK source admission differs')
        for rid, arch in ARCHITECTURES.items():
            require(row['archives'][rid] == _source_asset(receipt, f'cbodotnet-sdk-{version}-linux-{arch}-r2.tar.gz'),
                    'Legacy SDK archive differs from the exact neutral postverified source')
    for provider_id, row in value['providers'].items():
        kind, version, path, policy_sha, minimum = PROVIDERS[provider_id]
        source = _source_policy(provider_id); receipt = _receipt(version)
        require(set(row) == {'kind', 'version', 'revision', 'root', 'policyPath', 'policySha256',
                'minimumGlibc', 'canonicalSdkVersion', 'canonicalSdkRevision', 'sourceManifest',
                'sourceSignature', 'architectures'} and row['kind'] == kind
                and row['version'] == '2026.11.4' and row['revision'] == 1
                and row['root'] == source['root'] and row['policyPath'] == path.relative_to(ROOT).as_posix()
                and row['policySha256'] == policy_sha and row['minimumGlibc'] == minimum
                and row['canonicalSdkVersion'] == version and row['canonicalSdkRevision'] == 2
                and row['sourceManifest'] == _source_asset(receipt, 'distribution-manifest.json')
                and row['sourceSignature'] == _source_asset(receipt, 'distribution-manifest.json.asc')
                and set(row['architectures']) == set(ARCHITECTURES), 'Native provider source/policy admission differs')
        for rid, arch in ARCHITECTURES.items():
            item = row['architectures'][rid]; origin = source['architectures'][arch]
            require(set(item) == {'architecture', 'cpuBaseline', 'cpuFlags', 'archive'}
                    and item['architecture'] == arch and item['cpuBaseline'] == origin['cpuBaseline']
                    and item['cpuFlags'] == (CPU_FLAGS if provider_id == 'rocky9-20261104' and arch == 'x64' else [])
                    and item['archive'] == _source_asset(receipt,
                        f'{source["packageName"]}-{source["version"]}-linux-{arch}.tar.gz'),
                    'Provider archive or CPU contract differs from its reviewed source')
    return value


def provider_id(provider, rid):
    return provider['providerId'] + '-r' + str(provider['revision']) + '/' + rid


def required_provider_ids(version, rid):
    require(rid in ARCHITECTURES, 'Unreviewed provider RID/libc')
    if version not in VERSIONS:
        return []
    result = ['rocky9-20261104-r1/' + rid]
    if version.startswith('3.'):
        result.append('rocky8-curl-20261104-r1/' + rid)
    return result


def expected_manifest(provider_id_value, rid):
    """Reconstruct the historical provider's entire inventory from source pins."""
    require(provider_id_value in PROVIDERS and rid in ARCHITECTURES, 'Unknown reviewed native provider')
    policy = _source_policy(provider_id_value); arch = ARCHITECTURES[rid]
    files = [dict(path='lib', mode='0o755', type='directory')]
    for package in policy['architectures'][arch]['packages']:
        for item in package['files']:
            name = PurePosixPath(item['path']).name
            files.append(dict(path='lib/' + name, mode='0o755', type='file', size=item['size'], sha256=item['sha256']))
            files.append(dict(path='lib/' + item['soname'][0], mode='0o777', type='symlink', target=name))
        original = package['licenses'][0]
        filename = ('LICENSE.curl.txt' if provider_id_value == 'rocky8-curl-20261104' else
                    'LICENSE.openssl.txt' if package['packageName'] == 'compat-openssl11' else 'LICENSE.icu.txt')
        files.append(dict(path=filename, mode='0o644', type='file', size=original['size'], sha256=original['sha256']))
    notice = (BASE.notice_text(policy) if provider_id_value == 'rocky9-20261104' else CURL.notice_text(policy)).encode()
    files.append(dict(path='NOTICE.txt', mode='0o644', type='file', size=len(notice), sha256=hashlib.sha256(notice).hexdigest()))
    if provider_id_value == 'rocky9-20261104':
        config = policy['opensslConfiguration']['content'].encode()
        files.append(dict(path='openssl.cnf', mode='0o644', type='file', size=len(config), sha256=hashlib.sha256(config).hexdigest()))
    result = dict(schemaVersion=1, providerId=provider_id_value, providerRoot=policy['root'], architecture=arch,
        policySha256=PROVIDERS[provider_id_value][3], signingFingerprint=policy['signingFingerprint'],
        key=copy.deepcopy(policy['key']), packages=copy.deepcopy(policy['architectures'][arch]['packages']),
        sourcePackages=copy.deepcopy(policy['sources']), securityScope=policy['securityScope'],
        files=sorted(files, key=lambda row: row['path']))
    if provider_id_value == 'rocky9-20261104':
        result['opensslConfiguration'] = copy.deepcopy(policy['opensslConfiguration'])
    else:
        result.update(baseProvider=copy.deepcopy(policy['baseProvider']),
                      nativeHttpComponents=copy.deepcopy(policy['nativeHttpComponents']))
    return result


def _safe_name(name):
    path = PurePosixPath(name)
    return bool(name and not name.startswith('/') and str(path) == name and '\\' not in name
                and all(part not in ('..', '.') for part in path.parts))


def validate_companion(raw, manifest, root):
    """Validate both manifests and every tar entry; never extract untrusted paths."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 64 * 1024**2, 'Bounded provider companion bytes required')
    require(root.startswith('/usr/lib/cbodotnet/compat/') and _safe_name(root.lstrip('/')), 'Invalid provider root')
    manifest_bytes = encoded(manifest)
    relative = 'rootfs' + root
    expected = {'provider-manifest.json': dict(type='file', mode='0o644', size=len(manifest_bytes),
                                              sha256=hashlib.sha256(manifest_bytes).hexdigest())}
    for directory in [relative, *[str(path) for path in PurePosixPath(relative).parents if str(path) != '.']]:
        expected[directory] = dict(type='directory', mode='0o755')
    for item in manifest['files']:
        require(_safe_name(item['path']), 'Unsafe provider inventory path')
        path = relative + '/' + item['path']
        require(path not in expected, 'Duplicate provider inventory entry')
        expected[path] = item
    expected[relative + '/provider-manifest.json'] = expected['provider-manifest.json']
    seen, total = set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            require(_safe_name(member.name) and member.name in expected and member.name not in seen
                    and member.uid == member.gid == 0, 'Unexpected provider tar path, duplicate or ownership')
            seen.add(member.name); item = expected[member.name]
            require(member.mode == int(item['mode'], 8), 'Provider tar mode differs from signed inventory')
            kind = item['type']
            if kind == 'file':
                require(member.isfile() and member.size == item['size'] and member.size <= 64 * 1024**2,
                        'Provider file type or length differs')
                total += member.size
                require(total <= 128 * 1024**2, 'Provider companion expansion exceeds its bound')
                with archive.extractfile(member) as stream:
                    data = stream.read(member.size + 1)
                require(len(data) == member.size and hashlib.sha256(data).hexdigest() == item['sha256'],
                        'Provider file hash differs from independent source pins')
                if member.name.endswith('/provider-manifest.json') or member.name == 'provider-manifest.json':
                    require(data == manifest_bytes, 'Provider outer and inner manifests differ')
            elif kind == 'symlink':
                require(member.issym() and member.linkname == item['target'] and '/' not in member.linkname
                        and member.linkname not in ('', '.', '..'), 'Provider SONAME link differs or escapes its owned lib directory')
            else:
                require(kind == 'directory' and member.isdir(), 'Provider tar contains a special file')
    require(seen == set(expected), 'Provider companion is incomplete')
    return hashlib.sha256(manifest_bytes).hexdigest()


def _obtain(asset, cache):
    name = asset['url'].rsplit('/', 1)[1]
    require(re.fullmatch(r'[A-Za-z0-9_.+-]+', name) and re.fullmatch('[a-f0-9]{64}', asset['sha256'])
            and type(asset['size']) is int and 0 < asset['size'] <= 64 * 1024**2
            and re.fullmatch(r'https://github\.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-[0-9.]+-r2/[A-Za-z0-9_.+-]+', asset['url']),
            'Unreviewed provider download descriptor')
    cache = Path(cache).absolute()
    require(not any(path.is_symlink() for path in [cache, *cache.parents]), 'Provider metadata cache contains a symlink')
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (asset['sha256'] + '-' + name)
    if target.exists() or target.is_symlink():
        require(target.is_file() and not target.is_symlink(), 'Provider cache entry is not an ordinary file')
        raw = target.read_bytes()
    else:
        raw = get_bytes(asset['url'], asset['size'])
        require(len(raw) == asset['size'] and hashlib.sha256(raw).hexdigest() == asset['sha256'],
                'Provider download differs from its signed immutable descriptor')
        with target.open('xb') as output:
            output.write(raw)
    require(len(raw) == asset['size'] and hashlib.sha256(raw).hexdigest() == asset['sha256'],
            'Provider cache bytes differ from signed immutable descriptor')
    return raw


def _authenticated_source(version):
    receipt = _receipt(version)
    manifest = authenticate_receipt(receipt, historical=True)
    postverified_receipt(receipt, receipt['postVerification']['reports'], manifest,
                         source=receipt['postVerification']['workflow'])
    return receipt, manifest


def _sdk_id(sdk):
    return f'{sdk["sdkVersion"]}-r{sdk["revision"]}/{sdk["rid"]}'


def _bindings(sdks, policy):
    bindings, seen = [], set()
    for sdk in sdks:
        identity = _sdk_id(sdk)
        require(identity not in seen, 'Duplicate SDK provider binding identity'); seen.add(identity)
        version, rid = sdk['sdkVersion'], sdk['rid']
        if version not in VERSIONS:
            require(not sdk.get('requiresLegacyProvider', False), 'An unreviewed SDK requests native providers')
            continue
        expected = policy['sdkSources'][version]
        require(rid in ARCHITECTURES and sdk['revision'] == expected['revision']
                and sdk.get('requiresLegacyProvider') is True
                and sdk['sourceManifestSha256'] == expected['sourceManifestSha256']
                and sdk['archive'] == expected['archives'][rid], 'Legacy SDK provider binding differs from admitted SDK/source bytes')
        bindings.append(dict(sdkId=identity, sourceManifestSha256=sdk['sourceManifestSha256'],
                             archiveSha256=sdk['archive']['sha256'], providerIds=required_provider_ids(version, rid)))
    return sorted(bindings, key=lambda row: row['sdkId'])


def _targets(sdks, provider_identity, policy):
    sdk_targets = set()
    for sdk in sdks:
        if provider_identity not in required_provider_ids(sdk['sdkVersion'], sdk['rid']):
            continue
        for target in sdk['targets']:
            require(set(target) == {'os', 'versionId', 'rid'} and target['rid'] == sdk['rid']
                    and target['os'] + '-' + target['versionId'] in policy['targets'],
                    'Legacy provider target is not individually reviewed')
            sdk_targets.add((target['os'], target['versionId'], target['rid']))
    rid = provider_identity.rsplit('/', 1)[1]
    expected = [dict(os=variant.rsplit('-', 1)[0], versionId=variant.rsplit('-', 1)[1], rid=rid)
                for variant in policy['targets']]
    return [target for target in expected if (target['os'], target['versionId'], target['rid']) in sdk_targets]


def _provider_record(name, rid, sdks, policy):
    row = policy['providers'][name]; architecture = row['architectures'][rid]
    manifest = expected_manifest(name, rid)
    record = dict(providerId=name, version=row['version'], revision=row['revision'], rid=rid,
        root=row['root'], archive=copy.deepcopy(architecture['archive']),
        manifestSha256=hashlib.sha256(encoded(manifest)).hexdigest(), policySha256=row['policySha256'],
        libc='glibc', minimumGlibc=row['minimumGlibc'], cpuBaseline=architecture['cpuBaseline'],
        cpuFlags=copy.deepcopy(architecture['cpuFlags']), targets=[], securitySupport=SECURITY,
        manifest=manifest, sourceManifest=copy.deepcopy(row['sourceManifest']), sourceSignature=copy.deepcopy(row['sourceSignature']))
    record['targets'] = _targets(sdks, provider_id(record, rid), policy)
    require(record['targets'], 'Provider has no individually admitted SDK target')
    return record


def _source_provider(manifest, provider_name, rid):
    kind = PROVIDERS[provider_name][0]
    rows = [row for row in manifest.get(kind, []) if row['architecture'] == ARCHITECTURES[rid]]
    require(len(rows) == 1, 'Signed SDK publication omits or duplicates a required native companion')
    return rows[0]


def _verify_source_provider(manifest, name, rid, policy):
    source = _source_provider(manifest, name, rid); row = policy['providers'][name]
    archive = row['architectures'][rid]['archive']; filename = archive['url'].rsplit('/', 1)[1]
    require(source['asset'] == filename and source['record']['providerRoot'] == row['root']
            and source['record']['policySha256'] == row['policySha256']
            and source['record']['companion'] == dict(path=filename, size=archive['size'], sha256=archive['sha256'])
            and source['record']['manifest'] == expected_manifest(name, rid),
            'Signed SDK companion metadata differs from independent native source/notice pins')
    assets = [item for item in manifest['assets'] if item['name'] == filename]
    require(assets == [dict(name=filename, size=archive['size'], sha256=archive['sha256'])],
            'Signed SDK companion asset descriptor differs')


def catalog_provider_metadata(sdks, *, cache=None, policy=None):
    """Return four shared provider records and only the legacy SDK bindings.

    Every required SDK's own signed consumer publication is checked, even though
    the identical shared companion downloads use one canonical source each.
    """
    policy = load_policy() if policy is None else validate_policy(policy)
    sdks = list(sdks); bindings = _bindings(sdks, policy)
    if not bindings:
        return [], []
    sources = {}
    versions = {sdk['sdkVersion'] for sdk in sdks if sdk['sdkVersion'] in VERSIONS}
    needed = {identity for row in bindings for identity in row['providerIds']}
    versions.update(policy['providers'][identity.split('-r1/')[0]]['canonicalSdkVersion'] for identity in needed)
    for version in sorted(versions):
        sources[version] = _authenticated_source(version)
    for sdk in sdks:
        if sdk['sdkVersion'] not in VERSIONS:
            continue
        receipt, manifest = sources[sdk['sdkVersion']]
        require(manifest['identity']['sourceManifestSha256'] == sdk['sourceManifestSha256'],
                'Provider admission source differs from the SDK canonical producer manifest')
        builds = [record for record in manifest['records'] if record['architecture'] == ARCHITECTURES[sdk['rid']]]
        require(len(builds) == 1 and builds[0]['build']['directory'] == sdk['archiveRoot']
                and _source_asset(receipt, builds[0]['artifactAsset']) == sdk['archive'],
                'Legacy SDK archive/root differs from its authenticated consumer publication')
        for identity in required_provider_ids(sdk['sdkVersion'], sdk['rid']):
            _verify_source_provider(manifest, identity.split('-r1/')[0], sdk['rid'], policy)
    def produce(directory):
        providers = []
        for identity in sorted(needed):
            name, rid = identity.rsplit('-r1/', 1)
            provider = _provider_record(name, rid, sdks, policy)
            _, original = sources[policy['providers'][name]['canonicalSdkVersion']]
            _verify_source_provider(original, name, rid, policy)
            raw = _obtain(provider['archive'], directory)
            actual_manifest_sha = validate_companion(raw, provider['manifest'], provider['root'])
            require(actual_manifest_sha == provider['manifestSha256'], 'Provider manifest byte identity changed')
            providers.append(provider)
        return providers
    if cache is None:
        with tempfile.TemporaryDirectory(prefix='cbodotnetup-provider-admission-') as temporary:
            providers = produce(temporary)
    else:
        providers = produce(cache)
    validate_provider_catalog(dict(schemaVersion=3, sdks=sdks, providers=providers, providerBindings=bindings), policy=policy)
    return providers, bindings


def validate_provider_catalog(catalog, compatibility=None, *, policy=None):
    """Validate production provider shape, source pins, ABI and exact SDK bindings offline."""
    policy = load_policy() if policy is None else validate_policy(policy)
    require(catalog.get('schemaVersion') == 3 and isinstance(catalog.get('providers'), list)
            and isinstance(catalog.get('providerBindings'), list), 'Schema3 provider records and bindings are required')
    sdks = catalog['sdks']; bindings = _bindings(sdks, policy)
    require(catalog['providerBindings'] == bindings, 'Legacy provider bindings are missing, duplicated or differ from exact SDK/source bytes')
    needed = {identity for row in bindings for identity in row['providerIds']}
    expected = []
    for identity in sorted(needed):
        name, rid = identity.rsplit('-r1/', 1)
        expected.append(_provider_record(name, rid, sdks, policy))
    require(catalog['providers'] == expected, 'Provider source, manifest, target, ABI, identity or inventory differs from reviewed admission')
    if compatibility is not None:
        projection = {key: copy.deepcopy(value) for key, value in catalog.items()
                      if key not in {'providers', 'providerBindings', 'compatibilityCatalog'}}
        projection['schemaVersion'] = 2
        projection['sdks'] = [sdk for sdk in projection['sdks'] if not sdk['requiresLegacyProvider']]
        modern = {sdk['sdkVersion'] + '-r' + str(sdk['revision']) for sdk in projection['sdks']}
        projection['channels'] = {key: value for key, value in projection['channels'].items() if value in modern}
        require(compatibility == projection, 'Schema2 compatibility projection includes legacy provider records or differs from modern source identities')
    return len(expected)
