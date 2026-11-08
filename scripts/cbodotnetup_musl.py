"""Closed musl installer admission, independent of the historical candidate contract."""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import urllib.request

from downstream_release import ordinary_file, require
import musl_archive
import musl_contract as CONTRACT
import musl_site
from release_catalog import get_bytes

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/cbodotnetup-musl-policy.json'
FINGERPRINT = 'D7D154B4B33C19A82B95B13688135410ACD9C0EA'
ARCHITECTURES = {
    'x64': dict(rid='linux-musl-x64', cpuBaseline='x86-64', elfMachine=62, interpreter='/lib/ld-musl-x86_64.so.1'),
    'aarch64': dict(rid='linux-musl-arm64', cpuBaseline='armv8-a', elfMachine=183, interpreter='/lib/ld-musl-aarch64.so.1'),
}
CATALOG_FIELDS = {'schemaVersion', 'kind', 'libc', 'sequence', 'issuedAt', 'expiresAt',
                  'signingFingerprint', 'revoked', 'tools', 'sdks', 'channels'}
CHECKS = (
    'sdk-free-bootstrap', 'signature-authentication', 'source-producer-linkage', 'exact-version-install',
    'idempotent-install', 'owned-paths', 'official-package-coexistence', 'community-package-coexistence',
    'offline-build-runtime', 'http-crypto-globalization', 'branded-aliases', 'rollback', 'removal',
    'tamper-rejection', 'signature-rejection', 'concurrency', 'interrupted-activation', 'unqualified-rejection',
    'cross-libc-rejection', 'cross-architecture-rejection', 'native-musl-elf', 'self-update-rollback',
    'system-trust-https', 'complete-payload-elf-audit', 'native-tool-elf-audit', 'cross-libc-state-preservation',
)


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def nuget_content_hash(value):
    """NuGet's normalized package-content SHA512 is distinct from signed ZIP bytes."""
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9+/]{86}==', value) is None:return False
    return base64.b64encode(base64.b64decode(value, validate=True)).decode() == value


def load_policy(path=None):
    value = json.loads(ordinary_file(path or POLICY).read_bytes())
    fields = {'schemaVersion', 'kind', 'libc', 'minimumToolVersion', 'signingFingerprint', 'sdkVersion',
              'revision', 'producerRevision', 'sourceManifestSha256', 'publication', 'target', 'architectures', 'archives'}
    require(set(value) == fields and value['schemaVersion'] == 1 and value['kind'] == 'cbodotnetup-musl-sdk-admission'
            and value['libc'] == 'musl' and value['minimumToolVersion'] == '0.5.0'
            and value['signingFingerprint'] == FINGERPRINT and value['sdkVersion'] == '10.0.403'
            and type(value['revision']) is int and value['revision'] == 1 and type(value['producerRevision']) is int and value['producerRevision'] == 1
            and sha(value['sourceManifestSha256']) and value['target'] == dict(os='alpine', versionId='3.24.4')
            and value['architectures'] == ARCHITECTURES, 'Unreviewed installer musl/libc/CPU/Alpine admission')
    require(set(value['publication']) == {'manifestSha256', 'verificationManifestSha256'}
            and all(sha(v) for v in value['publication'].values()), 'Missing independently signed musl publication pins')
    require(set(value['archives']) == set(ARCHITECTURES), 'Both native musl archive admissions are mandatory')
    for arch, item in value['archives'].items():
        require(set(item) == {'name', 'size', 'sha256'}
                and item['name'] == CONTRACT.archive_name(value['sdkVersion'], arch, value['revision'])
                and type(item['size']) is int and 0 < item['size'] <= 1024**3 and sha(item['sha256']),
                'Unreviewed musl immutable archive descriptor')
    return value


def _authenticated(*, policy=None, status=None, authenticator=None, fetch=None):
    policy = policy or load_policy()
    status = status if status is not None else musl_site.load_status()
    rows = [r for r in status['publications'] if r.get('identity', {}).get('channel') == 'archive'
            and r['identity'].get('sdkVersion') == policy['sdkVersion']
            and r['identity'].get('packageRevision') == policy['revision']]
    require(len(rows) == 1, 'The exact admitted musl archive publication must appear once')
    receipt = rows[0]; identity = receipt['identity']
    require(receipt.get('status') == 'published-postverified' and identity.get('libc') == 'musl'
            and identity.get('producerRevision') == policy['producerRevision']
            and identity.get('sourceManifestSha256') == policy['sourceManifestSha256']
            and receipt.get('manifestSha256') == policy['publication']['manifestSha256']
            and receipt.get('verification', {}).get('manifestSha256') == policy['publication']['verificationManifestSha256']
            and receipt.get('signingFingerprint') == receipt.get('verification', {}).get('signingFingerprint') == FINGERPRINT,
            'Musl archive is not bound to the reviewed signed publication and final native verification')
    manifest = (authenticator or musl_site.authenticate_receipt)(receipt)
    require(manifest.get('identity') == identity and manifest.get('tag') == receipt.get('tag'),
            'Authenticated musl archive identity changed')
    url = f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{CONTRACT.producer_tag(policy["sdkVersion"], policy["producerRevision"])}/release-manifest.json'
    canonical = (fetch or get_bytes)(url, 16 * 1024**2)
    require(hashlib.sha256(canonical).hexdigest() == policy['sourceManifestSha256'], 'Musl producer manifest differs from reviewed source pin')
    source = CONTRACT.require_qualified_producer(canonical)
    require(source['sdkVersion'] == policy['sdkVersion'] and source['producerRevision'] == policy['producerRevision'],
            'Installer producer admission differs from the independently qualified native source')
    return policy, receipt, manifest, source, dict(url=url, size=len(canonical), sha256=policy['sourceManifestSha256'])


def sdk_catalog_record(arch, *, policy=None, status=None, authenticator=None, fetch=None):
    """Authenticate signed public SDK evidence before exposing an unchanged SDK record."""
    require(arch in ARCHITECTURES, 'Unsupported native musl architecture')
    policy, receipt, manifest, source, canonical = _authenticated(
        policy=policy, status=status, authenticator=authenticator, fetch=fetch)
    rows = [r for r in manifest['records'] if r['architecture'] == arch]
    require(len(rows) == 1, 'Exactly one signed native musl archive record is required')
    row = rows[0]; plan = row['build']['plan']; rid = ARCHITECTURES[arch]['rid']
    assets = [a for a in receipt['assets'] if a['name'] == row['artifactAsset']]
    require(len(assets) == 1, 'Musl archive asset is missing or duplicated')
    archive = assets[0]; admitted = policy['archives'][arch]
    require({key: archive[key] for key in admitted} == admitted
            and archive['url'] == f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{CONTRACT.distribution_tag("archive", policy["sdkVersion"], policy["revision"])}/{admitted["name"]}'
            and row.get('targetRid') == rid and plan.get('targetRid') == rid and plan.get('libc') == 'musl'
            and plan.get('sourceManifestSha256') == canonical['sha256'] and plan.get('sourceManifestUrl') == canonical['url']
            and plan.get('producer') == source['architectures'][arch]['provenance']
            and plan.get('evidence') == source['architectures'][arch]['evidence']
            and plan.get('dependencies') == CONTRACT.NATIVE_DEPENDENCIES
            and plan.get('licensePaths') == ['LICENSE.txt', 'ThirdPartyNotices.txt']
            and plan.get('securitySupport') == 'community-build-no-additional-security-maintenance'
            and row['build'].get('directory') == f'cbodotnet-{policy["sdkVersion"]}-linux-musl-{arch}-r{policy["revision"]}',
            'Musl SDK archive, RID, source, native dependencies or original notices differ from admission')
    return dict(sdkVersion=policy['sdkVersion'], revision=policy['revision'], rid=rid,
        archiveRoot=row['build']['directory'], archive={key: archive[key] for key in ('url', 'size', 'sha256')},
        sourceManifestSha256=canonical['sha256'], sourceManifest=canonical, producer=plan['producer'],
        evidence=dict(url=canonical['url'].rsplit('/',1)[0]+'/'+plan['evidence']['name'],
            **{key: plan['evidence'][key] for key in ('size', 'sha256')}), licensePaths=plan['licensePaths'],
        securitySupport=plan['securitySupport'], dependencies=sorted(plan['dependencies']),
        targets=[dict(policy['target'], rid=rid)], requiresLegacyProvider=False)


def authenticated_musl_sdk(arch, output):
    """Return (archive path, proof) for the caller's native SDK build environment."""
    output = Path(output).absolute()
    require(not output.exists() and not any(p.is_symlink() for p in (output, *output.parents)), 'A fresh ordinary musl SDK intake directory is required')
    record = sdk_catalog_record(arch); policy = load_policy()
    output.mkdir(parents=True)
    name = policy['archives'][arch]['name']; path = output / name; archive = dict(name=name, **record['archive'])
    with urllib.request.urlopen(archive['url'], timeout=120) as source, path.open('xb') as target:
        total = 0
        while block := source.read(1024 * 1024):
            total += len(block); require(total <= archive['size'], 'Musl SDK exceeds its signed archive bound'); target.write(block)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):digest.update(block)
    require(path.stat().st_size == archive['size'] and digest.hexdigest() == archive['sha256'],
            'Musl SDK build input differs from signed size/SHA256')
    proof = dict(libc='musl', architecture=arch, targetRid=record['rid'], archive=archive,
        archiveRoot=record['archiveRoot'], sourceManifest=record['sourceManifest'], producer=record['producer'],
        publication=policy['publication'], sdkVersion=policy['sdkVersion'], revision=policy['revision'])
    return path, proof


def validate_catalog(catalog, *, expected_sdks=None, now=None, fresh=False):
    policy = load_policy()
    require(set(catalog) == CATALOG_FIELDS and type(catalog['schemaVersion']) is int and catalog['schemaVersion'] == 4
            and catalog['kind'] == 'cbodotnetup-installation-catalog' and catalog['libc'] == 'musl'
            and catalog['signingFingerprint'] == FINGERPRINT and type(catalog['sequence']) is int and catalog['sequence'] > 0
            and catalog['channels'] == {'10.0': '10.0.403-r1'} and catalog['revoked'] == sorted(set(catalog['revoked'])),
            'Invalid separate musl installer catalog identity')
    now=now or datetime.now(timezone.utc)
    issued=datetime.fromisoformat(catalog['issuedAt'].replace('Z','+00:00'))
    expires=datetime.fromisoformat(catalog['expiresAt'].replace('Z','+00:00'))
    require(issued.utcoffset()==expires.utcoffset()==timedelta(0) and issued<=now+timedelta(minutes=5)
            and issued<expires and expires-issued<=timedelta(days=31) and (not fresh or now<expires),
            'Invalid musl installer catalog UTC lifetime, future date or expiry')
    require(isinstance(catalog['sdks'], list) and len(catalog['sdks']) == 2
            and {s['rid'] for s in catalog['sdks']} == {r['rid'] for r in ARCHITECTURES.values()}, 'Both isolated musl SDK records are required')
    for sdk in catalog['sdks']:
        arch = next(a for a, target in ARCHITECTURES.items() if target['rid'] == sdk['rid'])
        sdk_fields = {'sdkVersion', 'revision', 'rid', 'archiveRoot', 'archive', 'sourceManifestSha256', 'sourceManifest',
                      'producer', 'evidence', 'licensePaths', 'securitySupport', 'dependencies', 'targets', 'requiresLegacyProvider'}
        source_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{CONTRACT.producer_tag(policy["sdkVersion"], policy["producerRevision"])}/release-manifest.json'
        archive_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{CONTRACT.distribution_tag("archive", policy["sdkVersion"], policy["revision"])}/{policy["archives"][arch]["name"]}'
        qualified=CONTRACT.load_qualification_catalog()['builds']
        sources=[r for r in qualified if r['sdkVersion']==policy['sdkVersion'] and r['producerRevision']==policy['producerRevision']]
        require(set(sdk) == sdk_fields and sdk['sdkVersion'] == policy['sdkVersion'] and sdk['revision'] == policy['revision']
                and sdk['sourceManifestSha256'] == policy['sourceManifestSha256'] and sdk['sourceManifest']['sha256'] == policy['sourceManifestSha256']
                and sdk['sourceManifest']['url'] == source_url and type(sdk['sourceManifest']['size']) is int and 0 < sdk['sourceManifest']['size'] <= 16*1024**2
                and len(sources)==1 and sources[0]['sourceManifestSha256']==policy['sourceManifestSha256'] and sdk['producer']==sources[0]['architectures'][arch]
                and sdk['archive']['url'] == archive_url
                and sdk['archiveRoot'] == f'cbodotnet-{policy["sdkVersion"]}-linux-musl-{arch}-r{policy["revision"]}'
                and sdk['targets'] == [dict(policy['target'], rid=sdk['rid'])] and sdk['requiresLegacyProvider'] is False
                and sdk['dependencies'] == sorted(CONTRACT.NATIVE_DEPENDENCIES)
                and sdk['licensePaths'] == ['LICENSE.txt', 'ThirdPartyNotices.txt']
                and sdk['securitySupport'] == 'community-build-no-additional-security-maintenance'
                and {key: sdk['archive'][key] for key in ('size', 'sha256')} == {key: policy['archives'][arch][key] for key in ('size', 'sha256')},
                'Musl SDK target/archive admission differs from reviewed Alpine source')
    if expected_sdks is not None:require(catalog['sdks'] == expected_sdks, 'Musl SDK records differ from authenticated signed source bytes')
    require(isinstance(catalog['tools'], list) and 0 < len(catalog['tools']) <= 64, 'Missing musl installer tools')
    identities = set()
    for tool in catalog['tools']:
        require(set(tool) == {'version', 'rid', 'binary', 'notices'} and tool['rid'] in {row['rid'] for row in ARCHITECTURES.values()}
                and re.fullmatch(r'0\.[0-9]+\.[0-9]+', tool['version']) and tuple(map(int, tool['version'].split('.'))) >= (0, 5, 0)
                and (tool['version'], tool['rid']) not in identities, 'A musl catalog cannot admit glibc or duplicate tool identities')
        identities.add((tool['version'], tool['rid']))
        base=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/cbodotnetup-v{tool["version"]}/cbodotnetup-{tool["rid"]}'
        for key, suffix, maximum in (('binary', '', 128*1024**2), ('notices', '.LICENSE.txt', 8*1024**2)):
            item=tool[key]
            require(set(item) == {'url', 'size', 'sha256'} and item['url'] == base+suffix
                    and type(item['size']) is int and 0 < item['size'] <= maximum and sha(item['sha256']), 'Malformed musl tool immutable descriptor')
    return catalog


def validate_tool_report(report, arch, *, source_inputs=None, version='0.5.1', native_runtime='10.0.14', policy=None):
    policy = policy or load_policy(); target = ARCHITECTURES[arch]
    require(report.get('schemaVersion') == 1 and report.get('kind') == 'cbodotnetup-native-build'
            and report.get('libc') == 'musl' and report.get('version') == version and report.get('architecture') == arch
            and report.get('rid') == target['rid'] and report.get('nativeRuntime') == native_runtime
            and report.get('container') == musl_archive.BASES[arch] and report.get('securityTests') == 'passed',
            'Native musl installer build identity or security tests differ')
    proof = report.get('authenticatedSdk', {})
    require(proof.get('libc') == 'musl' and proof.get('architecture') == arch and proof.get('targetRid') == target['rid']
            and proof.get('publication') == policy['publication'] and proof.get('sourceManifest', {}).get('sha256') == policy['sourceManifestSha256']
            and report.get('buildSdk') == proof.get('archive')
            and {k: proof.get('archive', {}).get(k) for k in ('name', 'size', 'sha256')} == policy['archives'][arch],
            'Native musl installer build SDK is not the authenticated public archive')
    inputs = report.get('sourceInputs', {})
    require(isinstance(inputs, dict) and inputs and all(sha(digest) for digest in inputs.values()), 'Native installer source inventory is missing')
    if source_inputs is not None:
        require({k: v for k, v in inputs.items() if k != 'releases/cbodotnetup-policy.json'} ==
                {k: v for k, v in source_inputs.items() if k != 'releases/cbodotnetup-policy.json'}, 'Native installer source inputs changed')
    chain = report.get('toolchain', {})
    require(report.get('buildInputs') and all(sha(digest) for digest in report['buildInputs'].values())
            and chain.get('baseImage') == musl_archive.BASES[arch] and chain.get('imageId')
            and chain.get('apkInputs') and chain.get('installedPackages') and chain.get('clang') and chain.get('lld')
            and report.get('nativePackages') and report.get('elfAudit', {}).get('status') == 'passed',
            'Native musl installer lacks pinned compiler/package inputs and actual ELF audit')
    from cbodotnetup_retained_musl import validate_build_inputs
    validate_build_inputs(report, arch)
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', chain['imageId'])
            and isinstance(chain['installedPackages'], list) and len(chain['installedPackages']) == len(set(chain['installedPackages']))
            and not any(p.startswith(('gcompat-', 'libc6-compat-')) for p in chain['installedPackages']),
            'Native musl build image identity or installed stock package inventory differs')
    indexes=json.loads(ordinary_file(ROOT / f'profiles/dotnet-10.0.403-linux-musl-{arch}.json').read_bytes())['apkIndexes']
    require(len(chain.get('indexes', [])) == 2
            and {row['sha256'] for row in chain['indexes']} == {row['sha256'] for row in indexes.values()},
            'Native musl build did not retain both exact pinned APK indexes')
    for item in chain['apkInputs']:
        require(set(item) == {'name', 'size', 'sha256'} and re.fullmatch(r'[A-Za-z0-9+_.-]+\.apk', item['name'])
                and type(item['size']) is int and 0 < item['size'] <= 1024**3 and sha(item['sha256']),
                'Native musl compiler APK bytes are not fully recorded')
    packages = report['nativePackages']; identities = set()
    for item in packages:
        identity = (item.get('id'), item.get('version'))
        require(all(isinstance(p, str) and re.fullmatch(r'[A-Za-z0-9+_.-]+', p) for p in identity)
                and identity not in identities and item.get('source') == 'https://api.nuget.org/v3/index.json'
                and item.get('name') == item['id'].lower()+'.'+item['version'].lower()+'.nupkg'
                and type(item.get('size')) is int and 0 < item['size'] <= 1024**3 and sha(item.get('sha256'))
                and isinstance(item.get('sha512'), str) and re.fullmatch(r'[a-f0-9]{128}', item['sha512'])
                and nuget_content_hash(item.get('contentHash'))
                and item.get('downloadHash') == base64.b64encode(bytes.fromhex(item['sha512'])).decode(),
                'NativeAOT package identity, immutable origin or actual byte hashes are incomplete')
        identities.add(identity)
    require(('microsoft.dotnet.ilcompiler', native_runtime) in identities
            and all(v == native_runtime for name, v in identities
                if name == 'microsoft.dotnet.ilcompiler' or name.startswith('runtime.') and '.microsoft.dotnet.ilcompiler' in name),
            'Actual NativeAOT compiler/runtime packages differ from the reviewed version')
    audit=report['elfAudit'];binary='cbodotnetup-'+target['rid']
    entries=[row for row in audit.get('elfFiles', []) if row.get('path') == binary]
    artifacts=[row for row in report.get('artifacts', []) if row.get('path') == binary]
    require(audit.get('schemaVersion') == 1 and audit.get('native') is True and audit.get('libc') == 'musl'
            and audit.get('architecture') == arch and audit.get('targetRid') == target['rid']
            and type(audit.get('hostElfCount')) is int and audit['hostElfCount'] > 0 and audit.get('nonHostElfCount') == 0
            and audit.get('stockLibraries') and len(entries) == len(artifacts) == 1
            and entries[0].get('machine') == CONTRACT.ARCHITECTURES[arch]['elfMachine']
            and entries[0].get('interpreter') == target['interpreter'] and entries[0].get('sha256') == artifacts[0].get('sha256'),
            'Native musl installer ELF audit does not bind the actual native CPU, interpreter and published binary')
    if version == '0.5.0':require(report.get('versionOverride') == '-p:Version=0.5.0', 'Baseline compiler version override is not recorded')
    return report


def validate_qualifications(catalog, observations, *, catalog_sha256, bootstrap_sha256,
                            version='0.5.1', public=False, freeze_sha256=None):
    """Require both exact Alpine CPU proofs before the musl feed can be served."""
    validate_catalog(catalog)
    require(isinstance(observations, list) and len(observations) == 2,
            'Both actual native musl installer reports are required')
    from cbodotnetup_musl_native import validate_runtime_profile_preservation
    seen = set()
    for value in observations:
        arch = value.get('architecture'); target = ARCHITECTURES.get(arch)
        require(target is not None and arch not in seen, 'Duplicate or unreviewed musl installer CPU report')
        seen.add(arch); rid = target['rid']
        tools = [t for t in catalog['tools'] if t['version'] == version and t['rid'] == rid]
        baseline = [t for t in catalog['tools'] if t['version'] == '0.5.0' and t['rid'] == rid]
        require(len(tools) == len(baseline) == 1, 'Current and actual baseline musl tools must remain authenticated')
        require(value.get('schemaVersion') == 1 and value.get('scope') == 'cbodotnetup-native-installation'
                and value.get('status') == 'passed' and value.get('variant') == 'alpine-3.24'
                and value.get('libc') == 'musl' and value.get('rid') == rid and value.get('native') is True
                and value.get('baseImage') == musl_archive.BASES[arch]
                and value.get('checks') == dict.fromkeys(CHECKS, 'passed')
                and value.get('functionalChecks') == dict.fromkeys(musl_archive.FUNCTIONAL_CHECKS, 'passed')
                and value.get('catalogSha256') == catalog_sha256 and value.get('bootstrapSha256') == bootstrap_sha256
                and value.get('binarySha256') == tools[0]['binary']['sha256']
                and value.get('bootstrapBinarySource') == ('public-https' if public else 'protected-frozen-candidate')
                and value.get('networkForBuild') == 'none' and value.get('userId') == 10001
                and value.get('packageManagedCommunityIntegrity') == 'unchanged'
                and value.get('crossLibcStatePreserved') is True,
                'Incomplete native musl installer qualification or frozen/public byte identity')
        if freeze_sha256 is not None:require(value.get('freezeSha256') == freeze_sha256, 'Musl report differs from the exact frozen candidate')
        migration = value.get('migration', {})
        require(migration.get('status') == 'passed'
                and migration.get('protocol') == ('actual-musl-0.5.0-self-update-rollback-reupgrade' if public else 'musl-0.5.0-frozen-bootstrap-migration')
                and migration.get('oldVersion') == '0.5.0' and migration.get('newVersion') == version
                and migration.get('oldBinarySha256') == baseline[0]['binary']['sha256']
                and migration.get('sdkRollback') == migration.get('interruptedOwnershipRecovery') == 'passed',
                'Actual musl tool self-update, rollback and interrupted ownership recovery are required')
        for name in ('elfAudit', 'toolElfAudit'):
            require(value.get(name, {}).get('status') == 'passed', 'Actual native musl SDK/tool ELF audit is required')
        require(value.get('systemTrustHttps', {}).get('status') == 'passed', 'Native musl system-trust HTTPS evidence is required')
        profile=value.get('runtimeProfilePreservation')
        require(isinstance(profile,dict), 'Native musl SDK runtime profile preservation evidence is required')
        validate_runtime_profile_preservation(profile)
        profile_root=profile['originalInventory']['.']
        marker=profile['originalInventory'].get('preservation-only.txt',{})
        preserved=b'Unrelated retained state; not an executable SDK fixture.\n'
        require(profile_root.get('type')=='directory' and profile_root.get('uid')==profile_root.get('gid')==10001
                and marker.get('type')=='file' and marker.get('uid')==marker.get('gid')==10001
                and marker.get('size')==len(preserved) and marker.get('sha256')==hashlib.sha256(preserved).hexdigest(),
                'Native musl runtime preservation proof omits the original unrelated state marker')
    return observations
