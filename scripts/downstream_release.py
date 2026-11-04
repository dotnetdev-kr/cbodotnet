#!/usr/bin/env python3
"""Receive qualified releases and stage authenticated downstream evidence locally."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import urllib.request

from distribution_contract import candidate_target, load_contract, sha256_file, validate_qualified_producers, verified_plan
from release_catalog import get_bytes, MAX_CHECKSUM_BYTES, MAX_JSON_BYTES, validate_release

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
IDENTITY_FIELDS = ('sdkVersion', 'targetRid', 'sourceReleaseTag', 'sourceManifestSha256',
                   'channel', 'variant', 'packageRevision')
PREPUBLICATION_CHECKS = {
    'source-integrity', 'payload-preservation', 'native-dependencies', 'host-root',
    'offline-build-run', 'http-crypto-globalization', 'non-root',
    'official-dotnet-coexistence', 'upgrade', 'removal', 'command-aliases',
    'cli-branding', 'version-stdout-compatible',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def ordinary_file(value):
    path = Path(value).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary, non-linked file is required: ' + str(path))
    return path


def descriptor(value):
    path = ordinary_file(value)
    require(0 < path.stat().st_size < 2**31, 'Artifact must be nonempty and smaller than 2 GiB')
    return {'name': path.name, 'size': path.stat().st_size, 'sha256': sha256_file(path)}


def write_immutable(path, value):
    path = Path(path).absolute()
    require(path.parent.is_dir() and not any(p.is_symlink() for p in [path, *path.parents]),
            'An ordinary existing ledger directory is required')
    data = encoded(value)
    if path.exists():
        require(ordinary_file(path).read_bytes() == data, 'Conflicting existing immutable record: ' + path.name)
        return path
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.stage-', delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    try:
        # Linking exposes a complete file while refusing concurrent replacement.
        try:
            os.link(temporary, path)
        except FileExistsError:
            require(ordinary_file(path).read_bytes() == data, 'Conflicting concurrent immutable record')
    finally:
        temporary.unlink()
    return path


def local_intake(directory, channel, variant, arch, revision=1, contract=None, catalog=None):
    directory = Path(directory)
    manifest = ordinary_file(directory / 'release-manifest.json').read_bytes()
    version = json.loads(manifest)['sdkVersion']
    require(re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version), 'Invalid SDK version')
    require(arch in {'x64', 'aarch64'}, 'Unknown public architecture')
    return verified_plan(json.loads(ordinary_file(directory / 'release.json').read_bytes()), manifest,
                         ordinary_file(directory / 'SHA256SUMS').read_bytes(),
                         directory / f'cbodotnet-sdk-{version}-linux-{arch}.tar.gz',
                         channel, variant, arch, revision, contract=contract, catalog=catalog)


def receive_release(tag, directory, channel, variant, arch, revision=1):
    """Download public release assets, preserving matching retries and rejecting conflicts."""
    contract = load_contract()
    require(isinstance(tag, str) and re.fullmatch(r'sdk-[1-9][0-9]*\.[0-9]+\.[0-9]+', tag),
            'An exact stable sdk-X.Y.Z release tag is required')
    version = tag[4:]
    require(version in contract['releases'], 'Release is not admitted by the reviewed distribution contract')
    require(arch in contract['architectures'], 'Unknown public architecture')
    policy = contract['channels'].get(channel, {})
    require(policy.get('status') == 'preparation-only' and variant in policy.get('variants', []),
            'Unsupported or deferred channel/variant')
    candidate_target(contract, version, channel, variant, arch)
    directory = Path(directory).absolute()
    require(not any(p.is_symlink() for p in [directory, *directory.parents]), 'Unsafe intake directory')
    directory.mkdir(parents=True, exist_ok=True)
    release_bytes = get_bytes(f'https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}', MAX_JSON_BYTES,
                              token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'), api=True)
    release = json.loads(release_bytes)
    base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    manifest = get_bytes(base + 'release-manifest.json', MAX_JSON_BYTES)
    require(hashlib.sha256(manifest).hexdigest() == contract['releases'][version]['manifestSha256'],
            'Pinned source manifest digest mismatch')
    checksums = get_bytes(base + 'SHA256SUMS', MAX_CHECKSUM_BYTES)
    record = validate_release(release, manifest, checksums, REPOSITORY)
    require(record['sdkVersion'] == version, 'Release SDK version differs from the requested tag')
    validate_qualified_producers(record, contract['releases'][version]['target'])
    sdk = record['architectures'][arch]['sdk']
    destination = directory / sdk['name']
    if destination.exists():
        require(descriptor(destination) == {key: sdk[key] for key in ('name', 'size', 'sha256')},
                'Conflicting existing SDK archive')
    else:
        partial = directory / (sdk['name'] + '.partial')
        require(not partial.exists() and not partial.is_symlink(), 'An incomplete download already exists; inspect it first')
        digest = hashlib.sha256()
        total = 0
        with urllib.request.urlopen(sdk['url'], timeout=60) as incoming, partial.open('xb') as output:
            while True:
                block = incoming.read(4 * 1024 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= sdk['size'], 'Downloaded SDK exceeds its qualified size')
                digest.update(block)
                output.write(block)
        require(total == sdk['size'] and digest.hexdigest() == sdk['sha256'], 'Downloaded SDK size or digest mismatch')
        try:
            os.link(partial, destination)
        except FileExistsError:
            require(descriptor(destination) == {key: sdk[key] for key in ('name', 'size', 'sha256')},
                    'Conflicting concurrently received SDK archive')
        partial.unlink()
    for name, data in [('release.json', release_bytes), ('release-manifest.json', manifest), ('SHA256SUMS', checksums)]:
        path = directory / name
        if path.exists():
            # API counters can change, while the manifest and checksums cannot.
            if name != 'release.json':
                require(ordinary_file(path).read_bytes() == data, 'Conflicting existing release metadata')
        else:
            with path.open('xb') as output:
                output.write(data)
    return local_intake(directory, channel, variant, arch, revision)


def orchestration_identity(value):
    require(isinstance(value, dict) and value.get('repository') == REPOSITORY
            and re.fullmatch(r'\.github/workflows/[a-z0-9-]+\.yml', value.get('workflow', ''))
            and re.fullmatch(r'[a-f0-9]{40}', value.get('commit', ''))
            and all(not isinstance(value.get(key), bool) and re.fullmatch(r'[1-9][0-9]*', str(value.get(key)))
                    for key in ('runId', 'runAttempt')), 'Invalid immutable downstream workflow identity')
    return value


def verified_extra_files(root, inventory, commands, identity):
    root = Path(root).absolute()
    require(root.is_dir() and not any(p.is_symlink() for p in [root, *root.parents]), 'An ordinary command staging root is required')
    require(isinstance(inventory, list) and inventory, 'Generated command inventory is required')
    series = '.'.join(identity['sdkVersion'].split('.')[:2])
    sdk_owner = 'cbodotnet-sdk-' + series
    expected = {commands['versioned']: sdk_owner, commands['default']: commands['defaultOwner']}
    if identity['channel'] == 'oci':
        expected.update({commands['containerDirectory'] + '/' + name: sdk_owner
                         for name in ('cbodotnet-' + series, 'cbodotnet', 'dotnet')})
    require(len(inventory) == len(expected) and {row.get('path') for row in inventory} == set(expected),
            'Generated command inventory is incomplete or has a namespace collision')
    for row in inventory:
        name = row['path']
        relative = PurePosixPath(name)
        require(relative.is_absolute() and str(relative) == name and '..' not in relative.parts
                and not any(c in name for c in '\\:\0\r\n'), 'Unsafe command inventory path')
        path = ordinary_file(root / name.lstrip('/'))
        require(root in path.parents and descriptor(path) == {'name': path.name, 'size': row.get('size'), 'sha256': row.get('sha256')}
                and row.get('mode') == '0755' and stat.S_IMODE(path.stat().st_mode) == 0o755
                and row.get('owner') == expected[name], 'Generated command bytes, permissions or ownership changed')
    return sorted(inventory, key=lambda row: row['path'])


def package_record(plan, artifact_path, orchestration, extra_files=None):
    """Record an already-created artifact; this does not run a packager or signer."""
    require(plan.get('status') == 'prepared-unqualified' and plan.get('publicationAllowed') is False,
            'A freshly verified preparation plan is required')
    identity = {key: plan[key] for key in IDENTITY_FIELDS}
    inventory = (verified_extra_files(extra_files['root'], extra_files['inventory'], plan['commands'], identity)
                 if extra_files is not None else [])
    result = {'schemaVersion': 1, 'contractVersion': plan['contractVersion'],
            'status': 'packaged-unqualified', 'identity': identity,
            'architecture': plan['architecture']['public'], 'producer': plan['producer'],
            'branding': plan['branding'], 'commands': plan['commands'], 'extraFiles': inventory,
            'source': {key: plan[key] for key in ('sdk', 'source', 'evidence', 'sourceManifestUrl', 'licensePaths', 'securitySupport')},
            'artifact': descriptor(artifact_path), 'orchestration': orchestration_identity(orchestration),
            'publicationAllowed': False}
    if 'nativeCaBundle' in plan:
        result['runtimeCaBundle'] = plan['nativeCaBundle']
    return result


def load_status(path=None):
    value = json.loads(Path(path or ROOT / 'releases/downstream-status.json').read_bytes())
    require(value.get('schemaVersion') == 1 and value.get('repository') == REPOSITORY,
            'Unsupported downstream policy/status')
    return value


def validate_legacy_evidence(report, plan):
    """Do not promote legacy runtime results without the reviewed external provider."""
    if not plan['sdkVersion'].startswith(('3.', '5.')):
        return
    from legacy_compat import POLICY, PROVIDER_ROOT, FINGERPRINT
    expected_policy = hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest()
    proofs = report.get('compatibilityProvider')
    require(isinstance(proofs, list) and proofs, 'Legacy report lacks managed compatibility provider evidence')
    for proof in proofs:
        require(proof.get('status') == 'passed' and proof.get('providerRoot') == PROVIDER_ROOT
                and proof.get('architecture') == plan['architecture']['public']
                and proof.get('policySha256') == expected_policy and proof.get('signingFingerprint') == FINGERPRINT
                and re.fullmatch(r'[a-f0-9]{64}', proof.get('treeSha256', '')),
                'Legacy runtime provider source, policy or native architecture differs')


def require_published_provider_roots(plan):
    """Public installation proofs must never repair missing published libraries."""
    if not plan['sdkVersion'].startswith(('3.', '5.')):
        return
    from legacy_compat import PROVIDER_ROOT
    roots = [PROVIDER_ROOT]
    if plan['sdkVersion'].startswith('3.'):
        from legacy_curl import PROVIDER_ROOT as curl_root
        roots.append(curl_root)
    for value in roots:
        path = Path(value)
        require(path.is_dir() and not any(item.is_symlink() for item in [path, *path.parents]),
                'Published provider root is missing or linked; local preparation cannot repair it: ' + value)


def validate_native_curl_evidence(report, plan, *, sdk_root=None, provider_root=None):
    """Core3 promotion requires its real selectable native HTTP and HTTPS path."""
    if not plan['sdkVersion'].startswith('3.'):
        return
    import legacy_curl as provider
    arch = plan['architecture'] if isinstance(plan['architecture'], str) else plan['architecture']['public']
    policy = provider.load_policy()
    expected_policy = hashlib.sha256(provider.POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest()
    root = provider_root or provider.PROVIDER_ROOT
    proofs = report.get('nativeHttpCompatibilityProvider')
    require(isinstance(proofs, list) and proofs and all(isinstance(stage, dict) for stage in proofs),
            'Core3 report lacks native HTTP compatibility provider evidence')
    for stage in proofs:
        proof = stage.get('result', stage)
        require(isinstance(proof, dict) and proof.get('status') == 'passed' and proof.get('required') is True
                and proof.get('providerRoot') == root and proof.get('architecture') == arch
                and proof.get('policySha256') == expected_policy
                and proof.get('signingFingerprint') == provider.FINGERPRINT
                and proof.get('sourcePackages') == policy['architectures'][arch]['packages']
                and proof.get('sourceRpmPackages') == policy['sources']
                and re.fullmatch(r'[a-f0-9]{64}', proof.get('treeSha256', '')),
                'Core3 native HTTP provider source, policy, inventory or native architecture differs')
    result = report.get('nativeCurlHandler', {})
    expected_user = 1654 if plan.get('channel') == 'oci' else 10001
    require(isinstance(result, dict) and result.get('status') == 'passed' and result.get('handler') == 'CurlHandler'
            and all(result.get(name) == 'passed' for name in ('http', 'https', 'httpsDefaultTrust', 'tls12'))
            and type(result.get('callbackCount')) is int and result['callbackCount'] >= 1
            and result.get('network') == 'none' and result.get('userId') == expected_user,
            'Core3 requires actual non-root offline forced-Curl HTTP, callback HTTPS and standard-trust TLS1.2')
    pins = provider.runtime_pins(plan)
    sdk_root = sdk_root or plan.get('package', {}).get('root') or '/opt/cbodotnet/' + '.'.join(plan['sdkVersion'].split('.')[:2])
    expected_http = dict(pins['nativeHttp'], path=sdk_root.rstrip('/') + '/' + pins['nativeHttp']['path'])
    expected_curl = dict(pins['curl'], path=root.rstrip('/') + '/' + pins['curl']['path'])
    require(result.get('nativeHttp') == expected_http and result.get('curl') == expected_curl,
            'Core3 native HTTP or libcurl bytes/path differ from the reviewed source pins')
    mappings = result.get('nativeMappings')
    require(isinstance(mappings, list) and mappings and all(isinstance(row, str) for row in mappings),
            'Core3 native HTTP execution lacks actual loaded-library mappings')
    loaded = {re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), row.split(None, 5)[5])
              for row in mappings if len(row.split(None, 5)) == 6}
    require({expected_http['path'], expected_curl['path']} <= loaded,
            'Core3 forced handler did not load the reviewed native HTTP and private libcurl libraries')


def validate_native_ca_evidence(report, plan):
    """Require the reviewed Fedora trust path and actual ordinary HTTPS trust."""
    if not plan['sdkVersion'].startswith(('3.', '5.')) or plan.get('variant') != 'fedora-45':
        return
    expected = load_contract()['operatingSystems']['fedora-45']['nativeCaBundle']
    proof = report.get('nativeCaBundle')
    require(report.get('runtimeCaBundle') == expected and isinstance(proof, dict)
            and proof.get('path') == expected and isinstance(proof.get('sha256'), str)
            and re.fullmatch(r'[a-f0-9]{64}', proof['sha256'])
            and proof.get('defaultTrustHttps') == 'passed' and proof.get('network') == 'none'
            and proof.get('userId') == 10001 and proof.get('package') == 'ca-certificates'
            and isinstance(proof.get('version'), str) and proof['version'].strip(),
            'Legacy Fedora requires the reviewed stock CA bundle and actual non-root offline default-trust HTTPS')
    dependencies = report.get('target', {}).get('dependencies', {})
    if 'ca-certificates' in dependencies:
        require(proof['version'] == dependencies['ca-certificates'],
                'Fedora CA proof differs from the observed stock dependency version')


def oci_wrapper_license():
    return dict(path='/usr/share/licenses/cbodotnet-host/LICENSE', sha256=sha256_file(ROOT / 'LICENSE'))


def validate_oci_wrapper_license(report, plan):
    """New OCI promotions must prove the added launchers' project MIT notice."""
    if plan['channel'] != 'oci':
        return
    expected = dict(oci_wrapper_license(), ownership='0:0:644', status='passed')
    require(report.get('checks', {}).get('image-wrapper-license') == 'passed'
            and report.get('imageFiles', {}).get('wrapperLicense') == expected
            and report.get('imageUpgradeFiles', {}).get('wrapperLicense') == expected,
            'New OCI promotion lacks the unchanged project wrapper license in both tested images')


def verify_report_signature(report_path, signature_path, keyring_path, policy, workflow, gpgv='gpgv', *, historical=False):
    """Authenticate exact bytes; historical reads never authorize new promotion."""
    report, signature, keyring = map(ordinary_file, (report_path, signature_path, keyring_path))
    require(policy.get('evidenceSigners'), 'No trusted downstream evidence signer is configured')
    result = subprocess.run([gpgv, '--status-fd', '1', '--keyring', str(keyring), str(signature), str(report)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    lines = [line.split()[1:] for line in result.stdout.splitlines() if line.startswith('[GNUPG:] ')]
    valid = [parts for parts in lines if parts and parts[0] == 'VALIDSIG']
    require(result.returncode == 0 and len(valid) == 1 and len(valid[0]) >= 11,
            'Report signature did not independently verify')
    invalid = {'BADSIG', 'ERRSIG', 'REVKEYSIG', 'KEYREVOKED'}
    if not historical:
        invalid |= {'EXPKEYSIG', 'EXPSIG'}
    require(not any(parts and parts[0] in invalid for parts in lines),
            'Report signer or signature is revoked, expired or invalid')
    fields = valid[0]
    fingerprint = fields[10].upper()
    require(re.fullmatch(r'[A-F0-9]{40,64}', fingerprint), 'Invalid verified signer fingerprint')
    signer = policy['evidenceSigners'].get(fingerprint, {})
    now = datetime.now(timezone.utc)
    try:
        start = datetime.fromisoformat(signer['notBefore'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(signer['notAfter'].replace('Z', '+00:00'))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Signer has no valid reviewed trust window') from error
    require(start.tzinfo is not None and end.tzinfo is not None and start < end,
            'Signer has no valid reviewed trust window')
    require(re.fullmatch(r'[0-9]+', fields[3]) and re.fullmatch(r'[0-9]+', fields[4]),
            'Invalid independently verified signature timestamp')
    try:
        signed_at = datetime.fromtimestamp(int(fields[3]), timezone.utc)
        signature_expiry = int(fields[4])
    except (ValueError, OverflowError, OSError) as error:
        raise ValueError('Invalid independently verified signature timestamp') from error
    require(signed_at <= now, 'Signature creation timestamp is in the future')
    if historical:
        require(signer.get('state') in {'active', 'retired'} and start <= signed_at < end
                and signer.get('workflow') == workflow,
                'Historical signature was not authorized at its verified creation time')
        for parts in lines:
            if parts and parts[0] == 'KEYEXPIRED':
                require(len(parts) == 2 and re.fullmatch(r'[0-9]+', parts[1])
                        and int(parts[1]) > signed_at.timestamp(), 'Signing key was expired at signature creation')
        expiry_reference = signed_at.timestamp()
    else:
        require(signer.get('state') == 'active' and start <= now < end and signer.get('workflow') == workflow,
                'Evidence signer is not active or not authorized for this workflow')
        expiry_reference = now.timestamp()
    require(fields[8] in {'8', '9', '10', '11'} and (signature_expiry == 0 or signature_expiry > expiry_reference),
            'Report signature uses an expired signature or unsupported digest')
    return fingerprint


def validate_record(packaged, artifact_path, report_path, signature_path, keyring_path, policy=None, contract=None, catalog=None, commands_root=None, inputs_directory=None):
    policy = policy if policy is not None else load_status()
    contract = contract if contract is not None else load_contract()
    require(packaged.get('schemaVersion') == 1 and packaged.get('status') == 'packaged-unqualified',
            'A packaged record is required')
    require(packaged.get('contractVersion') == contract['schemaVersion'],
            'Packaged contract version differs from the reviewed contract')
    require(descriptor(artifact_path) == packaged['artifact'], 'Packaged artifact changed before validation')
    require(commands_root is not None and packaged.get('extraFiles'), 'Real generated command files and inventory are required')
    require(packaged.get('branding') == contract['branding'], 'Packaged CLI branding does not match the reviewed contract')
    series = '.'.join(packaged['identity']['sdkVersion'].split('.')[:2])
    installation = contract['installation']
    expected_commands = {'versioned': installation['launcherTemplate'].format(series=series),
                         'default': installation['defaultLauncher'], 'defaultOwner': installation['commonPackage'],
                         'defaultSelection': installation['defaultSelection'],
                         'containerDirectory': installation['containerCommandDirectory'],
                         'containerDotnet': installation['containerCommandDirectory'] + '/dotnet'}
    require(packaged.get('commands') == expected_commands, 'Command namespace differs from the reviewed contract')
    verified_extra_files(commands_root, packaged['extraFiles'], packaged['commands'], packaged['identity'])
    workflow = orchestration_identity(packaged['orchestration'])
    require(inputs_directory is not None, 'Canonical qualified-release inputs are required at validation/staging')
    identity = packaged['identity']
    canonical_plan = local_intake(inputs_directory, identity['channel'], identity['variant'], packaged['architecture'],
                                  identity['packageRevision'], contract=contract, catalog=catalog)
    canonical_package = package_record(canonical_plan, artifact_path, workflow,
                                       extra_files={'root': commands_root, 'inventory': packaged['extraFiles']})
    require(packaged == canonical_package, 'Packaged source/provenance differs from canonical qualified release inputs')
    report_path, signature_path = map(ordinary_file, (report_path, signature_path))
    require(report_path.stat().st_size <= MAX_JSON_BYTES and signature_path.stat().st_size <= MAX_JSON_BYTES,
            'Signed report or signature exceeds its size limit')
    report_bytes, signature_bytes = report_path.read_bytes(), signature_path.read_bytes()
    # Verify private snapshots of precisely the bytes parsed below, never a
    # file that can change between external signature checking and JSON reads.
    with tempfile.TemporaryDirectory(prefix='cbodotnet-evidence-') as temporary:
        report_copy, signature_copy = Path(temporary) / 'report.json', Path(temporary) / 'report.sig'
        report_copy.write_bytes(report_bytes)
        signature_copy.write_bytes(signature_bytes)
        fingerprint = verify_report_signature(report_copy, signature_copy, keyring_path, policy, workflow['workflow'])
    report = json.loads(report_bytes)
    require(report.get('schemaVersion') == 1 and report.get('phase') == 'prepublication'
            and report.get('status') == 'passed' and report.get('scope') == 'channel-installation',
            'A complete real-channel installation report is required; private-prefix checks cannot promote')
    for field in ('contractVersion', 'identity', 'artifact', 'producer', 'orchestration', 'branding', 'commands', 'extraFiles', 'source'):
        require(report.get(field) == packaged[field], 'Report does not bind the packaged ' + field)
    if 'runtimeCaBundle' in packaged:
        require(report.get('runtimeCaBundle') == packaged['runtimeCaBundle'], 'Report does not bind the packaged runtime CA bundle')
    identity = packaged['identity']
    require(set(identity) == set(IDENTITY_FIELDS), 'Incomplete publication identity')
    require(type(identity['packageRevision']) is int and identity['packageRevision'] > 0, 'Invalid package revision')
    release = contract['releases'].get(identity['sdkVersion'], {})
    require(release.get('manifestSha256') == identity['sourceManifestSha256']
            and identity['sourceReleaseTag'] == 'sdk-' + identity['sdkVersion'], 'Unadmitted source release identity')
    if catalog is None:
        catalog = json.loads((ROOT / 'releases/qualified-builds.json').read_bytes())
    producers = [row for row in catalog.get('builds', []) if row.get('sdkVersion') == identity['sdkVersion']]
    require(catalog.get('repository') == REPOSITORY and len(producers) == 1
            and producers[0].get('target') == release['target'], 'Unqualified source producer')
    producer = producers[0].get('architectures', {}).get(packaged['architecture'], {})
    require(producer and all(str(packaged['producer'].get(key)) == str(producer.get(key))
                             for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')),
            'Packaged producer differs from qualified catalog')
    target = report.get('target', {})
    os_record = contract['operatingSystems'].get(identity['variant'], {})
    require(os_record and target.get('osId') == os_record['id'] and target.get('versionId') == os_record['versionId']
            and target.get('architecture') == packaged['architecture'] and target.get('native') is True
            and identity['targetRid'] == contract['architectures'][packaged['architecture']]['rid'],
            'Report executed on the wrong OS/version or native architecture')
    dependencies = target.get('dependencies', {})
    require(all(isinstance(dependencies.get(name), str) and dependencies[name] for name in canonical_plan['dependencies']),
            'Report has unavailable or unrecorded native libraries')
    channel = policy['channels'].get(identity['channel'], {})
    validate_legacy_evidence(report, canonical_plan)
    validate_native_curl_evidence(report, canonical_plan)
    validate_native_ca_evidence(report, canonical_plan)
    validate_oci_wrapper_license(report, canonical_plan)
    checks = PREPUBLICATION_CHECKS | set(channel.get('requiredChecks', []))
    require(checks and all(report.get('checks', {}).get(name) == 'passed' for name in checks),
            'Required prepublication matrix check failed or is missing')
    return {**packaged, 'status': 'validated-unpublished',
            'report': {'name': report_path.name, 'size': len(report_bytes), 'sha256': hashlib.sha256(report_bytes).hexdigest()},
            'signature': {'name': signature_path.name, 'size': len(signature_bytes), 'sha256': hashlib.sha256(signature_bytes).hexdigest()},
            'evidenceSigner': fingerprint}


def stage_records(items, ledger_directory, policy=None, contract=None, catalog=None):
    """Reauthenticate every report and atomically record one complete local matrix."""
    policy = policy if policy is not None else load_status()
    contract = contract if contract is not None else load_contract()
    require(isinstance(items, list) and items, 'A complete matrix is required')
    records = [validate_record(item['package'], item['artifactPath'], item['reportPath'],
                               item['signaturePath'], item['keyringPath'], policy, contract, catalog,
                               commands_root=item.get('commandsRoot'), inputs_directory=item.get('inputsDirectory')) for item in items]
    first = records[0]['identity']
    common = ('sdkVersion', 'sourceReleaseTag', 'sourceManifestSha256', 'channel', 'packageRevision')
    require(all(all(record['identity'][key] == first[key] for key in common) for record in records),
            'A staging transaction must contain one channel/version/revision/source')
    expected = policy['channels'].get(first['channel'], {}).get('candidateMatrix', [])
    require(expected, 'No reviewed candidate matrix is configured')
    actual = [(record['identity']['variant'], record['architecture']) for record in records]
    require(len(set(actual)) == len(actual) and set(actual) == {(row['variant'], row['architecture']) for row in expected},
            'Partial, duplicate or unexpected advertised matrix; nothing may be staged')
    records.sort(key=lambda row: (row['identity']['variant'], row['architecture']))
    staged = {'schemaVersion': 1, 'contractVersion': contract['schemaVersion'], 'status': 'staged-unpublished',
              'identity': {key: first[key] for key in common}, 'records': records, 'publicationAllowed': False}
    name = f"{first['channel']}-{first['sdkVersion']}-r{first['packageRevision']}.json"
    require(re.fullmatch(r'(deb|oci|rpm|aur)-[0-9.]+-r[1-9][0-9]*\.json', name), 'Unsafe staging identity')
    write_immutable(Path(ledger_directory) / name, staged)
    return staged


def publish(staged, policy=None, bundle_directory=None, keyring_path=None, target_commit=None, gh='gh'):
    policy = policy if policy is not None else load_status()
    channel = staged.get('identity', {}).get('channel')
    require(staged.get('status') == 'staged-unpublished', 'A complete staged matrix is required')
    require(channel in policy.get('channels', {}), 'Unknown publisher')
    require(policy['channels'][channel].get('publisherConfigured') is True,
            'Publisher adapter is not configured: ' + channel + '; no remote publication was performed')
    require(bundle_directory is not None and keyring_path is not None,
            'A complete signed publication bundle and trusted public keyring are required')
    from downstream_publish import publish_bundle, validate_bundle
    manifest = validate_bundle(bundle_directory, keyring_path, target_commit, policy)
    require(manifest['identity'] == staged['identity'], 'Signed bundle differs from staged channel identity')
    return publish_bundle(bundle_directory, keyring_path, target_commit, policy, gh)
