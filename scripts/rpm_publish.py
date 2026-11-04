"""Protected RPM signing and immutable promotion using the common release gates."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from channel_packages import build_repositories, HOST_VERSION, rpm_release
from distribution_contract import load_contract, sha256_file
from downstream_release import (descriptor, encoded, load_status, local_intake, package_record, require, PREPUBLICATION_CHECKS,
                                verify_report_signature)
from downstream_publish import create_bundle, publish_bundle, validate_bundle, release_tag
from rpm_repository import asset_base, verify_repository

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rpm_distribution_core', ROOT / 'scripts/distribution-ci.py')
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)


def inspect_common(received, output):
    """Retain small unsigned RPMs and exact native differences for diagnosis."""
    received, output = Path(received).resolve(), Path(output).resolve()
    require(not output.exists() and output.parent.is_dir(), 'Fresh common RPM inspection output required')
    items = CORE.unpack_deliveries(received)
    output.mkdir()
    packages, headers, leads = [], {}, {}
    for item in items:
        identity = item['package']['identity']
        variant, architecture = identity['variant'], item['package']['architecture']
        require(re.fullmatch(r'[a-z][a-z0-9]*-[1-9][0-9]*(?:\.[0-9]+)?', variant)
                and architecture in {'x64', 'aarch64'}, 'Unsafe common RPM inspection identity')
        build_path = Path(item['artifactPath']).parent / 'package-build.json'
        require(received in build_path.absolute().parents, 'Common RPM build record escapes native transport')
        build = json.loads(build_path.read_bytes())
        hosts = [row for row in build['packages'] if row['kind'] == 'host']
        require(len(hosts) == 1 and re.fullmatch(r'cbodotnet-host-[A-Za-z0-9._+-]+\.rpm', hosts[0]['path']),
                'One ordinary common RPM is required')
        host = hosts[0]
        source = build_path.parent / host['path']
        require(descriptor(source) == {'name': host['path'], 'size': host['size'], 'sha256': host['sha256']},
                'Common RPM changed before inspection')
        name = variant + '-' + architecture + '--' + host['path']
        require(not (output / name).exists(), 'Duplicate common RPM inspection target')
        shutil.copyfile(source, output / name)
        text = CORE.run(['rpm', '--query', '--package', '--xml', source])
        (output / (name + '.xml')).write_text(text, encoding='utf-8')
        root = ET.fromstring('<headers>' + text + '</headers>')
        headers[(variant, architecture)] = {row.attrib['name']: ET.tostring(row, encoding='unicode')
            for row in root.iter() if 'name' in row.attrib}
        leads[(variant, architecture)] = source.read_bytes()[:96]
        payload = subprocess.check_output(['rpm2cpio', str(source)])
        packages.append(dict(variant=variant, architecture=architecture, **descriptor(output / name),
                             cpioSha256=hashlib.sha256(payload).hexdigest()))
    differences = []
    for variant in sorted({row['variant'] for row in packages}):
        selected = [row for row in packages if row['variant'] == variant]
        if len(selected) != 2 or {row['architecture'] for row in selected} != {'x64', 'aarch64'}:
            differences.append(dict(variant=variant, error='Incomplete common native RPM matrix'))
            continue
        if len({row['sha256'] for row in selected}) != 1:
            left, right = headers[(variant, 'x64')], headers[(variant, 'aarch64')]
            differences.append(dict(variant=variant,
                headers={key: dict(x64=left.get(key), aarch64=right.get(key))
                         for key in sorted(set(left) | set(right)) if left.get(key) != right.get(key)},
                leadDifferences=[dict(offset=index, x64=a, aarch64=b) for index, (a, b) in
                    enumerate(zip(leads[(variant, 'x64')], leads[(variant, 'aarch64')])) if a != b],
                payloadIdentical=len({row['cpioSha256'] for row in selected}) == 1))
    result = dict(schemaVersion=1, status='failed' if differences else 'passed', packages=packages, differences=differences)
    (output / 'common-inspection.json').write_bytes(encoded(result))
    require(packages and not differences, 'Common native RPM bytes differ; see common-inspection.json')
    return result


def protected():
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_REPOSITORY') == 'dotnetdev-kr/cbodotnet'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_WORKFLOW_REF') ==
                'dotnetdev-kr/cbodotnet/.github/workflows/distribution-release.yml@refs/heads/main',
            'Only the protected main distribution workflow may sign or publish')


def source_identity(run_id, attempt):
    require(re.fullmatch(r'[1-9][0-9]*', str(run_id)) and re.fullmatch(r'[1-9][0-9]*', str(attempt)),
            'An exact native source run and attempt are required')
    metadata = json.loads(CORE.run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{run_id}']))
    require(metadata.get('head_branch') == 'main' and metadata.get('event') == 'workflow_dispatch'
            and metadata.get('path') == '.github/workflows/distribution-release.yml'
            and metadata.get('repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet'
            and metadata.get('head_repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet'
            and re.fullmatch(r'[a-f0-9]{40}', metadata.get('head_sha', '')),
            'RPM native artifacts must originate from the trusted main workflow')
    jobs = json.loads(CORE.run(['gh', 'api',
        f'repos/dotnetdev-kr/cbodotnet/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100']))['jobs']
    for arch in ('x64', 'aarch64'):
        selected = [row for row in jobs if row['name'] == 'Install RPM packages on native ' + arch]
        require(len(selected) == 1 and selected[0].get('conclusion') == 'success', 'Complete native RPM matrix did not pass')
    return dict(repository='dotnetdev-kr/cbodotnet', workflow='.github/workflows/distribution-release.yml',
                commit=metadata['head_sha'], runId=str(run_id), runAttempt=str(attempt))


def verify_rpm_signature(package, keyring, fingerprint, database):
    database.mkdir(mode=0o700, exist_ok=True)
    CORE.run(['rpm', '--dbpath', database, '--initdb'])
    public = CORE.run(['gpg', '--batch', '--no-default-keyring', '--keyring', keyring, '--armor', '--export', fingerprint])
    require(public.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'), 'Pinned RPM public identity is absent')
    armored_key = database / 'pinned.asc'
    armored_key.write_text(public)
    CORE.run(['rpmkeys', '--dbpath', database, '--import', armored_key])
    status = CORE.run(['rpmkeys', '--dbpath', database, '--checksig', '--verbose', package])
    require(re.search(r'\bsignature\b[^\n]*:\s*OK\s*$', status, re.IGNORECASE | re.MULTILINE)
            and not re.search(r'\b(?:NOKEY|NOT\s+OK|NOTFOUND|NOTTRUSTED|BAD|FAILED)\b', status, re.IGNORECASE),
            'RPM package signature failed independently')
    # This private database contains only the repository-owned reviewed key.
    return {'signingFingerprint': fingerprint, 'status': 'passed', 'verification': status.strip()}


def preflight(item, received, identity, policy, contract):
    """Admit every native report and unsigned RPM before the signer is used."""
    require(item['package']['orchestration'] == identity, 'RPM evidence belongs to another source workflow run')
    for key in ('packagePath', 'artifactPath', 'reportPath', 'commandsRoot', 'inputsDirectory'):
        path = Path(item[key]).absolute()
        require(received in path.parents and not any(parent.is_symlink() for parent in [path, *path.parents]),
                'RPM native delivery path escapes its verified transport')
    packaged = item['package']
    plan = local_intake(item['inputsDirectory'], 'rpm', packaged['identity']['variant'],
                        packaged['architecture'], packaged['identity']['packageRevision'])
    canonical = package_record(plan, item['artifactPath'], identity,
                               extra_files={'root': item['commandsRoot'], 'inventory': packaged['extraFiles']})
    require(canonical == packaged, 'RPM source or command bytes differ from canonical qualified inputs')
    report = json.loads(Path(item['reportPath']).read_bytes())
    require(report.get('schemaVersion') == 1 and report.get('phase') == 'prepublication'
            and report.get('scope') == 'channel-installation' and report.get('status') == 'passed'
            and all(report.get(key) == packaged[key] for key in
            ('contractVersion', 'identity', 'artifact', 'source', 'producer', 'orchestration', 'branding', 'commands', 'extraFiles')),
            'Native RPM report does not bind its actual package and source')
    target, operating_system = report.get('target', {}), contract['operatingSystems'][plan['variant']]
    require(target.get('native') is True and target.get('osId') == operating_system['id']
            and target.get('versionId') == operating_system['versionId']
            and target.get('architecture') == plan['architecture']['public']
            and all(isinstance(target.get('dependencies', {}).get(name), str) and target['dependencies'][name]
                    for name in operating_system['dependencies']), 'RPM report lacks the required native target and libraries')
    checks = PREPUBLICATION_CHECKS | set(policy['channels']['rpm'].get('requiredChecks', []))
    checks -= {'package-signatures', 'repository-metadata'}
    require(all(report.get('checks', {}).get(name) == 'passed' for name in checks),
            'Required native RPM check is missing or failed before signing')
    from downstream_release import validate_legacy_evidence
    validate_legacy_evidence(report, plan)
    build_path = Path(item['artifactPath']).parent / 'package-build.json'
    build = json.loads(build_path.read_bytes())
    require(build.get('schemaVersion') == 1 and build.get('channel') == 'rpm'
            and build.get('plan') == plan and build.get('payloadPreserved') is True,
            'RPM package build differs from its canonical plan')
    legacy = plan['sdkVersion'].startswith(('3.', '5.'))
    kinds = {'sdk', 'host', 'compatibility'} if legacy else {'sdk', 'host'}
    native_http = plan['sdkVersion'].startswith('3.')
    if native_http:kinds.add('native-http-compatibility')
    require(len(build['packages']) == len(kinds) and {row['kind'] for row in build['packages']} == kinds,
            'Required RPM package ownership components are missing or duplicated')
    for row in build['packages']:
        host = row['kind'] == 'host'
        compatibility = row['kind'] == 'compatibility'
        curl = row['kind'] == 'native-http-compatibility'
        if curl:
            from legacy_curl import PACKAGE_NAME,VERSION
            name,version=PACKAGE_NAME,VERSION
        else:
            name = 'cbodotnet-compat-rocky9' if compatibility else ('cbodotnet-host' if host else plan['package']['name'])
            version = '2026.11.4' if compatibility else (HOST_VERSION.rsplit('-', 1)[0] if host else plan['sdkVersion'])
        release = '1.cbot.' + plan['variant'].replace('-', '') if compatibility or curl else rpm_release(plan, shared=host)
        architecture = 'noarch' if host else plan['architecture']['rpm']
        require(row['path'] == f'{name}-{version}-{release}.{architecture}.rpm'
                and (host or compatibility or curl or Path(item['artifactPath']).name == row['path']), 'Noncanonical native RPM package identity')
        path = build_path.parent / row['path']
        require(descriptor(path) == {'name': row['path'], 'size': row['size'], 'sha256': row['sha256']},
                'Unsigned RPM bytes differ from the native installation record')
        actual = CORE.run(['rpm', '--query', '--package', '--queryformat', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', path])
        require(actual.splitlines() == [name, version, release, architecture], 'RPM header differs from the canonical native identity')
    return plan, report, build_path, build


def retained_shared_rpm(row, plan, policy, keyring, signer, output):
    """Reuse one signed NEVRA byte-for-byte across all SDK repositories."""
    prefix = ('rpm-' + plan['variant'] + '--' if row['kind'] == 'host'
              else 'rpm-' + plan['variant'] + '-' + plan['architecture']['public'] + '--')
    name = prefix + row['path']
    candidates = []
    for receipt in policy['channels']['rpm'].get('receipts', []):
        for asset in receipt.get('assets', []):
            if asset.get('name') == name:
                candidates.append((receipt, asset))
    if not candidates:
        return None
    require(len({(asset['size'], asset['sha256']) for _, asset in candidates}) == 1,
            'Previously published shared RPM NEVRA has conflicting bytes')
    receipt, asset = candidates[0]
    prior_identity = receipt.get('identity', {})
    tag = release_tag('rpm', prior_identity.get('sdkVersion'), prior_identity.get('packageRevision'))
    base = f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/{tag}/'
    require(receipt.get('repository') == 'dotnetdev-kr/cbodotnet' and receipt.get('tag') == tag
            and receipt.get('manifestUrl') == base + 'distribution-manifest.json'
            and receipt.get('signatureUrl') == base + 'distribution-manifest.json.asc',
            'Prior shared RPM receipt project, tag or signature URL differs')
    from distribution_site import download
    with tempfile.TemporaryDirectory(prefix='cbodotnet-shared-rpm-') as temporary:
        directory = Path(temporary)
        manifest, signature = directory / 'manifest.json', directory / 'manifest.asc'
        require(receipt.get('status') == 'published-postverified' and receipt['identity']['channel'] == 'rpm',
                'Shared RPM requires a postverified prior publication')
        observed = download(receipt['manifestUrl'], manifest, 16 * 1024**2)
        require(observed == receipt['manifestSha256'], 'Prior shared RPM signed manifest changed')
        download(receipt['signatureUrl'], signature, 1024**2)
        fingerprint = verify_report_signature(manifest, signature, keyring, policy,
            '.github/workflows/distribution-release.yml', historical=True)
        document = json.loads(manifest.read_bytes())
        require(fingerprint == signer == receipt['signingFingerprint'] == document['signingFingerprint']
                and document['identity'] == receipt['identity']
                and document.get('repository') == receipt['repository'] and document.get('tag') == tag
                and document['status'] == 'validated-complete-matrix', 'Prior shared RPM signature or identity differs')
        binding = [item for item in document['assets'] if item['name'] == name]
        require(len(binding) == 1 and all(binding[0][key] == asset[key] for key in ('name', 'size', 'sha256')),
                'Prior manifest does not bind the retained shared RPM')
        expected_url = f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/{receipt["tag"]}/{name}'
        require(asset['url'] == expected_url, 'Noncanonical retained shared RPM URL')
        retained = output / name
        download(expected_url, retained, 2**31 - 1, asset)
        verify_rpm_signature(retained, keyring, signer, output / 'rpm-trust')
        unsigned = directory / row['path']
        shutil.copyfile(retained, unsigned)
        CORE.run(['rpmsign', '--delsign', unsigned])
        require(sha256_file(unsigned) == row['sha256'],
                'Shared RPM contents changed under an existing NEVRA; choose a new shared package revision')
    return retained


def stage(received, output, signing_key, keyring, source_run, source_attempt):
    protected()
    require(re.fullmatch(r'[A-F0-9]{40,64}', signing_key), 'Full reviewed signing fingerprint required')
    received, output, keyring = Path(received).resolve(), Path(output).resolve(), Path(keyring).resolve()
    require(not output.exists() and output.parent.is_dir(), 'Fresh RPM promotion output required')
    identity = source_identity(source_run, source_attempt)
    items = CORE.unpack_deliveries(received)
    policy, contract = load_status(), load_contract()
    expected = {(row['variant'], row['architecture']) for row in policy['channels']['rpm']['candidateMatrix']}
    require(len(items) == len(expected) and {(row['package']['identity']['variant'], row['package']['architecture'])
            for row in items} == expected, 'Incomplete native RPM delivery matrix')
    admitted = [preflight(item, received, identity, policy, contract) for item in items]
    immutable = {(plan['sdkVersion'], plan['packageRevision'], plan['sourceManifestSha256'])
                 for plan, _, _, _ in admitted}
    require(len(immutable) == 1, 'RPM matrix must describe one immutable SDK revision and source')
    shared = {}
    for plan, _, _, build in admitted:
        host = next(row for row in build['packages'] if row['kind'] == 'host')
        key = plan['variant'], host['path']
        require(key not in shared or shared[key] == host['sha256'], 'Common RPM differs across native architectures')
        shared[key] = host['sha256']
    output.mkdir()
    cache = output / 'signed-common'
    cache.mkdir()
    common = {}
    builds = []
    signatures = {}
    for item, (plan, report, build_path, build) in zip(items, admitted):
        packaged = item['package']
        for row in build['packages']:
            require(re.fullmatch(r'[A-Za-z0-9._+-]+\.rpm', row['path']), 'Unsafe native RPM filename')
            path = build_path.parent / row['path']
            require(descriptor(path) == {'name': row['path'], 'size': row['size'], 'sha256': row['sha256']},
                    'Unsigned RPM bytes differ from the native installation record')
            cache_key = (plan['variant'], row['path'])
            unsigned_hash = row['sha256']
            if row['kind'] == 'host' and cache_key in common:
                original_hash, signed_path = common[cache_key]
                require(original_hash == unsigned_hash, 'Common RPM differs across native architectures')
                shutil.copyfile(signed_path, path)
            else:
                retained = (retained_shared_rpm(row, plan, policy, keyring, signing_key, cache)
                            if row['kind'] in {'host', 'compatibility', 'native-http-compatibility'} else None)
                if retained is not None:
                    shutil.copyfile(retained, path)
                else:
                    CORE.run(['rpmsign', '--define', '_gpg_name ' + signing_key,
                              '--define', '_gpg_digest_algo sha256', '--define', '__gpg /usr/bin/gpg', '--addsign', path])
                if row['kind'] == 'host':
                    signed_path = cache / (plan['variant'] + '--' + row['path'])
                    shutil.copyfile(path, signed_path)
                    common[cache_key] = unsigned_hash, signed_path
            signatures[str(path)] = verify_rpm_signature(path, keyring, signing_key, output / 'rpm-trust')
            row.update(size=path.stat().st_size, sha256=sha256_file(path))
        build_path.write_bytes(encoded(build))
        builds.append(build_path)
        updated = package_record(plan, item['artifactPath'], identity,
                                 extra_files={'root': item['commandsRoot'], 'inventory': packaged['extraFiles']})
        report.update({key: updated[key] for key in ('contractVersion', 'identity', 'artifact', 'source', 'producer',
                                                   'orchestration', 'branding', 'commands', 'extraFiles')})
        report['checks']['package-signatures'] = 'passed'
        report['rpmSignatures'] = {row['kind']: signatures[str(build_path.parent / row['path'])] for row in build['packages']}
        Path(item['packagePath']).write_bytes(encoded(updated))
        item['package'] = updated
        Path(item['reportPath']).write_bytes(encoded(report))
    first = items[0]['package']['identity']
    base = asset_base(first['sdkVersion'], first['packageRevision'])
    repository = output / 'repositories'
    repositories = build_repositories(builds, 'rpm', repository, signing_key, rpm_asset_base_url=base)
    package_assets = {row['assetName']: {'name': row['assetName'], 'size': row['size'], 'sha256': row['sha256']}
                      for row in repositories['packageAssets']}
    for variant in sorted({variant for variant, _ in expected}):
        verify_repository(repository / variant, keyring, package_assets, base)
    for item in items:
        path = Path(item['reportPath'])
        report = json.loads(path.read_bytes())
        report['checks']['repository-metadata'] = 'passed'
        path.write_bytes(encoded(report))
        item['signaturePath'] = str(CORE.sign_report(path, signing_key))
        item['keyringPath'] = str(keyring)
    extra = [dict(path=str(repository / row['path']), kind='rpm-repository', variants=[row['variant']])
             for row in repositories['archives']]
    for row in repositories['packageAssets']:
        if row['kind'] in {'host', 'compatibility', 'native-http-compatibility'}:
            destination = output / row['assetName']
            shutil.copyfile(row['sourcePath'], destination)
            extra.append({'path': str(destination)})
    for build_path in builds:
        build=json.loads(build_path.read_bytes())
        for key in ('compatibilityAsset','nativeHttpCompatibilityAsset'):
            companion=build.get(key)
            if companion:extra.append(dict(path=str(build_path.parent / companion['path'])))
    manifest = create_bundle(items, output / 'bundle-rpm', identity['commit'], signing_key, keyring, extra_assets=extra)
    (output / 'promotion.json').write_bytes(encoded(dict(schemaVersion=1, status='signed-and-frozen',
        sourceOrchestration=identity, publisherCommit=os.environ['GITHUB_SHA'], channels={'rpm': manifest['tag']})))
    return {'status': 'signed-and-frozen', 'tag': manifest['tag'], 'targetCommit': identity['commit']}


def publish(promotion, keyring, frozen_run='', frozen_attempt='1'):
    protected()
    promotion, keyring = Path(promotion).resolve(), Path(keyring).resolve()
    if frozen_run:
        CORE.receive_frozen(frozen_run, frozen_attempt, promotion, channels=('rpm',),
                            publisher_job='Sign and publish RPM distributions',
                            freeze_step='Freeze signed RPM publication bytes', artifact_prefix='downstream-rpm-frozen')
    manifest = validate_bundle(promotion / 'bundle-rpm', keyring)
    require(manifest['identity']['channel'] == 'rpm', 'Frozen bundle is not an RPM publication')
    receipt = publish_bundle(promotion / 'bundle-rpm', keyring, manifest['targetCommit'])
    (promotion / 'rpm-publication.json').write_bytes(encoded(receipt))
    return receipt
