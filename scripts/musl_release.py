"""Authenticate the separate musl release pipeline without changing glibc feeds."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
import musl_source_transport as SOURCE_TRANSPORT

from downstream_release import descriptor, encoded, ordinary_file, verify_report_signature
from downstream_publish import GitHubReleases, verify_remote_assets
from musl_contract import (ARCHITECTURES, REPOSITORY, SOURCES, KINDS, require,
    producer_asset_name, producer_tag, validate_producer_manifest, validate_producer_release,
    load_qualification_catalog, distribution_tag, oci_tag, producer_workflow,
    producer_artifact_name, producer_script, producer_assets)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/musl-release.yml'
PRODUCER_WORKFLOW = '.github/workflows/musl-sdk.yml'
MAX_PRODUCER_TRANSPORT_BYTES = 8 * 1024**3


def validate_run(run, *, workflow, run_id, attempt, commit=None):
    """Successful native evidence must come from this repository's main branch."""
    require(isinstance(run, dict) and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0, 'Exact positive run and attempt required')
    observed = run.get('head_sha')
    require(isinstance(observed, str) and re.fullmatch(r'[a-f0-9]{40}', observed)
            and (commit is None or observed == commit), 'Producer commit differs from the reviewed commit')
    require(run.get('id') == run_id and run.get('run_attempt') == attempt
            and run.get('path') == workflow and run.get('head_branch') == 'main'
            and run.get('event') == 'workflow_dispatch'
            and run.get('repository', {}).get('full_name') == REPOSITORY
            and run.get('head_repository', {}).get('full_name') == REPOSITORY
            and run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'A successful exact main-branch musl workflow attempt is required')
    return observed


def validate_artifact(artifact, run, name):
    require(isinstance(artifact, dict) and type(artifact.get('id')) is int and artifact['id'] > 0
            and artifact.get('name') == name and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and artifact['size_in_bytes'] > 0
            and isinstance(artifact.get('digest'), str)
            and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact['digest']),
            'A unique unexpired musl artifact with an API digest is required')
    source = artifact.get('workflow_run', {})
    require(source.get('id') == run['id'] and source.get('head_sha') == run['head_sha']
            and source.get('head_branch') == 'main'
            and type(source.get('repository_id')) is int and source['repository_id'] > 0
            and source.get('head_repository_id') == source['repository_id'],
            'Musl artifact origin differs from the authenticated run')
    return artifact


def producer_transport_descriptor(value):
    """Actions ZIP/delivery transport can exceed a single release asset's size."""
    path = ordinary_file(value)
    before = path.stat()
    require(0 < before.st_size < MAX_PRODUCER_TRANSPORT_BYTES,
            'Musl producer transport must be nonempty and smaller than 8 GiB')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
            'Musl producer transport changed during fingerprinting')
    return dict(name=path.name, size=before.st_size, sha256=digest)


def extract_artifact(path, output, expected_names, *, api_artifact):
    """Verify actual transport bytes and a closed, flat ZIP before extraction."""
    path = ordinary_file(path)
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(p.is_symlink() for p in (output, *output.parents)),
            'Use a fresh ordinary musl artifact receive directory')
    item = producer_transport_descriptor(path)
    require(item['size'] == api_artifact['size_in_bytes']
            and 'sha256:' + item['sha256'] == api_artifact['digest'],
            'Musl artifact ZIP differs from its GitHub API size/digest')
    require(isinstance(expected_names, set) and expected_names
            and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}', name)
                    for name in expected_names), 'A closed musl artifact member inventory is required')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == len(expected_names) and {row.filename for row in entries} == expected_names,
                'Musl artifact ZIP has missing, duplicate or unexpected members')
        for row in entries:
            relative = PurePosixPath(row.filename)
            require(len(relative.parts) == 1 and not relative.is_absolute()
                    and not row.is_dir() and row.file_size > 0
                    and not row.flag_bits & 1
                    and (row.external_attr >> 16) & 0o170000 not in {0o120000, 0o060000, 0o020000, 0o010000},
                    'Musl artifact member is not an ordinary unencrypted file')
        require(sum(row.file_size for row in entries) + 512 * 1024**2 < shutil.disk_usage(output.parent).free,
                'Insufficient musl artifact receive capacity')
        output.mkdir()
        for row in entries:
            with archive.open(row) as incoming, (output / row.filename).open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
    return output


def load_signing_policy(path=None):
    path = Path(path) if path is not None else ROOT / 'releases/musl-signing-policy.json'
    policy = json.loads(path.read_bytes())
    require(policy.get('schemaVersion') == 1 and policy.get('kind') == 'musl-release-signing-policy'
            and policy.get('repository') == REPOSITORY and policy.get('workflow') == WORKFLOW
            and policy.get('environment') == 'downstream-release', 'Unreviewed musl signing policy')
    return policy


def verify_publication_signature(manifest_path, signature_path, keyring_path):
    return verify_report_signature(manifest_path, signature_path, keyring_path,
                                   load_signing_policy(), WORKFLOW, historical=True)


def validate_apk_signer(public_key, private_key=None, *, now=None):
    """Enforce the owner-approved APK identity and publisher rotation cutoff."""
    policy = load_signing_policy()['apkSigner']
    now = now if now is not None else datetime.now(timezone.utc)
    require(policy.get('state') == 'active' and policy.get('algorithm') == 'RSA4096'
            and policy.get('signatureType') == 'RSA256' and policy.get('digest') == 'SHA256'
            and policy.get('environment') == 'downstream-release' and policy.get('workflow') == WORKFLOW
            and policy.get('secret') == 'APK_SIGNING_KEY', 'No active approved APK signing identity')
    created = datetime.fromisoformat(policy['createdAt'].replace('Z','+00:00'))
    cutoff = datetime.fromisoformat(policy['publisherNotAfter'].replace('Z','+00:00'))
    require(now.tzinfo is not None and created <= now < cutoff, 'APK publisher signing window is not active')
    public_key = ordinary_file(public_key)
    require(public_key.name == policy['publicKeyName']
            and descriptor(public_key)['sha256'] == policy['publicKeySha256'], 'APK public key differs from approved exact PEM')
    der = subprocess.check_output(['openssl','pkey','-pubin','-in',str(public_key),'-outform','DER'], stderr=subprocess.PIPE)
    require(hashlib.sha256(der).hexdigest() == policy['spkiDerSha256'], 'APK public SPKI fingerprint differs')
    if private_key is not None:
        private_key = ordinary_file(private_key)
        require(private_key.stat().st_mode & 0o077 == 0, 'APK private key must have owner-only permissions')
        observed = subprocess.check_output(['openssl','pkey','-in',str(private_key),'-pubout','-outform','DER'], stderr=subprocess.PIPE)
        require(observed == der, 'APK private key does not match the approved public identity')
    return policy


def verify_release_tag(api, tag, expected_commit, *, allow_pending_draft=False):
    """Resolve the real tag ref, including annotated tags, to its exact commit."""
    require(isinstance(tag,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',tag)
            and isinstance(expected_commit,str) and re.fullmatch(r'[a-f0-9]{40}',expected_commit),
            'An exact safe release tag and full expected commit are required')
    ref = None
    for attempt in range(4):
        ref = api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}')
        if ref is not None or allow_pending_draft:
            break
        if attempt < 3:
            time.sleep(2**attempt)
    if ref is None and allow_pending_draft:
        return None
    require(isinstance(ref,dict) and ref.get('ref')=='refs/tags/'+tag, 'Published musl tag ref is absent or redirected')
    target = ref.get('object',{}); seen = set()
    for _ in range(5):
        sha = target.get('sha')
        require(isinstance(sha,str) and re.fullmatch(r'[a-f0-9]{40}',sha) and sha not in seen,
                'Malformed or cyclic annotated musl tag')
        seen.add(sha)
        if target.get('type')=='commit':
            require(sha==expected_commit, 'Actual musl tag ref points to another commit')
            return sha
        require(target.get('type')=='tag', 'Musl release tag must resolve to a commit')
        annotated = api.api(f'repos/{REPOSITORY}/git/tags/{sha}')
        require(isinstance(annotated,dict) and annotated.get('sha')==sha,
                'Annotated musl tag object differs from its ref')
        target = annotated.get('object',{})
    raise ValueError('Annotated musl release tag exceeds its depth limit')


def validate_publication_metadata(manifest, receipt, reports, *, verification_manifest=None):
    """Require signed delivery identity plus signed final two-CPU public evidence.

    Callers authenticate both manifest signatures independently before invoking
    this semantic validator. Large payloads remain bound to exact descriptors;
    actual anonymous native execution is bound through the final verification
    manifest, which is published separately after immutable payload promotion.
    """
    import musl_archive
    require(isinstance(manifest, dict) and manifest.get('schemaVersion') == 1
            and manifest.get('kind') == 'musl-distribution-publication'
            and manifest.get('repository') == REPOSITORY, 'Unsupported musl publication manifest')
    identity = manifest.get('identity', {})
    channel = identity.get('channel')
    require(channel in {'archive','apk','oci'} and identity.get('libc') == 'musl'
            and identity.get('sdkVersion') in SOURCES and identity.get('producerRevision') == 1
            and type(identity.get('packageRevision')) is int and identity['packageRevision'] > 0,
            'Unreviewed musl publication identity')
    tag = distribution_tag(channel, identity['sdkVersion'], identity['packageRevision'])
    base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    require(receipt.get('kind') == 'musl-distribution-publication-receipt'
            and receipt.get('status') == 'published-postverified' and receipt.get('identity') == identity
            and receipt.get('tag') == manifest.get('tag') == tag
            and receipt.get('releaseUrl') == f'https://github.com/{REPOSITORY}/releases/tag/{tag}'
            and receipt.get('manifestUrl') == base+'distribution-manifest.json'
            and receipt.get('signatureUrl') == base+'distribution-manifest.json.asc'
            and receipt.get('signingFingerprint') == manifest.get('signingFingerprint'),
            'Musl public receipt differs from signed delivery identity')
    catalog = load_qualification_catalog()
    producers = [row for row in catalog['builds'] if row['sdkVersion'] == identity['sdkVersion']
                 and row['producerRevision'] == identity['producerRevision']]
    require(len(producers) == 1 and identity.get('sourceReleaseTag') == producers[0]['sourceReleaseTag']
            and identity.get('sourceManifestSha256') == producers[0]['sourceManifestSha256'],
            'Musl publication source is not the independently qualified producer')
    assets = manifest.get('assets')
    require(isinstance(assets, list) and assets and all(isinstance(row, dict) for row in assets),
            'Musl signed asset inventory is missing')
    indexed = {row.get('name'):row for row in assets}
    require(len(indexed) == len(assets) and all(isinstance(name, str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',name) for name in indexed),
            'Unsafe or duplicate musl signed asset names')
    for row in assets:
        require(type(row.get('size')) is int and row['size'] > 0
                and re.fullmatch(r'[a-f0-9]{64}', row.get('sha256','')), 'Invalid musl signed asset descriptor')
    expected_assets = [dict(row, url=base+row['name']) for row in assets]
    require(receipt.get('assets') == expected_assets, 'Musl receipt asset URLs or bytes differ from signed inventory')
    records = manifest.get('records', [])
    require(isinstance(records, list) and len(records) == 2
            and {row.get('architecture') for row in records} == set(ARCHITECTURES), 'Musl publication needs both native CPUs')
    require(isinstance(reports, dict) and set(reports) == set(ARCHITECTURES), 'Both actual public report byte streams are required')
    public = receipt.get('postVerification', {}).get('reports', [])
    require(len(public) == 2 and {row.get('architecture') for row in public} == set(ARCHITECTURES),
            'Both final public native report descriptors are required')
    for row in records:
        arch = row['architecture']
        require(row.get('targetRid') == ARCHITECTURES[arch]['rid']
                and row.get('artifactAsset') in indexed and row.get('qualificationReportAsset') in indexed,
                'Musl record has an invalid RID or unbound artifact/report')
        plan = row.get('build', {}).get('plan', {})
        require(all(plan.get(key) == value for key,value in identity.items())
                and plan.get('targetRid') == ARCHITECTURES[arch]['rid']
                and plan.get('producer') == producers[0]['architectures'][arch],
                'Musl signed record differs from its qualified source/run identity')
        raw = reports[arch]
        require(isinstance(raw, bytes) and 0 < len(raw) <= 32*1024**2, 'Public native report exceeds bounds')
        public_row = next(item for item in public if item['architecture'] == arch)
        require(public_row.get('rawJsonSize') == len(raw)
                and public_row.get('rawJsonSha256') == hashlib.sha256(raw).hexdigest(),
                'Actual public native report bytes differ from final verification receipt')
        report = json.loads(raw)
        report_identity = {key:value for key,value in identity.items() if key != 'channel'}
        require(report.get('status') == 'passed' and report.get('native') is True
                and report.get('architecture') == arch and report.get('targetRid') == ARCHITECTURES[arch]['rid']
                and report.get('libc') == 'musl' and report.get('identity') == dict(report_identity,targetRid=ARCHITECTURES[arch]['rid'])
                and report.get('networkForBuild') == 'none', 'Public report lacks matching native musl execution')
        require(set(musl_archive.FUNCTIONAL_CHECKS) <= set(report.get('functionalChecks',{}))
                and all(report['functionalChecks'][check] == 'passed' for check in musl_archive.FUNCTIONAL_CHECKS),
                'Public musl report lacks full offline runtime/HTTP/TLS/crypto/ICU evidence')
        spaces = report.get('userSpaces', [])
        require(isinstance(spaces, list) and len(spaces) == 1
                and spaces[0].get('variant') == 'alpine-3.24' and spaces[0].get('alpineVersion') == '3.24.4'
                and spaces[0].get('status') in {None, 'passed'}
                and spaces[0].get('uid') == (1654 if channel == 'oci' else 10001)
                and spaces[0].get('gid') == (1654 if channel == 'oci' else 10001),
                'Public musl report must identify the exact non-root Alpine qualification user space')
        elf = spaces[0].get('elfAudit', {})
        require(elf.get('status') == 'passed' and elf.get('native') is (False if channel=='oci' else True) and elf.get('libc') == 'musl'
                and elf.get('architecture') == arch and elf.get('targetRid') == ARCHITECTURES[arch]['rid']
                and type(elf.get('hostElfCount')) is int and elf['hostElfCount'] > 0
                and isinstance(elf.get('stockLibraries'), list) and elf['stockLibraries']
                and spaces[0].get('systemTrustHttps', {}).get('status') == 'passed',
                'Public musl report lacks native ELF stock-library closure or system-trust HTTPS')
        if channel=='oci':
            execution=spaces[0].get('nativeImageExecution',{})
            require(execution.get('status')=='passed' and execution.get('native') is True
                    and execution.get('architecture')==arch and execution.get('targetRid')==ARCHITECTURES[arch]['rid']
                    and execution.get('loader')==ARCHITECTURES[arch]['interpreter']
                    and execution.get('imageId')==report.get('imageId')
                    and re.fullmatch(r'sha256:[a-f0-9]{64}',execution.get('imageId',''))
                    and re.fullmatch(r'[a-f0-9]{64}',execution.get('loaderOutputSha256','')),
                    'OCI static closure must be accompanied by actual native image loader execution')
            dynamic=[item for item in elf.get('elfFiles',[]) if item.get('disposition')=='host-runtime-or-tool'
                     and item.get('elfType') in {'DYN','EXEC'}]
            require(dynamic and execution.get('dynamicElfCount')==len(dynamic), 'OCI must probe every dynamic host ELF with its actual loader')
            providers=execution.get('stockLibraries',[])
            require(isinstance(providers,list) and providers
                    and sorted(item.get('sha256','') for item in providers)==sorted(item.get('sha256','') for item in elf['stockLibraries'])
                    and all(isinstance(item.get('path'),str) and item['path'].startswith(('/lib/','/usr/lib/','/usr/local/lib/'))
                        and item.get('apkOwner','').startswith(item['path']+' is owned by ')
                        and 'cbodotnet-' not in item['apkOwner'] for item in providers),
                    'OCI must recheck actual stock APK library ownership and bytes inside the image')
            ownership=spaces[0].get('ownership',{})
            require(ownership.get('status')=='passed' and ownership.get('uid')==ownership.get('gid')==0
                    and ownership.get('setIdOrWorldWritableEntries')==0 and ownership.get('sdkEntries',0)>0,
                    'OCI SDK and command ownership must be preserved as immutable root-owned files')
        public_bytes = report.get('publicVerification', {})
        require(public_bytes.get('anonymous') is True and public_bytes.get('status') == 'passed',
                'Public musl report must prove anonymous actual artifact retrieval')
        require(public_bytes.get('manifestSha256') == receipt.get('manifestSha256')
                and public_bytes.get('manifestUrl') == receipt['manifestUrl']
                and public_bytes.get('signingFingerprint') == receipt['signingFingerprint'],
                'Public execution was not bound to this exact signed musl release manifest')
        artifact = indexed[row['artifactAsset']]
        require(public_bytes.get('artifactSha256') == artifact['sha256'], 'Public retrieval differs from signed artifact bytes')
        if channel == 'archive':
            require(report.get('artifact')==row['build']['artifact'], 'Public archive report artifact differs from signed build')
            require(public_bytes.get('url') == base+row['artifactAsset'],
                    'Public archive execution used another release asset URL')
            require(set(musl_archive.REPORT_CHECKS) <= set(report.get('checks',{}))
                    and all(report['checks'][check] == 'passed' for check in musl_archive.REPORT_CHECKS),
                    'Public archive report lacks a required native qualification check')
        elif channel=='apk':
            from musl_package_native import APK_CHECKS
            require(APK_CHECKS <= set(report.get('checks',{}))
                    and all(report['checks'][check]=='passed' for check in APK_CHECKS), 'A required public APK qualification check is absent')
            repository=row.get('repository',{})
            repo_base=(f'https://github.com/{REPOSITORY}/releases/download/musl-apk-repo-'
                +identity['sdkVersion']+'-alpine324-'+arch+'-r'+str(identity['packageRevision'])+'/')
            require(repository.get('url')==repo_base
                    and public_bytes.get('indexUrl')==repo_base+'APKINDEX.tar.gz'
                    and public_bytes.get('indexSha256')==repository.get('indexSha256')
                    and public_bytes.get('sourceUrl')==repo_base+report.get('artifact',{}).get('name','')
                    and report.get('artifact',{}).get('sha256')==artifact['sha256'],
                    'Public APK execution differs from the signed immutable HTTPS repository')
            declared=repository.get('packages',[])
            actual=report.get('publicBytes',{}).get('packages',[])
            require(len(declared)==len(actual)==2
                    and sorted((item.get('name'),item.get('size'),item.get('sha256'),item.get('url')) for item in declared)
                      ==sorted((item.get('name'),item.get('size'),item.get('sha256'),item.get('url')) for item in actual),
                    'Public APK install must retrieve both exact signed SDK and shared-host packages')
        else:
            from musl_package_native import APK_CHECKS
            checks=(APK_CHECKS-{'package-signature','index-signature','package-index-binding','negative-signature-tests'}) | {
                'oci-config','native-image-loader','native-stock-provider-ownership','root-owned-sdk','no-source-build-tools','clean-runtime-environment'}
            require(checks <= set(report.get('checks',{})) and all(report['checks'][check]=='passed' for check in checks),
                    'A required public OCI qualification check is absent')
            index=manifest.get('ociIndex',{})
            platforms=index.get('platforms',{})
            require(index.get('repository')=='ghcr.io/'+REPOSITORY+'-sdk'
                    and index.get('tag')==oci_tag(identity['sdkVersion'],identity['packageRevision'])
                    and re.fullmatch(r'sha256:[a-f0-9]{64}',index.get('digest',''))
                    and isinstance(platforms,dict) and set(platforms)==set(ARCHITECTURES), 'Signed Alpine OCI index is incomplete')
            platform=platforms[arch]
            require(platform.get('platform')==ARCHITECTURES[arch]['oci']
                    and re.fullmatch(r'sha256:[a-f0-9]{64}',platform.get('digest',''))
                    and report.get('imageDigest')==public_bytes.get('imageDigest')==platform['digest']
                    and report.get('imageId')==public_bytes.get('imageConfigDigest')==platform.get('configDigest')
                    and public_bytes.get('indexDigest')==index['digest']
                    and public_bytes.get('descriptorUrl')==base+row['artifactAsset'],
                    'Actual anonymous OCI image/config/index digests differ from the signed platform matrix')
    require(isinstance(verification_manifest, dict)
            and verification_manifest.get('schemaVersion') == 1
            and verification_manifest.get('kind') == 'musl-public-verification'
            and verification_manifest.get('repository') == REPOSITORY,
            'A separately authenticated final musl public verification manifest is required')
    entries = verification_manifest.get('entries', [])
    wanted = {key:value for key,value in receipt.items() if key != 'verification'}
    require(isinstance(entries,list) and sum(entry == wanted for entry in entries) == 1,
            'Final signed public verification does not bind this exact receipt')
    return manifest


def extract_delivery(path, output):
    """The delivery envelope contains files, never executable filesystem links."""
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(p.is_symlink() for p in (output, *output.parents)),
            'Use a fresh ordinary musl delivery directory')
    with tarfile.open(ordinary_file(path), 'r:gz') as archive:
        entries = archive.getmembers()
        require(0 < len(entries) <= 100000, 'Unbounded musl delivery inventory')
        names = set()
        for row in entries:
            relative = PurePosixPath(row.name)
            require(not relative.is_absolute() and relative.parts and relative.parts[0] == 'delivery'
                    and all(part not in {'.', '..', ''} for part in relative.parts)
                    and row.name not in names and not any(c in row.name for c in '\\:\0\r\n')
                    and (row.isfile() or row.isdir()) and 0 <= row.size <= 32 * 1024**3,
                    'Unsafe, duplicate or oversized musl delivery member')
            require(row.name.rstrip('/') == relative.as_posix(), 'Noncanonical musl delivery member')
            names.add(row.name)
        require(sum(row.size for row in entries) + 512 * 1024**2 < shutil.disk_usage(output.parent).free,
                'Insufficient musl delivery extraction capacity')
        output.mkdir()
        for row in entries:
            target = output / row.name
            if row.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(row) as incoming, target.open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                target.chmod(0o644)
    return output / 'delivery'


def receive_producer(run_id, attempt, output, *, gh='gh', sdk_version='10.0.403'):
    """Receive both exact native artifacts; never accept a path supplied by them."""
    api = GitHubReleases(gh=gh)
    run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    workflow = producer_workflow(sdk_version)
    commit = validate_run(run, workflow=workflow, run_id=run_id, attempt=attempt)
    artifacts = []
    for page in range(1, 101):
        listing = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100&page={page}')
        require(isinstance(listing, dict) and isinstance(listing.get('artifacts'), list), 'Invalid musl artifact API listing')
        artifacts.extend(listing['artifacts'])
        if len(listing['artifacts']) < 100:
            break
    else:
        raise ValueError('Musl artifact listing exceeds its bounded page count')
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(p.is_symlink() for p in (output, *output.parents)), 'A fresh musl producer receive workspace is required')
    output.mkdir()
    (output/'run.json').write_bytes(encoded(run))
    received = {}
    for arch in ARCHITECTURES:
        name = producer_artifact_name(sdk_version, arch, run_id, attempt)
        matches = [row for row in artifacts if row.get('name') == name]
        require(len(matches) == 1, 'An exact unique native musl artifact is required: ' + arch)
        artifact = validate_artifact(matches[0], run, name)
        zip_path = output / (arch+'.zip')
        with zip_path.open('xb') as stream:
            subprocess.run([gh, 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'], stdout=stream, check=True)
        extracted = extract_artifact(zip_path, output/(arch+'-artifact'),
            {'delivery.tar.gz', 'delivery.tar.gz.sha256', 'delivery.json'}, api_artifact=artifact)
        actual = producer_transport_descriptor(extracted/'delivery.tar.gz')
        checksum = ordinary_file(extracted/'delivery.tar.gz.sha256').read_text(encoding='ascii')
        require(checksum in {actual['sha256']+'  delivery.tar.gz\n', actual['sha256']+' *delivery.tar.gz\n'},
                'Musl delivery checksum differs from actual tar bytes')
        tree = extract_delivery(extracted/'delivery.tar.gz', output/(arch+'-received'))
        transport = json.loads(ordinary_file(extracted/'delivery.json').read_bytes())
        require(transport.get('kind') == 'musl-sdk-producer-transport' and transport.get('status') == 'passed'
                and transport.get('sdkVersion') == sdk_version and transport.get('workflow') == workflow
                and transport.get('architecture') == arch and transport.get('projectCommit') == commit
                and transport.get('repository') == REPOSITORY and transport.get('libc') == 'musl'
                and str(transport.get('runId')) == str(run_id) and str(transport.get('runAttempt')) == str(attempt)
                and transport.get('bundle') == actual, 'Musl transport identity differs from exact requested run')
        subprocess.run([sys.executable, str(ROOT/'scripts'/producer_script(sdk_version)), 'validate', '--release-dir', str(tree)], check=True)
        sealed = json.loads(ordinary_file(tree/'producer-validation.json').read_bytes())
        require(sealed.get('sdkVersion') == sdk_version and sealed.get('architecture') == arch and sealed.get('projectCommit') == commit
                and str(sealed.get('runId')) == str(run_id) and str(sealed.get('runAttempt')) == str(attempt)
                and sealed.get('targetRid') == ARCHITECTURES[arch]['rid'] and sealed.get('libc') == 'musl',
                'Sealed musl delivery identity differs from the actual API-authenticated native run')
        received[arch] = dict(artifact=artifact, artifactZip=producer_transport_descriptor(zip_path),
            delivery=actual, directory=str(tree), commit=commit)
    result = dict(schemaVersion=1, kind='received-native-musl-producers', libc='musl',
        sdkVersion=sdk_version, runId=run_id, runAttempt=attempt, projectCommit=commit, architectures=received)
    (output/'received.json').write_bytes(encoded(result))
    return result


def _source_module():
    spec = importlib.util.spec_from_file_location('musl_source_delivery', ROOT/'scripts/package-used-source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def producer_checksum_bytes(manifest):
    """Keep source checksums in declared CPU/kind order across JSON round trips."""
    return ''.join(f'{row["sha256"]}  {row["name"]}\n' for row in producer_assets(manifest)).encode('ascii')


def stage_producer(received_directory, output):
    """Freeze a closed two-CPU source release from independently rechecked bytes."""
    from types import SimpleNamespace
    received_directory = Path(received_directory).absolute()
    received = json.loads(ordinary_file(received_directory/'received.json').read_bytes())
    version = received.get('sdkVersion', '10.0.403')
    workflow = producer_workflow(version)
    run = json.loads(ordinary_file(received_directory/'run.json').read_bytes())
    commit = validate_run(run, workflow=workflow, run_id=received['runId'],
                          attempt=received['runAttempt'], commit=received['projectCommit'])
    require(received.get('kind') == 'received-native-musl-producers' and received.get('libc') == 'musl'
            and set(received.get('architectures', {})) == set(ARCHITECTURES), 'An exact two-CPU musl receive record is required')
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(p.is_symlink() for p in (output, *output.parents)), 'A fresh musl producer staging directory is required')
    output.mkdir()
    manifest = dict(schemaVersion=1, kind='musl-sdk-producer-release', repository=REPOSITORY,
        sdkVersion=version, producerRevision=1, libc='musl', tag=producer_tag(version), architectures={})
    for arch, target in ARCHITECTURES.items():
        row = received['architectures'][arch]
        validate_artifact(row['artifact'], run, producer_artifact_name(version, arch, run['id'], run['run_attempt']))
        # The receiving record's absolute paths are informational, never routing inputs.
        tree = received_directory/(arch+'-received')/'delivery'
        subprocess.run([sys.executable, str(ROOT/'scripts'/producer_script(version)), 'validate', '--release-dir', str(tree)], check=True)
        sealed = json.loads(ordinary_file(tree/'producer-validation.json').read_bytes())
        producer = json.loads(ordinary_file(tree/'producer-sdk.json').read_bytes())
        for record in (sealed, producer):
            require(record.get('sdkVersion') == version and record.get('architecture') == arch and record.get('projectCommit') == commit
                    and str(record.get('runId')) == str(run['id']) and str(record.get('runAttempt')) == str(run['run_attempt'])
                    and record.get('targetRid') == target['rid'] and record.get('libc') == 'musl',
                    'Musl source stage identity differs from trusted origin')
        raw_name = producer['sdk']['name']
        require(isinstance(raw_name, str) and re.fullmatch(r'cbodotnet-sdk-'+re.escape(version)+r'-linux-musl-'+arch+r'-build\.[1-9][0-9]*\.tar\.gz', raw_name),
                'Unexpected native musl SDK filename')
        raw_sdk = ordinary_file(tree/raw_name)
        actual = descriptor(raw_sdk)
        require(actual['size'] == producer['sdk']['bytes'] and actual['sha256'] == producer['sdk']['sha256'],
                'Native SDK bytes differ from producer evidence')
        _source_module().verify(SimpleNamespace(release_dir=tree, expected_project_commit=commit,
            expected_run_id=str(run['id']), expected_run_attempt=str(run['run_attempt']), expected_target_rid=target['rid']))
        source_manifest = json.loads(ordinary_file(tree/'sources/source-manifest.json').read_bytes())
        source_name = source_manifest['archive']['path']
        require(isinstance(source_name, str) and re.fullmatch(r'[A-Za-z0-9._+-]+\.tar\.gz', source_name), 'Unsafe used-source archive name')
        source = ordinary_file(tree/'sources'/source_name)
        entry = dict(targetRid=target['rid'])
        destination = output/producer_asset_name('sdk', version, arch)
        shutil.copyfile(raw_sdk, destination)
        entry['sdk'] = descriptor(destination)
        require(entry['sdk']['sha256'] == descriptor(raw_sdk)['sha256'], 'Musl producer staging copy changed bytes')
        entry['source'], transport = SOURCE_TRANSPORT.stage(source, output, producer_asset_name('source', version, arch),
            tree/'sources/source-manifest.json', tree/'sources'/source_manifest['index']['path'], source_manifest['archive'])
        if transport is not None:
            entry['sourceTransport'] = transport
        evidence = output/producer_asset_name('evidence', version, arch)
        exclude = {raw_sdk, source}
        with tarfile.open(evidence, 'w:gz', compresslevel=6) as archive:
            for path in sorted(tree.rglob('*')):
                require(not path.is_symlink(), 'Musl evidence envelope must contain no symlinks')
                if path.is_file() and path not in exclude:
                    archive.add(path, arcname=path.relative_to(tree).as_posix(), recursive=False)
        entry['evidence'] = descriptor(evidence)
        entry['provenance'] = dict(projectCommit=commit, runId=str(run['id']), runAttempt=str(run['run_attempt']),
            artifactId=str(row['artifact']['id']), workflow=workflow,
            workflowUrl=f'https://github.com/{REPOSITORY}/actions/runs/{run["id"]}', libc='musl', targetRid=target['rid'], **SOURCES[version])
        manifest['architectures'][arch] = entry
    checksum_bytes = producer_checksum_bytes(manifest)
    (output/'SHA256SUMS').write_bytes(checksum_bytes)
    manifest['checksums'] = descriptor(output/'SHA256SUMS')
    validate_producer_manifest(manifest)
    (output/'release-manifest.json').write_bytes(encoded(manifest))
    return manifest


def validate_source_stage(directory):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(p.is_symlink() for p in (directory, *directory.parents)),
            'An ordinary musl producer stage is required')
    raw = ordinary_file(directory/'release-manifest.json').read_bytes()
    require(0 < len(raw) <= 16*1024**2, 'Oversized musl producer manifest')
    manifest = validate_producer_manifest(json.loads(raw))
    physical = list(producer_assets(manifest))
    expected = {row['name']: row for row in physical}
    require(len(expected) == len(physical), 'Duplicate musl physical source stage asset')
    expected['SHA256SUMS'] = manifest['checksums']
    expected['release-manifest.json'] = descriptor(directory/'release-manifest.json')
    require({path.name for path in directory.iterdir()} == set(expected), 'Musl producer stage is not a closed asset set')
    for name, wanted in expected.items():
        require(descriptor(directory/name) == wanted, 'Musl producer stage bytes changed: '+name)
    for entry in manifest['architectures'].values():
        if 'sourceTransport' in entry:
            SOURCE_TRANSPORT.verify_directory(directory, entry)
            SOURCE_TRANSPORT.source_controls(directory/entry['evidence']['name'], entry=entry)
    sums = ordinary_file(directory/'SHA256SUMS').read_bytes()
    checksum_bytes = producer_checksum_bytes(manifest)
    require(sums == checksum_bytes, 'Musl producer checksums differ from closed SDK/source/evidence inventory')
    commits = {entry['provenance']['projectCommit'] for entry in manifest['architectures'].values()}
    require(len(commits) == 1, 'Musl producer stage mixes orchestration commits')
    return manifest, expected


def publish_producer(directory, *, gh='gh'):
    """Publish exact source bytes once; historical releases are never adopted."""
    directory = Path(directory).absolute()
    manifest, expected = validate_source_stage(directory)
    api = GitHubReleases(gh=gh)
    commits = {entry['provenance']['projectCommit'] for entry in manifest['architectures'].values()}
    commit = next(iter(commits))
    for arch, entry in manifest['architectures'].items():
        provenance = entry['provenance']
        run = api.api(f'repos/{REPOSITORY}/actions/runs/{provenance["runId"]}/attempts/{provenance["runAttempt"]}')
        validate_run(run, workflow=producer_workflow(manifest['sdkVersion']), run_id=int(provenance['runId']),
                     attempt=int(provenance['runAttempt']), commit=commit)
        artifact = api.api(f'repos/{REPOSITORY}/actions/artifacts/{provenance["artifactId"]}')
        validate_artifact(artifact, run, producer_artifact_name(manifest['sdkVersion'], arch, provenance['runId'], provenance['runAttempt']))
    tag = manifest['tag']
    title = f'Community Build musl SDK {manifest["sdkVersion"]} producer r{manifest["producerRevision"]}'
    body = ('Native Alpine musl producer inputs for Community Build of .NET (built by .NET Dev).\n\n'
        'These unchanged upstream CLI payloads are source inputs for the separately branded consumer distribution. '
        'Use the qualified consumer archives, APK repository or explicit Alpine OCI variants listed at '
        'https://dotnetdev.kr/cbodotnet/ after their independent public verification.\n\n'
        'release-manifest.json and SHA256SUMS bind both native CPUs, actual used sources and complete evidence. '
        'The original source build reconstructs SDK tooling; the evidence records rebuilt and imported shared-framework inputs. '
        'NativeAOT, workloads and cbodotnetup musl admission are separate qualification work.\n')
    if manifest['sdkVersion'] == '10.0.403':
        # Preserve the immutable SDK10 release's exact existing metadata.
        body = body.replace(
            'The original source build reconstructs SDK tooling; the evidence records rebuilt and imported shared-framework inputs. ',
            'This regular VMR build rebuilds SDK tooling and imports attributed upstream musl shared-framework inputs. ')
    else:
        body = body.replace('These unchanged upstream CLI payloads', 'These source-produced SDK payloads')
    if any('sourceTransport' in entry for entry in manifest['architectures'].values()):
        body += ('\nOversized used-source gzip archives use explicit exact-byte multipart transport. '
            'The matching .transport.json binds every ordered part and the unchanged complete archive with SHA-256 and SHA-512. '
            'Restore and verify sources with scripts/musl_distribution.py receive-used-source; '
            'see docs/musl-source-multipart-transport.md in the tagged source.\n')
    release = api.find(tag)
    if release is None:
        require(api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}') is None,
                'Refusing an existing musl producer tag without its matching release')
        release = api.api(f'repos/{REPOSITORY}/releases', 'POST', dict(tag_name=tag,
            target_commitish=commit, name=title, body=body, draft=True, prerelease=False, make_latest='false'))
    require(release.get('tag_name') == tag and release.get('name') == title and release.get('body') == body
            and release.get('target_commitish') == commit and release.get('prerelease') is False,
            'Existing musl source release does not have this exact immutable identity')
    verify_release_tag(api,tag,commit,allow_pending_draft=release.get('draft') is True)
    by_name = {row['name']: row for row in release.get('assets', [])}
    require(len(by_name) == len(release.get('assets', [])) and set(by_name) <= set(expected),
            'Existing musl source release contains unexpected or duplicate assets')
    for name, wanted in expected.items():
        if name in by_name:
            require(by_name[name].get('size') == wanted['size']
                    and by_name[name].get('digest') == 'sha256:'+wanted['sha256'],
                    'Refusing to replace conflicting musl source asset: '+name)
        else:
            require(release.get('draft') is True, 'A public musl source release cannot gain new assets')
            api.upload(release, directory/name)
    release = api.get(release)
    verify_remote_assets(release, expected, api, public=False)
    if release['draft']:
        release = api.publish(release)
    release = api.get(release)
    verify_release_tag(api,tag,commit)
    validate_producer_release(release, (directory/'release-manifest.json').read_bytes(), (directory/'SHA256SUMS').read_bytes())
    verify_remote_assets(release, expected, api, public=True)
    return dict(schemaVersion=1, kind='musl-producer-publication', status='published-postverified',
        tag=tag, releaseId=release['id'], sourceManifestSha256=expected['release-manifest.json']['sha256'],
        sourceManifestUrl=f'https://github.com/{REPOSITORY}/releases/download/{tag}/release-manifest.json',
        architectures={arch:entry['provenance'] for arch,entry in manifest['architectures'].items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    receive = commands.add_parser('receive-producer')
    receive.add_argument('--run-id', type=int, required=True)
    receive.add_argument('--sdk-version', choices=sorted(SOURCES), default='10.0.403')
    receive.add_argument('--attempt', type=int, default=1)
    receive.add_argument('--output', type=Path, required=True)
    stage = commands.add_parser('stage-producer')
    stage.add_argument('--received', type=Path, required=True)
    stage.add_argument('--output', type=Path, required=True)
    publish = commands.add_parser('publish-producer')
    publish.add_argument('--stage', type=Path, required=True)
    publish.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'receive-producer':
        result = receive_producer(args.run_id, args.attempt, args.output, sdk_version=args.sdk_version)
        print(json.dumps(dict(status='received-validated', commit=result['projectCommit'],
                              architectures=sorted(result['architectures']))))
    elif args.command == 'stage-producer':
        result = stage_producer(args.received, args.output)
        print(json.dumps(dict(status='staged-unpublished', tag=result['tag'])))
    elif args.command == 'publish-producer':
        require(not args.output.exists() and args.output.parent.is_dir(), 'A fresh publication receipt path is required')
        result = publish_producer(args.stage)
        args.output.write_bytes(encoded(result))
        print(json.dumps(dict(status=result['status'], tag=result['tag'])))


if __name__ == '__main__':
    main()
