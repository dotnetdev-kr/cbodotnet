"""Independently verify native APK candidates and freeze protected signatures."""
import argparse
from sdk_runtime import target_framework
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_package_native as NATIVE
import musl_packages as APK
import musl_promotion as PROMOTION
from downstream_publish import GitHubReleases, verify_remote_assets
from downstream_release import descriptor, encoded, ordinary_file, require, verify_report_signature
from musl_release import WORKFLOW, extract_artifact, extract_delivery, load_signing_policy, validate_artifact, verify_release_tag
from musl_verification import listed, timestamp, artifact_provenance

REPOSITORY = CONTRACT.REPOSITORY
MANIFEST = PROMOTION.MANIFEST
SIGNATURE = PROMOTION.SIGNATURE
load_json = PROMOTION.load_json
NEGATIVE_CASES = {'changed-package-control', 'changed-package-payload', 'changed-index',
                  'wrong-key-same-name-package', 'wrong-key-same-name-index', 'missing-key'}
METADATA = ('plan.json', 'payload-inventory.json', 'command-inventory.json')
RUNNER_LABELS = {'x64': 'ubuntu-24.04', 'aarch64': 'ubuntu-24.04-arm'}


def protected():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
        and os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
        and os.environ.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
        and os.environ.get('GITHUB_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
        and os.environ.get('GITHUB_JOB') in {'freeze_apk', 'publish_apk'},
        'Only protected main APK freeze/publish jobs may sign or publish')
    result = dict(repository=REPOSITORY, workflow=WORKFLOW, commit=os.environ.get('GITHUB_SHA', ''),
        runId=os.environ.get('GITHUB_RUN_ID', ''), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT', ''))
    require(re.fullmatch(r'[a-f0-9]{40}', result['commit'])
        and all(re.fullmatch(r'[1-9][0-9]*', result[key]) for key in ('runId', 'runAttempt')),
        'Exact protected APK orchestration identity is required')
    return result


def native_identity(api, run_id, attempt, *, current=None):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'Exact positive APK run and attempt required')
    run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    require(isinstance(run, dict), 'APK native run is absent')
    commit = PROMOTION.validate_native_run(run, run_id, attempt, current=current)
    jobs = listed(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    selected = {}
    for arch in CONTRACT.ARCHITECTURES:
        matches = [row for row in jobs if row.get('name') == 'Qualify musl APK native ' + arch]
        require(len(matches) == 1, 'Both exact native APK jobs must have passed')
        job = matches[0]
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success'
            and job.get('head_sha') == run['head_sha'] and type(job.get('id')) is int and job['id'] > 0
            and type(job.get('runner_id')) is int and job['runner_id'] > 0
            and job.get('runner_group_name') == 'GitHub Actions'
            and job.get('runner_name') == 'GitHub Actions ' + str(job['runner_id'])
            and isinstance(job.get('labels'), list) and RUNNER_LABELS[arch] in job['labels']
            and 'self-hosted' not in job['labels'] and timestamp(job['started_at']) <= timestamp(job['completed_at']),
            'APK proof did not use the successful exact native GitHub-hosted CPU job')
        selected[arch] = job
    origin = dict(repository=REPOSITORY, workflow=WORKFLOW, commit=commit, runId=str(run_id), runAttempt=str(attempt))
    return run, origin, selected


def artifact_name(architecture, origin):
    require(architecture in CONTRACT.ARCHITECTURES, 'Unknown native APK architecture')
    return f'musl-native-apk-{architecture}-{origin["runId"]}-{origin["runAttempt"]}'


def receive_candidates(api, run_id, attempt, revision, output, *, current=None, downloader=None):
    require(revision == 1, 'Only the initial APK r1 is approved for publication')
    run, origin, jobs = native_identity(api, run_id, attempt, current=current)
    artifacts = listed(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts', 'artifacts')
    output = ARCHIVE.fresh_directory(output)
    received = {}
    for arch in CONTRACT.ARCHITECTURES:
        name = artifact_name(arch, origin)
        matches = [row for row in artifacts if row.get('name') == name]
        require(len(matches) == 1, 'Exactly one APK candidate artifact is required per CPU')
        artifact = validate_artifact(matches[0], run, name)
        archive = output / (arch + '.zip')
        if downloader is None:
            with archive.open('xb') as stream:
                subprocess.run([api.gh, 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'],
                               stdout=stream, check=True)
        else:
            downloader(artifact, archive)
        extracted = extract_artifact(archive, output / arch, {'candidate.tar.gz', 'candidate.json'}, api_artifact=artifact)
        transport = load_json(extracted / 'candidate.json')
        require(transport == dict(schemaVersion=1, kind='musl-apk-native-candidate-transport',
            orchestration=origin, artifact=descriptor(extracted / 'candidate.tar.gz')),
            'APK transport does not bind the exact trusted workflow and delivery bytes')
        delivery = extract_delivery(extracted / 'candidate.tar.gz', output / (arch + '-envelope'))
        received[arch] = dict(directory=delivery, transport=dict(artifact_provenance(artifact, archive, origin, job=jobs[arch]),
            candidate=transport, jobId=jobs[arch]['id'], jobName=jobs[arch]['name']))
    return origin, received


def package_artifact(build):
    row = next(row for row in NATIVE.package_roles(build) if row['kind'] == 'sdk')
    return dict(name=row['path'], size=row['size'], sha256=row['sha256'])


def validate_native_report(report, build, origin, *, payload=None):
    plan = build['plan']
    arch = plan['architecture']['public']
    require(report.get('schemaVersion') == 1 and report.get('scope') == 'musl-apk-installation'
        and report.get('status') == 'passed' and report.get('native') is True
        and report.get('architecture') == arch and report.get('targetRid') == plan['targetRid']
        and report.get('libc') == 'musl' and report.get('identity') == ARCHIVE.identity(plan)
        and report.get('networkForBuild') == 'none' and report.get('orchestration') == origin
        and report.get('artifact') == package_artifact(build), 'Native APK report is not bound to these original packages')
    for name, required in [('checks', NATIVE.APK_CHECKS), ('functionalChecks', ARCHIVE.FUNCTIONAL_CHECKS)]:
        observed = report.get(name, {})
        require(isinstance(observed, dict) and required <= set(observed)
            and all(observed[key] == 'passed' for key in required), 'A mandatory native APK check is absent')
    spaces = report.get('userSpaces', [])
    require(isinstance(spaces, list) and len(spaces) == 1, 'One exact native APK user space is required')
    space = spaces[0]
    require(space.get('variant') == 'alpine-3.24' and space.get('alpineVersion') == '3.24.4'
        and space.get('base') == ARCHIVE.BASES[arch] and space.get('uid') == space.get('gid') == 10001
        and re.fullmatch(r'sha256:[a-f0-9]{64}', space.get('imageId', '')), 'Native APK base/CPU/user differs')
    offline = space.get('offline', {})
    require(offline.get('schemaVersion') == 1 and offline.get('scope') == 'musl-apk-offline'
        and offline.get('status') == 'passed' and offline.get('native') is True and offline.get('architecture') == arch
        and offline.get('libc') == 'musl' and offline.get('targetRid') == plan['targetRid']
        and offline.get('identity') == ARCHIVE.identity(plan) and offline.get('networkForBuild') == 'none'
        and offline.get('uid') == offline.get('gid') == 10001, 'APK offline execution identity differs')
    for name, required in [('checks', NATIVE.APK_CHECKS - {'system-trust-https'}),
                           ('functionalChecks', ARCHIVE.FUNCTIONAL_CHECKS)]:
        observed = offline.get(name, {})
        require(isinstance(observed, dict) and required <= set(observed)
            and all(observed[key] == 'passed' for key in required), 'A mandatory offline APK check is absent')
    require(offline['functionalChecks'] == report['functionalChecks'], 'APK functional summaries differ')
    actual_packages = [dict(row) for row in build['packages']]
    for row in actual_packages:
        row.pop('kind', None)
    require(offline.get('packages') == actual_packages, 'Offline APK proof used another signed package set')
    root = plan['package']['root']
    series = '.'.join(plan['sdkVersion'].split('.')[:2])
    commands = offline.get('commands', [])
    require(len(commands) == 2 and {row.get('command') for row in commands} == {'cbodotnet', 'cbodotnet-' + series}
        and all(row.get('targetRid') == plan['targetRid'] and row.get('sdkRoot') == root for row in commands)
        and offline.get('payload') == root and offline.get('cli') == '/usr/bin/cbodotnet'
        and offline.get('trustProbe') == '/qualification/system-trust/bin/Debug/'+target_framework(build['plan']['sdkVersion'])+'/Trust.dll',
        'APK command aliases or trust probe escaped the exact installed SDK')
    require(all(name + '-' + version in offline.get('dependencies', [])
                for name, version in ARCHIVE.RUNTIME_PACKAGES.items()), 'APK stock runtime pins differ')
    ca = offline.get('caBundle', {})
    require(type(ca.get('size')) is int and 0 < ca['size'] <= 8 * 1024**2
        and re.fullmatch(r'[a-f0-9]{64}', ca.get('sha256', '')), 'APK stock CA bundle evidence is absent')
    negative = offline.get('negativeCases', {})
    require(set(negative) == NEGATIVE_CASES and all(row.get('status') == 'rejected'
        and type(row.get('exitCode')) is int and row['exitCode'] > 0
        and re.search(r'BAD signature|UNTRUSTED signature|integrity error', row.get('diagnostic', ''))
        for row in negative.values()), 'Actual APK negative signature/integrity checks are incomplete')
    trust = space.get('systemTrustHttps', {})
    require(trust.get('status') == 'passed' and trust.get('url') == ARCHIVE.trust_url(arch)
        and re.fullmatch(r'[a-f0-9]{64}', trust.get('outputSha256', '')), 'APK stock-system-trust HTTPS proof is absent')
    elf = space.get('elfAudit', {})
    require(elf.get('status') == 'passed' and elf.get('native') is True and elf.get('architecture') == arch
        and elf.get('libc') == 'musl' and elf.get('targetRid') == plan['targetRid']
        and elf.get('hostElfCount', 0) > 0 and elf.get('nonHostElfCount') == 0 and elf.get('stockLibraries'),
        'APK complete native ELF/provider closure is absent')
    if payload is not None:
        PROMOTION.validate_elf_report(elf, payload, arch)
    return report


def validate_lifecycle(report, build, upgrade, origin, public_key, *, payload=None):
    plan, next_plan = build['plan'], upgrade['plan']
    require(report.get('schemaVersion') == 1 and report.get('scope') == 'musl-apk-lifecycle'
        and report.get('status') == 'passed' and report.get('native') is True
        and report.get('architecture') == plan['architecture']['public'] and report.get('libc') == 'musl'
        and report.get('targetRid') == plan['targetRid'] and report.get('identity') == ARCHIVE.identity(plan)
        and report.get('orchestration') == origin and report.get('signingKey') == public_key,
        'APK lifecycle proof identity differs')
    require(next_plan['packageRevision'] == plan['packageRevision'] + 1
        and all(next_plan[key] == plan[key] for key in ('sdkVersion', 'producer', 'sdk', 'sourceManifestSha256')),
        'APK lifecycle upgrade must use the same admitted SDK')
    def install(source):
        return dict(operation='install-or-select', version=source['plan']['package']['version'],
                    sourceIndex=dict(name=source['repository']['path'], size=source['repository']['size'],
                                     sha256=source['repository']['sha256']))
    expected = [install(build), dict(operation='reinstall', version=plan['package']['version']),
        install(upgrade), install(build), dict(operation='remove-sdk-retain-explicit-host', status='passed'),
        install(build), dict(operation='remove-sdk-and-host', status='passed')]
    require(report.get('events') == expected, 'Actual APK reinstall/upgrade/rollback/removal events differ')
    official = report.get('official', {})
    host = official.get('host', {})
    require(official.get('version') == '10.0.303' and 'dotnet-host' in official.get('owner', '')
        and official.get('completeTreePreserved') is True and type(host.get('size')) is int and host['size'] > 0
        and re.fullmatch(r'[a-f0-9]{64}', host.get('sha256', '')),
        'APK lifecycle did not preserve the independent stock official SDK')
    if plan['sdkVersion'] != '10.0.403':
        import musl_side_by_side as COEXIST
        proof=report.get('communitySeriesCoexistence')
        require(isinstance(proof,dict) and isinstance(proof.get('referenceRecord'),dict),
                'Expanded SDK APK lifecycle needs actual second Community series coexistence')
        reference=COEXIST.authenticate_reference_record(proof['referenceRecord'],plan['architecture']['public'])
        COEXIST.validate(proof,build,upgrade,reference,
            candidate_payload=ARCHIVE.tools().snapshot(payload) if payload is not None else None)
    return report


def candidate_files(directory, builds):
    expected = {'build.rsa.pub', 'qualification-report.json', 'lifecycle-report.json', 'orchestration.json'}
    for label, build in builds.items():
        expected |= {label + '/' + name for name in ('package-build.json', *METADATA)}
        expected |= {label + '/repository/' + name for name in ('APKINDEX.tar.gz', *[r['path'] for r in NATIVE.package_roles(build)])}
        expected |= {label + '/aports/cbodotnet/' + kind + '/' + name
                     for kind in ('sdk', 'host') for name in ('APKBUILD', 'payload.tar.gz')}
    actual = set()
    for path in Path(directory).rglob('*'):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'APK envelope contains a link or special file')
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    require(actual == expected, 'APK candidate is not the closed public-data envelope')


def canonical_package_trees(plan, sdk, directory):
    staged, rootfs, commands, payload = APK.stage_payload(plan, sdk, directory)
    sdk_tree = staged / 'sdk-rootfs'
    shutil.copytree(rootfs, sdk_tree, symlinks=True, copy_function=os.link)
    (sdk_tree / 'usr/bin/cbodotnet').unlink()
    host_tree = staged / 'host-rootfs'
    (host_tree / 'usr/bin').mkdir(parents=True)
    shutil.copyfile(rootfs / 'usr/bin/cbodotnet', host_tree / 'usr/bin/cbodotnet')
    (host_tree / 'usr/bin/cbodotnet').chmod(0o755)
    license_path = host_tree / 'usr/share/licenses/cbodotnet-host/LICENSE'
    license_path.parent.mkdir(parents=True)
    shutil.copyfile(CONTRACT.ROOT / 'LICENSE', license_path)
    return dict(sdk=sdk_tree, host=host_tree), commands, payload


def verify_source_payload(source, expected, recipe, plan, kind):
    """Authenticate actual compressed source bytes and inspect tar paths in a stream."""
    source = ordinary_file(source)
    with source.open('rb') as stream:
        digest = APK.stream_digest(stream, 'sha512')
    require(ordinary_file(recipe).read_text() == APK.recipe(plan, kind, digest),
        'APKBUILD differs from the actual authenticated source payload and canonical recipe')
    snapshot = APK.payload_snapshot(source, {'dataOffset': 0})
    canonical = {'rootfs': ['directory', 0o755]}
    canonical.update({'rootfs/' + name: row for name, row in expected.items()})
    require(snapshot == canonical, 'Actual APK source gzip rootfs differs from the complete canonical package tree')
    return dict(sha512=digest, **descriptor(source))


def verify_build(directory, architecture, revision, inputs, public_key, canonical_directory):
    from musl_distribution import intake_plan
    directory = Path(directory)
    build = load_json(directory / 'package-build.json')
    plan, sdk = intake_plan(inputs, architecture, 'apk', revision)
    require(build.get('schemaVersion') == 1 and build.get('channel') == 'apk' and build.get('libc') == 'musl'
        and build.get('plan') == plan and build.get('payloadPreserved') is True and build.get('publicationQualified') is False
        and build.get('credentialPurpose') == 'ephemeral-build-candidate',
        'APK candidate build differs from the independently admitted source plan')
    require(load_json(directory / 'plan.json') == plan, 'APK retained plan differs')
    identity = APK.public_key_identity(public_key)
    require(build.get('signingKey') == identity and build.get('publicKeyAsset') == APK.descriptor(public_key),
        'APK candidate temporary public key identity differs')
    trees, commands, payload = canonical_package_trees(plan, sdk, canonical_directory)
    require(load_json(directory / 'payload-inventory.json') == payload
        and load_json(directory / 'command-inventory.json') == commands and build.get('commandInventory') == commands,
        'APK payload/command inventory differs from independently reconstructed source')
    packages = []
    for row in NATIVE.package_roles(build):
        path = ordinary_file(directory / 'repository' / row['path'])
        actual = APK.verify_apk(path, public_key)
        require(row == dict(actual, kind=row['kind']), 'APK signature/control/payload/byte descriptor differs')
        kind = row['kind']
        require(APK.payload_snapshot(path, actual) == ARCHIVE.tools().snapshot(trees[kind]),
            'APK actual payload differs from the complete canonical SDK/wrapper/license tree')
        dependencies = ['cbodotnet-host>=' + APK.HOST_VERSION, *plan['dependencies']] if kind == 'sdk' else ['busybox']
        require(sorted(actual['metadata'].get('depend', [])) == sorted(dependencies)
            and not any(actual['metadata'].get(field) for field in ('replaces', 'provides', 'install_if', 'triggers')),
            'APK control introduces unreviewed dependency or package routing')
        work = directory / 'aports/cbodotnet' / kind
        verify_source_payload(work / 'payload.tar.gz', ARCHIVE.tools().snapshot(trees[kind]), work / 'APKBUILD', plan, kind)
        packages.append(actual)
    index = APK.verify_index(directory / 'repository/APKINDEX.tar.gz', public_key, packages)
    require(build.get('repository') == index, 'APK repository index descriptor differs')
    return build, trees['sdk'] / plan['package']['root'].lstrip('/')


def verify_candidate(directory, architecture, origin, inputs, revision=1):
    require(revision == 1, 'Only APK r1 can be promoted; r2 is lifecycle validation only')
    directory = Path(directory)
    require(load_json(directory / 'orchestration.json') == origin, 'APK envelope orchestration differs')
    preliminary = {label: load_json(directory / label / 'package-build.json') for label in ('build', 'upgrade')}
    candidate_files(directory, preliminary)
    public = ordinary_file(directory / 'build.rsa.pub')
    with tempfile.TemporaryDirectory(prefix='musl-apk-canonical-') as temporary:
        first, payload = verify_build(directory / 'build', architecture, revision, inputs, public, Path(temporary) / 'first')
        second, _ = verify_build(directory / 'upgrade', architecture, revision + 1, inputs, public, Path(temporary) / 'second')
        require(load_json(directory / 'build/payload-inventory.json') == load_json(directory / 'upgrade/payload-inventory.json'),
            'APK lifecycle upgrade changed the unchanged qualified SDK')
        report = validate_native_report(load_json(directory / 'qualification-report.json'), first, origin, payload=payload)
        lifecycle = validate_lifecycle(load_json(directory / 'lifecycle-report.json'), first, second, origin,
                                       APK.public_key_identity(public), payload=payload)
    return first, second, report, lifecycle


def final_asset(architecture, name):
    require(architecture in CONTRACT.ARCHITECTURES and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', name),
            'Unsafe APK public asset name')
    return 'apk-' + architecture + '--' + name


def check_signature_bridge(original, permanent):
    require(permanent.get('signingPreservedCompressedControlAndPayload') is True
        and permanent.get('publicationQualified') is False
        and permanent.get('credentialPurpose') == 'protected-publication-candidate'
        and permanent.get('plan') == original['plan'], 'Protected APK signing changed build scope')
    before = {row['kind']: row for row in NATIVE.package_roles(original)}
    after = {row['kind']: row for row in NATIVE.package_roles(permanent)}
    require(permanent.get('priorNativePackages') == [dict((key, row[key])
        for key in ('path', 'size', 'sha256', 'controlSha256', 'dataSha256')) for row in original['packages']],
        'Permanent APK does not retain exact original native package digests')
    preserved = ('name', 'path', 'version', 'architecture', 'controlSha256', 'indexIdentity', 'dataSha256', 'metadata')
    require(all(all(after[kind][key] == row[key] for key in preserved) for kind, row in before.items()),
        'Permanent signature changed native-qualified APK control or payload')


def expected_package_snapshots(plan, payload, commands):
    """Independently bind the public inventory to every installed package path."""
    require(isinstance(payload, dict) and payload, 'Frozen APK SDK payload inventory is absent')
    root = plan['package']['root'].lstrip('/')
    expected = {}
    def directory(name):
        if name and name != '.':
            directory(str(Path(name).parent).replace('\\', '/'))
            expected[name] = ['directory', 0o755]
    directory(root)
    for name, row in payload.items():
        require(isinstance(name, str) and name and not name.startswith('/')
            and '..' not in name.split('/') and not any(c in name for c in '\\:\0\r\n'),
            'Unsafe frozen APK SDK inventory path')
        expected[root + '/' + name] = row
    versioned = plan['package']['launcher'].lstrip('/')
    directory('usr/bin')
    expected[versioned] = ['file', 0o755, hashlib.sha256(APK.launcher_text(plan).encode()).hexdigest()]
    doc = 'usr/share/doc/' + plan['package']['name']
    directory(doc)
    expected[doc + '/distribution.json'] = ['file', 0o644, hashlib.sha256(encoded(plan)).hexdigest()]
    for name in plan['licensePaths']:
        require(name in payload and payload[name][0] == 'file', 'Frozen APK original SDK license is absent')
        expected[doc + '/' + name] = ['file', 0o644, payload[name][2]]
    sdk_snapshot = expected
    host = {}
    for name in ('usr', 'usr/bin', 'usr/share', 'usr/share/licenses', 'usr/share/licenses/cbodotnet-host'):
        host[name] = ['directory', 0o755]
    host['usr/bin/cbodotnet'] = ['file', 0o755, hashlib.sha256(APK.default_launcher_text().encode()).hexdigest()]
    host['usr/share/licenses/cbodotnet-host/LICENSE'] = ['file', 0o644,
        hashlib.sha256((CONTRACT.ROOT / 'LICENSE').read_bytes()).hexdigest()]
    expected_commands = [dict(path=path, sha256=body[2], mode='0755',
        owner='cbodotnet-host' if path == '/usr/bin/cbodotnet' else plan['package']['name'])
        for path, body in sorted([('/' + versioned, sdk_snapshot[versioned]),
                                  ('/usr/bin/cbodotnet', host['usr/bin/cbodotnet'])])]
    require(commands == expected_commands, 'Frozen APK command inventory differs from canonical launcher bytes')
    return dict(sdk=sdk_snapshot, host=host)


def create_bundle(candidates, origin, output, *, apk_private_key, apk_public_key, keyring,
                  signing_key=None, gnupg_home=None, target_commit=None, policy=None, source_receiver=None, sdk_version="10.0.403"):
    require(set(candidates) == set(CONTRACT.ARCHITECTURES), 'Both native APK candidates are required')
    policy = policy if policy is not None else load_signing_policy()
    signing_key = signing_key or PROMOTION.active_signer(policy)
    require(signing_key == PROMOTION.active_signer(policy) and re.fullmatch(r'[a-f0-9]{40}', target_commit or ''),
        'Exact approved APK aggregate signer/publication commit required')
    from musl_release import validate_apk_signer
    validate_apk_signer(apk_public_key, apk_private_key)
    key_identity = APK.public_key_identity(apk_public_key)
    if source_receiver is None:
        from musl_distribution import receive_source
        from functools import partial
        source_receiver = partial(receive_source, sdk_version=sdk_version)
    output = ARCHIVE.fresh_directory(output)
    records, assets, common = [], {}, None
    def copy_asset(source, name):
        require(name not in assets, 'Duplicate APK publication asset')
        shutil.copyfile(ordinary_file(source), output / name)
        assets[name] = descriptor(output / name)
        return name
    key_name = copy_asset(apk_public_key, key_identity['filename'])
    with tempfile.TemporaryDirectory(prefix='musl-apk-freeze-') as temporary:
        for arch in CONTRACT.ARCHITECTURES:
            item = candidates[arch]
            directory = Path(item['directory'])
            inputs = source_receiver(arch, Path(temporary) / (arch + '-inputs'))
            native, upgrade, report, lifecycle = verify_candidate(directory, arch, origin, inputs)
            identity = PROMOTION.publication_identity(native['plan'])
            require(identity['channel'] == 'apk' and identity['sdkVersion'] == sdk_version and identity['packageRevision'] == 1
                and (common is None or common == identity), 'APK matrix mixes source/channel/version/revision')
            common = identity
            signed_dir = Path(temporary) / (arch + '-signed')
            permanent = NATIVE.resign_repository(directory / 'build', directory / 'build.rsa.pub', signed_dir,
                                                  apk_private_key, apk_public_key)
            check_signature_bridge(native, permanent)
            sdk = next(row for row in permanent['packages'] if row['kind'] == 'sdk')
            for row in permanent['packages']:
                copy_asset(signed_dir / 'repository' / row['path'], final_asset(arch, row['path']))
            copy_asset(signed_dir / 'repository/APKINDEX.tar.gz', final_asset(arch, 'APKINDEX.tar.gz'))
            for name in (*METADATA, 'package-build.json'):
                copy_asset(signed_dir / name, final_asset(arch, name))
            recipe_assets, source_assets = {}, {}
            for kind in ('sdk', 'host'):
                work = directory / 'build/aports/cbodotnet' / kind
                recipe_assets[kind] = copy_asset(work / 'APKBUILD', final_asset(arch, kind + '.APKBUILD'))
                source_assets[kind] = copy_asset(work / 'payload.tar.gz', final_asset(arch, kind + '-payload.tar.gz'))
            report_name = copy_asset(directory / 'qualification-report.json', 'qualification-' + arch + '.json')
            lifecycle_name = copy_asset(directory / 'lifecycle-report.json', 'lifecycle-' + arch + '.json')
            base = APK.repository_url(identity['sdkVersion'], arch, 1).rsplit('/', 1)[0] + '/'
            aggregate = f'https://github.com/{REPOSITORY}/releases/download/{CONTRACT.distribution_tag("apk", identity["sdkVersion"], 1)}/'
            records.append(dict(architecture=arch, targetRid=native['plan']['targetRid'],
                artifactAsset=final_asset(arch, sdk['path']), build=permanent, nativeBuild=native, nativeUpgradeBuild=upgrade,
                packageBuildAsset=final_asset(arch, 'package-build.json'),
                planAsset=final_asset(arch, 'plan.json'), payloadInventoryAsset=final_asset(arch, 'payload-inventory.json'),
                commandInventoryAsset=final_asset(arch, 'command-inventory.json'),
                recipeAssets=recipe_assets, packageSourceAssets=source_assets,
                qualificationReportAsset=report_name, lifecycleReportAsset=lifecycle_name,
                orchestration=origin, transport=item['transport'], repository=dict(url=base,
                    keyUrl=aggregate + key_name, keySha256=key_identity['sha256'], keyName=key_name,
                    indexSha256=permanent['repository']['sha256'], packages=[dict(name=row['path'], size=row['size'],
                        sha256=row['sha256'], url=base + row['path']) for row in permanent['packages']])))
    manifest = dict(schemaVersion=1, kind='musl-distribution-publication', repository=REPOSITORY,
        contractVersion=CONTRACT.load_contract()['schemaVersion'], tag=CONTRACT.distribution_tag('apk', common['sdkVersion'], 1),
        identity=common, targetCommit=target_commit, sourceOrchestration=origin, signingFingerprint=signing_key,
        status='validated-complete-matrix', records=sorted(records, key=lambda row: row['architecture']),
        assets=[assets[name] for name in sorted(assets)])
    (output / MANIFEST).write_bytes(encoded(manifest))
    command = ['gpg'] + (['--homedir', str(gnupg_home)] if gnupg_home is not None else [])
    subprocess.run(command + ['--batch', '--yes', '--armor', '--local-user', signing_key,
        '--output', str(output / SIGNATURE), '--detach-sign', str(output / MANIFEST)], check=True)
    validate_bundle(output, keyring, policy=policy)
    return manifest


def validate_bundle(directory, keyring, *, policy=None):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(path.is_symlink() for path in [directory, *directory.parents]),
        'Ordinary frozen APK bundle required')
    policy = policy if policy is not None else load_signing_policy()
    manifest = load_json(directory / MANIFEST)
    signer = verify_report_signature(directory / MANIFEST, directory / SIGNATURE, keyring, policy, WORKFLOW)
    identity = manifest.get('identity', {})
    require(manifest.get('schemaVersion') == 1 and manifest.get('kind') == 'musl-distribution-publication'
        and manifest.get('repository') == REPOSITORY and manifest.get('signingFingerprint') == signer
        and identity.get('channel') == 'apk' and identity.get('libc') == 'musl' and identity.get('packageRevision') == 1
        and manifest.get('tag') == CONTRACT.distribution_tag('apk', identity.get('sdkVersion'), 1)
        and re.fullmatch(r'[a-f0-9]{40}', manifest.get('targetCommit', '')), 'Frozen APK aggregate identity differs')
    catalog = CONTRACT.load_qualification_catalog()
    admitted = [row for row in catalog['builds'] if row['sdkVersion'] == identity['sdkVersion']
                and row['producerRevision'] == identity.get('producerRevision')]
    require(len(admitted) == 1 and admitted[0]['sourceReleaseTag'] == identity.get('sourceReleaseTag')
        and admitted[0]['sourceManifestSha256'] == identity.get('sourceManifestSha256'), 'Frozen APK source is no longer admitted')
    rows = manifest.get('assets', [])
    assets = {row.get('name'): row for row in rows}
    require(rows and len(assets) == len(rows) and all(isinstance(name, str)
        and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', name) for name in assets), 'Unsafe/duplicate frozen APK asset')
    require({p.name for p in directory.iterdir()} == set(assets) | {MANIFEST, SIGNATURE}, 'Frozen APK bundle is not a closed set')
    for name, row in assets.items():
        require(descriptor(directory / name) == row, 'Frozen APK asset bytes changed: ' + name)
    key_name = policy['apkSigner']['publicKeyName']
    public = ordinary_file(directory / key_name)
    key_identity = NATIVE.approved_signer(public, policy)
    records = manifest.get('records', [])
    require(len(records) == 2 and {row.get('architecture') for row in records} == set(CONTRACT.ARCHITECTURES),
        'Frozen APK native matrix is incomplete')
    used = {key_name}
    for row in records:
        arch, build = row['architecture'], row['build']
        plan = build['plan']
        require(PROMOTION.publication_identity(plan) == identity and plan['producer'] == admitted[0]['architectures'][arch]
            and plan['architecture'] == CONTRACT.ARCHITECTURES[arch] and row.get('targetRid') == plan['targetRid']
            and row.get('orchestration') == manifest['sourceOrchestration'], 'Frozen APK plan/source/orchestration differs')
        APK.validate_plan(plan, 'apk')
        require(build.get('signingKey') == key_identity and build.get('publicKeyAsset') == descriptor(public),
            'Frozen APK permanent public-key binding differs')
        require(row.get('qualificationReportAsset') == 'qualification-' + arch + '.json'
            and row.get('lifecycleReportAsset') == 'lifecycle-' + arch + '.json', 'Frozen APK native report role differs')
        check_signature_bridge(row['nativeBuild'], build)
        validate_native_report(load_json(directory / row['qualificationReportAsset']), row['nativeBuild'], manifest['sourceOrchestration'])
        validate_lifecycle(load_json(directory / row['lifecycleReportAsset']), row['nativeBuild'], row['nativeUpgradeBuild'],
                           manifest['sourceOrchestration'], row['nativeBuild']['signingKey'])
        sdk = next(p for p in NATIVE.package_roles(build) if p['kind'] == 'sdk')
        require(row.get('artifactAsset') == final_asset(arch, sdk['path']), 'Frozen APK SDK asset role differs')
        for field, name in [('packageBuildAsset', 'package-build.json'), ('planAsset', 'plan.json'),
                            ('payloadInventoryAsset', 'payload-inventory.json'), ('commandInventoryAsset', 'command-inventory.json')]:
            require(row.get(field) == final_asset(arch, name), 'Frozen APK metadata asset role differs')
            used.add(row[field])
        require(load_json(directory / row['packageBuildAsset']) == build
            and load_json(directory / row['planAsset']) == plan
            and load_json(directory / row['commandInventoryAsset']) == build['commandInventory'], 'Frozen APK build/plan/commands differ')
        snapshots = expected_package_snapshots(plan, load_json(directory / row['payloadInventoryAsset']), build['commandInventory'])
        for field, suffix in [('recipeAssets', '.APKBUILD'), ('packageSourceAssets', '-payload.tar.gz')]:
            require(row.get(field) == {kind: final_asset(arch, kind + suffix) for kind in ('sdk', 'host')},
                'Frozen APK source/recipe asset role differs')
            used.update(row[field].values())
        for kind in ('sdk', 'host'):
            verify_source_payload(directory / row['packageSourceAssets'][kind], snapshots[kind],
                                  directory / row['recipeAssets'][kind], plan, kind)
        package_rows = []
        for package in build['packages']:
            name = final_asset(arch, package['path'])
            current = APK.verify_apk(directory / name, public)
            # Public aggregate prefixes only the asset name, never its APK identity.
            current['path'] = package['path']
            require(dict(current, kind=package['kind']) == package, 'Frozen APK signed package descriptor differs')
            require(APK.payload_snapshot(directory / name, current) == snapshots[package['kind']],
                'Frozen APK package paths/payload/commands/licenses differ from the complete inventory')
            package_rows.append(current)
            used.add(name)
        index_name = final_asset(arch, 'APKINDEX.tar.gz')
        index = APK.verify_index(directory / index_name, public, package_rows)
        index['path'] = 'APKINDEX.tar.gz'
        require(index == build['repository'], 'Frozen APK index differs')
        used.add(index_name)
        for field, prefix in [('qualificationReportAsset', 'qualification-'), ('lifecycleReportAsset', 'lifecycle-')]:
            require(row.get(field) == prefix + arch + '.json', 'Frozen APK native report role differs')
            used.add(row[field])
        base = APK.repository_url(identity['sdkVersion'], arch, 1).rsplit('/', 1)[0] + '/'
        aggregate = f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
        require(row.get('repository') == dict(url=base, keyUrl=aggregate + key_name, keySha256=key_identity['sha256'],
            keyName=key_name, indexSha256=index['sha256'], packages=[dict(name=p['path'], size=p['size'], sha256=p['sha256'],
            url=base + p['path']) for p in build['packages']]), 'Frozen APK immutable repository URLs/bytes differ')
    require(used == set(assets), 'Frozen APK bundle contains unreferenced assets')
    return manifest


def freeze_apk(run_id, attempt, output, *, revision=1, apk_private_key, apk_public_key, keyring,
               signing_key=None, gnupg_home=None, api=None, sdk_version="10.0.403"):
    current = protected()
    api = api or GitHubReleases()
    with tempfile.TemporaryDirectory(prefix='musl-apk-receive-') as temporary:
        origin, candidates = receive_candidates(api, run_id, attempt, revision, Path(temporary) / 'received', current=current)
        return create_bundle(candidates, origin, output, apk_private_key=apk_private_key, apk_public_key=apk_public_key,
            keyring=keyring, signing_key=signing_key, gnupg_home=gnupg_home, target_commit=current['commit'], sdk_version=sdk_version)


def publish_release(api, tag, commit, title, body, files):
    expected = {name: dict(descriptor(path), name=name) for name, path in files.items()}
    release = api.find(tag)
    if release is None:
        require(api.api(f'repos/{REPOSITORY}/git/ref/tags/{tag}') is None, 'Refusing an unrelated APK repository tag')
        release = api.api(f'repos/{REPOSITORY}/releases', 'POST', dict(tag_name=tag, target_commitish=commit,
            name=title, body=body, draft=True, prerelease=False, make_latest='false'))
    require(release.get('tag_name') == tag and release.get('target_commitish') == commit
        and release.get('name') == title and release.get('body') == body and release.get('prerelease') is False,
        'Existing APK release has another immutable identity')
    verify_release_tag(api, tag, commit, allow_pending_draft=release.get('draft') is True)
    indexed = {row.get('name'): row for row in release.get('assets', [])}
    require(len(indexed) == len(release.get('assets', [])) and set(indexed) <= set(expected), 'Conflicting/duplicate remote APK assets')
    for name, wanted in expected.items():
        if name in indexed:
            require(indexed[name].get('size') == wanted['size'] and indexed[name].get('digest') == 'sha256:' + wanted['sha256'],
                'Refusing to replace an immutable APK asset: ' + name)
        else:
            require(release.get('draft') is True, 'A public APK release cannot gain or replace assets')
            # Repository assets have canonical package filenames; aggregate inputs
            # carry prefixes, so materialize only an ordinary local copy by name.
            path = Path(files[name])
            if path.name == name:
                api.upload(release, path)
            else:
                with tempfile.TemporaryDirectory(prefix='musl-apk-upload-') as temporary:
                    selected = Path(temporary) / name
                    shutil.copyfile(ordinary_file(path), selected)
                    api.upload(release, selected)
    release = api.get(release)
    verify_remote_assets(release, expected, api, public=False)
    if release['draft']:
        release = api.publish(release)
    release = api.get(release)
    verify_release_tag(api, tag, commit)
    verify_remote_assets(release, expected, api, public=True)
    return release


def publish_bundle(directory, keyring, *, api=None, policy=None, source_receiver=None, sdk_version="10.0.403"):
    current = protected()
    directory = Path(directory).absolute()
    manifest = validate_bundle(directory, keyring, policy=policy)
    api = api or GitHubReleases()
    source = manifest['sourceOrchestration']
    if source_receiver is None:
        from musl_distribution import receive_source
        from functools import partial
        source_receiver = partial(receive_source, sdk_version=manifest['identity']['sdkVersion'])
    # The signer does not execute native candidate SDKs. The publisher receives
    # the API-bound ZIPs again and repeats canonical source/control/payload checks.
    with tempfile.TemporaryDirectory(prefix='musl-apk-publish-recheck-') as temporary:
        temporary = Path(temporary)
        origin, candidates = receive_candidates(api, int(source['runId']), int(source['runAttempt']), 1,
                                                 temporary / 'received', current=current)
        require(origin == source, 'Frozen APK native origin changed before publication')
        for row in manifest['records']:
            arch = row['architecture']
            item = candidates[arch]
            require(item['transport'] == row['transport'], 'APK API artifact/job/ZIP changed after protected freeze')
            inputs = source_receiver(arch, temporary / (arch + '-inputs'))
            native, upgrade, report, lifecycle = verify_candidate(item['directory'], arch, origin, inputs)
            require(native == row['nativeBuild'] and upgrade == row['nativeUpgradeBuild']
                and report == load_json(directory / row['qualificationReportAsset'])
                and lifecycle == load_json(directory / row['lifecycleReportAsset']), 'Frozen APK native candidate was substituted')
    repositories = []
    key_name = manifest['records'][0]['repository']['keyName']
    for row in manifest['records']:
        arch = row['architecture']
        build = row['build']
        tag = APK.repository_tag(manifest['identity']['sdkVersion'], arch, 1)
        names = ['APKINDEX.tar.gz', *[p['path'] for p in build['packages']]]
        files = {name: directory / final_asset(arch, name) for name in names}
        files[key_name] = directory / key_name
        title = f'Community Build musl APK repository {manifest["identity"]["sdkVersion"]} {arch} r1'
        body = ('Immutable stock-signature-enforcing Alpine 3.24.4 APK repository.\n\n'
            'Authenticate its exact packages, index and dedicated RSA trust key using the signed aggregate manifest at '
            f'https://github.com/{REPOSITORY}/releases/tag/{manifest["tag"]}.\n')
        release = publish_release(api, tag, manifest['targetCommit'], title, body, files)
        repositories.append(dict(architecture=arch, tag=tag, releaseId=release['id'], releaseUrl=release['html_url']))
    files = {row['name']: directory / row['name'] for row in manifest['assets']}
    files.update({name: directory / name for name in (MANIFEST, SIGNATURE)})
    title, body = PROMOTION.publication_metadata(manifest)
    release = publish_release(api, manifest['tag'], manifest['targetCommit'], title, body, files)
    base = f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
    return dict(schemaVersion=1, kind='musl-distribution-publication-receipt', status='published-public-bytes-verified',
        identity=manifest['identity'], tag=manifest['tag'], releaseUrl=release['html_url'], releaseId=release['id'],
        manifestUrl=base + MANIFEST, signatureUrl=base + SIGNATURE, manifestSha256=descriptor(directory / MANIFEST)['sha256'],
        signingFingerprint=manifest['signingFingerprint'], repositoryReleases=repositories,
        assets=[dict(row, url=base + row['name']) for row in manifest['assets']])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    freeze = commands.add_parser('freeze-apk')
    freeze.add_argument('--run-id', type=int, required=True)
    freeze.add_argument('--attempt', type=int, default=1)
    freeze.add_argument('--revision', type=int, default=1)
    freeze.add_argument('--sdk-version', choices=sorted(CONTRACT.SOURCES), default='10.0.403')
    freeze.add_argument('--output', type=Path, required=True)
    freeze.add_argument('--apk-private-key', type=Path, required=True)
    freeze.add_argument('--apk-public-key', type=Path, required=True)
    freeze.add_argument('--signing-key')
    freeze.add_argument('--gnupg-home', type=Path)
    publish = commands.add_parser('publish')
    publish.add_argument('--bundle', type=Path, required=True)
    publish.add_argument('--output', type=Path, required=True)
    for child in (freeze, publish):
        child.add_argument('--keyring', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'freeze-apk':
        result = freeze_apk(args.run_id, args.attempt, args.output, revision=args.revision,
            apk_private_key=args.apk_private_key, apk_public_key=args.apk_public_key, keyring=args.keyring,
            signing_key=args.signing_key, gnupg_home=args.gnupg_home, sdk_version=args.sdk_version)
        print(json.dumps(dict(status='signed-and-frozen', tag=result['tag'])))
    else:
        require(args.output.parent.is_dir() and not args.output.exists(), 'Fresh APK publication receipt path required')
        result = publish_bundle(args.bundle, args.keyring)
        args.output.write_bytes(encoded(result))
        print(json.dumps(dict(status=result['status'], tag=result['tag'])))


if __name__ == '__main__':
    main()
