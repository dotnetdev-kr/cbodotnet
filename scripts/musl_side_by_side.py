"""Authenticate the real public SDK10 APK, then prove expanded-series coexistence.

prepare_reference is host-side, read-only network work. qualify mutates only a
fresh disposable native Alpine container, offline, using existing signed APKs.
Protected publishers use authenticate_reference_record and validate; neither
function executes an SDK or needs to download the large reference payload.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_distribution as DISTRIBUTION
import musl_package_native as NATIVE
import musl_packages as APK
import musl_apk_promotion as PROMOTION
from downstream_release import descriptor, encoded, ordinary_file, require

ROOT = CONTRACT.ROOT
REFERENCE_VERSION = '10.0.403'
METADATA = ('package-build.json', 'plan.json', 'payload-inventory.json', 'command-inventory.json')
OPERATIONS = ('candidate-install', 'reference-install', 'candidate-reinstall', 'candidate-upgrade',
              'candidate-rollback', 'reference-remove', 'reference-reinstall', 'candidate-remove',
              'candidate-reinstall-with-reference', 'reference-remove-fallback', 'candidate-remove-empty', 'host-remove')
RECORD_FIELDS = {'schemaVersion', 'kind', 'architecture', 'aggregate', 'plan', 'build', 'files'}
PROOF_FIELDS = {'schemaVersion', 'scope', 'status', 'native', 'architecture', 'libc', 'targetRid', 'identity',
                'upgradeIdentity', 'referenceRecord', 'networkForTransactions', 'executionUser', 'candidateSigningKey',
                'inputs', 'payloadInventories', 'official', 'events', 'allCommunityPathsRemoved', 'approvedTrustRestored'}


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def load(path):
    return json.loads(ordinary_file(path).read_bytes())


def pinned_receipt():
    status = load(ROOT / 'releases/musl-status.json')
    rows = [row for row in status['publications'] if row.get('identity', {}).get('sdkVersion') == REFERENCE_VERSION
            and row['identity'].get('channel') == 'apk' and row['identity'].get('packageRevision') == 1]
    require(len(rows) == 1 and rows[0].get('status') == 'published-postverified',
            'Exactly one already public-verified SDK10 r1 APK reference is required')
    receipt = rows[0]
    catalog = CONTRACT.load_qualification_catalog()
    producers = [row for row in catalog['builds'] if row['sdkVersion'] == REFERENCE_VERSION and row['producerRevision'] == 1]
    require(len(producers) == 1 and receipt['identity']['sourceReleaseTag'] == producers[0]['sourceReleaseTag']
            and receipt['identity']['sourceManifestSha256'] == producers[0]['sourceManifestSha256'],
            'SDK10 APK reference must retain its exact independently qualified source')
    return receipt, producers[0]


def reference_files(architecture, receipt=None):
    require(architecture in CONTRACT.ARCHITECTURES, 'Exact native reference CPU required')
    receipt = receipt or pinned_receipt()[0]
    assets = {row['name']: row for row in receipt['assets']}
    policy = load(ROOT / 'releases/musl-signing-policy.json')['apkSigner']
    sdk = 'cbodotnet-sdk-10.0-' + REFERENCE_VERSION + '-r1.apk'
    host = 'cbodotnet-host-' + APK.HOST_VERSION + '.apk'
    result = {}
    names = [(name, 'apk-' + architecture + '--' + name) for name in METADATA]
    names += [('repository/' + name, 'apk-' + architecture + '--' + name)
              for name in ('APKINDEX.tar.gz', sdk, host)]
    names += [(policy['publicKeyName'], policy['publicKeyName'])]
    for relative, asset in names:
        row = assets[asset]
        result[relative] = dict(name=Path(relative).name, size=row['size'], sha256=row['sha256'])
    return result


def authenticate_reference_record(record, architecture):
    """Pure authentication against retained public receipt hashes and source pins."""
    receipt, producer = pinned_receipt()
    require(isinstance(record, dict) and set(record) == RECORD_FIELDS
            and record.get('schemaVersion') == 1 and record.get('kind') == 'musl-public-apk-coexistence-reference'
            and record.get('architecture') == architecture, 'Closed exact SDK10 reference record required')
    aggregate = {key: receipt[key] for key in ('tag', 'manifestUrl', 'manifestSha256', 'signingFingerprint')}
    require(record['aggregate'] == aggregate and record['files'] == reference_files(architecture, receipt),
            'Reference signed manifest/key/index/package bytes differ from retained public SDK10 history')
    plan, build = record['plan'], record['build']
    for name, value in (('plan.json', plan), ('package-build.json', build)):
        raw = encoded(value)
        require(len(raw) == record['files'][name]['size']
                and hashlib.sha256(raw).hexdigest() == record['files'][name]['sha256'],
                'Reference canonical public metadata bytes differ: ' + name)
    expected = {key: value for key, value in receipt['identity'].items() if key != 'channel'}
    require(ARCHIVE.identity(plan) == dict(expected, targetRid=CONTRACT.ARCHITECTURES[architecture]['rid'])
            and plan['channel'] == 'apk' and build['plan'] == plan
            and plan['producer'] == producer['architectures'][architecture], 'Reference source/provenance/CPU identity differs')
    NATIVE.package_roles(build)
    policy = load(ROOT / 'releases/musl-signing-policy.json')['apkSigner']
    signing = dict(filename=policy['publicKeyName'], algorithm='RSA-4096', signatureType='RSA256',
                   digestAlgorithm='SHA-256', spkiSha256=policy['spkiDerSha256'], sha256=policy['publicKeySha256'])
    require(build['signingKey'] == signing
            and build['publicKeyAsset'] == record['files'][policy['publicKeyName']], 'Reference approved permanent APK key differs')
    return copy.deepcopy(record)


def read_reference_context(context, architecture):
    context = Path(context).absolute()
    require(context.is_dir() and not any(p.is_symlink() for p in (context, *context.parents)), 'Ordinary reference context required')
    record = authenticate_reference_record(load(context / 'reference.json'), architecture)
    paths = list(context.rglob('*'))
    require(not any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths), 'Reference context contains redirected or special files')
    require({p.relative_to(context).as_posix() for p in paths if p.is_file()} == set(record['files']) | {'reference.json'},
            'Reference context is not its closed public-data file set')
    for name, expected in record['files'].items():
        require(descriptor(context / name) == expected, 'Reference public asset changed: ' + name)
    public = context / record['build']['signingKey']['filename']
    require(NATIVE.approved_signer(public) == record['build']['signingKey'], 'Reference permanent trust identity differs')
    packages = []
    for row in record['build']['packages']:
        current = APK.verify_apk(context / 'repository' / row['path'], public)
        require(dict(current, kind=row['kind']) == row, 'Reference APK signature or package identity differs')
        packages.append(current)
    require(APK.verify_index(context / 'repository/APKINDEX.tar.gz', public, packages) == record['build']['repository'],
            'Reference approved signed APK index differs')
    payload = load(context / 'payload-inventory.json')
    require(digest(payload) == record['files']['payload-inventory.json']['sha256'], 'Reference payload inventory is not canonical public JSON')
    return record, public, payload


def prepare_reference(architecture, workspace):
    """Host-only: authenticate actual public signed APKs and unchanged SDK10 source."""
    workspace = ARCHIVE.fresh_directory(workspace)
    bundle, manifest, raw, signer, keyring, _ = DISTRIBUTION.public_bundle('apk', 1, workspace, sdk_version=REFERENCE_VERSION)
    receipt, _ = pinned_receipt()
    require(hashlib.sha256(raw).hexdigest() == receipt['manifestSha256'] and signer == receipt['signingFingerprint']
            and manifest['identity'] == receipt['identity'], 'Actual signed APK reference differs from retained public history')
    PROMOTION.validate_bundle(bundle, keyring)
    rows = [row for row in manifest['records'] if row['architecture'] == architecture]
    require(len(rows) == 1, 'One exact public SDK10 native reference record required')
    build = rows[0]['build']
    inputs = DISTRIBUTION.receive_source(architecture, workspace / 'source', anonymous=True, sdk_version=REFERENCE_VERSION)
    plan, sdk = DISTRIBUTION.intake_plan(inputs, architecture, 'apk', 1)
    require(build['plan'] == plan, 'Reference APK source is not the unchanged independently qualified SDK10')
    canonical, _, _, payload = APK.stage_payload(plan, sdk, workspace / 'canonical-source')
    require(load(bundle / ('apk-' + architecture + '--payload-inventory.json')) == payload,
            'Actual signed reference payload differs from the complete original SDK10 source bytes')
    context = ARCHIVE.fresh_directory(workspace / 'reference')
    files = reference_files(architecture, receipt)
    for name in files:
        source_name = Path(name).name
        source = bundle / (source_name if source_name == build['signingKey']['filename']
                           else 'apk-' + architecture + '--' + source_name)
        target = context / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ordinary_file(source), target)
    record = dict(schemaVersion=1, kind='musl-public-apk-coexistence-reference', architecture=architecture,
                  aggregate={key: receipt[key] for key in ('tag', 'manifestUrl', 'manifestSha256', 'signingFingerprint')},
                  plan=plan, build=build, files=files)
    authenticate_reference_record(record, architecture)
    (context / 'reference.json').write_bytes(encoded(record))
    read_reference_context(context, architecture)
    return dict(directory=str(context), record=record)


def package_inputs(build):
    return [{key: row[key] for key in ('kind', 'path', 'size', 'sha256', 'controlSha256', 'dataSha256')}
            for row in build['packages']]


def event_states(build, upgrade, reference):
    first, second, fixed = build['plan'], upgrade['plan'], reference['plan']
    states = [(first, None), (first, fixed), (first, fixed), (second, fixed), (first, fixed), (first, None),
              (first, fixed), (None, fixed), (first, fixed), (first, None), (None, None), (None, None)]
    return [(name, {'candidate': candidate, 'reference': ref}) for name, (candidate, ref) in zip(OPERATIONS, states)]


def selected_version(state):
    versions = [plan['sdkVersion'] for plan in state.values() if plan is not None]
    return max(versions, key=lambda v: tuple(map(int, v.split('.')))) if versions else None


def qualify(build_directory, upgrade_directory, public_key, reference_context, architecture, output):
    """Container-only: real two-series install/upgrade/rollback/remove transactions."""
    ARCHIVE.native_guard(architecture)
    require(os.geteuid() == 0 and (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists())
            and {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'},
            'Real coexistence mutation requires a fresh root-owned disposable offline native Alpine container')
    user = pwd.getpwnam('cbot-musl')
    require(user.pw_uid == user.pw_gid == 10001, 'The actual coexistence SDK execution user must be non-root 10001')
    output = Path(output)
    require(output.is_absolute() and output.parent.is_dir() and not output.exists()
            and not any(p.is_symlink() for p in (output, *output.parents)), 'Fresh ordinary coexistence proof output required')
    first, second = Path(build_directory), Path(upgrade_directory)
    build, upgrade = load(first / 'package-build.json'), load(second / 'package-build.json')
    for value in (build, upgrade):
        NATIVE.package_roles(value)
        NATIVE.qualified_plan_source(value['plan'])
        require(value['plan']['architecture']['public'] == architecture and value.get('credentialPurpose') != 'ephemeral-fixture',
                'Real source-qualified native candidate packages are required')
    require(build['plan']['sdkVersion'] != REFERENCE_VERSION and upgrade['plan']['sdkVersion'] == build['plan']['sdkVersion']
            and upgrade['plan']['packageRevision'] == build['plan']['packageRevision'] + 1
            and all(upgrade['plan'][k] == build['plan'][k] for k in ('sdk', 'producer', 'sourceManifestSha256')),
            'Expanded SDK lifecycle revision must preserve the exact source payload')
    reference, reference_key, reference_payload = read_reference_context(reference_context, architecture)
    public = ordinary_file(public_key)
    identity = APK.public_key_identity(public)
    payload = load(first / 'payload-inventory.json')
    require(load(second / 'payload-inventory.json') == payload, 'Candidate revision changed the complete SDK payload')
    for directory, value in ((first, build), (second, upgrade)):
        require(value['signingKey'] == identity, 'Candidate lifecycle trust identity differs')
        packages = []
        for row in value['packages']:
            current = APK.verify_apk(directory / 'repository' / row['path'], public)
            require(dict(current, kind=row['kind']) == row, 'Candidate APK bytes/signature changed')
            packages.append(current)
        require(APK.verify_index(directory / 'repository/APKINDEX.tar.gz', public, packages) == value['repository'],
                'Candidate signed APK index changed')
    # A same-version common package must have exactly the same complete payload.
    host = next(row for row in build['packages'] if row['kind'] == 'host')
    ref_host = next(row for row in reference['build']['packages'] if row['kind'] == 'host')
    require(APK.payload_snapshot(first / 'repository' / host['path'], host)
            == APK.payload_snapshot(Path(reference_context) / 'repository' / ref_host['path'], ref_host),
            'The common host package changed without its own version bump')
    plans = (build['plan'], reference['plan'])
    require(not Path('/usr/bin/cbodotnet').exists() and all(not Path(plan['package']['root']).exists()
            and not Path(plan['package']['launcher']).exists() for plan in plans), 'Fresh Community SDK namespace required')
    official = Path('/usr/bin/dotnet')
    require(official.is_file(), 'Independent stock official SDK must remain installed')
    official_version = ARCHIVE.run([official, '--version']).strip()
    official_owner = ARCHIVE.run(['apk', 'info', '--who-owns', official]).strip()
    require(official_version == '10.0.303' and 'dotnet-host' in official_owner, 'Exact independent stock official SDK required')
    official_tree = ARCHIVE.tools().snapshot(official.resolve().parent)
    official_record = dict(version=official_version, owner=official_owner, host=descriptor(official.resolve()), treeSha256=digest(official_tree))
    keys = []
    for source in (public, reference_key):
        target = Path('/etc/apk/keys') / source.name
        if target in keys:
            require(target.read_bytes() == source.read_bytes(), 'One APK trust filename names different keys')
            continue
        require(not target.exists(), 'Coexistence must not replace a preexisting APK trust key')
        shutil.copyfile(source, target)
        target.chmod(0o644)
        keys.append(target)
    environment = NATIVE.consumer_environment()
    events = []
    inventories = dict(candidate=digest(payload), reference=digest(reference_payload))
    def command_version(command, expected):
        process = subprocess.run(['su', 'cbot-musl', '-c', shlex.join([str(command), '--version'])],
                                 env=environment, text=True, capture_output=True)
        require(process.returncode == 0 and process.stdout == expected + '\n'
                and process.stderr == APK.BRANDING['displayName'] + '\n', 'Actual side-by-side command selection/branding differs')
    def check(name, state):
        installed = {}
        for label, plan in state.items():
            original = build['plan'] if label == 'candidate' else reference['plan']
            root, launcher = Path(original['package']['root']), Path(original['package']['launcher'])
            if plan is None:
                require(not root.exists() and not launcher.exists(), 'Removed Community SDK path remains')
                continue
            expected_payload = payload if label == 'candidate' else reference_payload
            require(ARCHIVE.tools().snapshot(root) == expected_payload, 'Complete immutable installed SDK payload changed')
            command_version(launcher, plan['sdkVersion'])
            detail = json.loads(ARCHIVE.run([launcher, '--cbodotnet-info'], env=environment))
            require(all(detail.get(k) == v for k, v in ARCHIVE.identity(plan).items())
                    and detail.get('sdkRoot') == str(root), 'Versioned command escaped its exact source SDK root')
            installed[label] = dict(identity=ARCHIVE.identity(plan), payloadSha256=inventories[label])
        selected = selected_version(state)
        if selected is not None:
            command_version('/usr/bin/cbodotnet', selected)
        else:
            result = subprocess.run(['/usr/bin/cbodotnet', '--version'], capture_output=True) if name != 'host-remove' else None
            require((result is not None and result.returncode == 127) if name != 'host-remove'
                    else not Path('/usr/bin/cbodotnet').exists(), 'Empty/default host removal semantics differ')
        require(ARCHIVE.run([official, '--version']).strip() == official_version
                and ARCHIVE.run(['apk', 'info', '--who-owns', official]).strip() == official_owner
                and descriptor(official.resolve()) == official_record['host']
                and ARCHIVE.tools().snapshot(official.resolve().parent) == official_tree,
                'Community side-by-side transactions changed the independent official SDK')
        events.append(dict(operation=name, installed=installed, defaultSdkVersion=selected,
                           defaultExitCode=0 if selected else (None if name == 'host-remove' else 127),
                           officialTreeSha256=official_record['treeSha256']))
    def install(directory, value, *options):
        ARCHIVE.run(['apk', '--no-cache', '--no-network', '--repository', Path(directory) / 'repository/APKINDEX.tar.gz',
                     'add', *options, value['plan']['package']['name'] + '=' + value['plan']['package']['version'],
                     'cbodotnet-host=' + APK.HOST_VERSION])
    for name, state in event_states(build, upgrade, reference):
        if name in ('candidate-install', 'candidate-rollback', 'candidate-reinstall-with-reference'):
            install(first, build)
        elif name in ('reference-install', 'reference-reinstall'):
            install(reference_context, reference['build'])
        elif name == 'candidate-reinstall':
            ARCHIVE.run(['apk', '--no-cache', '--no-network', '--repository', first / 'repository/APKINDEX.tar.gz',
                         'fix', '--reinstall', build['plan']['package']['name']])
        elif name == 'candidate-upgrade':
            install(second, upgrade, '--upgrade')
        elif name.startswith('reference-remove'):
            ARCHIVE.run(['apk', '--no-network', 'del', reference['plan']['package']['name']])
        elif name.startswith('candidate-remove'):
            ARCHIVE.run(['apk', '--no-network', 'del', build['plan']['package']['name']])
        else:
            ARCHIVE.run(['apk', '--no-network', 'del', 'cbodotnet-host'])
        check(name, state)
    for target in keys:
        target.unlink()
    proof = dict(schemaVersion=1, scope='musl-apk-community-series-coexistence', status='passed', native=True,
        architecture=architecture, libc='musl', targetRid=build['plan']['targetRid'], identity=ARCHIVE.identity(build['plan']),
        upgradeIdentity=ARCHIVE.identity(upgrade['plan']), referenceRecord=reference, networkForTransactions='none',
        executionUser=dict(name='cbot-musl', uid=10001, gid=10001), candidateSigningKey=identity,
        inputs=dict(candidate=package_inputs(build), upgrade=package_inputs(upgrade), reference=package_inputs(reference['build'])),
        payloadInventories=inventories, official=official_record, events=events,
        allCommunityPathsRemoved=True, approvedTrustRestored=all(not p.exists() for p in keys))
    validate(proof, build, upgrade, reference, candidate_payload=payload)
    output.write_bytes(encoded(proof))
    return proof


def validate(proof, build, upgrade, reference_record, *, candidate_payload=None):
    """Protected pure replay of source/package identities and every native state."""
    architecture = build['plan']['architecture']['public']
    reference = authenticate_reference_record(reference_record, architecture)
    require(build['plan']['package']['root'] != reference['plan']['package']['root']
            and build['plan']['package']['launcher'] != reference['plan']['package']['launcher']
            and upgrade['plan']['packageRevision'] == build['plan']['packageRevision'] + 1
            and all(upgrade['plan'][k] == build['plan'][k]
                    for k in ('sdkVersion', 'sdk', 'producer', 'sourceManifestSha256', 'targetRid')),
            'Coexistence needs distinct series and an unchanged candidate source across packaging revisions')
    require(isinstance(proof, dict) and set(proof) == PROOF_FIELDS
            and proof.get('schemaVersion') == 1 and proof.get('scope') == 'musl-apk-community-series-coexistence'
            and proof.get('status') == 'passed' and proof.get('native') is True and proof.get('libc') == 'musl'
            and proof.get('architecture') == architecture and proof.get('targetRid') == build['plan']['targetRid']
            and proof.get('identity') == ARCHIVE.identity(build['plan'])
            and proof.get('upgradeIdentity') == ARCHIVE.identity(upgrade['plan']) and proof.get('referenceRecord') == reference
            and build['plan']['sdkVersion'] != REFERENCE_VERSION and proof.get('networkForTransactions') == 'none'
            and proof.get('executionUser') == dict(name='cbot-musl', uid=10001, gid=10001)
            and proof.get('candidateSigningKey') == build['signingKey'] == upgrade['signingKey'],
            'Actual native two-Community-series proof/source/trust identity differs')
    require(proof.get('inputs') == dict(candidate=package_inputs(build), upgrade=package_inputs(upgrade),
                                      reference=package_inputs(reference['build'])), 'Actual coexistence APK bytes differ')
    inventories = proof.get('payloadInventories', {})
    require(set(inventories) == {'candidate', 'reference'} and all(re.fullmatch('[a-f0-9]{64}', value)
            for value in inventories.values()) and inventories['reference'] == reference['files']['payload-inventory.json']['sha256']
            and (candidate_payload is None or inventories['candidate'] == digest(candidate_payload)),
            'Complete immutable coexistence payload inventory differs')
    official = proof.get('official', {})
    require(official.get('version') == '10.0.303' and 'dotnet-host' in official.get('owner', '')
            and type(official.get('host', {}).get('size')) is int and official['host']['size'] > 0
            and re.fullmatch('[a-f0-9]{64}', official['host'].get('sha256', ''))
            and re.fullmatch('[a-f0-9]{64}', official.get('treeSha256', '')), 'Independent stock official SDK proof differs')
    expected = []
    for name, state in event_states(build, upgrade, reference):
        installed = {label: dict(identity=ARCHIVE.identity(plan), payloadSha256=inventories[label])
                     for label, plan in state.items() if plan is not None}
        selected = selected_version(state)
        expected.append(dict(operation=name, installed=installed, defaultSdkVersion=selected,
            defaultExitCode=0 if selected else (None if name == 'host-remove' else 127), officialTreeSha256=official['treeSha256']))
    require(proof.get('events') == expected and proof.get('allCommunityPathsRemoved') is True
            and proof.get('approvedTrustRestored') is True, 'Actual install/reinstall/upgrade/rollback/fallback/removal state matrix differs')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare-reference')
    prepare.add_argument('--arch', choices=tuple(CONTRACT.ARCHITECTURES), required=True)
    prepare.add_argument('--workspace', type=Path, required=True)
    prepare.add_argument('--output-record', type=Path)
    native = commands.add_parser('qualify')
    native.add_argument('--arch', choices=tuple(CONTRACT.ARCHITECTURES), required=True)
    for name in ('build', 'upgrade-build', 'public-key', 'reference', 'output'):
        native.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare-reference':
        result = prepare_reference(args.arch, args.workspace)
        if args.output_record:
            require(not args.output_record.exists(), 'Fresh reference record output required')
            args.output_record.write_bytes(encoded(result['record']))
        print(json.dumps(dict(directory=result['directory'], referenceVersion=REFERENCE_VERSION)))
    else:
        qualify(args.build, args.upgrade_build, args.public_key, args.reference, args.arch, args.output)
        print(json.dumps(dict(status='passed', scope='two-real-Community-SDK-series', architecture=args.arch)))


if __name__ == '__main__':
    main()
