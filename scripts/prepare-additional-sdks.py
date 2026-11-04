#!/usr/bin/env python3
"""Validate the reviewed additional SDK preparation matrix and emit inert plans."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from distribution_contract import (ARCHITECTURES, BRANDING, INSTALLATION, load_contract,
                                   validate_qualified_producers)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
# Independently reviewed public manifest byte hashes. Changing a preparation
# row cannot authorize a different source release or producer.
MANIFEST_PINS = {
    '9.0.123': 'd7d68c0e8aedeb0b261f9d22dfc1aec73bc359919835caa16d7df70dc9238be9',
    '8.0.133': '6df02b36738250943cc4ae3ee32f6da4ec1c37a56fa6b248c08aeddff7760f6c',
    '7.0.120': 'b82e5c10814606e50f3682f0787452362cc6d82ee01ed0f652691a98f98e2e30',
    '6.0.136': '5e9404de6bde02aed938951182da03380ae37f7b506a8fbf46a186d4bca484fd',
    '5.0.214': '2a98666b057b5e8c2c8ef149c5ebca7528c2048d7cc1aa38611d48d0d104c67f',
    '3.1.426': '70049972a8781c309fae40e5f68d74847d0a9a590d36de4f25ecc2ad50578b09',
    '3.0.103': '3bac912a788bf38320cb45bfe6a62b3da0dbcaf50bb564a370ae7c5a09fb5e98',
}
SDK_ISSUES = dict(zip(MANIFEST_PINS, range(16, 23)))
TARGETS = {(channel, variant, arch)
           for channel, variants, arches in (
               ('deb', ('ubuntu-24.04', 'debian-13'), ('x64', 'aarch64')),
               ('rpm', ('fedora-45', 'rocky-9.8'), ('x64', 'aarch64')),
               ('oci', ('debian-13',), ('x64', 'aarch64')),
               ('aur', ('arch-rolling',), ('x64',)))
           for variant in variants for arch in arches}
EFFECTS = dict(contractModified=False, releaseAdmitted=False, sdkBuilt=False, packageQualified=False, published=False)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(Path(path).read_bytes())


def checkout_text_digest(path):
    path = Path(path)
    require(path.parent == ROOT / 'profiles' and path.suffix == '.json'
            or path == ROOT / 'releases/distribution-contract.json',
            'Checkout text hashing is limited to profile and contract JSON')
    # Git's text checkout can use CRLF on Windows. Preserve every other byte;
    # public manifests and SDK/source/evidence archives never use this helper.
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def unqualified_flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {'qualified', 'publicationAllowed', 'packageBuildAllowed', 'published',
                       'packageQualified', 'releaseAdmitted', 'currentContractAdmission'}:
                require(item is False, 'Preparation must not assert qualification, admission or publication: ' + key)
            unqualified_flags(item)
    elif isinstance(value, list):
        for item in value:
            unqualified_flags(item)


def target_identity(row):
    return row['channel'], row['variant'], row['architecture']


def validate_preparation(data, contract=None, catalog=None):
    """Only validate planning evidence; never call package admission/build APIs."""
    contract = contract if contract is not None else load_contract()
    catalog = catalog if catalog is not None else load(ROOT / 'releases/qualified-builds.json')
    effects = data.get('productionEffect', {})
    require(data.get('schemaVersion') == 1 and data.get('repository') == REPOSITORY
            and data.get('status') == 'preparation-only' and set(effects) == set(EFFECTS)
            and all(value is False for value in effects.values()),
            'An inert reviewed preparation record is required')
    unqualified_flags(data)
    require(data.get('summary') == dict(sdks=7, sourceProducerBindings=14, archiveObservations=42,
            channelTargets=77, channelTargetsExecuted=0, channelTargetsQualified=0), 'Preparation summary must retain zero qualified targets')
    template = data.get('targetTemplate', [])
    require(len(template) == 11 and {target_identity(row) for row in template} == TARGETS,
            'Preparation target template differs from the eleven reviewed targets')
    sdks = data.get('sdks', [])
    require(len(sdks) == 7 and {row['sdkVersion'] for row in sdks} == set(MANIFEST_PINS),
            'Exactly the seven reviewed additional SDKs are required')
    require(data.get('parentEpic') == dict(issueNumber=12, issueUrl=f'https://github.com/{REPOSITORY}/issues/12'),
            'Preparation parent epic differs from the registered work')
    require(data['currentContract']['path'] == 'releases/distribution-contract.json'
            and data['currentContract']['sha256'] == checkout_text_digest(ROOT / 'releases/distribution-contract.json')
            and data['currentContract']['admittedSdkVersions'] == list(contract['releases']),
            'Production contract changed; refresh preparation without admitting releases')
    gates = data['gateDefinitions']
    for sdk in sdks:
        version = sdk['sdkVersion']
        require(sdk['series'] == '.'.join(version.split('.')[:2]), 'Preparation namespace differs from the selected SDK series')
        issue = sdk['issueDraft']
        require(issue.get('issueNumber') == SDK_ISSUES[version]
                and issue.get('issueUrl') == f'https://github.com/{REPOSITORY}/issues/{SDK_ISSUES[version]}'
                and issue.get('registrationStatus') == 'registered', 'Preparation SDK issue differs from its registered work')
        require(version not in contract['releases'] and sdk.get('currentContractAdmission') is False
                and sdk.get('channelQualification') == 'not-run', 'An additional SDK is already admitted or claims execution')
        manifest = sdk['publicRelease']['manifest']
        raw = (json.dumps(manifest['document'], indent=2) + '\n').encode('utf-8')
        require(manifest.get('sha256') == MANIFEST_PINS[version]
                and len(raw) == manifest['size'] and hashlib.sha256(raw).hexdigest() == MANIFEST_PINS[version],
                'Audited public source manifest pin or bytes changed: ' + version)
        document = manifest['document']
        require(document.get('repository') == REPOSITORY and document.get('sdkVersion') == version
                and document.get('tag') == 'sdk-' + version, 'Public source manifest identity differs')
        validate_qualified_producers(document, sdk['target'], catalog)
        base = f'https://github.com/{REPOSITORY}/releases/download/sdk-{version}/'
        require(sdk['publicRelease']['url'] == f'https://github.com/{REPOSITORY}/releases/tag/sdk-{version}'
                and manifest['name'] == 'release-manifest.json' and manifest['url'] == base + manifest['name'],
                'Preparation source URL differs from its exact public release')
        require(set(sdk['architectures']) == set(ARCHITECTURES), 'Both exact qualified architectures are required')
        for arch, row in sdk['architectures'].items():
            expected = document['architectures'][arch]
            require(row['producerCatalogBinding'] == 'matched' and row['provenance'] == expected['provenance']
                    and row['provenance']['targetRid'] == ARCHITECTURES[arch]['rid'], 'Preparation producer or architecture differs')
            for kind in ('sdk', 'source', 'evidence'):
                asset = row[kind]
                require(all(asset.get(key) == expected[kind][key] for key in ('name', 'size', 'sha256'))
                        and asset.get('url') == base + expected[kind]['name'], 'Preparation asset differs from pinned source manifest')
            profile = f'profiles/dotnet-{version}-linux-{arch}.json'
            require(row['profile'] == profile and row['profileSha256'] == checkout_text_digest(ROOT / profile), 'Preparation profile changed')
            actual = load(ROOT / profile)
            require(actual['sdkVersion'] == version and all(sdk['sourceSelection'].get(key) == actual['source'].get(key)
                    for key in ('repository', 'commit', 'tag', 'branch')), 'Preparation source selection differs from exact profile')
            observations = row['archiveObservations']
            require(len(observations) == 3 and {item['variant'] for item in observations}
                    == {'ubuntu-22.04', 'ubuntu-24.04', 'debian-13'}, 'Archive evidence and channel matrix must remain separate')
        targets = sdk['targets']
        require(len(targets) == 11 and {target_identity(row) for row in targets} == TARGETS,
                'Duplicate, missing or unsupported SDK preparation target')
        legacy = version in {'5.0.214', '3.1.426', '3.0.103'}
        for target in targets:
            require(target.get('installedPackageOrContainerEvidence') == 'not-run'
                    and target.get('qualification') == 'not-qualified' and target.get('published') is False,
                    'Preparation must not claim package/container execution or qualification')
            require(target.get('state') == ('blocked-external-dependency-policy' if legacy else 'pending-native-channel-qualification'),
                    'Preparation dependency blocker changed without qualification')
            required = target.get('requiredGates', [])
            base_gates = {'version-admission', 'version-aware-harness', 'native-channel-lifecycle', 'signed-publication'}
            if legacy: base_gates.add('external-openssl11')
            if version.startswith('3.') and target['variant'] in {'debian-13', 'fedora-45', 'arch-rolling'}:
                base_gates.add('external-core3-icu')
            if target['channel'] == 'aur': base_gates.add('aur-publication-10')
            if target['variant'] in {'fedora-45', 'rocky-9.8', 'arch-rolling'}: base_gates.add('new-distro-runtime')
            require(set(required) == base_gates and all(key in gates for key in required), 'A required preparation gate was omitted')
    return data


def prepare_plans(data, sdk=None, channel=None, variant=None, arch=None, contract=None, catalog=None):
    validate_preparation(data, contract, catalog)
    require(sdk is None or sdk in MANIFEST_PINS, 'Unsupported additional SDK filter')
    require(channel is None or channel in {'deb', 'rpm', 'oci', 'aur'}, 'Unsupported preparation channel')
    require(variant is None or variant in {row[1] for row in TARGETS}, 'Unsupported preparation distro')
    require(arch is None or arch in ARCHITECTURES, 'Unsupported public architecture')
    plans = []
    for selected in data['sdks']:
        version, series = selected['sdkVersion'], selected['series']
        if sdk is not None and sdk != version:
            continue
        for target in selected['targets']:
            if any(wanted is not None and target[key] != wanted for key, wanted in
                   [('channel', channel), ('variant', variant), ('architecture', arch)]):
                continue
            architecture = target['architecture']
            source = selected['architectures'][architecture]
            root = INSTALLATION['rootTemplate'].format(series=series)
            launcher = INSTALLATION['launcherTemplate'].format(series=series)
            proposed = dict(root=root, versionedLauncher=launcher, defaultLauncher=INSTALLATION['defaultLauncher'],
                            sharedHost=INSTALLATION['commonPackage'], defaultSelection=INSTALLATION['defaultSelection'])
            if target['channel'] == 'oci':
                proposed['containerCommands'] = [INSTALLATION['containerCommandDirectory'] + '/' + name
                                                for name in ('cbodotnet-' + series, 'cbodotnet', 'dotnet')]
            plans.append(dict(kind='additional-sdk-preparation-plan', status='prepared-unqualified', execution='not-run',
                qualified=False, packageBuildAllowed=False, publicationAllowed=False, published=False,
                requiresProductionVerifiedPlan=True, sdkVersion=version,
                target={key: target[key] for key in ('channel', 'variant', 'architecture')},
                targetRid=ARCHITECTURES[architecture]['rid'], proposedNamespace=proposed,
                proposedPackageName=INSTALLATION['aurPackageTemplate' if target['channel'] == 'aur' else 'packageTemplate'].format(series=series),
                branding=dict(BRANDING),
                sourceManifestSha256=MANIFEST_PINS[version], sourceReleaseUrl=selected['publicRelease']['url'],
                expectedProducer=source['provenance'], expectedSdkAsset=source['sdk'],
                expectedSourceAsset=source['source'], existingRuntimeObservation=target['existingRuntimeObservation'],
                preparationState=target['state'], requiredGates=target['requiredGates'],
                issueDraftKey=selected['issueDraft']['key'], issueNumber=selected['issueDraft']['issueNumber'],
                issueUrl=selected['issueDraft']['issueUrl']))
    require(plans, 'No reviewed preparation target matches the requested filters')
    return dict(schemaVersion=1, kind='additional-sdk-preparation', status='prepared-unqualified', execution='not-run',
                qualified=False, packageBuildAllowed=False, publicationAllowed=False, published=False,
                parentEpic=dict(data['parentEpic']), planCount=len(plans), plans=plans)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', type=Path, default=ROOT / 'releases/additional-sdk-preparation.json')
    parser.add_argument('--sdk', choices=tuple(MANIFEST_PINS))
    parser.add_argument('--channel', choices=('deb', 'rpm', 'oci', 'aur'))
    parser.add_argument('--variant', choices=sorted({row[1] for row in TARGETS}))
    parser.add_argument('--arch', choices=tuple(ARCHITECTURES))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = prepare_plans(load(args.matrix), args.sdk, args.channel, args.variant, args.arch)
        encoded = (json.dumps(result, indent=2) + '\n').encode('utf-8')
        if args.output:
            with args.output.open('xb') as output:
                output.write(encoded)
            print(json.dumps(dict(status=result['status'], execution='not-run', planCount=result['planCount'], output=str(args.output))))
        else:
            print(encoded.decode(), end='')
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
