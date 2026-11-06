"""Bind additional installer SDK qualification to every signed catalog target."""
import hashlib
import re

from consumer_archive import FUNCTIONAL_CHECKS
from downstream_release import encoded, require


SDK_CHECKS = ('bootstrap-authentication', 'signature-authentication', 'source-producer-linkage',
              'exact-version-install', 'idempotent-install', 'tracked-channel-update', 'rollback',
              'explicit-sdk-run', 'highest-series-default', 'versioned-alias', 'offline-build-runtime',
              'http-crypto-globalization', 'tamper-rejection', 'concurrency', 'interrupted-activation',
              'revocation-rejection', 'unqualified-rejection', 'official-package-coexistence',
              'community-package-coexistence', 'other-sdk-preservation', 'removal')


def validate_previous_tool_upgrade(value, row, baseline, catalog, tool_version, *, compatibility_catalog=None):
    """Bind the actual previous client cycle to signed binaries and owned SDK state."""
    require(isinstance(value, dict), 'Previous 0.2 tool upgrade evidence is required')
    public = row['bootstrapBinarySource'] == 'public-https'
    protocol = ('actual-0.2.0-self-update-rollback-reupgrade' if public
                else 'protected-frozen-candidate-bootstrap-from-0.2.0')
    projection=compatibility_catalog if catalog['schemaVersion']==3 else catalog
    require(isinstance(projection,dict) and projection['schemaVersion']==2,
            'Previous clients require their exact compatible schema2 catalog')
    prior_tools = [tool for tool in projection['tools'] if tool['version'] == '0.2.0'
                   and 'tool/' + tool['version'] + '/' + tool['rid'] not in catalog['revoked']]
    old = [tool for tool in prior_tools if tool['rid'] == row['rid']]
    previous = dict(projection, sequence=projection['sequence'] - 1, tools=prior_tools)
    require(len(old) == 1 and value.get('status') == 'passed'
            and value.get('fromVersion') == '0.2.0' and value.get('toVersion') == tool_version
            and value.get('protocol') == protocol
            and value.get('oldBinarySha256') == old[0]['binary']['sha256']
            and value.get('currentBinarySha256') == row['binarySha256']
            and value.get('previousCatalogSha256') == hashlib.sha256(encoded(previous)).hexdigest()
            and value.get('baselineCatalogSha256') == value.get('previousCatalogSha256')
            and value.get('currentCatalogSha256') == row['catalogSha256']
            and value.get('baseline') == {key: baseline[key] for key in ('sdkVersion', 'revision', 'rid')}
            and value.get('baselineReceiptUnchanged') is True
            and value.get('baselineOwnedStateUnchanged') is True
            and value.get('baselinePayloadVerified') is True
            and value.get('rollbackVerified') is public,
            'Previous tool upgrade/rollback evidence differs from signed binaries or retained SDK state')
    if catalog['schemaVersion']==3:
        require(value.get('compatibilityCatalogSha256')==catalog['compatibilityCatalog']['sha256']
                ==hashlib.sha256(encoded(projection)).hexdigest(),
                'Previous client migration differs from the signed modern projection')
    for name in ('baselineReceiptSha256', 'baselineInventorySha256',
                 'baselineCatalogSha256', 'baselineOwnedStateSha256'):
        require(isinstance(value.get(name), str) and re.fullmatch('[a-f0-9]{64}', value[name]),
                'Previous tool upgrade retained-state hash is incomplete')


def validate_additional_sdk_qualifications(catalog, observations, *, tool_version=None, compatibility_catalog=None):
    """Return exact passed cells; catalog-only admission never constitutes evidence."""
    expected = {}
    for sdk in catalog['sdks']:
        if sdk['sdkVersion'] == '10.0.403':
            continue  # The original per-target report owns the SDK10 migration regression.
        if catalog['schemaVersion']==3 and sdk['requiresLegacyProvider']:
            continue  # The separately gated legacy matrix owns these cells.
        require(catalog['schemaVersion'] in (2,3) and not sdk['requiresLegacyProvider'],
                'Additional installer SDKs require the modern catalog and no legacy provider')
        require(f"{sdk['sdkVersion']}-r{sdk['revision']}/{sdk['rid']}" not in catalog['revoked'],
                'A revoked SDK cannot be advertised as qualified for new installation')
        for target in sdk['targets']:
            key = (sdk['sdkVersion'], sdk['rid'], target['os'], target['versionId'])
            require(key not in expected and target['rid'] == sdk['rid'], 'Duplicate or inconsistent SDK target')
            expected[key] = (sdk, target)
    project_required=tool_version is not None and tuple(map(int,tool_version.split('.'))) >= (0,3,0)
    rows = []
    seen = set()
    for observation in observations:
        if project_required:
            from cbodotnetup_project import validate_reference_evidence
            require(isinstance(observation.get('projectSdkReference'),dict),'Native project-SDK reference evidence is required for this tool release')
            validate_reference_evidence(observation['projectSdkReference'])
        additions = observation.get('additionalSdkQualifications', [])
        require(isinstance(additions, list), 'Additional SDK qualification must be an array')
        for row in additions:
            target = row['target']
            key = (row['sdkVersion'], row['rid'], target['os'], target['versionId'])
            require(key in expected and key not in seen, 'Unexpected or duplicate additional SDK cell')
            sdk, admitted_target = expected[key]
            arch = {'linux-x64': 'x64', 'linux-arm64': 'aarch64'}.get(row['rid'])
            require(row['status'] == 'passed' and row['revision'] == sdk['revision']
                    and target == admitted_target and row['archive'] == sdk['archive']
                    and row['sourceManifestSha256'] == sdk['sourceManifestSha256']
                    and row['catalogSha256'] == observation['catalogSha256']
                    and row['bootstrapBinarySource'] == observation['bootstrapBinarySource']
                    and row['binarySha256'] == observation['binarySha256']
                    and row['bootstrapSha256'] == observation['bootstrapSha256']
                    and row['variant'] == observation['variant'] == target['os'] + '-' + target['versionId']
                    and row['architecture'] == observation['architecture'] == arch,
                    'Additional SDK evidence differs from its signed target/source/artifact')
            require(row['networkForBuild'] == 'none' and row['userId'] == 10001
                    and row['functionalChecks'] == dict.fromkeys(FUNCTIONAL_CHECKS, 'passed')
                    and row['checks'] == dict.fromkeys(SDK_CHECKS, 'passed'),
                    'Additional SDK lifecycle or functional evidence is incomplete')
            baseline=[item for item in catalog['sdks'] if item.get('sdkVersion')=='10.0.403' and item.get('rid')==sdk['rid']]
            aliases=row.get('aliases')
            require(len(baseline)==1 and isinstance(aliases,list) and len(aliases)==3,'Highest-series and versioned alias evidence is incomplete')
            for alias,release in zip(aliases,[baseline[0],baseline[0],sdk]):
                require(isinstance(alias,dict) and alias.get('sdkVersion')==release['sdkVersion'] and alias.get('packageRevision')==release['revision']
                        and alias.get('targetRid')==release['rid'] and alias.get('sourceManifestSha256')==release['sourceManifestSha256']
                        and alias.get('qualifiedPayloadModified') is False,'Alias selected another SDK source/revision/RID')
            if project_required:
                from cbodotnetup_project import validate_project_evidence
                require(isinstance(row.get('projectSelection'),dict),'Offline owned project-SDK selection evidence is required for this tool release')
                validate_project_evidence(row['projectSelection'],sdk,baseline[0],catalog)
                validate_previous_tool_upgrade(row.get('previousToolUpgrade'), row, baseline[0], catalog, tool_version,
                                               compatibility_catalog=compatibility_catalog)
            seen.add(key)
            rows.append(dict(sdkVersion=row['sdkVersion'], revision=row['revision'], rid=row['rid'],
                             target=target, variant=row['variant'], architecture=arch,
                             archive=row['archive'], sourceManifestSha256=row['sourceManifestSha256'], status='passed'))
    require(seen == set(expected), 'Every additional SDK/OS/CPU catalog cell needs native evidence')
    return sorted(rows, key=lambda row: (row['sdkVersion'], row['variant'], row['architecture']))
