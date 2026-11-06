"""Bind additional installer SDK qualification to every signed catalog target."""
from consumer_archive import FUNCTIONAL_CHECKS
from downstream_release import require


SDK_CHECKS = ('bootstrap-authentication', 'signature-authentication', 'source-producer-linkage',
              'exact-version-install', 'idempotent-install', 'tracked-channel-update', 'rollback',
              'explicit-sdk-run', 'highest-series-default', 'versioned-alias', 'offline-build-runtime',
              'http-crypto-globalization', 'tamper-rejection', 'concurrency', 'interrupted-activation',
              'revocation-rejection', 'unqualified-rejection', 'official-package-coexistence',
              'community-package-coexistence', 'other-sdk-preservation', 'removal')


def validate_additional_sdk_qualifications(catalog, observations):
    """Return exact passed cells; catalog-only admission never constitutes evidence."""
    expected = {}
    for sdk in catalog['sdks']:
        if sdk['sdkVersion'] == '10.0.403':
            continue  # The original per-target report owns the SDK10 migration regression.
        require(catalog['schemaVersion'] == 2 and not sdk['requiresLegacyProvider'],
                'Additional installer SDKs require the modern catalog and no legacy provider')
        require(f"{sdk['sdkVersion']}-r{sdk['revision']}/{sdk['rid']}" not in catalog['revoked'],
                'A revoked SDK cannot be advertised as qualified for new installation')
        for target in sdk['targets']:
            key = (sdk['sdkVersion'], sdk['rid'], target['os'], target['versionId'])
            require(key not in expected and target['rid'] == sdk['rid'], 'Duplicate or inconsistent SDK target')
            expected[key] = (sdk, target)
    rows = []
    seen = set()
    for observation in observations:
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
            seen.add(key)
            rows.append(dict(sdkVersion=row['sdkVersion'], revision=row['revision'], rid=row['rid'],
                             target=target, variant=row['variant'], architecture=arch,
                             archive=row['archive'], sourceManifestSha256=row['sourceManifestSha256'], status='passed'))
    require(seen == set(expected), 'Every additional SDK/OS/CPU catalog cell needs native evidence')
    return sorted(rows, key=lambda row: (row['sdkVersion'], row['variant'], row['architecture']))
