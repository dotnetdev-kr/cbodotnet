"""Fresh typed Core3.1 stage parents and byte accounting; never a worker launcher."""
from pathlib import PurePosixPath
import re

import musl_legacy31_construction as C

CONTEXT_FIELDS = {'sdkVersion', 'architecture', 'targetRid', 'libc', 'origin', 'projectCommit',
                  'runId', 'runAttempt', 'imageId', 'codeIdentity', 'policyIdentity', 'roots'}
ROOT_ROLES = {'source', 'bootstrap', 'work', 'reports', 'cache', 'product'}
STAGE_FIELDS = {'schemaVersion', 'kind', 'stage', 'context', 'parents', 'inputs', 'outputs', 'observations'}


def validate_context(context, policy, *, normal=True):
    C.validate_policy(policy)
    C.require(isinstance(context, dict) and set(context) == CONTEXT_FIELDS, 'closed stage context required')
    architecture = context.get('architecture')
    C.require(architecture in C.ARCHITECTURES and context.get('sdkVersion') == C.SDK
              and context.get('targetRid') == C.ARCHITECTURES[architecture] and context.get('libc') == 'musl', 'SDK/CPU/RID/libc context differs')
    C.require(context.get('origin') == 'normal-producer' if normal else context.get('origin') in {'normal-producer', 'historical-reference'},
              'historical evidence is not a fresh normal producer')
    C.require(re.fullmatch('[a-f0-9]{40}', context.get('projectCommit', ''))
              and re.fullmatch('[a-f0-9]{64}', context.get('imageId', '')), 'exact project/image identity required')
    for key in ('runId', 'runAttempt'):
        C.require(type(context.get(key)) is int and context[key] > 0, 'positive actual run identity required')
    C.identity(context['codeIdentity'], nonempty=True)
    C.require(C.identity(context['policyIdentity'], nonempty=True) == C.fingerprint(C.encoded(policy)), 'policy semantic identity differs')
    roots = context['roots']
    C.require(isinstance(roots, dict) and set(roots) == ROOT_ROLES, 'all separate stage roots required')
    for value in roots.values():
        C.require(isinstance(value, str) and value.startswith('/') and value != '/' and '\\' not in value,
                  'absolute ordinary Linux role root required')
        C.relative(value[1:])
    values = list(roots.values())
    C.require(all(left != right and not PurePosixPath(left).is_relative_to(right)
                  and not PurePosixPath(right).is_relative_to(left)
                  for index, left in enumerate(values) for right in values[index+1:]), 'source/bootstrap/work/report/cache/product roots overlap')
    return context


def _observations(row, spec, version_evidence):
    fields = {'commands', 'sourceInputs', 'version', 'nativeInputs'}
    C.require(isinstance(row, dict) and set(row) == fields, 'closed original-command/source/version observations required')
    commands = row['commands']
    C.require(isinstance(commands, list) and commands, 'actual original stage commands required')
    for command in commands:
        C.require(isinstance(command, dict) and set(command) == {'argv', 'environment', 'exitCode', 'recordIdentity', 'binlogIdentity'}, 'closed command record required')
        C.require(isinstance(command['argv'], list) and command['argv'] and all(isinstance(arg, str) and '\0' not in arg for arg in command['argv']), 'actual argv required')
        C.require(isinstance(command['environment'], dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in command['environment'].items()), 'actual environment required')
        C.require(type(command['exitCode']) is int and command['exitCode'] == 0, 'failed command cannot become a passing parent')
        C.identity(command['recordIdentity'], nonempty=True)
        if command['binlogIdentity'] is not None:
            C.identity(command['binlogIdentity'], nonempty=True)
    C.require(isinstance(row['sourceInputs'], dict) and set(row['sourceInputs']) == set(spec['sourceRepositories']), 'actual original source operand universe differs')
    for value in row['sourceInputs'].values():
        C.identity(value, nonempty=True)
    version = row['version']
    C.require(isinstance(version, dict) and set(version) == {'commit', 'tree', 'reachableCommitCount', 'gitCommitCount', 'countDerivationIdentity', 'sourceFileCount', 'originalVersionInputs', 'evaluatedVersions'}, 'real version inputs/count observations required')
    C.require(re.fullmatch('[a-f0-9]{40}', version.get('commit', '')) and re.fullmatch('[a-f0-9]{40}', version.get('tree', ''))
              and type(version['reachableCommitCount']) is int and version['reachableCommitCount'] > 0
              and type(version['sourceFileCount']) is int and version['sourceFileCount'] > 0, 'missing or synthetic source/version counts')
    C.identity(version['originalVersionInputs'], nonempty=True)
    C.require(isinstance(version_evidence, dict) and set(version_evidence) == {'commitObjects', 'originalTarget', 'derivation'},
              'raw original version/history witnesses required, not a cached verdict')
    original_target = version_evidence['originalTarget']
    C.require(isinstance(original_target, bytes), 'original version target bytes required')
    derived = C.verify_version_count(version['commit'], version['tree'], version_evidence['commitObjects'], original_target,
                                     spec.get('versionCountContract'), version_evidence['derivation'])
    C.require(type(version['gitCommitCount']) is int and version['gitCommitCount'] == derived['gitCommitCount']
              and version['reachableCommitCount'] == derived['reachableCommitCount']
              and C.identity(version['countDerivationIdentity']) == derived['derivationIdentity']
              and version['originalVersionInputs'] == derived['originalTargetIdentity'], 'actual version observations differ from original-target history derivation')
    for command in commands:
        for argument in command['argv']:
            for value in re.findall(r'(?:^|[/:;])GitCommitCount=([^;\s]+)', argument, re.I):
                C.require(value == str(derived['gitCommitCount']), 'argv overrides the proven original GitCommitCount')
        for key, value in command['environment'].items():
            if key.lower() == 'gitcommitcount':
                C.require(value == str(derived['gitCommitCount']), 'environment overrides the proven original GitCommitCount')
    C.require(isinstance(version['evaluatedVersions'], dict) and version['evaluatedVersions']
              and all(isinstance(key, str) and isinstance(value, str) and value for key, value in version['evaluatedVersions'].items()), 'original evaluated versions required')
    native = row['nativeInputs']
    C.require(isinstance(native, dict) and set(native) == set(spec.get('requiredNativeInputRoles', [])), 'selected own native/crossgen input universe differs')
    for value in native.values():
        C.identity(value, nonempty=True)


def validate_stage_graph(raw_receipts, artifacts, policy, context, version_evidence, *, maximum_artifact_bytes):
    """Recheck real files and raw parent documents; a cached 'passed' verdict is not input."""
    validate_context(context, policy)
    C.require(isinstance(raw_receipts, dict) and set(raw_receipts) == set(C.STAGES), 'all own Core3.1 stages required')
    C.require(isinstance(artifacts, dict), 'actual artifact role paths required')
    C.require(isinstance(version_evidence, dict) and set(version_evidence) == set(C.STAGES), 'every stage requires its own original target/history witness')
    receipts, identities, produced, consumed, actual = {}, {}, {}, {}, {}
    for stage in C.STAGES:
        raw = raw_receipts[stage]
        row = C.document(raw)
        C.require(isinstance(row, dict) and set(row) == STAGE_FIELDS and type(row.get('schemaVersion')) is int
                  and row['schemaVersion'] == 1 and row.get('kind') == 'core31-source-stage' and row.get('stage') == stage, 'own exact stage record required')
        C.require(row['context'] == context, 'stage parent context differs')
        spec = policy['stages'][stage]
        parents = row['parents']
        C.require(isinstance(parents, dict) and set(parents) == set(spec['requiredParents']), 'missing or invented stage parent')
        for parent, wanted in parents.items():
            C.require(C.identity(wanted, nonempty=True) == identities[parent], 'actual raw parent receipt changed')
        inputs, outputs = row['inputs'], row['outputs']
        C.require(isinstance(inputs, dict) and set(inputs) == set(spec.get('requiredInputRoles', [])), 'actual consumed parent role universe differs')
        available = {role for parent in spec['requiredParents'] for role in receipts[parent]['outputs']}
        for role, value in inputs.items():
            C.require(role in available and C.identity(value, nonempty=True) == produced[role]['identity'], 'consumed parent output differs or feed presence was mistaken for restore')
        C.require(isinstance(outputs, dict) and set(outputs) == set(spec['outputRoles']), 'actual stage output role universe differs')
        for role, value in outputs.items():
            C.relative(role)
            C.require(role not in produced and role in artifacts, 'duplicate or missing real output role')
            C.identity(value, nonempty=True)
            C.require(C.file_identity(artifacts[role], maximum_artifact_bytes) == value, 'actual produced bytes differ: ' + role)
            produced[role] = dict(stage=stage, identity=dict(value))
            actual[role] = dict(value)
        _observations(row['observations'], spec, version_evidence[stage])
        for role, value in row['observations']['nativeInputs'].items():
            C.require(role in artifacts and C.file_identity(artifacts[role], maximum_artifact_bytes) == value, 'actual selected native construction input differs')
            actual[role] = dict(value)
        consumed[stage] = list(inputs)
        receipts[stage], identities[stage] = row, C.fingerprint(raw)
    C.require(set(artifacts) == set(actual), 'unclassified artifact input outside closed stage graph')
    return dict(status='byte-accounted-fresh-Core3.1-stage-graph-unqualified', context=dict(context),
                receiptIdentities=identities, producedRoles=produced, consumedRoles=consumed,
                actualArtifactIdentities=actual, sourceClosureValidated=False,
                actualRestoreAndTaskCarriageIndependentlyQualified=False,
                originalCommandAndVersionDerivationIndependentlyQualified=False,
                nativeConstructionIndependentlyQualified=False, normalAdmissionAllowed=False)


def validate_collector(final_archive, final_identity, lineage, origins, graph_inputs, policy, bounds, *, root_origin=None):
    """Bind every final member to its exact producing archive or exact named import."""
    C.validate_policy(policy)
    C.require(isinstance(graph_inputs, dict) and set(graph_inputs) == {'rawReceipts', 'artifacts', 'context', 'versionEvidence', 'maximumArtifactBytes'},
              'raw fresh graph inputs required; a cached graph verdict cannot qualify a collector')
    graph = validate_stage_graph(graph_inputs['rawReceipts'], graph_inputs['artifacts'], policy, graph_inputs['context'],
                                 graph_inputs['versionEvidence'], maximum_artifact_bytes=graph_inputs['maximumArtifactBytes'])
    C.require('candidate_sdk_archive' in graph['producedRoles']
              and C.identity(final_identity, nonempty=True) == graph['producedRoles']['candidate_sdk_archive']['identity'],
              'collector archive is not the exact fresh collector-stage output')
    final = C.archive_inventory(final_archive, final_identity, bounds)
    rows = {row['path']: row for row in final['members']}
    C.require(isinstance(lineage, list) and len(lineage) == len(rows), 'every final archive member needs one origin')
    C.require(isinstance(origins, dict) and origins, 'closed real origin archives required')
    inventories, original_inventories, pending, used = {}, {}, [], set()
    for role, origin in origins.items():
        C.relative(role)
        C.require(isinstance(origin, dict) and set(origin) == {'disposition', 'path', 'identity', 'archiveType'}, 'closed origin record required')
        C.identity(origin['identity'], nonempty=True)
        C.require(origin['disposition'] in {'own-built', 'unchanged-import'}, 'unknown member disposition; no broad data/import fallback')
        if origin['archiveType'] == 'tree':
            C.require(origin['disposition'] == 'own-built', 'unchanged imports require their exact official archive')
            inventory = C.directory_inventory(origin['path'], origin['identity'], bounds)
        else:
            inventory = C.archive_inventory(origin['path'], origin['identity'], bounds, archive_type=origin['archiveType'])
        if origin['disposition'] == 'own-built':
            C.require(role in graph['producedRoles']
                      and graph['producedRoles'][role]['stage'] in C.STAGES[:C.STAGES.index('collector')]
                      and origin['identity'] == graph['producedRoles'][role]['identity'],
                      'own-built origin must be an actual upstream producing-stage output, never collector/self lineage')
        else:
            C.require(role in policy['importCandidates'], 'unregistered upstream import candidate')
            candidate = policy['importCandidates'][role]
            C.require(graph['context']['architecture'] in candidate['architectures'], 'cross-CPU imported product')
            C.require(C.three_fields(candidate['archive']) == origin['identity'], 'unchanged official archive bytes differ')
            pin = candidate.get('memberManifestPin')
            C.require(pin is not None and C.identity(pin, nonempty=True) == C.fingerprint(C.encoded(inventory)), 'exact import member manifest is unresolved or differs')
            C.require(candidate.get('sourceRepositories') and isinstance(candidate.get('knownLicensePaths'), list)
                      and candidate['knownLicensePaths'], 'unresolved import source/license obligations')
            paths = {row['path'] for row in inventory['members'] if row['type'] == 'file'}
            C.require(set(candidate['knownLicensePaths']) <= paths, 'original import licenses/notices missing')
            licenses = {row['path']: C.three_fields(row) for row in inventory['members']
                        if row['path'] in candidate['knownLicensePaths'] and row['type'] == 'file'}
            C.require(candidate.get('licenseInventoryPin') is not None
                      and C.identity(candidate['licenseInventoryPin'], nonempty=True) == C.fingerprint(C.encoded(licenses)),
                      'exact unchanged import license inventory is unresolved or differs')
            pending.append('Import remains an unadmitted candidate: ' + role)
        inventories[role] = {row['path']: row for row in inventory['members']}
        original_inventories[role] = inventory
    if final['rootDirectoryMode'] is None:
        C.require(root_origin is None, 'unexpected root-directory origin')
    else:
        C.require(isinstance(root_origin, dict) and set(root_origin) == {'originRole', 'originPath'}, 'final root directory needs an exact origin')
        role, path = root_origin['originRole'], root_origin['originPath']
        C.require(role in origins, 'unknown final root origin')
        if path == '.':
            mode = original_inventories[role]['rootDirectoryMode']
        else:
            C.relative(path)
            member = inventories[role].get(path, {})
            C.require(member.get('type') == 'directory', 'root origin is not a real source directory')
            mode = member['mode']
        C.require(mode == final['rootDirectoryMode'], 'final root-directory mode differs from its origin')
        used.add(role)
    seen = set()
    for binding in lineage:
        C.require(isinstance(binding, dict) and set(binding) == {'path', 'originRole', 'originPath', 'disposition'}, 'closed member-origin binding required')
        name = C.relative(binding['path'])
        C.require(name not in seen and name in rows, 'duplicate or unknown final member origin')
        seen.add(name)
        role, source = binding['originRole'], C.relative(binding['originPath'])
        C.require(role in origins and binding['disposition'] == origins[role]['disposition'] and source in inventories[role], 'unknown origin role/member or changed disposition')
        expected = dict(inventories[role][source], path=name)
        C.require(rows[name] == expected, 'shipped byte/mode/link differs from declared source/import member')
        used.add(role)
    C.require(seen == set(rows) and used == set(origins), 'unmapped final member or unused asserted origin')
    return dict(status='byte-accounted-Core3.1-collector-unqualified', finalArchive=dict(final_identity),
                inventoryIdentity=C.fingerprint(C.encoded(final)), members=len(rows), usedOriginRoles=sorted(used),
                pendingImportAdmission=pending, everyFinalByteModeAndLinkBound=True,
                sourceAndLicenseClosureIndependentlyQualified=False, normalAdmissionAllowed=False)
