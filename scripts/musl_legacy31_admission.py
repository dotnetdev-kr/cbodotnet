"""Typed declaration of Core3.1 normal gates; this first slice cannot admit a product.

Report fingerprints are declarations to be independently qualified, not cached
success verdicts. Registration and executable normal qualification do not exist
in this module. Importing it opens no files and starts no process.
"""
import re

import musl_legacy31_construction as C
import musl_legacy31_parents as P

QUALIFICATION_GATES = (
    'preferred_source_and_licenses', 'original_git_and_version_derivation',
    'own_construction_and_final_consumption', 'original_source_scan_universe',
    'stock_native_provider_closure', 'normal_container_security',
    'numeric_and_community_cli', 'csharp_vb_fsharp_fsi_web',
    'normal_r2r_optimization_and_native_apphost', 'all_13_source_cultures_and_full_icu',
    'trusted_tls_and_four_negative_certificates',
    'managed_lttng_gc_and_independent_native_control',
    'offline_nonroot_sdk_free_runtime_consumer',
)
RUN_FIELDS = {'context', 'stageReceiptIdentities', 'collectorIdentity', 'finalArchive', 'gateReports'}


def assess_normal_admission(candidate_raw, policy):
    """Validate fresh declarations and enumerate unresolved executable obligations.

    Even a complete declaration remains blocked. No 'passed' field, historical
    receipt, SDK7 contract or caller-supplied boolean qualifies any gate here.
    """
    C.validate_policy(policy)
    candidate = C.document(candidate_raw)
    fields = {'schemaVersion', 'kind', 'sdkVersion', 'origin', 'projectCommit', 'codeIdentity',
              'policyIdentity', 'sourceClosureIdentities', 'normalRuns'}
    C.require(isinstance(candidate, dict) and set(candidate) == fields
              and type(candidate.get('schemaVersion')) is int and candidate['schemaVersion'] == 1
              and candidate.get('kind') == 'core31-normal-candidate-declaration'
              and candidate.get('sdkVersion') == C.SDK, 'own typed Core3.1 normal declaration required')
    C.require(candidate.get('origin') == 'normal-producer', 'historical71-81/reference/bootstrap evidence cannot be normal admission')
    C.require(isinstance(candidate['projectCommit'], str) and re.fullmatch('[a-f0-9]{40}', candidate['projectCommit']), 'fresh exact project commit required')
    C.identity(candidate['codeIdentity'], nonempty=True)
    C.require(C.identity(candidate['policyIdentity'], nonempty=True) == C.fingerprint(C.encoded(policy)), 'candidate policy identity differs')
    sources = candidate['sourceClosureIdentities']
    C.require(isinstance(sources, dict) and set(sources) == set(policy['sourceRepositories']), 'complete declared source repository universe required')
    for value in sources.values():
        C.identity(value, nonempty=True)
    runs = candidate['normalRuns']
    C.require(isinstance(runs, dict) and set(runs) == set(C.ARCHITECTURES), 'both native x64 and AArch64 normal jobs are mandatory')
    run_ids = set()
    for architecture, row in runs.items():
        C.require(isinstance(row, dict) and set(row) == RUN_FIELDS, 'closed native normal-run declaration required')
        context = P.validate_context(row['context'], policy)
        C.require(context['architecture'] == architecture
                  and context['projectCommit'] == candidate['projectCommit']
                  and context['codeIdentity'] == candidate['codeIdentity']
                  and context['policyIdentity'] == candidate['policyIdentity'], 'normal-run project/code/policy/CPU binding differs')
        run_ids.add((context['runId'], context['runAttempt']))
        receipts = row['stageReceiptIdentities']
        C.require(isinstance(receipts, dict) and set(receipts) == set(C.STAGES), 'every native run needs all fresh stage declarations')
        for value in receipts.values():
            C.identity(value, nonempty=True)
        C.identity(row['collectorIdentity'], nonempty=True)
        C.identity(row['finalArchive'], nonempty=True)
        reports = row['gateReports']
        C.require(isinstance(reports, dict) and set(reports) == set(QUALIFICATION_GATES), 'all original qualification report slots required')
        for value in reports.values():
            C.identity(value, nonempty=True)
    C.require(len(run_ids) == 1, 'native jobs must belong to the same actual run and attempt')
    return dict(status='blocked-unregistered-Core3.1-normal-declaration',
                declarationIdentity=C.fingerprint(candidate_raw),
                declarationsAreNotQualifiedReports=True,
                requiredIndependentQualification=list(QUALIFICATION_GATES),
                unresolved=C.readiness(policy)['unresolved'],
                normalAdmissionAllowed=False, sourceAdmissionAllowed=False, releaseAdmissionAllowed=False)


def require_normal_admission(candidate_raw, policy):
    assessment = assess_normal_admission(candidate_raw, policy)
    raise C.ValidationError('Core3.1: normal route remains unregistered; source, construction, original controls and both CPUs require independent qualification ('
                            + assessment['declarationIdentity']['sha256'] + ')')
