"""Fresh parent/collector accounting fixtures cannot pass normal admission."""
import copy
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import musl_legacy31_construction as C
import musl_legacy31_parents as P
import musl_legacy31_admission as A

assert all(Path(module.__file__).resolve().parent == SCRIPTS for module in (C, P, A))
BOUNDS = dict(archiveBytes=131072, members=100, memberBytes=16384, expandedBytes=131072)


def fp(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def tar(path, body=b'MZfixture managed data'):
    with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in [('sdk/3.1.426/source.dll', body), ('LICENSE.txt', b'MIT fixture\n')]:
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o644, len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return fp(path.read_bytes())


class ParentAndAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='core31-parents-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = copy.deepcopy(C.load_policy())
        self.target = b'<Project><Target Name="FixtureOriginalVersionCount" /></Project>\n'
        self.tree = hashlib.sha1(b'tree 0\0').hexdigest()
        self.commit_raw = ('tree ' + self.tree + '\nauthor Fixture <a@example.invalid> 0 +0000\ncommitter Fixture <a@example.invalid> 0 +0000\n\nfixture\n').encode()
        self.commit = hashlib.sha1(b'commit ' + str(len(self.commit_raw)).encode() + b'\0' + self.commit_raw).hexdigest()
        self.contract = dict(targetIdentity=fp(self.target), algorithm='first-parent-distance', baseCommit=self.commit, property='GitCommitCount')
        self.derivation = dict(self.contract, commit=self.commit, tree=self.tree, value=0)
        for stage in C.STAGES:
            self.policy['stages'][stage]['versionCountContract'] = copy.deepcopy(self.contract)
        self.context = self.context_for('aarch64')

    def context_for(self, architecture):
        return dict(sdkVersion=C.SDK, architecture=architecture, targetRid=C.ARCHITECTURES[architecture], libc='musl',
                    origin='normal-producer', projectCommit='a' * 40, runId=17, runAttempt=2, imageId='b' * 64,
                    codeIdentity=fp(b'fixture owned orchestrator source'), policyIdentity=fp(C.encoded(self.policy)),
                    roots={role: '/owned-fixture/' + architecture + '/' + role for role in P.ROOT_ROLES})

    def fixture(self, *, origin=None, final=None):
        artifacts, raw_receipts, receipts, evidence = {}, {}, {}, {}
        for stage in C.STAGES:
            spec = self.policy['stages'][stage]
            outputs = {}
            for role in spec['outputRoles']:
                path = origin if role == 'source_sdk_layout' and origin else final if role == 'candidate_sdk_archive' and final else self.root / role
                if path not in (origin, final):
                    path.write_bytes(('actually produced fixture ' + role).encode())
                artifacts[role] = path
                outputs[role] = fp(path.read_bytes())
            native = {}
            for role in spec.get('requiredNativeInputRoles', []):
                path = self.root / role
                path.write_bytes(('actual selected native fixture ' + role).encode())
                artifacts[role] = path
                native[role] = fp(path.read_bytes())
            inputs = {role: receipts[parent]['outputs'][role]
                      for role in spec['requiredInputRoles'] for parent in spec['requiredParents']
                      if role in receipts[parent]['outputs']}
            version = dict(commit=self.commit, tree=self.tree, reachableCommitCount=1, gitCommitCount=0,
                           countDerivationIdentity=fp(C.encoded(self.derivation)), sourceFileCount=2,
                           originalVersionInputs=fp(self.target), evaluatedVersions={'Version': 'fixture-original-version'})
            command = dict(argv=['fixture-original-project', '/p:GitCommitCount=0'], environment={}, exitCode=0,
                           recordIdentity=fp(('actual fixture command ' + stage).encode()), binlogIdentity=None)
            observations = dict(commands=[command], sourceInputs={repo: fp(('fixture source ' + repo).encode()) for repo in spec['sourceRepositories']},
                                version=version, nativeInputs=native)
            row = dict(schemaVersion=1, kind='core31-source-stage', stage=stage, context=copy.deepcopy(self.context),
                       parents={parent: fp(raw_receipts[parent]) for parent in spec['requiredParents']}, inputs=inputs, outputs=outputs, observations=observations)
            receipts[stage], raw_receipts[stage] = row, C.encoded(row)
            evidence[stage] = dict(commitObjects={self.commit: self.commit_raw}, originalTarget=self.target, derivation=copy.deepcopy(self.derivation))
        return raw_receipts, artifacts, evidence

    def graph(self, fixture):
        return P.validate_stage_graph(*fixture[:2], self.policy, self.context, fixture[2], maximum_artifact_bytes=131072)

    def test_real_artifacts_fresh_parents_and_proven_zero_are_accounted_only(self):
        result = self.graph(self.fixture())
        self.assertEqual(set(result['consumedRoles']['toolset']), set(self.policy['stages']['toolset']['requiredInputRoles']))
        self.assertFalse(result['normalAdmissionAllowed'])
        self.assertFalse(result['actualRestoreAndTaskCarriageIndependentlyQualified'])
        self.assertFalse(result['sourceClosureValidated'])

    def test_current_real_policy_has_no_original_version_contract_and_is_unresolved(self):
        fixture = self.fixture()
        policy = C.load_policy()
        context = copy.deepcopy(self.context)
        context['policyIdentity'] = fp(C.encoded(policy))
        raws = {}
        for stage in C.STAGES:
            row = C.document(fixture[0][stage])
            row['context'] = context
            row['parents'] = {parent: fp(raws[parent]) for parent in policy['stages'][stage]['requiredParents']}
            raws[stage] = C.encoded(row)
        with self.assertRaisesRegex(C.ValidationError, 'unresolved'):
            P.validate_stage_graph(raws, fixture[1], policy, context, fixture[2], maximum_artifact_bytes=131072)

    def test_wrong_context_sdk_cpu_rid_run_image_code_and_overlapping_roots(self):
        changes = [('sdkVersion', '7.0.410'), ('architecture', 'x64'), ('targetRid', 'linux-arm64'), ('runId', 0),
                   ('imageId', 'unknown'), ('codeIdentity', {'sha256': 'c' * 64})]
        for key, value in changes:
            context = copy.deepcopy(self.context)
            context[key] = value
            with self.subTest(key=key), self.assertRaises(C.ValidationError):
                P.validate_context(context, self.policy)
        context = copy.deepcopy(self.context)
        context['roots']['cache'] = context['roots']['source'] + '/cache'
        with self.assertRaises(C.ValidationError):
            P.validate_context(context, self.policy)

    def test_changed_actual_output_is_not_a_cached_parent_pass(self):
        fixture = self.fixture()
        fixture[1]['toolset_internal_zip'].write_bytes(b'substituted ZIP bytes')
        with self.assertRaisesRegex(C.ValidationError, 'produced bytes'):
            self.graph(fixture)

    def test_swapped_fsharp_parent_and_stale_run_are_rejected(self):
        for mutation in ('parent', 'run'):
            fixture = self.fixture()
            row = C.document(fixture[0]['fsharp_release'])
            if mutation == 'parent':
                row['parents']['fsharp_proto'] = fp(fixture[0]['cli'])
            else:
                row['context']['runAttempt'] = 1
            fixture[0]['fsharp_release'] = C.encoded(row)
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                self.graph(fixture)

    def test_feed_candidate_is_not_inferred_consumption_and_required_parent_cannot_be_omitted(self):
        for mutation in ('optional_feed', 'missing_cli'):
            fixture = self.fixture()
            row = C.document(fixture[0]['toolset'])
            if mutation == 'optional_feed':
                row['inputs']['msbuild_sdk_resolver'] = C.document(fixture[0]['cli'])['outputs']['msbuild_sdk_resolver']
            else:
                row['inputs'].pop('cli_runtime')
            fixture[0]['toolset'] = C.encoded(row)
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                self.graph(fixture)

    def test_unproven_zero_and_mismatched_count_override_fail(self):
        for mutation in ('missing_history', 'unknown_target', 'argv', 'environment'):
            fixture = self.fixture()
            if mutation == 'missing_history':
                fixture[2]['sdk_tasks']['commitObjects'] = {}
            elif mutation == 'unknown_target':
                fixture[2]['sdk_tasks']['originalTarget'] += b'changed'
            else:
                row = C.document(fixture[0]['sdk_tasks'])
                command = row['observations']['commands'][0]
                if mutation == 'argv':
                    command['argv'] = ['original-project', '-p:gitcommitcount=5']
                else:
                    command['environment']['GitCommitCount'] = '5'
                fixture[0]['sdk_tasks'] = C.encoded(row)
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                self.graph(fixture)

    def collector_fixture(self):
        origin, final = self.root / 'own-layout.tar.gz', self.root / 'new-final.tar.gz'
        tar(origin)
        final.write_bytes(origin.read_bytes())
        fixture = self.fixture(origin=origin, final=final)
        graph = dict(rawReceipts=fixture[0], artifacts=fixture[1], context=copy.deepcopy(self.context),
                     versionEvidence=fixture[2], maximumArtifactBytes=131072)
        origins = {'source_sdk_layout': dict(disposition='own-built', path=origin, identity=fp(origin.read_bytes()), archiveType='tar.gz')}
        lineage = [dict(path=name, originRole='source_sdk_layout', originPath=name, disposition='own-built')
                   for name in ('LICENSE.txt', 'sdk/3.1.426/source.dll')]
        return final, lineage, origins, graph

    def refresh_graph(self, graph):
        """Author new fixture receipts from actual bytes, never edit a cached verdict."""
        graph['context']['policyIdentity'] = fp(C.encoded(self.policy))
        receipts = {}
        for stage in C.STAGES:
            row = C.document(graph['rawReceipts'][stage])
            spec = self.policy['stages'][stage]
            row['context'] = copy.deepcopy(graph['context'])
            row['parents'] = {parent: fp(graph['rawReceipts'][parent]) for parent in spec['requiredParents']}
            row['outputs'] = {role: fp(graph['artifacts'][role].read_bytes()) for role in spec['outputRoles']}
            row['inputs'] = {role: receipts[parent]['outputs'][role] for role in spec['requiredInputRoles']
                             for parent in spec['requiredParents'] if role in receipts[parent]['outputs']}
            graph['rawReceipts'][stage] = C.encoded(row)
            receipts[stage] = row

    def test_collector_real_member_bytes_modes_and_fresh_stage_output(self):
        final, lineage, origins, graph = self.collector_fixture()
        result = P.validate_collector(final, fp(final.read_bytes()), lineage, origins, graph, self.policy, BOUNDS)
        self.assertEqual(result['members'], 2)
        self.assertTrue(result['everyFinalByteModeAndLinkBound'])
        self.assertFalse(result['normalAdmissionAllowed'])

    def test_cached_graph_pass_is_not_a_collector_input(self):
        final, lineage, origins, graph_inputs = self.collector_fixture()
        cached = P.validate_stage_graph(graph_inputs['rawReceipts'], graph_inputs['artifacts'], self.policy, graph_inputs['context'],
                                         graph_inputs['versionEvidence'], maximum_artifact_bytes=131072)
        with self.assertRaisesRegex(C.ValidationError, 'cached graph verdict'):
            P.validate_collector(final, fp(final.read_bytes()), lineage, origins, cached, self.policy, BOUNDS)

    def test_final_archive_cannot_be_its_own_producing_origin(self):
        final, lineage, origins, graph_inputs = self.collector_fixture()
        origins = {'candidate_sdk_archive': dict(disposition='own-built', path=final,
                   identity=fp(final.read_bytes()), archiveType='tar.gz')}
        for row in lineage:
            row['originRole'] = 'candidate_sdk_archive'
        with self.assertRaisesRegex(C.ValidationError, 'never collector/self lineage'):
            P.validate_collector(final, fp(final.read_bytes()), lineage, origins, graph_inputs, self.policy, BOUNDS)

    def test_collector_changed_managed_bytes_unknown_or_omitted_member_fail(self):
        for mutation in ('bytes', 'omitted', 'unknown', 'bootstrap'):
            final, lineage, origins, graph = self.collector_fixture()
            if mutation == 'bytes':
                tar(final, body=b'MZchanged bytes')
                self.refresh_graph(graph)
            elif mutation == 'omitted':
                lineage.pop()
            elif mutation == 'unknown':
                lineage[0]['originPath'] = 'unknown'
            else:
                origins['source_sdk_layout']['disposition'] = 'bootstrap'
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                P.validate_collector(final, fp(final.read_bytes()), lineage, origins, graph, self.policy, BOUNDS)

    def test_collector_cannot_replace_fresh_stage_archive_or_omit_root_mode_origin(self):
        final, lineage, origins, graph = self.collector_fixture()
        changed = self.root / 'replacement.tar.gz'
        tar(changed, body=b'MZreplacement')
        with self.assertRaisesRegex(C.ValidationError, 'fresh collector-stage output'):
            P.validate_collector(changed, fp(changed.read_bytes()), lineage, origins, graph, self.policy, BOUNDS)
        # Add a real root directory to both producing and final archives.
        origin = origins['source_sdk_layout']['path']
        with tarfile.open(origin, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            root = tarfile.TarInfo('.')
            root.type, root.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(root)
            for name, raw in [('sdk/3.1.426/source.dll', b'MZfixture managed data'), ('LICENSE.txt', b'MIT fixture\n')]:
                item = tarfile.TarInfo(name)
                item.mode, item.size = 0o644, len(raw)
                archive.addfile(item, io.BytesIO(raw))
        final.write_bytes(origin.read_bytes())
        identity = fp(final.read_bytes())
        origins['source_sdk_layout']['identity'] = identity
        self.refresh_graph(graph)
        with self.assertRaisesRegex(C.ValidationError, 'root directory needs'):
            P.validate_collector(final, identity, lineage, origins, graph, self.policy, BOUNDS)
        result = P.validate_collector(final, identity, lineage, origins, graph, self.policy, BOUNDS,
                                      root_origin=dict(originRole='source_sdk_layout', originPath='.'))
        self.assertFalse(result['normalAdmissionAllowed'])

    def test_exact_import_candidate_is_accounted_but_not_admitted(self):
        final, lineage, origins, graph = self.collector_fixture()
        origin = origins.pop('source_sdk_layout')
        origin['disposition'] = 'unchanged-import'
        inventory = C.archive_inventory(origin['path'], origin['identity'], BOUNDS)
        candidate = self.policy['importCandidates']['official_runtime_arm64']
        candidate.update(archive=origin['identity'], memberManifestPin=fp(C.encoded(inventory)),
                         knownLicensePaths=['LICENSE.txt'], licenseInventoryPin=fp(C.encoded({'LICENSE.txt': fp(b'MIT fixture\n')})))
        self.refresh_graph(graph)
        origins['official_runtime_arm64'] = origin
        for row in lineage:
            row.update(originRole='official_runtime_arm64', disposition='unchanged-import')
        result = P.validate_collector(final, fp(final.read_bytes()), lineage, origins, graph, self.policy, BOUNDS)
        self.assertFalse(result['normalAdmissionAllowed'])
        self.assertTrue(result['pendingImportAdmission'])
        for field in ('memberManifestPin', 'licenseInventoryPin'):
            saved = candidate[field]
            candidate[field] = None
            self.refresh_graph(graph)
            with self.subTest(field=field), self.assertRaises(C.ValidationError):
                P.validate_collector(final, fp(final.read_bytes()), lineage, origins, graph, self.policy, BOUNDS)
            candidate[field] = saved

    def candidate(self):
        return dict(schemaVersion=1, kind='core31-normal-candidate-declaration', sdkVersion=C.SDK,
                    origin='normal-producer', projectCommit=self.context['projectCommit'], codeIdentity=self.context['codeIdentity'],
                    policyIdentity=self.context['policyIdentity'],
                    sourceClosureIdentities={repo: fp(('source declaration ' + repo).encode()) for repo in self.policy['sourceRepositories']},
                    normalRuns={architecture: dict(context=self.context_for(architecture),
                                                  stageReceiptIdentities={stage: fp((architecture + ' ' + stage).encode()) for stage in C.STAGES},
                                                  collectorIdentity=fp((architecture + ' collector').encode()), finalArchive=fp((architecture + ' final').encode()),
                                                  gateReports={gate: fp((architecture + ' report ' + gate).encode()) for gate in A.QUALIFICATION_GATES}) for architecture in C.ARCHITECTURES})

    def test_complete_declarations_still_fail_normal_source_release_admission(self):
        raw = C.encoded(self.candidate())
        result = A.assess_normal_admission(raw, self.policy)
        self.assertTrue(result['declarationsAreNotQualifiedReports'])
        self.assertFalse(result['normalAdmissionAllowed'])
        self.assertFalse(result['sourceAdmissionAllowed'])
        self.assertFalse(result['releaseAdmissionAllowed'])
        with self.assertRaisesRegex(C.ValidationError, 'unregistered'):
            A.require_normal_admission(raw, self.policy)

    def test_historical71_to81_and_bootstrap_cannot_be_normal(self):
        for origin in ('historical-reference', 'private-bootstrap', 'collector81'):
            candidate = self.candidate()
            candidate['origin'] = origin
            with self.subTest(origin=origin), self.assertRaises(C.ValidationError):
                A.assess_normal_admission(C.encoded(candidate), self.policy)

    def test_missing_second_native_cpu_wrong_family_or_cached_pass_fails(self):
        for mutation in ('cpu', 'sdk', 'cached_verdict', 'run'):
            candidate = self.candidate()
            if mutation == 'cpu':
                candidate['normalRuns'].pop('x64')
            elif mutation == 'sdk':
                candidate['sdkVersion'] = '7.0.410'
            elif mutation == 'run':
                candidate['normalRuns']['x64']['context']['runAttempt'] = 1
            else:
                candidate['normalRuns']['x64']['gateReports']['trusted_tls_and_four_negative_certificates'] = {'passed': True}
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                A.assess_normal_admission(C.encoded(candidate), self.policy)

    def test_original_smoke_locale_tls_native_trace_and_r2r_slots_cannot_be_omitted(self):
        for gate in A.QUALIFICATION_GATES:
            candidate = self.candidate()
            candidate['normalRuns']['aarch64']['gateReports'].pop(gate)
            with self.subTest(gate=gate), self.assertRaises(C.ValidationError):
                A.assess_normal_admission(C.encoded(candidate), self.policy)


if __name__ == '__main__':
    unittest.main()
