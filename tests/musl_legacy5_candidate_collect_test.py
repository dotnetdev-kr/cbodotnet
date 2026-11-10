"""Ordering/failure fixtures only: mocks never establish normal SDK/App success."""
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/'scripts'))
import musl_legacy5_candidate as V
import musl_legacy5_candidate_collect as C


class CollectionFailures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.delivery = self.root/'delivery'; self.delivery.mkdir()
        self.metadata = self.root/'private-metadata'; self.events = []
        self.expected = dict(sdkVersion=V.SDK, architecture='aarch64', targetRid='linux-musl-arm64',
            runId='ordinary', runAttempt='1', buildId='ordinary', projectCommit='a'*40)
        self.context = {'paths': {'delivery': str(self.delivery)}}
        (self.delivery/'reports/build/appinsights').mkdir(parents=True)
        self.proof = dict(unknowns=[dict(kind='ordinary-unresolved', originalRepository=None)])
        self.actual = dict(proof=self.proof, roots={}, tooling={}, app_workspace=self.root,
            app_host_roots={}, sdk_source=self.root, feed=self.root, normal_context={})

    def run_mocked_order(self, fail_at):
        import musl_legacy5_appinsights_capture as capture
        def emit(_):
            self.events.append('raw-emitter')
            (self.delivery/'reports/legacy-construction.json').write_bytes(V.encoded(self.proof))
            return self.proof
        def live(*args, **kwargs):
            self.events.append('actual-M-boundary')
            if fail_at == 'M': raise ValueError('ordinary M rejection')
            return {'ordinaryOrderingOnly': True}, self.actual
        def captured(*args, **kwargs):
            self.events.append('C-capture-boundary')
            if fail_at == 'capture': raise ValueError('ordinary capture rejection')
        def pack(_):
            self.events.append('final-pack')
            if fail_at == 'pack': raise ValueError('ordinary pack rejection')
        def verify(_):
            self.events.append('final-verify')
            return {'verifiedPacketOnly': True}
        def generated_sources(_, manifest):
            self.events.append('generated-source-validation')
            self.assertEqual(manifest, {'verifiedPacketOnly': True})
            return {'archivedGeneratedProviderSourceTreesValidated': True}
        def authenticate(*args, **kwargs):
            self.events.append('strict-authentication-boundary')
            raise ValueError('ordinary test stops; no genuine parent capability')
        modules = {'musl_legacy5_evidence.py': SimpleNamespace(emit=emit),
                   'package-used-source.py': SimpleNamespace(pack=pack, verify=verify),
                   'musl_legacy5_generated_source_inputs.py': SimpleNamespace(validate=generated_sources)}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(C, '_preflight', return_value=(self.delivery, self.metadata, self.expected, [], {}, {})))
            stack.enter_context(mock.patch.object(C, '_module', side_effect=lambda name: modules[name]))
            stack.enter_context(mock.patch.object(V, 'producer_record', return_value={'ordinaryDraftOnly': True}))
            stack.enter_context(mock.patch.object(V, 'draft_record', return_value={'sdk': {'ordinaryDraftOnly': True}}))
            stack.enter_context(mock.patch.object(V, 'live_consumption', side_effect=live))
            stack.enter_context(mock.patch.object(capture, 'capture', side_effect=captured))
            stack.enter_context(mock.patch.object(V, 'validate_capture', return_value=None))
            stack.enter_context(mock.patch.object(V, 'authenticate_normal_candidate', side_effect=authenticate))
            with self.assertRaises(ValueError):
                C.collect_completed_normal(self.delivery, self.metadata, self.expected, normal_context=self.context,
                    source_roots=[], evidence_context={}, budget=None, limits=None)
        self.assertFalse(self.metadata.exists()); self.assertFalse((self.delivery/'producer-validation.json').exists())
        stage = V.load(self.delivery/'reports/stages/collect.json')
        self.assertEqual(stage['status'], 'failed'); self.assertFalse(stage['candidateSealed'])

    def test_m_rejection_precedes_capture_or_source_packing(self):
        self.run_mocked_order('M')
        self.assertEqual(self.events, ['raw-emitter', 'actual-M-boundary'])

    def test_capture_failure_cannot_reach_packing_or_authentication(self):
        self.run_mocked_order('capture')
        self.assertEqual(self.events[-1], 'C-capture-boundary')

    def test_pack_failure_never_writes_candidate_success(self):
        self.run_mocked_order('pack')
        self.assertEqual(self.events, ['raw-emitter', 'actual-M-boundary', 'C-capture-boundary', 'final-pack'])

    def test_full_mocked_order_stops_at_real_auth_boundary_without_capability(self):
        self.run_mocked_order('authenticate')
        self.assertEqual(self.events, ['raw-emitter', 'actual-M-boundary', 'C-capture-boundary',
            'final-pack', 'final-verify', 'generated-source-validation', 'strict-authentication-boundary'])
        gaps = V.load(self.delivery/'reports/candidate-source-gaps.json')
        self.assertEqual(gaps['rawEmitterUnknowns'], self.proof['unknowns'])
        self.assertEqual(gaps['unresolvedRawUnknowns'], self.proof['unknowns'])
        self.assertEqual(gaps['independentlyResolvedRawUnknowns'], [])
        self.assertTrue(gaps['archivedGeneratedDataProviderSources']['archivedGeneratedProviderSourceTreesValidated'])
        self.assertTrue(all(gaps[key] is False for key in V.FLAGS))

    def test_unmocked_preflight_never_runs_a_mode_on_windows(self):
        if C.os.name == 'posix': self.skipTest('Windows platform boundary only')
        with mock.patch.object(C, '_module', side_effect=AssertionError('no product mode')):
            with self.assertRaisesRegex(ValueError, 'requires POSIX'):
                C.collect_completed_normal(self.delivery, self.metadata, self.expected, normal_context={},
                    source_roots=[], evidence_context={}, budget=None, limits=None)
        self.assertFalse((self.delivery/'reports/stages/collect.json').exists())


if __name__ == '__main__':
    unittest.main()
