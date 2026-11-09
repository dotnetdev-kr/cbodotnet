"""Tiny byte/source fixtures only; no genuine normal parent or App positive."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_legacy5_candidate as V


class ByteFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.delivery = self.root / 'delivery'; self.delivery.mkdir()
        self.expected = dict(sdkVersion=V.SDK, architecture='aarch64', targetRid='linux-musl-arm64',
            runId='ordinary', runAttempt='1', buildId='ordinary.1', projectCommit='a' * 40)
        self.limits = V.Limits(delivery_bytes=16*1024**2, file_bytes=8*1024**2, files=100)
        self.sdk_name = 'ordinary-sdk.tar.gz'
        with tarfile.open(self.delivery / self.sdk_name, 'w:gz') as archive:
            raw = b'ordinary file, not a genuine SDK'; entry = tarfile.TarInfo('notice.txt'); entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        self.sdk = dict(name=self.sdk_name, **V.file_fingerprint(self.delivery / self.sdk_name, self.limits.file_bytes))
        self.prepare = dict(self.expected, **V.COMMITS, libc='musl', imageId='sha256:'+'b'*64,
            emulation=False, diagnosticPtrace=False, diagnosticPodman=False, previousPrivateSdkArchiveUsed=False)
        self.write('reports/prepare/identity.json', self.prepare)
        for stage in V.STAGES:
            self.write('reports/stages/' + stage + '.json', dict(stage=stage, status='passed', commands=[]))
        self.write('reports/build/construction.json', dict(sdkVersion=V.SDK, sdkArchive=self.sdk))
        self.raw_unknown = dict(kind='unmapped-package-source', artifact='package-'+'c'*64,
            id='Ordinary.Input', version='1.0.0', originalRepository=None)
        self.proof = dict(kind='sdk5-musl-construction-proof', sdkVersion=V.SDK, architecture='aarch64',
            targetRid='linux-musl-arm64', sdkArchive=dict(path=self.sdk_name, **{key: self.sdk[key] for key in V.FP}),
            unknowns=[self.raw_unknown], diagnosticOnly=False, constructionInputScope='normal-producer-inputs',
            qualificationAllowed=False, sourceAdmissionAllowed=False)
        self.write('reports/legacy-construction.json', self.proof)
        self.write('producer-sdk.json', V.producer_record(self.delivery, self.expected, self.limits))

    def write(self, name, value):
        path = self.delivery / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(V.encoded(value))
        return path


class CanonicalCandidateBytes(ByteFixture):
    def test_byte_draft_keeps_original_sdk_and_raw_unknowns_without_capability(self):
        before = (self.delivery / 'reports/legacy-construction.json').read_bytes()
        record = V.draft_record(self.delivery, self.expected, limits=self.limits)
        self.assertEqual(record['sdk'], self.sdk)
        self.assertEqual(record['status'], 'retained-unadmitted')
        self.assertTrue(all(record[key] is False for key in V.FLAGS))
        self.assertEqual({row['path'] for row in record['files']},
            {p.relative_to(self.delivery).as_posix() for p in self.delivery.rglob('*') if p.is_file()})
        self.assertEqual((self.delivery / 'reports/legacy-construction.json').read_bytes(), before)
        self.assertIsNone(V.load(self.delivery / 'reports/legacy-construction.json')['unknowns'][0]['originalRepository'])
        self.assertFalse((self.root / 'metadata').exists())

    def test_original_construction_predicate_accepts_exact_sdk_and_rejects_substitution(self):
        import musl_legacy5_construction_inputs as C
        record = V.draft_record(self.delivery, self.expected, limits=self.limits)
        self.assertEqual(C.validate_final_sdk_archive(record, self.proof), self.proof['sdkArchive'])
        record['sdk']['sha512'] = 'd' * 128
        with self.assertRaisesRegex(ValueError, 'exact final archive'):
            C.validate_final_sdk_archive(record, self.proof)

    def test_producer_e5_and_actual_file_disagreement_is_never_repaired(self):
        changed = copy.deepcopy(self.proof); changed['sdkArchive']['sha256'] = 'd' * 64
        self.write('reports/legacy-construction.json', changed)
        with self.assertRaisesRegex(ValueError, 'Original normal E5'):
            V.draft_record(self.delivery, self.expected, limits=self.limits)
        self.assertEqual(V.load(self.delivery / 'reports/legacy-construction.json'), changed)

    def test_same_size_changed_archive_with_restored_mtime_rejects(self):
        path = self.delivery / self.sdk_name; before = path.stat(); raw = bytearray(path.read_bytes()); raw[-1] ^= 1
        path.write_bytes(raw); os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, 'actual final archive'):
            V.sdk_descriptor(self.delivery, self.expected, self.limits)

    def test_boolean_sdk_size_and_wrong_run_prepare_reject(self):
        self.write('reports/build/construction.json', dict(sdkVersion=V.SDK, sdkArchive=dict(self.sdk, bytes=True)))
        with self.assertRaisesRegex(ValueError, 'Original producer'):
            V.sdk_descriptor(self.delivery, self.expected, self.limits)
        self.write('reports/prepare/identity.json', dict(self.prepare, runAttempt='2'))
        with self.assertRaisesRegex(ValueError, 'preparation identity'):
            V.parent_facts(self.delivery, self.expected)

    def test_failed_stage_and_diagnostic_prepare_cannot_form_normal_facts(self):
        self.write('reports/stages/build.json', dict(stage='build', status='failed', commands=[]))
        with self.assertRaisesRegex(ValueError, 'normal stage.*build'):
            V.parent_facts(self.delivery, self.expected)
        self.write('reports/prepare/identity.json', dict(self.prepare, diagnosticPodman=True))
        with self.assertRaisesRegex(ValueError, 'normal preparation'):
            V.parent_facts(self.delivery, self.expected)

    def test_common_producer_record_forbidden_and_bounds_precede_body_reads(self):
        self.write('producer-validation.json', dict(status='passed'))
        with mock.patch.object(V, 'file_fingerprint', side_effect=AssertionError('must fail before body read')):
            with self.assertRaisesRegex(ValueError, 'never contain common'):
                V.inventory(self.delivery, self.limits)
        (self.delivery / 'producer-validation.json').unlink()
        with mock.patch.object(V, 'file_fingerprint', side_effect=AssertionError('must fail before body read')):
            with self.assertRaisesRegex(ValueError, 'total exceeds'):
                V.inventory(self.delivery, V.Limits(delivery_bytes=1, file_bytes=1, files=100))

    def test_sealed_file_set_detects_extra_or_removed_actual_members(self):
        first = V.inventory(self.delivery, self.limits)
        self.write('unbound.json', {'unexpected': True})
        self.assertNotEqual(V.inventory(self.delivery, self.limits), first)
        (self.delivery / 'unbound.json').unlink(); (self.delivery / 'producer-sdk.json').unlink()
        self.assertNotEqual(V.inventory(self.delivery, self.limits), first)

    def test_fake_capability_and_duplicate_keys_reject(self):
        with self.assertRaisesRegex(ValueError, 'Only full actual'):
            V.AuthenticatedNormalCandidate(object(), self.delivery, self.root/'metadata', b'{}', b'{}', self.limits, b'{}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            V.unique_json(b'{"status":"passed","status":"retained-unadmitted"}')
        with self.assertRaises(ValueError):
            V.Limits(delivery_bytes=True, file_bytes=1, files=1)

    def test_stable_raw_preserves_exact_formatting_and_bounds_before_open(self):
        path = self.root / 'ordinary-raw-proof.json'; raw = b'{ "unknowns" : [ ], "repository" : null }\n'
        path.write_bytes(raw)
        self.assertEqual(V.stable_raw(path, len(raw)), raw)
        self.assertEqual(V.unique_json(V.stable_raw(path)), {'unknowns': [], 'repository': None})
        with mock.patch.object(Path, 'open', side_effect=AssertionError('over-limit body must not open')):
            with self.assertRaisesRegex(ValueError, 'bound before read'):
                V.stable_raw(path, len(raw) - 1)

    def source_root_fixture(self, reported, archived):
        # Root-exclusion helper data only; this is not a genuine normal parent.
        self.write('reports/source-roots.json', dict(roots=[dict(name='reported', path=str(reported))]))
        self.write('sources/source-manifest.json', dict(roots=[dict(name='archived', originalPath=str(archived))]))
        return dict(files=V.inventory(self.delivery, self.limits)), dict(paths={'workspace': str(self.root/'workspace')})

    def test_source_root_exclusion_rejects_external_reported_root_before_staging(self):
        workspace=self.root/'workspace'; workspace.mkdir()
        external=self.root/'external-source'; external.mkdir()
        archived=self.root/'other-source'; archived.mkdir()
        record, context=self.source_root_fixture(external, archived)
        with mock.patch.object(V.tempfile, 'TemporaryDirectory', side_effect=AssertionError('no staging creation')):
            with self.assertRaisesRegex(ValueError, 'every original source root'):
                V.source_storage_exclusion(self.delivery, external/'metadata', context, record)
        self.assertEqual(list(external.iterdir()), [])

    def test_source_root_exclusion_covers_final_manifest_and_enclosing_metadata(self):
        workspace=self.root/'workspace'; workspace.mkdir()
        reported=self.root/'reported-source'; reported.mkdir()
        parent=self.root/'archive-parent'; parent.mkdir()
        archived=parent/'source'; archived.mkdir()
        record, context=self.source_root_fixture(reported, archived)
        with self.assertRaisesRegex(ValueError, 'every original source root'):
            V.source_storage_exclusion(self.delivery, archived/'metadata', context, record)
        with self.assertRaisesRegex(ValueError, 'every original source root'):
            V.source_storage_exclusion(self.delivery, parent, context, record)
        safe=self.root/'private-seal'
        originals=V.source_storage_exclusion(self.delivery, safe, context, record)
        self.assertIn(reported, originals); self.assertIn(archived, originals)
        self.assertFalse(safe.exists()); self.assertEqual(list(archived.iterdir()), [])

    @unittest.skipIf(os.name == 'posix', 'Windows full-factory negative only; POSIX genuine control remains pending')
    def test_windows_never_mints_full_normal_candidate_or_creates_output(self):
        with self.assertRaisesRegex(ValueError, 'requires POSIX'):
            V.authenticate_normal_candidate(self.delivery, self.root/'metadata', self.expected,
                normal_context={}, capture_relative='capture', capture_source_root='capture', budget=None, limits=self.limits)
        self.assertFalse((self.root/'metadata').exists())

    def test_real_nupkg_root_metadata_preserves_absent_repository(self):
        import musl_legacy5_candidate_collect as collector
        E = collector._module('musl_legacy5_evidence.py')
        path = self.root / 'ordinary.nupkg'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('Ordinary.nuspec', '<package><metadata><id>Ordinary</id><version>1.0.0</version></metadata></package>')
            archive.writestr('cbodotnet-provenance/original-definitions/Original.nuspec', '<package/>')
        before = V.file_fingerprint(path, self.limits.file_bytes)
        self.assertIsNone(E.nuspec_metadata(path).find('{*}repository'))
        self.assertEqual(V.file_fingerprint(path, self.limits.file_bytes), before)

    def test_original_x64_bootstrap_native_source_guard_stays_negative(self):
        import musl_legacy5_bootstrap_native_source_inputs as BN
        with self.assertRaisesRegex(ValueError, 'aarch64.*x64 positive is pending'):
            BN.validate(self.delivery, {}, dict(sdkVersion=V.SDK, architecture='x64'))


class SourceIndexBytes(unittest.TestCase):
    def test_original_source_session_authenticates_tiny_git_bytes_and_rejects_index_change(self):
        # Reuse only the existing ordinary byte-fixture builder, never retained inputs.
        fixture_path = ROOT/'tests/musl_legacy5_appinsights_archive_test.py'
        spec = importlib.util.spec_from_file_location('candidate_ordinary_source_fixture', fixture_path)
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        A = fixture.A
        archive, index, manifest, expected = fixture.source_fixture()
        with tempfile.TemporaryDirectory() as directory:
            budget = fixture.budget(); snapshots = []
            def captured(raw):
                value = A.Snapshot.from_bytes(raw, A.fingerprint(raw), budget=budget, category='source'); snapshots.append(value); return value
            def session(index_raw, value):
                raw = V.encoded(value)
                return A.SourceSession(captured(archive), captured(index_raw), raw, expected,
                    manifest_identity=A.fingerprint(raw), budget=budget, private_root=Path(directory))
            current = None
            try:
                current = session(index, manifest); result = current.verify()
                self.assertFalse(result['sourceAdmissionAllowed']); self.assertFalse(result['wholeProducerSourceClosure'])
                current.close(); current = None
                row = json.loads(index); row['sha256'] = 'e'*64; changed = (json.dumps(row)+'\n').encode()
                altered = copy.deepcopy(manifest); altered['index'].update(A.fingerprint(changed))
                with self.assertRaises(ValueError):
                    current = session(changed, altered); current.verify()
            finally:
                if current is not None: current.close()
                for value in snapshots: value.close()


if __name__ == '__main__':
    unittest.main()
