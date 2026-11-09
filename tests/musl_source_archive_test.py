"""Differential and failure controls for private source TAR byte transport."""
import copy
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_source_archive as M
import musl_legacy_admission as A


def fp(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


class ArchiveFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-source-view-test-')
        self.addCleanup(self.temporary.cleanup)
        self.stderr = io.StringIO()
        capture = contextlib.redirect_stderr(self.stderr)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)
        self.root = Path(self.temporary.name)
        self.release = self.root / 'release'
        self.sources = self.release / 'sources'
        self.sources.mkdir(parents=True)
        self.cache_parent = self.root / 'private'
        self.cache_parent.mkdir()
        self.entries = [
            ('code/ordinary.cs', 0o644, b'class Ordinary {}\n', None),
            ('code/run.sh', 0o755, b'#!/bin/sh\nexit 0\n', None),
            ('code/' + 'long/' * 30 + '번역.cs', 0o644, b'unicode PAX path\n', None),
            ('code/link', 0o777, b'', 'ordinary.cs'),
        ]
        self.manifest = self.archive(self.entries)

    def archive(self, entries):
        rows = []
        path = self.sources / 'source.tar.gz'
        with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            for name, mode, raw, target in entries:
                member = tarfile.TarInfo(name)
                member.mode = mode
                if target is None:
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
                    kind, data = '100755' if mode == 0o755 else '100644', raw
                else:
                    member.type, member.linkname = tarfile.SYMTYPE, target
                    archive.addfile(member)
                    kind, data = '120000', target.encode()
                rows.append(dict(path=name, mode=kind, **fp(data)))
        index = self.sources / 'source-index.jsonl'
        index.write_bytes(b''.join((json.dumps(row, ensure_ascii=False) + '\n').encode() for row in rows))
        return dict(sdkVersion='7.0.120', files=len(rows),
                    archive=dict(path=path.name, **fp(path.read_bytes())),
                    index=dict(path=index.name, **fp(index.read_bytes())))

    def session(self, manifest=None):
        return M.source_session(self.release, manifest or self.manifest, temporary_parent=self.cache_parent)

    def inspect(self, manifest=None):
        with M.open_source_archive(self.release, manifest or self.manifest) as archive:
            return [(member.name, member.type, member.mode, member.size, member.linkname,
                     dict(member.pax_headers), archive.extractfile(member).read() if member.isfile() else None)
                    for member in archive]

    def observations(self):
        return [json.loads(line) for line in self.stderr.getvalue().splitlines()]


class SourceArchiveBytes(ArchiveFixture, unittest.TestCase):
    def test_no_context_retains_original_streaming_gzip_reader(self):
        expected = self.inspect()
        self.assertEqual(4, len(expected))
        self.assertEqual(0o755, expected[1][2])
        self.assertEqual('ordinary.cs', expected[3][4])
        self.assertIn('path', expected[2][5])

    def test_unsupported_platform_keeps_gzip_and_never_prepares_a_snapshot(self):
        expected = self.inspect()
        with mock.patch.object(M, 'supported', return_value=False), \
                mock.patch.object(M, 'copy_authenticated', side_effect=AssertionError('snapshot on unsupported platform')):
            with self.session() as enabled:
                self.assertFalse(enabled)
                self.assertEqual(expected, self.inspect())
        self.assertEqual([], list(self.cache_parent.iterdir()))
        events = self.observations()
        self.assertEqual(['fallback', 'completed'], [row['event'] for row in events])
        self.assertEqual('unsupported-platform', events[0]['reason'])
        self.assertEqual('gzip', events[1]['mode'])
        self.assertEqual('returned', events[1]['outcome'])
        self.assertGreaterEqual(events[1]['durationSeconds'], 0)
        self.assertNotIn(str(self.root), self.stderr.getvalue())
        self.assertTrue(all(row['kind'] == 'musl-source-byte-transport-observation' for row in events))

    def test_linux_maxrss_is_converted_from_kib_and_unavailable_measurements_stay_null(self):
        native = SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda who: SimpleNamespace(ru_maxrss=7))
        with mock.patch.object(M.sys, 'platform', 'linux'), mock.patch.object(M, 'resource', native):
            self.assertEqual(7168, M.max_rss_bytes())
        with mock.patch.object(M, 'resource', None):
            self.assertIsNone(M.max_rss_bytes())
        with mock.patch.object(M.sys, 'platform', 'win32'), mock.patch.object(M, 'resource', native):
            self.assertIsNone(M.max_rss_bytes())
        native.getrusage = mock.Mock(side_effect=OSError('native measurement unavailable'))
        with mock.patch.object(M.sys, 'platform', 'linux'), mock.patch.object(M, 'resource', native):
            self.assertIsNone(M.max_rss_bytes())

    def test_diagnostic_output_failure_cannot_change_validation_or_bool_transport_api(self):
        broken = SimpleNamespace(write=mock.Mock(side_effect=BrokenPipeError('closed diagnostic pipe')),
                                 flush=mock.Mock(side_effect=BrokenPipeError('closed diagnostic pipe')))
        with mock.patch.object(M.sys, 'stderr', broken), mock.patch.object(M, 'supported', return_value=False):
            with self.session() as enabled:
                self.assertIs(enabled, False)
                self.assertEqual(4, len(self.inspect()))

    def test_snapshot_checks_all_three_fingerprints_of_the_bytes_actually_copied(self):
        source = self.sources / 'source.tar.gz'
        for field, forged in [('bytes', self.manifest['archive']['bytes'] + 1),
                              ('sha256', '0' * 64), ('sha512', '0' * 128)]:
            expected = {key: self.manifest['archive'][key] for key in M.FP}
            expected[field] = forged
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir=self.root) as temporary, \
                    self.assertRaisesRegex(ValueError, 'snapshot'):
                M.copy_authenticated(source, Path(temporary) / 'copy.gz', expected)

    def test_same_size_preserved_timestamp_replacement_cannot_evade_snapshot_hashes(self):
        source = self.sources / 'source.tar.gz'
        before = source.stat()
        raw = bytearray(source.read_bytes())
        raw[len(raw) // 2] ^= 1
        source.write_bytes(raw)
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(before.st_size, source.stat().st_size)
        self.assertEqual(before.st_mtime_ns, source.stat().st_mtime_ns)
        with self.assertRaisesRegex(ValueError, 'fingerprints'):
            M.copy_authenticated(source, self.root / 'copy.gz', M.identity(self.manifest['archive']))

    def test_capacity_index_is_itself_fully_fingerprinted(self):
        original = (self.sources / 'source-index.jsonl').read_bytes()
        # Preserve valid JSON and the file count while changing one mode.
        (self.sources / 'source-index.jsonl').write_bytes(original.replace(b'100644', b'100755', 1))
        with self.assertRaisesRegex(ValueError, 'index fingerprints'):
            M.expansion_bound(self.release, self.manifest)

    def test_capacity_bound_counts_headers_aligned_data_and_pax(self):
        actual = len(gzip.decompress((self.sources / 'source.tar.gz').read_bytes()))
        bound = M.expansion_bound(self.release, self.manifest)
        self.assertGreaterEqual(bound, actual)
        self.assertLess(bound, 1024**2)

    def test_unsafe_archive_paths_reject_before_any_reader(self):
        for path in ('../elsewhere.gz', '/absolute.gz', 'sub//source.gz', 'sub\\source.gz'):
            bad = copy.deepcopy(self.manifest)
            bad['archive']['path'] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'relative source archive'):
                self.inspect(bad)


@unittest.skipUnless(M.supported(), 'Linux read-only unlinked pread byte transport required')
class LinuxSourceArchiveBytes(ArchiveFixture, unittest.TestCase):
    def test_raw_readers_preserve_original_headers_bodies_order_and_pax(self):
        expected = self.inspect()
        original = M.fingerprint(self.sources / 'source.tar.gz')
        with self.session() as enabled:
            self.assertTrue(enabled)
            self.assertEqual(expected, self.inspect())
            self.assertEqual(expected, self.inspect())
        self.assertEqual(original, M.fingerprint(self.sources / 'source.tar.gz'))
        self.assertEqual([], list(self.cache_parent.iterdir()))
        events = self.observations()
        self.assertEqual(['prepared', 'completed'], [row['event'] for row in events])
        prepared, completed = events
        self.assertEqual(self.manifest['archive']['bytes'], prepared['compressedBytes'])
        self.assertEqual(len(gzip.decompress((self.sources / 'source.tar.gz').read_bytes())), prepared['rawBytes'])
        self.assertGreaterEqual(prepared['preparationSeconds'], 0)
        self.assertIsInstance(prepared['maxRssBytes'], int)
        self.assertGreater(prepared['temporaryFreeBytes'], 0)
        self.assertGreater(prepared['requiredTemporaryBytes'], prepared['rawBytes'] + prepared['compressedBytes'])
        self.assertEqual('returned', completed['outcome'])
        self.assertEqual('seekable', completed['mode'])
        self.assertGreaterEqual(completed['durationSeconds'], prepared['preparationSeconds'])
        self.assertGreaterEqual(completed['revalidationSeconds'], 0)
        self.assertNotIn(str(self.root), self.stderr.getvalue())

    def test_insufficient_space_falls_back_to_same_gzip_checks(self):
        expected = self.inspect()
        with mock.patch.object(M.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)), \
                mock.patch.object(M, 'copy_authenticated', side_effect=AssertionError('snapshot despite capacity fallback')):
            with self.session() as enabled:
                self.assertFalse(enabled)
                self.assertEqual(expected, self.inspect())
        self.assertEqual([], list(self.cache_parent.iterdir()))
        self.assertEqual('preflight-capacity', self.observations()[0]['reason'])
        self.assertEqual(0, self.observations()[0]['temporaryFreeBytes'])

    def test_absolute_expansion_capacity_also_keeps_original_validation(self):
        expected = self.inspect()
        with mock.patch.object(M, 'MAX_RAW_BYTES', 1), \
                mock.patch.object(M.shutil, 'disk_usage', side_effect=OSError('space measurement unavailable')), \
                mock.patch.object(M, 'copy_authenticated', side_effect=AssertionError('snapshot despite capacity cap')):
            with self.session() as enabled:
                self.assertFalse(enabled)
                self.assertEqual(expected, self.inspect())

    def test_private_view_is_unlinked_read_only_and_has_independent_positions(self):
        with self.session():
            _, _, descriptor, size = M._ACTIVE.get()
            self.assertEqual(0, os.fstat(descriptor).st_nlink)
            with self.assertRaises(OSError):
                os.write(descriptor, b'changed')
            with M.ReadAt(descriptor, size) as first, M.ReadAt(descriptor, size) as second:
                self.assertEqual(first.read(17), second.read(17))
                first.seek(512)
                self.assertEqual(17, second.tell())
                second.seek(-10, os.SEEK_END)
                self.assertEqual(10, len(second.read()))
            private = next(self.cache_parent.iterdir())
            self.assertEqual(0, private.stat().st_mode & 0o077)
            self.assertEqual([], list(private.iterdir()))

    def test_exception_cleanup_closes_descriptor_and_clears_session(self):
        descriptor = None
        with self.assertRaisesRegex(RuntimeError, 'consumer failed'):
            with self.session():
                descriptor = M._ACTIVE.get()[2]
                raise RuntimeError('consumer failed')
        self.assertIsNone(M._ACTIVE.get())
        self.assertEqual([], list(self.cache_parent.iterdir()))
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertEqual(4, len(self.inspect()))

    def test_nested_session_and_other_archive_identity_are_rejected(self):
        with self.session():
            with self.assertRaisesRegex(ValueError, 'Nested'):
                with self.session():
                    self.fail('nested context entered')
            for field, value in [('path', 'other.tar.gz'), ('sha512', '0' * 128)]:
                bad = copy.deepcopy(self.manifest)
                bad['archive'][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'another archive identity'):
                    self.inspect(bad)

    def test_compressed_authentication_failure_is_fatal_and_cleans_up(self):
        (self.sources / 'source.tar.gz').write_bytes(b'different compressed input')
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            with self.session():
                self.fail('failed authentication entered the context')
        self.assertEqual([], list(self.cache_parent.iterdir()))
        self.assertIsNone(M._ACTIVE.get())
        self.assertEqual(['completed'], [row['event'] for row in self.observations()])
        self.assertEqual('raised', self.observations()[0]['outcome'])
        self.assertEqual('unprepared', self.observations()[0]['mode'])

    def test_corrupt_gzip_trailer_with_resealed_transport_is_fatal(self):
        path = self.sources / 'source.tar.gz'
        raw = bytearray(path.read_bytes())
        raw[-8] ^= 1
        path.write_bytes(raw)
        self.manifest['archive'].update(fp(raw))
        with self.assertRaises((OSError, EOFError)):
            with self.session():
                self.fail('bad gzip trailer entered the context')
        self.assertEqual([], list(self.cache_parent.iterdir()))

    def test_expansion_overrun_is_fatal_not_a_fallback(self):
        self.manifest = self.archive(self.entries + [('code/large', 0o644, b'x' * 65536, None)])
        with mock.patch.object(M, 'expansion_bound', return_value=10240), \
                self.assertRaisesRegex(ValueError, 'expansion exceeds'):
            with self.session():
                self.fail('expansion failure entered the context')
        self.assertEqual([], list(self.cache_parent.iterdir()))

    def test_original_archive_mutation_during_semantic_checks_is_rejected_on_exit(self):
        with self.assertRaisesRegex(ValueError, 'changed during revalidation'):
            with self.session():
                self.assertEqual(4, len(self.inspect()))
                path = self.sources / 'source.tar.gz'
                path.write_bytes(path.read_bytes() + b'changed')
        self.assertEqual([], list(self.cache_parent.iterdir()))
        self.assertIsNone(M._ACTIVE.get())

    def test_source_member_absence_and_symlink_controls_match_original_reader(self):
        for enabled in (False, True):
            with self.subTest(seekable=enabled), mock.patch.object(M, 'supported', return_value=enabled):
                with self.session():
                    self.assertEqual(b'class Ordinary {}\n', A.source_member(self.release, self.manifest, 'code/ordinary.cs'))
                    with self.assertRaisesRegex(ValueError, 'absent'):
                        A.source_member(self.release, self.manifest, 'code/absent.cs')
                    with self.assertRaisesRegex(ValueError, 'ordinary corresponding source'):
                        A.source_member(self.release, self.manifest, 'code/link')

    def test_duplicate_headers_and_changed_modes_remain_visible_to_semantic_checks(self):
        self.manifest = self.archive(self.entries + [('code/ordinary.cs', 0o755, b'forged original\n', None)])
        expected = self.inspect()
        with self.session():
            actual = self.inspect()
            self.assertEqual(expected, actual)
            self.assertEqual(2, sum(row[0] == 'code/ordinary.cs' for row in actual))
            self.assertEqual(0o755, actual[-1][2])
            self.assertEqual(b'forged original\n', actual[-1][-1])

    def test_many_independent_reads_decompress_only_once_without_a_verdict_cache(self):
        with mock.patch.object(M.gzip, 'GzipFile', wraps=M.gzip.GzipFile) as decoded:
            with self.session():
                for _ in range(12):
                    self.assertEqual(4, len(self.inspect()))
            self.assertEqual(1, decoded.call_count)

    def test_linked_temporary_parent_and_source_path_are_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.cache_parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked paths'):
            with M.source_session(self.release, self.manifest, temporary_parent=alias):
                self.fail('linked parent entered')
        archive = self.sources / 'source.tar.gz'
        original = self.sources / 'original.gz'
        archive.rename(original)
        archive.symlink_to(original.name)
        with self.assertRaisesRegex(ValueError, 'linked paths'):
            with self.session():
                self.fail('linked source entered')

    def test_temporary_workspace_cannot_enter_the_inventoried_delivery(self):
        with self.assertRaisesRegex(ValueError, 'outside the delivery tree'):
            with M.source_session(self.release, self.manifest, temporary_parent=self.sources):
                self.fail('cache entered inventoried artifact tree')


if __name__ == '__main__':
    unittest.main()
