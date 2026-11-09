"""SDK6 uses the same immutable bytes, with independent original leaf checks."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest import mock

import musl_source_archive_test as ORIGINAL

M=ORIGINAL.M
A6=ORIGINAL.A.module('sdk6_transport_actual_leaf_test','musl_legacy6_admission.py')


class SDK6Fixture:
    def archive(self,entries):
        manifest=super().archive(entries)
        manifest['sdkVersion']='6.0.136'
        return manifest


class SDK6SourceArchiveBytes(SDK6Fixture,ORIGINAL.SourceArchiveBytes):
    """Rerun unchanged SDK7 byte-transport fixtures with exact SDK6 eligibility."""
    def test_only_both_exact_reviewed_versions_can_enter_even_platform_fallback(self):
        for version in('5.0.214','6.0.135','6.0.137','7.0.121','8.0.100',None):
            manifest=copy.deepcopy(self.manifest);manifest['sdkVersion']=version
            with (self.subTest(version=version),mock.patch.object(M,'supported',return_value=False),
                    mock.patch.object(M,'copy_authenticated',side_effect=AssertionError('unsupported version prepared')),
                    self.assertRaisesRegex(ValueError,'Only reviewed SDK6/SDK7')):
                with self.session(manifest):self.fail('unreviewed version entered')

    def test_original_and_unsupported_fallback_open_exact_streaming_gzip_mode(self):
        for use_session in(False,True):
            with self.subTest(session=use_session),mock.patch.object(M.tarfile,'open',wraps=M.tarfile.open)as opened:
                if use_session:
                    with mock.patch.object(M,'supported',return_value=False),self.session()as enabled:
                        self.assertFalse(enabled);self.assertEqual(4,len(self.inspect()))
                else:self.assertEqual(4,len(self.inspect()))
                self.assertEqual(1,opened.call_count)
                self.assertEqual((self.sources/'source.tar.gz','r|gz'),opened.call_args.args)
                self.assertEqual({},opened.call_args.kwargs)

    def test_dynamically_loaded_sdk6_consumers_share_canonical_module(self):
        self.assertIs(A6.open_source_archive,M.open_source_archive)
        self.assertIs(A6.source_session,M.source_session)
        for consumer in(A6.F,A6.C,A6.G,A6.MS,A6.BCL,A6.LITERAL,A6.NUGET_SOURCE,
                A6.VSTEST_SOURCE,A6.NATIVE_INPUTS,A6.BOUNDARY):
            self.assertIs(consumer.open_source_archive,M.open_source_archive)
        self.assertIs(A6.BOUNDARY.B.open_source_archive,M.open_source_archive)
        compiler=A6.module('sdk6_transport_already_shared_compiler','musl_legacy_compiler_inputs.py')
        self.assertIs(compiler.open_source_archive,M.open_source_archive)


@unittest.skipUnless(M.supported(),'Linux read-only unlinked pread byte transport required')
class LinuxSDK6SourceArchiveBytes(SDK6Fixture,ORIGINAL.LinuxSourceArchiveBytes):
    def test_capacity_fallback_opens_exact_original_streaming_gzip(self):
        with (mock.patch.object(M.shutil,'disk_usage',return_value=SimpleNamespace(free=0)),
                mock.patch.object(M.tarfile,'open',wraps=M.tarfile.open)as opened):
            with self.session()as enabled:
                self.assertFalse(enabled);self.assertEqual(4,len(self.inspect()))
            self.assertEqual((self.sources/'source.tar.gz','r|gz'),opened.call_args.args)
            self.assertEqual({},opened.call_args.kwargs)

    def test_actual_sdk6_index_member_predicates_match_gzip_and_owned_raw_readers(self):
        wanted={'code/ordinary.cs','code/run.sh'}
        with mock.patch.object(M,'supported',return_value=False),self.session():
            expected=A6.source_archive_members(self.release,self.manifest,wanted)
        with mock.patch.object(M.gzip,'GzipFile',wraps=M.gzip.GzipFile)as decoded:
            with self.session()as enabled:
                self.assertTrue(enabled)
                self.assertEqual(expected,A6.source_archive_members(self.release,self.manifest,wanted))
                self.assertEqual(expected,A6.source_archive_members(self.release,self.manifest,wanted))
                self.assertEqual(expected[0]['code/ordinary.cs'],
                    A6.BOUNDARY.source_member(self.release,self.manifest,'code/ordinary.cs'))
            self.assertEqual(1,decoded.call_count)

    def test_actual_sdk6_missing_duplicate_and_hash_failures_match_both_transports(self):
        for failure in('missing','duplicate','hash'):
            with self.subTest(failure=failure):
                self.manifest=self.archive(self.entries+([self.entries[0]]if failure=='duplicate'else[]))
                wanted={'code/absent.cs'if failure=='missing'else'code/ordinary.cs'}
                if failure=='hash':
                    path=self.sources/'source-index.jsonl'
                    rows=[json.loads(line)for line in path.read_bytes().splitlines()]
                    rows[0]['sha256']='0'*64
                    path.write_bytes(b''.join((json.dumps(row)+'\n').encode()for row in rows))
                    self.manifest['index'].update(ORIGINAL.fp(path.read_bytes()))
                message={'missing':'Complete SDK6 source member coverage','duplicate':'Duplicate SDK6 source archive member',
                    'hash':'Archived SDK6 source bytes differ'}[failure]
                for supported in(False,True):
                    with self.subTest(seekable=supported),mock.patch.object(M,'supported',return_value=supported):
                        with self.session(),self.assertRaisesRegex(ValueError,message):
                            A6.source_archive_members(self.release,self.manifest,wanted)

    def test_preparation_io_error_is_fatal_without_opening_a_fallback_reader(self):
        with (mock.patch.object(M,'copy_authenticated',side_effect=OSError('unit copy I/O failure')),
                mock.patch.object(M.tarfile,'open',side_effect=AssertionError('error fell back to gzip')),
                self.assertRaisesRegex(OSError,'unit copy I/O failure')):
            with self.session():self.fail('preparation error entered')
        self.assertIsNone(M._ACTIVE.get())
        self.assertEqual([],list(self.cache_parent.iterdir()))
        self.assertFalse(any(row['event']=='fallback'for row in self.observations()))


if __name__=='__main__':unittest.main()
