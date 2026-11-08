"""Keep failed source-build diagnostics bounded and independent of build policy."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import musl_build_diagnostics as M


@unittest.skipIf(os.name=='nt','Producer capture uses Linux O_NOFOLLOW')
class SourceCapture(unittest.TestCase):
    def test_actual_outer_inner_properties_and_binlog_are_preserved_with_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';out=root/'evidence'
            paths=['src/source-build-assets/eng/Build.props',
                   'src/source-build-assets/artifacts/source-build/self/src/src/referencePackages/Directory.Build.props',
                   'src/source-build-assets/artifacts/source-build/self/src/artifacts/sourcebuild.binlog']
            for name in paths:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'actual-input')
            result=M.capture(source,out)
            self.assertEqual(set(paths),{row['path'] for row in result['files']})
            self.assertFalse(result['qualificationAllowed'])
            for row in result['files']:
                self.assertEqual(hashlib.sha256(b'actual-input').hexdigest(),row['sha256'])
                self.assertEqual(b'actual-input',(out/row['path']).read_bytes())

    def test_redirected_and_oversized_inputs_are_skipped_without_reading_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';out=root/'evidence'
            link=source/'src/source-build-assets/eng/Build.props';link.parent.mkdir(parents=True)
            private=root/'outside';private.write_bytes(b'private-value');link.symlink_to(private)
            huge=source/'src/source-build-assets/artifacts/log/Release/Build.binlog';huge.parent.mkdir(parents=True)
            with huge.open('wb') as stream:stream.truncate(257*1024**2)
            result=M.capture(source,out)
            self.assertFalse(result['files'])
            self.assertFalse((out/link.relative_to(source)).exists())
            self.assertTrue(any('Redirected' in row['reason'] for row in result['skipped']))
            self.assertTrue(any('oversized' in row['reason'] for row in result['skipped']))


if __name__=='__main__':unittest.main()
