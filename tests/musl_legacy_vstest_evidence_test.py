"""Reject incomplete original VSTest compilers and imported-output relabeling."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy_vstest_evidence as M


class OriginalVSTestCompilerBoundary(unittest.TestCase):
    def task(self,output='obj/Release/Source.dll'):
        return dict(context='1:2:3:4',taskName='Csc',succeeded=True,projectFile='/vstest/src/P/P.csproj',
            events=[dict(kind='task-parameter',field='OutputAssembly',text=output)])

    def test_relative_original_compiler_output_is_resolved_from_its_actual_project(self):
        with tempfile.TemporaryDirectory()as temporary:
            source=Path(temporary);path=source/'src/P/obj/Release/Source.dll';path.parent.mkdir(parents=True);path.write_bytes(b'original output')
            result=M.compiler_outputs({'1:2:3:4':self.task()},'/vstest',source)
            self.assertEqual([('1:2:3:4','/vstest/src/P/obj/Release/Source.dll')],result[M.A.fingerprint(path)['sha256']])

    def test_skipped_failed_and_escaped_compiler_outputs_cannot_be_attributed(self):
        with tempfile.TemporaryDirectory()as temporary:
            source=Path(temporary);path=source/'src/P/obj/Release/Source.dll';path.parent.mkdir(parents=True);path.write_bytes(b'original output')
            skipped=self.task();skipped['events'].append(dict(kind='task-parameter',field='SkipCompilerExecution',text='true'))
            failed=dict(self.task(),succeeded=False)
            for task in(skipped,failed,self.task('/unrelated/Source.dll'),self.task('../../../../unrelated/Source.dll')):
                with self.subTest(task=task),self.assertRaises(ValueError):
                    M.compiler_outputs({'1:2:3:4':task},'/vstest',source)

    def test_incomplete_replay_is_rejected_before_package_or_binary_log_read(self):
        with tempfile.TemporaryDirectory()as temporary:
            source=Path(temporary);status=source/'status.json'
            context=dict(sdkVersion='7.0.120',vstestReplay=dict(status=str(status)))
            roots=dict(vstest=dict(path=str(source),kind='git',commit=M.COMMIT))
            base=dict(completedReplay=True,buildSucceeded=True,unfinishedTasks=0,unfinishedSelectedTasks=0)
            for changed in(dict(completedReplay=False),dict(buildSucceeded=False),dict(unfinishedTasks=1),dict(unfinishedSelectedTasks=1)):
                status.write_text(json.dumps(dict(base,**changed)))
                with mock.patch.object(M.subprocess,'check_output',return_value=M.COMMIT+'\n'),self.assertRaisesRegex(ValueError,'complete successful'):
                    M.emit(context,source/'release',roots)


if __name__=='__main__':unittest.main()
