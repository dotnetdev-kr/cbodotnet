import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_managed_inputs as M


class SeparateProcessSourceInputs(unittest.TestCase):
    def test_sdk_process_order_is_original_and_never_replaced_by_merged_stream(self):
        M.sequence('sdk', [dict(name='sdk'), dict(name='redist')])
        for names in (['merged'], ['redist', 'sdk'], ['sdk', 'sdk']):
            with self.subTest(names=names), self.assertRaises(ValueError): M.sequence('sdk', [dict(name=n) for n in names])

    def test_all_eleven_vstest_processes_including_four_empty_stages_remain_required(self):
        rows = [dict(name=n) for n in M.CE.VSTEST_REPLAYS]; M.sequence('vstest', rows)
        with self.assertRaises(ValueError): M.sequence('vstest', [r for r in rows if r['name'] not in M.CE.EMPTY_REPLAYS])
        with self.assertRaises(ValueError): M.sequence('installer', [dict(name='sdk')])

    def fixture(self, directory):
        paths = {key: directory / key for key in ('status', 'tasks', 'binlog')}
        paths['tasks'].write_bytes(b''); paths['binlog'].write_bytes(b'original binary log')
        status = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
            unfinishedSelectedTasks=0, failure=None, inputSha256=M.CE.fingerprint(paths['binlog'])['sha256'],
            completedSelectedTasks=0, observedTaskNames={})
        paths['status'].write_text(json.dumps(status)); return paths, status

    def test_only_original_empty_vstest_stage_can_have_empty_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths, _ = self.fixture(Path(tmp))
            self.assertEqual(M.read_process(paths, 'vstest', 'original-solution-restore', '/vstest'), {})
            for component, name in [('sdk', 'sdk'), ('installer', 'installer'), ('vstest', 'original-solution-build')]:
                with self.subTest(component=component, name=name), self.assertRaises(ValueError):
                    M.read_process(paths, component, name, '/source')

    def test_fake_empty_status_counts_and_changed_binlog_cannot_hide_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths, status = self.fixture(Path(tmp))
            for changed in (dict(status, completedSelectedTasks=1), dict(status, observedTaskNames={'Csc': 1}),
                            dict(status, inputSha256='0'*64), dict(status, buildSucceeded=False)):
                paths['status'].write_text(json.dumps(changed))
                with self.assertRaises(ValueError): M.read_process(paths, 'vstest', 'original-solution-restore', '/vstest')

    def test_nonempty_original_copy_process_has_no_synthetic_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths, status = self.fixture(Path(tmp))
            events = [dict(eventNumber=n, timestamp='2026-11-08T22:00:00Z', kind=kind,
                field=None, text=None, metadata={}, succeeded=True if n else None)
                for n, kind in enumerate(('task-started', 'task-finished'))]
            task = dict(context='1:2:3:4', taskName='Copy', projectFile='/vstest/src/original.csproj',
                taskFile='/bootstrap/original.targets', succeeded=True, events=events)
            paths['tasks'].write_text(json.dumps(task)+'\n'); status['completedSelectedTasks']=1
            paths['status'].write_text(json.dumps(status))
            self.assertEqual(M.read_process(paths, 'vstest', 'datacollector-publish', '/vstest'), {})

    def test_original_process_identity_and_all_input_fingerprints_are_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); paths, _ = self.fixture(directory)
            replay = dict(name='original-solution-restore', sourceMountRoot='/vstest',
                **{key: dict(path=path.name, **M.CE.fingerprint(path)) for key, path in paths.items()})
            process = dict(name=replay['name'], sourceRoot='vstest', sourceMountRoot='/vstest', compilerTasks=0,
                noCompilerTasks=True, emptyOriginalStage=True, inputFingerprints={key: M.CE.fingerprint(path) for key, path in paths.items()})
            self.assertEqual(M.validate_process(directory, 'vstest', replay, process), {})
            for key, value in [('name', 'Microsoft.TestPlatform.CLI-pack'), ('sourceMountRoot', '/other'), ('sourceRoot', 'sdk')]:
                changed = dict(process, **{key: value})
                with self.subTest(key=key), self.assertRaises(ValueError): M.validate_process(directory, 'vstest', replay, changed)
            changed = copy.deepcopy(process); changed['inputFingerprints']['tasks']['sha512'] = '0'*128
            with self.assertRaises(ValueError): M.validate_process(directory, 'vstest', replay, changed)


if __name__ == '__main__': unittest.main()
