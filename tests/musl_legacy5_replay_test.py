import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_replay as R


class ActualProcessReplayContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.binlog = Path(self.temporary.name) / 'original.binlog'; self.binlog.write_bytes(b'original binary log')
        self.status = dict(completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
            unfinishedSelectedTasks=0, failure=None, inputSha256=hashlib.sha256(self.binlog.read_bytes()).hexdigest(), completedSelectedTasks=0)

    def test_only_four_explicit_original_stages_accept_real_empty_reader_exit(self):
        for name in R.EMPTY_STAGES: R.validate(self.status, self.binlog, name, 1)
        for name in ('sdk', 'installer', 'original-library-matrix', 'original-solution-build'):
            with self.subTest(name=name), self.assertRaises(ValueError): R.validate(self.status, self.binlog, name, 1)

    def test_empty_success_and_nonempty_failure_are_not_relabelled(self):
        with self.assertRaises(ValueError): R.validate(self.status, self.binlog, 'original-solution-restore', 0)
        self.status['completedSelectedTasks'] = 1
        with self.assertRaises(ValueError): R.validate(self.status, self.binlog, 'sdk', 1)
        R.validate(self.status, self.binlog, 'sdk', 0)

    def test_changed_input_and_incomplete_replay_fail_even_at_allowed_stage(self):
        for key, value in [('inputSha256', '0' * 64), ('unfinishedTasks', 1), ('unfinishedSelectedTasks', 1),
                           ('failure', 'reader failed'), ('buildSucceeded', False), ('completedReplay', False)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                R.validate(dict(self.status, **{key: value}), self.binlog, 'original-solution-restore', 1)

    def test_task_count_is_numeric_not_a_truth_value(self):
        with self.assertRaises(ValueError): R.validate(dict(self.status, completedSelectedTasks=True), self.binlog, 'sdk', 0)


if __name__ == '__main__': unittest.main()
