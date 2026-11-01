"""Reject failed or substituted promotion stages before resuming publication."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('release_stage', Path(__file__).resolve().parents[1] / 'scripts/select-release-stage.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseStageTests(unittest.TestCase):
    def setUp(self):
        self.commit = 'a' * 40
        self.run = dict(id=123, run_attempt=1, head_sha=self.commit, head_branch='main', event='workflow_dispatch',
                        repository=dict(full_name=MODULE.REPOSITORY), head_repository=dict(full_name=MODULE.REPOSITORY),
                        path='.github/workflows/publish-releases.yml', status='completed', conclusion='failure')
        self.jobs = [dict(name='Verify and stage net10', status='completed', conclusion='success',
                          steps=[dict(name='Run actions/upload-artifact@' + 'b' * 40, conclusion='success')])]
        self.artifacts = [dict(id=456, name='public-net10-123-1', expired=False, digest='sha256:' + 'c' * 64,
                              workflow_run=dict(id=123, head_sha=self.commit, head_branch='main', repository_id=1,
                                                head_repository_id=1))]

    def select(self):
        return MODULE.select('net10', '123', '1', self.run, self.jobs, self.artifacts)

    def test_failed_publication_can_resume_its_successful_exact_stage(self):
        self.assertEqual(self.select(), dict(id='456', source_run='123', source_attempt='1', publication_commit=self.commit))

    def test_failed_or_missing_verification_and_upload_never_resume(self):
        original = copy.deepcopy(self.jobs)
        for mutate in (lambda: self.jobs.clear(), lambda: self.jobs.append(copy.deepcopy(self.jobs[0])),
                       lambda: self.jobs[0].update(conclusion='failure'),
                       lambda: self.jobs[0]['steps'][0].update(conclusion='failure')):
            self.jobs = copy.deepcopy(original)
            mutate()
            with self.assertRaises(ValueError):
                self.select()

    def test_wrong_branch_repository_workflow_or_attempt_never_resume(self):
        for key, value in [('head_branch', 'feature'), ('path', '.github/workflows/checks.yml'),
                           ('run_attempt', 2), ('head_repository', dict(full_name='attacker/fork')),
                           ('event', 'pull_request')]:
            with self.subTest(key=key):
                original = self.run[key]
                self.run[key] = value
                with self.assertRaises(ValueError):
                    self.select()
                self.run[key] = original

    def test_expired_duplicate_forked_or_replaced_artifact_never_resumes(self):
        original = copy.deepcopy(self.artifacts)
        changes = [lambda: self.artifacts[0].update(expired=True),
                   lambda: self.artifacts.append(copy.deepcopy(self.artifacts[0])),
                   lambda: self.artifacts[0].update(name='public-net10-123-2'),
                   lambda: self.artifacts[0].update(digest=None),
                   lambda: self.artifacts[0]['workflow_run'].update(head_sha='d' * 40),
                   lambda: self.artifacts[0]['workflow_run'].update(head_repository_id=2)]
        for change in changes:
            self.artifacts = copy.deepcopy(original)
            change()
            with self.assertRaises(ValueError):
                self.select()


if __name__ == '__main__':
    unittest.main()
