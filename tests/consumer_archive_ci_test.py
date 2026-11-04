"""Archive CI may mutate only disposable native containers and trusted main runs."""
import os
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive_ci as CI


class ConsumerArchiveCiTests(unittest.TestCase):
    def test_host_or_wrong_os_is_rejected_before_package_manager_commands(self):
        contract=CI.load_contract()
        with mock.patch.object(CI.os,'geteuid',return_value=0),mock.patch.object(CI.Path,'is_file',return_value=False),mock.patch.object(CI,'run') as run:
            with self.assertRaisesRegex(ValueError,'disposable'):CI.guard('ubuntu-24.04','x64')
            run.assert_not_called()
        with mock.patch.object(CI.os,'geteuid',return_value=0),mock.patch.object(CI.Path,'is_file',return_value=True),\
            mock.patch.object(CI.Path,'read_text',return_value='ID=debian\nVERSION_ID=12\n'),\
            mock.patch.object(CI,'load_contract',return_value=contract),mock.patch.object(CI,'run') as run:
            with self.assertRaisesRegex(ValueError,'OS/version'):CI.guard('debian-13','x64')
            run.assert_not_called()

    def test_source_identity_rejects_nonmain_or_unreviewed_workflow_events(self):
        good=dict(GITHUB_REPOSITORY=CI.REPOSITORY,GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_WORKFLOW_REF=CI.REPOSITORY+'/'+CI.WORKFLOW+'@refs/heads/main',GITHUB_SHA='a'*40,GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='1')
        with mock.patch.dict(os.environ,good,clear=True):self.assertEqual('42',CI.source_identity()['runId'])
        for key,value in [('GITHUB_REF','refs/heads/untrusted'),('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REPOSITORY','someone/fork')]:
            with self.subTest(key=key),mock.patch.dict(os.environ,dict(good,**{key:value}),clear=True):
                with self.assertRaises(ValueError):CI.source_identity()

    def test_every_publication_predicate_requires_boolean_true(self):
        workflow=(ROOT/'.github/workflows/distribution-release.yml').read_text()
        references=re.findall(r'inputs\.publish\b([^\n]*)',workflow)
        self.assertTrue(references)
        self.assertTrue(all(value.lstrip().startswith('== true') for value in references))
        self.assertIn('Build branded consumer archive on native',workflow)
        self.assertIn('compression-level: 0',workflow)


if __name__=='__main__':unittest.main()
