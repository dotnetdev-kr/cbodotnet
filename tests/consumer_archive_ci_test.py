"""Archive CI may mutate only disposable native containers and trusted main runs."""
import os
import errno
import json
from pathlib import Path
import re
import sys
import unittest
import tempfile
from unittest import mock
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive_ci as CI


class ConsumerArchiveCiTests(unittest.TestCase):
    def test_core3_preparation_installs_readelf_before_companion_elf_validation(self):
        for version in ('3.0.103','3.1.426','5.0.214','10.0.403'):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as temporary:
                workspace=Path(temporary);(workspace/'build').mkdir()
                plan=dict(sdkVersion=version,architecture='x64')
                if version.startswith('3.'):plan['nativeHttpCompatibility']={'required':True}
                (workspace/'build/package-build.json').write_text(json.dumps({'plan':plan}))
                calls=[]
                def run(arguments,**kwargs):
                    calls.append(arguments)
                    if arguments[0]=='useradd':raise RuntimeError('stop after validation prerequisites')
                    return ''
                with mock.patch.object(CI,'guard'),mock.patch.object(CI,'load_contract',return_value={}),\
                        mock.patch.object(CI,'native_dependencies',return_value=[]),mock.patch.object(CI,'run',side_effect=run):
                    with self.assertRaisesRegex(RuntimeError,'validation prerequisites'):
                        CI.prepare(SimpleNamespace(workspace=workspace,variant='ubuntu-22.04'))
                self.assertEqual(version.startswith('3.'),'binutils' in calls[1])
                self.assertEqual('useradd',calls[2][0])

    @unittest.skipUnless(os.name=='posix','Preserved Linux modes and symlinks required')
    def test_overlay_lower_layer_exdev_relocation_preserves_bytes_modes_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.mkdir();(source/'payload').mkdir()
            (source/'payload/host').write_bytes(b'qualified-host');(source/'payload/host').chmod(0o751)
            (source/'payload/host-link').symlink_to('host')
            before=CI.sdk_tools().snapshot(source);destination=Path(directory)/'moved directory'
            with mock.patch.object(Path,'rename',side_effect=OSError(errno.EXDEV,'overlay lower layer')):
                CI.relocate_tree(source,destination)
            self.assertFalse(source.exists());self.assertEqual(before,CI.sdk_tools().snapshot(destination))

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
