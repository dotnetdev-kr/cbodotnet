"""Fail-closed boundaries for one real PCL derivation and its retained replay."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sdk5_genuine_app',ROOT/'scripts/musl_legacy5_appinsights.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class GenuinePclBoundary(unittest.TestCase):
    def test_policy_is_authenticated_before_parse(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'{}'),mock.patch.object(M.json,'loads',side_effect=AssertionError('untrusted policy parsed')):
            with self.assertRaisesRegex(ValueError,'policy differs'):M.policy()

    def test_reference_zip_is_authenticated_before_parse(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'changed.zip';path.write_bytes(b'changed')
            with mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('untrusted ZIP parsed')):
                with self.assertRaisesRegex(ValueError,'reference ZIP'):M.validate_reference_zip(path)

    def test_original_target_git_bytes_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);raw=b'original';name='target.props';p=dict(portableTargets=dict(files={name:dict(**M.fingerprint(raw),gitBlob=hashlib.sha1(b'blob 8\0'+raw).hexdigest())}))
            (root/name).write_bytes(raw);self.assertEqual(M.validate_targets(root,p),{name:raw});(root/name).write_bytes(b'substitute')
            with self.assertRaisesRegex(ValueError,'Git bytes'):M.validate_targets(root,p)

    def test_root_worker_rejects_before_process_launch(self):
        with mock.patch.object(M.os,'getuid',return_value=0,create=True),mock.patch.object(M,'run_record',side_effect=AssertionError('compiler launched')):
            with self.assertRaisesRegex(ValueError,'non-root'):M.worker()

    def test_api_reader_rejects_truncated_or_escaped_pe(self):
        api=M.api_module()
        for raw in(b'MZ',b'MZ'+bytes(58)+b'\xff\xff\xff\xff'+bytes(64)):
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):api.public_api(raw)

    def test_replay_must_bind_its_original_binlog(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'replay').mkdir();(root/'app.binlog').write_bytes(b'original');status=dict(schemaVersion=1,completedReplay=True,buildSucceeded=True,unfinishedTasks=0,unfinishedSelectedTasks=0,failure=None,inputSha256='0'*64)
            (root/'replay/app-status.json').write_text(json.dumps(status))
            with self.assertRaisesRegex(ValueError,'original binary log'):M._tasks(root,'app')

    def test_replay_cannot_reuse_a_completed_context(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'replay').mkdir();(root/'app.binlog').write_bytes(b'original');status=dict(schemaVersion=1,completedReplay=True,buildSucceeded=True,unfinishedTasks=0,unfinishedSelectedTasks=0,failure=None,inputSha256=M.file_fingerprint(root/'app.binlog')['sha256'],completedSelectedTasks=2)
            task=dict(context='1:2:3:4',succeeded=True,events=[dict(kind='task-started',eventNumber=1),dict(kind='task-finished',eventNumber=2,succeeded=True)])
            (root/'replay/app-status.json').write_text(json.dumps(status));(root/'replay/app-tasks.jsonl').write_text((json.dumps(task)+'\n')*2)
            with self.assertRaisesRegex(ValueError,'unique completed'):M._tasks(root,'app')

    def test_api_difference_prevents_local_package_creation(self):
        with tempfile.TemporaryDirectory()as directory,mock.patch.object(M,'verify_execution',return_value={}),mock.patch.object(M,'api_proof',side_effect=ValueError('API difference')),mock.patch.object(M.zipfile,'ZipFile',side_effect=AssertionError('package created')):
            with self.assertRaisesRegex(ValueError,'API difference'):M.package_local(Path(directory),{})
            self.assertFalse((Path(directory)/'output/microsoft.applicationinsights.2.0.0-cbodotnet.1.nupkg').exists())

    def test_package_requires_real_execution_evidence_first(self):
        with tempfile.TemporaryDirectory()as directory,mock.patch.object(M,'verify_execution',side_effect=ValueError('missing actual compiler')),mock.patch.object(M,'api_proof',side_effect=AssertionError('API substituted for execution')):
            with self.assertRaisesRegex(ValueError,'missing actual compiler'):M.package_local(Path(directory),{})

    def test_legacy_item_parameters_preserve_items_separately_from_metadata(self):
        task=dict(events=[dict(kind='message',text='Task Parameter:\n    References=\n        /reference/first.dll\n                CopyLocal=false\n        /reference/second.dll')])
        self.assertEqual(M.task_values(task,'References'),{'/reference/first.dll','/reference/second.dll'})
        task['events'][0]['text']='Task Parameter:\n    References=\n                CopyLocal=false'
        with self.assertRaisesRegex(ValueError,'must follow'):M.task_values(task,'References')

    def test_uncontrolled_or_foreign_host_path_rejects_before_lookup(self):
        for path in('/usr/bin:/bootstrap','/foreign:/usr/bin'):
            with mock.patch.object(M.shutil,'which',side_effect=AssertionError('uncontrolled lookup')):
                with self.assertRaisesRegex(ValueError,'controlled compiler host'):M.bound_host(dict(PATH=path,DOTNET_ROOT='/bootstrap',DOTNET_HOST_PATH='/bootstrap/dotnet'),'/bootstrap')

if __name__=='__main__':unittest.main()
