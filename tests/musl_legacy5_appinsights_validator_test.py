"""The stronger verifier must reject the reviewer's retained-record forgeries."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('strong_app5_validator',ROOT/'scripts/musl_legacy5_appinsights_validator.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class RetainedAppCompilerBoundary(unittest.TestCase):
    def test_original_worker_is_pinned_before_import(self):
        with mock.patch.object(M.Path,'read_bytes',return_value=b'changed'):
            with self.assertRaisesRegex(ValueError,'original worker source differs'):M.original_worker()

    def test_generated_metadata_values_are_derived_from_policy(self):
        worker=M.original_worker();p=worker.policy();metadata=M.generated_metadata(p)
        self.assertEqual(len(metadata),2)
        self.assertIn(b'AssemblyFileVersionAttribute("2.0.0.30671")',metadata['/output/obj/AssemblyInfo.g.cs'])
        altered=copy.deepcopy(p);altered['assembly']['fileVersion']='2.0.0.12345'
        self.assertIn(b'AssemblyFileVersionAttribute("2.0.0.12345")',M.generated_metadata(altered)['/output/obj/AssemblyInfo.g.cs'])
        self.assertNotEqual(metadata,M.generated_metadata(altered))

    def test_generated_source_rejects_appended_code_even_with_rehashed_record(self):
        worker=M.original_worker();p=worker.policy()
        with tempfile.TemporaryDirectory()as directory:
            output=Path(directory);sources={'/inputs/source/'+n:{}for n in p['source']['compileItems']}
            for name,raw in M.generated_metadata(p).items():
                path=output/name[len('/output/'):];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);sources[name]=worker.fingerprint(raw)
            M.check_generated_metadata(sources,output,p)
            path=output/'obj/AssemblyInfo.g.cs';path.write_bytes(path.read_bytes()+b'internal class UnreviewedImplementation {}\n')
            sources['/output/obj/AssemblyInfo.g.cs']=worker.file_fingerprint(path)
            with self.assertRaisesRegex(ValueError,'policy-derived'):M.check_generated_metadata(sources,output,p)

    def test_generated_source_rejects_unknown_filename(self):
        worker=M.original_worker();p=worker.policy();sources={'/inputs/source/'+n:{}for n in p['source']['compileItems']}
        sources.update({n:worker.fingerprint(raw)for n,raw in M.generated_metadata(p).items()})
        sources['/output/obj/Other.cs']=sources.pop('/output/obj/AssemblyInfo.g.cs')
        with tempfile.TemporaryDirectory()as directory:
            with self.assertRaisesRegex(ValueError,'filenames'):M.check_generated_metadata(sources,Path(directory),p)

    def test_package_entry_calls_stronger_execution_guard_first(self):
        with (mock.patch.object(M,'verify_execution',side_effect=ValueError('strong compiler rejection')),
            mock.patch.object(M,'original_worker',side_effect=AssertionError('frozen packer called'))):
            with self.assertRaisesRegex(ValueError,'strong compiler rejection'):M.package_local(Path('.'),{})


if __name__=='__main__':unittest.main()
