"""Reference provenance must be an actual successful compiler command."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_compiler_evidence_tested', ROOT / 'scripts/musl_legacy6_component_evidence.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def actual_task():
    return dict(taskName='Csc', succeeded=True, context='1:2:3:4', projectFile='/source/src/Product/Product.csproj', events=[
        dict(kind='task-parameter', field='Sources', text='Product.cs'),
        dict(kind='task-parameter', field='SkipCompilerExecution', text='False'),
        dict(kind='task-parameter', field='OutputAssembly', text='obj/Product.dll'),
        dict(kind='command-line', text='dotnet csc.dll /out:obj/Product.dll /refout:obj/ref/Product.dll Product.cs')])


class CompilerReferenceOrigins(unittest.TestCase):
    def test_real_refout_does_not_need_an_invented_scalar(self):
        rows = M.compiler_rows({'1:2:3:4': actual_task()}, '/source')
        self.assertEqual([r['outputKind'] for r in rows], ['assembly', 'reference-assembly'])
        self.assertEqual(rows[1]['outputPath'], '/source/src/Product/obj/ref/Product.dll')

    def test_disagreeing_recorded_ref_scalar_is_rejected(self):
        task = actual_task(); task['events'].append(dict(kind='task-parameter', field='OutputRefAssembly', text='wrong.dll'))
        with self.assertRaisesRegex(ValueError, 'reference scalar and command disagree'):
            M.compiler_rows({'x': task}, '/source')

    def test_refout_outside_source_mount_is_rejected(self):
        task = actual_task(); task['events'][-1]['text'] = task['events'][-1]['text'].replace('obj/ref/Product.dll', '/foreign/Product.dll')
        with self.assertRaisesRegex(ValueError, 'escaped its source mount'):
            M.compiler_rows({'x': task}, '/source')

    def test_primary_scalar_and_real_command_must_agree(self):
        task = actual_task(); task['events'][-1]['text'] = task['events'][-1]['text'].replace('/out:obj/Product.dll', '/out:other.dll')
        with self.assertRaisesRegex(ValueError, 'OutputAssembly disagree'):
            M.compiler_rows({'x': task}, '/source')

    def test_skipped_or_source_less_tasks_cannot_establish_shipping_provenance(self):
        task = actual_task(); task['events'][1]['text'] = 'true'
        with self.assertRaisesRegex(ValueError, 'Successful source-bearing'):
            M.compiler_rows({'x': task}, '/source')
        task = actual_task(); task['events'] = [e for e in task['events'] if e.get('field') != 'Sources']
        with self.assertRaisesRegex(ValueError, 'Successful source-bearing'):
            M.compiler_rows({'x': task}, '/source')

    def test_two_compiler_commands_cannot_select_a_preferred_refout(self):
        task = actual_task(); task['events'].append(dict(kind='command-line', text='dotnet csc.dll /out:other.dll source.cs'))
        with self.assertRaisesRegex(ValueError, 'One actual executed'):
            M.compiler_rows({'x': task}, '/source')


if __name__ == '__main__': unittest.main()
