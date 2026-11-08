"""Protect actual managed-source coverage and empty-template boundaries."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('observed_compiler_inputs', Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_compiler_inputs.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def task(sources=('../Shared.cs',), command='dotnet exec csc.dll /out:Template.dll', skip=False):
    events = [dict(kind='command-line', field=None, text=command)]
    events.extend(dict(kind='task-parameter', field='Sources', text=name) for name in sources)
    if skip: events.append(dict(kind='task-parameter', field='SkipCompilerExecution', text='True'))
    return {'1:2:3:4': dict(taskName='Csc', succeeded=True, projectFile='/source/src/Project.csproj', events=events)}


class ObservedSourceBoundary(unittest.TestCase):
    def test_relative_and_generated_sources_preserve_actual_paths(self):
        value = M.task_inputs(task(('../Shared.cs', '/source/artifacts/obj/AssemblyInfo.cs')), '/source')['1:2:3:4']
        self.assertFalse(value['emptySources'])
        self.assertEqual({'artifacts/obj/AssemblyInfo.cs', 'Shared.cs'}, {v['relativePath'] for v in value['inputs']})

    def test_inputs_cannot_escape_the_actual_source_mount(self):
        for name in ('../../outside.cs', '/source-other/secret.cs', '/source/src/../../outside.cs', 'redirect\\source.cs'):
            with self.subTest(name=name), self.assertRaises(ValueError): M.task_inputs(task((name,)), '/source')

    def test_empty_template_compilation_cannot_hide_source_operands(self):
        self.assertTrue(M.task_inputs(task(()), '/source')['1:2:3:4']['emptySources'])
        for command in ('dotnet exec csc.dll /out:Template.dll @inputs.rsp',
                        'dotnet exec csc.dll /out:Template.dll Hidden.cs'):
            with self.assertRaisesRegex(ValueError, 'hide'): M.task_inputs(task((), command), '/source')

    def test_skipped_compilation_cannot_supply_source_coverage(self):
        with self.assertRaisesRegex(ValueError, 'executed'): M.task_inputs(task(skip=True), '/source')


if __name__ == '__main__': unittest.main()
