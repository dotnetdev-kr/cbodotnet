"""SDK5 evidence keeps independent process IDs and bootstrap generations."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_compiler_evidence_tested', ROOT / 'scripts/musl_legacy5_component_evidence.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def actual_task(component='sdk'):
    version = M.BOOTSTRAPS[component]
    return dict(taskName='Csc', succeeded=True, context='1:2:3:4',
        projectFile='/source/src/Product/Product.csproj',
        taskFile='/bootstrap/sdk/' + version + '/Roslyn/Microsoft.CSharp.Core.targets', events=[
            dict(kind='task-parameter', field='Sources', text='Product.cs'),
            dict(kind='task-parameter', field='SkipCompilerExecution', text='False'),
            dict(kind='task-parameter', field='OutputAssembly', text='obj/Product.dll'),
            dict(kind='command-line', text='/bootstrap/dotnet exec /bootstrap/sdk/' + version
                 + '/Roslyn/bincore/csc.dll /out:obj/Product.dll /refout:obj/ref/Product.dll Product.cs')])


def rows(task=None, replay='sdk', component='sdk'):
    task = task or actual_task(component)
    return M.compiler_rows({task['context']: task}, '/source', replay, component)


class SeparateCompilerProcesses(unittest.TestCase):
    def test_same_original_context_in_two_processes_is_not_renumbered(self):
        sdk = rows(replay='sdk'); redist = rows(replay='redist')
        self.assertEqual(sdk[0]['context'], redist[0]['context'])
        self.assertNotEqual(M.output_key(sdk[0]), M.output_key(redist[0]))
        self.assertEqual((sdk[0]['replayName'], redist[0]['replayName']), ('sdk', 'redist'))

    def test_reference_output_is_the_real_command_even_without_scalar(self):
        answer = rows()
        self.assertEqual([r['outputKind'] for r in answer], ['assembly', 'reference-assembly'])
        self.assertEqual(answer[1]['outputPath'], '/source/src/Product/obj/ref/Product.dll')

    def test_disagreeing_reference_scalar_is_rejected(self):
        task = actual_task(); task['events'].append(dict(kind='task-parameter', field='OutputRefAssembly', text='other.dll'))
        with self.assertRaisesRegex(ValueError, 'reference scalar and command disagree'): rows(task)

    def test_out_command_must_agree_with_original_task_parameter(self):
        task = actual_task(); task['events'][-1]['text'] = task['events'][-1]['text'].replace('/out:obj/Product.dll', '/out:other.dll')
        with self.assertRaisesRegex(ValueError, 'OutputAssembly disagree'): rows(task)

    def test_refout_cannot_escape_actual_mount(self):
        task = actual_task(); task['events'][-1]['text'] = task['events'][-1]['text'].replace('obj/ref/Product.dll', '/foreign/Product.dll')
        with self.assertRaisesRegex(ValueError, 'escaped its source mount'): rows(task)

    def test_vstest_has_its_independent_6_bootstrap(self):
        self.assertTrue(rows(component='vstest'))
        with self.assertRaisesRegex(ValueError, 'independent bootstrap'): rows(actual_task('sdk'), component='vstest')
        with self.assertRaisesRegex(ValueError, 'independent bootstrap'): rows(actual_task('vstest'), component='sdk')

    def test_compiler_targets_cannot_disagree_with_launched_host(self):
        task = actual_task(); task['taskFile'] = task['taskFile'].replace('5.0.401', '6.0.135')
        with self.assertRaisesRegex(ValueError, 'targets and launched bootstrap disagree'): rows(task)

    def test_multiple_compiler_commands_cannot_select_a_preferred_one(self):
        task = actual_task(); event = copy.deepcopy(task['events'][-1]); event['text'] += ' /define:SECOND'
        task['events'].append(event)
        with self.assertRaisesRegex(ValueError, 'One actual executed'): rows(task)

    def test_skipped_or_source_less_tasks_do_not_establish_products(self):
        task = actual_task(); task['events'][1]['text'] = 'True'; self.assertEqual(rows(task), [])
        task = actual_task(); task['events'] = [e for e in task['events'] if e.get('field') != 'Sources']
        self.assertEqual(rows(task), [])

    def test_no_merged_or_missing_original_processes(self):
        M.replay_names('sdk', [dict(name='sdk'), dict(name='redist')])
        for names in [('merged',), ('sdk', 'sdk'), ('redist', 'sdk'), ('sdk',)]:
            with self.assertRaisesRegex(ValueError, 'separate original'): M.replay_names('sdk', [dict(name=n) for n in names])


class EmptyOriginalSelections(unittest.TestCase):
    def fixture(self, directory, name):
        directory = Path(directory); (directory/'source.binlog').write_bytes(b'original binary log')
        (directory/'tasks.jsonl').write_bytes(b'')
        status = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
            unfinishedSelectedTasks=0, completedSelectedTasks=0, failure=None, observedTaskNames={},
            inputSha256=M.fingerprint(directory/'source.binlog')['sha256'])
        (directory/'status.json').write_text(json.dumps(status))
        return dict(name=name, sourceMountRoot='/source', status=directory/'status.json',
                    tasks=directory/'tasks.jsonl', binlog=directory/'source.binlog'), status

    def test_four_real_zero_selections_preserve_empty_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in M.EMPTY_REPLAYS:
                entry, _ = self.fixture(tmp, name)
                _, tasks, observed = M.read_replay('vstest', entry, tmp, retained=False)
                self.assertEqual((tasks, observed), ({}, []))

    def test_empty_source_build_cannot_be_relabelled_as_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry, _ = self.fixture(tmp, 'original-solution-build')
            with self.assertRaisesRegex(ValueError, 'four original'): M.read_replay('vstest', entry, tmp, retained=False)
            entry['name'] = 'original-solution-restore'
            with self.assertRaisesRegex(ValueError, 'four original'): M.read_replay('sdk', entry, tmp, retained=False)

    def test_original_binlog_hash_must_agree_even_for_empty_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry, status = self.fixture(tmp, 'original-solution-restore'); status['inputSha256'] = '0' * 64
            entry['status'].write_text(json.dumps(status))
            with self.assertRaisesRegex(ValueError, 'original binary log'): M.read_replay('vstest', entry, tmp, retained=False)

    def test_empty_stream_cannot_hide_a_reported_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry, status = self.fixture(tmp, 'original-solution-restore'); status['observedTaskNames'] = {'Csc': 1}
            entry['status'].write_text(json.dumps(status))
            with self.assertRaisesRegex(ValueError, 'four original'): M.read_replay('vstest', entry, tmp, retained=False)


class OriginalCrossgenCommands(unittest.TestCase):
    def fixture(self):
        source = '/installer/artifacts/bin/redist/Release/dotnet/sdk/5.0.214/Roslyn/bincore/csc.dll'
        directory = str(Path(source).parent).replace('\\', '/')
        framework = '/installer/artifacts/bin/redist/Release/dotnet/shared/Microsoft.NETCore.App/5.0.17'
        values = dict(SourceAssembly=source, DestinationPath=source, ReadyToRun='True', CrossgenPath='/imports/crossgen',
            JITPath='/imports/native-runtime/libclrjit.so', CreateSymbols='True')
        task = dict(context='1:2:3:4', taskName='Crossgen', succeeded=True,
            projectFile='/installer/src/redist/redist.csproj', taskFile='/installer/src/redist/targets/Crossgen.targets',
            events=[dict(kind='task-parameter', field=k, text=v) for k, v in values.items()])
        task['events'] += [dict(kind='task-parameter', field='PlatformAssemblyPaths', text=p) for p in [directory, framework]]
        task['events'] += [dict(kind='command-line', text='> /imports/crossgen -readytorun -MissingDependenciesOK -in '
            + source + ' -out /tmp/private/csc.dll -platform_assemblies_paths ' + directory + ':' + framework
            + ' -JITPath /imports/native-runtime/libclrjit.so'), dict(kind='command-line',
            text='> /imports/crossgen -readytorun -platform_assemblies_paths ' + directory + ':' + framework
                 + ' -createperfmap ' + directory + ' ' + source)]
        row = dict(replayName='installer', context=task['context'], task='Crossgen', archivePath='sdk/5.0.214/Roslyn/bincore/csc.dll',
                   inputPath=source, outputPath=source)
        fp = dict(bytes=1234, sha256='a' * 64, sha512='b' * 128)
        record = dict(sdkVersion=M.SDK, architecture='aarch64', targetRid='linux-musl-arm64', crossgenPath='/imports/crossgen',
            nativeRuntimeRoot='/imports/native-runtime', expectedNativeFingerprints={'crossgen': fp, 'libclrjit.so': fp})
        return row, dict(name='installer', sourceMountRoot='/installer'), {task['context']: task}, record

    def test_original_crossgen_has_implicit_native_architecture_and_real_symbols(self):
        row, replay, tasks, record = self.fixture()
        result = M.validate_crossgen_task(row, replay, tasks, record)
        self.assertEqual(result['replayName'], 'installer')
        self.assertEqual(len(result['commands']), 2)
        self.assertEqual(result['jitPath'], '/imports/native-runtime/libclrjit.so')

    def test_command_cannot_select_a_different_jit_than_its_original_scalar(self):
        row, replay, tasks, record = self.fixture()
        tasks[row['context']]['events'][-2]['text'] = tasks[row['context']]['events'][-2]['text'].replace('-JITPath /imports/', '-JITPath /other/')
        with self.assertRaisesRegex(ValueError, 'Crossgen/JIT command differs'): M.validate_crossgen_task(row, replay, tasks, record)

    def test_symbols_cannot_refer_to_another_output(self):
        row, replay, tasks, record = self.fixture()
        tasks[row['context']]['events'][-1]['text'] += '.other'
        with self.assertRaisesRegex(ValueError, 'same actual transformed'): M.validate_crossgen_task(row, replay, tasks, record)

    def test_native_fingerprints_are_required_from_the_independent_guard(self):
        row, replay, tasks, record = self.fixture(); record['expectedNativeFingerprints']['crossgen'] = {}
        with self.assertRaisesRegex(ValueError, 'native compiler/JIT fingerprints'): M.validate_crossgen_task(row, replay, tasks, record)


if __name__ == '__main__': unittest.main()
