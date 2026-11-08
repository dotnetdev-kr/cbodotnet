"""SDK5 source coverage for each original compiler process and context.

Separate SDK and VSTest logs may reuse context numbers. Each source snapshot
therefore retains its component and replay name; empty original VSTest stages
keep their actual empty status. No event streams are merged or renumbered.
"""
import json
from pathlib import Path
import tarfile

import musl_legacy5_component_evidence as CE
import musl_legacy_compiler_inputs as INPUTS

B = CE.B
require, portable = B.require, B.portable
ROOT_NAME = 'sdk5-managed-compiler-inputs'
ROLE = 'sdk5-separate-process-observed-managed-source-inputs'
FP = CE.FP
COMPONENTS = ('sdk', 'nuget', 'vstest', 'installer')


def sequence(component, entries):
    require(component in COMPONENTS, 'An original SDK5 source component is required')
    if component == 'installer': require([row['name'] for row in entries] == ['installer'], 'One original SDK5 installer process is required')
    else: CE.replay_names(component, entries)
    for entry in entries: portable(entry['name'])


def selected_tasks(tasks, mount, component, name):
    selected = {key: row for key, row in tasks.items() if row['taskName'] in ('Csc', 'Fsc')
                and row['succeeded'] and row['projectFile'].startswith(mount + '/')
                and not any(v.lower() == 'true' for v in B.task_values(row, 'SkipCompilerExecution'))}
    if not selected:
        # A complete nonempty process can contain only Copy/other selected
        # tasks. Empty Reader streams are separately restricted below.
        return {}
    return INPUTS.task_inputs(tasks, mount)


def read_process(paths, component, name, mount):
    status = json.loads(paths['status'].read_bytes())
    tasks = B.read_tasks(paths['tasks']) if paths['tasks'].stat().st_size else {}
    require(status.get('schemaVersion') == 1 and status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0
            and status.get('failure') is None and status.get('inputSha256') == CE.fingerprint(paths['binlog'])['sha256']
            and type(status.get('completedSelectedTasks')) is int and status['completedSelectedTasks'] == len(tasks),
            'Complete original SDK5 process/status/task matrix required for source capture')
    if not tasks:
        require(component == 'vstest' and name in CE.EMPTY_REPLAYS and status.get('observedTaskNames', {}).get('Csc', 0) == 0,
                'Only original empty SDK5 VSTest selections may have no tasks')
    return selected_tasks(tasks, mount, component, name)


def prepare(replays, roots, destination):
    require(set(replays) == set(COMPONENTS), 'All four SDK5 compiler components are required')
    destination = Path(destination).absolute()
    require(not destination.exists(), 'Fresh separate-process SDK5 compiler input root required')
    destination.mkdir(parents=True); processes = {}
    for component in COMPONENTS:
        sequence(component, replays[component]); processes[component] = []
        for entry in replays[component]:
            paths = {key: CE.ordinary(entry[key]) for key in ('status', 'tasks', 'binlog')}
            selected = read_process(paths, component, entry['name'], entry['sourceMountRoot'])
            row = dict(name=entry['name'], sourceRoot=component, sourceMountRoot=entry['sourceMountRoot'],
                inputFingerprints={key: CE.fingerprint(path) for key, path in paths.items()},
                compilerTasks=len(selected), noCompilerTasks=not bool(selected),
                emptyOriginalStage=json.loads(paths['status'].read_bytes())['completedSelectedTasks'] == 0)
            if selected:
                directory = destination / component / entry['name']
                INPUTS.prepare({component: dict(sourceRoot=component, sourceMountRoot=entry['sourceMountRoot'],
                    hostPath=roots[component]['path'], tasks=paths['tasks'])}, directory)
                row['directory'] = component + '/' + entry['name']
            processes[component].append(row)
    document = dict(schemaVersion=1, sdkVersion=CE.SDK, kind=ROLE, processes=processes,
        observation='after-completed-build', compileTimeHashingClaimed=False,
        syntheticMergedReplay=False, contextsRenumbered=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
    (destination / 'processes.json').write_text(json.dumps(document, indent=2) + '\n')
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate_process(directory, component, replay, process):
    """Recompute each task's exact sources, resources and generated outputs."""
    paths = {key: B.checked(directory, replay[key]) for key in ('status', 'tasks', 'binlog')}
    selected = read_process(paths, component, process['name'], replay['sourceMountRoot'])
    reader_empty = json.loads(paths['status'].read_bytes())['completedSelectedTasks'] == 0
    require(process['name'] == replay['name'] and process['sourceRoot'] == component and process['sourceMountRoot'] == replay['sourceMountRoot']
            and process['inputFingerprints'] == {key: {k: replay[key][k] for k in FP} for key in ('status', 'tasks', 'binlog')}
            and process['compilerTasks'] == len(selected) and process['noCompilerTasks'] is (not bool(selected))
            and process['emptyOriginalStage'] is reader_empty,
            'SDK5 source snapshot must bind its exact original replay and fingerprints')
    return selected


def validate(release, manifest, replays):
    release = Path(release); directory = release / 'reports/build' / ROOT_NAME
    raw = CE.ordinary(directory / 'processes.json').read_bytes(); document = json.loads(raw)
    require(document.get('schemaVersion') == 1 and document.get('sdkVersion') == CE.SDK and document.get('kind') == ROLE
            and document.get('observation') == 'after-completed-build'
            and all(document.get(key) is False for key in ('compileTimeHashingClaimed', 'syntheticMergedReplay',
                'contextsRenumbered', 'qualificationAllowed', 'sourceAdmissionAllowed'))
            and set(document['processes']) == set(replays) == set(COMPONENTS), 'Closed separate SDK5 compiler process source matrix required')
    roots = [row for row in manifest['roots'] if row['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0].get('role') == ROLE
            and roots[0].get('commit') is None, 'SDK5 generated source inputs require their distinct data-only root')
    expected = {ROOT_NAME + '/processes.json': INPUTS.fingerprint(raw)}; originals = {}; count = 0
    for component in COMPONENTS:
        sequence(component, replays[component]); sequence(component, document['processes'][component])
        for replay, process in zip(replays[component], document['processes'][component]):
            selected = validate_process(release, component, replay, process)
            if not selected:
                require(set(process) == {'name', 'sourceRoot', 'sourceMountRoot', 'inputFingerprints', 'compilerTasks', 'noCompilerTasks', 'emptyOriginalStage'},
                        'Original empty SDK5 stages may not carry synthetic compiler input trees')
                continue
            prefix = component + '/' + replay['name']; require(process['directory'] == prefix, 'Separate SDK5 compiler input directory differs')
            inner = directory / prefix; body = CE.ordinary(inner / 'compiler-inputs.json').read_bytes(); captured = json.loads(body)
            require(captured.get('schemaVersion') == 1 and captured.get('kind') == 'observed-managed-compiler-inputs'
                    and captured.get('observation') == 'after-completed-build' and captured.get('compileTimeHashingClaimed') is False
                    and set(captured['components']) == {component}, 'One original process per SDK5 compiler source snapshot required')
            observed = captured['components'][component]
            require(observed['sourceRoot'] == component and observed['sourceMountRoot'] == replay['sourceMountRoot']
                    and observed['tasks'].keys() == selected.keys(), 'Every original SDK5 compiler task needs source coverage')
            expected[ROOT_NAME + '/' + prefix + '/compiler-inputs.json'] = INPUTS.fingerprint(body)
            for context, task in selected.items():
                actual = observed['tasks'][context]; extra = {'generatedFiles'} if 'generatedDirectory' in task else set()
                require(set(actual) == set(task) | extra and all(actual[key] == value for key, value in task.items() if key != 'inputs')
                        and len(actual['inputs']) == len(task['inputs']), 'Original SDK5 task/input matrix differs')
                pairs = list(zip(task['inputs'], actual['inputs']))
                if 'generatedDirectory' in task:
                    paths = [item['sourcePath'] for item in actual['generatedFiles']]
                    require(paths == sorted(set(paths)) and len(paths) <= 100000, 'Unique bounded SDK5 compiler-generated source inputs required')
                    for item in actual['generatedFiles']:
                        source = item['sourcePath']
                        require(source.startswith(task['generatedDirectory'] + '/') and source.lower().endswith(('.cs', '.fs', '.vb')),
                                'SDK5 generated compiler source escaped its actual output directory')
                        pairs.append((dict(sourcePath=source, relativePath=portable(source[len(replay['sourceMountRoot']) + 1:])), item))
                for source, item in pairs:
                    relative = portable(source['relativePath']); local = 'files/' + component + '/' + relative
                    require(set(item) == set(source) | set(FP) | {'retained'} and item['retained'] == local
                            and all(item[key] == value for key, value in source.items()), 'Exact SDK5 compiler source path required; no source absence waiver')
                    fp = INPUTS.fingerprint(CE.ordinary(inner / local).read_bytes())
                    require(all(item[key] == fp[key] for key in FP), 'Retained actual SDK5 compiler source bytes differ')
                    expected[ROOT_NAME + '/' + prefix + '/' + local] = fp
                    original = component + '/' + relative
                    require(original not in originals or originals[original] == fp, 'SDK5 source bytes changed between original compiler processes')
                    originals[original] = fp
                count += 1
    require({ROOT_NAME + '/' + p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()} == expected.keys(),
            'No extra or omitted SDK5 compiler source snapshot files are permitted')
    indexed = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = row['path']
            if name in originals: require(all(row[key] == originals[name][key] for key in FP), 'SDK5 captured compiler source differs from archived original source')
            if name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate SDK5 compiler source index entry'); indexed[name] = {key: row[key] for key in FP}
    require(indexed == expected, 'Complete independently recomputed SDK5 compiler source index required')
    seen = set()
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.isfile() and entry.name not in seen and entry.size == expected[entry.name]['bytes']
                    and entry.size <= 64 * 1024**2, 'Bounded ordinary archived SDK5 compiler source required')
            require(INPUTS.fingerprint(archive.extractfile(entry).read()) == expected[entry.name], 'Archived SDK5 compiler source bytes differ')
            seen.add(entry.name)
    require(seen == expected.keys(), 'Complete actual archived SDK5 compiler sources required')
    return dict(status='passed-sdk5-separate-process-managed-source-coverage', processes=sum(map(len, replays.values())),
        compilerTasks=count, files=len(expected), compileTimeHashingClaimed=False, syntheticMergedReplay=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
