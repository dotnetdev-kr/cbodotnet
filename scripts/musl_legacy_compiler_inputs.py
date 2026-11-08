"""Retain observed managed compiler sources, including generated inputs.

Inputs are read after the completed build. Original binary logs bind the task
paths; this records their observed bytes without claiming compile-time hashing.
No compiler or input assembly is executed by this module.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import posixpath
import shlex
import tarfile

ROOT_NAME = 'managed-compiler-inputs'
ROLE = 'observed-managed-compiler-source-inputs'
FIELDS = {'Sources', 'Resources', 'EmbeddedFiles', 'AdditionalFiles'}
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def contract():
    spec = importlib.util.spec_from_file_location('managed_input_primitives', Path(__file__).with_name('musl_legacy_admission.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def task_inputs(tasks, mount):
    require(isinstance(mount, str) and mount.startswith('/') and posixpath.normpath(mount) == mount
            and not any(c in mount for c in '\\\0\r\n'), 'Ordinary absolute compiler source mount required')
    result = {}
    for context, task in tasks.items():
        if task['taskName'] not in ('Csc', 'Fsc') or not task['succeeded']: continue
        if not task['projectFile'].startswith(mount + '/'): continue
        if any(e['kind'] == 'task-parameter' and e['field'] == 'SkipCompilerExecution'
               and (e['text'] or '').lower() == 'true' for e in task['events']): continue
        selected = {}
        for event in task['events']:
            if event['kind'] != 'task-parameter' or event['field'] not in FIELDS: continue
            path = event['text']
            require(isinstance(path, str) and path and not any(c in path for c in '\\\0\r\n'), 'Ordinary recorded compiler input path required')
            resolved = posixpath.normpath(path if path.startswith('/') else posixpath.join(posixpath.dirname(task['projectFile']), path))
            require(resolved.startswith(mount + '/'), 'Managed compiler input escaped its declared source mount')
            key = (event['field'], resolved)
            selected[key] = dict(field=event['field'], sourcePath=resolved, relativePath=resolved[len(mount) + 1:])
        empty = not any(field == 'Sources' for field, path in selected)
        if empty:
            commands = [e['text'] for e in task['events'] if e['kind'] == 'command-line']
            require(task['taskName'] == 'Csc' and len(commands) == 1 and isinstance(commands[0], str)
                    and not any(token.startswith('@') or token.lower().endswith(('.cs', '.fs', '.vb'))
                                for token in shlex.split(commands[0])),
                    'A source-less metadata compilation may not hide source operands or response files')
        require(len(selected) <= 100000, 'Bounded managed compiler task inputs required')
        result[context] = dict(taskName=task['taskName'], projectFile=task['projectFile'], emptySources=empty,
            inputs=[selected[key] for key in sorted(selected)])
    require(result, 'Actual executed managed compiler tasks required')
    return result


def prepare(components, destination):
    """Copy complete actual source/resource inputs from recorded Csc/Fsc tasks."""
    reader = contract(); destination = Path(destination).absolute(); records, bodies = {}, {}
    for component, row in sorted(components.items()):
        reader.portable(component); reader.portable(row['sourceRoot'])
        tasks = reader.read_tasks(Path(row['tasks']))
        selected = task_inputs(tasks, row['sourceMountRoot']); host = Path(row['hostPath']).absolute()
        for task in selected.values():
            for item in task['inputs']:
                relative = reader.portable(item['relativePath']); path = host / relative
                require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                        and path.stat().st_size <= 64 * 1024**2, 'Bounded ordinary observed managed source input required')
                raw = path.read_bytes(); name = 'files/' + component + '/' + relative
                require(name not in bodies or bodies[name] == raw, 'Observed compiler input changed during capture')
                bodies[name] = raw; item.update(retained=name, **fingerprint(raw))
        records[component] = dict(sourceRoot=row['sourceRoot'], sourceMountRoot=row['sourceMountRoot'], tasks=selected)
    document = dict(schemaVersion=1, kind='observed-managed-compiler-inputs', observation='after-completed-build',
        compileTimeHashingClaimed=False, components=records)
    bodies['compiler-inputs.json'] = (json.dumps(document, indent=2) + '\n').encode()
    for name, raw in bodies.items():
        path = destination / reader.portable(name); path.parent.mkdir(parents=True, exist_ok=True)
        require(not any(p.is_symlink() for p in (path, *path.parents))
                and (not path.exists() or path.read_bytes() == raw), 'Refusing redirected or changed compiler source output')
        if not path.exists(): path.write_bytes(raw)
    require({p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()} == bodies.keys(),
            'Unexpected managed compiler input tree file')
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, replays):
    """Recompute task coverage and bind every observed source into the archive."""
    reader = contract(); release = Path(release); directory = release / 'reports/build' / ROOT_NAME
    path = directory / 'compiler-inputs.json'; raw = path.read_bytes(); document = json.loads(raw)
    require(document.get('schemaVersion') == 1 and document.get('kind') == 'observed-managed-compiler-inputs'
            and document.get('observation') == 'after-completed-build' and document.get('compileTimeHashingClaimed') is False
            and document['components'].keys() == replays.keys(), 'Complete observed compiler input component set required')
    roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0]['role'] == ROLE
            and roots[0].get('commit') is None, 'Observed generated source must retain its separate non-Git role')
    expected = {ROOT_NAME + '/compiler-inputs.json': fingerprint(raw)}; original = {}
    for component, replay in replays.items():
        observed = document['components'][component]
        require(observed['sourceRoot'] == component and observed['sourceMountRoot'] == replay['sourceMountRoot'],
                'Observed managed compiler source identity differs')
        tasks = task_inputs(reader.read_tasks(reader.checked(release, replay['tasks'])), replay['sourceMountRoot'])
        require(tasks.keys() == observed['tasks'].keys(), 'An executed managed compilation is missing source coverage')
        for context, task in tasks.items():
            actual = observed['tasks'][context]
            require(set(actual) == set(task) and task['taskName'] == actual['taskName'] and task['projectFile'] == actual['projectFile']
                    and task['emptySources'] == actual['emptySources']
                    and len(task['inputs']) == len(actual['inputs']), 'Observed compiler task/input matrix differs')
            for source, item in zip(task['inputs'], actual['inputs']):
                name = 'files/' + component + '/' + reader.portable(source['relativePath'])
                require(set(item) == set(source) | set(FP) | {'retained'} and item['retained'] == name
                        and all(item[key] == value for key, value in source.items()), 'Observed compiler source path differs from actual binary log')
                data_path = directory / name
                require(data_path.is_file() and not any(p.is_symlink() for p in (data_path, *data_path.parents)), 'Ordinary retained compiler source required')
                fp = fingerprint(data_path.read_bytes()); require(all(item[key] == fp[key] for key in FP), 'Retained compiler source bytes differ')
                full = ROOT_NAME + '/' + name
                require(full not in expected or expected[full] == fp, 'Conflicting compiler source bytes')
                expected[full] = fp; original[component + '/' + source['relativePath']] = fp
    index = {}
    with (release / 'sources' / reader.portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = row['path']
            if name.startswith(ROOT_NAME + '/'):
                require(name not in index, 'Duplicate compiler source index entry'); index[name] = row
            if name in original:
                require(all(row.get(key) == original[name][key] for key in FP), 'Compiler input copy differs from its archived original source')
    require(index.keys() == expected.keys() and all(all(index[name].get(key) == fp[key] for key in FP)
            for name, fp in expected.items()), 'Complete observed compiler source index required')
    seen = set()
    with tarfile.open(release / 'sources' / reader.portable(manifest['archive']['path']), 'r|gz') as archive:
        for member in archive:
            if member.name not in expected: continue
            require(member.isfile() and member.size == expected[member.name]['bytes'] and member.size <= 64 * 1024**2
                    and member.name not in seen, 'Ordinary bounded archived compiler source required')
            require(fingerprint(archive.extractfile(member).read()) == expected[member.name], 'Archived compiler source bytes differ')
            seen.add(member.name)
    require(seen == expected.keys(), 'Archived observed compiler source is incomplete')
    return dict(status='passed-observed-compiler-source-coverage', components=sorted(replays), files=len(expected))
