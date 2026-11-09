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
import subprocess
import tarfile
from musl_source_archive import open_source_archive

ROOT_NAME = 'managed-compiler-inputs'
ROLE = 'observed-managed-compiler-source-inputs'
FIELDS = {'Sources', 'Resources', 'EmbeddedFiles', 'AdditionalFiles'}
FP = ('bytes', 'sha256', 'sha512')
ABSENT_VSTEST_COMMIT = '79d56b02b69a582cd90428878a5e9411ab7538f5'
ABSENCE_BASIS = 'original-vstest-package-api-file-not-present'
ABSENT_API_FILES = {'src/package/package/PublicAPI/net7.0/PublicAPI.Shipped.txt',
                    'src/package/package/PublicAPI/net7.0/PublicAPI.Unshipped.txt'}


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def contract():
    spec = importlib.util.spec_from_file_location('managed_input_primitives', Path(__file__).with_name('musl_legacy_admission.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def generated_directory(task, mount):
    prefix = 'Task Parameter:GeneratedFilesOutputPath='
    values = set()
    for event in task['events']:
        if event['kind'] == 'task-parameter' and event['field'] == 'GeneratedFilesOutputPath': value = event['text']
        elif event['kind'] == 'message' and isinstance(event['text'], str) and event['text'].startswith(prefix): value = event['text'][len(prefix):]
        else: continue
        if value: values.add(value)
    require(len(values) <= 1, 'Ambiguous actual compiler-generated output directory')
    def resolve(value):
        require(isinstance(value, str) and not any(c in value for c in '\\\0\r\n'), 'Ordinary compiler-generated source directory required')
        result = posixpath.normpath(value if value.startswith('/') else posixpath.join(posixpath.dirname(task['projectFile']), value))
        require(result.startswith(mount + '/'), 'Compiler-generated source directory escaped its actual source mount')
        return result
    arguments = []
    for event in task['events']:
        if event['kind'] != 'command-line': continue
        arguments.extend(resolve(token.split(':', 1)[1]) for token in shlex.split(event['text'])
                         if token.lower().startswith(('/generatedfilesout:', '-generatedfilesout:')))
    if not values:
        require(not arguments, 'Compiler-generated output command lacks its actual recorded scalar')
        return None
    directory = resolve(next(iter(values)))
    require(arguments == [directory], 'Compiler-generated output scalar and actual command disagree')
    return directory


def reviewed_absence(component, task, item, mount):
    return (component == 'vstest' and task['taskName'] == 'Csc'
            and task['projectFile'] == mount + '/src/package/package/package.csproj'
            and item.get('field') == 'AdditionalFiles' and item['relativePath'] in ABSENT_API_FILES
            and item['sourcePath'] == mount + '/' + item['relativePath'])


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
        directory = generated_directory(task, mount)
        if directory is not None: result[context]['generatedDirectory'] = directory
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
                require(not any(p.is_symlink() for p in (path, *path.parents)), 'Redirected observed managed source input')
                if not path.exists():
                    require(reviewed_absence(component, task, item, row['sourceMountRoot']),
                            'Missing actual compiler source/resource input has no reviewed absence policy')
                    git = ['git', '-c', 'safe.directory=' + str(host), '-C', str(host)]
                    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == ABSENT_VSTEST_COMMIT
                            and not subprocess.check_output(git + ['ls-tree', '-z', '--full-tree', ABSENT_VSTEST_COMMIT, '--', relative]),
                            'Reviewed absent API-analyzer inputs must be absent from their exact original Git source')
                    item.update(observedAbsent=True, absenceBasis=ABSENCE_BASIS, sourceCommit=ABSENT_VSTEST_COMMIT)
                    continue
                require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                        and path.stat().st_size <= 64 * 1024**2, 'Bounded ordinary observed managed source input required')
                raw = path.read_bytes(); name = 'files/' + component + '/' + relative
                require(name not in bodies or bodies[name] == raw, 'Observed compiler input changed during capture')
                bodies[name] = raw; item.update(retained=name, **fingerprint(raw))
            if 'generatedDirectory' in task:
                relative_directory = task['generatedDirectory'][len(row['sourceMountRoot']) + 1:]
                directory = host / reader.portable(relative_directory)
                require(not any(p.is_symlink() for p in (directory, *directory.parents))
                        and (not directory.exists() or directory.is_dir()), 'Ordinary generated compiler source directory required')
                generated = []
                for path in sorted(directory.rglob('*')) if directory.exists() else []:
                    require(not path.is_symlink(), 'Linked compiler-generated source is forbidden')
                    if not path.is_file(): continue
                    require(path.suffix.lower() in ('.cs', '.vb', '.fs') and path.stat().st_size <= 64 * 1024**2,
                            'Only bounded readable compiler-generated source is accepted')
                    relative = path.relative_to(host).as_posix(); name = 'files/' + component + '/' + reader.portable(relative)
                    raw = path.read_bytes()
                    require(name not in bodies or bodies[name] == raw, 'Generated compiler source changed during capture')
                    bodies[name] = raw
                    generated.append(dict(sourcePath=row['sourceMountRoot'] + '/' + relative, relativePath=relative,
                        retained=name, **fingerprint(raw)))
                require(len(generated) <= 100000, 'Bounded compiler-generated source output matrix required')
                task['generatedFiles'] = generated
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
    expected = {ROOT_NAME + '/compiler-inputs.json': fingerprint(raw)}; original, absent = {}, set()
    for component, replay in replays.items():
        observed = document['components'][component]
        require(observed['sourceRoot'] == component and observed['sourceMountRoot'] == replay['sourceMountRoot'],
                'Observed managed compiler source identity differs')
        tasks = task_inputs(reader.read_tasks(reader.checked(release, replay['tasks'])), replay['sourceMountRoot'])
        require(tasks.keys() == observed['tasks'].keys(), 'An executed managed compilation is missing source coverage')
        for context, task in tasks.items():
            actual = observed['tasks'][context]
            extra = {'generatedFiles'} if 'generatedDirectory' in task else set()
            require(set(actual) == set(task) | extra and task['taskName'] == actual['taskName'] and task['projectFile'] == actual['projectFile']
                    and task['emptySources'] == actual['emptySources']
                    and len(task['inputs']) == len(actual['inputs']), 'Observed compiler task/input matrix differs')
            pairs = list(zip(task['inputs'], actual['inputs']))
            if 'generatedDirectory' in task:
                require(actual['generatedDirectory'] == task['generatedDirectory'] and isinstance(actual['generatedFiles'], list),
                        'Actual compiler-generated source directory differs')
                paths = [item['sourcePath'] for item in actual['generatedFiles']]
                require(paths == sorted(set(paths)) and len(paths) <= 100000, 'Unique bounded compiler-generated source paths required')
                for item in actual['generatedFiles']:
                    source = item['sourcePath']
                    require(source.startswith(task['generatedDirectory'] + '/') and posixpath.normpath(source) == source
                            and source.lower().endswith(('.cs', '.vb', '.fs')), 'Compiler-generated source escaped its actual output directory')
                    pairs.append((dict(sourcePath=source, relativePath=source[len(replay['sourceMountRoot']) + 1:]), item))
            for source, item in pairs:
                if item.get('observedAbsent') is True:
                    require(set(item) == set(source) | {'observedAbsent', 'absenceBasis', 'sourceCommit'}
                            and all(item[key] == value for key, value in source.items())
                            and item['absenceBasis'] == ABSENCE_BASIS and item['sourceCommit'] == ABSENT_VSTEST_COMMIT
                            and reviewed_absence(component, task, source, replay['sourceMountRoot']),
                            'Only two original VSTest package AdditionalFiles may record explicit observed absence')
                    vcs = [r for r in manifest['roots'] if r['name'] == 'vstest']
                    require(len(vcs) == 1 and vcs[0]['kind'] in ('git', 'git-export') and vcs[0].get('commit') == ABSENT_VSTEST_COMMIT
                            and not any(r['path'] == source['relativePath'] for r in vcs[0].get('deleted', [])),
                            'An observed absent analyzer input may not be a deleted original source')
                    absent.add(component + '/' + source['relativePath'])
                    continue
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
            require(name not in absent, 'An explicitly absent analyzer input is present in the source archive index')
            if name.startswith(ROOT_NAME + '/'):
                require(name not in index, 'Duplicate compiler source index entry'); index[name] = row
            if name in original:
                require(all(row.get(key) == original[name][key] for key in FP), 'Compiler input copy differs from its archived original source')
    require(index.keys() == expected.keys() and all(all(index[name].get(key) == fp[key] for key in FP)
            for name, fp in expected.items()), 'Complete observed compiler source index required')
    seen = set()
    with open_source_archive(release, manifest) as archive:
        for member in archive:
            if member.name not in expected: continue
            require(member.isfile() and member.size == expected[member.name]['bytes'] and member.size <= 64 * 1024**2
                    and member.name not in seen, 'Ordinary bounded archived compiler source required')
            require(fingerprint(archive.extractfile(member).read()) == expected[member.name], 'Archived compiler source bytes differ')
            seen.add(member.name)
    require(seen == expected.keys(), 'Archived observed compiler source is incomplete')
    return dict(status='passed-observed-compiler-source-coverage', components=sorted(replays), files=len(expected))
