"""Bind genuine original VSTest package members to completed compiler tasks.

Imported dependencies remain imported even when bundled by a genuine source
package. No SDK bytes are executed and no package wrapper is rewritten.
"""
import json
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import zipfile

import musl_legacy_admission as A
import musl_legacy_nuget_evidence as N

COMMIT='79d56b02b69a582cd90428878a5e9411ab7538f5'
VERSION='17.4.1-dev'
PACKAGES={'Microsoft.TestPlatform.CLI','Microsoft.TestPlatform.Build'}
ORIGIN='rebuilt-original-vstest-source-build-core-distribution'


def compiler_outputs(tasks,mount,source):
    result={}
    for task in tasks.values():
        if task['taskName']!='Csc' or task['succeeded']is not True or not task['projectFile'].startswith(mount+'/'):continue
        if any(event['kind']=='task-parameter'and event['field']=='SkipCompilerExecution'and(event['text']or'').lower()=='true'
               for event in task['events']):continue
        for filename in A.task_values(task,'OutputAssembly'):
            resolved=posixpath.normpath(filename if filename.startswith('/')else posixpath.join(posixpath.dirname(task['projectFile']),filename))
            A.require(resolved.startswith(mount+'/')and not any(c in resolved for c in '\\\0\r\n'),
                'VSTest compiler output escaped its actual source mount')
            path=N.ordinary(source.joinpath(*PurePosixPath(resolved).relative_to(mount).parts))
            result.setdefault(A.fingerprint(path)['sha256'],[]).append((task['context'],resolved))
    A.require(result,'Actual original VSTest compiler outputs are absent')
    return result


def emit(context,release,roots):
    """Retain two exact original outputs and classify every managed member.

    context.vstestReplay has status/tasks/binlog/sourceMountRoot. The two
    context.vstestPackages paths must be unchanged actual source-built outputs;
    roots.vstest binds the exact original Git checkout used by those tasks.
    """
    A.require(context.get('sdkVersion')=='7.0.120','Unreviewed VSTest source build route')
    root=roots['vstest'];source=Path(root['path']).absolute();release=Path(release).absolute()
    A.require(root.get('kind','git')=='git'and root.get('commit')==COMMIT
        and subprocess.check_output(['git','-c','safe.directory='+str(source),'-C',str(source),'rev-parse','HEAD'],text=True).strip()==COMMIT,
        'Exact original VSTest source checkout required')
    raw=context['vstestReplay'];status=A.load(N.ordinary(raw['status']))
    A.require(status.get('completedReplay')is True and status.get('buildSucceeded')is True
        and status.get('unfinishedTasks')==0 and status.get('unfinishedSelectedTasks',0)==0,
        'A complete successful original VSTest build replay is required')
    binlog=N.retain(release,raw['binlog'],'reports/build/vstest.binlog')
    A.require(status.get('inputSha256')==binlog['sha256'],'VSTest replay does not bind its original binary log')
    task_descriptor=N.retain(release,raw['tasks'],'reports/build/vstest-tasks.jsonl')
    mount=raw['sourceMountRoot'];A.require(mount.startswith('/')and mount==posixpath.normpath(mount),
        'Exact VSTest source mount required')
    compiled=compiler_outputs(A.read_tasks(release/task_descriptor['path']),mount,source)
    paths=[N.ordinary(path)for path in context['vstestPackages']]
    A.require(len(paths)==2 and len(set(paths))==2,'Exactly two unchanged original VSTest package outputs are required')
    records,outputs,imports=[],[],[]
    for path in paths:
        metadata=A.nuspec_metadata(path);package_id=metadata.findtext('{*}id');version=metadata.findtext('{*}version')
        A.require(package_id in PACKAGES and version==VERSION,'Genuine VSTest package identity/version differs')
        descriptor=N.retain(release,path,'imported-inputs/'+A.fingerprint(path)['sha256']+'.nupkg')
        records.append(dict(id=package_id,version=version,file=path.name,origin=ORIGIN,sourceCommit=COMMIT,
            retained=descriptor['path'],**{key:descriptor[key]for key in A.FP}))
        with zipfile.ZipFile(path)as archive:
            inventory=A.members(path,'managed-package')
            for member,identity in inventory.items():
                if not member.lower().endswith(('.dll','.exe')):continue
                data=archive.read(member);info=A.MANAGED.inspect(data);commit=A.embedded_component_commit(info)
                A.require(info['cliFlags']&1 and info['managedNativeHeaderBytes']==0,
                    'VSTest source packages must contain unchanged managed IL products')
                if commit!=COMMIT:
                    A.require(commit is not None,'A bundled VSTest dependency has no independently reviewed source identity')
                    imports.append(dict(packagePath=descriptor['path'],member=member,sourceCommit=commit,**identity))
                    continue
                matches=[(task,filename)for task,filename in compiled.get(identity['sha256'],[])
                    if PurePosixPath(filename).name==PurePosixPath(member).name]
                A.require(matches,'VSTest source product lacks an actual successful compiler output: '+member)
                task,filename=matches[0]
                outputs.append(dict(packagePath=descriptor['path'],member=member,sha256=identity['sha256'],sourceRoot='vstest',
                    sourceCommit=COMMIT,context=task,outputPath=filename))
    A.require({row['id']for row in records}==PACKAGES and len(outputs)==301 and len(imports)==6,
        'Complete original Core VSTest package scope requires 301 compiler-bound products and six separately imported members')
    replay=dict(schemaVersion=1,completedReplay=True,buildSucceeded=True,unfinishedTasks=0,inputSha256=status['inputSha256'],
        tasks=task_descriptor,sourceMountRoot=mount,compiledOutputs=outputs,transformations=[])
    descriptor=N.write(release,'reports/build/vstest-replay.json',replay)
    N.write(release,'reports/build/vstest-packages.json',dict(schemaVersion=1,kind=ORIGIN,sdkVersion='7.0.120',
        sourceCommit=COMMIT,version=VERSION,packages=records,importedMembers=imports))
    return dict(replay=descriptor,builtPackages=records,ownManagedMembers=len(outputs),importedManagedMembers=imports)
