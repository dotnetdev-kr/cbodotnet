"""Bind the genuine local App5 product to actual SDK restore/compiler/layout bytes.

The strengthened source validator is always called. A normal execution envelope
and complete source-packet admission remain separate required gates. This module
does not execute a compiler, change package versions, or rewrite raw E5 unknowns.
"""
import base64
from collections import Counter
import json
from pathlib import Path,PurePosixPath
import re
import tarfile
import zipfile

import musl_legacy5_appinsights_validator as STRONG
import musl_legacy5_component_evidence as CE
import musl_legacy5_construction_inputs as CONSTRUCTION

B=CE.B
require,portable=B.require,B.portable
ID='Microsoft.ApplicationInsights'
VERSION='2.0.0-cbodotnet.1'
PROPERTY='/p:MicrosoftApplicationInsightsPackageVersion='+VERSION
MEMBER='lib/dotnet5.4/Microsoft.ApplicationInsights.dll'
LAYOUT='sdk/'+CE.SDK+'/Microsoft.ApplicationInsights.dll'
SOURCE_COMMIT='9b5b49f2a7697a2bf38f09ca2f2c97326c49d93b'
PACKAGE='microsoft.applicationinsights.'+VERSION+'.nupkg'


def controlled_version_property(command):
    """All property aliases/compound assignments share one controlled slot."""
    target='microsoftapplicationinsightspackageversion';assignments=[]
    for arg in command:
        require(isinstance(arg,str),'Original SDK5 process arguments must be strings')
        require(not arg.startswith('@'),'Explicit SDK5 App process response-file overrides are forbidden')
        match=re.fullmatch(r'(?:/|-{1,2})(?:p|property):(.*)',arg,re.I)
        if match:
            for item in match[1].split(';'):
                if '=' not in item:continue
                key,value=item.split('=',1)
                if key.strip().lower()==target:assignments.append((arg,value))
        # Reject other/ambiguous switches mentioning the controlled slot too,
        # including restore-only or separated-argument variants.
        if target in arg.lower():require(arg==PROPERTY,'Alternate or compound SDK5 App version override is forbidden')
    require(assignments==[(PROPERTY,VERSION)],'One exact controlled App version property in each original SDK5 process required')


def distinct_consumer_replays(entries):
    require([row['name'] for row in entries]==['sdk','redist'],'Both separate original SDK5 App consumer replays required')
    identities={}
    for field in ('status','tasks','binlog'):
        descriptors=[row[field] for row in entries]
        require(all(set(row)=={'path',*CE.FP} and type(row['bytes']) is int and row['bytes']>0 for row in descriptors),
                'Complete original SDK5 consumer replay descriptors required')
        values=[tuple(row[key] for key in CE.FP) for row in descriptors]
        require(len(set(values))==2 and len({row['path'] for row in descriptors})==2,
                'Distinct original SDK5 status/tasks/binlog content identities required across sdk/redist: '+field)
        identities[field]=values
    return identities


def csc_reference_binding(task,expected,*,required=False):
    """Bind executed reference argv and task values, including absent-param cases."""
    argv=CE.commands(task);references=[];reference_arguments=[];unsupported=[];possible_app=[]
    app=lambda name:PurePosixPath(name).name.lower()=='microsoft.applicationinsights.dll'
    for arg in argv[3:]:
        match=re.fullmatch(r'[-/](?:reference|r):(.*)',arg,re.I)
        if match:
            value=match[1]
            if not value or any(c in value for c in ('=',',',';')):unsupported.append(arg)
            possible_app.extend(v.split('=',1)[-1] for v in re.split('[,;]',value) if app(v.split('=',1)[-1]))
            references.append(value);reference_arguments.append(arg)
        else:
            if arg.lower() in ('/r','-r','/reference','-reference') or arg.lower().startswith(('/link:','-link:')):
                unsupported.append(arg)
                if ':' in arg:possible_app.extend(v.split('=',1)[-1] for v in re.split('[,;]',arg.split(':',1)[1]) if app(v.split('=',1)[-1]))
    task_references=B.task_values(task,'References')
    task_app={name for name in task_references if app(name)};command_app=[name for name in references if app(name)]
    if not required and not task_app and not command_app and not possible_app:return None
    require(not unsupported,'Unsupported SDK5 Csc reference alias/list/link form is forbidden')
    require(not any(arg.startswith('@') for arg in argv[3:]) and argv[3:].count('/noconfig')==1,
            'Actual SDK5 App Csc references may not come from hidden response/configuration files')
    require(Counter(references)==Counter(task_references),
            'Actual SDK5 Csc reference arguments must equal their original References task values and multiplicities')
    require(task_app=={expected} and command_app==[expected],
            'Actual SDK5 Csc command and task must consume the same exact genuine App cache member')
    return dict(commandReferenceArguments=reference_arguments,appReference=expected)


def tooling_packages():
    return {**{name:'5.9.1-rc.8' for name in CE.NUGET_PACKAGES},
        **{name.lower():'16.9.4-dev' for name in CE.VSTEST_PACKAGES},
        'microsoft.codeanalysis.visualbasic.codestyle':'3.8.0-5.20519.18',
        'microsoft.fsharp.compiler':'11.3.2-beta.21102.9','microsoft.net.compilers.toolset':'3.9.0-6.21273.1',
        ID.lower():VERSION}


def validate_tooling(tooling,package):
    require(tooling.get('kind')=='legacy-musl-sdk5-source-tooling' and tooling.get('status')=='passed'
            and tooling.get('sdkVersion')==CE.SDK,'Actual successful SDK5 tooling process required')
    rows=tooling['packages'];expected=tooling_packages()
    require(len(rows)==len(expected)==25 and {row['id'].lower():row['version'] for row in rows}==expected,
            'The closed25-package SDK5 feed including the genuine local App version is required')
    app=next(row for row in rows if row['id'].lower()==ID.lower())
    require(all(app[key]==package[key] for key in CE.FP),'SDK5 feed App package must equal the actual genuine source-built NPK')
    names={'original-product-restore','original-product-build','original-redist-build-pack'}
    commands=[row for row in tooling['commands'] if row['name'] in names]
    require(len(commands)==3 and {row['name'] for row in commands}==names,'All three original SDK5 product/restore/layout processes required')
    for row in commands:
        require(row['exitCode']==0,'Every original SDK5 App consumer process must succeed')
        controlled_version_property(row['command'])
    return app


def validate_cache(source,feed,package,product):
    source=Path(source);feed=Path(feed)
    cache=source/'.packages'/ID.lower()/VERSION
    raw=CE.ordinary(cache/PACKAGE);extracted=CE.ordinary(cache/MEMBER)
    require(CE.fingerprint(raw)=={key:package[key] for key in CE.FP}
            and CE.fingerprint(extracted)==product,'Actual SDK5 App restore cache must consume the genuine package/member bytes')
    require(CE.fingerprint(CE.ordinary(feed/PACKAGE))=={key:package[key] for key in CE.FP},'Actual SDK5 local feed App package differs')
    metadata=json.loads(CE.ordinary(cache/'.nupkg.metadata').read_bytes())
    content=base64.b64encode(bytes.fromhex(package['sha512'])).decode()
    require(metadata.get('source')=='/work/inputs/bootstrap-feed' and metadata.get('contentHash')==content
            and CE.ordinary(cache/(PACKAGE+'.sha512')).read_text().strip()==content,
            'Real SDK5 NuGet local-feed/cache content hash must remain unchanged')
    return dict(cachePackage=CE.fingerprint(raw),cacheMember=CE.fingerprint(extracted),originalNugetMetadata=metadata)


def validate_toolset_member(release,proof,product):
    row=proof['artifacts']['toolset']
    require(row.get('kind')=='sdk-toolset' and row.get('sourceRoot')=='sdk' and row.get('sourceCommit')==CE.COMMITS['sdk'],
            'The named actual SDK5 compiler toolset role is required')
    path=B.checked(Path(release),{key:row[key] for key in ('path',*CE.FP)})
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist().count('Microsoft.ApplicationInsights.dll')==1,
                'One actual SDK5 toolset App product required')
        raw=archive.read('Microsoft.ApplicationInsights.dll')
    require(STRONG.original_worker().fingerprint(raw)==product,
            'The actual SDK5 toolset must contain the genuine locally compiled App product')
    return {key:row[key] for key in ('path',*CE.FP)}


def validate_sdk_tasks(release,source,compiler,product):
    distinct_consumer_replays(compiler['proof']['replays'])
    mount='/work/work/sdk';source=Path(source);app=mount+'/.packages/'+ID.lower()+'/'+VERSION+'/'+MEMBER
    name='Microsoft.ApplicationInsights.dll';cli=mount+'/src/Cli/dotnet/dotnet.csproj';redist=mount+'/src/Layout/redist/redist.csproj'
    bootstrap=mount+'/.dotnet/sdk/5.0.401/';artifact=mount+'/artifacts/bin/'
    edges={(cli,bootstrap+'Microsoft.Common.CurrentVersion.targets',app,artifact+'dotnet/Release/net5.0/'+name),
        (redist,bootstrap+'Microsoft.Common.CurrentVersion.targets',app,artifact+'redist/Release/net5.0/'+name),
        (redist,mount+'/src/Layout/redist/targets/GenerateLayout.targets',artifact+'redist/Release/net5.0/'+name,
            artifact+'redist/Release/layouts/dotnet-toolset-internal/'+name),
        (redist,mount+'/src/Layout/redist/targets/OverlaySdkOnLKG.targets',artifact+'redist/Release/net5.0/'+name,
            artifact+'redist/Release/dotnet//sdk/'+CE.SDK+'-ci/'+name)}
    observed=[]
    for replay in compiler['proof']['replays']:
        tasks=B.read_tasks(B.checked(Path(release),replay['tasks']))
        executed={row['context'] for row in CE.compiler_rows(tasks,mount,replay['name'],'sdk')}
        references=[];copies=[];projects=set();found=set()
        for task in tasks.values():
            if not task.get('succeeded'):continue
            if task['taskName']=='Csc' and task['context'] in executed:
                binding=csc_reference_binding(task,app,required=task['projectFile'] in (cli,redist))
                if binding is None:continue
                require(task['projectFile'] in (cli,redist),'Actual SDK5 App Csc must belong to its original CLI/redist consumer projects')
                projects.add(task['projectFile']);references.append(task['context'])
            if task['taskName']!='Copy':continue
            sources={v for v in B.task_values(task,'SourceFiles') if v.endswith('/'+name)}
            destinations={v for v in B.task_values(task,'DestinationFiles') if v.endswith('/'+name)}
            if not sources and not destinations:continue
            require(len(sources)==len(destinations)==1,'One exact SDK5 App file per original Copy edge required')
            edge=(task['projectFile'],task['taskFile'],next(iter(sources)),next(iter(destinations)))
            require(edge in edges and edge not in found,'All and only the four original SDK5 App Copy edges required per process')
            for value in edge[-2:]:
                local=CE.ordinary(source/PurePosixPath(value).relative_to(mount))
                require(CE.fingerprint(local)==product,'Actual SDK5 App Copy source/destination bytes differ from genuine compiler output')
            found.add(edge);copies.append(dict(context=task['context'],source=edge[-2],destination=edge[-1]))
        require(projects=={cli,redist} and found==edges,'Both original SDK5 processes must consume App in Csc and all four Copy edges')
        observed.append(dict(replayName=replay['name'],actualCscContexts=references,actualCopies=copies))
    require([row['replayName'] for row in observed]==['sdk','redist'],'Both separate original SDK5 App consumer replays required')
    return observed


def supplier_application(workspace,host_roots,*,normal_context=None):
    """Select only an explicit authenticated normal supplier or the old private entry."""
    if normal_context is None:
        return STRONG.validate(workspace,host_roots)
    import musl_legacy5_appinsights_normal as NORMAL
    application=NORMAL.validate(workspace,host_roots,normal_context=normal_context)
    require(application.get('kind')=='strong-normal-genuine-App5-execution-api-package-validation'
            and application.get('normalAppWorkerBoundaryValidated')is True
            and application['execution']['boundary']['parentSdkBuildValidated']is True,
            'Actual normal App supplier and successful parent SDK build boundary required')
    return application


def validate(release,record,proof,roots,tooling,*,app_workspace,app_host_roots,sdk_source,feed,normal_context=None):
    # The constructor's older verify_execution entry cannot substitute for this.
    application=supplier_application(app_workspace,app_host_roots,normal_context=normal_context)
    package=application['package'];product=application['members'][MEMBER];release=Path(release)
    final=CONSTRUCTION.validate_final_sdk_archive(record,proof)
    B.checked(release,final)
    toolset=validate_toolset_member(release,proof,product)
    artifact=proof['artifacts'].get('package-'+package['sha256'])
    require(artifact is not None and artifact.get('kind')=='managed-package' and artifact.get('sourceCommit')==SOURCE_COMMIT
            and artifact.get('sourceRoot') in roots and roots[artifact['sourceRoot']].get('commit')==SOURCE_COMMIT
            and all(artifact[key]==package[key] for key in CE.FP),'Actual genuine App supplier package/source role required')
    require(artifact['path']=='imported-inputs/'+package['sha256']+'.nupkg','Canonical retained genuine App supplier package path required')
    B.checked(release,{key:artifact[key] for key in ('path',*CE.FP)})
    compiler=CE.validate(release,proof['componentCompilerProofs']['sdk'],roots)
    require(len(compiler['proof']['packages'])==1 and all(compiler['proof']['packages'][0][key]==toolset[key] for key in CE.FP),
            'App must be in the actual SDK5 compiler-produced toolset package')
    validate_tooling(tooling,package);cache=validate_cache(sdk_source,feed,package,product)
    tasks=validate_sdk_tasks(release,sdk_source,compiler,product)
    installer=json.loads(B.checked(release,proof['installerBuildReplay']).read_bytes())
    transformations=[row for row in installer['transformations'] if row['archivePath']==LAYOUT]
    require(len(transformations)<=1,'One final original SDK5 App Crossgen transformation at most')
    final_product=None
    with tarfile.open(B.checked(release,final),'r|gz') as archive:
        for entry in archive:
            if entry.name.removeprefix('./')!=LAYOUT:continue
            require(entry.isfile() and final_product is None,'One ordinary final SDK5 App product required')
            final_product=STRONG.original_worker().fingerprint(archive.extractfile(entry).read())
    require(final_product is not None,'Actual final SDK5 App member required')
    if transformations:
        row=transformations[0]
        require(row['input']=='toolset' and row['member']=='Microsoft.ApplicationInsights.dll'
                and row['inputSha256']==product['sha256'] and row['outputSha256']==final_product['sha256'],
                'Actual final SDK5 App must bind its genuine pre-Crossgen bytes')
        replay=installer['replay'];selected=B.read_tasks(B.checked(release,replay['tasks']))
        crossgen=CE.validate_crossgen_task(row,replay,selected,installer['sourceCrossgenRecord'])
    else:
        require(final_product==product,'Final SDK5 App bytes changed without their original Crossgen task');crossgen=None
    return dict(kind='sdk5-genuine-local-App-actual-sdk-consumption',sourceValidation=application,
        package=package,product=product,cache=cache,toolset=toolset,sdkConsumers=tasks,finalProduct=final_product,crossgen=crossgen,
        sourceDisposition=dict(path=LAYOUT,sourceRoot=artifact['sourceRoot'],sourceCommit=SOURCE_COMMIT,
            fingerprint=product,allowedPackageMembers=[dict(packageSha256=package['sha256'],member=MEMBER)],
            sourceBasis='genuine-local-App5-original-source-build-and-actual-sdk-consumption'),
        wholeProducerSourceClosure=False,normalSourceWorkerEnvelopeValidatedByThisPart=normal_context is not None,
        referenceInputPreferredSourceAndLicenseClosureValidatedByThisPart=False,
        remainingWholeSourceGates=['original Profile7 ZIP65PE/baseXML preferred-source and license roles',
            'original Mono4 target/license build-input source roles',
            *([]if normal_context is not None else['normal App source-worker envelope']),
            'complete combined source packet and every other producer/consumer guard'],
        qualificationAllowed=False,sourceAdmissionAllowed=False)
