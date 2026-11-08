#!/usr/bin/env python3
"""Native bounded SDK6 tooling graph, without release admission.

This deliberately does not invoke the glibc legacy source-build wrappers. The
regular SDK redist graph rebuilds CLI/MSBuild tooling and attributes its NuGet
inputs; downstream installer/runtime delivery remains separately unqualified.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('legacy_musl_diagnostics', ROOT/'scripts/musl-legacy-assess.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
PINS = {'6.0.136': dict(sdk='1d205826ddc14c8f868eb6373e7a6bafcb9fe5be', bootstrap='6.0.135')}

TRANSLATION_HOOK='''  <Target Name="CopyCommunityMuslNuGetTranslationData"
          AfterTargets="PublishTestCli"
          Condition="'$(CommunityMuslNuGetTranslationRoot)' != ''">
    <ItemGroup>
      <_CommunityMuslNuGetTranslation Include="$(CommunityMuslNuGetTranslationRoot)/**/*.resources.dll" />
    </ItemGroup>
    <Error Condition="'@(_CommunityMuslNuGetTranslation)' == ''"
           Text="The exact reviewed imported NuGet translation data is absent" />
    <Copy SourceFiles="@(_CommunityMuslNuGetTranslation)"
          DestinationFiles="@(_CommunityMuslNuGetTranslation->'$(OutputPath)/%(RecursiveDir)%(Filename)%(Extension)')"
          SkipUnchangedFiles="false" />
  </Target>

'''

LINUX_HOST_TASKS_HOOK='''    <ItemGroup Condition="'$(OSName)' == 'linux-musl'">
      <NETSdksContent Remove="$(NETSdkSourceRoot)\\tools\\net472\\**" />
      <NETSdksContent Remove="$(NETSdkRazorSourceRoot)\\tasks\\net472\\**" />
    </ItemGroup>
'''


def source_command(workspace, *arguments):
    source=workspace/'sdk'
    return subprocess.check_output(['git','-c','safe.directory='+str(source),'-C',str(source),*arguments],text=True).strip()


def prepare_test_hook(workspace, pin, report):
    source=workspace/'sdk'
    hook=source/'eng/restore-toolset.sh'
    upstream=source_command(workspace,'show',pin['sdk']+':eng/restore-toolset.sh')+'\n'
    original=hook.read_text()
    marker='  # The following frameworks and tools are used only for testing.\n'
    replacement=('  # Diagnostic redist builds do not execute these historical test frameworks.\n'
                 '  if [[ ${CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS:-} == true ]]; then\n'
                 '    return\n'
                 '  fi\n\n'+marker)
    M.require(marker in upstream,'Pinned test-only runtime bootstrap hook changed')
    adjusted=upstream.replace(marker,replacement,1)
    M.require(original in {upstream,adjusted},'Unexpected source bootstrap hook modification')
    if original==upstream:
        hook.write_text(adjusted)
    M.write(report/'test-runtime-hook.json',dict(path='eng/restore-toolset.sh',sourceCommit=pin['sdk'],
        originalSha256=hashlib.sha256(upstream.encode()).hexdigest(),
        adjustedSha256=M.digest(hook)['sha256'],environment='CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS=true',
        purpose='Skip only legacy test-runtime downloads during the regular product redist build; no framework/RID/package substitution'))


def prepare(args):
    workspace = args.workspace
    workspace.mkdir(parents=True,exist_ok=False)
    pin=PINS[args.sdk]
    series='.'.join(args.sdk.split('.')[:2])
    metadata=workspace/'release-metadata.json'
    metadata_record=M.fetch(f'https://builds.dotnet.microsoft.com/dotnet/release-metadata/{series}/releases.json',metadata,4*1024**2)
    document=json.loads(metadata.read_text())
    rid='linux-musl-'+args.arch
    rows=[item for release in document['releases'] for sdk in release.get('sdks',[release.get('sdk',{})])
          if sdk.get('version')==pin['bootstrap'] for item in sdk.get('files',[]) if item.get('rid')==rid]
    rows=list({row['url']:row for row in rows}.values())
    M.require(len(rows)==1,'One matching official musl bootstrap required')
    if args.bootstrap_archive:
        archive=args.bootstrap_archive
        M.require(archive.is_file() and not archive.is_symlink() and M.digest(archive)['sha512'].lower()==rows[0]['hash'].lower(),
                  'Retained official musl bootstrap hash differs')
        shutil.copyfile(archive,workspace/'bootstrap-sdk.tar.gz')
    bootstrap=M.fetch(rows[0]['url'],workspace/'bootstrap-sdk.tar.gz',512*1024**2,rows[0]['hash'])
    source=workspace/'sdk'
    source.mkdir()
    for command in [['git','init',str(source)],['git','-C',str(source),'remote','add','origin','https://github.com/dotnet/sdk'],
                    ['git','-C',str(source),'fetch','--depth','1','origin',pin['sdk']],
                    ['git','-C',str(source),'checkout','--detach','FETCH_HEAD']]:
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
    M.require(source_command(workspace,'rev-parse','HEAD')==pin['sdk'],'SDK source pin differs')
    dotnet=source/'.dotnet'
    dotnet.mkdir()
    subprocess.run(['tar','-xzf',str(workspace/'bootstrap-sdk.tar.gz'),'-C',str(dotnet)],check=True)
    (workspace/'evidence').mkdir()
    M.write(workspace/'prepared.json',dict(schemaVersion=1,kind='legacy-musl-sdk-tooling-experiment',sdkVersion=args.sdk,
        source=dict(repository='https://github.com/dotnet/sdk',commit=pin['sdk']),bootstrap=bootstrap,
        metadata=metadata_record,rid=rid,qualificationAllowed=False,sourceAdmissionAllowed=False,
        productSdkProduced=False,preparedAt=datetime.now(timezone.utc).isoformat()))
    if os.getuid()==0:
        subprocess.run(['chown','-R','1000:1000',str(workspace)],check=True)
    print(json.dumps(dict(status='prepared',workspace=str(workspace),bootstrap=pin['bootstrap'],rid=rid)),flush=True)


def build(args):
    M.require(args.sdk=='6.0.136' and args.component_source_build and
              getattr(args,'msbuild_localization_version',None)=='17.0.4-cbodotnet.1' and
              getattr(args,'vstest_source_version',None)=='17.0.3-dev' and
              not getattr(args,'scope_linux_host_tasks',False),
              'SDK6 requires its complete original graph and genuine source component versions')
    workspace=args.workspace
    prepared=json.loads((workspace/'prepared.json').read_text())
    pin=PINS[args.sdk]
    M.require(not (getattr(args,'scope_linux_host_tasks',False) or getattr(args,'vstest_source_version',None))
              or args.sdk=='6.0.136','The reviewed source-package/host-task adaptations are specific to SDK6')
    rid='linux-musl-'+args.arch
    M.require(prepared['sdkVersion']==args.sdk and prepared['rid']==rid and
        source_command(workspace,'rev-parse','HEAD')==pin['sdk'],'Prepared input identity differs')
    M.require(re.fullmatch(r'[a-f0-9]{64}',args.image or ''),'Immutable native image required')
    M.require(re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',args.attempt),'Bounded attempt name required')
    report=workspace/'evidence'/args.attempt
    report.mkdir()
    prepare_test_hook(workspace,pin,report)
    if args.vstest_tfm or getattr(args,'nuget_resources',None) or getattr(args,'scope_linux_host_tasks',False):
        target=workspace/'sdk/src/Layout/redist/targets/GenerateLayout.targets'
        original=source_command(workspace,'show',pin['sdk']+':src/Layout/redist/targets/GenerateLayout.targets')+'\n'
        marker='      <TestCliNuGetDirectory>$(NuGetPackageRoot)'
        addition=('      <TestCliNuGetDirectoryTargetFramework Condition="\'$(CommunityMuslTestCliFramework)\' != \'\'">'
                  '$(CommunityMuslTestCliFramework)</TestCliNuGetDirectoryTargetFramework>\n')
        adjusted=original.replace(marker,addition+marker,1) if args.vstest_tfm else original
        current=target.read_text()
        if TRANSLATION_HOOK in current:
            M.require(getattr(args,'nuget_resources',None) is not None and current.count(TRANSLATION_HOOK)==1,
                      'An existing explicit translation source hook requires its original reviewed input')
            current=current.replace(TRANSLATION_HOOK,'',1)
        if LINUX_HOST_TASKS_HOOK in current:
            M.require(getattr(args,'scope_linux_host_tasks',False) and current.count(LINUX_HOST_TASKS_HOOK)==1,
                      'An existing Linux CLI host-task scope requires its explicit reviewed build option')
            current=current.replace(LINUX_HOST_TASKS_HOOK,'',1)
        M.require(current in {original,adjusted},'Pinned SDK layout source changed')
        target.write_text(adjusted)
        import difflib
        patch=''.join(difflib.unified_diff(original.splitlines(True),adjusted.splitlines(True),
                  fromfile='a/src/Layout/redist/targets/GenerateLayout.targets',tofile='b/src/Layout/redist/targets/GenerateLayout.targets'))
        (report/'vstest-layout.patch').write_text(patch)
        M.write(report/'vstest-layout.json',dict(sourceCommit=pin['sdk'],framework=args.vstest_tfm,
            reason='Use the explicitly declared package target directory when supplied; otherwise preserve the original source-build directory',
            patch=M.digest(report/'vstest-layout.patch')))
        if getattr(args,'nuget_resources',None):
            M.require(args.sdk=='6.0.136' and args.nuget_resources.is_absolute() and args.nuget_resources.is_dir() and
                      not args.nuget_resources.is_symlink(),'Exact reviewed SDK6 translation-data root required')
            origin=json.loads((args.nuget_resources/'origin.json').read_text())
            M.require(origin.get('kind')=='imported-official-nuget-translation-data' and len(origin.get('files',[]))==286 and
                      origin.get('sourceCommit')=='451e9bc27184dc49d04e975122c9e7189d525872','Reviewed original translation input identity differs')
            text=target.read_text();M.require(text.endswith('</Project>\n'),'Pinned SDK layout target ending changed')
            revised=text[:-len('</Project>\n')]+TRANSLATION_HOOK+'</Project>\n';target.write_text(revised)
            patch=''.join(difflib.unified_diff(text.splitlines(True),revised.splitlines(True),
                fromfile='a/src/Layout/redist/targets/GenerateLayout.targets',tofile='b/src/Layout/redist/targets/GenerateLayout.targets'))
            (report/'nuget-translation-data.patch').write_text(patch)
            M.write(report/'nuget-translation-data.json',dict(sourceCommit=pin['sdk'],translationSourceCommit=origin['sourceCommit'],
                origin=M.digest(args.nuget_resources/'origin.json'),patch=M.digest(report/'nuget-translation-data.patch'),
                purpose='Import only exact reviewed resource-only translation data; no primary NuGet assembly or native input is copied'))
        if getattr(args,'scope_linux_host_tasks',False):
            M.require(args.sdk=='6.0.136','Only the reviewed exact SDK6 Linux CLI host-task scope is available')
            text=target.read_text();marker='    <Copy SourceFiles="@(NETSdksContent)"\n'
            M.require(text.count(marker)==1,'Pinned SDK host-task copy boundary changed')
            revised=text.replace(marker,LINUX_HOST_TASKS_HOOK+marker,1);target.write_text(revised)
            patch=''.join(difflib.unified_diff(text.splitlines(True),revised.splitlines(True),
                fromfile='a/src/Layout/redist/targets/GenerateLayout.targets',tofile='b/src/Layout/redist/targets/GenerateLayout.targets'))
            (report/'linux-host-task-scope.patch').write_text(patch)
            M.write(report/'linux-host-task-scope.json',dict(sourceCommit=pin['sdk'],osName='linux-musl',
                removedLayoutPrefixes=['Sdks/Microsoft.NET.Sdk/tools/net472/','Sdks/Microsoft.NET.Sdk.Razor/tasks/net472/'],
                preserved=['all target reference assemblies','Build.Extensions/net46*/lib','all reference packs','TestHostNetFramework'],
                reason='The Linux CLI uses the original Core MSBuild task selection; Full/Mono MSBuild host task execution is outside this product layout',
                patch=M.digest(report/'linux-host-task-scope.patch')))
    inspect=json.loads(subprocess.check_output(M.ENGINE+['image','inspect',args.image],text=True))
    M.require(len(inspect)==1 and inspect[0]['Architecture']=={'x64':'amd64','arm64':'arm64'}[args.arch],
              'Builder image CPU differs')
    M.write(report/'image.json',inspect)
    name='cbodotnet-musl-tooling-'+args.sdk.replace('.','-')+'-'+args.arch+'-'+args.attempt
    from_source='true' if args.component_source_build else 'false'
    project='/source/source-build.slnf' if args.component_source_build else '/source/src/Layout/redist/redist.csproj'
    inner=['./build.sh','--configuration','Release','--pack','--projects',project,
           '/p:ArcadeBuildFromSource=false','/p:DotNetBuildFromSource='+from_source,'/p:Architecture='+args.arch,
           '/p:OSName=linux-musl','/p:Rid='+rid,'/p:PortableBuild=true','/p:CrossBuild=false',
           '/p:ContinuousIntegrationBuild=true','/p:UseSharedCompilation=false','/p:EmitCompilerGeneratedFiles=true','/m:2',
           '/bl:/source/artifacts/log/Release/community-sdk-'+args.attempt+'.binlog']
    if getattr(args,'rebuild',False):inner+=['--rebuild']
    if args.vstest_tfm:
        inner+=['/p:CommunityMuslTestCliFramework='+args.vstest_tfm]
    if getattr(args,'nuget_resources',None):
        inner+=['/p:CommunityMuslNuGetTranslationRoot=/nuget-translation-data/resources']
    if getattr(args,'vstest_source_version',None):
        version=args.vstest_source_version
        M.require(args.sdk=='6.0.136' and version=='17.0.3-dev' and args.component_source_build and args.nuget_feed,
                  'Only the exact SDK6 source-built VSTest candidate version is available')
        inner+=['/p:MicrosoftNETTestSdkPackageVersion='+version,
                '/p:MicrosoftTestPlatformCLIPackageVersion='+version,
                '/p:MicrosoftTestPlatformBuildPackageVersion='+version]
        M.write(report/'vstest-source-package-version.json',dict(sourceCommit='cc7fb0593127e24f55ce016fb3ac85b5b2857fec',
            actualSourceDefaultVersion=version,vendorVersionRelabeled=False,
            packages=[dict(path=name,**M.digest(args.nuget_feed/name)) for name in
                ['Microsoft.TestPlatform.CLI.'+version+'.nupkg','Microsoft.TestPlatform.Build.'+version+'.nupkg']],
            interpretation='Explicit actual source-package version; compilation, source and consumption evidence require independent validation',
            qualificationAllowed=False))
    if getattr(args,'msbuild_localization_version',None):
        version=args.msbuild_localization_version
        M.require(args.sdk=='6.0.136' and version=='17.0.4-cbodotnet.1' and args.component_source_build and args.nuget_feed,
                  'Only the genuine exact-source MSBuild6 localization package is available')
        inner+=['/p:MicrosoftBuildLocalizationPackageVersion='+version]
        M.write(report/'msbuild-localization-source-version.json',dict(sourceCommit='85d71072f8fa22cc761d6b65954da263364bee4d',
            genuineDownstreamPackageVersion=version,vendorVersionReconstructed=False,
            package=dict(path='Microsoft.Build.Localization.'+version+'.nupkg',**M.digest(args.nuget_feed/('Microsoft.Build.Localization.'+version+'.nupkg'))),
            interpretation='Original product source/TFMs, explicit downstream source package; independent actual compiler and resource validation required',
            qualificationAllowed=False))
    uid,gid=(1000,1000) if os.getuid()==0 else (os.getuid(),os.getgid())
    command=M.ENGINE+['run','--rm','--name',name,'--network=host','--user',str(uid)+':'+str(gid),
        '--cap-drop=all','--security-opt=no-new-privileges','--workdir','/source',
        '--env','HOME=/tmp','--env','DOTNET_ROOT=/source/.dotnet','--env','DOTNET_INSTALL_DIR=/source/.dotnet',
        '--env','DOTNET_MULTILEVEL_LOOKUP=0','--env','DOTNET_CLI_TELEMETRY_OPTOUT=1','--env','DOTNET_NOLOGO=1',
        '--env','NUGET_PACKAGES=/source/'+args.package_cache,
        '--env','CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS=true',
        '--env','DOTNET_PROCESSOR_COUNT=2','--volume',str(workspace/'sdk')+':/source']
    if args.nuget_feed:
        M.require(args.nuget_feed.is_absolute() and args.nuget_feed.is_dir() and not args.nuget_feed.is_symlink(),
                  'An ordinary absolute source-built NuGet feed is required')
        command+=['--volume',str(args.nuget_feed)+':/bootstrap-feed:ro']
        inner+=['/p:RestoreAdditionalProjectSources=/bootstrap-feed']
    if getattr(args,'nuget_resources',None):
        command+=['--volume',str(args.nuget_resources)+':/nuget-translation-data:ro']
    command+=[args.image]+inner
    if getattr(args,'wrap_command',None):
        command=args.wrap_command(command)
    M.write(report/'invocation.json',dict(command=command,qualificationAllowed=False,sourceAdmissionAllowed=False,
        diagnosticEngine=getattr(args,'engine_label','rootful-podman'),cpu=platform.machine(),network='host',timeoutSeconds=args.seconds,
        interpretation='Rebuild regular SDK tooling from exact source; imported runtime/compiler/NuGet components remain attributed inputs'))
    started=datetime.now(timezone.utc).isoformat()
    code=None
    timed_out=False
    with (report/'build.log').open('xb') as stream:
        try:
            # The upstream redist publishes these tools through custom MSBuild
            # calls rather than ProjectReference, so a targeted redist restore
            # must restore their original project graphs explicitly first.
            prefix=command[:command.index(args.image)+1]
            code=0
            for name in ['src/BlazorWasmSdk/Tool/Microsoft.NET.Sdk.BlazorWebAssembly.Tool.csproj',
                         'src/RazorSdk/Tool/Microsoft.NET.Sdk.Razor.Tool.csproj',
                         'src/WebSdk/ProjectSystem/Tasks/Microsoft.NET.Sdk.Web.ProjectSystem.Tasks.csproj',
                         'src/WebSdk/Publish/Tasks/Microsoft.NET.Sdk.Publish.Tasks.csproj',
                         'src/WebSdk/Web/Tasks/Microsoft.NET.Sdk.Web.Tasks.csproj',
                         'src/WebSdk/Worker/Tasks/Microsoft.NET.Sdk.Worker.Tasks.csproj',
                         'src/Layout/tool_fsharp/tool_fsc.csproj',
                         'src/Layout/tool_fsharp/tool_fsi.csproj']:
                if args.component_source_build:
                    break
                if not (workspace/'sdk'/name).is_file():
                    continue
                restore=prefix+['/source/.dotnet/dotnet','restore','/source/'+name,
                    '/p:Configuration=Release','/p:DotNetBuildFromSource='+from_source]
                if args.nuget_feed:
                    restore+=['/p:RestoreAdditionalProjectSources=/bootstrap-feed']
                stream.write((json.dumps(restore)+'\n').encode());stream.flush()
                code=subprocess.run(restore,stdout=stream,stderr=subprocess.STDOUT,timeout=180).returncode
                if code:
                    break
            if code==0:
                code=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=args.seconds).returncode
        except subprocess.TimeoutExpired:
            timed_out=True
            subprocess.run(M.ENGINE+['stop','--time','5',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    M.write(report/'result.json',dict(startedAt=started,finishedAt=datetime.now(timezone.utc).isoformat(),
        exitCode=code,timedOut=timed_out,qualificationAllowed=False,sourceAdmissionAllowed=False,
        productSdkProduced=False,log=M.digest(report/'build.log')))
    print(json.dumps(dict(exitCode=code,timedOut=timed_out,report=str(report))),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','build'])
    parser.add_argument('--sdk',choices=list(PINS),required=True)
    parser.add_argument('--arch',choices=['arm64','x64'],required=True)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--image')
    parser.add_argument('--attempt',default='attempt1')
    parser.add_argument('--seconds',type=int,default=300)
    parser.add_argument('--bootstrap-archive',type=Path,help='Reuse a retained official bootstrap only after metadata SHA-512 verification')
    parser.add_argument('--component-source-build',action='store_true',help='Use SDK-component source-build semantics without the full source-build wrapper; UI/workload differences require review')
    parser.add_argument('--nuget-feed',type=Path,help='Retained local source-built input packages with recorded actual identities')
    parser.add_argument('--package-cache',default='.packages',help='Fresh source-local cache name when bootstrap input bytes change')
    parser.add_argument('--vstest-tfm',help='Actual target directory of the exact imported VSTest CLI package')
    parser.add_argument('--scope-linux-host-tasks',action='store_true',help='Apply the exact reviewed SDK6 Linux CLI host-task layout scope')
    parser.add_argument('--vstest-source-version',choices=['17.0.3-dev'],help='Consume the actual SDK6 VSTest source-build package version without vendor relabeling')
    parser.add_argument('--msbuild-localization-version',choices=['17.0.4-cbodotnet.1'])
    parser.add_argument('--nuget-resources',type=Path,help='Exact reviewed NuGet6 resource-only translation-data input')
    parser.add_argument('--rebuild',action='store_true',help='Run original graph Rebuild to retain every fresh compiler event in this binary log')
    args=parser.parse_args()
    M.require(os.getuid()==0 and platform.system()=='Linux' and
        platform.machine()=={'arm64':'aarch64','x64':'x86_64'}[args.arch], 'Matching native rootful diagnostic host required')
    M.require(args.workspace.is_absolute() and args.workspace!=Path('/') and
        not any(p.is_symlink() for p in [args.workspace,*args.workspace.parents]),'Ordinary absolute workspace required')
    M.require(30<=args.seconds<=900,'Bounded build duration required')
    M.require(re.fullmatch(r'\.packages(?:-[a-z0-9]+)*',args.package_cache),'Bounded local package cache name required')
    M.require(args.vstest_tfm is None or re.fullmatch(r'net(?:coreapp)?[0-9]+\.[0-9]+',args.vstest_tfm),
              'Explicit VSTest package framework required')
    (prepare if args.action=='prepare' else build)(args)


if __name__=='__main__':
    main()
