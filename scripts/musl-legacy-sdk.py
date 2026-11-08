#!/usr/bin/env python3
"""Native legacy musl SDK candidate producer; no signing, publishing or admission.

The regular SDK source-build solution filter rebuilds CLI, SDK tasks, resolvers,
templates and redist. The installer consumes that local ZIP, explicitly imported
matching musl frameworks and independently rebuilt version-specific native
components. Diagnostic Podman results can never qualify a public release.
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
import sys
import tarfile
from types import SimpleNamespace
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


P=module('legacy_secure_musl_primitives','musl-sdk.py')
T=module('legacy_source_tooling','musl-legacy-tooling.py')
require=P.require
fingerprint=P.fingerprint
write=P.write
STAGES=['prepare','build','scan','test','collect','verify']
SPECS={
 '7.0.120':dict(runtime='7.0.20',installer='25b977658c06fd0217ec0bc0714398bb9d0a7bb0',
     sdk='a06803c09702777c6550fede13c8bdc52d780191',runtimeCommit='0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903',
     aspnetcore='d9ba962869d1b1c410ea476b02de2f8e27eec762',nuget='1653cf17925473602f5460c5e4682a0dab4c4d22',
     vstest='79d56b02b69a582cd90428878a5e9411ab7538f5',msbuild='6918b863aa37ad0699f98482fbab9f7a52e65a92',
     nugetVersion='6.4.3-rc.1',vstestVersion='17.4.1-dev',vstestTfm='net7.0'),
 '6.0.136':dict(runtime='6.0.36',installer='d638663530d923adbe0442604b7a6562127321e9',
     sdk='1d205826ddc14c8f868eb6373e7a6bafcb9fe5be',runtimeCommit='f1dd57165bfd91875761329ac3a8b17f6606ad18',
     aspnetcore='64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc',nuget='451e9bc27184dc49d04e975122c9e7189d525872',
     vstest='cc7fb0593127e24f55ce016fb3ac85b5b2857fec',msbuild='85d71072f8fa22cc761d6b65954da263364bee4d',
     nugetVersion='6.0.6-rc.4',vstestVersion='17.0.3-release-20230412-05',vstestTfm='netcoreapp2.1'),
 '5.0.214':dict(runtime='5.0.17',installer='430330f7c5428f031b4a835be3dcf5945f55a56a',
     sdk='3fdf76c35026e311b7edc245d4b3d9e812fe532e',runtimeCommit='6a984143635bde23e728abaaccbde52f5ea8fa3e',
     aspnetcore='02c6de4ba6022025fcda7581415f310f8c73cdc3'),
}


def comparison_package(url,destination,identity):
    """Retain a bounded pinned publisher comparison, never a restored origin."""
    require(url in (
        'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/flat2/netstandard.library.netframework/2.0.1-servicing-26011-01/netstandard.library.netframework.2.0.1-servicing-26011-01.nupkg',
        'https://api.nuget.org/v3-flatcontainer/system.runtime.compilerservices.unsafe/5.0.0/system.runtime.compilerservices.unsafe.5.0.0.nupkg'),
        'Only the two reviewed immutable comparison packages may be downloaded')
    expected={key:identity[key] for key in ('bytes','sha256','sha512')}
    require(0<expected['bytes']<=32*1024**2,'A bounded immutable comparison package is required')
    destination=P.ordinary(destination)
    if not destination.exists():
        with urllib.request.urlopen(url,timeout=90) as response:
            raw=response.read(expected['bytes']+1)
        require(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())==expected,
            'Downloaded immutable comparison package differs')
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(raw)
    require(destination.is_file() and destination.stat().st_size==expected['bytes']
        and fingerprint(destination)==expected,'Retained immutable comparison package differs')
    return destination


class Producer(P.Producer):
    def __init__(self,args):
        self.args=args;self.sdk=args.sdk_version;self.selected=SPECS[self.sdk]
        self.id=P.identity(args.arch);self.diagnostic_ptrace=False
        self.diagnostic=bool(args.diagnostic_podman)
        self.workspace=P.ordinary(args.workspace);self.output=P.ordinary(args.output_dir)
        require(self.workspace!=self.output and self.workspace not in self.output.parents and self.output not in self.workspace.parents,
                'Build workspace and delivery must be separate ordinary roots')
        require(platform.system()=='Linux' and platform.machine()==self.id['machine'],'Native matching Linux CPU required')
        require(os.getuid()!=0 or self.diagnostic,'Official producer orchestration must use the unprivileged native runner account')
        self.uid,self.gid=(1000,1000) if os.getuid()==0 else (os.getuid(),os.getgid())
        self.engine=P.container_engine(self.diagnostic)
        self.project=P.git(ROOT,'rev-parse','HEAD')
        self.profile_path=ROOT/'profiles'/f'dotnet-{self.sdk}-linux-musl-{args.arch}.json'
        self.profile=json.loads(self.profile_path.read_text())
        require(self.profile['target']==dict(rid=self.id['rid'],libc='musl') and
                self.profile['componentCommits']['runtime']==self.selected['runtimeCommit'],'Reviewed legacy profile/source identity differs')
        self.stock_profile=json.loads((ROOT/'profiles'/f'dotnet-10.0.403-linux-musl-{args.arch}.json').read_text())
        self.reports=self.output/'reports';self.work=self.workspace/'work';self.inputs=self.workspace/'inputs'
        self.home=self.workspace/'home';self.image_context=self.workspace/'image-context'
        self.sdk_work=self.work/'sdk-build';self.installer=self.work/'installer';self.runtime=self.work/'runtime'
        self.nuget=self.work/'nuget';self.feed=self.inputs/'bootstrap-feed';self.sources={}
        self.image=None;self.verify_image=None;self.test_image=None;self.tracing_image=None;self.commands=[];self.archive=None

    def record_container_engine(self):
        # Engine identity and diagnostic privilege choices are independent.
        # Podman diagnostics keep precisely the same dropped-capability options.
        saved=self.diagnostic_ptrace
        try:
            self.diagnostic_ptrace=self.diagnostic
            super().record_container_engine()
        finally:self.diagnostic_ptrace=saved

    def diagnostic_options(self):
        # Enabling minidumps on every .NET process breaks Crossgen2 on normal
        # native builds. Record MSBuild/process/cgroup diagnostics without
        # changing runtime dump or tracing policy for product commands.
        path=self.reports/'diagnostics'/('container-'+str(len(self.commands)).zfill(4))
        path.mkdir(parents=True)
        return ['--volume',str(path)+':/diag','--env','MSBUILDDEBUGPATH=/diag','--env','MSBUILDDEBUGCOMM=1']

    def container(self,arguments,*,network='host',source=True,image=None,log=None,environment=None,workdir='/tmp'):
        if log:
            log.parent.mkdir(parents=True,exist_ok=True)
            if os.getuid()==0:os.chown(log.parent,self.uid,self.gid)
        argv=self.engine+['run','--rm','--network='+network,'--user',str(self.uid)+':'+str(self.gid),
            '--cap-drop=all','--security-opt=no-new-privileges',
            '--env','HOME=/home/build','--env','DOTNET_CLI_HOME=/home/build','--env','DOTNET_CLI_TELEMETRY_OPTOUT=1',
            '--env','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1','--env','DOTNET_MULTILEVEL_LOOKUP=0',
            '--env','DOTNET_PROCESSOR_COUNT=2','--env','PYTHONDONTWRITEBYTECODE=1',
            '--volume',str(ROOT)+':/project:ro',
            '--volume',str(self.output)+':/delivery','--volume',str(self.home)+':/home/build','--workdir',workdir]
        if source:argv+=['--volume',str(self.workspace)+':/work']
        for name,value in (environment or {}).items():argv+=['--env',name+'='+value]
        options=self.diagnostic_options()
        if os.getuid()==0:
            diagnostic=Path(options[1].removesuffix(':/diag'))
            os.chown(diagnostic,self.uid,self.gid)
        argv+=options+[image or self.image]+self.observed_command(arguments)
        self.run(argv,log=log)
        if not self.diagnostic:P.validate_default_container_policy(self.output,list(map(str,argv)))

    def clone(self,name,repository,commit):
        require(repository.startswith('https://github.com/') and re.fullmatch('[0-9a-f]{40}',commit),'Pinned public source identity required')
        destination=self.work/name
        destination.mkdir()
        for arguments in [['git','init',str(destination)],['git','-C',str(destination),'remote','add','origin',repository],
                          ['git','-C',str(destination),'fetch','--depth','1','origin',commit],
                          ['git','-C',str(destination),'checkout','--detach','FETCH_HEAD'],
                          ['git','-C',str(destination),'submodule','update','--init','--recursive']]:
            self.run(arguments)
        require(P.git(destination,'rev-parse','HEAD')==commit,'Cloned source commit differs')
        self.sources[name]=dict(name=name,path=str(destination),kind='git',expectedCommit=commit)
        return destination

    def prepare(self):
        if not self.diagnostic:
            require(not P.git(ROOT,'status','--porcelain','--untracked-files=all'),'Official producer requires a pristine orchestration checkout')
        for directory in [self.workspace,self.output]:
            require(not directory.exists() or directory.is_dir() and not any(directory.iterdir()),'Fresh empty roots required')
        for directory in [self.work,self.inputs,self.home,self.reports/'prepare',self.reports/'diagnostics']:
            directory.mkdir(parents=True,exist_ok=True)
        self.home.chmod(0o700)
        self.record_container_engine()
        P.prepare_image_context(self.stock_profile,self.image_context)
        for suffix,field in [('', 'image'),('-runtime','verify_image')]:
            tag='localhost/cbodotnet-legacy-musl-'+('builder' if not suffix else 'runtime')+':'+self.args.run_id+'-'+self.args.arch
            recipe=ROOT/'containers'/(self.args.arch+'-net10-musl'+suffix+'.Containerfile')
            self.run(self.engine+['build','--network=host','--file',str(recipe),'--tag',tag,str(self.image_context)],
                     self.reports/'prepare'/('builder.log' if not suffix else 'runtime.log'))
            inspected=json.loads(self.run(self.engine+['image','inspect',tag],capture=True))
            require(len(inspected)==1 and inspected[0]['Architecture']==self.id['image'],'Native image CPU differs')
            setattr(self,field,inspected[0]['Id']);write(self.reports/'prepare'/(field+'.json'),inspected)
        tag='localhost/cbodotnet-legacy-musl-original-tests:'+self.args.run_id+'-'+self.args.arch
        parent=module('legacy_local_image_parent','musl_local_image.py').bind_parent(self,self.verify_image,'runtime')
        self.run(self.engine+['build','--network=host','--file',str(ROOT/'containers/legacy-musl-smoke.Containerfile'),
            '--build-arg','RUNTIME_IMAGE='+parent,'--tag',tag,str(self.image_context)],self.reports/'prepare/original-test-image.log')
        inspected=json.loads(self.run(self.engine+['image','inspect',tag],capture=True))
        require(len(inspected)==1 and inspected[0]['Architecture']==self.id['image'],'Original-test image CPU differs')
        self.test_image=inspected[0]['Id'];write(self.reports/'prepare/test-image.json',inspected)
        tag='localhost/cbodotnet-legacy-musl-tracing:'+self.args.run_id+'-'+self.args.arch
        self.run(self.engine+['build','--network=host','--file',str(ROOT/'containers/legacy-musl-tracing.Containerfile'),
            '--build-arg','RUNTIME_IMAGE='+parent,'--tag',tag,str(self.image_context)],self.reports/'prepare/tracing-image.log')
        inspected=json.loads(self.run(self.engine+['image','inspect',tag],capture=True))
        require(len(inspected)==1 and inspected[0]['Architecture']==self.id['image'],'Tracing-test image CPU differs')
        self.tracing_image=inspected[0]['Id'];write(self.reports/'prepare/tracing-image.json',inspected)
        self.installer=self.clone('installer','https://github.com/dotnet/installer',self.selected['installer'])
        self.runtime=self.clone('runtime','https://github.com/dotnet/runtime',self.selected['runtimeCommit'])
        self.clone('aspnetcore','https://github.com/dotnet/aspnetcore',self.selected['aspnetcore'])
        T.M.ENGINE=self.engine
        T.prepare(SimpleNamespace(workspace=self.sdk_work,sdk=self.sdk,arch='arm64' if self.args.arch=='aarch64' else 'x64',bootstrap_archive=None))
        module('legacy_actual_bootstrap_receipt','musl_legacy_bootstrap_receipt.py').retain(
            self.sdk_work,self.profile,self.sdk,self.id['rid'],self.reports/'prepare')
        self.sources['sdk']=dict(name='sdk',path=str(self.sdk_work/'sdk'),kind='git',expectedCommit=self.selected['sdk'])
        for name,repository in [('nuget','https://github.com/NuGet/NuGet.Client'),('vstest','https://github.com/microsoft/vstest'),
                                ('msbuild','https://github.com/dotnet/msbuild')]:
            if name in self.selected:self.clone(name,repository,self.selected[name])
        if self.sdk=='7.0.120':
            # The original NETStandard.Library.Ref2.1.0 nuspec identifies its
            # Core Setup packaging commit in description rather than a
            # repository element. That exact manifest pins the separate API
            # source. Retain both; no current-runtime attribution is inferred.
            for name,repository,commit in [
                ('netstandard-core-setup','https://github.com/dotnet/core-setup','7d57652f33493fa022125b7f63aad0d70c52d810'),
                ('netstandard-library','https://github.com/dotnet/standard','a5b5f2e1e369972c8ff1e2183979fab6099f52ef')]:
                self.clone(name,repository,commit)
                self.sources[name]['role']='source-for-imported-netstandard21-targeting-pack'
            self.clone('test-templates','https://github.com/dotnet/test-templates','aaaa0c1826f97a9dfcc67e94136bf01010b55f23')
            self.sources['test-templates']['role']='source-for-imported-test-project-templates'
        self.feed.mkdir()
        series='.'.join(self.sdk.split('.')[:2]);metadata=self.inputs/'release-metadata.json'
        T.M.fetch(f'https://builds.dotnet.microsoft.com/dotnet/release-metadata/{series}/releases.json',metadata,4*1024**2)
        document=json.loads(metadata.read_text());release=next(r for r in document['releases'] if r['runtime']['version']==self.selected['runtime'])
        imports=[];self.framework_inputs={}
        for kind in ['runtime','aspnetcore-runtime']:
            item=next(f for f in release[kind]['files'] if f['rid']==self.id['rid'] and f['name'].endswith('.tar.gz'))
            destination=self.inputs/Path(item['url']).name
            imports.append(dict(component=kind,origin='imported-official-matching-musl',**T.M.fetch(item['url'],destination,128*1024**2,item['hash'])))
            self.framework_inputs[kind]=destination
        sdk_item=next(f for r in document['releases'] for version in r.get('sdks',[r.get('sdk',{})]) if version.get('version')==self.sdk
                      for f in version['files'] if f.get('rid')==self.id['rid'])
        self.official=self.inputs/'official-comparison-sdk.tar.gz'
        imports.append(dict(component='official-sdk-comparison-only',origin='not-a-producer-payload',
            **T.M.fetch(sdk_item['url'],self.official,512*1024**2,sdk_item['hash'])))
        write(self.reports/'prepare/imports.json',dict(inputs=imports))
        # Retain the exact pinned source identities declared by SDK product
        # imports, including compiler/F#/MSBuild sources, without rebuilding
        # those imported managed packages or claiming a source-only product.
        dependencies=[];unmapped=[]
        details=ET.parse(self.sdk_work/'sdk/eng/Version.Details.xml')
        for dependency in details.iter('Dependency'):
            repository=dependency.findtext('Uri') or '';commit=dependency.findtext('Sha') or ''
            original_repository=repository
            if repository.startswith('https://dev.azure.com/devdiv/') and dependency.get('Name','').startswith('NuGet.'):
                repository='https://github.com/NuGet/NuGet.Client'
            parsed=urllib.parse.urlparse(repository)
            if parsed.netloc=='dev.azure.com' and parsed.path.startswith('/dnceng/internal/_git/'):
                known={'dotnet-runtime':'runtime','dotnet-aspnetcore':'aspnetcore','dotnet-templating':'templating',
                       'dotnet-windowsdesktop':'windowsdesktop','dotnet-wpf':'wpf','dotnet-msbuild':'msbuild',
                       'dotnet-roslyn':'roslyn','dotnet-fsharp':'fsharp'}
                leaf=parsed.path.rsplit('/',1)[-1]
                if leaf in known:repository='https://github.com/dotnet/'+known[leaf]
            if repository.startswith('https://github.com/') and re.fullmatch('[a-f0-9]{40}',commit):
                existing=next((r for r in self.sources.values() if r.get('expectedCommit')==commit),None)
                name=existing['name'] if existing else 'sdk-import-'+hashlib.sha256((repository+commit).encode()).hexdigest()[:16]
                if existing is None:
                    self.clone(name,repository,commit)
                    self.sources[name]['role']='source-for-reused-managed-input'
                dependencies.append(dict(package=dependency.get('Name'),version=dependency.get('Version'),repository=repository,
                    declaredRepository=original_repository,commit=commit,sourceRoot=name))
            elif re.fullmatch('[a-f0-9]{40}',commit):
                unmapped.append(dict(package=dependency.get('Name'),version=dependency.get('Version'),repository=original_repository,commit=commit,
                    status='unmapped-source-requires-shipping-scope-review'))
        write(self.reports/'prepare/managed-source-identities.json',dict(dependencies=dependencies,
            unmappedDeclaredSources=unmapped,
            scope='Exact public product dependency identities declared by the pinned SDK Version.Details.xml; actual restored package inventory is collected separately'))
        self.run(['cp','-a',str(self.sdk_work/'sdk/.dotnet'),str(self.installer/'.dotnet')])
        if os.getuid()==0:self.run(['chown','-R',str(self.uid)+':'+str(self.gid),str(self.workspace),str(self.output)])
        write(self.reports/'prepare/identity.json',dict(schemaVersion=1,sdkVersion=self.sdk,targetRid=self.id['rid'],libc='musl',
            projectCommit=self.project,sourceCommit=self.selected['installer'],sdkSourceCommit=self.selected['sdk'],
            runtimeSourceCommit=self.selected['runtimeCommit'],runId=self.args.run_id,runAttempt=self.args.run_attempt,
            architecture=self.args.arch,buildId=self.args.build_id,nativeArchitecture=platform.machine(),nativeKernelVersion=platform.release(),
            emulation=False,diagnosticPodman=self.diagnostic,diagnosticPtrace=False,containerEngine=self.engine_record,
            sourceAppArmorPolicy='engine-default',consumerAppArmorPolicy='engine-default',
            sourceSeccompPolicy='engine-default',consumerSeccompPolicy='engine-default',
            imageId=self.image,verificationImageId=self.verify_image,tracingImageId=self.tracing_image,
            profile=dict(path=self.profile_path.name,**fingerprint(self.profile_path))))
        if self.args.host_reports:
            require(self.args.host_reports.is_dir() and not self.args.host_reports.is_symlink(),'Ordinary original host preflight reports required')
            shutil.copytree(self.args.host_reports,self.reports/'prepare/host')
        for role,image in [('builder',self.image),('runtime',self.verify_image),('original-tests',self.test_image),('tracing-tests',self.tracing_image)]:
            self.container(['sh','-ec','! command -v dotnet; ! apk info -e gcompat; ! apk info -e libc6-compat; '
                'test "$(cat /etc/alpine-release)" = 3.24.4; '
                'cp -a /cbodotnet-apks /delivery/reports/prepare/'+role+'-apks; '
                'apk info -vv > /delivery/reports/prepare/'+role+'-installed-packages.txt; '
                'cp -a /etc/apk/keys /delivery/reports/prepare/'+role+'-apk-keys'],
                source=False,image=image,network='none',log=self.reports/'prepare'/(role+'-inventory.log'))
        self.container(['sh','-ec','cp -a /cbodotnet-trace-test-apks /delivery/reports/prepare/tracing-test-apks'],
            source=False,image=self.tracing_image,network='none',log=self.reports/'prepare/tracing-apk-inventory.log')
        self.container(['/work/work/sdk-build/sdk/.dotnet/dotnet','msbuild','/project/scripts/probe-source-cultures.proj',
            '/p:SourceCultureReport=/delivery/reports/prepare/source-cultures.json'],
            environment=dict(DOTNET_ROOT='/work/work/sdk-build/sdk/.dotnet'),log=self.reports/'prepare/source-cultures.log')

    def build(self):
        require(self.sdk=='7.0.120','SDK6/5 regular producer graphs remain under bounded source/bootstrap investigation; no untested product is manufactured')
        arch='arm64' if self.args.arch=='aarch64' else 'x64'
        bootstrap='/work/work/sdk-build/sdk/.dotnet'
        # Rebuild missing exact NuGet 6.4.3-rc.1 packages from their matching
        # public source and original library target matrix. No nearest-version
        # packages, retargeted library subset or prebuilt full SDK is accepted.
        self.container([bootstrap+'/dotnet','msbuild','/work/work/nuget/build/build.proj',
            '-t:RestoreXPLAT,BuildXPLAT,PackXPLAT','/p:Configuration=Release','/p:BuildNumber=1','/p:ReleaseLabel=rc',
            '/p:IsXPlat=true','/p:DotNetBuildFromSource=true','/p:NETCoreTargetFramework=net7.0',
            '/p:TargetFrameworksExe=net7.0','/p:TargetFrameworksExeForSigning=net7.0','/p:BuildProjectReferences=true',
            '/p:UseSharedCompilation=false','/p:EmitCompilerGeneratedFiles=true','/m:2','/bl:/delivery/reports/build/nuget.binlog'],
            environment=dict(DOTNET_ROOT=bootstrap,NUGET_PACKAGES='/work/work/nuget/.packages'),
            workdir='/work/work/nuget',log=self.reports/'build/nuget.log')
        local=[]
        rebuilt_inputs=self.reports/'build/rebuilt-nuget-inputs';rebuilt_inputs.mkdir()
        for package in sorted((self.nuget/'artifacts/nupkgs').glob('*.nupkg')):
            if package.name.endswith('.symbols.nupkg'):continue
            require(package.name.endswith('.'+self.selected['nugetVersion']+'.nupkg'),'Locally built NuGet package version differs')
            destination=self.feed/package.name;shutil.copyfile(package,destination)
            retained=rebuilt_inputs/package.name;shutil.copyfile(package,retained)
            local.append(dict(file=package.name,origin='rebuilt-exact-nuget-original-library-target-matrix',
                sourceCommit=self.selected['nuget'],retained=retained.relative_to(self.output).as_posix(),
                **fingerprint(destination)))
        require(len(local)>=19,'Complete pinned source-built NuGet product package set is absent')
        self.sources['rebuilt-nuget-package-inputs']=dict(name='rebuilt-nuget-package-inputs',kind='tree',
            path=str(rebuilt_inputs),role='actual-source-built-package-outputs-not-a-restore-consumption-claim')
        vstest=self.reports/'build/vstest'
        self.container(['python3','/project/scripts/musl-legacy-vstest.py','--sdk',self.sdk,'--arch',self.args.arch,
            '--source','/work/work/vstest','--dotnet',bootstrap+'/dotnet','--output','/delivery/reports/build/vstest'],
            log=self.reports/'build/vstest.log')
        result=json.loads((vstest/'results.json').read_text())
        require(result['status']=='passed' and result['sourceCommit']==self.selected['vstest']
                and result['version']==self.selected['vstestVersion'],'The exact original VSTest source build failed')
        self.sources['vstest-generated']=dict(name='vstest-generated',kind='tree',path=str(vstest/'generated'),
            role='generated-managed-component-source')
        for package in sorted((vstest/'source-built-feed').glob('*.nupkg')):
            shutil.copyfile(package,self.feed/package.name)
            local.append(dict(file=package.name,origin='rebuilt-original-vstest-source-build-core-distribution',
                sourceCommit=self.selected['vstest'],version=self.selected['vstestVersion'],
                retained=package.relative_to(self.output).as_posix(),**fingerprint(package)))
        require(sum(row['origin']=='rebuilt-original-vstest-source-build-core-distribution' for row in local)==2,
                'Both genuine original VSTest source packages are required')
        shutil.copyfile(vstest/'original-solution-build.binlog',self.reports/'build/vstest.binlog')
        write(self.reports/'build/bootstrap-feed.json',dict(packages=local))
        translations=self.reports/'build/nuget-translation-data'
        self.container(['python3','/project/scripts/musl-legacy-nuget-resources.py',
            '--sdk-archive','/work/inputs/official-comparison-sdk.tar.gz','--arch',self.args.arch,
            '--source','/work/work/nuget','--dotnet',bootstrap+'/dotnet','--output','/delivery/reports/build/nuget-translation-data'],
            log=self.reports/'build/nuget-translation-data.log')
        self.sources['nuget-translation-data']=dict(name='nuget-translation-data',kind='tree',path=str(translations),
            role='actual-imported-translation-data-and-generated-readable-source')
        T.M.ENGINE=self.engine
        image=self.image.removeprefix('sha256:')
        T.build(SimpleNamespace(workspace=self.sdk_work,sdk=self.sdk,arch=arch,image=image,attempt='producer-source-graph',
            seconds=900,component_source_build=True,rebuild=True,nuget_feed=self.feed,package_cache='.packages',vstest_tfm=None,
            vstest_source_version=self.selected['vstestVersion'],scope_linux_host_tasks=True,
            nuget_resources=translations,wrap_command=self.wrap_tooling_command,
            engine_label='rootful-podman' if self.diagnostic else 'normal-rootful-docker'))
        tooling=self.sdk_work/'evidence/producer-source-graph'
        require(json.loads((tooling/'result.json').read_text())['exitCode']==0,'Pinned original SDK source-build solution filter failed')
        shutil.copytree(tooling,self.reports/'build/sdk-tooling')
        invocation=json.loads((tooling/'invocation.json').read_text())['command']
        if not self.diagnostic:P.validate_default_container_policy(self.output,invocation)
        binlog=self.sdk_work/'sdk/artifacts/log/Release/community-sdk-producer-source-graph.binlog'
        require(binlog.is_file(),'Actual SDK source graph binary log is required')
        shutil.copyfile(binlog,self.reports/'build/sdk.binlog')
        trace=self.reports/'build/native-trace'
        self.container(['python3','/project/scripts/musl-legacy-native.py','trace','--sdk',self.sdk,'--arch',self.args.arch,
            '--source','/work/work/runtime','--output','/delivery/reports/build/native-trace'],
            log=self.reports/'build/native-trace.log')
        require(json.loads((trace/'results.json').read_text())['status']=='passed','Matching native trace provider source build failed')
        self.sources['native-trace-generated']=dict(name='native-trace-generated',kind='tree',path=str(trace/'generated'),
            role='generated-native-component-source')
        native_runtime=self.reports/'build/native-runtime'
        self.container(['python3','/project/scripts/musl-legacy-coreclr.py','--sdk',self.sdk,'--arch',self.args.arch,
            '--source','/work/work/runtime','--dotnet',bootstrap+'/dotnet','--build-id',self.args.build_id,
            '--output','/delivery/reports/build/native-runtime'],log=self.reports/'build/native-runtime.log')
        require(json.loads((native_runtime/'results.json').read_text())['status']=='passed',
                'Matching native CoreCLR/JIT/debugger source build failed')
        self.sources['native-runtime-generated']=dict(name='native-runtime-generated',kind='tree',
            path=str(native_runtime/'generated'),role='generated-native-component-source')
        imports=self.inputs/'installer-components';imports.mkdir()
        toolset=self.sdk_work/'sdk/artifacts/packages/Release/NonShipping'/('dotnet-toolset-internal-'+self.sdk+'-ci.zip')
        require(toolset.is_file(),'Genuinely built SDK tooling ZIP is absent')
        with zipfile.ZipFile(toolset) as archive:
            names=archive.namelist()
            require('vstest.console.dll' in names and any(n.endswith('Microsoft.NET.Sdk.Razor.Tasks.dll') for n in names),
                    'Source-built tooling ZIP lacks actual VSTest or Razor product outputs')
        shutil.copyfile(toolset,imports/toolset.name)
        for kind,path in self.framework_inputs.items():
            shutil.copyfile(path,imports/path.name)
            if kind=='aspnetcore-runtime':
                alias='aspnetcore-runtime-internal-'+self.selected['runtime']+'-'+self.id['rid']+'.tar.gz'
                shutil.copyfile(path,imports/alias)
        shutil.copyfile(trace/'libcoreclrtraceptprovider.so',imports/'libcoreclrtraceptprovider.so')
        (imports/'native-runtime').mkdir()
        for name in ['libcoreclr.so','libclrjit.so','libmscordaccore.so','libmscordbi.so']:
            shutil.copyfile(native_runtime/name,imports/'native-runtime'/name)
        for patch in ['0001-copy-local-source-built-components.patch','0006-copy-matching-source-built-native-runtime.patch',
                      '0008-honor-skip-installer-version-metadata.patch']:
            self.run(['git','-C',str(self.installer),'apply','--check',str(ROOT/'patches/net7-musl'/patch)])
            self.run(['git','-C',str(self.installer),'apply',str(ROOT/'patches/net7-musl'/patch)])
        command=['./build.sh','--configuration','Release','--restore','--build','--pack','--projects',
            '/work/work/installer/src/redist/redist.csproj','/p:ArcadeBuildFromSource=false','/p:DotNetBuildFromSource=true',
            '/p:DotNetBuildOffline=true','/p:PublicBaseURL=/work/inputs/installer-components/',
            '/p:MicrosoftDotnetToolsetInternalPackageVersion='+self.sdk+'-ci','/p:Version='+self.sdk,
            '/p:Architecture='+arch,'/p:OSName=linux-musl','/p:PortableOSName=linux-musl','/p:Rid='+self.id['rid'],
            '/p:HostRid='+self.id['rid'],'/p:SharedFrameworkRid='+self.id['rid'],'/p:CoreSetupRid='+self.id['rid'],
            '/p:Crossgen2Rid='+self.id['rid'],'/p:UsePortableLinuxSharedFramework=false','/p:SkipBuildingInstallers=true',
            '/p:RestoreAdditionalProjectSources=/work/inputs/bootstrap-feed','/p:UseSharedCompilation=false','/m:2',
            '/bl:/delivery/reports/build/installer.binlog','/p:CommunityMuslComponentRoot=/work/inputs/installer-components',
            '/p:CommunityMuslNativeTraceProvider=/work/inputs/installer-components/libcoreclrtraceptprovider.so',
            '/p:CommunityMuslNativeRuntimeRoot=/work/inputs/installer-components/native-runtime']
        self.container(command,environment=dict(DOTNET_ROOT='/work/work/installer/.dotnet',
            DOTNET_INSTALL_DIR='/work/work/installer/.dotnet',NUGET_PACKAGES='/work/work/installer/.packages'),
            workdir='/work/work/installer',log=self.reports/'build/installer.log')
        archive=self.installer/'artifacts/packages/Release/Shipping'/('dotnet-sdk-'+self.sdk+'-'+self.id['rid']+'.tar.gz')
        require(archive.is_file(),'Pinned installer produced no genuine matching musl SDK archive')
        self.archive=self.output/('cbodotnet-sdk-'+self.sdk+'-linux-musl-'+self.args.arch+'-build.'+self.args.run_id+'.tar.gz')
        shutil.copyfile(archive,self.archive)
        require(fingerprint(archive)==fingerprint(self.archive),'Genuine installer archive changed during collection')
        write(self.reports/'build/construction.json',dict(schemaVersion=1,sourceOnly=False,
            sdkArchive=dict(name=self.archive.name,**fingerprint(self.archive)),
            toolingZip=dict(name=toolset.name,**fingerprint(toolset)),sourceGraph='sdk/source-build.slnf',
            rebuiltComponents=['SDK CLI/tooling/tasks/templates/redist','exact NuGet packages','original VSTest Core hosts and all thirteen resource cultures',
                'matching runtime trace provider',
                'matching native CoreCLR/JIT/DAC/debugger shared libraries'],
            importedComponents=['matching official musl host/managed runtime/ASP.NET and remaining native libraries',
                'managed/compiler packages recorded separately'],
            originalFullSdkUsedAsPayload=False,
            imports=[dict(name=p.relative_to(imports).as_posix(),**fingerprint(p)) for p in sorted(imports.rglob('*')) if p.is_file()]))
        self.replay_build_logs()

    def replay_build_logs(self):
        reader=self.reports/'build/reader'
        shutil.copytree(ROOT/'scripts/musl-legacy-reader',reader)
        (reader/'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>\n')
        if os.getuid()==0:
            self.run(['chown','-R',str(self.uid)+':'+str(self.gid),str(reader)])
        major=self.sdk.split('.')[0]
        bootstrap='/work/work/sdk-build/sdk/.dotnet';sdk=bootstrap+'/sdk/'+T.PINS[self.sdk]['bootstrap']
        self.container([bootstrap+'/dotnet','build','/delivery/reports/build/reader/Reader.csproj','--configuration','Release',
            '/p:BootstrapMajor='+major,'/p:BootstrapSdkDir='+sdk,'/p:UseSharedCompilation=false'],
            environment=dict(DOTNET_ROOT=bootstrap),log=self.reports/'build/reader-build.log')
        for component in ['nuget','sdk','installer','vstest']:
            self.container([bootstrap+'/dotnet','/delivery/reports/build/reader/bin/Release/net'+major+'.0/Reader.dll',
                '/delivery/reports/build/'+component+'.binlog',sdk,'/delivery/reports/build/'+component+'-replay'],
                environment=dict(DOTNET_ROOT=bootstrap),log=self.reports/'build'/(component+'-replay.log'))

    def wrap_tooling_command(self,argv):
        image=self.image.removeprefix('sha256:');position=argv.index(image)
        options=self.diagnostic_options()
        if os.getuid()==0:os.chown(Path(options[1].removesuffix(':/diag')),self.uid,self.gid)
        result=argv[:position]+['--volume',str(ROOT)+':/project:ro','--volume',str(self.output)+':/delivery']+options+[
            argv[position]]+self.observed_command(argv[position+1:])
        self.commands.append(result)
        return result

    def scan(self):
        graph=self.sdk_work/'sdk/source-build.slnf'
        original=self.run(['git','-C',str(self.sdk_work/'sdk'),'show',self.selected['sdk']+':source-build.slnf'],capture=True)
        projects=json.loads(original)['solution']['projects']
        require(projects and not any('BinaryToolKit' in name for name in projects),'Legacy source graph/scanner applicability changed')
        write(self.reports/'scan-applicability.json',dict(status='not-applicable',
            reason='Legacy regular SDK/installer graphs do not contain VMR BinaryToolKit scanning. No empty VMR report is manufactured.',
            sourceOnly=False,importedInputsRequireInventory=True,sourceCommit=self.selected['sdk'],
            sourceGraph=dict(path='sdk/source-build.slnf',projects=projects,**fingerprint(graph))))

    def test(self):
        require(self.archive is not None,'A genuinely built SDK archive is required before original tests')
        tests=self.installer/'src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests'
        self.container(['python3','/project/scripts/musl-legacy-smoke.py','--sdk-version',self.sdk,'--arch',self.args.arch,
            '--source-tests','/work/work/installer/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests',
            '--sdk-archive','/delivery/'+self.archive.name,'--official-archive','/work/inputs/official-comparison-sdk.tar.gz',
            '--output','/delivery/reports/test/original-smoke'],source=True,image=self.test_image,
            log=self.reports/'test/original-smoke.log')
        self.container(['python3','/project/scripts/musl-legacy-lttng.py','--sdk',self.sdk,'--arch',self.args.arch,
            '--archive','/delivery/'+self.archive.name,'--output','/delivery/reports/test/native-lttng'],
            source=False,image=self.tracing_image,network='none',log=self.reports/'test/native-lttng.log')

    def collect(self):
        require(self.archive is not None and self.archive.is_file(),'No genuine legacy SDK has been produced')
        retained=self.output/'imported-inputs';retained.mkdir()
        packages=[];known={}
        for name,root in sorted(self.sources.items()):
            for cache in [Path(root['path'])/'.packages',Path(root['path'])/'artifacts/.packages']:
                if not cache.is_dir():continue
                for package in sorted(cache.rglob('*.nupkg')):
                    require(package.is_file() and not package.is_symlink(),'An actual imported NuGet package is redirected')
                    identity=fingerprint(package);sha=identity['sha256']
                    if sha not in known:
                        destination=retained/(sha+'.nupkg');shutil.copyfile(package,destination)
                        require(fingerprint(destination)==identity,'Retained actual NuGet input bytes changed')
                        known[sha]=destination.name
                    metadata_path=package.parent/'.nupkg.metadata'
                    metadata=json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
                    with zipfile.ZipFile(package) as archive:
                        licenses=[dict(path=p,sha256=hashlib.sha256(archive.read(p)).hexdigest()) for p in archive.namelist()
                                  if not p.endswith('/') and any(x in Path(p).name.lower() for x in ['license','notice','.nuspec'])]
                    packages.append(dict(repository=name,cache=str(cache),path=package.relative_to(cache).as_posix(),
                        source=metadata.get('source'),retained='imported-inputs/'+known[sha],licensesAndNuspec=licenses,**identity))
        require(packages,'Actual restored NuGet inputs must be inventoried and retained')
        write(self.reports/'restored-inputs.json',dict(schemaVersion=1,packages=packages,
            scope='Unchanged actual restored package bytes, original NuGet origins, embedded licenses/notices/nuspec; imported packages are not described as locally rebuilt'))
        self.sources['actual-managed-package-inputs']=dict(name='actual-managed-package-inputs',path=str(retained),kind='tree',role='actual-imported-managed-inputs')
        if self.sdk=='7.0.120':
            manifests=module('legacy_readable_manifest_inputs','musl_legacy_manifest_inputs.py')
            wanted={tuple(row['fingerprint'][key] for key in manifests.FP) for row in manifests.policy()}
            paths=sorted({self.output/row['retained'] for row in packages
                if tuple(row[key] for key in manifests.FP) in wanted})
            require(len(paths)==8,'The eight exact reviewed manifest packages were not actually restored')
            descriptor=manifests.prepare_tree(paths,self.reports/'build/workload-manifest-data')
            self.sources[descriptor['name']]=descriptor
            localization=module('legacy_readable_msbuild_localization','musl_legacy_msbuild_resources.py')
            paths=sorted({self.output/row['retained'] for row in packages
                if all(row[key]==localization.PACKAGE[key] for key in localization.FP)})
            require(len(paths)==1,'The exact reviewed MSBuild localization package was not actually restored')
            descriptor=localization.prepare(paths[0],Path(self.sources['msbuild']['path']),
                self.reports/'build/msbuild-localization-data')
            self.sources[descriptor['name']]=descriptor
            facades=module('legacy_literal_type_forwarder_inputs','musl_legacy_facade_inputs.py')
            identity=facades.policy()['package']['fingerprint']
            paths=sorted({self.output/row['retained'] for row in packages
                if all(row[key]==identity[key] for key in facades.FP)})
            require(len(paths)==1,'The exact original facade metadata package was not actually restored')
            descriptor=facades.prepare(paths[0],self.sdk_work/'sdk',self.reports/'build/literal-type-forwarder-metadata')
            self.sources[descriptor['name']]=descriptor
            globbing=module('legacy_globbing_source_and_binary_license','musl_legacy_globbing_inputs.py')
            identity=globbing.policy()['package']
            paths=sorted({self.output/row['retained'] for row in packages
                if all(row[key]==identity[key] for key in globbing.FP)})
            require(len(paths)==1,'The exact original Globbing package was not actually restored')
            publisher=globbing.fetch_publisher(self.inputs/'publisher-license-comparison'/(globbing.PUBLISHER_SHA+'.nupkg'))
            descriptor=globbing.prepare(paths[0],publisher,Path(self.sources['vstest']['path']),
                self.reports/'build/globbing-binary-source-inputs')
            self.sources[descriptor['name']]=descriptor
        packer=module('legacy_used_source_packer','package-used-source.py')
        component_sources=module('legacy_exact_component_sources','musl_legacy_component_sources.py')
        component_sources.register(self.sdk,self.sources,self.clone,packer.expand_submodules,
            report_path=self.reports/'prepare/component-source-materialization.json')
        if self.sdk=='7.0.120':
            framework=module('legacy_framework_preferred_il_inputs','musl_legacy_framework_il_inputs.py')
            policy=framework.policy();identity=policy['package']['fingerprint']
            paths=sorted({self.output/row['retained'] for row in packages
                if all(row[key]==identity[key] for key in framework.FP)})
            require(len(paths)==1,'The original implementation-source package must have been actually restored')
            assets=[row for row in self.sources.values() if row.get('kind')=='git'
                and row.get('expectedCommit')==policy['preferredSource']['commit']]
            require(len(assets)==1,'The complete exact preferred-IL source must be registered before capture')
            canonical=comparison_package(
                'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/flat2/netstandard.library.netframework/2.0.1-servicing-26011-01/netstandard.library.netframework.2.0.1-servicing-26011-01.nupkg',
                self.inputs/'publisher-source-comparisons'/(framework.CANONICAL_SHA+'.nupkg'),policy['canonicalPackage']['fingerprint'])
            descriptor=framework.prepare(paths[0],canonical,self.sdk_work/'sdk',Path(assets[0]['path']),
                self.reports/'build/framework-implementation-il-inputs')
            self.sources[descriptor['name']]=descriptor
            attributed=module('legacy_attributed_component_inputs','musl_legacy_attributed_components.py')
            policy=attributed.policy()
            for source in policy['sources'].values():
                require(sum(row.get('kind')=='git' and row.get('expectedCommit')==source['commit']
                    for row in self.sources.values())==1,'Every exact original component source must be registered')
            unsafe=comparison_package(
                'https://api.nuget.org/v3-flatcontainer/system.runtime.compilerservices.unsafe/5.0.0/system.runtime.compilerservices.unsafe.5.0.0.nupkg',
                self.inputs/'publisher-source-comparisons'/(policy['unsafeCanonicalPackage']['sha256']+'.nupkg'),policy['unsafeCanonicalPackage'])
            descriptor=attributed.prepare(unsafe,self.reports/'build/attributed-component-inputs')
            self.sources[descriptor['name']]=descriptor
            write(self.reports/'build/publisher-source-comparisons.json',dict(schemaVersion=1,
                scope='Immutable publisher comparison inputs retained only inside corresponding-source data trees',
                actualRestoredInputClaimed=False,layoutOriginClaimed=False,executed=False,
                packages=[dict(path=str(path),**fingerprint(path)) for path in [canonical,unsafe]]))
        compiler_inputs=module('legacy_observed_managed_compiler_inputs','musl_legacy_compiler_inputs.py')
        components={name:dict(sourceRoot=name,sourceMountRoot=mount,hostPath=str(path),
            tasks=self.reports/'build'/(name+'-replay-tasks.jsonl'))
            for name,mount,path in [('sdk','/source',self.sdk_work/'sdk'),('nuget','/work/work/nuget',self.nuget),
                ('vstest','/work/work/vstest',self.work/'vstest')]}
        descriptor=compiler_inputs.prepare(components,self.reports/'build/managed-compiler-inputs')
        self.sources[descriptor['name']]=descriptor
        (self.reports/'ci').mkdir(parents=True,exist_ok=True)
        self.emit_construction_evidence()
        write(self.reports/'source-roots.json',dict(schemaVersion=1,roots=list(self.sources.values())))
        packer.pack(SimpleNamespace(project_root=ROOT,project_commit=self.project,output_dir=self.output/'sources',
            roots_json=self.reports/'source-roots.json',sdk_version=self.sdk,target_rid=self.id['rid'],
            run_id=self.args.run_id,run_attempt=self.args.run_attempt))
        packer.verify(SimpleNamespace(release_dir=self.output,expected_project_commit=self.project,
            expected_run_id=self.args.run_id,expected_run_attempt=self.args.run_attempt,expected_target_rid=self.id['rid']))
        write(self.output/'producer-sdk.json',dict(schemaVersion=1,kind='musl-sdk-build',producerRevision=1,
            sdkVersion=self.sdk,architecture=self.args.arch,targetRid=self.id['rid'],libc='musl',
            sourceCommit=self.selected['installer'],sdkSourceCommit=self.selected['sdk'],runtimeSourceCommit=self.selected['runtimeCommit'],
            projectCommit=self.project,runId=self.args.run_id,runAttempt=self.args.run_attempt,imageId=self.image,
            sdk=dict(name=self.archive.name,**fingerprint(self.archive))))

    def emit_construction_evidence(self):
        roots={name:dict(path=row['path'],kind=row.get('kind','git'),commit=row.get('expectedCommit'),
            **({'role':row['role']} if row.get('role') else {}))
            for name,row in self.sources.items()}
        context=dict(sdkVersion=self.sdk,architecture=self.args.arch,releaseDir=str(self.output),
            sourceRoots=roots,sdkArchive=str(self.archive),
            originalSdkComparison=str(self.official),
            toolsetZip=str(self.inputs/'installer-components'/('dotnet-toolset-internal-'+self.sdk+'-ci.zip')),
            runtimeArchive=str(self.framework_inputs['runtime']),aspnetArchive=str(self.framework_inputs['aspnetcore-runtime']),
            traceFile=str(self.reports/'build/native-trace/libcoreclrtraceptprovider.so'),
            nativeRuntimeDir=str(self.reports/'build/native-runtime'),
            installerLayout=str(self.installer/'artifacts/bin/redist/Release/dotnet'),
            installerLayoutMount='/work/work/installer/artifacts/bin/redist/Release/dotnet',
            restoredInputs=str(self.reports/'restored-inputs.json'),
            translationDataDir=str(self.reports/'build/nuget-translation-data'),
            vstestPackages=[str(path) for path in sorted((self.reports/'build/vstest/source-built-feed').glob('*.nupkg'))],
            bootstrapFeed=str(self.reports/'build/bootstrap-feed.json'))
        for name,mount in [('sdk','/source'),('installer','/work/work/installer'),('nuget','/work/work/nuget'),
                           ('vstest','/work/work/vstest')]:
            context[name+'Replay']=dict(status=str(self.reports/'build'/(name+'-replay-status.json')),
                tasks=str(self.reports/'build'/(name+'-replay-tasks.jsonl')),
                binlog=str(self.reports/'build'/(name+'.binlog')),sourceMountRoot=mount)
        write(self.reports/'build/evidence-context.json',context)
        proof=module('legacy_observed_construction','musl_legacy_evidence.py').emit(context)
        require(not proof.get('unknowns'),'Actual legacy construction has unresolved file or corresponding-source origins')

    def verify(self):
        require(self.archive is not None,'A genuine archive is required')
        self.container(['bash','/project/scripts/verify-sdk.sh','--archive','/delivery/'+self.archive.name,
            '--output-dir','/delivery/reports/verify/sdk','--expected-version',self.sdk,'--expected-rid',self.id['rid'],
            '--framework','net'+self.sdk.split('.')[0]+'.0','--arch','arm64' if self.args.arch=='aarch64' else 'x64'],
            source=False,image=self.verify_image,network='none',log=self.reports/'verify/sdk.log')
        self.container(['python3','/project/scripts/musl-sdk-audit.py','--archive','/delivery/'+self.archive.name,
            '--output','/delivery/reports/verify/elf.json','--arch',self.args.arch],source=False,
            image=self.verify_image,network='none',log=self.reports/'verify/elf.log')
        for mode,network in [('offline','none'),('tls','host')]:
            self.container(['python3','/project/scripts/musl-legacy-functional.py',mode,'--archive','/delivery/'+self.archive.name,
                '--sdk-version',self.sdk,'--arch',self.args.arch,'--output','/delivery/reports/verify/functional'],
                source=False,image=self.verify_image,network=network,log=self.reports/'verify'/('functional-'+mode+'.log'))

    def execute(self):
        for name in STAGES:
            self.stage(name,getattr(self,name))
        if not self.diagnostic:
            self.seal()
            return
        report_inventory=[dict(path=p.relative_to(self.output).as_posix(),**fingerprint(p))
                          for p in sorted(self.reports.rglob('*')) if p.is_file() and not p.is_symlink()]
        write(self.output/'producer-validation.json',dict(schemaVersion=1,kind='legacy-musl-sdk-candidate-validation',
            sdkVersion=self.sdk,targetRid=self.id['rid'],libc='musl',architecture=self.args.arch,
            projectCommit=self.project,sourceCommit=self.selected['installer'],sdkSourceCommit=self.selected['sdk'],
            runtimeSourceCommit=self.selected['runtimeCommit'],runId=self.args.run_id,runAttempt=self.args.run_attempt,
            status='diagnostic-only' if self.diagnostic else 'candidate-review-required',
            allRequiredStages=STAGES,qualificationAllowed=False,sourceAdmissionAllowed=False,
            sdkArchive=dict(name=self.archive.name,**fingerprint(self.archive)),reports=report_inventory,
            note='Publication, two-CPU official provenance, full used-source review and admission remain separate explicit gates.'))

    def seal(self):
        require(not self.diagnostic,'Diagnostic runs may never seal normal producer proof')
        for name in STAGES:
            require(json.loads((self.reports/'stages'/f'{name}.json').read_text()).get('status')=='passed',
                    'Required legacy producer stage did not pass: '+name)
        require((self.reports/'legacy-construction.json').is_file(),
                'Complete independent legacy construction evidence must be emitted before sealing')
        rows=[dict(path=p.relative_to(self.output).as_posix(),**fingerprint(p)) for p in sorted(self.output.rglob('*'))
              if p.is_file() and not p.is_symlink()]
        write(self.output/'producer-validation.json',dict(schemaVersion=2,kind='musl-sdk-producer-validation',producerRevision=1,
            status='passed',diagnosticPtrace=False,diagnosticPodman=False,sdkVersion=self.sdk,architecture=self.args.arch,
            targetRid=self.id['rid'],libc='musl',sourceCommit=self.selected['installer'],sdkSourceCommit=self.selected['sdk'],
            runtimeSourceCommit=self.selected['runtimeCommit'],projectCommit=self.project,runId=self.args.run_id,
            runAttempt=self.args.run_attempt,buildId=self.args.build_id,allRequiredStages=STAGES,files=rows,
            qualificationAllowed=False,sourceAdmissionAllowed=False,releaseAvailabilityAllowed=False))
        module('strict_legacy_admission','musl_legacy_admission.py').validate(self.output)


def validate(args):
    release=P.ordinary(args.release_dir)
    record=json.loads((release/'producer-validation.json').read_text())
    if record.get('kind')=='musl-sdk-producer-validation':
        module('strict_legacy_admission_cli','musl_legacy_admission.py').validate(release)
        for name,key in [('sdk_version','sdkVersion'),('arch','architecture'),('expected_project_commit','projectCommit'),
                         ('expected_run_id','runId'),('expected_run_attempt','runAttempt')]:
            value=getattr(args,name,None)
            if value is not None:require(record.get(key)==value,'Expected legacy producer identity differs: '+key)
        print(json.dumps(dict(status='validated-producer-proof',sourceAdmissionAllowed=False)))
        return
    raise ValueError('Diagnostic/candidate-only legacy records cannot qualify a normal producer or common receiver')


def validate_diagnostic_candidate(args):
    release=P.ordinary(args.release_dir)
    record=json.loads((release/'producer-validation.json').read_text())
    require(record.get('schemaVersion')==1 and record.get('kind')=='legacy-musl-sdk-candidate-validation' and
        record.get('qualificationAllowed') is False and record.get('sourceAdmissionAllowed') is False,
        'Only the explicit non-admitted legacy candidate record is accepted')
    require(record.get('sdkVersion')==args.sdk_version and record.get('architecture')==args.arch and
        record.get('projectCommit')==args.expected_project_commit and record.get('runId')==args.expected_run_id and
        record.get('runAttempt')==args.expected_run_attempt,'Legacy candidate source/run identity differs')
    require(record.get('targetRid')==P.identity(args.arch)['rid'] and record.get('allRequiredStages')==STAGES,
        'Legacy candidate target/stage identity differs')
    for name in STAGES:
        require(json.loads((release/'reports/stages'/f'{name}.json').read_text()).get('status')=='passed',
                'Legacy candidate stage did not actually pass: '+name)
    for row in record.get('reports',[]):
        relative=Path(row['path']);require(not relative.is_absolute() and '..' not in relative.parts,'Unsafe candidate evidence path')
        path=release/relative
        require(path.is_file() and not path.is_symlink() and all(row.get(k)==v for k,v in fingerprint(path).items()),
                'Bound candidate evidence changed: '+row['path'])
    sdk=record['sdkArchive'];path=release/sdk['name']
    require(path.parent==release and path.is_file() and not path.is_symlink() and
        all(sdk.get(k)==v for k,v in fingerprint(path).items()),'Bound genuine legacy SDK archive changed')
    smoke=json.loads((release/'reports/test/original-smoke/summary.json').read_text())
    require(smoke.get('total')==42 and smoke.get('passed')==41 and smoke.get('skipped')==1,
            'All original legacy smoke assertions must be observed')
    require(json.loads((release/'reports/verify/elf.json').read_text()).get('status')=='passed',
            'Complete native musl ELF audit must actually pass')
    print(json.dumps(dict(status='validated-candidate-only',sdkVersion=args.sdk_version,architecture=args.arch,
        qualificationAllowed=False,sourceAdmissionAllowed=False)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    run=sub.add_parser('run')
    run.add_argument('--sdk-version',choices=list(SPECS),required=True)
    run.add_argument('--arch',choices=['x64','aarch64'],required=True)
    for name in ['workspace','output-dir']:run.add_argument('--'+name,type=Path,required=True)
    for name in ['build-id','run-id','run-attempt']:run.add_argument('--'+name,required=True)
    run.add_argument('--host-reports',type=Path)
    run.add_argument('--diagnostic-podman',action='store_true')
    check=sub.add_parser('validate')
    check.add_argument('--sdk-version',choices=list(SPECS))
    check.add_argument('--arch',choices=['x64','aarch64'])
    check.add_argument('--release-dir',type=Path,required=True)
    for name in ['expected-project-commit','expected-run-id','expected-run-attempt']:check.add_argument('--'+name)
    capture=sub.add_parser('capture-failure-logs');capture.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='capture-failure-logs':P.capture_failure_logs(args.destination);return
    if args.command=='validate':validate(args);return
    require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*',args.build_id) and
        all(re.fullmatch('[1-9][0-9]*',value) for value in [args.run_id,args.run_attempt]),'Exact build/run identity required')
    Producer(args).execute()


if __name__=='__main__':
    main()
