"""Bounded x64 legacy identity, native ABI and signed-sysroot evidence fixtures."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(name, arch='x64'):
    with mock.patch.object(sys, 'argv', ['fixture', '--arch', arch]):
        return runpy.run_path(str(ROOT/'scripts'/(name+'.py')))


class LegacyX64Tests(unittest.TestCase):
    def test_bootstrap_and_analysis_pins_cannot_select_arm_archives(self):
        helper = module('ci_legacy_arch')
        for version in ('3.0.100', '3.1.422', '5.0.212', '9.0.121'):
            x64 = helper['sdk_pin'](version, 'x64'); arm = helper['sdk_pin'](version, 'arm64')
            self.assertTrue(x64['name'].endswith('-linux-x64.tar.gz'))
            self.assertNotEqual(x64['sha512'], arm['sha512'])
            self.assertEqual(len(x64['sha512']), 128)
        bootstrap = module('prepare-core30-bootstrap')
        self.assertEqual(bootstrap['SDK_BYTES'], 113463755)
        self.assertEqual(bootstrap['SDK_NAME'], 'dotnet-sdk-3.0.100-linux-x64.tar.gz')
        template = module('prepare-core30-template-inputs')['ARCHIVES']['3.0.100']
        self.assertEqual(template['sha512'], bootstrap['SDK_SHA512'])
        self.assertEqual(template['sha256'], '12098fe29d5c857fd6093b1fd63eda9f91b92798e3748fcedc0e0727f1ac01c2')
        self.assertEqual(module('prepare-core30-bootstrap', 'arm64')['SDK_BYTES'], 113669548)

    def test_native_platform_manifest_binding_rejects_arm_image(self):
        verifier = module('ci-legacy-verify'); digest = 'sha256:'+'a'*64
        row = {'Architecture':'amd64','Os':'linux','Digest':digest,
               'RepoDigests':['docker.io/library/ubuntu@'+digest]}
        self.assertEqual(verifier['manifest_reference'](row,'ubuntu'),'docker.io/library/ubuntu@'+digest)
        for architecture in ('arm64','x64','386'):
            with self.subTest(architecture=architecture), self.assertRaises(ValueError):
                verifier['manifest_reference'](dict(row,Architecture=architecture),'ubuntu')

    def test_complete_native_x64_sdk_checks_reject_foreign_machine_and_distro(self):
        verifier = module('ci-legacy-verify')
        archive = {'sha256':'a'*64,'bytes':123}
        result = {'verificationStatus':'passed','sdkVersion':'5.0.214','framework':'net5.0','reportedRid':'linux-x64',
            'functionalChecks':dict.fromkeys(verifier['FUNCTIONS'],'passed'),
            'archive':{'sha256':'a'*64,'sizeBytes':123,'sdkContentMatched':True},
            'abi':{'elfFileCount':20,'machines':{'Advanced Micro Devices X86-64':20},'glibcCeilingPassed':True,
                   'glibcCeiling':'2.23','symbolicGlibcRequirements':[],
                   'maximumRequiredVersions':{'GLIBC':'2.17','GLIBCXX':'3.4.21','CXXABI':'1.3.7'}}}
        verifier['check_verification']('net5','debian13',result,archive)
        bad = copy.deepcopy(result); bad['abi']['machines']={'AArch64':20}
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)
        bad = copy.deepcopy(result); bad['reportedRid']='linux-arm64'
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)
        bad = copy.deepcopy(result); bad['functionalChecks'].pop('frFrDecimalFormatting')
        with self.assertRaises(ValueError): verifier['check_verification']('net5','debian13',bad,archive)

    def test_x64_profiles_preserve_source_pins_without_historical_qualification(self):
        for version, family in [('5.0.214','net5'),('3.1.426','core31'),('3.0.103','core30')]:
            with self.subTest(version=version):
                arm = json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-arm64.json')).read_text())
                x64 = json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-x64.json')).read_text())
                self.assertEqual(x64['source'], arm['source'])
                self.assertEqual(x64['target']['rid'], 'linux-x64')
                self.assertEqual(x64['container']['architecture'], 'amd64')
                self.assertNotEqual(x64['container']['digest'], arm['container']['digest'])
                self.assertNotIn('verification',x64); self.assertNotIn('testing',x64)
                self.assertIn('pending',x64['status'])
                self.assertTrue(x64['build']['patches'])
                for item in x64['build']['patches']:
                    self.assertEqual(hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest(),item['sha256'])
                if family!='net5':
                    manifest = x64['build']['patchManifest']
                    self.assertEqual(hashlib.sha256((ROOT/manifest['path']).read_bytes()).hexdigest(),manifest['sha256'])

    def test_committed_profiles_pass_the_real_collector_direct_metadata_contract(self):
        collector=module('collect-artifacts'); validate=collector['direct_source_metadata']
        class ManifestBoundaryReached(Exception):pass
        with tempfile.TemporaryDirectory(prefix='legacy-profile-collector-') as temporary:
            source=Path(temporary).resolve()
            overrides={'git_output':lambda *args:str(source),'fixed_source_path':lambda *args:source/'Version.Details.xml',
                       'git_blob':mock.Mock(side_effect=ManifestBoundaryReached)}
            with mock.patch.dict(validate.__globals__,overrides):
                for version in ('5.0.214','3.1.426','3.0.103'):
                    for arch in ('arm64','x64'):
                        with self.subTest(version=version,arch=arch):
                            profile=json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-'+arch+'.json')).read_text())
                            # The real collector must accept all declared
                            # metadata before reaching source Git/blob I/O.
                            with self.assertRaises(ManifestBoundaryReached):validate(source,profile)
                            invalid=[]
                            for value in (None,'999.0.0'):
                                bad=copy.deepcopy(profile)
                                if value is None:bad['upstreamInputs'].pop('runtime')
                                else:bad['upstreamInputs']['runtime']=value
                                invalid.append((bad,'exact coordinated upstreamInputs.runtime'))
                            bad=copy.deepcopy(profile);bad.pop('legacySource');invalid.append((bad,'componentManifest'))
                            bad=copy.deepcopy(profile);bad['legacySource']['componentManifest']='wrong-manifest.xml';invalid.append((bad,'componentManifest'))
                            bad=copy.deepcopy(profile);bad['legacySource']['componentCommits'].pop(collector['DIRECT_SOURCE_CONTRACTS'][version]['components'][0]);invalid.append((bad,'critical component pins'))
                            bad=copy.deepcopy(profile);bad['legacySource']['componentCommits']['coreclr' if version.startswith('5.') else 'runtime']='0'*40;invalid.append((bad,'unified .NET 5 or split Core 3.x'))
                            for bad,message in invalid:
                                with self.assertRaisesRegex(collector['CollectionError'],message):validate(source,bad)

    def test_real_collector_preflight_validates_pinned_manifest_before_generated_exports(self):
        collector=module('collect-artifacts');validate=collector['direct_source_metadata']
        for version in ('5.0.214','3.1.426','3.0.103'):
            with self.subTest(version=version),tempfile.TemporaryDirectory(prefix='legacy-direct-preflight-') as temporary:
                source=Path(temporary).resolve();profile=json.loads((ROOT/'profiles'/('dotnet-'+version+'-linux-x64.json')).read_text())
                contract=collector['DIRECT_SOURCE_CONTRACTS'][version]
                manifest=ET.Element('Project');dependencies=ET.SubElement(manifest,'Dependencies')
                for name,commit in profile['legacySource']['componentCommits'].items():
                    dependency=ET.SubElement(dependencies,'Dependency',Name=name)
                    ET.SubElement(dependency,'Uri').text='https://github.com/dotnet/'+name
                    ET.SubElement(dependency,'Sha').text=commit
                manifest_bytes=ET.tostring(manifest)
                path=source/'eng/Version.Details.xml';path.parent.mkdir();path.write_bytes(manifest_bytes)
                layout={'OutputPath':'$(BaseOutputPath)$(Platform)/$(Configuration)/','ClonedSubmoduleDirectory':'$(BaseOutputPath)src/',
                        'GitInfoOutputDir':'$(BaseOutputPath)git-info/','BaseOutputPath':'$(ProjectDir)bin/' if contract['base']=='bin' else '$(ArtifactsDir)'}
                if contract['base']=='artifacts':layout['ArtifactsDir']='$(ProjectDir)artifacts/'
                properties=ET.Element('Project');group=ET.SubElement(properties,'PropertyGroup')
                for name,value in layout.items():ET.SubElement(group,name).text=value
                layout_bytes=ET.tostring(properties)
                def blob(root,commit,relative):
                    self.assertEqual(commit,contract['commit'])
                    return manifest_bytes if relative=='eng/Version.Details.xml' else layout_bytes
                with mock.patch.dict(validate.__globals__,{'git_output':lambda *args:str(source),'git_blob':blob}):
                    report=validate(source,profile,require_exports=False)
                    self.assertEqual(report['declaredComponentCommits'],profile['legacySource']['componentCommits'])
                    self.assertTrue(report['generatedComponentMetadataDeferred'])
                    self.assertEqual(set(report['criticalComponents']),set(contract['components']))
                    with self.assertRaises(collector['CollectionError']):validate(source,profile)
                    bad=copy.deepcopy(profile);bad['legacySource']['componentCommits'][contract['components'][0]]='f'*40
                    with self.assertRaisesRegex(collector['CollectionError'],'does not uniquely match'):
                        validate(source,bad,require_exports=False)

    def sysroot(self, temporary):
        root = Path(temporary)/'sysroot'; reports = Path(temporary)/'reports'; reports.mkdir(); root.mkdir()
        library = root/'lib/x86_64-linux-gnu/libc-2.23.so'; library.parent.mkdir(parents=True)
        data = bytearray(64); data[:6]=b'\x7fELF\x02\x01'; data[18:20]=(62).to_bytes(2,'little'); library.write_bytes(data)
        (library.parent/'libc.so.6').symlink_to(library.name)
        def row(path): return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        provenance = {'family':'core30','architecture':'amd64','sysroot':str(root),'method':'explicit-native-amd64-debootstrap',
            'originalGeneratorVerified':True,'packageSignatureVerification':True,'releaseSignatureLogVerified':True,'emulation':False}
        for key in ('producer','archiveRelease','archiveSignature','signatureStatus'):
            path=reports/key; path.write_bytes(('synthetic-'+key).encode()); provenance[key]=row(path)
        source=reports/'producer-ca.pem'; source.write_bytes(b'synthetic retained TLS trust bundle')
        retained=reports/'apt-tls-ca.pem'; retained.write_bytes(source.read_bytes())
        ca_info='/etc/ssl/certs/cbodotnet-producer-ca.pem'
        target=root/ca_info.lstrip('/'); target.parent.mkdir(parents=True); target.write_bytes(source.read_bytes())
        provenance['aptTls']={'source':row(source),'retained':row(retained),'target':row(target),'caInfo':ca_info,
            'peerVerification':True,'hostVerification':True,'packageSignatureVerification':True,
            'arguments':['-o','Acquire::https::CaInfo='+ca_info,'-o','Acquire::https::Verify-Peer=true','-o','Acquire::https::Verify-Host=true']}
        (reports/'sysroot-provenance.json').write_text(json.dumps(provenance))
        (reports/'sysroot-packages.tsv').write_text('libc6:amd64\t2.23-0ubuntu11.3\tamd64\n')
        (reports/'sysroot-symlinks.tsv').write_text(str(library.parent/'libc.so.6')+'\t'+library.name+'\n')
        def seal():
            manifest=reports/'sysroot-files.sha256'
            manifest.write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path)+'\n' for path in (library,target)))
            (reports/'sysroot-file-list.sha256').write_text(hashlib.sha256(manifest.read_bytes()).hexdigest()+'  '+str(manifest)+'\n')
        seal()
        return root,reports,library,seal

    def test_complete_sysroot_index_cannot_relabel_arm_libc_or_accept_extra_files(self):
        helper=module('verify-legacy-x64-sysroot')
        for mode in ('good','foreign-machine','extra-file','changed-producer','changed-ca','disabled-peer','different-ca-target'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='legacy-x64-sysroot-') as temporary:
                root,reports,library,seal=self.sysroot(temporary)
                if mode=='foreign-machine':
                    data=bytearray(library.read_bytes());data[18:20]=(183).to_bytes(2,'little');library.write_bytes(data);seal()
                if mode=='extra-file': (root/'unbound').write_bytes(b'not indexed')
                if mode=='changed-producer': (reports/'producer').write_bytes(b'not the captured producer')
                if mode=='changed-ca': (reports/'apt-tls-ca.pem').write_bytes(b'not the captured trust input')
                if mode in ('disabled-peer','different-ca-target'):
                    path=reports/'sysroot-provenance.json'; provenance=json.loads(path.read_text())
                    if mode=='disabled-peer': provenance['aptTls']['peerVerification']=False
                    else: provenance['aptTls']['target']['path']=str(root/'foreign-ca.pem')
                    path.write_text(json.dumps(provenance))
                args=['fixture','--family','core30','--sysroot',str(root),'--reports-dir',str(reports)]
                with mock.patch.object(sys,'argv',args),contextlib.redirect_stdout(io.StringIO()):
                    if mode=='good': helper['main']()
                    else:
                        with self.assertRaises(ValueError): helper['main']()

    def genapi(self, temporary):
        helper=module('ci-legacy-evidence'); release=Path(temporary)
        directory=release/'reports/build/product-build/genapi-validation'; directory.mkdir(parents=True)
        arcade='ce459ae07c3d7a1e68251268855e0bc7b3d97f75'; version='1.0.0-beta.19463.3'; source='/fixture/source'
        tool=source+'/bin/src/arcade.'+arcade+'/artifacts/bin/Microsoft.DotNet.GenAPI/Release/netcoreapp2.1/Microsoft.DotNet.GenAPI.dll'
        dotnet=source+'/.dotnet/dotnet'; reference='/fixture/refs/.NETFramework/v4.7.2/System.ComponentModel.DataAnnotations.dll'
        def raw(data):return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'sha512':hashlib.sha512(data).hexdigest()}
        bootstrap=[{'path':source+'/.dotnet/'+name,'bytes':20,'sha256':str(index+1)*64}
                   for index,name in enumerate(('dotnet','sdk/3.0.100/MSBuild.dll','sdk/3.0.100/.version'))]
        inputs={'status':'passed','sourceCommit':'40de72d1087a1d05dfd39c87f888a0611ec6c60f','sourceDirectory':source,
                'bootstrapVersion':'3.0.100','bootstrapExecutionVerified':True,'bootstrapFiles':bootstrap,
                'exports':[{'repository':'https://github.com/dotnet/arcade','commit':arcade,'directory':source+'/bin/src/arcade.'+arcade}]}
        inputs_path=directory.parent/'core30-inputs.json';inputs_path.write_text(json.dumps(inputs))
        config={'runtimeOptions':{'tfm':'netcoreapp2.1','framework':{'name':'Microsoft.NETCore.App','version':'2.1.0'},'rollForwardOnNoCandidateFx':2}}
        config_bytes=json.dumps(config).encode(); dll=b'synthetic fixture of a source-produced managed GenAPI payload'
        package=directory/('source-built-genapi-'+version+'.nupkg')
        with zipfile.ZipFile(str(package),'w') as archive:
            archive.writestr('Microsoft.DotNet.GenAPI.nuspec','<package><metadata><id>Microsoft.DotNet.GenAPI</id><version>'+version+'</version><repository commit="'+arcade+'"/></metadata></package>')
            archive.writestr('tools/netcoreapp2.1/Microsoft.DotNet.GenAPI.dll',dll)
            archive.writestr('tools/net472/Microsoft.DotNet.GenAPI.exe',b'synthetic unexecuted net472 payload')
            archive.writestr('tools/netcoreapp2.1/Microsoft.DotNet.GenAPI.runtimeconfig.json',config_bytes)
        generated=directory/'DataAnnotations.notsupported.cs';generated.write_text('class ValidationAttribute { /* PlatformNotSupported_GenApiProbe */ }\n'*4)
        header=bytearray(20);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62).to_bytes(2,'little')
        data={'status':'passed','arcadeCommit':arcade,'nativePlatform':{'system':'Linux','machine':'x86_64'},
            'nativeHelpExitCode':0,'actualGenerationExitCode':0,'hostConfigurationValid':True,'executedWindowsOutput':False,
            'verifiedBootstrapInputReport':helper['fp'](inputs_path),'verifiedBootstrapFiles':bootstrap,
            'verifiedBootstrapElf':{'class':64,'machine':62,'headerHex':header.hex(),'bootstrapSha256':bootstrap[0]['sha256']},
            'sourcePackageIdentity':{'id':'Microsoft.DotNet.GenAPI','version':version,'repositoryCommit':arcade},
            'sourceProducedPackage':dict(path=source+'/bin/src/arcade.'+arcade+'/artifacts/packages/Release/NonShipping/Microsoft.DotNet.GenAPI.'+version+'.nupkg',**helper['fp'](package)),
            'retainedSourcePackage':dict(path=str(package),**helper['fp'](package)),
            'actualTool':dict(path=tool,**raw(dll)),
            'originalRuntimeTemplate':{'sha256':'d036bb1552ba69491efe81cac1640b54d2a87f063893f556bbbb8deb244a1de0'},
            'runtimeConfiguration':dict(value=config,**raw(config_bytes)),
            'generatedSource':dict(path=str(generated),**helper['fp'](generated)),
            'generationInputReferenceAssembly':{'path':reference,'prebuiltReferenceInput':True}}
        arguments=[[dotnet,tool,'--help'],[dotnet,tool,reference,'--lib-path',str(Path(reference).parent)+';'+str(Path(reference).parent)+'/Facades',
                   '--out',str(generated),'--lang-version','preview','--throw','SR.PlatformNotSupported_GenApiProbe','--global']]
        data['commands']=[]
        for args,name,contents in zip(arguments,('genapi-help.log','genapi-generation.log'),('synthetic help fixture','')):
            path=directory/name;path.write_text(contents)
            data['commands'].append({'arguments':args,'exitCode':0,'logFingerprint':helper['fp'](path)})
        report=directory/'genapi-validation.json';report.write_text(json.dumps(data))
        return helper,release,directory,report,data,package

    def test_local_genapi_requires_bound_package_native_execution_and_generation_evidence(self):
        for mode in ('good','missing-report','changed-package','changed-log','foreign-machine','foreign-package','external-version','changed-generation'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='legacy-x64-genapi-') as temporary:
                helper,release,directory,report,data,package=self.genapi(temporary)
                if mode=='missing-report':report.unlink()
                if mode=='changed-package':package.write_bytes(b'changed local producer package')
                if mode=='changed-log':(directory/'genapi-help.log').write_text('unbound log')
                if mode=='foreign-machine':data['verifiedBootstrapElf']['machine']=183;report.write_text(json.dumps(data))
                if mode=='foreign-package':
                    with zipfile.ZipFile(str(package)) as archive: entries={item.filename:archive.read(item.filename) for item in archive.infolist()}
                    entries['Microsoft.DotNet.GenAPI.nuspec']=entries['Microsoft.DotNet.GenAPI.nuspec'].replace(b'ce459ae07c3d7a1e68251268855e0bc7b3d97f75',b'b'*40)
                    with zipfile.ZipFile(str(package),'w') as archive:
                        for name,payload in entries.items():archive.writestr(name,payload)
                    for row in (data['sourceProducedPackage'],data['retainedSourcePackage']):row.update(helper['fp'](package))
                    report.write_text(json.dumps(data))
                if mode=='external-version':data['sourcePackageIdentity']['version']='1.0.0-beta.20113.5';report.write_text(json.dumps(data))
                if mode=='changed-generation':(directory/'DataAnnotations.notsupported.cs').write_text('no real bound reference generation')
                if mode=='good':helper['core30_genapi_proof'](release)
                else:
                    with self.assertRaises(ValueError):helper['core30_genapi_proof'](release)

    def test_genapi_retention_reaches_the_actual_final_json_report_writer(self):
        verifier=module('verify-core30-genapi')
        with tempfile.TemporaryDirectory(prefix='legacy-x64-genapi-final-report-') as temporary:
            root=Path(temporary);source=root/'source';refs=root/'references';reports=root/'reports'
            for path in (source,refs,reports):path.mkdir()
            def put(path,data):
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return path
            def fingerprint(path):
                value=path.read_bytes();return {'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),'sha512':hashlib.sha512(value).hexdigest()}
            header=bytearray(64);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62).to_bytes(2,'little')
            dotnet=put(source/'.dotnet/dotnet',header)
            bootstrap=[dotnet,put(source/'.dotnet/sdk/3.0.100/MSBuild.dll',b'fixture MSBuild'),put(source/'.dotnet/sdk/3.0.100/.version',b'fixture version')]
            inputs={'status':'passed','sourceCommit':verifier['ROOT'],'sourceDirectory':str(source),'bootstrapVersion':'3.0.100',
                    'bootstrapExecutionVerified':True,'bootstrapFiles':[dict(path=str(path),**fingerprint(path)) for path in bootstrap]}
            input_report=put(root/'inputs.json',json.dumps(inputs).encode())
            component=source/('bin/src/arcade.'+verifier['ARCADE'])
            put(component/'.git/HEAD',verifier['ARCADE'].encode())
            template=b'{"rollForwardOnNoCandidateFx":2}'
            put(component/'src/Microsoft.DotNet.GenAPI/runtimeconfig.template.json',template)
            config={'runtimeOptions':{'tfm':'netcoreapp2.1','framework':{'name':'Microsoft.NETCore.App','version':'2.1.0'},'rollForwardOnNoCandidateFx':2}}
            dll=b'fixture actual locally built GenAPI';exe=b'fixture original unexecuted net472 GenAPI'
            put(component/'artifacts/bin/Microsoft.DotNet.GenAPI/Release/netcoreapp2.1/Microsoft.DotNet.GenAPI.dll',dll)
            put(component/'artifacts/bin/Microsoft.DotNet.GenAPI/Release/netcoreapp2.1/Microsoft.DotNet.GenAPI.runtimeconfig.json',json.dumps(config).encode())
            put(component/'artifacts/bin/Microsoft.DotNet.GenAPI/Release/net472/Microsoft.DotNet.GenAPI.exe',exe)
            package=component/('artifacts/packages/Release/NonShipping/Microsoft.DotNet.GenAPI.'+verifier['VERSION']+'.nupkg');package.parent.mkdir(parents=True)
            with zipfile.ZipFile(str(package),'w') as archive:
                archive.writestr('Microsoft.DotNet.GenAPI.nuspec','<package><metadata><id>Microsoft.DotNet.GenAPI</id><version>'+verifier['VERSION']+'</version><repository commit="'+verifier['ARCADE']+'"/></metadata></package>')
                for name,value in [('tools/netcoreapp2.1/Microsoft.DotNet.GenAPI.dll',dll),('tools/net472/Microsoft.DotNet.GenAPI.exe',exe),('tools/netcoreapp2.1/Microsoft.DotNet.GenAPI.runtimeconfig.json',json.dumps(config).encode())]:archive.writestr(name,value)
            put(refs/'.NETFramework/v4.7.2/System.ComponentModel.DataAnnotations.dll',b'fixture compilation reference only')
            private=root/'private';private.mkdir(mode=0o700)
            def run(arguments,cwd,environment,log,commands):
                log.write_bytes(b'fixture native execution log');commands.append({'exitCode':0})
                if '--out' in arguments:Path(arguments[arguments.index('--out')+1]).write_text('class ValidationAttribute { /* PlatformNotSupported_GenApiProbe */ }\n'*4)
            def write_json(path,value):
                # This is the real finally-path contract: a report Path must
                # survive the additional binary package retention operation.
                with path.open('x') as output:json.dump(value,output)
            helpers={'directory':lambda path:path,'ordinary_file':lambda path:path,'fingerprint':fingerprint,
                     'git':lambda *args:verifier['ROOT'].encode() if 'rev-parse' in args else template,
                     'now':lambda:'2026-11-01T00:00:00+00:00','run':run,'write_json':write_json}
            args=['fixture','--arch','x64','--source-dir',str(source),'--reference-root',str(refs),'--reports-dir',str(reports),'--input-report',str(input_report)]
            with mock.patch.object(sys,'argv',args),mock.patch.object(verifier['runpy'],'run_path',return_value=helpers),\
                    mock.patch.object(verifier['platform'],'system',return_value='Linux'),mock.patch.object(verifier['platform'],'machine',return_value='x86_64'),\
                    mock.patch.object(verifier['tempfile'],'mkdtemp',return_value=str(private)),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verifier['main'](),0)
            result=json.loads((reports/'genapi-validation.json').read_text())
            self.assertEqual(result['status'],'passed');self.assertEqual(result['verifiedBootstrapElf']['machine'],62)
            self.assertEqual(Path(result['retainedSourcePackage']['path']).read_bytes(),package.read_bytes())


if __name__=='__main__': unittest.main()
