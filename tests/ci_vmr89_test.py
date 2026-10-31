#!/usr/bin/env python3
"""Synthetic regression fixtures for version-specific CI evidence; no SDK build."""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import subprocess
import contextlib
import importlib.util
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import ci_vmr89_support as S
fence_spec=importlib.util.spec_from_file_location('fence_fixture',ROOT/'scripts/prepare-scenario-report-fence.py')
F=importlib.util.module_from_spec(fence_spec);fence_spec.loader.exec_module(F)


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data if isinstance(data,bytes) else data.encode());return path


def dump(path,data):
    return write(path,json.dumps(data)+'\n')


def trx(path,version):
    ns='{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}'
    root=ET.Element(ns+'TestRun');results=ET.SubElement(root,ns+'Results')
    total,passed=(46,44) if version=='8' else (522,522)
    if version=='9':
        names=list(S.N9.policy()['factMethods'])
        for method in S.N9.policy()['packageMethods']:
            for package in sorted(S.N9.available_ids()):
                display=package[:50]+'"···' if len(package)>50 else package+'"'
                names.append(method+'(packageName: "'+display+', testNugetPackagePath: "/vmr/fixture.nupkg", baselineNugetPackagePath: "/vmr/baseline.nupkg")')
    else:names=['Fixture.Test'+str(index) for index in range(passed)]
    for index,name in enumerate(names):
        ET.SubElement(results,ns+'UnitTestResult',executionId=str(index),outcome='Passed',testName=name)
    if version=='8':
        for index,name in enumerate(['LicenseScanTests.ScanForLicenses','PoisonTests.VerifyUsage']):
            ET.SubElement(results,ns+'UnitTestResult',executionId='skip'+str(index),outcome='NotExecuted',testName='Microsoft.DotNet.SourceBuild.SmokeTests.'+name)
    summary=ET.SubElement(root,ns+'ResultSummary')
    ET.SubElement(summary,ns+'Counters',total=str(total),executed=str(passed),passed=str(passed),failed='0')
    return write(path,ET.tostring(root))


def scenarios(path):
    root=ET.Element('assemblies');assembly=ET.SubElement(root,'assembly',total='34',passed='32',failed='0',skipped='2',errors='0')
    collection=ET.SubElement(assembly,'collection')
    for index in range(32): ET.SubElement(collection,'test',name='Scenario'+str(index),method='Method'+str(index),result='Pass')
    for method in sorted(S.G.SKIPS): ET.SubElement(collection,'test',name=method,method=method,result='Skip')
    return write(path,ET.tostring(root))


def archive(path,entries):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(path,'w:gz') as output:
        for name,data in entries.items():
            info=tarfile.TarInfo(name);info.size=len(data);output.addfile(info,io.BytesIO(data))
    return path


def package_case_inputs(source,release):
    S.N9.before_test(source,release)
    p=S.N9.policy();manifest=ET.Element('Build');paths=[]
    for row in p['sourceFiles']:
        write(source/row['path'],(ROOT/'tests/fixtures/net9-package-cases'/Path(row['path']).name).read_bytes())
    for name in p['shippingPackageIds']:
        ET.SubElement(manifest,'Package',Id=name,Version='9.0.22',RepoOrigin='fixture',DotNetReleaseShipping='true')
        filename=name+'.9.0.22.nupkg';paths.append('/vmr/artifacts/packages/Release/Shipping/fixture/'+filename)
        cache=source/S.N9.CACHE/filename;cache.parent.mkdir(parents=True,exist_ok=True)
        if name in p['unavailableBaselineIds']:cache.write_bytes(b'')
        else:
            with zipfile.ZipFile(cache,'w') as package:
                package.writestr(name+'.nuspec','<package><metadata><id>'+name+'</id><version>9.0.22</version></metadata></package>')
    write(source/'artifacts/VerticalManifest.xml',ET.tostring(manifest))
    dump(source/S.N9.CONFIG,dict(runtimeOptions=dict(configProperties={
        S.N9.PREFIX+'AssetManifestPath':'/vmr/artifacts/VerticalManifest.xml',
        S.N9.PREFIX+'LogsDirectory':'/vmr/artifacts/TestResults/Release',S.N9.PREFIX+'Packages':';'.join(paths)})))
    S.N9.capture(source,release)
    shutil.copytree(source/S.N9.CACHE,release/'reports/test/upstream-results/Microsoft.DotNet.UnifiedBuild.Tests/DownloadCache/NugetPackageBaselines')


def source_scan_inputs(source,release):
    source.mkdir()
    def git(*args):return subprocess.check_output(['git','-C',str(source),*args])
    git('init','-q');git('config','user.email','fixture@example.invalid');git('config','user.name','Fixture')
    write(source/'README',b'\x7fELF source fixture target')
    (source/'README.md').symlink_to('README')
    git('add','.');git('commit','-qm','Fixture source inventory')
    summary=S.write_source_header_inventory(source,release)
    summary['sourceCommit']=S.V['8']['commit']
    dump(release/'reports/scan/pinned-source-inventory.json',summary)
    return summary


class OriginFixture:
    def __init__(self,root,version):
        self.root,self.version=root,version
        self.source=root/'source';self.release=root/'delivery';self.candidate=root/'candidate'
        self.directory=self.release/'reports/construction';self.directory.mkdir(parents=True)
        runtime=S.V[version]['runtime'];self.records=[];tasks=[];sdk={}
        for index,(framework,prefix,component) in enumerate([('Microsoft.NETCore.App','dotnet-runtime-','runtime'),('Microsoft.AspNetCore.App','aspnetcore-runtime-','aspnetcore')]):
            basename=prefix+runtime+'-linux-arm64.tar.gz';contents={'shared/'+framework+'/'+runtime+'/fixture.dll':(framework+' fixture').encode(),
                'shared/'+framework+'/'+runtime+'/.version':((S.V['9']['commit'] if version=='9' and component=='runtime' else S.COMPONENTS[version][component])+'\n'+runtime+'\n').encode()};sdk.update(contents)
            path=archive(self.directory/('retained/'+str(index)+'.tar.gz'),contents)
            fp=S.record(self.release,path)
            local=component=='runtime' or version=='8'
            source='/vmr/artifacts/feed/'+basename if local else 'https://ci.dot.net/public/aspnetcore/Runtime/'+runtime+'-servicing.fixture/'+basename
            destination='/vmr/src/'+('installer' if version=='8' else 'sdk')+'/artifacts/obj/redist/Release/downloads/'+basename
            paths=[destination]
            if local: paths.extend([source,'/vmr/src/'+component+'/artifacts/packages/Release/Shipping/'+basename])
            for observed in paths: self.records.append(dict(recordedPath=observed,archive=fp,stableCompleteArchive=True))
            tasks.append(dict(context='context'+str(index),taskName='DownloadFile',succeeded=True,events=[
                {'kind':'task-started'},dict(kind='local-copy-attempt' if local else 'network-download-attempt',source=source,destination=destination),
                {'kind':'task-finished','succeeded':True}]))
        self.tasks=tasks
        dump(self.directory/'component-source-manifest.json',{'repositories':[{'path':name,'commitSha':value} for name,value in S.COMPONENTS[version].items()]})
        filename='cbodotnet-sdk-'+S.V[version]['sdk']+'-linux-arm64-build.1.tar.gz'
        archive(self.candidate/filename,sdk)
        dump(self.release/'reports/ci/candidate-build-manifest.json',{'sdkArchive':{'path':filename}})
        self.save()
        write(self.directory/'consumer.binlog',b'Fixture closed binlog: not a product run')
        dump(self.directory/'downloads-status.json',dict(completedReplay=True,buildSucceeded=True,completedDownloadTasks=2,
             inputSha256=S.fingerprint(self.directory/'consumer.binlog')['sha256']))

    def save(self):
        write(self.directory/'observations.jsonl',''.join(json.dumps(row)+'\n' for row in self.records))
        write(self.directory/'downloads-tasks.jsonl',''.join(json.dumps(row)+'\n' for row in self.tasks))


class FullFixture(OriginFixture):
    """Complete synthetic metadata bundle, never a claimed build result."""
    def __init__(self,root,version):
        super().__init__(root,version);S.construct(self.release,version,self.candidate)
        frozen=self.release/'reports/ci-inputs/project'
        for name in S.G.CRITICAL:write(frozen/name,'# Fixture committed source\n')
        profile=frozen/'profiles'/('dotnet-'+S.V[version]['sdk']+'-linux-arm64.json')
        original=json.loads((ROOT/'profiles'/profile.name).read_text());dump(profile,original)
        for name in ('Program.cs','Reader.csproj'):write(frozen/'scripts/ci-vmr89-reader'/name,'Fixture reader '+name+'\n')
        if version=='9':
            write(frozen/'scripts/prepare-scenario-report-fence.py',(ROOT/'scripts/prepare-scenario-report-fence.py').read_bytes())
            write(frozen/'scripts/ci-net9-test-cases.json',(ROOT/'scripts/ci-net9-test-cases.json').read_bytes())
        def git(*args):return subprocess.check_output(['git','-C',str(frozen),*args])
        git('init','-q');git('config','user.email','fixture@example.invalid');git('config','user.name','Fixture');git('add','.');git('commit','-qm','Fixture tree')
        commit=git('rev-parse','HEAD').decode().strip();commit_object=git('cat-file','commit',commit)
        rows=[]
        for entry in git('ls-files','--stage','-z').decode().split('\0'):
            if not entry:continue
            metadata,name=entry.split('\t',1);mode,blob,_=metadata.split();data=git('cat-file','blob',blob)
            rows.append(dict(S.record(self.release,frozen/name),gitMode=mode,gitBlobSha1=blob,**S.G.checkout_details(frozen,name,blob,data)))
        shutil.rmtree(frozen/'.git')
        self.identity=dict(sourceCommit=S.V[version]['commit'],projectCommit=commit,buildId='20261031.1',buildRevision='1',runId='12345',runAttempt='1')
        selected=S.effective(original,version);dump(self.release/'reports/ci-inputs/effective-profile.json',selected)
        write(self.release/'reports/ci-inputs/project-commit.txt',commit_object)
        dump(self.release/'reports/ci-inputs/snapshot.json',dict(self.identity,scenarioReportFenceRequired=version=='9',packageCaseCoverageRequired=version=='9',executionContext='github-actions',sourceInitiallyPristine=True,
             projectInitiallyPristine=True,inputRepresentation='canonical-git-blobs-with-verified-checkout',projectFiles=rows,
             projectCommitObject=S.record(self.release,self.release/'reports/ci-inputs/project-commit.txt'),originalProfile=S.record(self.release,profile),
             effectiveProfile=S.record(self.release,self.release/'reports/ci-inputs/effective-profile.json')))
        sysroot=self.release/'reports/sysroot';write(sysroot/'sysroot-prepare-fixture.log','I: Valid Release signature\n')
        dump(sysroot/'sysroot-provenance.json',dict(sourceCommit=S.V[version]['commit'],packageSignatureVerification=True,emulation=False,
             keyrings=[{}]*3,logFile='/reports/sysroot-prepare-fixture.log'))
        write(sysroot/'sysroot-files.sha256','a'*64+'  /inputs/arm64-xenial/lib/fixture.so\n')
        if version=='8':
            trx(self.release/'reports/test/upstream-results/smoke.trx','8');test_value=S.test_results(version,self.release/'reports/test/upstream-results/smoke.trx')
            scan=source_scan_inputs(root/'scan-source',self.release)
            dump(self.release/'reports/build/net8-patches-apply.json',dict(status='passed',patches=[{},{}]))
            dump(self.release/'reports/prepare/bootstrap/bootstrap-inputs.json',dict(sourceCommit=S.V[version]['commit'],bootstrapSdk=S.V[version]['bootstrap']))
        else:
            package_case_inputs(root/'case-source',self.release)
            path=self.release/'reports/test/package-cases-before.json';value=S.load(path);value['observedAtUtc']='2026-10-31T00:03:00.500000Z';dump(path,value)
            path=self.release/'reports/test/package-cases/coverage.json';value=S.load(path);value['capturedAtUtc']='2026-10-31T00:03:29.500000Z';dump(path,value)
            path=trx(self.release/'reports/test/upstream-results/Microsoft.DotNet.UnifiedBuild.Tests.trx','9')
            scenario=scenarios(self.release/'reports/test/upstream-results/scenario-tests/results.xml');test_value=S.test_results(version,path,scenario)
            dump(self.release/'reports/scan/upstream/status.json',dict(status='passed',exitCode=0,toolExitCode=0,teeExitCode=0,
                 sourceCommit=S.V[version]['commit'],cleanSourceCommit=S.V[version]['commit'],cleanPristineBefore=True,cleanPristineAfter=True,
                 allowlistsUnchanged=True,newBinariesReport={'exists':False}))
            original=(ROOT/'tests/fixtures/scenario-report-fence/Program.net9.original.cs').read_bytes()
            patched=F.patched_source(original,'9');directory=self.release/'reports/test/scenario-report-fence'
            write(directory/'Program.original.cs',original);write(directory/'Program.patched.cs',patched)
            dump(directory/'scenario-report-fence.json',dict(schemaVersion=1,status='passed',action='apply',version='9',
                 sourceCommit=F.PINS['9'][0],target=F.TARGET,changed=True,original=F.fingerprint(original),patched=F.fingerprint(patched),
                 helper=F.fingerprint((frozen/'scripts/prepare-scenario-report-fence.py').read_bytes()),completedAtUtc='2026-10-31T00:03:01Z'))
        dump(self.release/'reports/test/upstream-summary.json',test_value)
        for index,name in enumerate(('prepare','build','scan','test','verify')):
            commands=[['fixture',name]]
            if name=='test' and version=='9':
                commands.append(['podman','run','python3','/delivery/reports/ci-inputs/project/scripts/prepare-scenario-report-fence.py','apply',
                                 '--version','9','--source-dir','/vmr','--reports-dir','/delivery/reports/test/scenario-report-fence'])
            if name in ('build','test'):
                dump(self.release/'reports'/name/(name+'-status.json'),dict(action=name,exitCode=0,sourceCommit=S.V[version]['commit'],sourceOnly=S.V[version]['sourceOnly'],
                     startedAt='2026-10-31T00:%02d:01Z'%index,finishedAt='2026-10-31T00:%02d:29Z'%index))
            if name in ('prepare','build','test'):
                dump(self.release/'reports'/name/'sysroot-validation.json',dict(status='passed',files=1,symlinks=1,sourceCommit=S.V[version]['commit'],packageSignatureVerification=True,
                     provenance=S.fingerprint(sysroot/'sysroot-provenance.json'),log=S.fingerprint(sysroot/'sysroot-prepare-fixture.log')))
            if name=='verify':
                commands=[]
                for userland,(distribution,os_version,icu,ssl) in S.G.USERLANDS.items():
                    base='docker.io/library/'+distribution+'@sha256:'+'c'*64
                    tag='localhost/cbodotnet-net'+version+'-verify-'+userland+':12345-1'
                    dump(self.release/('reports/ci/'+userland+'-base-image.json'),[dict(Id='c'*64,Architecture='arm64',Os='linux',Digest='sha256:'+'c'*64,RepoDigests=[base])])
                    dump(self.release/('reports/ci/'+userland+'-verification-image.json'),[dict(Id='b'*64,Architecture='arm64',Os='linux',RepoTags=[tag])])
                    dump(self.release/('reports/ci/'+userland+'-userland.json'),dict(imageId='b'*64,architecture='aarch64',uid=1000,
                         osRelease={'ID':distribution,'VERSION_ID':os_version},installedPackages=dict.fromkeys([icu,ssl,'libc6','libstdc++6','zlib1g','libgssapi-krb5-2'],'fixture'),
                         environmentOverrides=dict.fromkeys(S.G.ENVIRONMENT_OVERRIDES,None)))
                    commands.extend([['podman','build','--build-arg','BASE_IMAGE='+base,'--tag',tag],['podman','run','--network=none','b'*64]])
            dump(self.release/('reports/ci/stages/'+name+'.json'),dict(self.identity,stage=name,status='passed',exitCode=0,commands=commands,imageId='a'*64,
                 nativeArchitecture='aarch64',uid=1000,startedAtUtc='2026-10-31T00:%02d:00Z'%index,finishedAtUtc='2026-10-31T00:%02d:30Z'%index))
        dump(self.release/'reports/prepare/build-image.json',[dict(Id='a'*64,Architecture='arm64',Os='linux')])
        reader=write(self.directory/'reader/Reader.dll',b'Fixture analysis tool bytes')
        dump(self.directory/'reader-inputs.json',dict(compilerSdk=S.V[version]['bootstrap'],sourceCommit=S.V[version]['commit'],reader=S.record(self.release,reader),
             sourceFiles=[S.record(self.release,frozen/'scripts/ci-vmr89-reader'/name) for name in ('Program.cs','Reader.csproj')]))
        roots=[dict(name='vmr',kind='git',expectedCommit=S.V[version]['commit'],path='/fixture/vmr')]
        if version=='8':roots.append(dict(name='consumer-runtime',kind='tree',path='/fixture/consumer',exclude=['artifacts']))
        dump(self.release/'reports/ci/source-roots.json',dict(roots=roots))
        dump(self.release/'sources/source-manifest.json',dict(fixtureOnly=True,roots=[dict(name='vmr',kind='git',commit=S.V[version]['commit'],tree=scan['sourceTree'])] if version=='8' else []))
        if version=='9':
            original=(ROOT/'tests/fixtures/scenario-report-fence/Program.net9.original.cs').read_bytes()
            write(self.release/'sources/source-index.jsonl',json.dumps(dict(path='vmr/'+F.TARGET,**F.fingerprint(F.patched_source(original,'9'))))+'\n')
        dump(self.release/'reports/ci/used-source.json',S.load(self.release/'sources/source-manifest.json'))
        candidate=S.load(self.release/'reports/ci/candidate-build-manifest.json')['sdkArchive']['path']
        shutil.copyfile(self.candidate/candidate,self.release/candidate)
        self.archive=dict(S.record(self.release,self.release/candidate),copiedWithoutModification=True)
        for algorithm in ('sha256','sha512'):write(self.release/(algorithm.upper()+'SUMS'),self.archive[algorithm]+'  '+candidate+'\n')
        for userland in S.G.USERLANDS:
            dump(self.release/('reports/verify-'+userland+'/verification.json'),dict(verificationStatus='passed',smokeStatus='passed',sdkVersion=S.V[version]['sdk'],
                 reportedRid='linux-arm64',hostArchitecture='aarch64',framework='net'+version+'.0',functionalChecks=dict.fromkeys(S.G.FUNCTIONS,'passed'),
                 archive=dict(sdkContentMatched=True,sha256=self.archive['sha256'],sizeBytes=self.archive['bytes']),
                 abi=dict(elfFileCount=1,machines={'AArch64':1},glibcCeiling='2.23',glibcCeilingPassed=True,symbolicGlibcRequirements=[],
                          maximumRequiredVersions={'GLIBC':'2.17','GLIBCXX':'3.4.21','CXXABI':'1.3.7'})))
        write(self.release/'collect.log','Fixture actual collector transcript\n')
        self.manifest=dict(sdkVersion=S.V[version]['sdk'],targetRid='linux-arm64',sourceOnly=S.V[version]['sourceOnly'],buildRevision='1',sdkArchive=self.archive,
                           source=dict(actualCommit=S.V[version]['commit'],commitVerified=True),construction=dict(upstreamSharedRuntimeReused=version=='9'),
                           profile=dict(contents=selected,**S.fingerprint(self.release/'reports/ci-inputs/effective-profile.json')),buildImage={'id':'a'*64},
                           rebuildInputs=[S.record(frozen,p) for folder in ('scripts','containers','patches') for p in (frozen/folder).rglob('*') if p.is_file()])
        self.seal()

    def seal(self):
        reports=self.release/'reports';self.manifest['reports']={'files':[S.record(reports,p) for p in sorted(S.G.tree_files(reports))]}
        dump(self.release/'build-manifest.json',self.manifest)
        dump(self.release/'collect-receipt.json',dict(self.identity,stage='collect',commands=[['fixture','collect']],imageId='a'*64,
             startedAtUtc='2026-10-31T00:05:00Z',finishedAtUtc='2026-10-31T00:05:30Z',status='passed',exitCode=0,
             manifest=S.record(self.release,self.release/'build-manifest.json'),log=S.record(self.release,self.release/'collect.log')))

    def args(self,stage='validate'):
        return SimpleNamespace(version=self.version,output_dir=self.release,project_root=None,stage=stage,
                               expected_project_commit=self.identity['projectCommit'],expected_run_id='12345',expected_run_attempt='1')


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).absolute()

    def tearDown(self): self.temp.cleanup()

    def test_net8_preserved_source_binlog_uses_original_producer_not_cleanup_copy(self):
        source=self.root/'source';release=self.root/'delivery'
        relative='src/installer/artifacts/source-build/self/src/artifacts/sourcebuild.binlog'
        original=write(source/relative,b'Closed producer binlog fixture')
        cleanup=source/'src/installer/artifacts/buildLogs/source-build/self/src/artifacts/sourcebuild.binlog'
        self.assertFalse(cleanup.exists())
        S.capture_consumer_binlog(source,release,'8')
        receipt=S.load(release/'reports/construction/binlog-input.json')
        self.assertEqual(receipt['sourceRelativePath'],relative)
        self.assertEqual((release/'reports/construction/consumer.binlog').read_bytes(),original.read_bytes())
        # A stale cleanup copy cannot substitute for a missing original producer.
        original.unlink();write(cleanup,b'Stale cleanup copy')
        with self.assertRaisesRegex(ValueError,'ordinary absolute file'):
            S.capture_consumer_binlog(source,self.root/'missing-original','8')

    def test_pristine_source_inventory_authenticates_symlinks_without_following(self):
        source=self.root/'source-symlinks';source.mkdir()
        def git(*args):return subprocess.check_output(['git','-C',str(source),*args])
        git('init','-q');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
        write(source/'README',b'\x7fELF fixture target, not executable test input')
        (source/'README.md').symlink_to('README')
        git('add','.');git('commit','-qm','Pinned file kinds')
        rows=S.pinned_source_header_inventory(source);by_name={row['path']:row for row in rows}
        self.assertEqual(by_name['README']['binaryHeader'],'ELF')
        link=by_name['README.md'];self.assertEqual(link['gitMode'],'120000');self.assertEqual(link['linkTarget'],'README')
        self.assertEqual(link['sha256'],S.G.byte_fingerprint(b'README')['sha256']);self.assertIsNone(link['binaryHeader'])
        # Hide ordinary status checks deliberately, then require the direct blob guard.
        git('update-index','--assume-unchanged','README.md')
        (source/'README.md').unlink();(source/'README.md').symlink_to('different-target')
        with self.assertRaisesRegex(ValueError,'symlink target differs'):
            S.pinned_source_header_inventory(source)
        (source/'README.md').unlink();(source/'README.md').write_text('README')
        with self.assertRaisesRegex(ValueError,'changed its Git entry kind'):
            S.pinned_source_header_inventory(source)

    def test_streamed_source_inventory_rejects_missing_duplicate_unsafe_or_unknown_entries(self):
        fixture=FullFixture(self.root/'source-scan','8')
        summary=S.load(fixture.release/'reports/scan/pinned-source-inventory.json')
        index=fixture.release/summary['files']['path'];original=index.read_text();rows=[json.loads(line) for line in original.splitlines()]
        for change in ('missing','duplicate','unsafe','unknown-mode'):
            values=copy.deepcopy(rows);current=copy.deepcopy(summary)
            if change=='missing':
                removed=values.pop();current['fileCount']-=1;current['gitModes'][removed['gitMode']]-=1
                current['binaryHeaderFiles']-=removed['binaryHeader'] is not None
            elif change=='duplicate':values.append(copy.deepcopy(values[0]))
            elif change=='unsafe':values[0]['path']='../outside'
            else:values[0]['gitMode']='160000'
            index.write_text(''.join(json.dumps(row)+'\n' for row in values))
            current['files']=S.record(fixture.release,index)
            with self.assertRaises(ValueError):S.validate_source_header_inventory(fixture.release,current)
        index.write_text(original)
        S.validate_source_header_inventory(fixture.release,summary)

    def test_new_net9_gate_requires_exact_report_fence_and_actual_invocation(self):
        fixture=FullFixture(self.root/'fence','9')
        S.qualify(fixture.args())
        receipt=fixture.release/'reports/test/scenario-report-fence/scenario-report-fence.json'
        value=S.load(receipt);value['changed']=False;dump(receipt,value);fixture.seal()
        with self.assertRaisesRegex(ValueError,'fresh pinned XML'):
            S.qualify(fixture.args('verify-release'))
        value['changed']=True;dump(receipt,value)
        stage=fixture.release/'reports/ci/stages/test.json';value=S.load(stage);value['commands']=[['fixture','test']];dump(stage,value);fixture.seal()
        with self.assertRaisesRegex(ValueError,'Exactly one actual pinned'):
            S.qualify(fixture.args('verify-release'))

    def test_downloaded_scenario_helper_is_never_executed(self):
        fixture=FullFixture(self.root/'malicious-helper','9')
        marker=self.root/'artifact-code-executed'
        helper=fixture.release/'reports/ci-inputs/project/scripts/prepare-scenario-report-fence.py'
        helper.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\nraise Exception("artifact code ran")\n')
        stage=S.load(fixture.release/'reports/ci/stages/test.json')
        with self.assertRaisesRegex(ValueError,'receipt fingerprints differ'):
            S.scenario_fence(fixture.release,stage,helper)
        self.assertFalse(marker.exists())

    def test_scenario_fence_must_match_captured_used_source(self):
        fixture=FullFixture(self.root/'wrong-runner-source','9')
        write(fixture.release/'sources/source-index.jsonl',json.dumps(dict(path='vmr/'+F.TARGET,bytes=1,sha256='0'*64,sha512='0'*128))+'\n')
        fixture.seal()
        with self.assertRaisesRegex(ValueError,'Captured actual scenario runner'):
            S.qualify(fixture.args())

    def test_actual_result_shapes_both_versions(self):
        self.assertEqual(S.test_results('8',trx(self.root/'8.trx','8'))['passed'],44)
        result=S.test_results('9',trx(self.root/'9.trx','9'),scenarios(self.root/'scenario.xml'))
        self.assertEqual(result['passed'],522);self.assertEqual(result['scenarios']['passed'],32)

    def test_net9_exact_case_pairs_reject_count_preserving_substitution_and_missing_fact(self):
        ns={'t':'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
        for change in ('duplicate-pair','wrong-package','missing-fact'):
            path=trx(self.root/(change+'.trx'),'9');tree=ET.parse(path);rows=tree.findall('./t:Results/t:UnitTestResult',ns)
            if change=='duplicate-pair':rows[2].set('testName',rows[3].get('testName'))
            elif change=='wrong-package':rows[2].set('testName',rows[2].get('testName').replace('packageName: "','packageName: "Unknown.',1))
            else:rows[0].set('testName',rows[1].get('testName'))
            tree.write(path)
            with self.assertRaisesRegex(ValueError,'Duplicate NET9|Unexpected or ambiguous NET9'):
                S.test_results('9',path,scenarios(self.root/(change+'.xml')))

    def test_net9_fixed_baseline_absences_and_pinned_sources_are_required(self):
        release=self.root/'case-evidence';source=self.root/'case-inputs';package_case_inputs(source,release)
        self.assertEqual(S.N9.validate(release)['availableBaselines'],260)
        with self.assertRaisesRegex(ValueError,'must be absent'):
            S.N9.before_test(source,self.root/'reused-cache')
        path=release/'reports/test/package-cases/coverage.json';receipt=S.load(path)
        available=next(row for row in receipt['cacheRows'] if row['available']);available['available']=False;available['bytes']=0;dump(path,receipt)
        with self.assertRaisesRegex(ValueError,'identity/absence differs'):
            S.N9.validate(release)
        available['available']=True;available['bytes']=1;dump(path,receipt)
        original=release/'reports/test/package-cases/source/NugetPackageDownloadHelpers.cs';original.write_bytes(original.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'Pinned package comparison source bytes differ'):
            S.N9.validate(release)

    def test_standalone_frozen_helpers_never_add_bytecode_files(self):
        for entry in ('ci-vmr89.py','ci_vmr89_support.py'):
            with self.subTest(entry=entry):
                directory=self.root/entry/'scripts';directory.mkdir(parents=True)
                names=['ci-vmr89.py','ci_vmr89_support.py','ci-net10-evidence.py','ci_net9_cases.py','ci-net9-test-cases.json']
                for name in names:shutil.copyfile(ROOT/'scripts'/name,directory/name)
                before={path.relative_to(directory).as_posix() for path in directory.rglob('*') if path.is_file()}
                environment=os.environ.copy();environment.pop('PYTHONDONTWRITEBYTECODE',None);environment.pop('PYTHONPYCACHEPREFIX',None)
                result=subprocess.run([sys.executable,str(directory/entry),'--help'],env=environment,
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
                self.assertEqual(result.returncode,0,result.stderr)
                after={path.relative_to(directory).as_posix() for path in directory.rglob('*') if path.is_file()}
                self.assertEqual(after,before)
                self.assertFalse(list(directory.rglob('__pycache__')))

    def test_complete_version_gates_and_portable_reread(self):
        for version in ('8','9'):
            fixture=FullFixture(self.root/version,version)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(S.qualify(fixture.args()),0);self.assertEqual(S.qualify(fixture.args('verify-release')),0)

    def test_portable_gate_accepts_later_trusted_checkout_without_skipping_frozen_authentication(self):
        fixture=FullFixture(self.root/'portable-producer','8')
        frozen=fixture.release/'reports/ci-inputs/project';project=self.root/'trusted-checkout';shutil.copytree(frozen,project)
        def git(*args,input=None):return subprocess.check_output(['git','-C',str(project),*args],input=input)
        git('init','-q');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid');git('add','.')
        original_commit=(fixture.release/'reports/ci-inputs/project-commit.txt').read_bytes()
        git('write-tree');actual=git('hash-object','-t','commit','-w','--stdin',input=original_commit).decode().strip()
        self.assertEqual(actual,fixture.identity['projectCommit']);git('update-ref','HEAD',actual)
        live=fixture.args();live.project_root=project
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(S.qualify(live),0)
        target=project/'scripts/ci-net10.sh';target.write_text(target.read_text()+'\n# Uncommitted live change\n')
        with self.assertRaisesRegex(ValueError,'does not clean'):
            S.qualify(live)
        git('add','.');git('commit','-qm','Later trusted verifier checkout')
        self.assertNotEqual(git('rev-parse','HEAD').decode().strip(),fixture.identity['projectCommit'])
        with self.assertRaisesRegex(ValueError,'Live orchestration commit differs'):
            S.qualify(live)
        portable=fixture.args('verify-release');portable.project_root=project
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(S.qualify(portable),0)
        original=frozen/'scripts/ci-net10.sh';original.write_text(original.read_text()+'\n# Forged old frozen input\n')
        with self.assertRaisesRegex(ValueError,'Evidence digest mismatch'):
            S.qualify(portable)

    def test_complete_gate_rejects_sdk_tamper_and_missing_used_source(self):
        fixture=FullFixture(self.root,'8');source=fixture.release/'sources/source-manifest.json';original=source.read_bytes();source.unlink()
        with self.assertRaises(ValueError):S.qualify(fixture.args())
        source.write_bytes(original);write(fixture.release/fixture.archive['path'],b'changed SDK')
        with self.assertRaisesRegex(ValueError,'digest mismatch'):S.qualify(fixture.args())

    def test_omitted_raw_result_rejected(self):
        path=trx(self.root/'8.trx','8');root=ET.parse(path).getroot();results=root.find('{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}Results');results.remove(results[0]);path.write_bytes(ET.tostring(root))
        with self.assertRaisesRegex(ValueError,'Incomplete actual'):S.test_results('8',path)

    def test_unapproved_skip_rejected(self):
        path=trx(self.root/'8.trx','8');root=ET.parse(path).getroot();root.find('{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}Results')[-1].set('testName','Unexpected.Skip');path.write_bytes(ET.tostring(root))
        with self.assertRaisesRegex(ValueError,'failures/skips'):S.test_results('8',path)

    def test_scenario_result_drift_rejected(self):
        path=scenarios(self.root/'scenario.xml');root=ET.parse(path).getroot();root.findall('./assembly/collection/test')[-1].set('method','UnexpectedSkip');path.write_bytes(ET.tostring(root))
        with self.assertRaisesRegex(ValueError,'Scenario failures'):S.test_results('9',trx(self.root/'9.trx','9'),path)

    def test_effective_profiles_remove_historical_success_text_only(self):
        for version in ('8','9'):
            profile=json.loads((ROOT/'profiles'/('dotnet-'+S.V[version]['sdk']+'-linux-arm64.json')).read_text())
            before=copy.deepcopy(profile);after=S.effective(profile,version)
            self.assertEqual(profile,before);self.assertEqual(after['source'],profile['source'])
            self.assertEqual(after['build']['sourceOnly'],profile['build']['sourceOnly'])
            self.assertEqual(after['construction']['upstreamSharedRuntimeReused'],profile['construction']['upstreamSharedRuntimeReused'])
            self.assertEqual(after['build']['cleanWhileBuilding'],version!='8')
            self.assertNotIn('8c9ab2',after['construction']['note'])

    def test_both_complete_origin_shapes_and_portable_reread(self):
        for version in ('8','9'):
            fixture=OriginFixture(self.root/version,version);S.construct(fixture.release,version,fixture.candidate)
            first=S.load(fixture.directory/'origin-evidence.json');self.assertEqual(S.origin_value(fixture.release,version),first)
            self.assertEqual([row['origin'] for row in first['components']],['locally-built','locally-built' if version=='8' else 'upstream-download'])
            for component,row in zip(('runtime','aspnetcore'),first['components']):
                if version=='8':
                    self.assertEqual(row['sourceRevision'],S.COMPONENTS[version][component])
                    self.assertNotIn('componentSourceRevision',row);self.assertNotIn('versionMarkerNamespace',row)
                else:
                    self.assertEqual(row['componentSourceRevision'],S.COMPONENTS[version][component])
                    vmr=component=='runtime'
                    self.assertEqual(row['versionMarkerNamespace'],'vmr-root' if vmr else 'component')
                    self.assertEqual(row['versionMarkerRevision'],S.V[version]['commit'] if vmr else S.COMPONENTS[version][component])

    def test_legacy_net8_origin_shape_stays_byte_stable_when_recomputed(self):
        fixture=OriginFixture(self.root/'legacy8','8');S.construct(fixture.release,'8',fixture.candidate)
        path=fixture.directory/'origin-evidence.json';original=path.read_bytes();legacy=S.load(path)
        for row in legacy['components']:
            self.assertEqual(set(row),{'framework','origin','originVerified','context','inputArchive','actualAttempt',
                                      'identicalEntries','sourceRevision','versionMarker'})
        rechecked=S.origin_value(fixture.release,'8')
        self.assertEqual(rechecked,legacy)
        self.assertEqual((json.dumps(rechecked,indent=2)+'\n').encode(),original)

    def test_candidate_without_copy_or_download_is_not_origin(self):
        fixture=OriginFixture(self.root,'8');fixture.tasks[0]['events'].pop(1);fixture.save()
        with self.assertRaisesRegex(ValueError,'DownloadFile'):S.construct(fixture.release,'8',fixture.candidate)

    def test_failed_task_is_not_origin(self):
        fixture=OriginFixture(self.root,'9');fixture.tasks[1]['succeeded']=False;fixture.save()
        with self.assertRaisesRegex(ValueError,'No completed consumed'):S.construct(fixture.release,'9',fixture.candidate)

    def test_feed_copy_without_actual_component_producer_is_not_local_origin(self):
        fixture=OriginFixture(self.root,'8');fixture.records=[row for row in fixture.records if not row['recordedPath'].startswith('/vmr/src/runtime/artifacts/')];fixture.save()
        with self.assertRaisesRegex(ValueError,'component producer'):S.construct(fixture.release,'8',fixture.candidate)

    def test_mutated_retained_input_rejected(self):
        fixture=OriginFixture(self.root,'8');write(fixture.directory/'retained/0.tar.gz',b'changed compressed bytes')
        with self.assertRaises((ValueError,tarfile.TarError)):S.construct(fixture.release,'8',fixture.candidate)

    def test_incomplete_replay_is_not_origin(self):
        fixture=OriginFixture(self.root,'9');status=S.load(fixture.directory/'downloads-status.json');status['completedReplay']=False;dump(fixture.directory/'downloads-status.json',status)
        with self.assertRaisesRegex(ValueError,'complete successful'):S.construct(fixture.release,'9',fixture.candidate)

    def test_matching_framework_bytes_with_wrong_source_revision_are_rejected(self):
        for version,component,index,framework,basename in [('9','runtime',0,'Microsoft.NETCore.App','dotnet-runtime-'),
            ('9','aspnetcore',1,'Microsoft.AspNetCore.App','aspnetcore-runtime-'),
            ('8','runtime',0,'Microsoft.NETCore.App','dotnet-runtime-'),('8','aspnetcore',1,'Microsoft.AspNetCore.App','aspnetcore-runtime-')]:
            fixture=OriginFixture(self.root/(version+'-'+component),version);runtime=S.V[version]['runtime'];prefix='shared/'+framework+'/'+runtime+'/'
            path=fixture.directory/('retained/'+str(index)+'.tar.gz')
            with tarfile.open(path) as tar:entries={member.name:tar.extractfile(member).read() for member in tar if member.isfile()}
            # Even a real source SHA is rejected when it names the wrong Git namespace.
            wrong=S.COMPONENTS['9']['runtime'] if version=='9' and component=='runtime' else S.V[version]['commit']
            entries[prefix+'.version']=(wrong+'\n'+runtime+'\n').encode();archive(path,entries)
            for row in fixture.records:
                if row['recordedPath'].endswith('/'+basename+runtime+'-linux-arm64.tar.gz'):row['archive']=S.record(fixture.release,path)
            filename=S.load(fixture.release/'reports/ci/candidate-build-manifest.json')['sdkArchive']['path'];sdk_path=fixture.candidate/filename
            with tarfile.open(sdk_path) as tar:sdk={member.name:tar.extractfile(member).read() for member in tar if member.isfile()}
            sdk[prefix+'.version']=entries[prefix+'.version'];archive(sdk_path,sdk);fixture.save()
            with self.assertRaisesRegex(ValueError,'revision does not match delivered'):S.construct(fixture.release,version,fixture.candidate)

    def test_observer_preserves_real_complete_archives_and_actual_paths(self):
        source=self.root/'source';release=self.root/'delivery';basename='dotnet-runtime-8.0.33-linux-arm64.tar.gz'
        produced=archive(source/'src/runtime/artifacts/packages/Release/Shipping'/basename,{'shared/Microsoft.NETCore.App/8.0.33/core.dll':b'fixture payload'})
        feed=source/'artifacts/feed'/basename;feed.parent.mkdir(parents=True);shutil.copyfile(produced,feed)
        observer=S.Observer(source,release,'8');observer.start()
        deadline=time.monotonic()+5
        path=release/'reports/construction/observations.jsonl'
        while time.monotonic()<deadline:
            if path.exists() and len(path.read_text().splitlines())>=2:break
            time.sleep(.05)
        produced.unlink()
        observer.finish();rows=[json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(len(rows),2);self.assertEqual(len({row['archive']['sha256'] for row in rows}),1)
        self.assertTrue(any(row['recordedPath'].startswith('/vmr/src/runtime/') for row in rows))
        for row in rows:S.checked(release,row['archive'])

    def test_consumer_source_exclusions_never_hide_tracked_source(self):
        source=self.root/'source';write(source/'src/runtime/bin/source-tool.sh','original tracked source\n')
        generated=source/'src/runtime/artifacts/source-build/self/src';generated.mkdir(parents=True)
        for args in [('init','-q'),('add','src/runtime/bin/source-tool.sh')]:subprocess.check_call(['git','-C',str(source),*args])
        roots,ledger=S.consumer_roots(source,'8')
        self.assertNotIn('bin',roots[1]['exclude']);self.assertIn('artifacts',roots[1]['exclude'])
        row=next(row for row in ledger if row['prefix']=='bin');self.assertTrue(row['originalTrackedSourcePresent'])


if __name__=='__main__':unittest.main()
