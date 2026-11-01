#!/usr/bin/env python3
"""Synthetic portable gate contracts; these files never qualify an actual SDK.

Real builds, native execution, signature verification and binlog replay are not
performed here. The fixture uses a real Git snapshot and the production origin
report assembler, then exercises the complete portable report-schema gate.
The source archive verifier has its own independent source_delivery_test suite.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('net67_delivery_helpers', ROOT/'tests/ci_net67_test.py')
H = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(H)
E = H.E


class CompleteGeneratedDeliveryTests(unittest.TestCase):
    def json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2)+'\n')

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value); return path

    def fixture(self, root, major):
        selected=E.VERSIONS[major]
        run=H.GeneratedSourceCiTests().origin_fixture(root,major)
        release=run.output; reports=run.reports
        project=root/'project'; (project/'profiles').mkdir(parents=True)
        def git(*args): return subprocess.check_output(['git','-C',str(project),*args],stderr=subprocess.PIPE).decode().strip()
        git('init','-q'); git('config','user.name','Synthetic gate fixture'); git('config','user.email','fixture@example.invalid')
        original=ROOT/'profiles'/('dotnet-'+selected['sdk']+'-linux-aarch64.json')
        shutil.copyfile(original, project/'profiles'/original.name)
        (project/'fixture.py').write_text('# Synthetic gate fixture only.\n')
        git('add','.'); git('commit','-qm','Synthetic orchestration snapshot')
        identity=dict(projectCommit=git('rev-parse','HEAD'),runId='123',runAttempt='1',buildId='20261101.1',buildRevision='123')
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):
            snapshot=E.freeze(project,release,major,identity)
        profile=E.load(reports/'ci-inputs/effective-profile.json')
        generation=dict(installerCommit=selected['commit'],preserveTarballGitFolders=True,
                        componentCommits=profile['generatedSource']['componentCommits'])
        self.json(reports/'generation/generation.json',generation)
        replay=E.load(reports/'origin-tools/replay.json'); replay['eventsRead']=100
        self.json(reports/'origin-tools/replay.json',replay)
        sdk_source=run.source/'artifacts/arm64/Release'/('dotnet-sdk-'+selected['sdk']+'-linux-arm64.tar.gz')
        def inspector(*args,**kwargs):
            comparison={'status':'passed','sdkArchive':dict(path=str(sdk_source),bytes=sdk_source.stat().st_size,
                        sha256=E.fingerprint(sdk_source)['sha256']), 'comparisons':[]}
            for framework in ['Microsoft.NETCore.App','Microsoft.AspNetCore.App']:
                entries={'fixture.dll':{'type':'file','bytes':1,'sha256':'f'*64}}
                comparison['comparisons'].append(dict(framework=framework,version=selected['runtime'],
                    sdkEntryCount=1,inputEntryCount=1,identical=True,sdkEntries=entries,inputEntries=copy.deepcopy(entries)))
            self.json(reports/'construction/identity/shared-framework-identity.json',comparison)
        run.container=inspector; run.origin()
        for name in ['build','test']:
            self.json(reports/name/(name+'-status.json'),dict(action=name,exitCode=0,installerCommit=selected['commit'],
                      sourceOnly=True,portableBuild=True,crossBuild=True))
        stages={}
        image='c'*64
        for name in ['prepare','build','scan','test','verify']:
            stages[name]=dict(stage=name,status='passed',exitCode=0,commands=[['fixture-'+name]],
                              sourceCommit=selected['commit'],imageId=image,**identity)
        self.json(reports/'scan/applicability.json',dict(status='not-applicable',reason='Synthetic legacy scanner applicability contract.'))
        base=self.put(reports/'prepare/seccomp-base-policy.json',b'{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}\n')
        policy=self.put(reports/'prepare/seccomp-policy.json',base.read_bytes())
        self.json(reports/'prepare/seccomp.json',dict(seccompUnconfined=False,allOtherRulesUnchanged=True,
                  addedRuleCount=0,basePolicy=E.fingerprint(base),outputPolicy=E.fingerprint(policy)))
        log=self.put(reports/'sysroot/sysroot-build.log',b'Synthetic fixture: Valid Release signature\n')
        self.json(reports/'sysroot/sysroot-provenance.json',dict(sourceCommit=selected['commit'],
                  runtimeCommit=generation['componentCommits']['runtime'],packageSignatureVerification=True,
                  emulation=False,logFile='/delivery/reports/sysroot/'+log.name))
        self.json(reports/'sysroot/current-validation.json',dict(status='passed',files=1,symlinks=1))
        keyrings=[]
        for number in range(3):
            key=self.put(reports/'sysroot/producer-inputs'/('fixture-'+str(number)+'.gpg'),b'not a signing key; test-only fixture')
            keyrings.append(E.record(release,key))
        self.json(reports/'sysroot/producer-inputs.json',dict(keyrings=keyrings))
        self.json(reports/'bootstrap/bootstrap-inputs.json',dict(installerCommit=selected['commit'],bootstrapSdk=selected['bootstrap'],
                  originalInputs=[dict(bytes=selected['psbSize'],sha256=selected['psbSha256'])],
                  finalInputs=[dict(scope='Synthetic transformed-input contract')],arm64PackageEntries=[dict(scope='Synthetic native-entry contract')]))
        H.GeneratedSourceCiTests().make_trx(reports/'test/upstream.trx')
        self.json(reports/'test'/('net'+major+'-test-tools.json'),dict(status='passed',scope='Synthetic test fixture; no OmniSharp execution.'))
        self.json(reports/'test-inputs/official-sdk-baseline.json',dict(version=selected['sdk'],bytes=selected['baselineSize'],sha512=selected['baselineSha512']))
        actual=self.put(reports/'test/comparison/UpdatedMsftToSbSdk.diff',b'Synthetic current layout diff\n')
        baseline=self.put(reports/'test/comparison/MsftToSbSdk.diff',b'Synthetic upstream expected layout diff\n')
        self.json(reports/'test/comparison/summary.json',dict(warningMode=True,actualDiff=E.record(release,actual),baselineDiff=E.record(release,baseline)))
        raw=self.put(reports/'prebuilt/prebuilt-usage.xml',b'<Usages/>\n')
        self.json(reports/'prebuilt/summary.json',dict(preservedRawReports=[E.record(release,raw)],scope='Synthetic prebuilt-report schema only.'))
        archive=self.put(release/('cbodotnet-sdk-'+selected['sdk']+'-linux-arm64-build.123.tar.gz'),sdk_source.read_bytes())
        archive_row=E.record(release,archive)
        for name,rid in zip(['ubuntu22','ubuntu24','debian13'],selected['rids']):
            user_image={'ubuntu22':'1','ubuntu24':'2','debian13':'3'}[name]*64
            abi=dict(elfFileCount=22,machines={'AArch64':22},maximumRequiredVersions={'GLIBC':'2.17','GLIBCXX':'3.4.21','CXXABI':'1.3.7'},
                     glibcCeiling='2.23',glibcCeilingPassed=True)
            self.json(reports/('verify-'+name)/'verification.json',dict(verificationStatus='passed',sdkVersion=selected['sdk'],
                      reportedRid=rid,framework='net'+major+'.0',functionalChecks=dict.fromkeys(E.CHECKS,'passed'),abi=abi,
                      archive=dict(sha256=archive_row['sha256'],sdkContentMatched=True),scope='Synthetic native-report contract only.'))
            os_id,os_version=('ubuntu','22.04') if name=='ubuntu22' else ('ubuntu','24.04') if name=='ubuntu24' else ('debian','13')
            self.json(reports/'ci'/(name+'-userland.json'),dict(imageId=user_image,architecture='aarch64',uid=1001,
                      osRelease={'ID':os_id,'VERSION_ID':os_version},environmentOverrides=dict.fromkeys(
                      ['LD_LIBRARY_PATH','DOTNET_ROOT','DOTNET_SYSTEM_GLOBALIZATION_INVARIANT','CLR_ICU_VERSION_OVERRIDE','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics'])))
            self.json(reports/'ci'/(name+'-verification-image.json'),[dict(Id=user_image,Architecture='arm64',Os='linux')])
            stages['verify']['commands'].append(['sudo','podman','run','--network=none',user_image,'bash','verify-sdk.sh'])
        for name,stage in stages.items():self.json(reports/'ci/stages'/(name+'.json'),stage)
        # The separate source-delivery test suite verifies real source archives.
        # This fixture checks that the family gate binds the same raw control.
        source_control=dict(schemaVersion=1,scope='Synthetic family gate control only; not an actual used-source archive.')
        self.json(release/'sources/source-manifest.json',source_control)
        self.json(reports/'ci/used-source.json',source_control)
        frozen=snapshot['projectFiles'][0]
        manifest=dict(sdkVersion=selected['sdk'],targetRid='linux-arm64',sourceOnly=True,profile={'contents':profile},
                      source={'actualCommit':selected['commit']},buildImage={'id':image},sdkArchive=archive_row,
                      rebuildInputs=[dict(path=frozen['path'].removeprefix('reports/ci-inputs/project/'),
                                         **{key:frozen[key] for key in ['bytes','sha256','sha512']})],reports={'files':[]})
        self.json(release/'build-manifest.json',manifest)
        for algorithm,name in [('sha256','SHA256SUMS'),('sha512','SHA512SUMS')]:
            self.put(release/name,(archive_row[algorithm]+'  '+archive_row['path']+'\n').encode())
        collect_log=self.put(release/'collect.log',b'Synthetic collection log only\n')
        collect_commands=self.put(release/'collect-commands.jsonl',b'["synthetic-collector"]\n')
        self.json(release/'collect-receipt.json',dict(status='passed',exitCode=0,**identity,
                  manifest=E.record(release,release/'build-manifest.json'),log=E.record(release,collect_log),commandsFile=E.record(release,collect_commands)))
        self.reseal(release)
        return release,{key:identity[key] for key in ['projectCommit','runId','runAttempt']}

    def reseal(self,release):
        origin_path=release/'reports/construction/origin.json'
        origin=E.load(origin_path)
        origin['evidenceFiles']=[E.record(release,release/row['path']) for row in origin['evidenceFiles']]
        self.json(origin_path,origin)
        manifest_path=release/'build-manifest.json';manifest=E.load(manifest_path)
        reports=release/'reports'
        manifest['reports']['files']=[dict(path=path.relative_to(reports).as_posix(),**E.fingerprint(path))
                                     for path in sorted(reports.rglob('*')) if path.is_file()]
        self.json(manifest_path,manifest)
        receipt=E.load(release/'collect-receipt.json');receipt['manifest']=E.record(release,manifest_path)
        self.json(release/'collect-receipt.json',receipt)

    def test_complete_portable_gate_accepts_both_synthetic_delivery_shapes(self):
        for major in ['6','7']:
            with self.subTest(major=major),tempfile.TemporaryDirectory() as temporary:
                release,expected=self.fixture(Path(temporary),major)
                report=E.validate(release,expected)
                self.assertEqual(report['status'],'passed');self.assertEqual(report['sdkVersion'],E.VERSIONS[major]['sdk'])
                self.assertEqual(report['tests']['omniSharpPassed'],12)
                self.assertEqual(set(report['native']),{'ubuntu22','ubuntu24','debian13'})
                E.write(release/'ci-validation.json',report)
                self.assertEqual(E.validate(release,expected),report)

    def test_resealed_semantic_failures_remain_blocked(self):
        mutations=[
            ('native','Native checks failed'),('image','Actual native verifier image invocation is missing'),
            ('payload','Complete current shared-framework comparison is required'),
            ('copy','Malformed completed local-copy task proof'),
            ('source','Used-source controls differ'),('sysroot','Actual successful upstream Release signature verification is required')]
        for mutation,message in mutations:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                release,expected=self.fixture(Path(temporary),'6')
                if mutation=='native':
                    path=release/'reports/verify-ubuntu24/verification.json';data=E.load(path)
                    data['functionalChecks']['rsaSha256SignAndVerify']='failed';self.json(path,data)
                elif mutation=='image':
                    path=release/'reports/ci/stages/verify.json';data=E.load(path)
                    data['commands']=[command for command in data['commands'] if '--network=none' not in command];self.json(path,data)
                elif mutation=='payload':
                    path=release/'reports/construction/identity/shared-framework-identity.json';data=E.load(path)
                    data['comparisons'][0]['sdkEntries']['unexpected.dll']={};self.json(path,data)
                elif mutation=='copy':
                    path=release/'reports/construction/origin.json';data=E.load(path)
                    data['components'][0]['completedLocalCopies'][0]['task']['Succeeded']=False;self.json(path,data)
                elif mutation=='source':self.json(release/'sources/source-manifest.json',{'changed':True})
                else:(release/'reports/sysroot/sysroot-build.log').write_text('Synthetic failed signature check\n')
                self.reseal(release)
                with self.assertRaisesRegex(ValueError,message):E.validate(release,expected)

    def test_uninventoried_reports_and_wrong_run_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            release,expected=self.fixture(Path(temporary),'7')
            with self.assertRaisesRegex(ValueError,'Wrong run/project identity'):
                E.validate(release,dict(expected,runId='999'))
            self.put(release/'reports/unbound.log',b'Not in the final report inventory')
            with self.assertRaisesRegex(ValueError,'Report inventory membership changed'):E.validate(release,expected)


if __name__=='__main__':unittest.main()
