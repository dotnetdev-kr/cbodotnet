#!/usr/bin/env python3
"""Bounded .NET 6/7 orchestration and honest evidence-policy regressions."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
E = module('net67_gate_test',ROOT/'scripts/ci-net67-evidence.py')
D = module('net67_driver_test',ROOT/'scripts/ci-net67.py')


class GeneratedSourceCiTests(unittest.TestCase):
    def test_real_installer_double_separator_is_normalized_without_path_escape(self):
        value='/work/source-v6.0.136/artifacts/obj/arm64/Release/blob-feed/assets//dotnet-runtime-6.0.36-linux-arm64.tar.gz'
        self.assertEqual(E.generated_relative(value,'6.0.136'),'artifacts/obj/arm64/Release/blob-feed/assets/dotnet-runtime-6.0.36-linux-arm64.tar.gz')
        for value in ['/work/source-v6.0.136/../other','file:///work/source-v6.0.136/file','/work/another/file']:
            with self.subTest(value=value),self.assertRaises(ValueError): E.generated_relative(value,'6.0.136')

    def test_effective_profiles_preserve_policy_and_remove_historical_claims(self):
        for major, selected in E.VERSIONS.items():
            with self.subTest(major=major):
                path = ROOT/'profiles'/('dotnet-'+selected['sdk']+'-linux-arm64.json')
                original = json.loads(path.read_text()); before = copy.deepcopy(original)
                actual = E.effective_profile(original,'20261101.42')
                self.assertEqual(original,before)
                for key in ['source','generatedSource','sysroot','toolchain','upstreamInputs']:
                    self.assertEqual(actual[key], original[key])
                self.assertTrue(actual['build']['sourceOnly'])
                self.assertFalse(actual['construction']['upstreamSharedRuntimeReused'])
                self.assertNotIn('verification',actual)
                self.assertNotIn('observedDerivedImageId',actual['container'])
                self.assertNotIn('abiRequirementVerified',actual['target'])
                self.assertEqual(actual['build']['ciBuildId'],'20261101.42')
                self.assertIn('no clean-bootstrap',actual['construction']['note'])

    def make_trx(self, path, failed=False, other_skip=False, total='42'):
        ns='http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
        root=ET.Element('{'+ns+'}TestRun'); results=ET.SubElement(root,'{'+ns+'}Results')
        for n in range(41):
            name='OmniSharpTests.Case'+str(n) if n < 12 else 'Original.Case'+str(n)
            ET.SubElement(results,'{'+ns+'}UnitTestResult',testName=name,outcome='Failed' if failed and n==0 else 'Passed')
        ET.SubElement(results,'{'+ns+'}UnitTestResult',testName='Other.Skip' if other_skip else 'PoisonTests.VerifyUsage',outcome='NotExecuted')
        summary=ET.SubElement(root,'{'+ns+'}ResultSummary')
        ET.SubElement(summary,'{'+ns+'}Counters',total=total,passed='40' if failed else '41',failed='1' if failed else '0',notExecuted='1')
        path.write_bytes(ET.tostring(root))

    def test_all_42_original_cases_and_12_omnisharp_cases_are_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'current.trx'; self.make_trx(path)
            self.assertEqual(E.smoke_results(path)['omniSharpPassed'],12)
            for mutation in [{'failed':True},{'other_skip':True},{'total':'41'}]:
                with self.subTest(mutation=mutation):
                    self.make_trx(path,**mutation)
                    with self.assertRaises(ValueError): E.smoke_results(path)

    def test_canonical_freeze_binds_git_tree_and_effective_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); project=root/'project'; release=root/'delivery'
            project.mkdir(); release.mkdir()
            def git(*args):
                return subprocess.check_output(['git','-C',str(project),*args],stderr=subprocess.PIPE)
            git('init','-q'); git('config','user.email','fixture@example.invalid'); git('config','user.name','Fixture')
            (project/'.gitattributes').write_text('*.cmd text eol=crlf\n')
            (project/'tool.cmd').write_bytes(b'@echo off\r\n')
            selected=E.VERSIONS['6']; profile=project/'profiles'/('dotnet-'+selected['sdk']+'-linux-arm64.json')
            profile.parent.mkdir(); profile.write_bytes((ROOT/'profiles'/profile.name).read_bytes())
            git('add','.'); git('commit','-qm','Fixture source')
            sha=git('rev-parse','HEAD').decode().strip()
            identity=dict(projectCommit=sha,runId='123',runAttempt='1',buildId='20261101.1',buildRevision='123')
            snapshot=E.freeze(project,release,'6',identity)
            commit=E.checked(release,snapshot['projectCommitObject']).read_bytes()
            self.assertEqual(E.git_hash('commit',commit),sha)
            self.assertTrue(commit.startswith(('tree '+E.snapshot_tree(release,snapshot['projectFiles'])+'\n').encode()))
            self.assertEqual((release/'reports/ci-inputs/project/tool.cmd').read_bytes(),b'@echo off\n')
            frozen=release/'reports/ci-inputs/project/tool.cmd'; frozen.write_bytes(b'tampered')
            with self.assertRaises(ValueError): E.snapshot_tree(release,snapshot['projectFiles'])

    def test_container_scope_for_product_and_sysroot_is_distinct(self):
        run=D.Run.__new__(D.Run)
        for key,value in dict(project='/project-host',work='/workspace/work',installer='/workspace/installer',
                              inputs='/workspace/inputs',home='/workspace/home',output='/delivery-host',candidate='/candidate-host',source='/absent-source').items():
            setattr(run,key,Path(value))
        run.engine=['sudo','-n','--','podman']; run.uid=1001; run.gid=1001; run.image='a'*64; run.cpus='0,1'; run.sdk='6.0.136'
        captured=[]; run.command=lambda args,**kwargs: captured.append(args)
        run.container(['true'],readonly=True,network='none')
        args=captured[-1]
        self.assertIn('/workspace/work:/work:ro',args); self.assertIn('/workspace/inputs:/inputs:ro',args)
        self.assertIn('/project-host:/project:ro',args); self.assertNotIn('--privileged',args)
        self.assertIn('seccomp=/workspace/inputs/seccomp.json',args)
        run.container(['true'],privileged=True)
        args=captured[-1]
        self.assertIn('--privileged',args); self.assertIn('0:0',args)
        self.assertIn('/workspace/work:/work:ro',args); self.assertIn('/project-host:/project:ro',args)
        self.assertIn('/workspace/inputs:/inputs',args)

    def test_family_wrappers_route_stage_and_portable_gate_cli(self):
        for major in ['6','7']:
            wrapper=ROOT/'scripts'/('ci-net'+major+'.sh')
            for args in [['--help'],['validate','--help'],['verify-release','--help']]:
                with self.subTest(major=major,args=args):
                    result=subprocess.run(['bash',str(wrapper),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotEqual(subprocess.run(['bash',str(wrapper),'unknown'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode,0)


if __name__ == '__main__': unittest.main()
