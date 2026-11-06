"""Synthetic lifecycle contracts plus actual bounded selection/extraction cleanup."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive as CA
import consumer_archive_lifecycle as LIFE


def selected_plan():
    return dict(sdkVersion='3.1.426',architecture='aarch64',packageRevision=3,archiveLauncherVersion=2,
        sourceReleaseTag='sdk-3.1.426',sourceManifestSha256='1'*64,targetRid='linux-arm64',
        compatibility=dict(root='/usr/lib/cbodotnet/compat/rocky9'),
        nativeHttpCompatibility=dict(root='/usr/lib/cbodotnet/compat/curl-rocky8'))


def synthetic_proof(plan=None):
    """Metadata-only fixture, never a release report or actual qualification claim."""
    plan=plan or selected_plan();root=LIFE.INSTALL_ROOT
    def directory(path):return dict(path=str(path),present=True,type='directory',mode='0o755',uid=0,gid=0,
        entries=1,files=1,links=0,inventorySha256='a'*64)
    def observation(revision,path):
        return dict(revision=revision,root=str(path),payload=str(path/'payload'),linkTarget=str(path/'cbodotnet'),
            versionStdout=plan['sdkVersion']+'\n',brandingStderr=CA.BRANDING['displayName']+'\n',
            identity=dict(CA.identity(plan),packageRevision=revision,sdkRoot=str(path/'payload'),qualifiedPayloadModified=False))
    old=root/'historical r2 archive'/'old-r2';current=root/'relocated consumer archive';fresh=root/'reinstalled r3 archive'/'fresh-r3'
    inventory=dict(sha256='b'*64,entries=4,files=3,links=0)
    baseline=dict(schemaVersion=1,scope=LIFE.SYSTEM_SCOPE,sdkVersion=plan['sdkVersion'],architecture=plan['architecture'],
        officialPackageProvisioned=False,globalPaths=[dict(path=path,present=False) for path in LIFE.GLOBAL_PATHS],
        providers=[directory(path) for path in (plan['compatibility']['root'],plan['nativeHttpCompatibility']['root'])],
        stockLibraries=[dict(path='/usr/lib/libc.so.6',present=True,type='file',mode='0o755',uid=0,gid=0,size=1,sha256='c'*64)],
        libraryInputs=[str(current/'payload/dotnet')],packages=dict(manager='dpkg',inventorySha256='d'*64,packageCount=3,
            database=directory('/var/lib/dpkg'),excludedVolatileNames=list(LIFE.RPM_VOLATILE)+['*-shm','*-wal','*-journal']),
        unrelatedSentinel=directory(root/'unrelated user state'),sentinelPurpose='deliberately-created-unrelated-user-file-for-qualification')
    baseline['unrelatedSentinel']['uid']=10001
    return dict(schemaVersion=1,scope=LIFE.SCOPE,status='passed',sdkVersion=plan['sdkVersion'],architecture=plan['architecture'],
        userId=10001,network='none',officialPackageProvisioned=False,installRoot=str(root),
        selectionTransitions=[observation(revision,old if revision==2 else current) for revision in LIFE.TRANSITIONS],
        retainedInventories=dict(r2=inventory,r3=inventory),reinstall=dict(root=str(fresh),
            artifact=dict(name=f'cbodotnet-sdk-{plan["sdkVersion"]}-linux-{plan["architecture"]}-r3.tar.gz',size=1,sha256='e'*64),
            inventory=inventory,retainedInventory=inventory,identical=True,commandObservation=observation(3,fresh)),
        removal=dict(roots=[str(old),str(current),str(fresh)],allAbsent=True,selectionRemoved=True,missingSelectionExitCode=127,noHostOutput=True),
        systemBefore=baseline,systemAfter=copy.deepcopy(baseline),systemStateUnchanged=True,providersUnchanged=True)


class LifecycleEvidenceTests(unittest.TestCase):
    def test_ldd_accepts_only_mapping_address_lines_and_preserves_missing_dependency_rejection(self):
        binary='/opt/cbodotnet-consumer-validation/original/SDK payload/System.Net.Http.Native.so'
        warning=binary+': /usr/lib/cbodotnet/compat/curl-rocky8/lib/libcurl.so.4: no version information available (required by '+binary+')'
        output='\n'.join([warning,'\tlinux-vdso.so.1 (0x00007feab19f0000)',
            '\tlibcurl.so.4 => /usr/lib/cbodotnet/compat/curl-rocky8/lib/libcurl.so.4 (0x00007f112200)',
            '\tlibc.so.6 => /test stock libraries/libc.so.6 (0xAABB)',
            '\t/lib64/ld-linux-x86-64.so.2 (0x1234)',
            'ldd: warning: you do not have execution permission for '+binary])
        self.assertEqual(['/usr/lib/cbodotnet/compat/curl-rocky8/lib/libcurl.so.4',
            '/test stock libraries/libc.so.6','/lib64/ld-linux-x86-64.so.2'],LIFE._ldd_paths(output))
        for missing in ('libcurl.so.4 => not found','\tlibssl.so.1.1 =>   not found\n'):
            with self.assertRaisesRegex(ValueError,'dependency is missing'):LIFE._ldd_paths(output+'\n'+missing)

    def test_gate_rejects_missing_or_self_inconsistent_lifecycle_fields(self):
        plan=selected_plan();proof=synthetic_proof(plan);LIFE.validate_lifecycle_evidence(proof,plan)
        changes=(lambda p:p.update(officialPackageProvisioned=True),
            lambda p:p['selectionTransitions'].pop(),lambda p:p['selectionTransitions'][1].update(revision=2),
            lambda p:p['selectionTransitions'][2]['identity'].update(packageRevision=3),
            lambda p:p['selectionTransitions'][0].update(root='/usr/share/dotnet'),
            lambda p:p['retainedInventories']['r2'].update(sha256='unverified'),
            lambda p:p['reinstall'].update(identical=False),lambda p:p['reinstall']['inventory'].update(entries=0),
            lambda p:p['removal'].update(noHostOutput=False),lambda p:p['removal']['roots'].append('/usr/share/dotnet'),
            lambda p:p['systemAfter']['globalPaths'][0].update(present=True),
            lambda p:p['systemAfter']['providers'][0].update(inventorySha256='f'*64),
            lambda p:p['systemBefore'].update(stockLibraries=[]),lambda p:p['systemBefore']['packages'].update(packageCount=0))
        for mutate in changes:
            changed=copy.deepcopy(proof);mutate(changed)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):LIFE.validate_lifecycle_evidence(changed,plan)
        for field,value in [('sha256','bad'),('mode','untracked')]:
            changed=copy.deepcopy(proof)
            for key in ('systemBefore','systemAfter'):changed[key]['stockLibraries'][0][field]=value
            with self.assertRaises(ValueError):LIFE.validate_lifecycle_evidence(changed,plan)


@unittest.skipUnless(os.name=='posix','Real POSIX archive permissions and symlinks required')
class BoundedArchiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='archive lifecycle unit-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.install=self.root/'owned';self.install.mkdir();self.workspace=self.root/'workspace';(self.workspace/'build').mkdir(parents=True)
        self.plan=selected_plan();self.tools=CA.sdk_tools()
        patch=mock.patch.object(LIFE,'INSTALL_ROOT',self.install);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(LIFE,'_container_guard',return_value=self.install);patch.start();self.addCleanup(patch.stop)
        self.old=self.install/'historical r2 archive'/'old-r2';self.current=self.install/'relocated consumer archive'
        self.make_tree(self.old,2);self.make_tree(self.current,3)
        source=self.root/'source'/'cbodotnet-3.1.426-linux-aarch64-r3';source.parent.mkdir()
        import shutil
        shutil.copytree(self.current,source)
        artifact=self.workspace/'build'/'cbodotnet-sdk-3.1.426-linux-aarch64-r3.tar.gz'
        with tarfile.open(artifact,'w:gz') as tar:tar.add(source,arcname=source.name)
        self.build=dict(directory=source.name,artifact=CA.descriptor(artifact),additionalDirectories=[],
            qualifiedPayload=CA.payload_summary(self.tools.snapshot(self.current/'payload')))
        self.baseline=synthetic_proof(self.plan)['systemBefore']
        patch=mock.patch.object(LIFE,'_resnapshot',side_effect=lambda baseline,api:copy.deepcopy(baseline));patch.start();self.addCleanup(patch.stop)
        owner=self
        class API:
            INSTALL=owner.install
            @staticmethod
            def sdk_tools():return owner.tools
            @staticmethod
            def user_result(arguments,**kwargs):
                try:return subprocess.run(list(map(str,arguments)),text=True,capture_output=True)
                except FileNotFoundError:return subprocess.CompletedProcess(arguments,127,'','missing selected path')
            @staticmethod
            def user_run(arguments,**kwargs):
                result=API.user_result(arguments,**kwargs)
                if result.returncode:raise ValueError(result.stderr)
                return result.stdout
        self.api=API

    def make_tree(self,path,revision):
        (path/'payload').mkdir(parents=True)
        (path/'payload/dotnet').write_bytes(b'unchanged qualified SDK fixture')
        (path/'LICENSE.wrapper.txt').write_bytes(b'wrapper fixture license')
        information=dict(CA.identity(self.plan),packageRevision=revision,qualifiedPayloadModified=False)
        text='#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\ninfo='+repr(information)+'\ninfo["sdkRoot"]=str(Path(__file__).resolve().parent/"payload")\n'
        text+='if sys.argv[1]=="--version":\n print('+repr(self.plan['sdkVersion'])+')\n print('+repr(CA.BRANDING['displayName'])+',file=sys.stderr)\nelse: print(json.dumps(info))\n'
        (path/'cbodotnet').write_text(text);(path/'cbodotnet').chmod(0o755)

    def test_actual_fixture_selection_reinstall_and_removal_are_bounded_and_preserve_unrelated_files(self):
        unrelated=self.install/'unrelated original.txt';unrelated.write_bytes(b'keep original bytes')
        outside=self.root/'outside.txt';outside.write_bytes(b'outside must remain')
        proof=LIFE.qualify(self.plan,self.build,self.workspace,self.current,dict(root=str(self.old)),self.baseline,self.api)
        self.assertEqual([2,3,2,3],[row['revision'] for row in proof['selectionTransitions']])
        self.assertFalse(self.old.exists());self.assertFalse(self.current.exists())
        self.assertFalse(Path(proof['reinstall']['root']).exists());self.assertFalse((self.install/'selected archive CLI').exists())
        self.assertEqual(b'keep original bytes',unrelated.read_bytes());self.assertEqual(b'outside must remain',outside.read_bytes())
        LIFE.validate_lifecycle_evidence(proof,self.plan)

    def test_changed_archive_is_rejected_before_any_retained_sdk_root_is_removed(self):
        (self.workspace/'build'/self.build['artifact']['name']).write_bytes(b'wrong archive')
        with self.assertRaisesRegex(ValueError,'Reinstallation source'):
            LIFE.qualify(self.plan,self.build,self.workspace,self.current,dict(root=str(self.old)),self.baseline,self.api)
        self.assertTrue(self.old.is_dir());self.assertTrue(self.current.is_dir())

    def test_boundary_checks_reject_escape_install_root_and_symlinked_paths(self):
        outside=self.root/'outside';outside.mkdir();(outside/'keep').write_text('untouched')
        alias=self.install/'alias';alias.symlink_to(outside,target_is_directory=True)
        for path in (self.install,self.root,alias,alias/'keep',self.install/'..'/'outside'):
            with self.subTest(path=path),self.assertRaises(ValueError):LIFE._owned(self.install,path)
        self.assertEqual('untouched',(outside/'keep').read_text())

    def test_stock_dependency_capture_excludes_optional_diagnostics_and_separate_provider_libraries(self):
        payload=self.install/'native payload';(payload/'shared/Microsoft.NETCore.App/3.1.32').mkdir(parents=True)
        for name in ('dotnet','shared/Microsoft.NETCore.App/3.1.32/libcoreclr.so','shared/Microsoft.NETCore.App/3.1.32/libcoreclrtraceptprovider.so'):
            (payload/name).write_bytes(b'\x7fELFfixture')
        provider=self.root/'provider';(provider/'lib').mkdir(parents=True);library=provider/'lib/libcurl.so.4.5.0';library.write_bytes(b'\x7fELFprovider')
        stock=self.root/'stock libc.so';stock.write_bytes(b'untouched stock bytes')
        calls=[]
        def ldd(arguments,**kwargs):
            calls.append(arguments[1]);self.assertNotIn('tracept',arguments[1])
            warning=arguments[1]+': '+str(library)+': no version information available (required by '+arguments[1]+')\n'
            return subprocess.CompletedProcess(arguments,0,warning+'libcurl.so.4 => '+str(library)+' (0x1)\nlibc.so.6 => '+str(stock)+' (0x2)\n',warning)
        with mock.patch.object(LIFE.subprocess,'run',side_effect=ldd):
            inputs,libraries=LIFE._stock_libraries(payload,[str(provider)],{},self.api,self.install)
        self.assertEqual([str(stock)],[row['path'] for row in libraries]);self.assertEqual(3,len(calls))
        self.assertFalse(any('tracept' in path for path in inputs))


if __name__=='__main__':unittest.main()
