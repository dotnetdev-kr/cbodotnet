from pathlib import Path
import copy
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cbodotnetup_matrix import SDK_CHECKS,validate_additional_sdk_qualifications,validate_previous_tool_upgrade
from consumer_archive import FUNCTIONAL_CHECKS
import cbodotnetup_release as UP


class InterruptedWorkerTests(unittest.TestCase):
    def test_worker_is_direct_session_leader_with_explicit_unprivileged_identity(self):
        account=SimpleNamespace(pw_uid=10001,pw_gid=10002)
        environment={'CBODOTNETUP_HOME':'/home/'+UP.MULTI.USER+'/matrix'}
        with patch.dict(sys.modules,{'pwd':SimpleNamespace(getpwnam=lambda name:account)}),\
                patch.object(UP.os,'geteuid',return_value=0,create=True),\
                patch.dict(UP.os.environ,{'GH_TOKEN':'must-not-inherit','LD_PRELOAD':'must-not-inherit'}),\
                patch.object(UP.subprocess,'Popen') as popen:
            UP.user_process([Path('/home/worker/cbodotnetup'),'install','8.0.133-r2'],stdout=UP.subprocess.DEVNULL,
                            extra_environment=environment)
        command=popen.call_args.args[0];options=popen.call_args.kwargs
        self.assertEqual(command,['/home/worker/cbodotnetup','install','8.0.133-r2'])
        self.assertNotIn('runuser',command)
        self.assertEqual(options['user'],10001);self.assertEqual(options['group'],10002)
        self.assertEqual(options['extra_groups'],[]);self.assertIs(options['start_new_session'],True)
        self.assertEqual(options['cwd'],'/home/'+UP.MULTI.USER)
        self.assertEqual(options['env'],dict(UP.user_environment(),**environment))
        self.assertNotIn('GH_TOKEN',options['env']);self.assertNotIn('LD_PRELOAD',options['env'])

    @unittest.skipUnless(sys.platform=='linux','POSIX process groups and flock are required')
    def test_killed_worker_is_reaped_and_its_operation_lock_is_immediately_available(self):
        # Exercise actual process-group termination without requiring root in the
        # unit-test runner. Credential kwargs are checked above, then removed by
        # this test-only launcher so the real child runs as the current account.
        import fcntl
        real_popen=subprocess.Popen
        account=SimpleNamespace(pw_uid=10001,pw_gid=10002)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);lock=root/'operation.lock';ready=root/'ready';child=None
            def unprivileged_launch(arguments,**options):
                for name in ('user','group','extra_groups'):options.pop(name)
                options['cwd']=temporary
                options['env']=dict(options['env'],HOME=temporary,DOTNET_CLI_HOME=temporary)
                return real_popen(arguments,**options)
            script=('import fcntl,os,pathlib,sys,time\n'
                    'with open(sys.argv[1],"a+b") as lease:\n'
                    ' fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                    ' pathlib.Path(sys.argv[2]).write_text(str(os.getpid())+":"+str(os.getpgrp()))\n'
                    ' time.sleep(120)\n')
            try:
                with patch.dict(sys.modules,{'pwd':SimpleNamespace(getpwnam=lambda name:account)}),\
                        patch.object(UP.os,'geteuid',return_value=0),\
                        patch.object(UP.subprocess,'Popen',side_effect=unprivileged_launch):
                    child=UP.user_process([sys.executable,'-c',script,str(lock),str(ready)],stdout=UP.subprocess.DEVNULL)
                deadline=time.monotonic()+10
                while not ready.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(0.01)
                self.assertTrue(ready.exists(),'The direct worker did not acquire its lock')
                self.assertEqual(ready.read_text(),f'{child.pid}:{child.pid}')
                with lock.open('a+b') as retry:
                    with self.assertRaises(BlockingIOError):fcntl.flock(retry,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    os.killpg(child.pid,signal.SIGKILL)
                    self.assertEqual(child.wait(timeout=5),-signal.SIGKILL)
                    # No sleep, lock retry or orphan cleanup may be needed here.
                    fcntl.flock(retry,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                if child is not None and child.poll() is None:
                    os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)


class InstallerMatrixTests(unittest.TestCase):
    def inputs(self):
        variants=[('ubuntu','24.04'),('debian','13'),('fedora','45'),('rocky','9.8')]
        versions=['10.0.403','9.0.123','8.0.133','7.0.120','6.0.136']
        sdks=[]
        for version in versions:
            for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
                revision=3 if version=='10.0.403' else 2
                sdks.append(dict(sdkVersion=version,revision=revision,rid=rid,requiresLegacyProvider=False,
                    archive=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/cbodotnet-sdk-{version}-linux-{arch}-r{revision}.tar.gz',
                                 size=123,sha256=hashlib.sha256((version+rid).encode()).hexdigest()),
                    sourceManifestSha256=hashlib.sha256(version.encode()).hexdigest(),
                    targets=[dict(os=os,versionId=number,rid=rid) for os,number in variants]))
        def alias(sdk):
            return dict(sdkVersion=sdk['sdkVersion'],packageRevision=sdk['revision'],targetRid=sdk['rid'],
                        sourceManifestSha256=sdk['sourceManifestSha256'],qualifiedPayloadModified=False)
        observations=[]
        for os,number in variants:
            for rid,arch in [('linux-x64','x64'),('linux-arm64','aarch64')]:
                context=dict(variant=os+'-'+number,architecture=arch,catalogSha256='a'*64,
                    bootstrapSha256='b'*64,binarySha256='c'*64,bootstrapBinarySource='public-https')
                baseline=next(sdk for sdk in sdks if sdk['sdkVersion']=='10.0.403' and sdk['rid']==rid)
                rows=[]
                for sdk in sdks:
                    if sdk['rid']!=rid or sdk['sdkVersion']=='10.0.403':continue
                    rows.append(dict(context,status='passed',sdkVersion=sdk['sdkVersion'],revision=sdk['revision'],rid=rid,
                        target=dict(os=os,versionId=number,rid=rid),archive=copy.deepcopy(sdk['archive']),
                        sourceManifestSha256=sdk['sourceManifestSha256'],networkForBuild='none',userId=10001,
                        checks=dict.fromkeys(SDK_CHECKS,'passed'),functionalChecks=dict.fromkeys(FUNCTIONAL_CHECKS,'passed'),
                        aliases=[alias(baseline),alias(baseline),alias(sdk)]))
                observations.append(dict(context,additionalSdkQualifications=rows))
        return dict(schemaVersion=2,sdks=sdks,revoked=[]),observations

    def upgrade_inputs(self, public=True):
        catalog, observations = self.inputs()
        catalog.update(sequence=123, tools=[dict(version='0.2.0', rid=rid, binary=dict(sha256=digit*64))
                       for rid, digit in [('linux-x64', 'd'), ('linux-arm64', 'e')]])
        row = observations[0]['additionalSdkQualifications'][0]
        row['bootstrapBinarySource'] = 'public-https' if public else 'protected-frozen-candidate'
        baseline = next(sdk for sdk in catalog['sdks'] if sdk['sdkVersion'] == '10.0.403' and sdk['rid'] == row['rid'])
        prior = dict(catalog, sequence=122)
        prior_hash = hashlib.sha256(UP.encoded(prior)).hexdigest()
        proof = dict(status='passed', fromVersion='0.2.0', toVersion='0.3.0',
                     protocol='actual-0.2.0-self-update-rollback-reupgrade' if public else 'protected-frozen-candidate-bootstrap-from-0.2.0',
                     oldBinarySha256='d'*64, currentBinarySha256=row['binarySha256'],
                     previousCatalogSha256=prior_hash, currentCatalogSha256=row['catalogSha256'],
                     baseline={key: baseline[key] for key in ('sdkVersion', 'revision', 'rid')},
                     baselineReceiptSha256='f'*64, baselineInventorySha256='1'*64,
                     baselineCatalogSha256=prior_hash, baselineOwnedStateSha256='2'*64,
                     baselineReceiptUnchanged=True, baselineOwnedStateUnchanged=True,
                     baselinePayloadVerified=True, rollbackVerified=public)
        return proof, row, baseline, catalog

    def test_previous_tool_cycle_is_bound_to_public_or_candidate_protocol(self):
        for public in (True, False):
            proof, row, baseline, catalog = self.upgrade_inputs(public)
            validate_previous_tool_upgrade(proof, row, baseline, catalog, '0.3.0')

    def test_previous_tool_cycle_cannot_substitute_binary_catalog_or_owned_sdk(self):
        mutations = [lambda proof: proof.update(oldBinarySha256='0'*64),
                     lambda proof: proof.update(currentBinarySha256='0'*64),
                     lambda proof: proof.update(previousCatalogSha256='0'*64),
                     lambda proof: proof.update(baselineCatalogSha256='0'*64),
                     lambda proof: proof.update(baselineOwnedStateUnchanged=False),
                     lambda proof: proof.update(rollbackVerified=False),
                     lambda proof: proof.update(protocol='protected-frozen-candidate-bootstrap-from-0.2.0'),
                     lambda proof: proof['baseline'].update(sdkVersion='9.0.123'),
                     lambda proof: proof.update(baselineReceiptSha256='not-a-hash')]
        for mutate in mutations:
            proof, row, baseline, catalog = self.upgrade_inputs()
            mutate(proof)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                validate_previous_tool_upgrade(proof, row, baseline, catalog, '0.3.0')

    def test_all_thirty_two_cells_are_independently_bound(self):
        catalog,observations=self.inputs()
        rows=validate_additional_sdk_qualifications(catalog,observations)
        self.assertEqual(len(rows),32)
        self.assertEqual({row['sdkVersion'] for row in rows},{'9.0.123','8.0.133','7.0.120','6.0.136'})

    def test_project_tool_requires_new_proof_without_breaking_published_old_tool(self):
        catalog,observations=self.inputs()
        self.assertEqual(len(validate_additional_sdk_qualifications(catalog,observations,tool_version='0.2.0')),32)
        with self.assertRaisesRegex(ValueError,'project-SDK reference'):
            validate_additional_sdk_qualifications(catalog,observations,tool_version='0.3.0')

    def test_ten_only_historical_feed_needs_no_additional_proof(self):
        catalog,observations=self.inputs()
        catalog['sdks']=[sdk for sdk in catalog['sdks'] if sdk['sdkVersion']=='10.0.403']
        for observation in observations:observation.pop('additionalSdkQualifications')
        self.assertEqual(validate_additional_sdk_qualifications(catalog,observations),[])

    def test_a_passed_target_summary_cannot_replace_one_missing_sdk_cell(self):
        catalog,observations=self.inputs();observations[0]['additionalSdkQualifications'].pop()
        with self.assertRaisesRegex(ValueError,'Every additional'):validate_additional_sdk_qualifications(catalog,observations)

    def test_duplicate_cell_cannot_cover_a_missing_cpu_or_os(self):
        catalog,observations=self.inputs();observations[0]['additionalSdkQualifications'][0]=copy.deepcopy(observations[0]['additionalSdkQualifications'][1])
        with self.assertRaisesRegex(ValueError,'duplicate'):validate_additional_sdk_qualifications(catalog,observations)

    def test_archive_source_revision_and_actual_target_are_closed(self):
        mutations=[lambda row:row['archive'].update(sha256='d'*64),lambda row:row.update(sourceManifestSha256='d'*64),
                   lambda row:row.update(revision=1),lambda row:row['target'].update(versionId='22.04'),
                   lambda row:row.update(architecture='aarch64'),lambda row:row.update(rid='linux-musl-x64'),
                   lambda row:row.update(catalogSha256='d'*64),lambda row:row.update(bootstrapBinarySource='unverified')]
        for mutate in mutations:
            catalog,observations=self.inputs();mutate(observations[0]['additionalSdkQualifications'][0])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):validate_additional_sdk_qualifications(catalog,observations)

    def test_every_lifecycle_and_functional_check_is_required(self):
        for field in ('checks','functionalChecks'):
            catalog,observations=self.inputs();row=observations[0]['additionalSdkQualifications'][0]
            row[field].pop(next(iter(row[field])))
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'incomplete'):validate_additional_sdk_qualifications(catalog,observations)

    def test_offline_non_root_execution_and_alias_sources_are_required(self):
        mutations=[lambda row:row.update(networkForBuild='enabled'),lambda row:row.update(userId=0),
                   lambda row:row['aliases'][2].update(sdkVersion='10.0.403'),
                   lambda row:row['aliases'][0].update(sourceManifestSha256='d'*64),
                   lambda row:row['aliases'][2].update(qualifiedPayloadModified=True)]
        for mutate in mutations:
            catalog,observations=self.inputs();mutate(observations[0]['additionalSdkQualifications'][0])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):validate_additional_sdk_qualifications(catalog,observations)

    def test_revoked_or_legacy_provider_sdk_cannot_be_promoted(self):
        catalog,observations=self.inputs();sdk=next(s for s in catalog['sdks'] if s['sdkVersion']=='9.0.123')
        catalog['revoked']=[sdk['sdkVersion']+'-r'+str(sdk['revision'])+'/'+sdk['rid']]
        with self.assertRaisesRegex(ValueError,'revoked'):validate_additional_sdk_qualifications(catalog,observations)
        catalog['revoked']=[];sdk['requiresLegacyProvider']=True
        with self.assertRaisesRegex(ValueError,'legacy'):validate_additional_sdk_qualifications(catalog,observations)


if __name__=='__main__':unittest.main()
