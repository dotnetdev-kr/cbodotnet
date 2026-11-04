"""Consumer wrappers relocate without changing qualified SDK files or source assets."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import consumer_archive as CA
import consumer_archive_release as CR


@unittest.skipUnless(os.name=='posix','Archive permissions and launchers require Linux')
class ConsumerArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.contract=copy.deepcopy(CA.load_contract())
        self.catalog=json.loads((ROOT/'releases/qualified-builds.json').read_bytes())
        producers=next(item for item in self.catalog['builds'] if item['sdkVersion']=='10.0.403')['architectures']
        self.inputs={}; architectures={}
        for arch in ('x64','aarch64'):
            directory=self.root/arch; directory.mkdir(); self.inputs[arch]=directory
            name=f'cbodotnet-sdk-10.0.403-linux-{arch}.tar.gz'
            with tarfile.open(directory/name,'w:gz') as tar:
                for relative,data,mode in [('dotnet',b'#!/bin/sh\ncase "$1" in --version) printf "10.0.403\\n";; --list-sdks) printf "10.0.403 [%s/sdk]\\n" "$DOTNET_ROOT";; esac\n',0o755),
                    ('LICENSE.txt',b'Original license\n',0o644),('ThirdPartyNotices.txt',b'Original notices\n',0o644),
                    ('sdk/10.0.403/reference.dll',b'qualified-sdk-file\x00\xff',0o644)]:
                    entry=tarfile.TarInfo(relative); entry.size=len(data); entry.mode=mode; tar.addfile(entry,io.BytesIO(data))
            provenance=copy.deepcopy(producers[arch]); provenance.update(targetRid=CA.ARCHITECTURES[arch]['rid'],
                workflowUrl=f'https://github.com/{CA.REPOSITORY}/actions/runs/{provenance["runId"]}')
            architectures[arch]=dict(sdk=CA.descriptor(directory/name),
                source=dict(name=f'cbodotnet-source-10.0.403-linux-{arch}.tar.gz',size=17,sha256='b'*64),
                evidence=dict(name=f'evidence-{arch}.tar.gz',size=19,sha256='c'*64),provenance=provenance)
        sums=''.join(f'{item["sha256"]}  {item["name"]}\n' for arch in ('x64','aarch64') for item in
            [architectures[arch][kind] for kind in ('sdk','source','evidence')]).encode()
        manifest=dict(schemaVersion=1,repository=CA.REPOSITORY,sdkVersion='10.0.403',tag='sdk-10.0.403',
            architectures=architectures,checksums=dict(name='SHA256SUMS',size=len(sums),sha256=hashlib.sha256(sums).hexdigest()))
        raw=CA.encoded(manifest); self.manifest=manifest
        self.contract['releases']['10.0.403']['manifestSha256']=hashlib.sha256(raw).hexdigest()
        base=f'https://github.com/{CA.REPOSITORY}/releases/download/sdk-10.0.403/'
        descriptors=[architectures[arch][kind] for arch in ('x64','aarch64') for kind in ('sdk','source','evidence')]
        descriptors += [manifest['checksums'],dict(name='release-manifest.json',size=len(raw),sha256=hashlib.sha256(raw).hexdigest())]
        release=dict(tag_name='sdk-10.0.403',draft=False,prerelease=False,
            html_url=f'https://github.com/{CA.REPOSITORY}/releases/tag/sdk-10.0.403',name='.NET SDK 10.0.403',body='Original release notes',
            assets=[dict(name=item['name'],state='uploaded',size=item['size'],digest='sha256:'+item['sha256'],browser_download_url=base+item['name']) for item in descriptors])
        self.release=release
        for directory in self.inputs.values():
            (directory/'release-manifest.json').write_bytes(raw); (directory/'SHA256SUMS').write_bytes(sums)
            (directory/'release.json').write_bytes(CA.encoded(release))

    def build(self,arch='x64',name='build'):
        return CA.build_archive(self.inputs[arch],arch,1,self.root/name,contract=self.contract,catalog=self.catalog)

    def test_archive_preserves_original_payload_and_separately_inventories_three_commands(self):
        build=self.build(); tree=self.root/'build'/build['directory']
        self.assertEqual({'dotnet','cbodotnet','cbodotnet-10.0'},{row['path'] for row in build['commands']})
        self.assertEqual(b'qualified-sdk-file\x00\xff',(tree/'payload/sdk/10.0.403/reference.dll').read_bytes())
        self.assertEqual(b'Original notices\n',(tree/'payload/ThirdPartyNotices.txt').read_bytes())
        self.assertFalse(build['publicationAllowed'])
        with mock.patch.object(CR,'intake',side_effect=lambda directory,arch,revision:CA.intake(directory,arch,revision,contract=self.contract,catalog=self.catalog)):
            CR.verify_build(self.root/'build/package-build.json',self.inputs['x64'])

    def test_all_entrypoints_relocate_with_spaces_quotes_and_symlinked_selection(self):
        build=self.build(); original=self.root/'build'/build['directory']; relocated=self.root/'moved "SDK" directory'
        original.rename(relocated)
        for name in ('dotnet','cbodotnet','cbodotnet-10.0'):
            result=subprocess.run([str(relocated/name),'--version'],capture_output=True,text=True)
            self.assertEqual(0,result.returncode); self.assertEqual('10.0.403\n',result.stdout)
            self.assertEqual(CA.BRANDING['displayName']+'\n',result.stderr)
            info=json.loads(subprocess.check_output([str(relocated/name),'--cbodotnet-info'],text=True))
            self.assertEqual(str(relocated/'payload'),info['sdkRoot']); self.assertFalse(info['qualifiedPayloadModified'])
        link=self.root/'selected'; link.symlink_to(relocated/'cbodotnet')
        info=json.loads(subprocess.check_output([str(link),'--cbodotnet-info'],text=True))
        self.assertEqual(str(relocated/'payload'),info['sdkRoot'])
        environment=dict(os.environ,PATH=str(relocated)+':'+os.environ['PATH'])
        self.assertEqual('10.0.403 ['+str(relocated/'payload/sdk')+']\n',subprocess.check_output(['cbodotnet','--list-sdks'],env=environment,text=True))

    def test_missing_selected_payload_never_falls_back_to_another_dotnet(self):
        build=self.build(); tree=self.root/'build'/build['directory']; (tree/'payload/dotnet').unlink()
        result=subprocess.run([str(tree/'dotnet'),'--version'],capture_output=True,text=True)
        self.assertEqual(127,result.returncode); self.assertEqual('',result.stdout)

    def test_source_pin_or_corrupt_sdk_rejected_before_output_is_created(self):
        contract=copy.deepcopy(self.contract); contract['releases']['10.0.403']['manifestSha256']='f'*64
        with self.assertRaisesRegex(ValueError,'source pin'):
            CA.build_archive(self.inputs['x64'],'x64',1,self.root/'bad-pin',contract=contract,catalog=self.catalog)
        self.assertFalse((self.root/'bad-pin').exists())
        sdk=self.inputs['x64']/self.manifest['architectures']['x64']['sdk']['name']; sdk.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'archive changed'):
            self.build()
        self.assertFalse((self.root/'build').exists())

    def test_metadata_draft_changes_only_title_and_body_and_is_idempotent(self):
        patch=CA.metadata_patch(self.release)
        self.assertEqual({'name','body'},set(patch)); self.assertIn('Trial',patch['name'])
        self.assertIn('/distribution-archive-sdk-10.0.403-r1',patch['body'])
        self.assertIn('Original release notes',patch['body'])
        self.assertEqual(patch,CA.metadata_patch(dict(self.release,**patch)))
        updated=dict(self.release,**patch)
        self.assertEqual(self.release['assets'],updated['assets'])
        self.assertFalse(updated['draft']); self.assertFalse(updated['prerelease'])

    def test_report_cannot_omit_architecture_user_space_or_real_checks(self):
        build=self.build(); plan=build['plan']
        source=dict(repository=CA.REPOSITORY,workflow=CA.WORKFLOW,commit='a'*40,runId='1',runAttempt='1')
        report=dict(schemaVersion=1,scope='consumer-archive-installation',status='passed',architecture='x64',
            identity=CA.identity(plan),artifact=build['artifact'],commands=build['commands'],qualifiedPayload=build['qualifiedPayload'],
            orchestration=source,networkForBuild='none',checks=dict.fromkeys(CA.REPORT_CHECKS,'passed'),
            userSpaces=[dict(variant=variant,status='passed',architecture='x64',native=True,networkForBuild='none',
                checks=dict.fromkeys(CA.REPORT_CHECKS,'passed')) for variant in plan['validatedUserSpaces']])
        CR.validate_native_report(report,build,source)
        for mutate in (lambda value:value['userSpaces'].pop(),lambda value:value['checks'].update({'relocation':'failed'}),
                       lambda value:value.update(architecture='aarch64'),lambda value:value['artifact'].update(sha256='f'*64)):
            changed=copy.deepcopy(report); mutate(changed)
            with self.assertRaises(ValueError):CR.validate_native_report(changed,build,source)


if __name__=='__main__':unittest.main()
