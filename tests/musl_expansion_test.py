"""Version isolation and retained released tool identity across musl expansion."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_verification as VERIFY
import musl_oci_delivery as OCI
import cbodotnetup_retained_musl as RETAINED
from downstream_release import encoded
from musl_contract_test import fixture
from musl_archive_test import prepared_inputs


class ExpansionTests(unittest.TestCase):
    def test_exact_candidate_sources_do_not_grant_qualification(self):
        for version in ('9.0.123', '8.0.133'):
            release, manifest, raw, sums, catalog, _ = fixture(version)
            self.assertEqual(manifest, CONTRACT.validate_producer_release(release, raw, sums))
            self.assertEqual(manifest, CONTRACT.require_qualified_producer(raw, catalog=catalog))
            with self.assertRaisesRegex(ValueError, 'not independently qualified'):
                CONTRACT.require_qualified_producer(raw)
            for key, value in (('sourceCommit', CONTRACT.SOURCE['sourceCommit']),
                               ('workflow', '.github/workflows/musl-sdk.yml'),
                               ('sharedVmrCommit', CONTRACT.SOURCE['sharedVmrCommit'])):
                changed = copy.deepcopy(manifest)
                changed['architectures']['aarch64']['provenance'][key] = value
                with self.subTest(version=version, key=key), self.assertRaises(ValueError):
                    CONTRACT.validate_producer_manifest(changed)

    def test_versioned_payload_wrappers_and_trust_probe_use_the_same_sdk(self):
        for version in ('9.0.123', '8.0.133'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); inputs = root / 'inputs'; inputs.mkdir()
                catalog = prepared_inputs(inputs, version)
                result = ARCHIVE.build_archive(inputs, 'x64', 1, root / 'built', catalog=catalog)
                tree = root / 'built' / result['directory']
                self.assertEqual(CONTRACT.archive_name(version, 'x64'), result['artifact']['name'])
                self.assertEqual(b'Original SDK bytes\n', (tree / 'payload/sdk' / version / 'sentinel').read_bytes())
                for name in ('dotnet', 'cbodotnet', 'cbodotnet-'+version.split('.')[0]+'.0'):
                    process = subprocess.run([str(tree / name), '--version'], capture_output=True, text=True)
                    self.assertEqual(0, process.returncode)
                    self.assertEqual(version+'\n', process.stdout)
                    self.assertEqual(CONTRACT.BRANDING['displayName']+'\n', process.stderr)
                script = ARCHIVE.trust_probe_script(result['plan'], '/payload', '/cli', '/work')
                self.assertIn('<TargetFramework>net'+version.split('.')[0]+'.0</TargetFramework>', script)
                self.assertNotIn('net10.0', script)
                self.assertEqual('verification-musl-sdk-'+version+'-r1', VERIFY.verification_tag(1, version))

    def test_retained_report_requires_complete_identity_and_unchanged_compiled_sources(self):
        report = dict(version='0.5.1', buildInputs={'helper': 'a'*64}, sourceInputs={'tools/program': 'b'*64})
        with patch('cbodotnetup_musl_native.build_inputs', return_value={'helper': 'c'*64}):
            with self.assertRaisesRegex(ValueError, 'exact retained public build report'):
                RETAINED.validate_build_inputs(report, 'x64')
            digest = hashlib.sha256(encoded(report)).hexdigest()
            with patch.dict(RETAINED.REPORTS, {('0.5.1', 'x64'): digest}), \
                    patch('cbodotnetup_release.tool_inputs', return_value={'tools/program': 'd'*64}):
                with self.assertRaisesRegex(ValueError, 'changed compiled source'):
                    RETAINED.validate_build_inputs(report, 'x64')
            with patch.dict(RETAINED.REPORTS, {('0.5.1', 'x64'): digest}), \
                    patch('cbodotnetup_release.tool_inputs', return_value=report['sourceInputs']):
                self.assertEqual('exact-retained-public-report', RETAINED.validate_build_inputs(report, 'x64'))
                changed = copy.deepcopy(report); changed['buildInputs']['helper'] = 'e'*64
                with self.assertRaises(ValueError):
                    RETAINED.validate_build_inputs(changed, 'x64')

    def test_public_oci_reconstruction_receives_the_requested_sdk(self):
        for version in ('9.0.123', '8.0.133'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); tag = CONTRACT.distribution_tag('oci', version)
                base = 'https://github.com/'+CONTRACT.REPOSITORY+'/releases/download/'+tag+'/'
                data = b'{}'; signer = 'A'*40
                names = ['oci-index.json', 'qualification-x64.json', 'qualification-aarch64.json']
                assets = [dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()) for name in names]
                manifest = dict(tag=tag, identity=dict(channel='oci', sdkVersion=version), signingFingerprint=signer,
                    assets=assets, targetCommit='b'*40, records=[dict(architecture='x64')])
                objects = {base+OCI.MANIFEST: encoded(manifest), base+OCI.SIGNATURE: b'signature'}
                objects.update({base+name: data for name in names})
                release = dict(tag_name=tag, draft=False, prerelease=False, assets=[
                    dict(name=url.rsplit('/', 1)[1], size=len(raw), state='uploaded',
                        digest='sha256:'+hashlib.sha256(raw).hexdigest(), browser_download_url=url)
                    for url, raw in objects.items()])
                objects['https://api.github.com/repos/'+CONTRACT.REPOSITORY+'/releases/tags/'+tag] = encoded(release)
                def download(url, path, expected):
                    path.write_bytes(objects[url])
                with patch.object(OCI.DISTRIBUTION, 'orchestration', return_value={}), \
                        patch.object(OCI.DISTRIBUTION, '_docker_architecture'), \
                        patch.object(OCI, 'get_bytes', side_effect=lambda url, *a, **k: objects[url]), \
                        patch.object(OCI.subprocess, 'run'), \
                        patch('musl_release.verify_publication_signature', return_value=signer), \
                        patch.object(OCI.DISTRIBUTION, 'download_asset', side_effect=download), \
                        patch.object(OCI, 'validate_bundle'), patch.object(OCI, 'verify_release_tag'), \
                        patch.object(OCI.DISTRIBUTION, 'receive_source', side_effect=ValueError('stop at source intake')) as receive:
                    with self.assertRaisesRegex(ValueError, 'stop at source intake'):
                        OCI.public_oci('x64', 1, root/'work', root/'output', sdk_version=version)
                    receive.assert_called_once_with('x64', root/'work/source', anonymous=True, sdk_version=version)


if __name__ == '__main__':
    unittest.main()
