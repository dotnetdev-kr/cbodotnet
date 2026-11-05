import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import published_sdk_coexistence as MULTI


def complete_policy():
    """Extend actual postverification shapes without granting a real receipt."""
    policy = MULTI.load_status(); contract = MULTI.load_contract()
    for channel in ('deb', 'rpm'):
        template = copy.deepcopy(policy['channels'][channel]['receipts'][0])
        receipts = []
        for version in MULTI.VERSIONS:
            row = copy.deepcopy(template)
            row['identity'].update(sdkVersion=version, sourceReleaseTag='sdk-' + version,
                sourceManifestSha256=contract['releases'][version]['manifestSha256'])
            if version == '10.0.403':
                row['identity']['packageRevision'] = 3 if channel == 'deb' else 2
            tag = MULTI.release_tag(channel, version, row['identity']['packageRevision'])
            base = f'https://github.com/{MULTI.REPOSITORY}/releases/download/{tag}/'
            row.update(tag=tag, manifestUrl=base + MULTI.MANIFEST, signatureUrl=base + MULTI.SIGNATURE)
            if version.startswith('3.'):
                from native_curl_fixture import evidence
                for report in row['postVerification']['reports']:
                    for target in report['aptTargets' if channel == 'deb' else 'rpmTargets']:
                        target.update(evidence(version, report['architecture'], channel))
            if channel == 'rpm' and version.startswith(('3.', '5.')):
                from native_curl_fixture import ca_evidence
                for report in row['postVerification']['reports']:
                    for target in report['rpmTargets']:
                        if target['variant'] == 'fedora-45':
                            target.update(ca_evidence())
                            target['nativeCaBundle']['version'] = target['target']['dependencies']['ca-certificates']
            receipts.append(row)
        policy['channels'][channel]['receipts'] = receipts
    return policy, contract


def fake_publication(directory, channel='deb'):
    policy, contract = complete_policy()
    version = MULTI.VERSIONS[0]
    identity = dict(channel=channel, sdkVersion=version, packageRevision=3,
        sourceReleaseTag='sdk-' + version, sourceManifestSha256=contract['releases'][version]['manifestSha256'])
    fingerprint = 'A' * 40
    source = dict(manifestUrl='https://github.com/' + MULTI.REPOSITORY + '/releases/download/sdk-' + version + '/release-manifest.json', architectures={})
    for arch in ('x64', 'aarch64'):
        source['architectures'][arch] = dict(provenance=dict(runId='2', runAttempt='1', artifactId='3', projectCommit='b' * 40),
            **{kind: dict(name=kind + '-' + arch, size=123, sha256='c' * 64, url='https://example.invalid/' + kind) for kind in ('sdk', 'source', 'evidence')})
    assets = []; records = []; repositories = []
    for target in policy['channels'][channel]['candidateMatrix']:
        variant, arch = target['variant'], target['architecture']
        name = channel + '-' + variant + '-' + arch
        assets.append(dict(name=name, size=42, sha256='d' * 64))
        record = dict(identity=dict(identity, variant=variant, targetRid=MULTI.ARCHITECTURES[arch]['rid']), architecture=arch,
            producer=source['architectures'][arch]['provenance'], source=dict(source['architectures'][arch], sourceManifestUrl=source['manifestUrl']),
            artifact=dict(name='package', size=42, sha256='d' * 64), report=dict(sha256='e' * 64))
        records.append(dict(record=record, artifactAsset=name, reportAsset=name + '-report'))
    for variant in contract['channels'][channel]['variants']:
        name = channel + '-' + variant + '.tar.gz'
        assets.append(dict(name=name, size=100, sha256='f' * 64))
        repository = dict(asset=name, kind='apt-repository' if channel == 'deb' else 'rpm-repository', variants=[variant])
        if channel == 'deb':
            from apt_release import release_tag
            repository.update(delivery='github-release-flat', releaseTag=release_tag(variant, version, 3),
                flatAssets=[dict(name=name, size=20, sha256='a' * 64) for name in ('InRelease', 'Release', 'Release.gpg',
                    'Packages', 'Packages.gz', 'repository-manifest.json', 'cbodotnet-archive-keyring.gpg')])
        repositories.append(repository)
    tag = MULTI.release_tag(channel, version, 3)
    manifest = dict(schemaVersion=1, contractVersion=contract['schemaVersion'], repository=MULTI.REPOSITORY,
        status='validated-complete-matrix', identity=identity, tag=tag, signingFingerprint=fingerprint,
        records=records, repositories=repositories, assets=assets)
    MULTI.save(directory / MULTI.MANIFEST, manifest)
    (directory / MULTI.SIGNATURE).write_bytes(b'unit-test-signature-placeholder')
    base = f'https://github.com/{MULTI.REPOSITORY}/releases/download/{tag}/'
    digest = MULTI.APT.digest(directory / MULTI.MANIFEST)
    receipt = dict(identity=identity, tag=tag, signingFingerprint=fingerprint, manifestSha256=digest, manifestUrl=base + MULTI.MANIFEST,
        repositories=repositories, publications=MULTI.publication_rows(manifest, digest, base),
        assets=[dict(item, url=base + item['name']) for item in [*assets, MULTI.descriptor(directory / MULTI.MANIFEST), MULTI.descriptor(directory / MULTI.SIGNATURE)]])
    return receipt, manifest, source, policy, contract


class AdmissionTests(unittest.TestCase):
    def test_exact_eight_by_two_channel_gate_accepts_only_complete_postverified_receipts(self):
        policy, contract = complete_policy()
        rows = MULTI.selected_receipts(policy, contract)
        self.assertEqual(16, len(rows))
        self.assertEqual(set(MULTI.VERSIONS), {row['identity']['sdkVersion'] for row in rows})

    def test_missing_unqualified_duplicate_and_partial_native_proofs_fail_closed(self):
        for mutation in ('missing', 'unqualified-latest', 'duplicate', 'partial-architecture', 'foreign-source',
                         'foreign-run', 'old-10-selector', 'missing-core3-native-handler', 'missing-fedora-ca-proof'):
            with self.subTest(mutation=mutation):
                policy, contract = complete_policy()
                rows = policy['channels']['deb']['receipts']
                if mutation == 'missing': rows.pop()
                elif mutation == 'unqualified-latest':
                    latest = copy.deepcopy(rows[0]); latest['identity']['packageRevision'] += 1; latest['status'] = 'packaged-unqualified'; rows.append(latest)
                elif mutation == 'duplicate': rows.append(copy.deepcopy(rows[0]))
                elif mutation == 'partial-architecture': rows[0]['postVerification']['reports'].pop()
                elif mutation == 'foreign-source': rows[0]['identity']['sourceManifestSha256'] = '0' * 64
                elif mutation == 'foreign-run': rows[0]['postVerification']['workflow']['url'] = 'https://example.invalid/actions/runs/1'
                elif mutation == 'old-10-selector': rows[0]['identity']['packageRevision'] = 1
                elif mutation == 'missing-core3-native-handler':
                    rows[-1]['postVerification']['reports'][0]['aptTargets'][0].pop('nativeCurlHandler')
                else:
                    rpm = policy['channels']['rpm']['receipts'][-1]
                    fedora = next(target for target in rpm['postVerification']['reports'][0]['rpmTargets']
                                  if target['variant'] == 'fedora-45')
                    fedora.pop('nativeCaBundle')
                with self.assertRaises(ValueError): MULTI.selected_receipts(policy, contract)

    def test_missing_current_publications_stop_before_download_and_container(self):
        policy, _ = complete_policy(); policy['channels']['rpm']['receipts'].pop()
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(preflight=Path(temporary) / 'absent', variant='ubuntu-24.04', arch='x64', workspace=Path(temporary) / 'native')
            with patch.object(MULTI, 'load_status', return_value=policy), patch.object(MULTI, 'fetch') as fetch, patch.object(MULTI, 'run') as run:
                with self.assertRaises(ValueError): MULTI.native(args)
                fetch.assert_not_called(); run.assert_not_called()
                self.assertFalse(args.workspace.exists())


class SignedBindingTests(unittest.TestCase):
    def test_signed_targets_producers_asset_bytes_and_flat_repository_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt, manifest, source, policy, contract = fake_publication(directory)
            self.assertIs(manifest, MULTI.verified_manifest(receipt, manifest, directory, 'A' * 40, source, policy, contract))
            for mutation in ('producer', 'sdk-digest', 'source-digest', 'artifact-digest', 'missing-cpu', 'wrong-signer', 'receipt-assets', 'receipt-targets', 'historical-pool', 'flat-tag'):
                candidate = copy.deepcopy(manifest); supplied = copy.deepcopy(receipt); expected_source = copy.deepcopy(source); signer = 'A' * 40
                if mutation == 'producer': candidate['records'][0]['record']['producer']['runId'] = '999'
                elif mutation == 'sdk-digest': candidate['records'][0]['record']['source']['sdk']['sha256'] = '0' * 64
                elif mutation == 'source-digest': candidate['records'][0]['record']['identity']['sourceManifestSha256'] = '0' * 64
                elif mutation == 'artifact-digest': candidate['records'][0]['record']['artifact']['sha256'] = '0' * 64
                elif mutation == 'missing-cpu': candidate['records'].pop()
                elif mutation == 'wrong-signer': signer = 'B' * 40
                elif mutation == 'receipt-assets': supplied['assets'][0]['sha256'] = '0' * 64
                elif mutation == 'receipt-targets': supplied['publications'].pop()
                elif mutation == 'historical-pool':
                    candidate['repositories'][0].pop('delivery'); supplied['repositories'] = candidate['repositories']
                else:
                    candidate['repositories'][0]['releaseTag'] = 'repository-deb-wrong'; supplied['repositories'] = candidate['repositories']
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    MULTI.verified_manifest(supplied, candidate, directory, signer, expected_source, policy, contract)

    def test_duplicate_or_unsafe_signed_asset_names_fail(self):
        for rows in ([dict(name='../package', size=1, sha256='a' * 64)],
                     [dict(name='package', size=1, sha256='a' * 64)] * 2,
                     [dict(name='package', size=0, sha256='a' * 64)]):
            with self.assertRaises(ValueError): MULTI.asset_map(rows)

    def test_source_manifest_digest_is_checked_before_source_api_record_use(self):
        policy, contract = complete_policy()
        with tempfile.TemporaryDirectory() as temporary:
            location = Path(temporary) / 'sources' / MULTI.VERSIONS[0]; location.mkdir(parents=True)
            (location / 'release-manifest.json').write_bytes(b'foreign pinned source')
            with self.assertRaisesRegex(ValueError, 'Pinned public SDK manifest changed'):
                MULTI.preflight(Path(temporary), policy=policy, contract=contract)


class RuntimePlanTests(unittest.TestCase):
    def test_live_project_metadata_uses_no_credentials_and_must_match_signed_bytes(self):
        raw = b'<repomd>approved</repomd>'
        url = 'https://dotnetdev.kr/cbodotnet/packages/rpm/fedora-45/sdk-3.0.103-r1/repodata/repomd.xml'
        expected = dict(name='repomd.xml', size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'observed.xml'
            with patch.dict(os.environ, GH_TOKEN='fixture-never-send-to-pages'), \
                    patch.object(MULTI.urllib.request, 'urlopen', return_value=io.BytesIO(raw)) as opened:
                self.assertEqual(raw, MULTI.fetch_hosted_metadata(url, path, expected))
                request = opened.call_args.args[0]
                self.assertEqual(url, request.full_url)
                self.assertIsNone(request.get_header('Authorization'))
                self.assertEqual(raw, path.read_bytes())
            for corrupted in (raw + b'extra', raw[:-1], b'x' * len(raw)):
                target = Path(temporary) / 'bad.xml'
                with self.subTest(payload=corrupted), patch.object(MULTI.urllib.request, 'urlopen', return_value=io.BytesIO(corrupted)):
                    with self.assertRaisesRegex(ValueError, 'differs from its signed publication'):
                        MULTI.fetch_hosted_metadata(url, target, expected)
                self.assertFalse(target.exists())

    def test_live_metadata_reader_does_not_broaden_github_or_project_origin_boundaries(self):
        valid = 'https://dotnetdev.kr/cbodotnet/packages/rpm/rocky-9.8/sdk-5.0.214-r1/repodata/repomd.xml.asc'
        expected = dict(name='repomd.xml.asc', size=1, sha256='a' * 64)
        bad_urls = [valid.replace('https:', 'http:'), valid.replace('dotnetdev.kr', 'example.invalid'),
                    valid + '?token=forbidden', valid + '#fragment', valid.replace('/repodata/', '/../repodata/'),
                    valid.replace('5.0.214', '11.0.100'), valid.replace('repomd.xml.asc', 'Packages')]
        with tempfile.TemporaryDirectory() as temporary, patch.object(MULTI.urllib.request, 'urlopen') as opened:
            for url in bad_urls:
                with self.subTest(url=url), self.assertRaisesRegex(ValueError, 'Untrusted hosted RPM metadata'):
                    MULTI.fetch_hosted_metadata(url, Path(temporary) / 'bad', expected)
            for descriptor in (None, dict(expected, size=0), dict(expected, size=2**20 + 1), dict(expected, sha256='bad')):
                with self.subTest(descriptor=descriptor), self.assertRaisesRegex(ValueError, 'bounded signed descriptor'):
                    MULTI.fetch_hosted_metadata(valid, Path(temporary) / 'bad', descriptor)
            opened.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'Untrusted GitHub metadata URL'):
                MULTI.fetch(valid, Path(temporary) / 'bad', expected=expected)

    def test_all_eight_native_targets_and_no_publishing_or_secret_permissions(self):
        self.assertEqual({'ubuntu-24.04', 'debian-13', 'fedora-45', 'rocky-9.8'}, set(MULTI.BASES))
        self.assertTrue(all(set(rows) == {'x64', 'aarch64'} for rows in MULTI.BASES.values()))
        workflow = (ROOT / '.github/workflows/published-sdk-coexistence.yml').read_text()
        self.assertIn('contents: read', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('DOWNSTREAM_SIGNING_KEY', workflow)
        self.assertIn('needs: authenticate', workflow)

    def test_genuine_legacy_process_inherits_scope_and_modern_child_checks_restoration_and_tls(self):
        script = MULTI.nested_environment_script()
        self.assertIn('ProcessStartInfo("/usr/bin/cbodotnet-10.0"', script)
        self.assertIn('cbodotnet-3.0 bin/Debug/netcoreapp3.0/Parent.dll', script)
        self.assertIn('Environment.GetEnvironmentVariable("CBODOTNET_COMPAT_SCOPE")!="rocky9"', script)
        self.assertIn('Legacy environment leaked into modern child', script)
        self.assertIn('published-tls12-passed', script)
        self.assertNotIn('start.Environment', script)
        subprocess.run(['bash', '-n'], input=script, text=True, check=True)

    def test_wrong_native_cpu_or_offline_network_fails(self):
        contract = MULTI.load_contract()
        with patch.object(MULTI.os, 'geteuid', return_value=0), patch.object(MULTI.platform, 'machine', return_value='x86_64'), patch.object(MULTI.Path, 'is_file', return_value=True):
            with self.assertRaisesRegex(ValueError, 'Matching native CPU'): MULTI.check_container('debian-13', 'aarch64')
        with patch.object(MULTI.os, 'geteuid', return_value=0), patch.object(MULTI.platform, 'machine', return_value='x86_64'), \
             patch.object(MULTI.Path, 'is_file', return_value=True), patch.object(MULTI.Path, 'read_text', return_value='ID=debian\nVERSION_ID=13\n'), \
             patch.object(MULTI, 'load_contract', return_value=contract), \
             patch.object(MULTI, 'run', return_value='amd64\n'), \
             patch.object(MULTI.Path, 'iterdir', return_value=iter([Path('/sys/class/net/lo'), Path('/sys/class/net/eth0')])):
            with self.assertRaisesRegex(ValueError, '--network none'): MULTI.check_container('debian-13', 'x64', offline=True)


if __name__ == '__main__':
    unittest.main()
