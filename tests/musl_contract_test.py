"""Reject musl/glibc identity confusion and unqualified native producer bytes."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_contract as MUSL
import release_catalog as GLIBC


def fixture():
    version, revision = '10.0.403', 1
    tag = MUSL.producer_tag(version, revision)
    manifest = dict(schemaVersion=1, kind='musl-sdk-producer-release', repository=MUSL.REPOSITORY,
        libc='musl', sdkVersion=version, producerRevision=revision, tag=tag, architectures={})
    payloads = {}
    for arch, identity in MUSL.ARCHITECTURES.items():
        entry = dict(targetRid=identity['rid'], provenance=dict(MUSL.SOURCE, libc='musl', targetRid=identity['rid'],
            projectCommit='a' * 40, workflow='.github/workflows/musl-sdk.yml', runId='123', runAttempt='1',
            artifactId='456' if arch == 'x64' else '457',
            workflowUrl=f'https://github.com/{MUSL.REPOSITORY}/actions/runs/123'))
        for kind in MUSL.KINDS:
            name = MUSL.producer_asset_name(kind, version, arch, revision)
            data = (kind + arch).encode()
            payloads[name] = data
            entry[kind] = dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest())
        manifest['architectures'][arch] = entry
    checksums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in payloads.items()).encode()
    manifest['checksums'] = dict(name='SHA256SUMS', size=len(checksums), sha256=hashlib.sha256(checksums).hexdigest())
    raw = json.dumps(manifest).encode()
    payloads.update({'SHA256SUMS': checksums, 'release-manifest.json': raw})
    release = dict(tag_name=tag, draft=False, prerelease=False,
        html_url=f'https://github.com/{MUSL.REPOSITORY}/releases/tag/{tag}', assets=[
            dict(name=name, size=len(data), state='uploaded', digest='sha256:' + hashlib.sha256(data).hexdigest(),
                browser_download_url=f'https://github.com/{MUSL.REPOSITORY}/releases/download/{tag}/{name}')
            for name, data in payloads.items()])
    catalog = dict(schemaVersion=1, kind='qualified-musl-sdk-producers', repository=MUSL.REPOSITORY,
        libc='musl', builds=[dict(target='net10-musl', sdkVersion=version, producerRevision=revision,
            libc='musl', sourceReleaseTag=tag, sourceManifestSha256=hashlib.sha256(raw).hexdigest(),
            architectures={arch: copy.deepcopy(entry['provenance']) for arch, entry in manifest['architectures'].items()})])
    return release, manifest, raw, checksums, catalog, payloads


class MuslContractTests(unittest.TestCase):
    def setUp(self):
        self.release, self.manifest, self.raw, self.checksums, self.catalog, self.payloads = fixture()

    def test_separate_candidate_policy_requires_an_explicit_qualified_producer(self):
        contract = MUSL.load_contract()
        self.assertFalse(contract['publicationAllowed'])
        self.assertEqual('separate-issue-30', contract['qualification']['installerAdmission'])
        empty_catalog = copy.deepcopy(MUSL.load_qualification_catalog())
        empty_catalog['builds'] = []
        with self.assertRaisesRegex(ValueError, 'not independently qualified'):
            MUSL.require_qualified_producer(self.raw, catalog=empty_catalog)
        status = json.loads((ROOT / 'releases/musl-status.json').read_bytes())
        self.assertEqual('musl-distribution-availability', status['kind'])
        self.assertEqual('musl', status['libc'])

    def test_public_spelling_and_rid_are_distinct_explicit_mappings(self):
        self.assertEqual('linux-musl-arm64', MUSL.ARCHITECTURES['aarch64']['rid'])
        self.assertEqual('aarch64', MUSL.ARCHITECTURES['aarch64']['apk'])
        self.assertIn('-linux-musl-aarch64-', MUSL.archive_name('10.0.403', 'aarch64'))
        self.assertEqual('10.0.403-alpine324-musl-r1', MUSL.oci_tag('10.0.403'))
        for arch in ('arm64', 'amd64', '../x64'):
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                MUSL.archive_name('10.0.403', arch)

    def test_existing_strict_source_catalog_ignores_new_producer_prefix(self):
        catalog = GLIBC.build_catalog([self.release], lambda *args: self.fail('Old reader must not fetch musl assets'),
                                      MUSL.REPOSITORY, generated_at='2026-11-07T00:00:00Z')
        self.assertEqual([], catalog['releases'])
        self.assertNotEqual(MUSL.distribution_tag('archive', '10.0.403'), 'distribution-archive-sdk-10.0.403-r1')

    def test_complete_producer_release_and_exact_qualified_manifest_are_accepted(self):
        self.assertEqual(self.manifest, MUSL.validate_producer_release(self.release, self.raw, self.checksums))
        self.assertEqual(self.manifest, MUSL.require_qualified_producer(self.raw, catalog=self.catalog))

    def test_glibc_identity_cannot_enter_a_musl_manifest(self):
        for field, value in (('libc', 'glibc'), ('targetRid', 'linux-x64')):
            changed = copy.deepcopy(self.manifest)
            changed['architectures']['x64']['provenance'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'libc or target RID'):
                MUSL.validate_producer_manifest(changed)
        self.manifest['architectures']['x64']['targetRid'] = 'linux-x64'
        with self.assertRaisesRegex(ValueError, 'target RID'):
            MUSL.validate_producer_manifest(self.manifest)

    def test_missing_native_architecture_is_rejected(self):
        del self.manifest['architectures']['aarch64']
        with self.assertRaisesRegex(ValueError, 'both native architectures'):
            MUSL.validate_producer_manifest(self.manifest)
        del self.catalog['builds'][0]['architectures']['aarch64']
        with self.assertRaisesRegex(ValueError, 'both native architectures'):
            MUSL.validate_qualification_catalog(self.catalog)

    def test_unreviewed_source_bootstrap_workflow_or_tag_is_rejected(self):
        for field, value in (('sourceCommit', 'b' * 40), ('sharedVmrCommit', 'b' * 40),
                             ('bootstrapSdk', '10.0.402'), ('sharedSdk', '10.0.115'),
                             ('runtimeVersion', '10.0.15'), ('workflow', '.github/workflows/net10-sdk.yml')):
            changed = copy.deepcopy(self.manifest)
            changed['architectures']['x64']['provenance'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MUSL.validate_producer_manifest(changed)
        for tag in ('sdk-10.0.403', 'sdk-musl-10.0.403', 'musl-sdk-10.0.403-r2'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                MUSL.validate_producer_manifest(dict(self.manifest, tag=tag))

    def test_exact_manifest_bytes_and_per_arch_run_identity_are_pinned(self):
        with self.assertRaisesRegex(ValueError, 'exact manifest bytes'):
            MUSL.require_qualified_producer(self.raw + b'\n', catalog=self.catalog)
        for field, value in (('artifactId', '999'), ('runAttempt', '2'), ('projectCommit', 'b' * 40)):
            changed = copy.deepcopy(self.catalog)
            changed['builds'][0]['architectures']['x64'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'qualified native run'):
                MUSL.require_qualified_producer(self.raw, catalog=changed)

    def test_duplicate_catalog_identity_and_glibc_catalog_are_rejected(self):
        self.catalog['builds'].append(copy.deepcopy(self.catalog['builds'][0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            MUSL.validate_qualification_catalog(self.catalog)
        old_catalog = json.loads((ROOT / 'releases/qualified-builds.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'Invalid musl qualification catalog'):
            MUSL.validate_qualification_catalog(old_catalog)

    def test_wrong_asset_name_missing_source_or_unexpected_payload_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['architectures']['aarch64']['sdk']['name'] = 'cbodotnet-sdk-10.0.403-linux-aarch64.tar.gz'
        with self.assertRaisesRegex(ValueError, 'Unexpected asset name'):
            MUSL.validate_producer_manifest(changed)
        changed = copy.deepcopy(self.manifest)
        del changed['architectures']['x64']['source']
        with self.assertRaisesRegex(ValueError, 'Missing asset descriptor'):
            MUSL.validate_producer_manifest(changed)
        self.release['assets'].append(dict(name='unexpected.sh'))
        with self.assertRaisesRegex(ValueError, 'incomplete or unexpected'):
            MUSL.validate_producer_release(self.release, self.raw, self.checksums)

    def test_checksum_tampering_is_rejected(self):
        with self.assertRaises(ValueError):
            MUSL.validate_producer_release(self.release, self.raw, self.checksums.replace(b'  ', b' *', 1))
        self.release['assets'][0]['browser_download_url'] = 'https://example.org/sdk.tar.gz'
        with self.assertRaisesRegex(ValueError, 'Unexpected asset download URL'):
            MUSL.validate_producer_release(self.release, self.raw, self.checksums)

    def test_candidate_policy_cannot_silently_admit_installer_or_glibc_layer(self):
        for field, value in (('installerAdmission', 'admitted'), ('glibcCompatibilityLayerAllowed', True),
                             ('completePayloadElfAuditRequired', False)):
            contract = copy.deepcopy(MUSL.load_contract())
            contract['qualification'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MUSL.validate_contract(contract)

    def test_apk_and_oci_preparation_bind_exact_sdk_bytes_and_preserve_official_dotnet(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = self.manifest['architectures']['x64']['sdk']
            path = Path(temporary) / sdk['name']
            path.write_bytes(self.payloads[sdk['name']])
            for channel in ('apk', 'oci', 'archive'):
                plan = MUSL.verified_plan(self.release, self.raw, self.checksums, path, channel, 'alpine-3.24', 'x64', catalog=self.catalog)
                self.assertEqual('musl', plan['libc'])
                self.assertEqual('linux-musl-x64', plan['targetRid'])
                self.assertEqual('/opt/cbodotnet/10.0', plan['package']['root'])
                self.assertEqual('/usr/bin/cbodotnet-10.0', plan['package']['launcher'])
                self.assertEqual('/usr/bin/cbodotnet', plan['commands']['default'])
                self.assertEqual('/usr/local/bin/dotnet', plan['commands']['containerDotnet'])
                self.assertFalse(plan['publicationAllowed'])
                self.assertNotIn('gcompat', plan['dependencies'])
            path.write_bytes(b'changed SDK')
            with self.assertRaisesRegex(ValueError, 'archive name, size or digest'):
                MUSL.verified_plan(self.release, self.raw, self.checksums, path, 'apk', 'alpine-3.24', 'x64', catalog=self.catalog)


if __name__ == '__main__':
    unittest.main()
