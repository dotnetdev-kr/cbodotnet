"""Complete evidence remains authenticated across staging, publication and intake."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import musl_evidence_transport as E
import musl_source_transport as S
import musl_contract as C
import musl_release as R
import musl_distribution as D
import musl_packages as APK
import cbodotnetup_musl as INSTALLER
import downstream_release as PHYSICAL
from downstream_release import descriptor, encoded
import musl_source_transport_test as SOURCE_TESTS
from musl_source_transport_test import public_packet, bounds as source_bounds
from musl_contract_test import fixture


@contextlib.contextmanager
def bounds(part=64, limit=128, maximum=1024):
    with mock.patch.multiple(E, PART_BYTES=part, MAX_RELEASE_BYTES=limit, MAX_ARCHIVE_BYTES=maximum):
        yield


def packet(base, size=201):
    original = base / 'original-evidence.tar.gz'; original.write_bytes(bytes(range(size)))
    output = base / 'stage'; output.mkdir()
    evidence, transport = E.stage(original, output, C.producer_asset_name('evidence', '6.0.136', 'x64'))
    return original, output, dict(evidence=evidence, **(dict(evidenceTransport=transport) if transport else {}))


def reseal(entry):
    transport = entry['evidenceTransport']; raw = encoded(E.document(transport))
    transport['descriptor'] = dict(name=entry['evidence']['name']+'.transport.json', size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def refresh_public(release, manifest, catalog, payloads):
    sums = R.producer_checksum_bytes(manifest)
    manifest['checksums'] = dict(name='SHA256SUMS', size=len(sums), sha256=hashlib.sha256(sums).hexdigest())
    raw = encoded(manifest); payloads.update({'release-manifest.json': raw, 'SHA256SUMS': sums})
    catalog['builds'][0]['sourceManifestSha256'] = hashlib.sha256(raw).hexdigest()
    release['assets'] = [dict(name=name, size=len(body), state='uploaded', digest='sha256:'+hashlib.sha256(body).hexdigest(),
        browser_download_url=f'https://github.com/{C.REPOSITORY}/releases/download/{manifest["tag"]}/{name}')
        for name, body in payloads.items()]


def evidence_public_packet(base, source_multipart):
    result = public_packet(base, source_multipart)
    release, manifest, catalog, payloads, _ = result
    entry = manifest['architectures']['x64']; name = entry['evidence']['name']
    original = base / name
    # Preserve original controls and additional imported-input evidence bytes.
    with tarfile.open(fileobj=io.BytesIO(payloads.pop(name)), mode='r:gz') as previous, tarfile.open(original, 'w:gz') as archive:
        for member in previous:
            archive.addfile(member, previous.extractfile(member))
        raw = random.Random(5).randbytes(9000); member = tarfile.TarInfo('imported-inputs/original.bin'); member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
    evidence, transport = E.stage(original, base / 'stage', name)
    assert transport is not None
    entry['evidence'] = evidence; entry['evidenceTransport'] = transport
    for row in E.evidence_assets(entry): payloads[row['name']] = (base / 'stage' / row['name']).read_bytes()
    refresh_public(release, manifest, catalog, payloads)
    return result


class EvidenceBoundaryTests(unittest.TestCase):
    def test_existing_physical_descriptor_still_rejects_two_gib_before_hashing(self):
        path = mock.Mock(name='physical-asset'); path.name = 'physical-asset'
        for size in (0, 2**31, 2**31+1):
            path.stat.return_value = SimpleNamespace(st_size=size)
            with self.subTest(size=size), mock.patch.object(PHYSICAL, 'ordinary_file', return_value=path), \
                    mock.patch.object(PHYSICAL, 'sha256_file', side_effect=AssertionError('Oversized physical asset hashed')):
                with self.assertRaisesRegex(ValueError, 'smaller than 2 GiB'): PHYSICAL.descriptor('physical-asset')
        path.stat.return_value = SimpleNamespace(st_size=2**31-1)
        with mock.patch.object(PHYSICAL, 'ordinary_file', return_value=path), mock.patch.object(PHYSICAL, 'sha256_file', return_value='a'*64):
            self.assertEqual(2**31-1, PHYSICAL.descriptor('physical-asset')['size'])

    def test_exact_whole_and_both_hashes_private_materialization_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            base = Path(temporary); original, stage, entry = packet(base)
            self.assertEqual([64, 64, 64, 9], [r['size'] for r in entry['evidenceTransport']['parts']])
            self.assertFalse((stage / entry['evidence']['name']).exists())
            before = {p.name for p in stage.iterdir()}
            with E.materialize_directory(stage, entry) as whole:
                self.assertNotEqual(whole.parent, stage)
                self.assertEqual(original.read_bytes(), whole.read_bytes())
                self.assertEqual(entry['evidence'], S.fingerprint(whole))
                private = whole.parent
            self.assertFalse(private.exists()); self.assertEqual(before, {p.name for p in stage.iterdir()})
            self.assertEqual(5, len(E.evidence_assets(entry)))

    def test_legacy_identity_and_whole_bytes_stay_three_field(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            original, stage, entry = packet(Path(temporary), size=100)
            self.assertNotIn('evidenceTransport', entry)
            self.assertEqual({'name', 'size', 'sha256'}, set(entry['evidence']))
            self.assertEqual([entry['evidence']], E.evidence_assets(entry))
            with E.materialize_directory(stage, entry) as whole:
                self.assertEqual(stage, whole.parent); self.assertEqual(original.read_bytes(), whole.read_bytes())
            self.assertTrue(whole.exists())

    def test_missing_duplicate_reordered_wrong_boundary_kind_alias_and_unknown_keys_reject(self):
        mutations = [lambda t:t['parts'].pop(), lambda t:t['parts'].reverse(),
            lambda t:t['parts'].__setitem__(1, copy.deepcopy(t['parts'][0])),
            lambda t:t['parts'][0].update(size=63), lambda t:t.update(kind=S.KIND),
            lambda t:t.update(partSizeBytes=True), lambda t:t.update(schemaVersion=True),
            lambda t:t.update(unexpected=True), lambda t:t['parts'][0].update(name='../alias'),
            lambda t:t.update(archive=dict(t['archive'], name='source.tar.gz'))]
        with tempfile.TemporaryDirectory() as temporary, bounds():
            _, _, entry = packet(Path(temporary))
            for mutate in mutations:
                changed = copy.deepcopy(entry); mutate(changed['evidenceTransport']); reseal(changed)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError): E.validate(changed)
            changed = copy.deepcopy(entry); changed['sourceTransport'] = changed.pop('evidenceTransport')
            with self.assertRaises(ValueError): E.evidence_assets(changed)
            changed = copy.deepcopy(entry); changed.pop('evidenceTransport')
            with self.assertRaises(ValueError): E.evidence_assets(changed)

    def test_member_and_whole_hashes_truncation_growth_and_missing_part_fail_without_residue(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            base = Path(temporary); _, stage, entry = packet(base)
            def altered_part(row, change):
                return io.BytesIO(change((stage / row['name']).read_bytes()) if row is entry['evidenceTransport']['parts'][0]
                                  else (stage / row['name']).read_bytes())
            changes = [lambda raw:raw[:-1], lambda raw:raw+b'x', lambda raw:b'X'*len(raw)]
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    E.authenticate(entry, lambda row:altered_part(row, change), base/'restored.tar.gz')
                self.assertFalse((base/'restored.tar.gz').exists())
            for location in ('parts', 'archive'):
                for algorithm in ('sha256', 'sha512'):
                    changed = copy.deepcopy(entry)
                    row = changed['evidenceTransport']['parts'][0] if location == 'parts' else changed['evidence']
                    row[algorithm] = '0' * (64 if algorithm == 'sha256' else 128)
                    if location == 'archive': changed['evidenceTransport']['archive'] = changed['evidence']
                    reseal(changed)
                    with self.subTest(location=location, algorithm=algorithm), self.assertRaises(ValueError):
                        E.authenticate(changed, lambda row:(stage/row['name']).open('rb'), base/'restored.tar.gz')
                    self.assertFalse((base/'restored.tar.gz').exists())
            (stage/entry['evidenceTransport']['parts'][1]['name']).unlink()
            with self.assertRaises(ValueError):
                with E.materialize_directory(stage, entry): self.fail('Missing evidence accepted')
            self.assertFalse(any(p.name.startswith('musl-evidence-private-') for p in base.iterdir()))

    def test_sidecar_noncanonical_tampering_and_output_overwrite_reject(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            base = Path(temporary); _, stage, entry = packet(base)
            sidecar = stage/entry['evidenceTransport']['descriptor']['name']; original = sidecar.read_bytes()
            for raw in (original+b'\n', encoded(dict(E.document(entry['evidenceTransport']), kind=S.KIND))):
                with self.assertRaises(ValueError): E.validate_sidecar(entry, raw)
            sidecar.write_bytes(original+b'x')
            with self.assertRaises(ValueError):
                with E.materialize_directory(stage, entry): self.fail('Changed sidecar accepted')
            target = base/'retained'; target.write_bytes(b'retained original')
            with self.assertRaises(ValueError): E.authenticate(entry, lambda row:None, target)
            self.assertEqual(b'retained original', target.read_bytes())

    def test_staging_rejects_upper_limit_empty_alias_and_reused_output(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            base = Path(temporary); source = base/'original'; stage = base/'stage'; stage.mkdir()
            name = C.producer_asset_name('evidence', '6.0.136', 'x64')
            for raw in (b'', b'x'*1024):
                source.write_bytes(raw)
                with self.assertRaises(ValueError): E.stage(source, stage, name)
            source.write_bytes(b'x'*201)
            for invalid in ('source.tar.gz', '../alias-evidence.tar.gz'):
                with self.assertRaises(ValueError): E.stage(source, stage, invalid)
            E.stage(source, stage, name)
            original = {p.name:p.read_bytes() for p in stage.iterdir()}
            with self.assertRaises(FileExistsError): E.stage(source, stage, name)
            self.assertEqual(original, {p.name:p.read_bytes() for p in stage.iterdir()})

    def test_redirected_input_part_and_output_parent_reject(self):
        with tempfile.TemporaryDirectory() as temporary, bounds():
            base = Path(temporary); original, stage, entry = packet(base)
            actual = Path.is_symlink
            linked = stage/entry['evidenceTransport']['parts'][0]['name']
            with mock.patch.object(Path, 'is_symlink', lambda p:p == linked or actual(p)):
                with self.assertRaisesRegex(ValueError, 'non-linked'):
                    with E.materialize_directory(stage, entry): self.fail('Redirected member accepted')
            with mock.patch.object(Path, 'is_symlink', lambda p:p == original or actual(p)):
                with self.assertRaisesRegex(ValueError, 'non-linked'): E.stage(original, stage, 'other-evidence.tar.gz')
            with mock.patch.object(Path, 'is_symlink', lambda p:p == stage or actual(p)):
                with self.assertRaisesRegex(ValueError, 'Ordinary evidence'):
                    with E.materialize_directory(stage, entry): self.fail('Redirected directory accepted')

    def test_mid_read_truncation_and_growth_reject_without_retry(self):
        for growth in (False, True):
            with self.subTest(growth=growth), tempfile.TemporaryDirectory() as temporary, bounds():
                base = Path(temporary); source = base/'original'; source.write_bytes(bytes(range(201)))
                output = base/'stage'; output.mkdir(); normal_open = Path.open; opens = 0
                def opened(path, mode='r', *args, **kwargs):
                    nonlocal opens
                    if path == source and mode == 'rb':
                        opens += 1
                        with normal_open(path, 'wb') as stream: stream.write(bytes(range(201))+b'x' if growth else b'')
                    return normal_open(path, mode, *args, **kwargs)
                with mock.patch.object(Path, 'open', new=opened):
                    with self.assertRaisesRegex(ValueError, 'grew|truncated'):
                        E.stage(source, output, 'original-evidence.tar.gz')
                self.assertEqual(1, opens)
                self.assertFalse(any(p.name.endswith('.transport.json') for p in output.iterdir()))


class EvidencePublicTests(unittest.TestCase):
    received = SOURCE_TESTS.PublicSourceRetrievalTests.received

    def test_complete_public_evidence_then_existing_real_source_verifier_with_both_source_forms(self):
        for multipart in (False, True):
            with self.subTest(sourceMultipart=multipart), tempfile.TemporaryDirectory() as temporary, \
                    bounds(part=2048, limit=4096, maximum=32768), \
                    source_bounds(part=2048, limit=4096 if multipart else 16384, maximum=32768):
                base = Path(temporary); public = evidence_public_packet(base, multipart)
                release, manifest, _, payloads, original = public; entry = manifest['architectures']['x64']
                C.validate_producer_release(release, payloads['release-manifest.json'], payloads['SHA256SUMS'])
                self.assertNotIn(entry['evidence']['name'], payloads)
                report = self.received(base, public)
                self.assertEqual(multipart, report['multipart'])
                self.assertTrue(report['evidenceMultipart']); self.assertEqual(entry['evidence'], report['evidenceArchive'])
                self.assertEqual(original.read_bytes(), (base/'received/sources'/original.name).read_bytes())
                self.assertFalse((base/'received'/entry['evidence']['name']).exists())
                self.assertFalse((base/'received/imported-inputs').exists())
                self.assertFalse(any(p.name.startswith('musl-evidence-private-') for p in base.iterdir()))
                for name, raw in payloads.items(): (base/'stage'/name).write_bytes(raw)
                R.validate_source_stage(base/'stage')
                with E.materialize_directory(base/'stage', entry) as whole, tarfile.open(whole, 'r:gz') as archive:
                    self.assertEqual(random.Random(5).randbytes(9000), archive.extractfile('imported-inputs/original.bin').read())
                (base/'stage'/entry['evidence']['name']).write_bytes(b'unpublished whole must not remain')
                with self.assertRaisesRegex(ValueError, 'closed asset set'): R.validate_source_stage(base/'stage')

    def test_corrupted_remote_evidence_never_reaches_source_controls_or_source_verifier(self):
        with tempfile.TemporaryDirectory() as temporary, bounds(part=2048, limit=4096, maximum=32768):
            base = Path(temporary); public = evidence_public_packet(base, False)
            entry = public[1]['architectures']['x64']; name = entry['evidenceTransport']['parts'][1]['name']
            public[3][name] = b'X'*len(public[3][name])
            with mock.patch.object(S, 'source_controls', side_effect=AssertionError('Unauthenticated evidence parsed')), \
                    mock.patch.object(D, '_source_module', side_effect=AssertionError('Unauthenticated evidence reached source verifier')):
                with self.assertRaisesRegex(ValueError, 'Evidence multipart member'): self.received(base, public)
            self.assertFalse(any(p.name.startswith('musl-evidence-private-') for p in base.iterdir()))
            self.assertFalse((base/'received/sources').exists())

    def test_source_and_evidence_kind_or_archive_substitution_cannot_be_resealed_into_release(self):
        with tempfile.TemporaryDirectory() as temporary, bounds(part=2048, limit=4096, maximum=32768), \
                source_bounds(part=2048, limit=4096, maximum=32768):
            public = evidence_public_packet(Path(temporary), True); entry = public[1]['architectures']['x64']
            for key in ('evidenceTransport', 'sourceTransport'):
                bad = copy.deepcopy(public[1]); row = bad['architectures']['x64']
                row[key] = copy.deepcopy(entry['sourceTransport' if key == 'evidenceTransport' else 'evidenceTransport'])
                with self.subTest(key=key), self.assertRaises(ValueError): C.validate_producer_manifest(bad)

    def test_verified_plan_oci_and_installer_links_name_actual_evidence_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary, bounds(part=2048, limit=4096, maximum=32768):
            base = Path(temporary); release, manifest, catalog, payloads, _ = evidence_public_packet(base, False)
            entry = manifest['architectures']['x64']; sdk_path = base/entry['sdk']['name']; sdk_path.write_bytes(payloads[sdk_path.name])
            plan = C.verified_plan(release, payloads['release-manifest.json'], payloads['SHA256SUMS'], sdk_path,
                'oci', 'alpine-3.24', 'x64', catalog=catalog)
            self.assertEqual(entry['evidenceTransport'], plan['evidenceTransport'])
            output = base/'oci'; output.mkdir(); rootfs = output/'rootfs'; rootfs.mkdir()
            with mock.patch.object(APK, 'stage_payload', return_value=(output, rootfs, {}, {})):
                result = APK.build_oci_context(plan, sdk_path, output, APK.BASE_IMAGES['x64'])
            labels = result['labels']; physical = entry['evidenceTransport']['descriptor']
            self.assertTrue(labels['kr.dotnetdev.cbodotnet.evidence.url'].endswith(physical['name']))
            self.assertEqual(physical['sha256'], labels['kr.dotnetdev.cbodotnet.evidence.sha256'])
            self.assertEqual(entry['evidence']['sha512'], labels['kr.dotnetdev.cbodotnet.evidence.archive.sha512'])
        from cbodotnetup_musl_test import fixture as installer_fixture
        policy, status, signed, source, canonical = installer_fixture()
        entry = source['architectures']['x64']; transport = dict(descriptor=physical)
        entry['evidenceTransport'] = transport
        signed['records'][0]['build']['plan']['evidenceTransport'] = copy.deepcopy(transport)
        canonical = encoded(source); policy['sourceManifestSha256'] = hashlib.sha256(canonical).hexdigest()
        status['publications'][0]['identity']['sourceManifestSha256'] = policy['sourceManifestSha256']
        for row in signed['records']: row['build']['plan']['sourceManifestSha256'] = policy['sourceManifestSha256']
        with mock.patch.object(INSTALLER.CONTRACT, 'require_qualified_producer', return_value=source):
            record = INSTALLER.sdk_catalog_record('x64', policy=policy, status=status,
                authenticator=lambda receipt:signed, fetch=lambda url, maximum:canonical)
            self.assertTrue(record['evidence']['url'].endswith(physical['name']))
            signed['records'][0]['build']['plan']['evidenceTransport'] = dict(descriptor=dict(physical, sha256='0'*64))
            with self.assertRaises(ValueError): INSTALLER.sdk_catalog_record('x64', policy=policy, status=status,
                authenticator=lambda receipt:signed, fetch=lambda url, maximum:canonical)

    def test_legacy_all_existing_versions_retain_exact_manifest_checksum_asset_inventory(self):
        for version in ('10.0.403', '9.0.123', '8.0.133', '7.0.120'):
            release, manifest, raw, sums, _, payloads = fixture(version)
            before = copy.deepcopy(manifest)
            self.assertEqual(before, C.validate_producer_release(release, raw, sums))
            self.assertEqual(sums, R.producer_checksum_bytes(manifest)); self.assertEqual(8, len(payloads))
            self.assertEqual(before, manifest)

    def test_publication_uploads_only_physical_parts_then_real_private_and_public_postverification(self):
        with tempfile.TemporaryDirectory() as temporary, bounds(part=2048, limit=4096, maximum=32768):
            base = Path(temporary); previous, manifest, _, payloads, _ = evidence_public_packet(base, False)
            for name, raw in payloads.items(): (base/'stage'/name).write_bytes(raw)
            commit = manifest['architectures']['x64']['provenance']['projectCommit']
            run = dict(id=123, run_attempt=1, head_sha=commit, path=C.producer_workflow('6.0.136'), head_branch='main',
                event='workflow_dispatch', repository=dict(full_name=C.REPOSITORY), head_repository=dict(full_name=C.REPOSITORY),
                status='completed', conclusion='success')
            class API:
                def __init__(self): self.release = None; self.payloads = {}; self.downloads = []
                def find(self, tag): return None
                def api(self, endpoint, method='GET', body=None):
                    if '/actions/runs/' in endpoint: return run
                    if '/actions/artifacts/' in endpoint:
                        identity = int(endpoint.rsplit('/', 1)[-1]); arch = 'x64' if identity == 456 else 'aarch64'
                        return dict(id=identity, name=C.producer_artifact_name('6.0.136', arch, 123, 1), expired=False,
                            size_in_bytes=100, digest='sha256:'+'b'*64, workflow_run=dict(id=123, head_sha=commit,
                                head_branch='main', repository_id=10, head_repository_id=10))
                    if '/git/ref/tags/' in endpoint: return None
                    if method == 'POST':
                        self.release = dict(body, id=99, assets=[], html_url=previous['html_url']); return copy.deepcopy(self.release)
                    raise AssertionError('Unexpected API '+endpoint)
                def upload(self, release, path):
                    raw = path.read_bytes(); self.payloads[path.name] = raw
                    self.release['assets'].append(dict(name=path.name, size=len(raw), state='uploaded',
                        digest='sha256:'+hashlib.sha256(raw).hexdigest(),
                        browser_download_url=f'https://github.com/{C.REPOSITORY}/releases/download/{release["tag_name"]}/{path.name}'))
                def get(self, release): return copy.deepcopy(self.release)
                def publish(self, release): self.release['draft'] = False; return copy.deepcopy(self.release)
                def download(self, asset, destination, public=False):
                    self.downloads.append((public, asset['name'])); destination.write_bytes(self.payloads[asset['name']])
            api = API()
            with mock.patch.object(R, 'GitHubReleases', return_value=api), mock.patch.object(R, 'verify_release_tag'):
                receipt = R.publish_producer(base/'stage')
            self.assertEqual('published-postverified', receipt['status'])
            self.assertEqual(payloads, api.payloads)
            for public in (False, True):
                self.assertEqual(set(payloads), {name for phase, name in api.downloads if phase == public})
            self.assertEqual(2*len(payloads), len(api.downloads))
            self.assertIn('complete unchanged gzip', api.release['body'])
            self.assertIn('https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/musl-evidence-multipart-transport.md.', api.release['body'])
            whole = manifest['architectures']['x64']['evidence']['name']; self.assertNotIn(whole, api.payloads)
            self.assertFalse((base/'stage'/whole).exists())


class EvidenceProducerStageTests(unittest.TestCase):
    def test_actual_stage_retains_every_original_evidence_file_but_no_unpublished_whole(self):
        with tempfile.TemporaryDirectory() as temporary, bounds(part=2048, limit=4096, maximum=32768):
            base = Path(temporary); received = base/'received'; received.mkdir(); version = '6.0.136'; commit = 'a'*40
            run = dict(id=123, run_attempt=1, head_sha=commit, path=C.producer_workflow(version), head_branch='main',
                event='workflow_dispatch', repository=dict(full_name=C.REPOSITORY), head_repository=dict(full_name=C.REPOSITORY),
                status='completed', conclusion='success')
            receiving = dict(kind='received-native-musl-producers', libc='musl', sdkVersion=version, runId=123,
                runAttempt=1, projectCommit=commit, architectures={})
            expected = {}
            for arch, target in C.ARCHITECTURES.items():
                tree = received/(arch+'-received')/'delivery'; (tree/'sources').mkdir(parents=True); (tree/'reports/ci').mkdir(parents=True)
                sdk = tree/f'cbodotnet-sdk-{version}-linux-musl-{arch}-build.123.tar.gz'; sdk.write_bytes(b'sdk '+arch.encode())
                source = tree/'sources/original.tar.gz'; source.write_bytes(b'original source '+arch.encode())
                source_id = S.fingerprint(source); index = tree/'sources/source-index.jsonl'; index.write_bytes(b'{"original":true}\n')
                used = dict(archive=dict(path=source.name, bytes=source_id['size'], sha256=source_id['sha256'], sha512=source_id['sha512']),
                    index=dict(path=index.name), sdkVersion=version)
                (tree/'sources/source-manifest.json').write_bytes(encoded(used)); (tree/'reports/ci/used-source.json').write_bytes(encoded(used))
                identity = dict(sdkVersion=version, architecture=arch, projectCommit=commit, runId='123', runAttempt='1',
                    targetRid=target['rid'], libc='musl')
                (tree/'producer-validation.json').write_bytes(encoded(identity))
                (tree/'producer-sdk.json').write_bytes(encoded(dict(identity, sdk=dict(name=sdk.name, bytes=sdk.stat().st_size,
                    sha256=hashlib.sha256(sdk.read_bytes()).hexdigest()))))
                (tree/'imported-inputs').mkdir(); (tree/'imported-inputs/all-original.bin').write_bytes(random.Random(7).randbytes(9000))
                expected[arch] = {p.relative_to(tree).as_posix():p.read_bytes() for p in tree.rglob('*') if p.is_file() and p not in {sdk, source}}
                receiving['architectures'][arch] = dict(artifact=dict(id=456 if arch == 'x64' else 457,
                    name=C.producer_artifact_name(version, arch, 123, 1), expired=False, size_in_bytes=100, digest='sha256:'+'b'*64,
                    workflow_run=dict(id=123, head_sha=commit, head_branch='main', repository_id=10, head_repository_id=10)))
            (received/'received.json').write_bytes(encoded(receiving)); (received/'run.json').write_bytes(encoded(run))
            with mock.patch.object(R.subprocess, 'run') as validate, mock.patch.object(R, '_source_module') as packer:
                manifest = R.stage_producer(received, base/'stage')
                self.assertEqual(2, validate.call_count); self.assertEqual(2, packer.return_value.verify.call_count)
            _, physical = R.validate_source_stage(base/'stage')
            self.assertEqual(set(physical), {p.name for p in (base/'stage').iterdir()})
            for arch, entry in manifest['architectures'].items():
                self.assertIn('evidenceTransport', entry)
                self.assertFalse((base/'stage'/entry['evidence']['name']).exists())
                with E.materialize_directory(base/'stage', entry) as whole, tarfile.open(whole, 'r:gz') as archive:
                    actual = {member.name:archive.extractfile(member).read() for member in archive}
                self.assertEqual(expected[arch], actual)
            self.assertFalse(any(p.name.startswith(('musl-evidence-pack-', 'musl-evidence-private-')) for p in base.iterdir()))


if __name__ == '__main__': unittest.main()
