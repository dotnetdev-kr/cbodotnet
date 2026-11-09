"""Multipart bytes are authenticated before the unchanged source verifier."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import random
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import musl_source_transport as T
import musl_contract as C
import musl_release as R
import musl_distribution as D
import musl_packages as APK
from downstream_release import descriptor, encoded
from musl_contract_test import fixture


@contextlib.contextmanager
def bounds(part=64, limit=128, maximum=1024):
    with mock.patch.multiple(T, PART_BYTES=part, MAX_RELEASE_BYTES=limit, MAX_ARCHIVE_BYTES=maximum):
        yield


def expected(path):
    row = T.fingerprint(path)
    return dict(bytes=row['size'], sha256=row['sha256'], sha512=row['sha512'])


def pure_packet(base, size=201):
    original = base / 'original.tar.gz'; original.write_bytes(bytes(range(size)))
    manifest = base / 'source-manifest.json'; manifest.write_bytes(b'{}\n')
    index = base / 'source-index.jsonl'; index.write_bytes(b'{}\n')
    stage = base / 'stage'; stage.mkdir()
    source, transport = T.stage(original, stage, C.producer_asset_name('source', '6.0.136', 'x64'), manifest, index, expected(original))
    return original, stage, dict(source=source, **(dict(sourceTransport=transport) if transport else {}))


def reseal(entry):
    transport = entry['sourceTransport']; raw = encoded(T.document(transport))
    transport['descriptor'] = dict(name=entry['source']['name']+'.transport.json', size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


class MultipartBoundaryTests(unittest.TestCase):
    def test_exact_reassembly_and_legacy_copy_preserve_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            original, stage, entry = pure_packet(Path(directory))
            self.assertEqual([64, 64, 64, 9], [row['size'] for row in entry['sourceTransport']['parts']])
            self.assertFalse((stage / entry['source']['name']).exists())
            self.assertEqual(entry['source'], T.verify_directory(stage, entry))
            restored = Path(directory) / 'restored.tar.gz'
            T.authenticate(entry, lambda row: (stage / row['name']).open('rb'), restored)
            self.assertEqual(original.read_bytes(), restored.read_bytes())
            self.assertEqual(expected(original), expected(restored))
        with tempfile.TemporaryDirectory() as directory, bounds():
            original, stage, entry = pure_packet(Path(directory), size=100)
            self.assertNotIn('sourceTransport', entry)
            self.assertEqual({'name', 'size', 'sha256'}, set(entry['source']))
            self.assertEqual([entry['source']], T.source_assets(entry))
            self.assertEqual(original.read_bytes(), (stage / entry['source']['name']).read_bytes())

    def test_reordered_missing_duplicate_or_oversized_declarations_reject(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            _, _, entry = pure_packet(Path(directory))
            for mutation in (lambda rows: rows.reverse(), lambda rows: rows.pop(),
                    lambda rows: rows.append(copy.deepcopy(rows[0])), lambda rows: rows[0].update(size=65)):
                changed = copy.deepcopy(entry); mutation(changed['sourceTransport']['parts']); reseal(changed)
                with self.assertRaises(ValueError): T.validate(changed)

    def test_missing_substituted_truncated_and_oversized_physical_parts_reject(self):
        for attack in ('missing', 'substituted', 'truncated', 'oversized'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory, bounds():
                _, stage, entry = pure_packet(Path(directory))
                path = stage / entry['sourceTransport']['parts'][0]['name']; raw = path.read_bytes()
                if attack == 'missing': path.unlink()
                else: path.write_bytes(b'X' * len(raw) if attack == 'substituted' else raw[:-1] if attack == 'truncated' else raw+b'!')
                with self.assertRaises(ValueError): T.verify_directory(stage, entry)

    def test_whole_sha256_and_sha512_reject_even_with_valid_part_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            _, stage, entry = pure_packet(Path(directory))
            for algorithm in ('sha256', 'sha512'):
                changed = copy.deepcopy(entry)
                changed['source'][algorithm] = '0' * len(changed['source'][algorithm])
                changed['sourceTransport']['archive'][algorithm] = changed['source'][algorithm]
                reseal(changed)
                output = Path(directory) / (algorithm+'.tar.gz')
                with self.assertRaisesRegex(ValueError, 'Reconstructed'):
                    T.authenticate(changed, lambda row: (stage / row['name']).open('rb'), output)
                self.assertFalse(output.exists())

    def test_sidecar_and_manifest_index_bindings_are_closed(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            _, stage, entry = pure_packet(Path(directory))
            raw = (stage / entry['sourceTransport']['descriptor']['name']).read_bytes()
            with self.assertRaises(ValueError): T.validate_sidecar(entry, raw+b'\n')
            for key in ('sourceManifest', 'sourceIndex'):
                changed = copy.deepcopy(entry); changed['sourceTransport'][key]['sha512'] = '0'*128
                with self.assertRaises(ValueError): T.validate(changed)
            for field in ('unexpected', 'parts'):
                changed = copy.deepcopy(entry)
                if field == 'unexpected': changed['sourceTransport'][field] = True
                else: changed['sourceTransport'][field][0]['name'] = '../part'
                with self.assertRaises(ValueError): T.validate(changed)

    def test_stream_overrun_rejects_and_removes_only_partial_reconstruction(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            original, stage, entry = pure_packet(Path(directory)); output = Path(directory) / 'restored.tar.gz'
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                T.authenticate(entry, lambda row: io.BytesIO((stage / row['name']).read_bytes()+b'!'), output)
            self.assertFalse(output.exists()); self.assertEqual(201, original.stat().st_size)

    def test_part_sha512_is_required_even_when_sha256_matches(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            _, stage, entry = pure_packet(Path(directory))
            changed = copy.deepcopy(entry); changed['sourceTransport']['parts'][0]['sha512'] = '0'*128; reseal(changed)
            with self.assertRaisesRegex(ValueError, 'multipart member'):
                T.authenticate(changed, lambda row: (stage / row['name']).open('rb'))

    def test_truncation_at_source_open_rejects_before_a_second_empty_part(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            base = Path(directory); original = base / 'original.tar.gz'; original.write_bytes(bytes(range(201)))
            manifest = base / 'source-manifest.json'; manifest.write_bytes(b'{}\n')
            index = base / 'source-index.jsonl'; index.write_bytes(b'{}\n')
            stage = base / 'stage'; stage.mkdir(); baseline = expected(original)
            normal_open = Path.open; mutated = False; part_opens = []
            def opened(path, mode='r', *args, **kwargs):
                nonlocal mutated
                if path == original and mode == 'rb' and not mutated:
                    mutated = True
                    with normal_open(path, 'wb') as stream: stream.write(b'')
                if path.parent == stage and '.part-' in path.name and mode == 'xb':
                    part_opens.append(path.name)
                    if len(part_opens) > 1:
                        raise AssertionError('Early EOF attempted a second empty part')
                return normal_open(path, mode, *args, **kwargs)
            with mock.patch.object(Path, 'open', new=opened):
                with self.assertRaisesRegex(ValueError, 'truncated during multipart staging'):
                    T.stage(original, stage, 'source.tar.gz', manifest, index, baseline)
            self.assertTrue(mutated); self.assertEqual(1, len(part_opens))
            failed = list(stage.iterdir())
            self.assertLessEqual(len(failed), 1)
            self.assertEqual([0], [path.stat().st_size for path in failed])

    def test_growth_at_source_open_rejects_the_one_byte_tail_after_bounded_parts(self):
        with tempfile.TemporaryDirectory() as directory, bounds():
            base = Path(directory); original = base / 'original.tar.gz'; raw = bytes(range(201)); original.write_bytes(raw)
            manifest = base / 'source-manifest.json'; manifest.write_bytes(b'{}\n')
            index = base / 'source-index.jsonl'; index.write_bytes(b'{}\n')
            stage = base / 'stage'; stage.mkdir(); baseline = expected(original)
            normal_open = Path.open; mutated = False
            def opened(path, mode='r', *args, **kwargs):
                nonlocal mutated
                if path == original and mode == 'rb' and not mutated:
                    mutated = True
                    with normal_open(path, 'wb') as stream: stream.write(raw+b'!')
                return normal_open(path, mode, *args, **kwargs)
            with mock.patch.object(Path, 'open', new=opened):
                with self.assertRaisesRegex(ValueError, 'grew during multipart staging'):
                    T.stage(original, stage, 'source.tar.gz', manifest, index, baseline)
            self.assertTrue(mutated)
            self.assertEqual([64, 64, 64, 9], [path.stat().st_size for path in sorted(stage.iterdir())])
            self.assertEqual(202, original.stat().st_size)


def public_packet(base, multipart):
    project = base / 'project'; project.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(project), *args], stderr=subprocess.PIPE)
    git('init', '--quiet')
    (project / '.gitattributes').write_bytes(b'* text eol=lf\n')
    (project / 'README').write_bytes(b'Original orchestration\n')
    git('add', '.')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Original')
    commit = git('rev-parse', 'HEAD').decode().strip()
    actual = base / 'actual'; (actual / 'reports/ci').mkdir(parents=True)
    data = base / 'data'; data.mkdir(); (data / 'original.bin').write_bytes(random.Random(7).randbytes(6000))
    roots = base / 'roots.json'; roots.write_bytes(encoded(dict(schemaVersion=1, roots=[dict(name='data', kind='tree', path=str(data))])))
    packer = R._source_module()
    packer.pack(SimpleNamespace(project_root=project, project_commit=commit, output_dir=actual / 'sources', roots_json=roots,
        sdk_version='6.0.136', target_rid='linux-musl-x64', run_id='123', run_attempt='1'))
    used = json.loads((actual / 'sources/source-manifest.json').read_bytes())
    original = actual / 'sources' / used['archive']['path']; stage = base / 'stage'; stage.mkdir()
    release, manifest, _, _, catalog, payloads = fixture('6.0.136')
    entry = manifest['architectures']['x64']; del payloads[entry['source']['name']]
    source, transport = T.stage(original, stage, entry['source']['name'], actual / 'sources/source-manifest.json',
        actual / 'sources/source-index.jsonl', used['archive'])
    assert (transport is not None) == multipart
    entry['source'] = source
    if transport is not None: entry['sourceTransport'] = transport
    for path in stage.iterdir(): payloads[path.name] = path.read_bytes()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name in ('sources/source-manifest.json', 'sources/source-index.jsonl', 'reports/ci/used-source.json'):
            raw = (actual / name).read_bytes(); info = tarfile.TarInfo(name); info.size = len(raw); archive.addfile(info, io.BytesIO(raw))
    raw = buffer.getvalue(); payloads[entry['evidence']['name']] = raw
    entry['evidence'] = dict(name=entry['evidence']['name'], size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    for arch, row in manifest['architectures'].items():
        row['provenance']['projectCommit'] = commit
        catalog['builds'][0]['architectures'][arch] = copy.deepcopy(row['provenance'])
    sums = R.producer_checksum_bytes(manifest)
    manifest['checksums'] = dict(name='SHA256SUMS', size=len(sums), sha256=hashlib.sha256(sums).hexdigest())
    raw = encoded(manifest); payloads.update({'release-manifest.json': raw, 'SHA256SUMS': sums})
    catalog['builds'][0]['sourceManifestSha256'] = hashlib.sha256(raw).hexdigest()
    release['assets'] = [dict(name=name, size=len(body), state='uploaded', digest='sha256:'+hashlib.sha256(body).hexdigest(),
        browser_download_url=f'https://github.com/{C.REPOSITORY}/releases/download/{manifest["tag"]}/{name}') for name, body in payloads.items()]
    return release, manifest, catalog, payloads, original


class PublicSourceRetrievalTests(unittest.TestCase):
    def received(self, base, packet):
        release, _, catalog, payloads, _ = packet
        with mock.patch.object(C, 'load_qualification_catalog', return_value=catalog), \
                mock.patch.object(D, 'AnonymousGitHubAPI', return_value=SimpleNamespace(api=lambda endpoint: release)), \
                mock.patch.object(D, 'get_bytes', side_effect=lambda url, limit: payloads[url.rsplit('/', 1)[-1]]), \
                mock.patch.object(D.urllib.request, 'urlopen', side_effect=lambda request, timeout: io.BytesIO(payloads[getattr(request, 'full_url', request).split('?', 1)[0].rsplit('/', 1)[-1]])):
            return D.receive_used_source('x64', base / 'received', sdk_version='6.0.136')

    def test_multipart_public_retrieval_runs_real_existing_verifier_without_source_extraction(self):
        with tempfile.TemporaryDirectory() as directory, bounds(part=2048, limit=4096, maximum=16384):
            base = Path(directory); packet = public_packet(base, True)
            release, manifest, _, payloads, original = packet
            C.validate_producer_release(release, payloads['release-manifest.json'], payloads['SHA256SUMS'])
            self.assertNotIn(manifest['architectures']['x64']['source']['name'], payloads)
            report = self.received(base, packet)
            self.assertTrue(report['multipart']); self.assertFalse(report['sourceTarExtracted'])
            self.assertEqual(original.read_bytes(), (base / 'received/sources' / original.name).read_bytes())
            self.assertEqual(3, len(list((base / 'received/sources').iterdir())))
            self.assertFalse((base / 'received/data/original.bin').exists())
            for name, raw in payloads.items(): (base / 'stage' / name).write_bytes(raw)
            R.validate_source_stage(base / 'stage')
            (base / 'stage/unexpected.part-0009').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'closed asset set'): R.validate_source_stage(base / 'stage')

    def test_legacy_v1_public_source_retrieval_and_eight_assets_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); packet = public_packet(base, False)
            self.assertEqual(8, len(packet[3]))
            self.assertNotIn('sourceTransport', packet[1]['architectures']['x64'])
            self.assertFalse(self.received(base, packet)['multipart'])

    def test_substituted_public_part_never_reaches_source_validator(self):
        with tempfile.TemporaryDirectory() as directory, bounds(part=2048, limit=4096, maximum=16384):
            base = Path(directory); packet = public_packet(base, True)
            entry = packet[1]['architectures']['x64']; name = entry['sourceTransport']['parts'][0]['name']
            packet[3][name] = b'X' * len(packet[3][name])
            with mock.patch.object(D, '_source_module', side_effect=AssertionError('Untrusted reconstructed gzip reached source verifier')):
                with self.assertRaisesRegex(ValueError, 'multipart member'): self.received(base, packet)
            self.assertFalse((base / 'received/sources' / packet[4].name).exists())

    def test_oci_source_link_names_actual_transport_asset(self):
        with tempfile.TemporaryDirectory() as directory, bounds(part=2048, limit=4096, maximum=16384):
            base = Path(directory); release, manifest, catalog, payloads, _ = public_packet(base, True)
            sdk = manifest['architectures']['x64']['sdk']; sdk_path = base / sdk['name']; sdk_path.write_bytes(payloads[sdk['name']])
            plan = C.verified_plan(release, payloads['release-manifest.json'], payloads['SHA256SUMS'], sdk_path,
                'oci', 'alpine-3.24', 'x64', catalog=catalog)
            output = base / 'oci'; output.mkdir(); rootfs = output / 'rootfs'; rootfs.mkdir()
            with mock.patch.object(APK, 'stage_payload', return_value=(output, rootfs, {}, {})):
                result = APK.build_oci_context(plan, sdk_path, output, APK.BASE_IMAGES['x64'])
            linked = result['labels']['kr.dotnetdev.cbodotnet.source.url']
            self.assertTrue(linked.endswith(plan['sourceTransport']['descriptor']['name']))
            self.assertFalse(linked.endswith(plan['source']['name']))
            self.assertEqual(plan['source']['sha512'], result['labels']['kr.dotnetdev.cbodotnet.source.archive.sha512'])

    def test_rehashed_transport_cannot_substitute_original_evidence_controls(self):
        with tempfile.TemporaryDirectory() as directory, bounds(part=2048, limit=4096, maximum=16384):
            base = Path(directory); _, manifest, _, payloads, _ = public_packet(base, True)
            entry = manifest['architectures']['x64']
            evidence = base / entry['evidence']['name']; evidence.write_bytes(payloads[evidence.name])
            for key in ('sourceManifest', 'sourceIndex'):
                changed = copy.deepcopy(entry); changed['sourceTransport'][key]['sha512'] = '0'*128; reseal(changed)
                with self.assertRaisesRegex(ValueError, 'control fingerprint'):
                    T.source_controls(evidence, entry=changed)


if __name__ == '__main__': unittest.main()
