"""Small real byte/Git-object fixtures; no product assemblies or tools execute."""
import base64
import copy
import contextlib
import hashlib
import io
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import musl_legacy31_construction as C

assert Path(C.__file__).resolve().parent == SCRIPTS
BOUNDS = dict(archiveBytes=131072, members=100, memberBytes=16384, expandedBytes=131072)


def fp(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def commit(tree, parent=None):
    raw = ('tree ' + tree + '\n' + (('parent ' + parent + '\n') if parent else '')
           + 'author Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nfixture\n').encode()
    return oid('commit', raw), raw


def tar(path, rows):
    with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw, mode in rows:
            item = tarfile.TarInfo(name)
            item.mode = mode
            if isinstance(raw, tuple):
                item.type, item.linkname = raw
                archive.addfile(item)
            else:
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
    return fp(path.read_bytes())


class ArchiveAndGitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='core31-source-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_archive_real_bytes_modes_links_and_disguised_elf(self):
        path = self.root / 'source.tar.gz'
        identity = tar(path, [('tool', b'MZtiny', 0o755), ('data.dll', b'\x7fELFtiny', 0o644),
                              ('link', (tarfile.SYMTYPE, 'tool'), 0o777)])
        rows = C.archive_inventory(path, identity, BOUNDS)['members']
        self.assertEqual([(row['path'], row['type']) for row in rows], [('data.dll', 'file'), ('link', 'symlink'), ('tool', 'file')])
        self.assertEqual(rows[0]['format'], 'elf')
        self.assertEqual(rows[2]['mode'], 0o755)
        self.assertEqual(rows[2]['gitBlob'], oid('blob', b'MZtiny'))
        self.assertEqual(rows[1]['target'], 'tool')

    def test_archive_whole_and_member_limits(self):
        path = self.root / 'a.tar.gz'
        identity = tar(path, [('file', b'abcd', 0o644)])
        for mutation in ({**identity, 'sha512': '0' * 128}, {key: value for key, value in identity.items() if key != 'sha512'}):
            with self.subTest(identity=mutation), self.assertRaises(C.ValidationError):
                C.archive_inventory(path, mutation, BOUNDS)
        for field, value in [('members', 0), ('memberBytes', 3), ('expandedBytes', 100)]:
            with self.subTest(limit=field), self.assertRaises(C.ValidationError):
                C.archive_inventory(path, identity, {**BOUNDS, field: value})

    def test_tar_unsafe_duplicate_special_and_alias_members(self):
        cases = [[('../escape', b'x', 0o644)], [('a', b'x', 0o644), ('./a', b'x', 0o644)],
                 [('link', (tarfile.SYMTYPE, '../escape'), 0o777)], [('link', (tarfile.LNKTYPE, 'a'), 0o644)]]
        for index, rows in enumerate(cases):
            path = self.root / ('bad' + str(index) + '.tar.gz')
            identity = tar(path, rows)
            with self.subTest(index=index), self.assertRaises(C.ValidationError):
                C.archive_inventory(path, identity, BOUNDS)

    def test_gzip_inflation_limit_includes_padding_not_just_declared_files(self):
        import gzip
        path = self.root / 'padding.tar.gz'
        identity = tar(path, [('file', b'x', 0o644)])
        raw = gzip.decompress(path.read_bytes()) + b'\0' * 131072
        path.write_bytes(gzip.compress(raw))
        with self.assertRaises(C.ValidationError):
            C.archive_inventory(path, fp(path.read_bytes()), BOUNDS)

    def test_zip_and_nuget_real_unsigned_hash_is_not_signed_whole_hash(self):
        plain, signed = self.root / 'plain.nupkg', self.root / 'signed.nupkg'
        for path, signature in [(plain, False), (signed, True)]:
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(zipfile.ZipInfo('lib/a.dll', date_time=(2020, 1, 1, 0, 0, 0)), b'MZnot-an-executable-fixture')
                if signature:
                    archive.writestr(zipfile.ZipInfo('.signature.p7s', date_time=(2020, 1, 1, 0, 0, 0)), b'dummy-signature-bytes-not-a-trust-proof')
        unsigned = base64.b64encode(hashlib.sha512(plain.read_bytes()).digest()).decode()
        result = C.nuget_package(signed, fp(signed.read_bytes()), unsigned, BOUNDS)
        self.assertEqual(result['nugetContentHash'], unsigned)
        self.assertNotEqual(unsigned, base64.b64encode(hashlib.sha512(signed.read_bytes()).digest()).decode())
        with self.assertRaises(C.ValidationError):
            C.nuget_package(signed, fp(signed.read_bytes()), base64.b64encode(hashlib.sha512(signed.read_bytes()).digest()).decode(), BOUNDS)

    def test_zip_duplicate_traversal_and_oversize(self):
        for index, names in enumerate([['../a'], ['a', 'a']]):
            path = self.root / ('bad' + str(index) + '.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                for name in names:
                    archive.writestr(name, b'1234')
            with self.subTest(index=index), self.assertRaises(C.ValidationError):
                C.archive_inventory(path, fp(path.read_bytes()), BOUNDS, archive_type='zip')

    def test_tiny_nuget_under_valid_eight_gib_archive_ceiling_is_accepted(self):
        path = self.root / 'generous-ceiling.nupkg'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('lib/fixture.dll', b'MZtiny package accounting fixture')
        raw = path.read_bytes()
        self.assertLess(len(raw), 1024)
        content_hash = base64.b64encode(hashlib.sha512(raw).digest()).decode()
        result = C.nuget_package(path, fp(raw), content_hash, {**BOUNDS, 'archiveBytes': 8 * 1024 ** 3})
        self.assertEqual(result['archive'], fp(raw))
        self.assertEqual(result['nugetContentHash'], content_hash)

    def test_generous_ceiling_never_skips_nuget_whole_or_content_identity(self):
        path = self.root / 'generous-ceiling-bad.nupkg'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('lib/fixture.dll', b'MZtiny package accounting fixture')
        raw, expected = path.read_bytes(), fp(path.read_bytes())
        content_hash = base64.b64encode(hashlib.sha512(raw).digest()).decode()
        bounds = {**BOUNDS, 'archiveBytes': 8 * 1024 ** 3}
        for identity, content in [({**expected, 'sha512': '0' * 128}, content_hash),
                                  (expected, base64.b64encode(b'wrong content hash').decode())]:
            with self.subTest(identity=identity, content=content), self.assertRaises(C.ValidationError):
                C.nuget_package(path, identity, content, bounds)

    def history(self):
        tree = oid('tree', b'')
        base, base_raw = commit(tree)
        head, head_raw = commit(tree, base)
        target = b'<Project><Target Name="FixtureFirstParentDistance" /></Project>\n'
        contract = dict(targetIdentity=fp(target), algorithm='first-parent-distance', baseCommit=base, property='GitCommitCount')
        witness = dict(contract, commit=head, tree=tree, value=1)
        return tree, base, head, {base: base_raw, head: head_raw}, target, contract, witness

    def test_real_git_history_and_original_count_are_different_metrics(self):
        tree, base, head, objects, target, contract, witness = self.history()
        result = C.verify_version_count(head, tree, objects, target, contract, witness)
        self.assertEqual(result['reachableCommitCount'], 2)
        self.assertEqual(result['gitCommitCount'], 1)
        self.assertFalse(result['normalAdmissionAllowed'])

    def test_genuinely_proven_zero_at_version_base_is_valid(self):
        tree, base, head, objects, target, contract, witness = self.history()
        witness.update(commit=base, value=0)
        result = C.verify_version_count(base, tree, {base: objects[base]}, target, contract, witness)
        self.assertEqual(result['gitCommitCount'], 0)
        self.assertEqual(result['reachableCommitCount'], 1)

    def test_synthetic_zero_missing_history_wrong_target_or_unknown_algorithm(self):
        tree, base, head, objects, target, contract, witness = self.history()
        calls = [(objects, target, contract, {**witness, 'value': 0}),
                 ({head: objects[head]}, target, contract, witness),
                 (objects, target + b'changed', contract, witness),
                 (objects, target, {**contract, 'algorithm': 'guessed-height'}, witness),
                 (objects, target, None, witness)]
        for index, (graph, body, approved, declared) in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(C.ValidationError):
                C.verify_version_count(head, tree, graph, body, approved, declared)

    def test_git_objects_are_rehashed_and_extraneous_objects_rejected(self):
        tree, base, head, objects, target, contract, witness = self.history()
        for graph in [{**objects, base: objects[base] + b'x'}, {**objects, '0' * 40: b'extra'}]:
            with self.assertRaises(C.ValidationError):
                C.verify_version_count(head, tree, graph, target, contract, witness)

    def source_fixture(self):
        path = self.root / 'source.tar.gz'
        bodies = {'LICENSE': b'fixture MIT license\n', 'build.sh': b'#!/bin/sh\nexit 0\n'}
        tree_raw = b''.join(mode + b' ' + name.encode() + b'\0' + bytes.fromhex(oid('blob', raw))
                            for mode, name, raw in [(b'100644', 'LICENSE', bodies['LICENSE']), (b'100755', 'build.sh', bodies['build.sh'])])
        tree = oid('tree', tree_raw)
        revision, revision_raw = commit(tree)
        archive_id = tar(path, [('repo/' + name, raw, 0o755 if name == 'build.sh' else 0o644) for name, raw in bodies.items()])
        licenses = {'repo/LICENSE': fp(bodies['LICENSE'])}
        policy = copy.deepcopy(C.load_policy())
        spec = policy['sourceRepositories']['sdk']
        spec.update(commit=revision, tree=tree, knownLicensePaths=['repo/LICENSE'], licenseInventoryPin=fp(C.encoded(licenses)))
        manifest = dict(schemaVersion=1, kind='core31-preferred-source-manifest', repositoryId='sdk', repository=spec['repository'],
                        commit=revision, tree=tree, archive=archive_id, archivePrefix='repo', licenses=licenses,
                        gitEntries={'repo/' + name: dict(mode=0o755 if name == 'build.sh' else 0o644, gitBlob=oid('blob', raw), **fp(raw)) for name, raw in bodies.items()},
                        submoduleProofs={}, generatedInputProofs={}, sharedInputProofs={})
        raw = C.encoded(manifest)
        spec['preferredSourceManifestPin'] = fp(raw)
        return policy, path, raw, {revision: revision_raw}, {tree: tree_raw}

    def test_preferred_source_actual_blob_tree_modes_license_and_history(self):
        policy, path, manifest, commits, trees = self.source_fixture()
        result = C.verify_preferred_source(policy, 'sdk', path, manifest, commits, trees, BOUNDS)
        self.assertEqual(result['sourceFileCount'], 2)
        self.assertEqual(result['treeWitness']['sourceEntries'], 2)
        self.assertFalse(result['sourceAdmissionAllowed'])
        self.assertTrue(result['dependentSubmoduleGeneratedAndSharedProofsStillRequireIndependentValidation'])

    def test_preferred_source_missing_license_pin_and_modified_tree_fail(self):
        for mutation in ('license', 'tree', 'source_manifest'):
            policy, path, manifest, commits, trees = self.source_fixture()
            if mutation == 'license':
                policy['sourceRepositories']['sdk']['licenseInventoryPin'] = None
            elif mutation == 'tree':
                trees = {key: value + b'x' for key, value in trees.items()}
            else:
                manifest += b' '
            with self.subTest(mutation=mutation), self.assertRaises(C.ValidationError):
                C.verify_preferred_source(policy, 'sdk', path, manifest, commits, trees, BOUNDS)

    def test_gitlink_cannot_be_omitted_or_replaced_by_parent_blob(self):
        child = '1' * 40
        raw = b'160000 child\0' + bytes.fromhex(child)
        tree = oid('tree', raw)
        proof = {'child': dict(commit=child, manifestIdentity=fp(b'actual child source manifest'))}
        self.assertEqual(C.verify_git_tree(tree, {tree: raw}, {}, proof)['submoduleGitlinks'], 1)
        for submodules in ({}, {'child': dict(commit='2' * 40, manifestIdentity=fp(b'wrong'))}):
            with self.assertRaises(C.ValidationError):
                C.verify_git_tree(tree, {tree: raw}, {}, submodules)

    def test_duplicate_json_keys_and_identity_aliases_rejected(self):
        with self.assertRaises(C.ValidationError):
            C.document(b'{"same":1,"same":2}')
        for name in ('../x', 'a//b', 'a/./b', '/x', 'a\\b', 'a:b'):
            with self.subTest(name=name), self.assertRaises(C.ValidationError):
                C.relative(name)

    def test_actual_directory_layout_is_rechecked_against_manifest_bytes(self):
        root = self.root / 'owned-layout'
        root.mkdir()
        raw = b'original layout bytes\n'
        path = root / 'LICENSE'
        path.write_bytes(raw)
        row = dict(path='LICENSE', type='file', mode=stat.S_IMODE(path.stat().st_mode),
                   **fp(raw), gitBlob=oid('blob', raw), format='data')
        manifest = dict(kind='core31-layout-inventory', rootDirectoryMode=stat.S_IMODE(root.stat().st_mode),
                        members=[row], expandedBytes=len(raw))
        identity = fp(C.encoded(manifest))
        self.assertEqual(C.directory_inventory(root, identity, BOUNDS), manifest)
        path.write_bytes(b'changed after stage output')
        with self.assertRaises(C.ValidationError):
            C.directory_inventory(root, identity, BOUNDS)

    def test_directory_entry_limit_stops_actual_scandir_before_sorting(self):
        root = self.root / 'many-entries'
        root.mkdir()
        for index in range(8):
            (root / str(index)).write_bytes(b'x')
        actual_scandir, yielded = C.os.scandir, []
        @contextlib.contextmanager
        def counted_scandir(path):
            with actual_scandir(path) as stream:
                def entries():
                    for entry in stream:
                        yielded.append(entry.name)
                        yield entry
                yield entries()
        with mock.patch.object(C.os, 'scandir', counted_scandir):
            with self.assertRaisesRegex(C.ValidationError, 'observed entry count'):
                C.directory_inventory(root, fp(b'unreached manifest'), {**BOUNDS, 'members': 2})
        self.assertEqual(len(yielded), 3, 'must stop at max+1, before preallocating all eight entries')

    def growing_open(self, target, grown, reads, ready=lambda: True):
        actual_open = Path.open
        def open_file(path, mode='r', *args, **kwargs):
            if Path(path) == target and mode == 'rb' and ready():
                with actual_open(target, 'wb') as stream:
                    stream.write(grown)
                stream = actual_open(path, mode, *args, **kwargs)
                class Reader:
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        stream.close()
                    def read(self, size=-1):
                        reads.append(size)
                        return stream.read(size)
                return Reader()
            return actual_open(path, mode, *args, **kwargs)
        return open_file

    def test_policy_growth_after_size_check_never_triggers_unbounded_read(self):
        path = self.root / 'growing-policy.json'
        original = (SCRIPTS / 'musl-legacy31-construction-policy.json').read_bytes()
        path.write_bytes(original)
        reads = []
        with mock.patch.object(Path, 'open', self.growing_open(path, b'x' * (65536 + 1), reads)):
            with self.assertRaisesRegex(C.ValidationError, 'raw input grew'):
                C.load_policy(path)
        self.assertEqual(reads, [len(original) + 1])
        self.assertLessEqual(reads[0], 65536 + 1)

    def test_nuget_growth_after_actual_archive_authentication_has_bounded_reread(self):
        path = self.root / 'growing.nupkg'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('lib/fixture.dll', b'MZfixture bytes')
        original = path.read_bytes()
        content_hash = base64.b64encode(hashlib.sha512(original).digest()).decode()
        actual_inventory, reads, state = C.archive_inventory, [], {'authenticated': False}
        def inventory(*args, **kwargs):
            result = actual_inventory(*args, **kwargs)
            state['authenticated'] = True
            return result
        opener = self.growing_open(path, b'x' * (BOUNDS['archiveBytes'] + 1), reads, lambda: state['authenticated'])
        with mock.patch.object(C, 'archive_inventory', side_effect=inventory), mock.patch.object(Path, 'open', opener):
            with self.assertRaisesRegex(C.ValidationError, 'raw input grew'):
                C.nuget_package(path, fp(original), content_hash, BOUNDS)
        self.assertTrue(state['authenticated'])
        self.assertEqual(reads, [len(original) + 1])
        self.assertLessEqual(reads[0], BOUNDS['archiveBytes'] + 1)

    def test_cold_import_has_no_writes_process_network_or_policy_read(self):
        script = r'''
import builtins, pathlib, socket, subprocess, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
def forbidden(*args, **kwargs): raise AssertionError('cold import side effect')
builtins.open = forbidden
pathlib.Path.open = forbidden
pathlib.Path.read_bytes = forbidden
pathlib.Path.write_bytes = forbidden
subprocess.Popen = forbidden
socket.socket = forbidden
import musl_legacy31_construction, musl_legacy31_parents, musl_legacy31_admission
print('cold import passed')
'''
        process = subprocess.run([sys.executable, '-B', '-c', script, str(SCRIPTS)], capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), 'cold import passed')


if __name__ == '__main__':
    unittest.main()
