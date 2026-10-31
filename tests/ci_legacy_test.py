"""Bounded legacy CI safety/origin fixtures; no product build or container run."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


origin = module('ci-legacy-origin')
gate = module('ci-legacy-evidence')
driver = module('ci-legacy-direct')
retry = module('prepare-core30-retry')
bootstrap = module('prepare-core30-bootstrap')


class LegacyFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-legacy-fixture-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, entries):
        path = self.root / 'sample.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, content in entries:
                item = tarfile.TarInfo(name); item.mode = 0o755
                if kind == 'file':
                    item.size = len(content); archive.addfile(item, io.BytesIO(content))
                elif kind == 'directory':
                    item.type = tarfile.DIRTYPE; archive.addfile(item)
                elif kind == 'link':
                    item.type = tarfile.SYMTYPE; item.linkname = content; archive.addfile(item)
                else:
                    item.type = tarfile.FIFOTYPE; archive.addfile(item)
        return path

    def test_safe_archive_and_bounded_directory_normalization(self):
        path = self.archive([('./sdk/', 'directory', b''), ('./sdk/file', 'file', b'actual'), ('sdk/link', 'link', 'file')])
        result = origin.tar_tree(path)
        self.assertEqual(result['sdk/file']['sha256'], hashlib.sha256(b'actual').hexdigest())
        self.assertEqual(result['sdk/link']['target'], 'file')

    def test_archive_rejects_escaping_member(self):
        for name in ('../escape', '/absolute', 'sdk/../../escape', 'bad\\name'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    origin.tar_tree(self.archive([(name, 'file', b'x')]))

    def test_archive_rejects_duplicate_and_special(self):
        for entries in ([('x', 'file', b'a'), ('./x', 'file', b'b')], [('pipe', 'special', b'')]):
            with self.assertRaises(ValueError):
                origin.tar_tree(self.archive(entries))

    def test_archive_rejects_escaping_link(self):
        with self.assertRaises(ValueError):
            origin.tar_tree(self.archive([('folder/link', 'link', '../../outside')]))

    def test_framework_only_normal_write_bit_mask_is_allowed(self):
        original = {'assembly': {'type': 'file', 'mode': 0o664, 'bytes': 1, 'sha256': 'a'}}
        masked = copy.deepcopy(original); masked['assembly']['mode'] = 0o644
        self.assertEqual(len(origin.compare_framework(original, masked)), 1)
        for key, value in (('mode', 0o755), ('sha256', 'b'), ('bytes', 2)):
            changed = copy.deepcopy(masked); changed['assembly'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                origin.compare_framework(original, changed)

    def tasks(self):
        rows = []
        for index, name in enumerate(origin.names('5.0.17')):
            rows.append({'context': str(index), 'succeeded': True, 'events': [
                {'kind': 'task-started'},
                {'kind': 'local-copy-attempt', 'sourceUri': 'file://' + str(self.root / 'source/feed' / name),
                 'destination': str(self.root / 'source/consumer' / name)},
                {'kind': 'task-finished', 'succeeded': True}]})
        return rows

    def copy_proof(self, rows):
        reports = self.root / 'reports'; reports.mkdir(exist_ok=True)
        (reports / 'replay-0-download-tasks.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return origin.completed_copies(reports, self.root / 'source', '5.0.17')

    def test_completed_sole_local_copies(self):
        self.assertEqual(len(self.copy_proof(self.tasks())), 2)

    def test_network_attempt_cannot_be_called_local(self):
        rows = self.tasks(); rows[0]['events'][1]['kind'] = 'network-download-attempt'
        with self.assertRaises(ValueError):
            self.copy_proof(rows)

    def test_candidate_properties_are_not_execution(self):
        rows = self.tasks(); rows[0]['events'][1]['kind'] = 'task-parameter'
        with self.assertRaises(ValueError):
            self.copy_proof(rows)

    def test_unsuccessful_or_incomplete_task_rejected(self):
        for kind in ('failed', 'missing-finish', 'duplicate'):
            rows = self.tasks()
            if kind == 'failed':
                rows[0]['succeeded'] = False
            elif kind == 'missing-finish':
                rows[0]['events'].pop()
            else:
                rows.append(copy.deepcopy(rows[0]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.copy_proof(rows)

    def test_source_outside_selected_workspace_rejected(self):
        rows = self.tasks(); rows[0]['events'][1]['sourceUri'] = 'file:///other/feed/archive.tar.gz'
        with self.assertRaises(ValueError):
            self.copy_proof(rows)

    def test_hash_binding_rejects_changed_bytes(self):
        path = self.root / 'evidence'; path.write_bytes(b'first'); row = gate.record(self.root, path)
        self.assertEqual(gate.checked(self.root, row), path)
        path.write_bytes(b'other')
        with self.assertRaises(ValueError):
            gate.checked(self.root, row)

    def test_portable_paths_and_links_fail_closed(self):
        path = self.root / 'actual'; path.write_bytes(b'x'); (self.root / 'link').symlink_to(path)
        for name in ('../actual', '/actual', 'link', 'a\\b', './actual'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.member(self.root, name)

    def test_snapshot_tree_matches_git(self):
        repo = self.root / 'git'; repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'a').write_bytes(b'root\n'); (repo / 'sub').mkdir(); (repo / 'sub/b').write_bytes(b'nested\n')
        subprocess.run(['git', '-C', str(repo), 'add', 'a', 'sub/b'], check=True)
        expected = subprocess.check_output(['git', '-C', str(repo), 'write-tree']).decode().strip()
        rows = []
        for name in ('a', 'sub/b'):
            data = (repo / name).read_bytes(); target = self.root / 'reports/ci-inputs/project' / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            rows.append(dict(gate.record(self.root, target), gitMode='100644', gitBlob=gate.git_hash('blob', data)))
        self.assertEqual(gate.snapshot_tree(self.root, rows), expected)
        rows[0]['gitBlob'] = '0' * 40
        with self.assertRaises(ValueError):
            gate.snapshot_tree(self.root, rows)

    def test_actual_ephemeral_destination_capture(self):
        source = self.root / 'source'; downloads = source / 'artifacts/src/installer.fixture/artifacts/obj/redist/Release/downloads'
        downloads.mkdir(parents=True); (self.root / 'inputs').mkdir()
        output = self.root / 'output'; (output / 'reports/build').mkdir(parents=True)
        command = [sys.executable, str(ROOT / 'scripts/ci-legacy-origin.py'), 'observe', '--family', 'net5',
                   '--source-dir', str(source), '--workspace', str(self.root), '--output-dir', str(output)]
        process = subprocess.Popen(command)
        try:
            time.sleep(0.15)
            path = downloads / origin.names('5.0.17')[0]
            with path.open('xb') as stream:
                stream.write(b'first'); stream.flush(); time.sleep(0.1); stream.write(b'last')
            path.unlink()
        finally:
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=10), 0)
        rows = [json.loads(line) for line in (output / 'reports/build/installer-observations.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(Path(rows[0]['retained']).read_bytes(), b'firstlast')

    def test_all_legacy_clis_parse_without_product_access(self):
        for name in ('ci-net5.sh', 'ci-core31.sh', 'ci-core30.sh'):
            subprocess.run(['bash', str(ROOT / 'scripts' / name), '--help'], check=True, stdout=subprocess.DEVNULL)

    def test_runner_owns_sysroot_report_directory_before_privileged_producer(self):
        runner = driver.CI.__new__(driver.CI); runner.reports = self.root
        report = runner.sysroot_report_directory()
        self.assertEqual(report.stat().st_uid, os.getuid())
        self.assertEqual(report.stat().st_gid, os.getgid())
        (report / 'current-validation.json').write_text('{}')
        with self.assertRaises(FileExistsError):
            runner.sysroot_report_directory()

    def test_sysroot_report_directory_refuses_link(self):
        destination = self.root / 'elsewhere'; destination.mkdir()
        (self.root / 'sysroot').symlink_to(destination, target_is_directory=True)
        runner = driver.CI.__new__(driver.CI); runner.reports = self.root
        with self.assertRaises(ValueError):
            runner.sysroot_report_directory()

    def test_capture_helper_preserves_real_verifier_output_and_keyring_bytes(self):
        scripts = self.root / 'scripts'; scripts.mkdir()
        helper = scripts / 'ci-legacy-capture-sysroot.py'
        shutil.copyfile(ROOT / 'scripts/ci-legacy-capture-sysroot.py', helper)
        # Model only the external whole-tree verifier; run the real capture
        # helper, subprocess decoding, keyring hashing/copying and file writes.
        (scripts / 'verify-sysroot-core30.py').write_text(
            "import json\nprint(json.dumps({'status':'passed','files':17026,'symlinks':5225}))\n")
        reports = self.root / 'reports'; reports.mkdir()
        inputs = self.root / 'inputs'; inputs.mkdir()
        keys = []
        for index in range(3):
            path = self.root / ('keyring-' + str(index)); path.write_bytes(('authenticated-key-' + str(index)).encode())
            keys.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        (reports / 'sysroot-provenance.json').write_text(json.dumps({'keyrings': keys}))
        subprocess.run([sys.executable, str(helper), '--family', 'core30', '--inputs-dir', str(inputs), '--reports-dir', str(reports)], check=True)
        self.assertEqual(json.loads((reports / 'current-validation.json').read_text())['files'], 17026)
        result = json.loads((reports / 'producer-inputs.json').read_text())
        self.assertEqual(result['status'], 'passed')
        for index, row in enumerate(result['keyrings']):
            self.assertEqual(row['sha256'], keys[index]['sha256'])
            self.assertEqual((reports / ('signing-keyring-' + str(index) + '.gpg')).read_bytes(), Path(keys[index]['path']).read_bytes())

    def inspect_feed(self, path, allow=False):
        return retry.inspect_feed(path, allow, bootstrap.directory, bootstrap.ordinary_file, bootstrap.fingerprint)

    def test_explicit_cold_feed_opt_in_never_creates_synthetic_outputs(self):
        source = self.root / 'source'; source.mkdir()
        feed = source / 'bin/obj/arm64/Release/blob-feed/packages'
        with self.assertRaises(ValueError):
            self.inspect_feed(feed)
        entries, absent = self.inspect_feed(feed, True)
        self.assertEqual(entries, [])
        self.assertIs(absent, True)
        self.assertEqual(list(source.iterdir()), [])

    def test_existing_empty_feed_preserves_default_retry_semantics(self):
        feed = self.root / 'packages'; feed.mkdir()
        for allow in (False, True):
            self.assertEqual(self.inspect_feed(feed, allow), ([], False))

    def test_cold_opt_in_does_not_accept_linked_or_malformed_feeds(self):
        target = self.root / 'target'; target.mkdir()
        link = self.root / 'linked'; link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.inspect_feed(link / 'packages', True)
        (target / 'unexpected.txt').write_text('not a source-built package')
        with self.assertRaises(ValueError):
            self.inspect_feed(target, True)

    def test_cold_opt_in_retains_existing_package_producer_proof(self):
        feed = self.root / 'packages'; feed.mkdir()
        package = feed / 'Unproven.1.0.0.nupkg'
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('Unproven.nuspec', '<package><metadata><id>Unproven</id><version>1.0.0</version></metadata></package>')
        entries, absent = self.inspect_feed(feed, True)
        self.assertIs(absent, False)
        self.assertEqual(len(entries), 1)
        destination = self.root / 'quarantine'; destination.mkdir()
        with self.assertRaises(retry.UnprovenPackagesError):
            retry.package_plan(entries, {package.name: []}, destination)
        self.assertTrue(package.is_file())
        self.assertEqual(list(destination.iterdir()), [])

    def test_only_core30_ci_build_opts_into_cold_feed(self):
        for family in ('net5', 'core31', 'core30'):
            runner = driver.CI.__new__(driver.CI)
            runner.family = family; runner.source = self.root / 'source'; runner.inputs = self.root / 'inputs'
            runner.snapshot = self.root / 'frozen'; runner.profile = self.root / 'profile.json'; runner.reports = self.root / family
            runner.product = driver.CONFIG[family][4]; runner.cpus = '0,1'; runner.raw_sdk = lambda: self.root / 'sdk.tar.gz'
            for action in ('prepare', 'build', 'test'):
                command = runner.product_command(action, self.root / family / action / 'product')
                self.assertEqual('--allow-cold-feed' in command, family == 'core30' and action == 'build')

    def test_real_cold_helper_report_and_gate_require_absence_without_outputs(self):
        source = self.root / 'empty-source'; source.mkdir()
        inputs = self.root / 'inputs'; inputs.mkdir()
        reports = self.root / 'reports'; reports.mkdir()
        arguments = ['prepare-core30-retry.py', '--source-dir', str(source), '--inputs-dir', str(inputs),
                     '--reports-dir', str(reports), '--profile', str(self.root / 'profile.json'), '--allow-cold-feed']
        # Isolate only the external pinned-source verifier. All directory
        # inspection, branching, report generation and portable gate code runs.
        def external(path):
            if str(path).endswith('prepare-core30-bootstrap.py'):
                return vars(bootstrap)
            return {'verify': lambda *_: {'sourceCommit': retry.COMMIT}}
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(retry.runpy, 'run_path', side_effect=external):
            self.assertEqual(retry.main(), 0)
        result = json.loads((reports / 'core30-retry-inputs.json').read_text())
        gate.cold_feed_proof(result, retry.COMMIT)
        self.assertEqual(list(source.iterdir()), [])
        self.assertEqual(list(inputs.iterdir()), [])
        for key, value in (('feedInitiallyAbsent', False), ('planOnly', True), ('syntheticPackageOutputsCreated', True),
                           ('publishedPackagesQuarantined', 1), ('moved', [{'original': 'old'}])):
            changed = copy.deepcopy(result); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.cold_feed_proof(changed, retry.COMMIT)


if __name__ == '__main__':
    unittest.main()
