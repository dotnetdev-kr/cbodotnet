"""Bounded legacy CI safety/origin fixtures; no product build or container run."""
import ast
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
                self.assertEqual('--skip-source-bundle-downloads' in command, family == 'core30' and action == 'build')

    def test_ci_report_paths_match_the_original_core30_isolation_guard(self):
        source = (ROOT / 'scripts/prepare-core30-smoke.py').read_text()
        tree = ast.parse(source)
        guard = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                     and any(isinstance(value, ast.Str) and value.s == 'Use an isolated test root selected by the new test report directory'
                             for value in ast.walk(node)))
        code = compile(ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[])), '<original Core3.0 isolation guard>', 'exec')
        for family in ('net5', 'core31', 'core30'):
            runner = driver.CI.__new__(driver.CI)
            runner.family = family; runner.source = self.root / 'source'; runner.inputs = self.root / 'inputs'
            runner.snapshot = self.root / 'frozen'; runner.profile = self.root / 'profile.json'; runner.reports = self.root / family / 'reports'
            runner.product = driver.CONFIG[family][4]; runner.cpus = '0,1'; runner.raw_sdk = lambda: self.root / 'sdk.tar.gz'
            for action in ('prepare', 'build', 'test'):
                command = runner.product_command(action, runner.reports / action / 'product')
                reports = Path(command[command.index('--reports-dir') + 1])
                expected = 'test-product' if family == 'core30' and action == 'test' else 'product-' + action
                self.assertEqual(reports.name, expected)
                if action == 'test':
                    self.assertEqual(Path(gate.test_report_path(family)).parent, reports.relative_to(runner.reports.parent))
                if family == 'core30' and action == 'test':
                    context = {'root': runner.inputs / 'core30-tests' / reports.name,
                               'inputs': runner.inputs, 'reports': reports, 're': driver.re}
                    exec(code, context)
                    for invalid in ('product-test', 'test-other'):
                        changed = dict(context, root=runner.inputs / 'core30-tests' / invalid)
                        with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'isolated test root'):
                            exec(code, changed)
                    with self.assertRaisesRegex(ValueError, 'isolated test root'):
                        exec(code, dict(context, root=self.root / 'outside' / reports.name))

    def test_official_sdk_transport_diagnostics_keep_exact_integrity(self):
        expected = b'\x1f\x8bexact SDK response fixture'
        for name, status, body in (('partial206', 206, expected[:7]), ('short200', 200, expected[:9]),
                                   ('html200', 200, b'<html>unexpected CDN response</html>'), ('exact200', 200, expected)):
            with self.subTest(response=name):
                inputs = self.root / name / 'inputs'; reports = self.root / name / 'reports'
                inputs.mkdir(parents=True); reports.mkdir()
                response = io.BytesIO(body)
                response.getcode = lambda status=status: status
                response.geturl = lambda: bootstrap.SDK_URL + '?unrecorded-credential=value'
                response.headers = {'Content-Length': str(len(body)), 'Content-Type': 'application/octet-stream',
                                    'Content-Range': 'bytes 0-6/' + str(len(expected)) if status == 206 else None,
                                    'Set-Cookie': 'unrecorded-cookie', 'Authorization': 'unrecorded-token'}
                with mock.patch.object(bootstrap, 'SDK_SHA512', hashlib.sha512(expected).hexdigest()), \
                        mock.patch.object(bootstrap, 'SDK_BYTES', len(expected)), \
                        mock.patch.object(bootstrap.urllib.request, 'urlopen', return_value=response) as download:
                    if name == 'exact200':
                        target, info = bootstrap.official_sdk_archive(inputs, reports)
                        self.assertEqual(target.read_bytes(), expected)
                        self.assertEqual(info['sha512'], hashlib.sha512(expected).hexdigest())
                    else:
                        with self.assertRaisesRegex(ValueError, 'differs from official release metadata'):
                            bootstrap.official_sdk_archive(inputs, reports)
                        self.assertFalse((inputs / 'official-sdk' / bootstrap.SDK_NAME).exists())
                        self.assertEqual((reports / 'rejected-sdk-download.bin').read_bytes(), body)
                    self.assertEqual(download.call_count, 1)
                receipt = json.loads((reports / 'sdk-download.json').read_text())
                self.assertEqual(receipt['httpStatus'], status)
                self.assertEqual(receipt['responseBody']['bytes'], len(body))
                self.assertEqual(receipt['responseBody']['sha512'], hashlib.sha512(body).hexdigest())
                self.assertEqual(receipt['expectedBytes'], len(expected))
                self.assertEqual(receipt['hashMatchesOfficialMetadata'], name == 'exact200')
                self.assertEqual(receipt['status'], 'passed' if name == 'exact200' else 'rejected')
                self.assertTrue(receipt['finalUrlQueryOmitted'])
                self.assertNotIn('unrecorded-', (reports / 'sdk-download.json').read_text())
                self.assertEqual(list((inputs / 'official-sdk').glob('.core30-sdk-download-*')), [])

    def test_sdk_download_diagnostics_refuse_existing_controls_and_links(self):
        outside = self.root / 'outside'; outside.write_bytes(b'never overwrite')
        for name, kind in (('sdk-download.json', 'file'), ('rejected-sdk-download.bin', 'file'),
                           ('sdk-download.json', 'link'), ('rejected-sdk-download.bin', 'link')):
            reports = self.root / (name + '-' + kind); reports.mkdir()
            path = reports / name
            path.symlink_to(outside) if kind == 'link' else path.write_bytes(b'original control')
            with mock.patch.object(bootstrap.urllib.request, 'urlopen') as download:
                with self.assertRaisesRegex(ValueError, 'existing SDK download diagnostics'):
                    bootstrap.official_sdk_archive(self.root / 'unused-inputs', reports)
                download.assert_not_called()
            self.assertEqual(outside.read_bytes(), b'never overwrite')
            self.assertEqual(path.read_bytes(), b'never overwrite' if kind == 'link' else b'original control')
        linked_reports = self.root / 'linked-reports'; linked_reports.symlink_to(reports, target_is_directory=True)
        with mock.patch.object(bootstrap.urllib.request, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'symlink'):
                bootstrap.official_sdk_archive(self.root / 'unused-inputs', linked_reports)
            download.assert_not_called()

    def test_existing_sdk_input_is_never_overwritten_or_followed(self):
        for kind in ('file', 'link'):
            inputs = self.root / kind / 'inputs'; reports = self.root / kind / 'reports'
            cache = inputs / 'official-sdk'; cache.mkdir(parents=True); reports.mkdir()
            outside = self.root / ('sdk-outside-' + kind); outside.write_bytes(b'original unverified archive')
            target = cache / bootstrap.SDK_NAME
            target.symlink_to(outside) if kind == 'link' else target.write_bytes(outside.read_bytes())
            with mock.patch.object(bootstrap.urllib.request, 'urlopen') as download:
                with self.assertRaises(ValueError):
                    bootstrap.official_sdk_archive(inputs, reports)
                download.assert_not_called()
            self.assertEqual(target.read_bytes(), b'original unverified archive')
            self.assertEqual(outside.read_bytes(), b'original unverified archive')

    def test_core30_only_prefetches_the_exact_sdk_before_container_preparation(self):
        for family in ('net5', 'core31', 'core30'):
            with self.subTest(family=family):
                runner = driver.CI.__new__(driver.CI)
                runner.family = family; runner.sdk, runner.commit, _, _, _ = driver.CONFIG[family]
                runner.workspace = self.root / family; runner.source = runner.workspace / 'source'
                runner.inputs = runner.workspace / 'inputs'; runner.output = runner.workspace / 'output'
                runner.reports = runner.output / 'reports'; runner.snapshot = ROOT
                runner.profile = ROOT / ('profiles/dotnet-' + runner.sdk + '-linux-arm64.json')
                runner.run_id = '42'; runner.attempt = '1'; runner.engine = ['fixture-engine']
                runner.state = runner.workspace / 'state.json'
                (runner.reports / 'ci-inputs').mkdir(parents=True)
                (runner.reports / 'ci-inputs/snapshot.json').write_text('{}')
                events = []
                runner.run = mock.Mock(); runner.freeze = mock.Mock()
                runner.identity = lambda: {'fixture': True}
                runner.image_inspect = mock.Mock(return_value='fixture-image')
                runner.product_command = lambda action, *_: ['fixture-product', action]
                runner.container = lambda command, **_: events.append(('container', command))
                def record_download(url, target, expected, report):
                    events.append(('download', url, target, expected, report))
                with mock.patch.object(driver, 'download', side_effect=record_download), \
                        mock.patch.object(driver.shutil, 'copyfile'), mock.patch.object(driver, 'write'):
                    runner.prepare()
                sdk_calls = [event for event in events if event[0] == 'download' and event[1] == bootstrap.SDK_URL]
                self.assertEqual(len(sdk_calls), 1 if family == 'core30' else 0)
                if family == 'core30':
                    call = sdk_calls[0]
                    self.assertEqual(call[2], runner.inputs / 'official-sdk' / bootstrap.SDK_NAME)
                    self.assertEqual(call[3], {'bytes': 113669548, 'sha512': bootstrap.SDK_SHA512})
                    self.assertEqual(call[4], runner.reports / 'prepare/official-sdk-download.json')
                    self.assertLess(events.index(call), next(i for i, event in enumerate(events) if event[0] == 'container'))

    def test_bootstrap_rehashes_prefetched_sdk_without_another_download(self):
        inputs = self.root / 'inputs'; reports = self.root / 'reports'; reports.mkdir()
        cache = inputs / 'official-sdk'; cache.mkdir(parents=True)
        archive = cache / bootstrap.SDK_NAME; payload = b'exact preverified transport fixture'
        archive.write_bytes(payload)
        with mock.patch.object(bootstrap, 'SDK_SHA512', hashlib.sha512(payload).hexdigest()), \
                mock.patch.object(bootstrap.urllib.request, 'urlopen') as download:
            target, record = bootstrap.official_sdk_archive(inputs, reports)
            download.assert_not_called()
        self.assertEqual(target, archive); self.assertEqual(record['sha512'], hashlib.sha512(payload).hexdigest())
        receipt = json.loads((reports / 'sdk-download.json').read_text())
        self.assertIs(receipt['downloadAttempted'], False)
        self.assertIs(receipt['hashMatchesOfficialMetadata'], True)
        self.assertEqual(receipt['status'], 'passed'); self.assertEqual(archive.read_bytes(), payload)

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

    def component_runner(self):
        runner = driver.CI.__new__(driver.CI)
        runner.source = self.root / 'source'; runner.source.mkdir()
        runner.layout = 'bin'; runner.family = 'core30'; runner.workspace = self.root / 'workspace'
        runner.output = self.root / 'output'; runner.reports = runner.output / 'reports'
        (runner.reports / 'build').mkdir(parents=True)
        runner.snapshot = self.root / 'frozen'; runner.log = io.StringIO()
        runner.product_command = lambda *_: ['isolated-fake-producer']
        archive = self.root / 'sdk-fixture'; archive.write_bytes(b'not a product SDK; control-flow fixture')
        runner.raw_sdk = lambda: archive
        return runner

    def test_component_logs_are_byte_exact_and_scoped(self):
        runner = self.component_runner(); logs = runner.source / 'bin/logs'; (logs / 'nested').mkdir(parents=True)
        (logs / 'roslyn.log').write_bytes(b'actual producer exit139\n')
        (logs / 'nested/pack.binlog').write_bytes(b'actual binary log\0bytes')
        (logs / 'unrelated.nupkg').write_bytes(b'not a log')
        result = driver.capture_component_logs(runner.source, runner.layout, runner.reports)
        self.assertEqual(result['status'], 'captured'); self.assertEqual(result['selectedFileCount'], 2)
        for row in result['files']:
            self.assertEqual((runner.output / row['path']).read_bytes(), Path(row['original']).read_bytes())
        self.assertFalse((runner.reports / 'build/component-logs/unrelated.nupkg').exists())

    def test_failed_producer_keeps_original_exception_and_captures_logs(self):
        runner = self.component_runner(); logs = runner.source / 'bin/logs'; logs.mkdir(parents=True)
        (logs / 'roslyn.log').write_text('Segmentation fault\n')
        failure = RuntimeError('original producer exit139')
        runner.container = mock.Mock(side_effect=failure)
        observer = mock.Mock(); observer.wait.return_value = 0
        with mock.patch.object(driver.subprocess, 'Popen', return_value=observer):
            with self.assertRaises(RuntimeError) as raised:
                runner.build()
        self.assertIs(raised.exception, failure)
        self.assertEqual(runner.container.call_count, 1)
        self.assertEqual((runner.reports / 'build/component-logs/roslyn.log').read_text(), 'Segmentation fault\n')

    def test_missing_component_logs_are_reported_without_masking_failure(self):
        runner = self.component_runner(); failure = RuntimeError('before component logs')
        runner.container = mock.Mock(side_effect=failure)
        observer = mock.Mock(); observer.wait.return_value = 0
        with mock.patch.object(driver.subprocess, 'Popen', return_value=observer):
            with self.assertRaises(RuntimeError) as raised:
                runner.build()
        self.assertIs(raised.exception, failure)
        receipt = json.loads((runner.reports / 'build/component-log-capture.json').read_text())
        self.assertEqual(receipt['status'], 'not-produced'); self.assertEqual(receipt['files'], [])
        self.assertFalse((runner.source / 'bin/logs').exists())

    def test_log_capture_rejects_links_and_preserves_producer_failure(self):
        runner = self.component_runner(); logs = runner.source / 'bin/logs'; logs.mkdir(parents=True)
        outside = self.root / 'outside.log'; outside.write_text('never copy outside declared logs')
        (logs / 'linked.log').symlink_to(outside)
        failure = RuntimeError('original producer failure')
        runner.container = mock.Mock(side_effect=failure)
        observer = mock.Mock(); observer.wait.return_value = 0
        with mock.patch.object(driver.subprocess, 'Popen', return_value=observer):
            with self.assertRaises(RuntimeError) as raised:
                runner.build()
        self.assertIs(raised.exception, failure)
        receipt = json.loads((runner.reports / 'build/component-log-capture.json').read_text())
        self.assertEqual(receipt['status'], 'failed'); self.assertEqual(receipt['files'], [])
        self.assertFalse((runner.reports / 'build/component-logs').exists())
        self.assertEqual(outside.read_text(), 'never copy outside declared logs')

    def test_log_capture_failure_does_not_replace_successful_producer_status(self):
        runner = self.component_runner(); runner.container = mock.Mock()
        observer = mock.Mock(); observer.wait.return_value = 0
        with mock.patch.object(driver.subprocess, 'Popen', return_value=observer), mock.patch.object(driver, 'capture_component_logs', side_effect=OSError('diagnostic copy failed')):
            runner.build()
        self.assertEqual(runner.container.call_count, 1)
        self.assertIn('Component log capture failed', runner.log.getvalue())

    def test_unwritable_diagnostic_warning_keeps_original_producer_exception(self):
        runner = self.component_runner(); failure = RuntimeError('original producer failure')
        runner.container = mock.Mock(side_effect=failure)
        runner.log = mock.Mock(); runner.log.write.side_effect = OSError('full diagnostic volume')
        observer = mock.Mock(); observer.wait.return_value = 0
        with mock.patch.object(driver.subprocess, 'Popen', return_value=observer), mock.patch.object(driver, 'capture_component_logs', side_effect=OSError('cannot preserve log')):
            with self.assertRaises(RuntimeError) as raised:
                runner.build()
        self.assertIs(raised.exception, failure)


if __name__ == '__main__':
    unittest.main()
