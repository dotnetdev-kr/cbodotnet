"""Exercise .NET 8 input derivation, strict admission and actual bootstrap pins."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('net8_upstream_tested', ROOT / 'scripts/upstream_vmr8.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def declarations(bootstrap='8.0.131', psb='8.0.131-servicing.26422.1'):
    return ('<Project><PropertyGroup><PrivateSourceBuiltArtifactsUrl>'
            'https://builds.dotnet.microsoft.com/source-built-artifacts/assets/Private.SourceBuilt.Artifacts.'
            + psb + '.centos.9-x64.tar.gz</PrivateSourceBuiltArtifactsUrl><PrivateSourceBuiltSdkUrl>'
            'https://builds.dotnet.microsoft.com/source-built-artifacts/sdks/dotnet-sdk-' + bootstrap
            + '-centos.9-x64.tar.gz</PrivateSourceBuiltSdkUrl></PropertyGroup></Project>').encode()


def sdk_files(bootstrap):
    return {arch: dict(url='https://builds.dotnet.microsoft.com/dotnet/Sdk/' + bootstrap + '/dotnet-sdk-'
                      + bootstrap + '-linux-' + arch + '.tar.gz', sha512=('a' if arch == 'arm64' else 'b') * 128)
            for arch in ('arm64', 'x64')}


def global_document(bootstrap='8.0.131', arcade='8.0.0-beta.26411.4'):
    return json.dumps({'tools': {'dotnet': bootstrap}, 'msbuild-sdks': {
        'Microsoft.Build.CentralPackageVersions': '2.0.1', 'Microsoft.Build.Traversal': '2.0.2',
        'Microsoft.NET.Sdk.IL': '3.0.0-preview-27107-01', 'Microsoft.DotNet.Arcade.Sdk': arcade,
        'Yarn.MSBuild': '1.15.2'}}).encode()


def candidate():
    inputs = dict(bootstrapSdk='8.0.133', sourceBuiltArtifacts='8.0.133-servicing.26599.1',
                  sourceBuiltArtifactsRid='centos.9-x64', runtime='8.0.34',
                  components={'runtime': '1' * 40, 'aspnetcore': '2' * 40},
                  psbArchive=dict(url='https://builds.dotnet.microsoft.com/source-built-artifacts/assets/Private.SourceBuilt.Artifacts.8.0.133-servicing.26599.1.centos.9-x64.tar.gz',
                                  bytes=123, sha256='c' * 64, sha512='d' * 128), bootstrapSdkFiles=sdk_files('8.0.133'),
                  buildSdkVersions=json.loads(global_document())['msbuild-sdks'])
    return dict(schemaVersion=1, adapter='net8-1xx-source-build', target='net8', sdkVersion='8.0.134',
                sourceTag='v8.0.134', sourceCommit='3' * 40, releaseDate='2026-11-10',
                runtimeVersion='8.0.34', upstreamInputs=inputs)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def git(root, *args, **kwargs):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false', '-C', str(root), *args])


def entries(root, commit, *paths):
    result = {}
    for row in git(root, 'ls-tree', '-r', '-z', commit, '--', *paths).split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1); mode, kind, blob = meta.decode().split()
            result[name.decode()] = dict(mode=mode, type=kind, blob=blob)
    return result


def exact(data, old, new, required=False):
    if required and old not in data: raise ValueError('Missing exact input')
    return data.replace(old, new)


HELPERS = types.SimpleNamespace(git=git, tree_entries=entries, digest=lambda value: hashlib.sha256(encoded(value)).hexdigest(),
                                encode=encoded, load=lambda path: json.loads(path.read_text()), replace_exact=exact,
                                WORKFLOW='dotnetdev-kr/cbodotnet/.github/workflows/upstream-sdk.yml@refs/heads/main')


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{'path': name, 'commitSha': pin, 'packageVersion': '8.0.33-servicing.26522.19'}
                     for name, pin in M.BASELINE_COMPONENTS.items()]
        self.data = {'global.json': global_document(),
                     'eng/Versions.props': declarations(), 'src/source-manifest.json': json.dumps({'repositories': self.rows}).encode()}

    def test_baseline_uses_retained_psb_fingerprint_and_actual_components(self):
        with mock.patch.object(M, 'bootstrap_sdk_files', return_value=sdk_files('8.0.131')), mock.patch.object(M, 'observe_archive') as observe:
            values = M.manifest_values('8.0.133', M.BASELINE_SOURCE, self.data.__getitem__)
        self.assertEqual(values['psbArchive'], M.BASELINE_PSB)
        self.assertEqual(values['components'], M.BASELINE_COMPONENTS)
        self.assertEqual(values['runtime'], '8.0.33')
        observe.assert_not_called()

    def test_new_bootstrap_uses_new_original_psb_and_official_sdk_hashes(self):
        self.data['global.json'] = global_document('8.0.133')
        self.data['eng/Versions.props'] = declarations('8.0.133', '8.0.133-servicing.26599.1')
        expected = candidate()['upstreamInputs']['psbArchive']
        with mock.patch.object(M, 'bootstrap_sdk_files', return_value=sdk_files('8.0.133')) as sdk, \
             mock.patch.object(M, 'observe_archive', return_value=expected) as observe:
            value = M.manifest_values('8.0.134', '3' * 40, self.data.__getitem__)
        self.assertEqual(value['psbArchive'], expected)
        sdk.assert_called_once_with('8.0.133'); observe.assert_called_once_with(expected['url'])

    def test_incoherent_versions_duplicate_sources_and_other_bands_fail_closed(self):
        self.data['eng/Versions.props'] = declarations('8.0.132', '8.0.132-servicing.26599.1')
        with self.assertRaisesRegex(ValueError, 'incoherent'):
            M.manifest_values('8.0.134', '3' * 40, self.data.__getitem__)
        self.data['eng/Versions.props'] = declarations()
        self.data['src/source-manifest.json'] = json.dumps({'repositories': self.rows + [self.rows[0]]}).encode()
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            M.manifest_values('8.0.134', '3' * 40, self.data.__getitem__)
        with self.assertRaises(ValueError):
            M.manifest_values('8.0.427', '3' * 40, self.data.__getitem__)

    def test_sdk_hashes_require_both_exact_official_archives(self):
        M.bootstrap_sdk_files.cache_clear()
        expected = sdk_files('8.0.133')
        release = {'version': '8.0.133', 'files': [dict(rid='linux-' + arch, hash=row['sha512'], url=row['url']) for arch, row in expected.items()]}
        with mock.patch.object(M, 'request', return_value=json.dumps({'releases': [{'sdk': None, 'sdks': None}, {'sdk': release, 'sdks': [release]}]}).encode()):
            self.assertEqual(M.bootstrap_sdk_files('8.0.133'), expected)
        M.bootstrap_sdk_files.cache_clear(); release['files'].pop()
        with mock.patch.object(M, 'request', return_value=json.dumps({'releases': [{'sdk': release}]}).encode()):
            with self.assertRaisesRegex(ValueError, 'both exact native'):
                M.bootstrap_sdk_files('8.0.133')
        M.bootstrap_sdk_files.cache_clear()

    def test_observed_pin_rejects_content_drift_and_foreign_urls(self):
        with mock.patch.object(M, '_observe_archive', return_value=dict(M.BASELINE_PSB, sha256='0' * 64)):
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                M.observe_archive(M.BASELINE_PSB['url'], M.BASELINE_PSB)
        for url in ('http://builds.dotnet.microsoft.com/a', 'https://example.com/a', 'https://builds.dotnet.microsoft.com/a?query=1'):
            with self.assertRaises(ValueError): M.official_url(url)

    def test_only_existing_build_sdk_names_and_version_data_are_admitted(self):
        sdk, versions = M.global_inputs(global_document('8.0.131', '8.0.0-beta.26411.4'))
        self.assertEqual(sdk, '8.0.131'); self.assertEqual(len(versions), 5)
        for name, version in [('Malicious.New.Sdk', '1.0.0'), ('Yarn.MSBuild', 'https://example.com/sdk')]:
            data = json.loads(global_document()); data['msbuild-sdks'][name] = version
            with self.assertRaises(ValueError): M.global_inputs(json.dumps(data).encode())

    def test_unpublished_psb_is_pending_and_transient_network_failure_propagates(self):
        M._observe_archive.cache_clear()
        with mock.patch.object(M.urllib.request, 'urlopen', side_effect=M.urllib.error.HTTPError(M.BASELINE_PSB['url'], 404, 'missing', {}, None)):
            with self.assertRaisesRegex(ValueError, 'pending-bootstrap'):
                M.observe_archive(M.BASELINE_PSB['url'])
        with mock.patch.object(M.urllib.request, 'urlopen', side_effect=TimeoutError('fixture timeout')):
            with self.assertRaises(TimeoutError): M.observe_archive(M.BASELINE_PSB['url'])


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-vmr8-admission.')
        self.addCleanup(temporary.cleanup); self.root = Path(temporary.name)
        git(self.root, 'init', '-q'); git(self.root, 'config', 'user.name', 'Fixture'); git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        self.policy = {'adapter': dict(baselineSource='', requiredUnchangedFiles=['eng/tool.sh'], requiredUnchangedRoots=['test', 'eng/bootstrap'])}
        for name, data in [('eng/tool.sh', b'original\n'), ('test/Case.cs', b'class Case {}\n'),
                           ('eng/bootstrap/build.csproj', b'<Project/>\n'), ('global.json', global_document()),
                           ('eng/Versions.props', declarations())]: self.put(name, data)
        self.old = self.commit(); self.policy['adapter']['baselineSource'] = self.old

    def put(self, name, data):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def commit(self):
        git(self.root, 'add', '-A'); git(self.root, 'commit', '-qm', 'Fixture')
        return git(self.root, 'rev-parse', 'HEAD').decode().strip()

    def test_changed_versioned_inputs_are_admitted_without_weakening_source_tests(self):
        self.put('global.json', global_document('8.0.133', '8.0.0-beta.26599.1'))
        self.put('eng/Versions.props', declarations('8.0.133', '8.0.133-servicing.26599.1'))
        value = candidate(); value['sourceCommit'] = self.commit()
        proof = M.compatibility(self.root, self.policy, value, HELPERS)
        self.assertEqual(proof['bootstrapSdk'], '8.0.133'); self.assertEqual(proof['unchangedInventories']['test']['files'], 1)
        self.put('test/NewCase.cs', b'class NewCase {}\n'); value['sourceCommit'] = self.commit()
        with self.assertRaisesRegex(ValueError, 'test inventory changed'):
            M.compatibility(self.root, self.policy, value, HELPERS)

    def test_removed_patch_input_and_changed_bootstrap_code_fail_closed(self):
        (self.root / 'eng/tool.sh').unlink(); value = candidate(); value['sourceCommit'] = self.commit()
        with self.assertRaisesRegex(ValueError, 'compatibility input changed'):
            M.compatibility(self.root, self.policy, value, HELPERS)
        self.put('eng/tool.sh', b'original\n'); self.put('eng/bootstrap/build.csproj', b'<Project><Target/></Project>\n')
        value['sourceCommit'] = self.commit()
        with self.assertRaisesRegex(ValueError, 'bootstrap, sysroot or test inventory changed'):
            M.compatibility(self.root, self.policy, value, HELPERS)

    def test_actual_131_to_132_dependency_versions_are_not_spuriously_blocked(self):
        # Immutable VMR tags dcd1e156 (8.0.131) and 56d2f304 (8.0.132)
        # retain these executable inputs while updating the following data.
        self.put('global.json', global_document('8.0.130', '8.0.0-beta.26371.5'))
        self.put('eng/Versions.props', declarations('8.0.130', '8.0.130-servicing.26374.1'))
        self.policy['adapter']['baselineSource'] = self.commit()
        self.put('global.json', global_document('8.0.131', '8.0.0-beta.26411.4'))
        self.put('eng/Versions.props', declarations())
        value = candidate(); value['sourceCommit'] = self.commit()
        self.assertIn('unchangedInventories', M.compatibility(self.root, self.policy, value, HELPERS))


class TransformTests(unittest.TestCase):
    def test_full_current_adapter_transformation_preserves_strict_gates(self):
        policy = json.loads((ROOT / 'profiles/upstream-vmr8-policy.json').read_text()); value = candidate()
        with tempfile.TemporaryDirectory(prefix='cbodotnet-vmr8-transform.') as temporary:
            root = Path(temporary)
            paths = [*policy['adapter']['generatedFiles'], 'profiles/dotnet-8.0.133-linux-aarch64.json', 'profiles/dotnet-8.0.133-linux-x64.json']
            for name in paths:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((ROOT / name).read_bytes())
            M.transform(root, policy, value, HELPERS)
            for path in (root / 'scripts').glob('*.py'): ast.parse(path.read_text())
            selected = json.loads((root / 'profiles/dotnet-8.0.134-linux-aarch64.json').read_text())
            self.assertEqual(selected['upstreamInputs']['bootstrapSdk'], '8.0.133')
            self.assertEqual(selected['source']['commit'], '3' * 40)
            support = (root / 'scripts/ci_vmr89_support.py').read_text()
            self.assertIn("total, passed = 46, 44", support)
            self.assertIn("version == '8'", support)
            self.assertIn("'9': dict(sdk='9.0.123'", support)
            self.assertIn("sdk='8.0.134'", support); self.assertIn("bootstrap='8.0.133'", support)
            self.assertIn(HELPERS.WORKFLOW, support)
            watcher = runpy.run_path(str(root / 'scripts/watch-bootstrap8.py'))
            pin = value['upstreamInputs']['psbArchive']
            record = {'originalUrl': pin['url'], 'originalArchive': dict(pin)}
            watcher['verify_generated_original'](record)
            record['originalArchive']['sha512'] = '0' * 128
            with self.assertRaises(ValueError): watcher['verify_generated_original'](record)
            patcher = (root / 'scripts/apply-net8-patches.py').read_text()
            self.assertIn('e3ccca4155e4a5811576c6e3f18a5efc6aa0d49b3a352d0a98366c020fa2eab2', patcher)
            self.assertIn('10bb2a651fb1176b6f4641aea93f035ab2124bbb2ef3ce32f9989fa814b99a97', patcher)


class Response(io.BytesIO):
    def __init__(self, data, url, status=200, headers=None):
        super().__init__(data); self.url = url; self.status = status
        self.headers = {'Content-Length': str(len(data))} if headers is None else headers
    def geturl(self): return self.url


class BootstrapArchiveTests(unittest.TestCase):
    def archive(self, malicious=False):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            header = bytearray(20); header[:6] = b'\x7fELF\x02\x01'; header[18:20] = (183).to_bytes(2, 'little')
            for name, data in [('dotnet', bytes(header)), ('sdk/8.0.133/dotnet.dll', b'fixture DLL')]:
                info = tarfile.TarInfo('../escape' if malicious else name); info.size = len(data); info.mode = 0o755
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue()

    def exercise(self, data, wrong_hash=False):
        temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-vmr8-bootstrap.'); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); source = root / 'source'; inputs = root / 'inputs'; source.mkdir(); inputs.mkdir()
        value = candidate()['upstreamInputs']; pin = value['bootstrapSdkFiles']['arm64']
        pin['sha512'] = '0' * 128 if wrong_hash else hashlib.sha512(data).hexdigest()
        profile = root / 'profile.json'
        self.profile = {'source': {'commit': '3' * 40}, 'target': {'rid': 'linux-arm64'}, 'upstreamInputs': value}
        profile.write_text(json.dumps(self.profile))
        args = argparse.Namespace(source_dir=source, inputs_dir=inputs, report=root / 'reports/prepare/bootstrap-sdk-input.json', profile=profile, arch='aarch64')
        self.args = args
        with mock.patch.object(M.urllib.request, 'urlopen', return_value=Response(data, pin['url'])):
            M.prepare_bootstrap(args)
        return json.loads(args.report.read_text()), root

    def finish(self, root):
        directory = root / 'reports/prepare/bootstrap'; directory.mkdir(parents=True, exist_ok=True)
        (directory / 'prepare-status.json').write_text(json.dumps(dict(action='prepare', exitCode=0, sourceOnly=True,
                                                       sourceCommit='3' * 40, targetRid='linux-arm64')))
        (directory / 'prepare.log').write_text('  ./.dotnet SDK directory exists...it will not be installed\n'
                                             '  Building bootstrap previously source-built in /tmp/fixture\n')
        M.verify_bootstrap(self.args)
        self.commands = [M.bootstrap_command('prepare-bootstrap', 'arm64'),
                         ['bash', '/inputs/ci-tools/scripts/build-vmr8.sh', '--arch', 'arm64', '--source-dir', '/vmr',
                          '--sysroot', '/inputs/arm64-xenial', '--reports-dir', '/delivery/reports/prepare/bootstrap', '--action', 'prepare'],
                         M.bootstrap_command('verify-bootstrap', 'arm64')]
        return M.validate_bootstrap(root, self.profile, 'arm64', self.commands)

    def test_verified_bootstrap_is_extracted_without_execution(self):
        report, root = self.exercise(self.archive())
        self.assertEqual(report['status'], 'prepared'); self.assertEqual(report['targetRid'], 'linux-arm64')
        self.assertTrue((root / 'source/.dotnet/sdk/8.0.133/dotnet.dll').is_file())
        completed = self.finish(root)
        self.assertEqual(completed['status'], 'passed')
        self.assertEqual(completed['beforeOriginalPrep'], completed['afterOriginalPrep'])
        self.assertTrue((root / completed['archive']['path']).is_file())

    def test_mismatched_hash_and_path_escape_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-512 mismatch'): self.exercise(self.archive(), wrong_hash=True)
        with self.assertRaisesRegex(ValueError, 'Unsafe or duplicate'): self.exercise(self.archive(malicious=True))

    def test_fabricated_sdk_identity_receipt_is_rejected_against_retained_archive(self):
        _, root = self.exercise(self.archive()); receipt = self.finish(root)
        for name in ('beforeOriginalPrep', 'afterOriginalPrep'):
            receipt[name]['sdkDll']['sha256'] = '0' * 64
        self.args.report.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'replaced during original prep'):
            M.validate_bootstrap(root, self.profile, 'arm64', self.commands)

    def test_mutated_retained_archive_and_missing_or_reordered_actual_commands_fail(self):
        _, root = self.exercise(self.archive()); receipt = self.finish(root)
        with self.assertRaisesRegex(ValueError, 'Exactly one actual'):
            M.validate_bootstrap(root, self.profile, 'arm64', self.commands[:-1])
        with self.assertRaisesRegex(ValueError, 'before original prep'):
            M.validate_bootstrap(root, self.profile, 'arm64', list(reversed(self.commands)))
        with (root / receipt['archive']['path']).open('ab') as output: output.write(b'mutated')
        with self.assertRaisesRegex(ValueError, 'retained official bootstrap SDK archive differs'):
            M.validate_bootstrap(root, self.profile, 'arm64', self.commands)

    def test_original_prep_may_not_replace_the_sdk_host_or_sdk_dll(self):
        for member in ('dotnet', 'sdk/8.0.133/dotnet.dll'):
            with self.subTest(member=member):
                _, root = self.exercise(self.archive())
                path = root / 'source/.dotnet' / member
                with path.open('ab') as output: output.write(b'changed by prep')
                with self.assertRaisesRegex(ValueError, 'replaced during original prep'): self.finish(root)

    def test_first_psb_observation_rejects_partial_truncated_and_corrupt_streams(self):
        url = candidate()['upstreamInputs']['psbArchive']['url']; payload = self.archive()
        cases = [(payload, 206, {'Content-Length': str(len(payload)), 'Content-Range': 'bytes 0-1/9999'}),
                 (payload[:-8], 200, {'Content-Length': str(len(payload))}),
                 (payload[:-8], 200, {'Content-Length': str(len(payload) - 8)}),
                 (payload[:-20] + b'corrupt bytes', 200, None)]
        for data, status, headers in cases:
            with self.subTest(status=status, size=len(data)):
                M._observe_archive.cache_clear()
                with mock.patch.object(M.urllib.request, 'urlopen', return_value=Response(data, url, status, headers)):
                    with self.assertRaises(ValueError): M.observe_archive(url)
        M._observe_archive.cache_clear()
        with mock.patch.object(M.urllib.request, 'urlopen', return_value=Response(payload, url)):
            value = M.observe_archive(url)
        self.assertEqual(value['bytes'], len(payload)); self.assertEqual(value['sha512'], hashlib.sha512(payload).hexdigest())


if __name__ == '__main__':
    unittest.main()
