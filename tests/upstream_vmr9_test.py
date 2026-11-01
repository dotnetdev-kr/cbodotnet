"""Exercise NET9 servicing admission, generated policies and native bootstrap proof."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('upstream_vmr9_tested', ROOT / 'scripts/upstream_vmr9.py')
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)
import upstream_vmr8 as SHARED

# The two actual preceding servicing tags have this identical global.json blob.
PRIMARY_GLOBAL = b'''{
  "tools": {
    "dotnet": "9.0.121"
  },
  "msbuild-sdks": {
    "Microsoft.Build.NoTargets": "3.7.0",
    "Microsoft.Build.Traversal": "3.4.0",
    "Microsoft.DotNet.Arcade.Sdk": "9.0.0-beta.26406.11"
  }
}
'''
PROPS = b'''<Project><PropertyGroup>
<PrivateSourceBuiltSdkVersion>9.0.121</PrivateSourceBuiltSdkVersion>
<PrivateSourceBuiltArtifactsVersion>9.0.121-servicing.26421.1</PrivateSourceBuiltArtifactsVersion>
<UseVSTestRunner>true</UseVSTestRunner>
</PropertyGroup></Project>'''
TEST_PROJECTS = b'''<Project><ItemGroup>
<ProjectReference Include="Microsoft.DotNet.SourceBuild.SmokeTests/Microsoft.DotNet.SourceBuild.SmokeTests.csproj"
 Condition="'$(DotNetBuildSourceOnly)' == 'true'" />
<ProjectReference Include="Microsoft.DotNet.UnifiedBuild.Tests/Microsoft.DotNet.UnifiedBuild.Tests.csproj" />
</ItemGroup></Project>'''
POLICY = json.loads((ROOT / 'profiles/upstream-vmr9-policy.json').read_text())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def git(root, *args, data=None, env=None):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false',
                                    '-C', str(root), *args], input=data, env=env)


def tree_entries(root, commit, *paths):
    result = {}
    for row in git(root, 'ls-tree', '-r', '-z', commit, '--', *paths).split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1); mode, kind, blob = meta.decode().split()
            result[name.decode()] = dict(mode=mode, type=kind, blob=blob)
    return result


HELPERS = SimpleNamespace(git=git, tree_entries=tree_entries, encode=encode,
    digest=lambda value: hashlib.sha256(encode(value)).hexdigest(),
    load=lambda path: json.loads(path.read_text()),
    WORKFLOW='dotnetdev-kr/cbodotnet/.github/workflows/upstream-sdk.yml@refs/heads/main')


def bootstrap_files(version='9.0.121', sha512='1' * 128):
    return {arch: dict(url='https://builds.dotnet.microsoft.com/dotnet/Sdk/' + version +
                        '/dotnet-sdk-' + version + '-' + rid + '.tar.gz', sha512=sha512)
            for arch, (rid, _, _) in MODULE.ARCHES.items()}


def source_manifest():
    return {'repositories': [dict(path=name, commitSha=pin, packageVersion='9.0.22-servicing.26522.18')
            for name, pin in POLICY['adapter']['baselineComponents'].items()]}


def candidate():
    return dict(adapter='net9-1xx-portable', target='net9', sdkVersion='9.0.124', sourceTag='v9.0.124',
                sourceCommit='4' * 40, runtimeVersion='9.0.23', releaseDate='2026-11-10',
                upstreamInputs=dict(bootstrapSdk='9.0.122', sourceBuiltArtifacts='9.0.122-servicing.26599.1',
                    runtime='9.0.23', components={'runtime': '5' * 40, 'aspnetcore': '6' * 40},
                    bootstrapSdkFiles=bootstrap_files('9.0.122')))


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.documents = {'global.json': PRIMARY_GLOBAL, 'eng/Versions.props': PROPS,
                          'src/source-manifest.json': encode(source_manifest())}

    def read_values(self, sdk='9.0.123'):
        with mock.patch.object(SHARED, 'bootstrap_sdk_files', side_effect=bootstrap_files):
            return MODULE.manifest_values(sdk, MODULE.BASELINE_SOURCE, self.documents.__getitem__)

    def test_exact_net9_manifests_supply_components_and_both_official_sdk_pins(self):
        value = self.read_values()
        self.assertEqual(POLICY['adapter']['baselineComponents'], value['components'])
        self.assertEqual('9.0.22', value['runtime'])
        self.assertEqual('9.0.121', value['bootstrapSdk'])
        self.assertEqual('9.0.121-servicing.26421.1', value['sourceBuiltArtifacts'])
        self.assertEqual({'arm64', 'x64'}, set(value['bootstrapSdkFiles']))
        self.assertNotIn('psbArchive', value)

    def test_real_preceding_patch_global_json_blob_is_exact(self):
        blob = b'blob ' + str(len(PRIMARY_GLOBAL)).encode() + b'\0' + PRIMARY_GLOBAL
        self.assertEqual('3bbc33fcb052dc4664f95d75a1fd8f381f3c8fa2', hashlib.sha1(blob).hexdigest())

    def test_bootstrap_update_is_derived_without_using_previous_sdk_bytes(self):
        self.documents['global.json'] = PRIMARY_GLOBAL.replace(b'9.0.121', b'9.0.122')
        self.documents['eng/Versions.props'] = PROPS.replace(b'9.0.121', b'9.0.122')
        value = self.read_values('9.0.124')
        self.assertEqual('9.0.122', value['bootstrapSdk'])
        self.assertTrue(all('/9.0.122/' in item['url'] for item in value['bootstrapSdkFiles'].values()))

    def test_higher_sdk_band_cannot_relabel_a_1xx_source_tree(self):
        with self.assertRaisesRegex(ValueError, '1xx sources'):
            self.read_values('9.0.320')

    def test_ambiguous_missing_or_cross_runtime_component_metadata_is_rejected(self):
        original = source_manifest()
        for change in ('duplicate', 'missing', 'runtime', 'pin', 'version'):
            data = copy.deepcopy(original)
            if change == 'duplicate': data['repositories'].append(data['repositories'][0])
            elif change == 'missing': data['repositories'].pop()
            elif change == 'runtime': data['repositories'][0]['packageVersion'] = '9.0.23-servicing.26522.18'
            elif change == 'pin': data['repositories'][0]['commitSha'] = 'bad'
            else: data['repositories'][0]['packageVersion'] = '9.0.22-preview.1'
            self.documents['src/source-manifest.json'] = encode(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.read_values()

    def test_ambiguous_or_mismatched_bootstrap_declarations_are_rejected(self):
        for changed in (PROPS.replace(b'<UseVSTestRunner>', b'<PrivateSourceBuiltSdkVersion>9.0.122</PrivateSourceBuiltSdkVersion><UseVSTestRunner>'),
                        PROPS.replace(b'>9.0.121<', b'>9.0.122<'),
                        PROPS.replace(b'9.0.121-servicing.26421.1', b'9.0.121-preview.1')):
            self.documents['eng/Versions.props'] = changed
            with self.assertRaises(ValueError):
                self.read_values()


class GitAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        git(self.root, 'init', '--quiet'); git(self.root, 'config', 'user.name', 'Fixture')
        git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        self.policy = copy.deepcopy(POLICY)
        for path in self.policy['adapter']['requiredUnchangedFiles']:
            self.put(path, b'unchanged original build wiring\n')
        for path in self.policy['adapter']['integrityRoots']:
            self.put(path + '/tool.txt', b'unchanged original integrity input\n')
        for path in self.policy['adapter']['testRoots']:
            self.put(path + '/Test.cs', b'class OriginalTest {}\n')
        for path in self.policy['adapter']['testSourceFiles']:
            self.put(path, (ROOT / 'tests/fixtures/net9-package-cases' / Path(path).name).read_bytes())
        self.put('global.json', PRIMARY_GLOBAL); self.put('eng/Versions.props', PROPS)
        self.put('test/tests.proj', TEST_PROJECTS)
        self.put('test/Microsoft.DotNet.SourceBuild.SmokeTests/LegacyTest.cs', b'class OriginalSourceOnlyTest {}\n')
        self.old = self.commit(); self.policy['adapter']['baselineSource'] = self.old

    def put(self, name, data):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def commit(self):
        git(self.root, 'add', '--all'); git(self.root, 'commit', '--quiet', '-m', 'Fixture')
        return git(self.root, 'rev-parse', 'HEAD').decode().strip()

    def check(self, commit=None):
        return MODULE.compatibility(self.root, self.policy,
                    {'sdkVersion': '9.0.124', 'sourceCommit': commit or self.commit()}, HELPERS)

    def test_real_git_objects_admit_only_declared_bootstrap_version_updates(self):
        self.put('global.json', PRIMARY_GLOBAL.replace(b'9.0.121', b'9.0.122'))
        self.put('eng/Versions.props', PROPS.replace(b'9.0.121', b'9.0.122'))
        result = self.check()
        self.assertEqual(522, result['commonResults'])
        self.assertEqual(34, result['scenarioResults'])
        self.assertEqual(262, result['shippingPackages'])
        self.assertIn('Unused declaration', result['psbConstruction'])

    def test_changed_sysroot_test_source_or_new_test_definition_is_rejected(self):
        names = [self.policy['adapter']['requiredUnchangedFiles'][0],
                 next(iter(self.policy['adapter']['testSourceFiles'])),
                 self.policy['adapter']['testRoots'][0] + '/NewTest.cs',
                 self.policy['adapter']['integrityRoots'][0] + '/NewTool.py']
        for name in names:
            git(self.root, 'reset', '--quiet', '--hard', self.old); git(self.root, 'clean', '-fdq')
            self.put(name, b'changed executable or test input\n')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check()

    def test_nonversion_global_or_msbuild_conditions_are_rejected(self):
        self.put('global.json', PRIMARY_GLOBAL.replace(b'3.7.0', b'3.8.0'))
        with self.assertRaisesRegex(ValueError, 'non-version'):
            self.check()
        git(self.root, 'reset', '--quiet', '--hard', self.old)
        self.put('eng/Versions.props', PROPS.replace(b'>true<', b'>false<'))
        with self.assertRaisesRegex(ValueError, 'non-version'):
            self.check()

    def test_unused_source_only_fact_changes_are_admitted_but_wiring_changes_are_rejected(self):
        self.put('test/Microsoft.DotNet.SourceBuild.SmokeTests/LegacyTest.cs',
                 b'class OriginalSourceOnlyTest { void SourceBuiltTarballsHaveExpectedOwnership() {} }\n')
        result = self.check()
        self.assertIn('not executed', result['executedTestClosure'])
        self.put('test/tests.proj', TEST_PROJECTS.replace(b"== 'true'", b"!= 'true'"))
        with self.assertRaises(ValueError):
            self.check()

    def test_new_automatic_test_import_cannot_enter_outside_the_frozen_project_roots(self):
        self.put('test/Directory.Build.targets', b'<Project><Target Name="Changed" /></Project>')
        with self.assertRaisesRegex(ValueError, 'test import wiring'):
            self.check()

    def test_package_source_hash_cannot_be_relaxed_by_matching_new_git_tree(self):
        name = next(iter(self.policy['adapter']['testSourceFiles']))
        self.put(name, b'changed package comparison source\n')
        changed = self.commit(); self.policy['adapter']['baselineSource'] = changed
        with self.assertRaisesRegex(ValueError, 'exact NET9 package test source'):
            self.check(changed)


class TransformationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in POLICY['adapter']['generatedFiles'] + ['scripts/ci_arch.py']:
            destination = self.root / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        for path in (ROOT / 'profiles').glob('dotnet-9.0.123-linux-*.json'):
            (self.root / 'profiles').mkdir(exist_ok=True)
            shutil.copyfile(path, self.root / 'profiles' / path.name)
        self.before = {path.relative_to(self.root).as_posix(): path.read_bytes()
                       for path in self.root.rglob('*') if path.is_file()}

    def test_generated_adapter_retains_all_cases_and_binds_new_source_and_bootstrap(self):
        selected = candidate(); MODULE.transform(self.root, POLICY, selected, HELPERS)
        arm = json.loads((self.root / 'scripts/ci-net9-test-cases.json').read_text())
        x64 = json.loads((self.root / 'scripts/ci-net9-test-cases-x64.json').read_text())
        original = json.loads(self.before['scripts/ci-net9-test-cases.json'])
        for key in ('shippingPackageIds', 'unavailableBaselineIds', 'factMethods', 'packageMethods', 'sourceFiles'):
            self.assertEqual(original[key], arm[key])
        self.assertEqual('9.0.124', arm['sdkVersion'])
        self.assertEqual(selected['sourceCommit'], arm['sourceCommit'])
        self.assertEqual(hashlib.sha256((self.root / 'scripts/ci-net9-test-cases.json').read_bytes()).hexdigest(),
                         x64['derivation']['arm64PolicySha256'])
        self.assertEqual(8, x64['derivation']['targetRidSubstitutions'])
        for path in (self.root / 'scripts').glob('*.py'):
            ast.parse(path.read_text())
        driver = (self.root / 'scripts/ci-vmr89.py').read_text()
        self.assertLess(driver.index('S.freeze('), driver.index("'scripts/upstream_vmr9.py', 'bootstrap'"))
        support = (self.root / 'scripts/ci_vmr89_support.py').read_text()
        self.assertIn(HELPERS.WORKFLOW, support)
        self.assertIn("validate_bootstrap(release, V[version]['bootstrap']", support)
        self.assertIn("validate_bootstrap_use(release, V[version]['bootstrap']", support)
        self.assertIn("'scripts/upstream_vmr9.py', 'verify-bootstrap'", driver)
        self.assertIn("len(tests) == 34", support)
        self.assertIn('export DOTNET_INSTALL_DIR="$source_dir/.dotnet"',
                      (self.root / 'scripts/build-vmr9.sh').read_text())
        self.assertEqual(self.before['scripts/ci_arch.py'], (self.root / 'scripts/ci_arch.py').read_bytes())
        for path in (self.root / 'profiles').glob('*.json'):
            profile = json.loads(path.read_text())
            self.assertEqual('9.0.124', profile['sdkVersion'])
            self.assertFalse(profile['build']['sourceOnly'])
            self.assertTrue(profile['construction']['upstreamSharedRuntimeReused'])
            self.assertEqual(selected['upstreamInputs'], profile['upstreamInputs'])

    def test_modified_trusted_adapter_input_is_rejected_before_any_transformation(self):
        path = self.root / 'scripts/build-vmr9.sh'; path.write_text(path.read_text() + '\n# unknown edit\n')
        prior = {name: (self.root / name).read_bytes() for name in self.before}
        with self.assertRaisesRegex(ValueError, 'trusted NET9 adapter input changed'):
            MODULE.transform(self.root, POLICY, candidate(), HELPERS)
        self.assertTrue(all((self.root / name).read_bytes() == value for name, value in prior.items()))


def sdk_archive(machine=62, version='9.0.121', extra=None):
    output = io.BytesIO(); host = bytearray(24); host[:6] = b'\x7fELF\x02\x01'; host[18:20] = struct.pack('<H', machine)
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, value in [('dotnet', bytes(host)), ('sdk/' + version + '/dotnet.dll', b'official SDK fixture')]:
            entry = tarfile.TarInfo(name); entry.size = len(value); entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(value))
        if extra:
            entry = tarfile.TarInfo(extra[0]); entry.size = 1
            if extra[1] == 'link': entry.type = tarfile.SYMTYPE; entry.linkname = '/etc/passwd'; entry.size = 0
            archive.addfile(entry, io.BytesIO(b'x'))
    return output.getvalue()


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.source = self.root / 'vmr'; self.source.mkdir()
        self.release = self.root / 'release'; self.profile = self.release / 'reports/ci-inputs/effective-profile.json'
        self.profile.parent.mkdir(parents=True); (self.release / 'reports/prepare').mkdir()
        self.reports = self.release / 'reports/prepare/bootstrap'

    def prepare(self, arch='x64', payload=None, expected=None, reported='9.0.121'):
        data = payload or sdk_archive(MODULE.ARCHES[arch][2]); digest = hashlib.sha512(data).hexdigest()
        profile = dict(source={'commit': MODULE.BASELINE_SOURCE}, target={'rid': MODULE.ARCHES[arch][0]},
            upstreamInputs=dict(bootstrapSdk='9.0.121', bootstrapSdkFiles=bootstrap_files(sha512=expected or digest)))
        self.profile.write_bytes(encode(profile))
        invocation = ['/usr/bin/python3', '/delivery/reports/ci-inputs/project/scripts/upstream_vmr9.py', 'bootstrap',
                      '--source-dir', str(self.source), '--profile', str(self.profile),
                      '--reports-dir', str(self.reports), '--arch', arch]
        def command(args, **kwargs):
            return (MODULE.BASELINE_SOURCE if args[0] == 'git' else reported) + '\n'
        with mock.patch.object(MODULE.platform, 'system', return_value='Linux'), \
             mock.patch.object(MODULE.platform, 'machine', return_value=MODULE.ARCHES[arch][1]), \
             mock.patch.object(MODULE.urllib.request, 'urlopen', return_value=io.BytesIO(data)), \
             mock.patch.object(MODULE.subprocess, 'check_output', side_effect=command) as invoked:
            MODULE.prepare_bootstrap(self.source, self.profile, self.reports, arch, invocation)
        return invocation, invoked

    def test_native_bootstrap_retains_verified_archive_and_portable_proof(self):
        invocation, invoked = self.prepare()
        self.assertEqual(2, invoked.call_count)
        MODULE.validate_bootstrap(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', [invocation])
        self.assertTrue((self.source / '.dotnet/sdk/9.0.121/dotnet.dll').is_file())
        self.assertTrue((self.reports / 'dotnet-sdk-9.0.121-linux-x64.tar.gz').is_file())
        receipt = json.loads((self.reports / 'bootstrap-sdk.json').read_text())
        self.assertEqual(62, receipt['dotnetHost']['elfMachine'])
        self.assertTrue(receipt['sha512Verified'])

    def test_bad_sha512_or_sdk_version_never_qualifies(self):
        with self.assertRaisesRegex(ValueError, 'SHA-512 mismatch'):
            self.prepare(expected='f' * 128)
        self.assertFalse((self.source / '.dotnet').exists())
        self.assertFalse((self.reports / 'bootstrap-sdk.json').exists())

    def test_native_reported_version_must_match_the_official_pin(self):
        with self.assertRaisesRegex(ValueError, 'reports a different version'):
            self.prepare(reported='9.0.122')
        self.assertFalse((self.reports / 'bootstrap-sdk.json').exists())

    def test_wrong_architecture_or_archive_sdk_directory_is_rejected(self):
        for payload in (sdk_archive(183), sdk_archive(62, '9.0.122')):
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive, self.assertRaises(ValueError):
                MODULE.archive_members(archive, '9.0.121', 62)

    def test_archive_links_traversal_and_duplicate_names_are_rejected(self):
        for name, kind in [('../escape', 'file'), ('/absolute', 'file'), ('back\\slash', 'file'),
                           ('linked', 'link'), ('dotnet', 'file')]:
            payload = sdk_archive(extra=(name, kind))
            with self.subTest(name=name), tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive, self.assertRaises(ValueError):
                MODULE.archive_members(archive, '9.0.121', 62)

    def test_portable_gate_rejects_tampered_bytes_or_missing_actual_command(self):
        invocation, _ = self.prepare()
        with self.assertRaisesRegex(ValueError, 'actual generated bootstrap'):
            MODULE.validate_bootstrap(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', [])
        archive = self.reports / 'dotnet-sdk-9.0.121-linux-x64.tar.gz'; archive.write_bytes(b'tampered archive')
        with self.assertRaisesRegex(ValueError, 'bootstrap bytes changed'):
            MODULE.validate_bootstrap(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', [invocation])

    def test_untrusted_bootstrap_origin_is_rejected(self):
        profile = dict(target={'rid': 'linux-x64'}, upstreamInputs=dict(bootstrapSdk='9.0.121', bootstrapSdkFiles=bootstrap_files()))
        profile['upstreamInputs']['bootstrapSdkFiles']['x64']['url'] = 'https://example.com/dotnet-sdk.tar.gz'
        with self.assertRaisesRegex(ValueError, 'official SDK bootstrap'):
            MODULE.sdk_descriptor(profile, 'x64')

    def use(self, stage):
        receipt_dir = self.release / 'reports' / stage; receipt_dir.mkdir(exist_ok=True)
        invocation = ['/usr/bin/python3', '/delivery/reports/ci-inputs/project/scripts/upstream_vmr9.py', 'verify-bootstrap',
                      '--source-dir', str(self.source), '--profile', str(self.profile),
                      '--reports-dir', str(self.reports), '--arch', 'x64', '--stage', stage, '--receipt-dir', str(receipt_dir)]
        with mock.patch.object(MODULE.subprocess, 'check_output', return_value='9.0.121\n'):
            MODULE.verify_bootstrap_use(self.source, self.profile, self.reports, 'x64', stage, receipt_dir, invocation)
        return invocation

    def test_both_actual_build_and_test_must_preserve_root_host_and_sdk_assembly(self):
        self.prepare()
        commands = {stage: [self.use(stage)] for stage in ('build', 'test')}
        MODULE.validate_bootstrap_use(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', commands)
        commands['test'] = []
        with self.assertRaisesRegex(ValueError, 'actual post-test'):
            MODULE.validate_bootstrap_use(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', commands)

    def test_replaced_sdk_cli_assembly_never_receives_a_successful_use_receipt(self):
        self.prepare()
        (self.source / '.dotnet/sdk/9.0.121/dotnet.dll').write_bytes(b'replaced CLI assembly')
        with self.assertRaisesRegex(ValueError, 'replaced a pinned bootstrap'):
            self.use('build')
        self.assertFalse((self.release / 'reports/build/bootstrap-sdk-use.json').exists())

    def test_portable_bootstrap_use_proof_rejects_changed_fingerprints(self):
        self.prepare()
        commands = {stage: [self.use(stage)] for stage in ('build', 'test')}
        path = self.release / 'reports/test/bootstrap-sdk-use.json'; receipt = json.loads(path.read_text())
        receipt['rootFiles']['sdkAssembly']['sha256'] = 'f' * 64; path.write_bytes(encode(receipt))
        with self.assertRaisesRegex(ValueError, 'unchanged root bootstrap'):
            MODULE.validate_bootstrap_use(self.release, '9.0.121', MODULE.BASELINE_SOURCE, 'x64', commands)


if __name__ == '__main__':
    unittest.main()
