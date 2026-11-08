import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_independent_admission_tests', ROOT / 'scripts/musl_legacy6_admission.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
P = M.module('sdk6_source_guard_test_primitives', 'package-used-source.py')
TOOLING = M.module('sdk6_source_guard_exact_hook', 'musl-legacy6-tooling.py')
RESTORE_HOOK = (b'  # Diagnostic redist builds do not execute these historical test frameworks.\n'
    b'  if [[ ${CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS:-} == true ]]; then\n'
    b'    return\n  fi\n\n')
LAYOUT_HOOK = TOOLING.TRANSLATION_HOOK.encode()


class SDK6FinalArchiveBindingTests(unittest.TestCase):
    def test_old_managed_archive_with_same_native_bytes_rejects_before_source_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); (release / 'reports').mkdir()
            archives = []
            for name, managed in [('older.tar.gz', b'old managed assembly'), ('final.tar.gz', b'new managed assembly')]:
                path = release / name
                with tarfile.open(path, 'w:gz') as archive:
                    for member, raw in [('sdk/6.0.136/CLI.dll', managed), ('shared/libcoreclr.so', b'identical native product')]:
                        entry = tarfile.TarInfo(member); entry.size = len(raw); archive.addfile(entry, io.BytesIO(raw))
                archives.append(dict(name=name, **M.fingerprint(path)))
            final = archives[1]; old = archives[0]
            record = dict(sdkVersion=M.SDK, architecture='aarch64', targetRid='linux-musl-arm64', sdk=final)
            proof = dict(schemaVersion=1, kind='sdk6-musl-construction-proof', sdkVersion=M.SDK,
                         architecture=record['architecture'], targetRid=record['targetRid'], unknowns=[], diagnosticOnly=False,
                         sdkArchive=dict(path=old['name'], **{key: old[key] for key in M.FP}))
            (release / 'reports/legacy-construction.json').write_text(json.dumps(proof))
            with mock.patch.object(M, 'roots_by_name', side_effect=AssertionError('Wrong archive reached source gates')):
                with self.assertRaisesRegex(ValueError, 'exact final SDK archive'):
                    M.validate_construction(release, record, {})
            proof['sdkArchive'] = dict(path=final['name'], **{key: final[key] for key in M.FP})
            self.assertEqual(M.validate_final_sdk_archive(record, proof), proof['sdkArchive'])
            for key, value in [('path', old['name']), ('bytes', final['bytes'] + 1), ('sha256', old['sha256']), ('sha512', old['sha512'])]:
                changed = copy.deepcopy(proof); changed['sdkArchive'][key] = value
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact final SDK archive'):
                    M.validate_final_sdk_archive(record, changed)

    def test_diagnostic_callers_also_need_an_explicit_actual_final_archive(self):
        with self.assertRaisesRegex(ValueError, 'explicit actual final'):
            M.validate_final_sdk_archive(dict(sdkVersion=M.SDK), dict(sdkArchive={}))


class SDK6OriginalToolingSourceTests(unittest.TestCase):
    """Rehashed captured files must still reconstruct the original Git tree."""

    def fixture(self):
        original = {
            'eng/restore-toolset.sh': b'#!/bin/bash\nfunction RestoreTools() {\n  # The following frameworks and tools are used only for testing.\n}\n',
            'src/Layout/redist/targets/GenerateLayout.targets': b'<Project>\n  <Target Name="Original" />\n</Project>\n',
            'src/Cli/Program.cs': b'class Program { static void Main() {} }\n',
            'original.sln': b'original solution\nsecond line\n',
        }
        baseline = {name: dict(mode='100644', blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
            for name, raw in original.items()}
        changed = dict(original)
        changed['eng/restore-toolset.sh'] = original['eng/restore-toolset.sh'].replace(
            b'  # The following frameworks', RESTORE_HOOK + b'  # The following frameworks')
        changed['src/Layout/redist/targets/GenerateLayout.targets'] = original['src/Layout/redist/targets/GenerateLayout.targets'].replace(
            b'</Project>\n', LAYOUT_HOOK + b'</Project>\n')
        # This is a working-copy line-ending change, not a changed original blob.
        changed['original.sln'] = original['original.sln'].replace(b'\n', b'\r\n')
        source = dict(commit=M.POLICY['sdk'], tree=P.baseline_tree(baseline), submodules=[])
        return changed, baseline, source

    def write(self, release, files, baseline):
        directory = release / 'sources'; directory.mkdir(exist_ok=True)
        rows = []
        with tarfile.open(directory / 'sources.tar.gz', 'w:gz') as archive:
            for name, raw in files.items():
                entry = tarfile.TarInfo('sdk/' + name); entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
                rows.append(dict(path=entry.name, mode='100644', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                    sha512=hashlib.sha512(raw).hexdigest(), baseline=baseline[name]))
        (directory / 'source-index.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return dict(index=dict(path='source-index.jsonl'), archive=dict(path='sources.tar.gz'))

    def test_original_tree_with_exact_two_hooks_and_declared_working_eol_passes(self):
        files, baseline, source = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); manifest = self.write(release, files, baseline)
            result = M.validate_sdk_sources(release, manifest, dict(sdk=source))
        self.assertEqual(result['sourceFiles'], 4)
        self.assertEqual(len(result['declaredHooks']), 2)
        self.assertFalse(result['productCSharpChanged'])
        self.assertFalse(result['manualHostTaskPruningApplied'])

    def test_rehashed_product_source_and_removed_original_source_are_rejected(self):
        for mode in ('changed-code', 'removed-source'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                files, baseline, source = self.fixture()
                if mode == 'changed-code': files['src/Cli/Program.cs'] += b'class Injected {}\n'
                else: del files['src/Cli/Program.cs']
                release = Path(temporary); manifest = self.write(release, files, baseline)
                with self.assertRaisesRegex(ValueError, 'undeclared SDK6 tooling|Full original SDK6 tooling tree'):
                    M.validate_sdk_sources(release, manifest, dict(sdk=source))

    def test_duplicate_moved_or_extended_declared_hooks_are_rejected_after_rehash(self):
        for mode in ('duplicate', 'moved-layout', 'extended-restore'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                files, baseline, source = self.fixture()
                layout = 'src/Layout/redist/targets/GenerateLayout.targets'
                if mode == 'duplicate': files[layout] = files[layout].replace(LAYOUT_HOOK, LAYOUT_HOOK * 2)
                elif mode == 'moved-layout': files[layout] = files[layout].replace(LAYOUT_HOOK, b'').replace(b'<Project>\n', b'<Project>\n' + LAYOUT_HOOK)
                else: files['eng/restore-toolset.sh'] = files['eng/restore-toolset.sh'].replace(RESTORE_HOOK, RESTORE_HOOK + b'  return\n')
                release = Path(temporary); manifest = self.write(release, files, baseline)
                with self.assertRaisesRegex(ValueError, 'declared SDK6 build/layout hook|final original project target|only the original test-runtime'):
                    M.validate_sdk_sources(release, manifest, dict(sdk=source))


class SDK6NormalAdmissionEntryTests(unittest.TestCase):
    def normal_record(self):
        return dict(schemaVersion=2, producerRevision=1, kind='musl-sdk-producer-validation', status='passed',
            sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64', libc='musl',
            diagnosticPodman=False, diagnosticPtrace=False, qualificationAllowed=False, sourceAdmissionAllowed=False,
            releaseAvailabilityAllowed=False, allRequiredStages=list(M.BOUNDARY.STAGES), sourceCommit=M.POLICY['installer'],
            sdkSourceCommit=M.POLICY['sdk'], runtimeSourceCommit=M.POLICY['runtimeCommit'], projectCommit='a' * 40,
            buildId='20261109.1', runId='917', runAttempt='1')

    def test_outer_entry_rejects_wrong_native_source_run_and_stage_identity(self):
        base = self.normal_record()
        changes = dict(sdkVersion='7.0.120', architecture='x64', libc='glibc', sourceCommit='0' * 40,
            sdkSourceCommit='0' * 40, runtimeSourceCommit='0' * 40, projectCommit='main', buildId='latest',
            runId='0', runAttempt='-1', allRequiredStages=list(M.BOUNDARY.STAGES)[:-1])
        for key,value in changes.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                record = dict(base, **{key:value}); release = Path(temporary)
                (release / 'producer-validation.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError): M.validate(release)

    def test_outer_entry_binds_all_retained_delivery_bytes_before_source_claims(self):
        for mode in ('changed-bound-bytes', 'unbound-file', 'missing-file', 'unsafe-path'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                release = Path(temporary); path = release / 'retained.txt'; path.write_bytes(b'original retained report')
                record = self.normal_record(); record['files'] = [dict(path='retained.txt', **M.fingerprint(path))]
                if mode == 'changed-bound-bytes': path.write_bytes(b'changed report')
                elif mode == 'unbound-file': (release / 'injected.txt').write_bytes(b'not retained')
                elif mode == 'missing-file': path.unlink()
                else: record['files'][0]['path'] = '../retained.txt'
                (release / 'producer-validation.json').write_text(json.dumps(record))
                with self.assertRaises(ValueError): M.validate(release)

    def test_unresolved_construction_is_rejected_even_for_diagnostic_prefix_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); (release / 'reports').mkdir()
            proof = dict(schemaVersion=1, kind='sdk6-musl-construction-proof', sdkVersion='6.0.136',
                architecture='aarch64', targetRid='linux-musl-arm64', diagnosticOnly=True,
                unknowns=[dict(kind='unmapped-managed-source',path='sdk/6.0.136/dotnet.dll')])
            (release / 'reports/legacy-construction.json').write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, 'Unresolved or diagnostic'):
                M.validate_construction(release, self.normal_record(), {}, allow_diagnostic=True)

    def tooling_fixture(self, release):
        image = 'sha256:' + '1' * 64
        record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64')
        inner = ['./build.sh', '--configuration', 'Release', '--pack', '--projects', '/source/source-build.slnf',
            '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true', '/p:Architecture=arm64',
            '/p:OSName=linux-musl', '/p:Rid=linux-musl-arm64', '/p:PortableBuild=true', '/p:CrossBuild=false',
            '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true', '/m:2',
            '/bl:/source/artifacts/log/Release/community-sdk-producer-source-graph.binlog', '--rebuild',
            '/p:CommunityMuslNuGetTranslationRoot=/nuget-translation-data/resources', '/p:MicrosoftNETTestSdkPackageVersion=17.0.3-dev',
            '/p:MicrosoftTestPlatformCLIPackageVersion=17.0.3-dev', '/p:MicrosoftTestPlatformBuildPackageVersion=17.0.3-dev',
            '/p:MicrosoftBuildLocalizationPackageVersion=17.0.4-cbodotnet.1', '/p:RestoreAdditionalProjectSources=/bootstrap-feed']
        environment = dict(HOME='/tmp', DOTNET_ROOT='/source/.dotnet', DOTNET_INSTALL_DIR='/source/.dotnet',
            DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', NUGET_PACKAGES='/source/.packages',
            CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS='true', DOTNET_PROCESSOR_COUNT='2', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1')
        mounts = ['/build/work/sdk-build/sdk:/source', '/build/inputs/bootstrap-feed:/bootstrap-feed:ro',
            '/delivery/reports/build/nuget-translation-data:/nuget-translation-data:ro', '/checkout:/project:ro',
            '/delivery:/delivery', '/delivery/reports/diagnostics/container-0001:/diag']
        call = M.B.P.DOCKER_ENGINE + ['run', '--network=host',
            *[value for key,data in environment.items() for value in ('--env', key + '=' + data)],
            *[value for mount in mounts for value in ('--volume', mount)], image.removeprefix('sha256:'),
            *M.B.P.Producer.observed_command(inner)]
        directory = release / 'reports/build/sdk-tooling'; directory.mkdir(parents=True)
        (directory / 'image.json').write_text(json.dumps([dict(Id=image, Architecture='arm64', Os='linux')]))
        invocation = dict(command=call, diagnosticEngine='normal-rootful-docker', cpu='aarch64', network='host',
            qualificationAllowed=False, sourceAdmissionAllowed=False)
        roots = [dict(name=name, originalPath=path) for name,path in [('sdk', '/build/work/sdk-build/sdk'),
            ('orchestration', '/checkout'), ('actual-managed-package-inputs', '/delivery/imported-inputs'),
            ('nuget-translation-data', '/delivery/reports/build/nuget-translation-data')]]
        return directory, record, dict(imageId=image), invocation, dict(roots=roots)

    def test_tooling_envelope_rejects_wrong_image_source_graph_alias_mount_and_runtime_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); directory, record, prepare, invocation, manifest = self.tooling_fixture(release)
            def check(candidate):
                (directory / 'invocation.json').write_text(json.dumps(candidate))
                M.validate_tooling_boundary(release, record, prepare, dict(build=dict(commands=[candidate['command']])), manifest)
            check(invocation)
            cases = []
            for old,new in [('1' * 64, '2' * 64), ('/build/work/sdk-build/sdk:/source', '/other:/source'),
                ('/source/source-build.slnf', '/source/src/Layout/redist/redist.csproj'),
                ('DOTNET_ROOT=/source/.dotnet', 'DOTNET_ROOT=/host'), ('/p:DotNetBuildFromSource=true', '/p:DotNetBuildFromSource=false')]:
                changed = copy.deepcopy(invocation); call = changed['command']; call[call.index(old)] = new; cases.append(changed)
            for alias in (['-v', '/hidden:/source/src'], ['--volume=/hidden:/source/src'], ['-eCOMPlus_ReadyToRun=0']):
                changed = copy.deepcopy(invocation); call = changed['command']; index = call.index('1' * 64)
                call[index:index] = alias; cases.append(changed)
            changed = copy.deepcopy(invocation); changed['diagnosticEngine'] = 'private-rootful-podman'; cases.append(changed)
            for changed in cases:
                with self.subTest(command=changed['command'][-4:]), self.assertRaises(ValueError): check(changed)

    def test_diagnostic_construction_cannot_be_used_as_normal_producer_evidence(self):
        proof = dict(schemaVersion=1, kind='sdk6-musl-construction-proof', sdkVersion='6.0.136',
            architecture='aarch64', targetRid='linux-musl-arm64', unknowns=[], diagnosticOnly=True)
        record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64')
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); (release / 'reports').mkdir()
            (release / 'reports/legacy-construction.json').write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, 'diagnostic SDK6 construction cannot seal'):
                M.validate_construction(release, record, {})

    def test_normal_entry_rejects_diagnostics_or_premature_qualification(self):
        base = dict(schemaVersion=2, producerRevision=1, kind='musl-sdk-producer-validation', status='passed',
            sdkVersion='6.0.136', diagnosticPodman=False, diagnosticPtrace=False, qualificationAllowed=False,
            sourceAdmissionAllowed=False, releaseAvailabilityAllowed=False)
        for key in ('diagnosticPodman', 'diagnosticPtrace', 'qualificationAllowed', 'sourceAdmissionAllowed', 'releaseAvailabilityAllowed'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                record = copy.deepcopy(base); record[key] = True
                release = Path(temporary); (release / 'producer-validation.json').write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'non-diagnostic SDK6 normal producer'):
                    M.validate(release)


class SDK6InstallerOriginalTreeTests(unittest.TestCase):
    def fixture(self):
        patches = {name: (ROOT / name).read_bytes() for name in M.INSTALLER_PATCHES}
        def hunk(raw, signs):
            return b''.join(line[1:] for line in raw.splitlines(True)[3:] if line[:1] in signs)
        first, native, metadata = list(patches.values())
        original = b'<Project>\n' + hunk(metadata, (b' ', b'-')) + b'\n' + hunk(first, (b' ', b'-'))
        original += b'    <ItemGroup>\n      <BundledLayoutComponent>\n</Project>\n'
        changed = original
        for patch in patches.values():
            before, after = hunk(patch, (b' ', b'-')), hunk(patch, (b' ', b'+'))
            self.assertEqual(changed.count(before), 1); changed = changed.replace(before, after)
        target = 'src/redist/targets/GenerateLayout.targets'
        pristine = {target: original, 'src/tasks/Program.cs': b'class Original {}\n',
            'src/redist/targets/Crossgen.targets': b'<Project><Target Name="OriginalCrossgen" /></Project>\n'}
        baseline = {name: dict(mode='100644', blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()) for name, raw in pristine.items()}
        indexed = {name: dict(path='installer/' + name, mode='100644', baseline=baseline[name]) for name in baseline}
        source = dict(commit=M.POLICY['installer'], tree=P.baseline_tree(baseline), submodules=[], deleted=[], exclude=[])
        return dict(pristine, **{target: changed}), indexed, source, patches

    def test_exact_three_reviewed_patches_recover_every_original_installer_blob(self):
        files, index, source, patches = self.fixture()
        result = M.validate_installer_tree(files, index, source, patches)
        self.assertEqual(result['sourceFiles'], 3); self.assertEqual(len(result['reviewedPatches']), 3)

    def test_rehashed_code_crossgen_new_hook_deleted_source_and_changed_patch_reject(self):
        for mode in ('C#', 'crossgen', 'hook', 'deleted', 'excluded', 'patch'):
            files, index, source, patches = self.fixture()
            if mode == 'C#': files['src/tasks/Program.cs'] += b'class Injected {}\n'
            elif mode == 'crossgen': files['src/redist/targets/Crossgen.targets'] += b'<Target Name="Injected" />\n'
            elif mode == 'hook': files['src/redist/targets/GenerateLayout.targets'] += b'<Target Name="Injected" />\n'
            elif mode == 'deleted': del files['src/tasks/Program.cs']; del index['src/tasks/Program.cs']
            elif mode == 'excluded': source['exclude'] = ['src/tasks']
            else: patches[next(iter(patches))] += b'\n'
            with self.subTest(mode=mode), self.assertRaises(ValueError): M.validate_installer_tree(files, index, source, patches)


class SDK6ClosedArtifactRoleTests(unittest.TestCase):
    def fixture(self):
        roles = {'toolset': ('sdk-toolset', 'sdk'), 'runtime': ('official-runtime', 'runtime'),
            'aspnet': ('official-aspnet', 'aspnetcore'), 'original-sdk-comparison': ('official-sdk-comparison', 'installer'),
            'post-crossgen': ('post-crossgen-sdk', 'installer'), 'generated': ('generated-installer-data', 'installer'),
            'translations': ('nuget-translation-data', 'nuget')}
        roles.update({'native-' + n: ('native-coreclr', 'runtime') for n in M.NATIVE})
        roots = {n: dict(kind='git', commit=M.POLICY['runtimeCommit' if n == 'runtime' else n]) for _, n in roles.values()}
        artifacts = {name: dict(path='reports/construction-inputs/' + name, kind=kind, sourceRoot=source,
            sourceCommit=roots[source]['commit'], bytes=1, sha256='1' * 64, sha512='2' * 128) for name, (kind, source) in roles.items()}
        for name in ('runtime', 'aspnet'): artifacts[name]['sha512'] = M.FRAMEWORK_SHA512[(artifacts[name]['kind'], 'aarch64')]
        artifacts['original-sdk-comparison']['sha512'] = M.T.COMPARISON_SHA512['aarch64']
        for name in M.NATIVE: artifacts['native-' + name]['path'] = 'reports/build/native-runtime/' + name
        return artifacts, roots, dict(architecture='aarch64')

    def test_named_roles_reject_kind_flip_missing_duplicate_unknown_and_wrong_source(self):
        artifacts, roots, record = self.fixture(); M.validate_artifact_roles(artifacts, roots, {}, record)
        for mode in ('kind-flip', 'missing', 'alias', 'unknown', 'wrong-source', 'framework-hash'):
            changed = copy.deepcopy(artifacts)
            if mode == 'kind-flip': changed['runtime']['kind'] = 'generated-installer-data'
            elif mode == 'missing': del changed['aspnet']
            elif mode == 'alias': changed['second-runtime'] = dict(changed['runtime'])
            elif mode == 'unknown': changed['mystery'] = dict(changed['runtime'], path='unknown')
            elif mode == 'wrong-source': changed['runtime'].update(sourceRoot='installer', sourceCommit=M.POLICY['installer'])
            else: changed['runtime']['sha512'] = '0' * 128
            with self.subTest(mode=mode), self.assertRaises(ValueError): M.validate_artifact_roles(changed, roots, {}, record)

    def test_shared_managed_file_cannot_bypass_sdk_prefix_checks_through_generated_or_package_role(self):
        name = 'shared/Microsoft.NETCore.App/6.0.36/System.Private.CoreLib.dll'
        actual = {name: dict(bytes=5, sha256='1' * 64, signature='4d5a')}
        for role in ('runtime', 'generated', 'package-' + '2' * 64):
            proof = dict(layout=[dict(path=name, input=role, member=name)])
            inventory = {role: {name: actual[name]}}
            if role == 'runtime': M.validate_layout(proof, actual, inventory)
            else:
                with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'shared SDK6 framework'): M.validate_layout(proof, actual, inventory)

    def test_toolset_requires_actual_sdk_compiler_package_full_fingerprint(self):
        artifacts, _, _ = self.fixture(); package = {k: artifacts['toolset'][k] for k in M.FP}
        M.validate_toolset_binding(artifacts, dict(sdk=dict(proof=dict(packages=[package]))))
        for key in M.FP:
            changed = dict(package, **{key: 2 if key == 'bytes' else '0' * len(package[key])})
            with self.subTest(key=key), self.assertRaises(ValueError): M.validate_toolset_binding(artifacts, dict(sdk=dict(proof=dict(packages=[changed]))))

    def test_snapshot_inventory_and_layout_must_close_over_validated_task_outputs(self):
        transformed = {'sdk/6.0.136/CLI.dll': {}}; generated = {'sdk/6.0.136/.version': {}}
        inventories = {'post-crossgen': dict(transformed), 'generated': dict(generated)}
        layout = [dict(path=name, member=name, input=role) for role, outputs in [('post-crossgen', transformed), ('generated', generated)] for name in outputs]
        M.validate_snapshot_coverage(layout, inventories, transformed, generated)
        for mode in ('extra-generated', 'extra-crossgen', 'missing-crossgen-task', 'missing-generated-task', 'wrong-layout-member', 'unconsumed-crossgen'):
            inv = copy.deepcopy(inventories); rows = copy.deepcopy(layout); trans = dict(transformed); gen = dict(generated)
            if mode == 'extra-generated': inv['generated']['injected.dll'] = {}
            elif mode == 'extra-crossgen': inv['post-crossgen']['injected.dll'] = {}
            elif mode == 'missing-crossgen-task': trans.clear()
            elif mode == 'missing-generated-task': gen.clear()
            elif mode == 'wrong-layout-member': rows[0]['member'] = 'wrong.dll'
            else: rows[0]['input'] = 'toolset'
            with self.subTest(mode=mode), self.assertRaises(ValueError): M.validate_snapshot_coverage(rows, inv, trans, gen)

    def test_package_artifact_cannot_claim_an_unrelated_git_source_or_basis(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); package = release / 'input.nupkg'; commit = 'a' * 40
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('Input.nuspec', '<package><metadata><id>Input</id><version>1.0</version><repository type="git" url="https://example.test/source" commit="' + commit + '" /></metadata></package>')
            row = dict(path=package.name, **M.fingerprint(package), kind='managed-package', sourceRoot='original', sourceCommit=commit, sourceBasis='original-package-repository')
            key = 'package-' + row['sha256']; M.validate_package_artifact_sources(release, {key: row}, {})
            for field, value in [('sourceCommit', 'b' * 40), ('sourceBasis', 'arbitrary-source-claim')]:
                with self.subTest(field=field), self.assertRaises(ValueError): M.validate_package_artifact_sources(release, {key: dict(row, **{field: value})}, {})


class SDK6ReaderAndInstallerEnvelopeTests(unittest.TestCase):
    def fixture(self):
        producer_module = M.module('sdk6_real_producer_envelope_test', 'musl_legacy_sdk6.py')
        producer = producer_module.Producer.__new__(producer_module.Producer)
        producer.engine = M.B.P.DOCKER_ENGINE; producer.uid = producer.gid = 1000
        producer.output = PurePosixPath('/delivery'); producer.workspace = PurePosixPath('/builder'); producer.home = PurePosixPath('/builder/home')
        producer.image = 'sha256:' + '1' * 64; producer.diagnostic = True
        producer.diagnostic_options = lambda: ['--volume', '/delivery/reports/diagnostics/container-0001:/diag',
            '--env', 'MSBUILDDEBUGPATH=/diag', '--env', 'MSBUILDDEBUGCOMM=1']
        commands = []; producer.run = lambda args, **kwargs: commands.append(args)
        record = dict(sdkVersion=M.SDK, architecture='aarch64', targetRid='linux-musl-arm64')
        manifest = dict(roots=[dict(name=name, originalPath=path) for name, path in [
            ('sdk', '/builder/work/sdk-build/sdk'), ('installer', '/builder/work/installer'),
            ('orchestration', '/checkout'), ('actual-managed-package-inputs', '/delivery/imported-inputs')]])
        return producer_module, producer, commands, record, manifest

    def test_actual_producer_installer_envelope_and_counterexamples(self):
        mod, producer, commands, record, manifest = self.fixture()
        environment = dict(DOTNET_ROOT='/work/work/installer/.dotnet', DOTNET_INSTALL_DIR='/work/work/installer/.dotnet',
            NUGET_PACKAGES='/work/work/installer/.packages')
        with mock.patch.object(mod.L, 'ROOT', PurePosixPath('/checkout')), mock.patch.object(mod.L.os, 'getuid', return_value=1000, create=True):
            producer.container(M.installer_command(record), environment=environment, workdir='/work/work/installer')
        call = commands[0]; prepare = dict(imageId=producer.image)
        def check(candidate): M.validate_installer_boundary(None, record, prepare, dict(build=dict(commands=[candidate])), manifest)
        check(call)
        changes = [('/p:UseSharedCompilation=false', '/p:UseSharedCompilation=true'), ('/m:2', '/m:8'),
            ('/p:DotNetBuildOffline=true', '/p:DotNetBuildOffline=false'), ('--network=host', '--network=none'),
            ('/builder:/work', '/other:/work'), ('/checkout:/project:ro', '/other:/project:ro'),
            ('DOTNET_ROOT=/work/work/installer/.dotnet', 'DOTNET_ROOT=/host'), (producer.image, 'sha256:' + '2' * 64)]
        for before, after in changes:
            changed = list(call); changed[changed.index(before)] = after
            with self.subTest(before=before), self.assertRaises(ValueError): check(changed)
        for extra in (['--volume', '/hidden:/work/work/installer/src'], ['--env', 'COMPlus_ReadyToRun=0'], ['--entrypoint', 'sh']):
            changed = list(call); position = changed.index(producer.image); changed[position:position] = extra
            with self.subTest(extra=extra), self.assertRaises(ValueError): check(changed)

    def test_copied_reader_sources_and_clear_only_config_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); directory = release / 'reports/build/reader'; directory.mkdir(parents=True)
            archived = {}
            for name in ('Program.cs', 'Reader.csproj'):
                raw = (ROOT / 'scripts/musl-legacy-reader' / name).read_bytes(); (directory / name).write_bytes(raw)
                archived['orchestration/scripts/musl-legacy-reader/' + name] = raw
            (directory / 'NuGet.Config').write_bytes(M.READER_CONFIG)
            M.validate_reader_sources(release, archived)
            for name in ('Program.cs', 'Reader.csproj', 'NuGet.Config'):
                path = directory / name; raw = path.read_bytes(); path.write_bytes(raw + b'\n<!-- unreviewed input -->\n')
                with self.subTest(name=name), self.assertRaises(ValueError): M.validate_reader_sources(release, archived)
                path.write_bytes(raw)
            (directory / 'Injected.cs').write_text('class Injected {}')
            with self.assertRaisesRegex(ValueError, 'two copied SDK6 Reader sources'): M.validate_reader_sources(release, archived)

    def test_each_actual_reader_status_and_task_stream_is_bound_to_the_consumed_proof_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); directory = release / 'reports/build'; directory.mkdir(parents=True)
            proof = dict(componentCompilerProofs={})
            def descriptor(path): return dict(path=path.relative_to(release).as_posix(), **M.fingerprint(path))
            for name in M.REPLAY_COMPONENTS:
                binlog = directory / (name + '.binlog'); binlog.write_bytes((name + ' actual binary log').encode())
                raw = directory / (name + '-replay-tasks.jsonl'); raw.write_bytes((name + ' actual Reader task events').encode())
                copied = directory / (name + '-tasks.jsonl'); copied.write_bytes(raw.read_bytes())
                status = dict(schemaVersion=1, completedReplay=True, buildSucceeded=True, unfinishedTasks=0,
                    unfinishedSelectedTasks=0, failure=None, completedSelectedTasks=3, inputSha256=M.fingerprint(binlog)['sha256'])
                (directory / (name + '-replay-status.json')).write_text(json.dumps(status))
                consumed = dict(completedReplay=True, buildSucceeded=True, unfinishedTasks=0, tasks=descriptor(copied))
                if name == 'installer': consumed['inputSha256'] = status['inputSha256']
                else: consumed['binlog'] = descriptor(binlog)
                path = directory / (name + '-proof.json'); path.write_text(json.dumps(consumed)); desc = descriptor(path)
                if name == 'installer': proof['installerBuildReplay'] = desc
                elif name == 'msbuild-localization': proof['localizationBuildReplay'] = desc
                else: proof['componentCompilerProofs'][name] = desc
            self.assertEqual(set(M.validate_replay_copies(release, proof)), set(M.REPLAY_COMPONENTS))
            for name in M.REPLAY_COMPONENTS:
                for suffix in ('-replay-tasks.jsonl', '-tasks.jsonl', '.binlog'):
                    path = directory / (name + suffix); raw = path.read_bytes(); path.write_bytes(raw + b'injected')
                    with self.subTest(name=name, suffix=suffix), self.assertRaises(ValueError): M.validate_replay_copies(release, proof)
                    path.write_bytes(raw)
                path = directory / (name + '-replay-status.json'); raw = path.read_bytes(); status = json.loads(raw); status['unfinishedSelectedTasks'] = 1
                path.write_text(json.dumps(status))
                with self.subTest(name=name, status='unfinished'), self.assertRaises(ValueError): M.validate_replay_copies(release, proof)
                path.write_bytes(raw)

    def test_reader_requires_exact_build_and_all_five_replay_envelopes(self):
        mod, producer, commands, record, manifest = self.fixture()
        bootstrap = '/work/work/sdk-build/sdk/.dotnet'; sdk = bootstrap + '/sdk/6.0.135'
        inners = [[bootstrap + '/dotnet', 'build', '/delivery/reports/build/reader/Reader.csproj', '--configuration', 'Release',
            '/p:BootstrapMajor=6', '/p:BootstrapSdkDir=' + sdk, '/p:UseSharedCompilation=false']]
        inners += [[bootstrap + '/dotnet', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll',
            '/delivery/reports/build/' + name + '.binlog', sdk, '/delivery/reports/build/' + name + '-replay'] for name in M.REPLAY_COMPONENTS]
        with mock.patch.object(mod.L, 'ROOT', PurePosixPath('/checkout')), mock.patch.object(mod.L.os, 'getuid', return_value=1000, create=True):
            for inner in inners: producer.container(inner, environment=dict(DOTNET_ROOT=bootstrap))
        with mock.patch.object(M, 'source_archive_members', return_value=({}, {})), mock.patch.object(M, 'validate_reader_sources'), \
                mock.patch.object(M, 'validate_replay_copies', return_value={}), mock.patch.object(M, 'load', return_value={}):
            def check(calls): M.validate_reader_boundary(Path('/delivery'), record, dict(imageId=producer.image), dict(build=dict(commands=calls)), manifest)
            check(commands)
            for index in range(6):
                with self.subTest(missing=index), self.assertRaises(ValueError): check(commands[:index] + commands[index + 1:])
            for old, new in [(sdk, '/work/work/sdk-build/sdk/.dotnet/sdk/7.0.119'), ('--network=host', '--network=none'),
                ('DOTNET_ROOT=' + bootstrap, 'DOTNET_ROOT=/host'), ('/builder:/work', '/hidden:/work')]:
                changed = copy.deepcopy(commands); changed[1][changed[1].index(old)] = new
                with self.subTest(old=old), self.assertRaises(ValueError): check(changed)


if __name__ == '__main__': unittest.main()
