import base64
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('sdk5_only_tooling', ROOT / 'scripts/musl-legacy5-tooling.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)


class ProductGraph(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.source = self.root / 'sdk'; self.source.mkdir()
        self.inputs = {}; lines = []
        for index in range(56):
            path = ('src\\Product' if index < 25 else 'src\\Tests\\Test') + str(index) + '\\Project.csproj'
            name = PureWindowsPath(path).as_posix(); self.inputs[name] = b'<Project />\n'
            p = self.source / name; p.parent.mkdir(parents=True); p.write_bytes(self.inputs[name])
            lines.append('Project("{TYPE}") = "Project", "' + path + '", "{GUID' + str(index) + '}"')
        self.inputs['sdk.sln'] = ('\n'.join(lines) + '\n').encode(); (self.source / 'sdk.sln').write_bytes(self.inputs['sdk.sln'])
        self.mock = patch.object(T, 'git', side_effect=lambda source, action, query: self.inputs[query.split(':', 1)[1]])
        self.mock.start(); self.addCleanup(self.mock.stop)

    def test_external_filter_preserves_all_56_original_declarations(self):
        target = self.root / 'proof'; path = T.product_filter(self.source, target)
        data = json.loads(path.read_text()); proof = json.loads((target / 'origin.json').read_text())
        self.assertEqual(len(data['solution']['projects']), 25)
        self.assertEqual(len(proof['projects']), 56)
        self.assertEqual(sum(not p['included'] for p in proof['projects']), 31)
        self.assertFalse(proof['checkedInSourceBuildFilterClaimed'])
        self.assertEqual(proof['original68SmokeExclusions'], [])

    def test_derived_filter_inside_original_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            T.product_filter(self.source, self.source / 'made-up-source-filter')

    def test_modified_original_project_is_rejected(self):
        (self.source / next(iter(self.inputs))).write_bytes(b'<Project Sdk="other" />')
        with self.assertRaisesRegex(ValueError, 'original SDK5 project'):
            T.product_filter(self.source, self.root / 'proof')

    def test_incomplete_original_solution_matrix_is_rejected(self):
        self.inputs['sdk.sln'] = self.inputs['sdk.sln'].split(b'\n', 1)[1]
        (self.source / 'sdk.sln').write_bytes(self.inputs['sdk.sln'])
        with self.assertRaisesRegex(ValueError, 'complete original SDK5'):
            T.product_filter(self.source, self.root / 'proof')


class SourcePackages(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.feed = self.root / 'feed'; self.feed.mkdir()
        for name, version in T.VERSIONS.items(): self.package(name, version)

    def package(self, name, version):
        with zipfile.ZipFile(self.feed / (name + '.nupkg'), 'w') as archive:
            archive.writestr(name + '.nuspec', '<package><metadata><id>' + name + '</id><version>' + version + '</version></metadata></package>')

    def test_all_24_inputs_keep_compiler_derivation_separate(self):
        rows = T.feed_packages(self.feed)
        self.assertEqual(len(rows), 24)
        self.assertEqual(sum(r['role'] == 'matching-original-sdk-derived-compiler-input' for r in rows), 3)
        self.assertTrue(all(r['compilerLocallySourceBuiltClaimed'] is False for r in rows))

    def test_same_id_wrong_version_is_rejected(self):
        self.package('nuget.common', '5.9.0')
        with self.assertRaisesRegex(ValueError, 'package/version'):
            T.feed_packages(self.feed)

    def test_nested_original_compiler_nuspec_is_preserved_as_provenance(self):
        name = 'microsoft.fsharp.compiler'
        with zipfile.ZipFile(self.feed / (name + '.nupkg'), 'a') as archive:
            archive.writestr('cbodotnet-provenance/original-definitions/Microsoft.FSharp.Compiler.nuspec',
                             '<package><metadata><id>Original.Compiler.Definition</id></metadata></package>')
        rows = T.feed_packages(self.feed)
        self.assertEqual(len(rows), 24)
        self.assertEqual(next(r for r in rows if r['id'] == name)['version'], '11.3.2-beta.21102.9')

    def test_extra_own_source_package_cannot_silently_expand_the_closed_graph(self):
        with zipfile.ZipFile(self.feed / 'extra.nupkg', 'w') as archive:
            archive.writestr('extra.nuspec', '<package><metadata><id>NuGet.Common</id><version>5.9.1-rc.8</version></metadata></package>')
        with self.assertRaisesRegex(ValueError, 'Exactly24'):
            T.feed_packages(self.feed)

    def test_cache_requires_actual_local_source_and_raw_package_hash(self):
        rows = T.feed_packages(self.feed); source = self.root / 'sdk'; source.mkdir()
        for row in rows:
            directory = source / '.packages' / row['id'].lower() / row['version'].lower(); directory.mkdir(parents=True)
            name = row['id'].lower() + '.' + row['version'].lower() + '.nupkg'
            (directory / name).write_bytes((self.feed / row['file']).read_bytes())
            sha = base64.b64encode(bytes.fromhex(row['sha512'])).decode()
            (directory / (name + '.sha512')).write_text(sha)
            (directory / '.nupkg.metadata').write_text(json.dumps(dict(source=str(self.feed), contentHash=sha)))
        self.assertEqual(len(T.verify_cache(source, rows, self.feed)), 24)
        changed = source / '.packages' / rows[0]['id'].lower() / rows[0]['version'].lower() / '.nupkg.metadata'
        metadata = json.loads(changed.read_text()); metadata['source'] = 'https://api.nuget.org/v3/index.json'; changed.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'local-source cache provenance'):
            T.verify_cache(source, rows, self.feed)


class ExplicitAppFeed(unittest.TestCase):
    """Synthetic NPK/cache fixtures are not actual strong App source evidence."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.feed = self.root / 'feed'; self.feed.mkdir()
        self.M = T.appinsights_contract()
        for name, version in T.VERSIONS.items(): self.package(name + '.nupkg', name, version)
        self.app = self.feed / self.M.PACKAGE
        self.package(self.M.PACKAGE, self.M.ID, self.M.VERSION)

    def package(self, filename, identity, version):
        with zipfile.ZipFile(self.feed / filename, 'w') as archive:
            archive.writestr('package.nuspec', '<package><metadata><id>' + identity + '</id><version>' + version + '</version></metadata></package>')
            archive.writestr('fixture-only.bin', b'Not an App source/compile proof.\n')

    def commands(self, app=None, arch='aarch64'):
        return T.product_commands(self.root / 'bootstrap/dotnet', self.root / 'sdk', self.root / 'filter/source-build.slnf',
            self.root / 'output', arch, self.feed, self.root / 'translations', app)

    def report(self):
        return dict(kind='legacy-musl-sdk5-source-tooling', status='passed', sdkVersion=T.SDK,
            packages=T.feed_packages(self.feed, self.app), commands=[dict(name=name, command=list(map(str, command)), exitCode=0)
                for name, command in self.commands(self.app)], qualificationAllowed=False, sourceAdmissionAllowed=False)

    def cache(self, source, rows):
        source.mkdir()
        for row in rows:
            folder = source / '.packages' / row['id'].lower() / row['version'].lower(); folder.mkdir(parents=True)
            name = row['id'].lower() + '.' + row['version'].lower() + '.nupkg'
            (folder / name).write_bytes((self.feed / row['file']).read_bytes())
            digest = base64.b64encode(bytes.fromhex(row['sha512'])).decode()
            (folder / (name + '.sha512')).write_text(digest)
            (folder / '.nupkg.metadata').write_text(json.dumps(dict(source=str(self.feed), contentHash=digest)))

    def test_optional_cli_preserves_default_and_parses_explicit_package_path(self):
        args = ['--sdk', T.SDK, '--arch', 'aarch64']
        for name in ('workspace', 'dotnet', 'feed', 'translation-data', 'output'): args += ['--' + name, str(self.root / name)]
        self.assertIsNone(T.argument_parser().parse_args(args).appinsights_package)
        self.assertEqual(T.argument_parser().parse_args(args + ['--appinsights-package', str(self.app)]).appinsights_package, self.app)

    def test_default24_does_not_implicitly_accept_the_extra_app_package(self):
        with self.assertRaisesRegex(ValueError, 'package/version'):
            T.feed_packages(self.feed)
        self.app.unlink()
        with patch.object(T, 'appinsights_contract', side_effect=AssertionError('Default24 loaded the App contract')):
            self.assertEqual(len(T.feed_packages(self.feed)), 24)
            self.assertEqual(len(self.commands()), 3)
            value = dict(legacy='unchanged')
            self.assertIs(T.finalize_tooling_report(value, self.feed), value)

    def test_explicit25_closed_matrix_raw_input_and_distinct_unproven_app_role(self):
        rows = T.feed_packages(self.feed, self.app)
        self.assertEqual(len(rows), 25)
        self.assertEqual({row['id'].lower(): row['version'] for row in rows}, self.M.tooling_packages())
        app = next(row for row in rows if row['id'].lower() == self.M.ID.lower())
        self.assertEqual({key: app[key] for key in ('bytes', 'sha256', 'sha512')}, T.fingerprint(self.app))
        self.assertEqual(app['file'], self.M.PACKAGE)
        self.assertEqual(app['role'], 'local-App-product-requiring-external-strong-supplier-proof')
        self.assertTrue(app['externalStrongSupplierProofRequired'])
        self.assertFalse(app['externalStrongSupplierProofValidated'])
        self.assertFalse(app['compilerLocallySourceBuiltClaimed'])

    def test_duplicate_case_alias_ids_are_not_additional_feed_roles(self):
        self.package('alias.nupkg', 'NuGet.Common', T.VERSIONS['nuget.common'])
        with self.assertRaisesRegex(ValueError, 'Exactly25'):
            T.feed_packages(self.feed, self.app)

    def test_app_alias_package_cannot_replace_the_canonical_supplied_file(self):
        self.package('app-alias.NUPKG', self.M.ID.swapcase(), self.M.VERSION)
        with self.assertRaisesRegex(ValueError, 'provided canonical'):
            T.feed_packages(self.feed, self.app)

    def test_wrong_app_version_or_identity_cannot_use_the_canonical_filename(self):
        for identity, version in [(self.M.ID, '2.0.0'), ('NuGet.Common', '5.9.1-rc.8')]:
            with self.subTest(identity=identity, version=version):
                self.package(self.M.PACKAGE, identity, version)
                with self.assertRaisesRegex(ValueError, 'App package identity/version'):
                    T.feed_packages(self.feed, self.app)

    def test_missing_app_or_another_missing_required_feed_id_rejects(self):
        (self.feed / 'nuget.common.nupkg').unlink()
        with self.assertRaisesRegex(ValueError, 'Exactly25'):
            T.feed_packages(self.feed, self.app)
        self.app.unlink()
        with self.assertRaisesRegex(ValueError, 'ordinary canonical'):
            T.feed_packages(self.feed, self.app)

    def test_outside_relative_case_alias_and_directory_package_paths_reject(self):
        outside = self.root / self.M.PACKAGE; outside.write_bytes(self.app.read_bytes())
        for path in (outside, Path(self.M.PACKAGE), self.app.with_name(self.M.PACKAGE.upper())):
            with self.subTest(path=path), self.assertRaises(ValueError):
                T.appinsights_package_input(self.feed, path)
        self.app.unlink(); self.app.mkdir()
        with self.assertRaisesRegex(ValueError, 'ordinary canonical'):
            T.appinsights_package_input(self.feed, self.app)

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink and special-file semantics required')
    def test_symlink_fifo_and_special_permission_app_inputs_reject(self):
        raw = self.app.read_bytes(); self.app.unlink(); os.mkfifo(self.app)
        with self.assertRaisesRegex(ValueError, 'ordinary canonical'):
            T.appinsights_package_input(self.feed, self.app)
        self.app.unlink(); target = self.root / 'actual.nupkg'; target.write_bytes(raw); self.app.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'Ordinary absolute'):
            T.appinsights_package_input(self.feed, self.app)
        self.app.unlink(); self.app.write_bytes(raw); self.app.chmod(0o4644)
        with self.assertRaisesRegex(ValueError, 'ordinary canonical'):
            T.appinsights_package_input(self.feed, self.app)

    def test_exact_property_is_added_only_to_all_three_new_mode_product_commands(self):
        for arch in ('aarch64', 'x64'):
            default, current = self.commands(arch=arch), self.commands(self.app, arch)
            self.assertEqual([name for name, _ in current], ['original-product-restore', 'original-product-build', 'original-redist-build-pack'])
            for (old_name, old), (name, command) in zip(default, current):
                self.assertEqual(old_name, name)
                self.assertEqual(command.count(self.M.PROPERTY), 1)
                self.M.controlled_version_property(list(map(str, command)))
                self.assertEqual([value for value in command if value != self.M.PROPERTY], old)

    def test_duplicate_alias_compound_and_response_overrides_fail_final_binding(self):
        extras = [self.M.PROPERTY, '-p:MicrosoftApplicationInsightsPackageVersion=2.0.0',
            '/property:Other=x;MicrosoftApplicationInsightsPackageVersion=2.0.0', '@override.rsp']
        provided, _ = T.appinsights_package_input(self.feed, self.app)
        for extra in extras:
            report = self.report(); report['commands'][0]['command'].append(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                T.finalize_tooling_report(report, self.feed, self.app, provided)

    def test_cache_prime_project_downloads_all25_exact_versions_without_framework_restore(self):
        rows = T.feed_packages(self.feed, self.app); root = ET.fromstring(T.cache_prime_project(rows))
        self.assertEqual(root.findtext('PropertyGroup/DisableImplicitFrameworkReferences'), 'true')
        downloads = root.findall('ItemGroup/PackageDownload')
        self.assertEqual(len(downloads), 25)
        self.assertEqual({row.get('Include').lower(): row.get('Version') for row in downloads},
                         {name: '[' + version + ']' for name, version in self.M.tooling_packages().items()})

    def test_all25_cache_raw_hash_metadata_and_content_hash_are_checked(self):
        rows = T.feed_packages(self.feed, self.app)
        for index, changed in enumerate(('raw', 'metadata', 'sha512')):
            source = self.root / ('sdk' + str(index)); self.cache(source, rows)
            self.assertEqual(len(T.verify_cache(source, rows, self.feed)), 25)
            folder = source / '.packages' / self.M.ID.lower() / self.M.VERSION
            if changed == 'raw': (folder / self.M.PACKAGE).write_bytes(b'wrong package')
            elif changed == 'sha512': (folder / (self.M.PACKAGE + '.sha512')).write_text('unbound')
            else:
                path = folder / '.nupkg.metadata'; data = json.loads(path.read_bytes()); data['contentHash'] = 'unbound'; path.write_text(json.dumps(data))
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                T.verify_cache(source, rows, self.feed)

    def test_final_report_uses_existing_contract_with_actual_provided_three_fingerprints(self):
        report = self.report(); provided, _ = T.appinsights_package_input(self.feed, self.app)
        with patch.object(self.M, 'validate_tooling', wraps=self.M.validate_tooling) as bound:
            result = T.finalize_tooling_report(report, self.feed, self.app, provided)
        bound.assert_called_once_with(report, provided)
        self.assertEqual(result['appinsightsPackageInput'], provided)
        self.assertTrue(result['externalStrongAppSupplierProofRequired'])
        self.assertFalse(result['externalStrongAppSupplierProofValidated'])
        self.assertFalse(result['qualificationAllowed']); self.assertFalse(result['sourceAdmissionAllowed'])
        self.assertNotIn('sourceFeedMode', report)

    def test_provided_package_mutation_or_report_fingerprint_substitution_rejects(self):
        report = self.report(); provided, _ = T.appinsights_package_input(self.feed, self.app)
        app = next(row for row in report['packages'] if row['id'].lower() == self.M.ID.lower()); app['sha512'] = '0' * 128
        with self.assertRaisesRegex(ValueError, 'actual genuine source-built NPK'):
            T.finalize_tooling_report(report, self.feed, self.app, provided)
        report = self.report()
        with zipfile.ZipFile(self.app, 'a') as archive: archive.writestr('changed.bin', b'changed')
        with patch.object(self.M, 'validate_tooling', side_effect=AssertionError('Changed input reached final validation')):
            with self.assertRaisesRegex(ValueError, 'bytes changed during tooling'):
                T.finalize_tooling_report(report, self.feed, self.app, provided)


if __name__ == '__main__': unittest.main()
