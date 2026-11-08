import base64
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
from unittest.mock import patch
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


if __name__ == '__main__': unittest.main()
