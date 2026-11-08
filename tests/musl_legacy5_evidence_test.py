"""SDK5 construction reports byte facts without granting missing source origins."""
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk5_construction_evidence_tested', ROOT / 'scripts/musl_legacy5_evidence.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class IndependentConstruction(unittest.TestCase):
    def test_another_sdk_cannot_enter_sdk5_emitter(self):
        with self.assertRaisesRegex(ValueError, 'Independent SDK5'):
            M.emit(dict(sdkVersion='6.0.136', architecture='aarch64'))

    def test_mount_is_exact_instead_of_silently_rewritten(self):
        for value in ['/source/../foreign', 'relative', '/source\\other', '/source\nother', '/']:
            with self.assertRaisesRegex(ValueError, 'Exact ordinary'): M.normalized(value)

    def test_missing_repository_metadata_stays_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); original = root/'original'; original.mkdir(); package = original/'input.nupkg'
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('input.nuspec', '<package><metadata><id>Example</id><version>1.0.0</version></metadata></package>')
                archive.writestr('lib/net5.0/data.txt', b'original data')
            fp = M.fingerprint(package)
            (root/'restored.json').write_text(json.dumps(dict(packages=[dict(retained='original/input.nupkg', **fp)])))
            release = root/'release'; release.mkdir()
            packages, index, descriptor = M.package_inputs(dict(restoredInputs=str(root/'restored.json')), release,
                dict(nuget=dict(kind='git', commit=M.COMMITS['nuget'])), {fp['sha256']}, {})
            actual = next(iter(packages.values()))
            self.assertIsNone(actual['repository']); self.assertIsNone(actual['sourceRoot']); self.assertIsNone(actual['sourceCommit'])
            self.assertIsNone(index[fp['sha256']][0]['member'])
            self.assertTrue((release/descriptor['path']).is_file())

    def test_changed_raw_restored_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); package = root/'input.nupkg'; package.write_bytes(b'changed raw package')
            wrong = dict(M.fingerprint(package), sha256='0' * 64)
            (root/'restored.json').write_text(json.dumps(dict(packages=[dict(retained='input.nupkg', **wrong)])))
            with self.assertRaisesRegex(ValueError, 'fingerprint differs'):
                M.package_inputs(dict(restoredInputs=str(root/'restored.json')), root/'release', {}, set(), {})

    def test_original_definition_payload_cannot_shadow_root_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'input.nupkg'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('Example.nuspec', '<package><metadata><id>ActualRoot</id></metadata></package>')
                archive.writestr('cbodotnet-provenance/original-definitions/Example.nuspec',
                                 '<package><metadata><id>HistoricalOriginal</id></metadata></package>')
            self.assertEqual(M.nuspec_metadata(path).findtext('{*}id'), 'ActualRoot')
            self.assertEqual(len(M.members(path, 'managed-package')), 2)

    def test_two_root_definitions_or_xml_entities_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'input.nupkg'
            with zipfile.ZipFile(path, 'w') as archive:
                for name in ['One.nuspec', 'Two.nuspec']:
                    archive.writestr(name, '<package><metadata /></package>')
            with self.assertRaisesRegex(ValueError, 'One bounded SDK5 root'): M.nuspec_metadata(path)
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('One.nuspec', '<!DOCTYPE package [<!ENTITY e "bad">]><package><metadata /></package>')
            with self.assertRaisesRegex(ValueError, 'Unsafe SDK5 root'): M.nuspec_metadata(path)

    def test_snapshot_preserves_only_declared_ordinary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'data'; source.write_bytes(b'actual output')
            descriptor = M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source})
            inventory = M.members(root/descriptor['path'], 'generated-installer-data')
            self.assertEqual(inventory['sdk/5.0.214/data.txt']['sha256'], M.fingerprint(source)['sha256'])
            self.assertEqual(M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source}), descriptor)
            source.write_bytes(b'different output')
            with self.assertRaisesRegex(ValueError, 'snapshot bytes or member set differ'):
                M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source})
            source.write_bytes(b'actual output')
            with self.assertRaisesRegex(ValueError, 'snapshot bytes or member set differ'):
                M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source, 'extra.txt': source})

    def test_retained_snapshot_rejects_truncation_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'data'; source.write_bytes(b'actual output')
            M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source})
            target = root/'retained.tar.gz'; original = target.read_bytes(); target.write_bytes(original[:20])
            with self.assertRaises((ValueError, EOFError, tarfile.TarError)):
                M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source})
            with tarfile.open(target, 'w:gz') as archive:
                info = tarfile.TarInfo('sdk/5.0.214/data.txt'); info.type = tarfile.SYMTYPE; info.linkname = 'outside'
                archive.addfile(info)
            with self.assertRaisesRegex(ValueError, 'Closed ordinary SDK5 snapshot'):
                M.snapshot(root, 'retained.tar.gz', {'sdk/5.0.214/data.txt': source})


class OriginalDataWrites(unittest.TestCase):
    def fixture(self, root):
        name = 'sdk/5.0.214/data.txt'; path = root/name; path.parent.mkdir(parents=True); path.write_bytes(b'actual data')
        fp = M.fingerprint(path); actual = {name: dict(bytes=fp['bytes'], sha256=fp['sha256'], signature=b'actual data'.hex())}
        mount = '/installer/artifacts/bin/redist/Release/dotnet'
        task = dict(taskName='WriteLinesToFile', succeeded=True, context='1:2:3:4', projectFile='/installer/src/redist/redist.csproj',
            taskFile='/installer/src/redist/targets/GenerateLayout.targets', events=[dict(kind='task-parameter', field='File', text=mount+'/'+name), dict(kind='task-finished', eventNumber=10)])
        context = dict(installerLayout=str(root), installerLayoutMount=mount)
        return name, actual, task, context

    def test_only_explicit_output_parameter_establishes_generated_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            name, actual, task, context = self.fixture(Path(tmp))
            answer = M.generated_outputs(actual, dict(sourceMountRoot='/installer'), {'x': task}, context, {})
            self.assertEqual(answer[name]['outputParameter'], 'File'); self.assertEqual(answer[name]['replayName'], 'installer')
            task['events'][0]['field'] = 'SourceFiles'
            self.assertEqual(M.generated_outputs(actual, dict(sourceMountRoot='/installer'), {'x': task}, context, {}), {})

    def test_generated_metadata_cannot_claim_a_managed_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, actual, task, context = self.fixture(Path(tmp)); next(iter(actual.values()))['signature'] = '4d5a0000'
            self.assertEqual(M.generated_outputs(actual, dict(sourceMountRoot='/installer'), {'x': task}, context, {}), {})

    def test_generated_data_must_equal_actual_final_sdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, actual, task, context = self.fixture(Path(tmp)); next(iter(actual.values()))['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'differs from final SDK'):
                M.generated_outputs(actual, dict(sourceMountRoot='/installer'), {'x': task}, context, {})


if __name__ == '__main__': unittest.main()
