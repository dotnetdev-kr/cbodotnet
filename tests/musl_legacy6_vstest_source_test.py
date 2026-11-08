import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vstest6_source_contract', ROOT / 'scripts/musl_legacy6_vstest_source.py')
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)


class OriginalTargets(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        for index in range(18):
            base = root / 'src' / ('Project' + str(index)) / 'Resources'
            (base / 'xlf').mkdir(parents=True)
            (base / 'Strings.resx').write_bytes(b'<root><data name="key"><value>English</value></data></root>')
            for culture in sorted(V.XLF.CULTURES):
                xml = ('<xliff xmlns="urn:oasis:names:tc:xliff:document:1.2"><file target-language="' + culture
                       + '"><body><trans-unit id="key"><source>English</source><target>translated-'
                       + culture + '-' + str(index) + '</target></trans-unit></body></file></xliff>')
                (base / 'xlf' / ('Strings.' + culture + '.xlf')).write_bytes(xml.encode())
        self.originals = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        self.receipt = V.XLF.generate(root, root / 'receipt.json', V.COMMIT)
        self.generated = {row['generated']: (root / row['generated']).read_bytes() for row in self.receipt['rows']}

    def test_all_234_original_targets_recreate_exact_readable_compiler_sources(self):
        self.assertEqual(V.regenerate(self.originals, self.receipt, self.generated), self.receipt)

    def test_self_consistent_english_fallback_cannot_replace_original_target(self):
        generated = dict(self.generated); name = next(iter(generated))
        generated[name] = generated[name].replace(b'translated-cs-0', b'English')
        receipt = copy.deepcopy(self.receipt)
        receipt['rows'][0]['generatedSha256'] = V.hashlib.sha256(generated[name]).hexdigest()
        with self.assertRaisesRegex(ValueError, 'original XLF targets'):
            V.regenerate(self.originals, receipt, generated)

    def test_one_changed_generated_string_is_rejected(self):
        generated = dict(self.generated); name = next(iter(generated)); generated[name] += b' '
        with self.assertRaisesRegex(ValueError, 'generated RESX bytes'):
            V.regenerate(self.originals, self.receipt, generated)

    def test_missing_one_original_translation_is_rejected(self):
        original = dict(self.originals); del original[next(name for name in original if name.endswith('.xlf'))]
        with self.assertRaisesRegex(ValueError, 'original XLF targets'):
            V.regenerate(original, self.receipt, self.generated)

    def test_dtd_in_original_translation_is_rejected(self):
        original = dict(self.originals); name = next(n for n in original if n.endswith('.xlf'))
        original[name] = b'<!DOCTYPE xliff [<!ENTITY injected "English">]>' + original[name]
        with self.assertRaisesRegex(ValueError, 'document types or entities'):
            V.regenerate(original, self.receipt, self.generated)


class StagedPackaging(unittest.TestCase):
    def test_only_exact_staged_nuspec_tfm_and_original_version_tokens_change(self):
        originals = {}
        for name, tfm in [('CLI', 'netcoreapp2.1'), ('Build', 'netstandard2.0')]:
            originals['src/package/nuspec/TestPlatform.' + name + '.nuspec'] = (
                '<package><version>15.0.0</version><file target="' + tfm + '" /></package>').encode()
            originals['src/package/nuspec/Microsoft.TestPlatform.' + name + '.csproj'] = (
                b'<Project><NuspecProperties>version=$(Version)</NuspecProperties></Project>')
        before = dict(originals); result = V.adaptations(originals)
        self.assertEqual(originals, before)
        self.assertEqual(len(result['files']), 4)
        self.assertIs(result['originalGitSourceChanged'], False)
        self.assertIs(result['csharpSourcesRetargeted'], False)
        originals['src/package/nuspec/TestPlatform.CLI.nuspec'] = b'<version>17.0.3-dev</version>'
        with self.assertRaisesRegex(ValueError, 'Original SDK6 staged nuspec'):
            V.adaptations(originals)


if __name__ == '__main__': unittest.main()
