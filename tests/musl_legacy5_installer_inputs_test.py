from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_installer_inputs as I


class InstallerOriginalSources(unittest.TestCase):
    def patch(self):
        return b'--- a/file.targets\n+++ b/file.targets\n@@ -1,3 +1,4 @@\n first\n+new hook\n second\n third\n'

    def test_exact_context_offset_reverses_to_original_bytes(self):
        actual = b'original prefix\nfirst\nnew hook\nsecond\nthird\n'
        self.assertEqual(I.reverse_exact_hunks(actual, self.patch(), 'file.targets'),
                         b'original prefix\nfirst\nsecond\nthird\n')

    def test_changed_or_ambiguous_hook_context_cannot_reverse(self):
        block = b'first\nnew hook\nsecond\nthird\n'
        for actual in (block.replace(b'new hook', b'forged hook'), block + block):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                I.reverse_exact_hunks(actual, self.patch(), 'file.targets')

    def test_unknown_patch_target_or_hunk_count_rejects(self):
        actual = b'first\nnew hook\nsecond\nthird\n'
        with self.assertRaises(ValueError): I.reverse_exact_hunks(actual, self.patch(), 'other.targets')
        with self.assertRaises(ValueError): I.reverse_exact_hunks(actual, self.patch().replace(b'+1,4', b'+1,5'), 'file.targets')

    def test_only_six_exact_patches_and_four_original_xml_targets_are_declared(self):
        targets = {target for sha, paths in I.PATCHES.values() for target in paths}
        self.assertEqual(len(I.PATCHES), 6)
        self.assertEqual(targets, {'src/redist/redist.csproj', 'src/redist/targets/Crossgen.targets',
            'src/redist/targets/GenerateLayout.targets', 'src/redist/targets/GenerateMSIs.targets'})
        self.assertFalse(any(name.lower().endswith('.cs') for name in targets))


if __name__ == '__main__': unittest.main()
