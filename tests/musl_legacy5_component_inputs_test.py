from pathlib import Path
import sys
import tarfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_component_inputs as C


class ExactComponentSources(unittest.TestCase):
    def test_only_reviewed_patched_nuget_xml_can_recover_original_uniform_checkout_encoding(self):
        name = C.PATCHES['nuget'][2]; original = b'<Project>\noriginal declaration\n</Project>\n'
        self.assertEqual(C.patched_project_text('nuget', name, original.replace(b'\n', b'\r\n')), original)
        for component, target, raw in [('sdk', name, original.replace(b'\n', b'\r\n')),
            ('nuget', 'src/implementation.cs', original.replace(b'\n', b'\r\n')),
            ('nuget', name, b'<Project>\r\noriginal declaration\n</Project>\r\n')]:
            with self.subTest(component=component,target=target),self.assertRaises(ValueError):C.patched_project_text(component,target,raw)

    def test_only_exact_product_runtime_hook_recovers_original_source(self):
        original = b'before\n' + C.RESTORE_MARKER + b'after\n'
        actual = original.replace(C.RESTORE_MARKER, C.RESTORE_HOOK + C.RESTORE_MARKER)
        self.assertEqual(C.reverse_sdk_hooks('eng/restore-toolset.sh', actual), original)
        with self.assertRaises(ValueError): C.reverse_sdk_hooks('eng/restore-toolset.sh', actual.replace(b'    return', b'    arbitrary'))
        with self.assertRaises(ValueError): C.reverse_sdk_hooks('eng/restore-toolset.sh', actual + C.RESTORE_HOOK + C.RESTORE_MARKER)

    def test_translation_hook_is_exact_and_only_at_original_project_terminator(self):
        original = b'<Project>original targets\n</Project>\n'
        actual = original[:-len(b'</Project>\n')] + C.TRANSLATION_HOOK + b'</Project>\n'
        name = 'src/Layout/redist/targets/GenerateLayout.targets'
        self.assertEqual(C.reverse_sdk_hooks(name, actual), original)
        for changed in (actual.replace(b'PublishTestCli', b'Build'), actual + b'new hook', actual + C.TRANSLATION_HOOK):
            with self.assertRaises(ValueError): C.reverse_sdk_hooks(name, changed)

    def test_nuget_driver_preserves_original_unconditional_xplat_selection(self):
        projects = {'src/Core/True/True.csproj': b'<Project><PropertyGroup><XPLATProject>true</XPLATProject></PropertyGroup></Project>',
                    'src/Core/False/False.csproj': b'<Project><PropertyGroup><XPLATProject>false</XPLATProject></PropertyGroup></Project>',
                    'src/Core/Absent/Absent.csproj': b'<Project />'}
        raw, selected = C.nuget_driver(projects)
        self.assertEqual(selected, ['src/Core/True/True.csproj'])
        document = ET.fromstring(raw)
        self.assertEqual(document.find('Import').get('Project'), '$(MSBuildThisFileDirectory)build.proj')
        self.assertEqual(document.find('Target/ItemGroup/XPLATProjects').get('Include'), '$(MSBuildThisFileDirectory)../src/Core/True/True.csproj')

    def test_changed_conditional_xplat_or_arbitrary_driver_candidates_reject(self):
        for name, raw in [('src/Core/Test/Test.csproj', b'<Project><PropertyGroup Condition="true"><XPLATProject>true</XPLATProject></PropertyGroup></Project>'),
                          ('src/Test.csproj', b'<Project />')]:
            with self.subTest(name=name), self.assertRaises(ValueError): C.nuget_driver({name: raw})



class OriginalSourceModes(unittest.TestCase):
    def fixture(self, original='100644', mode='100644', tar_mode=0o644, kind=tarfile.REGTYPE):
        raw = b'unchanged original source bytes\n'
        row = dict(mode=mode, baseline=dict(mode=original, blob=C.original_blob(raw)))
        entry = tarfile.TarInfo('sdk/original.cs'); entry.type = kind; entry.mode = tar_mode
        return row, entry, raw

    def test_genuine_regular_and_executable_originals_retain_exact_modes(self):
        for mode, permissions in [('100644', 0o644), ('100755', 0o755)]:
            row, entry, _ = self.fixture(mode, mode, permissions)
            with self.subTest(mode=mode): self.assertTrue(C.original_source_mode(row, entry))

    def test_self_consistent_executable_bit_change_rejects_unchanged_source_blob(self):
        row, entry, raw = self.fixture(mode='100755', tar_mode=0o755)
        self.assertEqual(C.original_blob(raw), row['baseline']['blob'])
        self.assertFalse(C.original_source_mode(row, entry))

    def test_tar_mode_change_cannot_hide_behind_original_index_mode(self):
        row, entry, _ = self.fixture(tar_mode=0o755)
        self.assertFalse(C.original_source_mode(row, entry))

    def test_index_or_tar_kind_substitution_rejected(self):
        for mode, kind in [('120000', tarfile.SYMTYPE), ('100644', tarfile.SYMTYPE)]:
            row, entry, _ = self.fixture(mode=mode, tar_mode=0o777, kind=kind)
            with self.subTest(mode=mode): self.assertFalse(C.original_source_mode(row, entry))

    def test_original_git_symlink_retains_kind_and_original_archive_permissions(self):
        row, entry, _ = self.fixture('120000', '120000', 0o777, tarfile.SYMTYPE)
        self.assertTrue(C.original_source_mode(row, entry))
        entry.mode = 0o644; self.assertFalse(C.original_source_mode(row, entry))
        entry.mode = 0o777; entry.type = tarfile.REGTYPE; self.assertFalse(C.original_source_mode(row, entry))

    def test_sparse_and_special_permission_originals_are_not_ordinary_regular_sources(self):
        row, entry, _ = self.fixture(); entry.sparse = [(0, 1)]
        self.assertFalse(C.original_source_mode(row, entry))
        entry.sparse = None; entry.mode = 0o4644
        self.assertFalse(C.original_source_mode(row, entry))

    def test_missing_original_baseline_cannot_claim_an_original_mode(self):
        row, entry, _ = self.fixture(); row.pop('baseline')
        self.assertFalse(C.original_source_mode(row, entry))

if __name__ == '__main__': unittest.main()
