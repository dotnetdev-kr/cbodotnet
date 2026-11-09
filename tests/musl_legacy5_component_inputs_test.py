from pathlib import Path
import sys
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


if __name__ == '__main__': unittest.main()
