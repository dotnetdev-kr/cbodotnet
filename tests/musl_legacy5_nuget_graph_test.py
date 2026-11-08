"""Boundaries for the SDK5 original-XPLAT selection and raw source verifier."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nuget5_graph', ROOT / 'scripts/musl_legacy5_nuget_graph.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


class OriginalGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.git(self.source, 'init', '-q')

    def git(self, source, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Source Test', '-c',
            'user.email=source-test@example.invalid', '-c', 'core.autocrlf=false',
            '-C', str(source), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def write(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8', newline='\n')

    def commit(self):
        self.git(self.source, 'add', '.')
        self.git(self.source, 'commit', '-qm', 'original fixture')
        return self.git(self.source, 'rev-parse', 'HEAD')

    def graph(self, conditional='', inherited=False, declaration=None):
        self.write('build/build.proj', '<Project><ItemGroup ' + conditional + '><ProductProjects Include="' +
            (declaration or G.PRODUCT_GLOB) + '" /></ItemGroup><Target Name="RestoreXPLAT" />' +
            '<Target Name="BuildXPLAT" /><Target Name="PackXPLAT" /></Project>')
        self.write('build/common.project.props', '<Project />')
        self.write('build/common.targets', '<Project />')
        for name, value in [('Included', '<XPLATProject>true</XPLATProject>'),
                            ('Excluded', '<XPLATProject>false</XPLATProject>'), ('Absent', '')]:
            self.write('src/Core/' + name + '/' + name + '.csproj',
                '<Project><PropertyGroup>' + value + '</PropertyGroup></Project>')
        if inherited:
            self.write('build/inherited.props', '<Project><PropertyGroup><XPLATProject>true</XPLATProject></PropertyGroup></Project>')
        return self.commit()

    def prepare(self, commit):
        with patch.object(G, 'COMMIT', commit):
            return G.prepare(self.source, self.base / 'evidence')

    def test_exact_selection_preserves_original_target_bodies_and_all_candidates(self):
        driver, report = self.prepare(self.graph())
        self.assertEqual((report['selectedCount'], report['originalCandidateCount']), (1, 3))
        self.assertEqual(report['selectedProjects'], ['src/Core/Included/Included.csproj'])
        self.assertEqual(driver.parent, self.source / 'build')
        self.assertEqual(ET.parse(driver).getroot().find('Import').attrib['Project'], '$(MSBuildThisFileDirectory)build.proj')
        self.assertEqual((self.base / 'evidence/build/build.proj').read_bytes(),
                         (self.source / 'build/build.proj').read_bytes())
        self.assertFalse(report['originalFullRootGraphClaimed'])

    def test_conditional_product_declaration_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conditional/inherited ProductProjects'):
            self.prepare(self.graph('Condition="true"'))

    def test_changed_product_glob_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'declaration/override'):
            self.prepare(self.graph(declaration='$(RepositoryRootDirectory)src/**/*.csproj'))

    def test_inherited_xplat_property_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'inherited XPLAT'):
            self.prepare(self.graph(inherited=True))

    def test_conditional_or_overridden_xplat_properties_are_rejected(self):
        for contents in [
            '<PropertyGroup Condition="true"><XPLATProject>true</XPLATProject></PropertyGroup>',
            '<PropertyGroup><XPLATProject Condition="true">true</XPLATProject></PropertyGroup>',
            '<PropertyGroup><XPLATProject>true</XPLATProject><XPLATProject>false</XPLATProject></PropertyGroup>',
            '<Target Name="Injected"><PropertyGroup><XPLATProject>true</XPLATProject></PropertyGroup></Target>']:
            with self.subTest(contents=contents), self.assertRaises(ValueError):
                G.properties(ET.fromstring('<Project>' + contents + '</Project>'), 'XPLATProject')

    def test_verifier_checks_raw_git_bytes_even_when_eol_status_is_dirty(self):
        self.write('.gitattributes', '*.props text eol=crlf\n')
        self.write('input.props', '<Project />\n')
        commit = self.commit()
        (self.source / 'input.props').write_bytes(b'<Project />\n')
        self.assertTrue(G.verify_original_raw_tree(self.source, commit)['allTrackedRawGitBlobsIdentical'])
        (self.source / 'input.props').write_bytes(b'<Project Changed="true" />\n')
        with self.assertRaisesRegex(ValueError, 'raw Git blob differs'):
            G.verify_original_raw_tree(self.source, commit)

    def test_missing_or_changed_gitlink_source_is_rejected(self):
        child = self.source / 'submodules/Child'
        child.mkdir(parents=True)
        self.git(child, 'init', '-q')
        (child / 'original.cs').write_text('class Original {}\n')
        self.git(child, 'add', '.')
        self.git(child, 'commit', '-qm', 'child original')
        child_commit = self.git(child, 'rev-parse', 'HEAD')
        self.git(self.source, 'update-index', '--add', '--cacheinfo', '160000,' + child_commit + ',submodules/Child')
        self.git(self.source, 'commit', '-qm', 'original gitlink')
        commit = self.git(self.source, 'rev-parse', 'HEAD')
        self.assertEqual(G.verify_original_raw_tree(self.source, commit)['submodules'][0]['commit'], child_commit)
        (child / 'original.cs').write_text('class Modified {}\n')
        with self.assertRaisesRegex(ValueError, 'raw Git blob differs'):
            G.verify_original_raw_tree(self.source, commit)
        retained = self.base / 'retained-child'
        self.assertTrue(child.resolve().is_relative_to(self.base.resolve()))
        self.assertTrue(retained.resolve().is_relative_to(self.base.resolve()))
        child.rename(retained)
        with self.assertRaisesRegex(ValueError, 'Gitlink source'):
            G.verify_original_raw_tree(self.source, commit)

    def test_untracked_source_is_rejected(self):
        self.write('original.cs', 'class Original {}\n')
        commit = self.commit()
        self.write('injected.cs', 'class Injected {}\n')
        with self.assertRaisesRegex(ValueError, 'untracked'):
            G.verify_original_raw_tree(self.source, commit)


if __name__ == '__main__':
    unittest.main()
