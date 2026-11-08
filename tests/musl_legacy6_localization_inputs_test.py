"""Version isolation and closed input boundaries for source-built localization6."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tested_sdk6_localization', ROOT / 'scripts/musl_legacy6_localization_inputs.py')
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)


def package(version=L.VERSION, repository='', license_expression='MIT', members=()):
    target = io.BytesIO()
    xml = ('<package><metadata><id>Microsoft.Build.Localization</id><version>' + version + '</version>'
           '<license type="expression">' + license_expression + '</license>' + repository + '</metadata></package>')
    with zipfile.ZipFile(target, 'w') as archive:
        archive.writestr('Microsoft.Build.Localization.nuspec', xml)
        for name in members: archive.writestr(name, b'untrusted placeholder')
    return target.getvalue()


class LocalizationSixInputs(unittest.TestCase):
    def test_policy_has_full_original_language_matrix_and_no_publisher_reuse(self):
        p = L.policy()
        self.assertEqual(52, len(p['resources']))
        self.assertEqual(13, len({name.split('/')[2] for name in p['resources']}))
        self.assertEqual(19929, sum(r['keyCount'] for rows in p['resources'].values() for r in rows.values()))
        self.assertFalse(p['originalPublisherVersionReused'])
        self.assertNotEqual(p['originalMissingPublisherPackageVersion'], p['packageVersion'])

    def test_other_sdk_and_missing_publisher_versions_cannot_be_restamped(self):
        for version in ('17.4.8-preview-23319-01', '17.0.4-preview-24422-07', '17.0.4-cbodotnet.2'):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'downstream localization identity'):
                L.package_members(package(version))

    def test_fabricated_repository_and_substituted_license_are_rejected(self):
        for raw in (package(repository='<repository commit="' + L.COMMIT + '"/>'), package(license_expression='Apache-2.0')):
            with self.assertRaisesRegex(ValueError, 'downstream localization identity'): L.package_members(raw)

    def test_missing_culture_or_executable_payload_is_rejected_before_pe_decoding(self):
        for members in ((), ('lib/netstandard1.3/ko/MSBuild.resources.dll',), ('lib/netstandard1.3/ko/app.exe',)):
            with self.subTest(members=members), self.assertRaisesRegex(ValueError, 'All52'):
                L.package_members(package(members=members))

    def test_build_sdk_substitution_is_rejected_before_preparation_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'inputs'
            with self.assertRaisesRegex(ValueError, 'reviewed public Arcade'): L.build_sdk(b'same-version different build SDK')
            self.assertFalse(destination.exists())

    def test_only_exact_original_arcade_declaration_is_adapted(self):
        original = b'{"Microsoft.DotNet.Arcade.Sdk":"6.0.0-beta.24176.9","product":"17.0.4"}'
        self.assertEqual(original.replace(b'24176.9', b'24204.4'), L.original_global(original))
        for raw in (original + original, original.replace(b'24176.9', b'24204.4'), original.replace(b'24176.9', b'24176.8')):
            with self.assertRaisesRegex(ValueError, 'Exact original SDK6 Arcade'): L.original_global(raw)


if __name__ == '__main__': unittest.main()
