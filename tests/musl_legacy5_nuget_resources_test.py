"""The SDK5 literal translation input stays bounded to its original archive."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nuget5_resources', ROOT / 'scripts/musl-legacy5-nuget-resources.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class TranslationBoundary(unittest.TestCase):
    def test_names_are_the_complete_resource_only_thirteen_culture_set(self):
        names = M.relative_names()
        self.assertEqual((len(names), len(set(names))), (286, 286))
        self.assertTrue(all(n.endswith('.resources.dll') and '..' not in Path(n).parts for n in names))
        self.assertEqual(len(M.CULTURES), 13)
        self.assertEqual(M.SDK, '5.0.214')
        self.assertEqual(M.COMMIT, 'd525b0e670f3b6cbd5c73a35f04730a9f658c852')
        for culture in M.CULTURES:
            self.assertIn('Sdks/NuGet.Build.Tasks.Pack/CoreCLR/' + culture + '/NuGet.Build.Tasks.Pack.resources.dll', names)
            self.assertIn('Sdks/NuGet.Build.Tasks.Pack/Desktop/' + culture + '/NuGet.Build.Tasks.Pack.resources.dll', names)

    def test_only_the_two_observed_original_metadata_spellings_are_mapped(self):
        self.assertEqual(M.METADATA_CULTURES, {'zh-Hans': 'zh-HANS', 'zh-Hant': 'zh-HANT'})
        self.assertTrue(set(M.METADATA_CULTURES) <= set(M.CULTURES))

    def test_wrong_archive_is_rejected_before_source_queries_or_output_writes(self):
        arguments = ['reader', '--sdk-archive', '/not-an-sdk.tar.gz', '--arch', 'aarch64',
            '--source', '/unread-source', '--dotnet', '/unexecuted-dotnet', '--output', '/unwritten-output']
        with mock.patch.object(sys, 'argv', arguments), \
                mock.patch.object(M, 'fingerprint', return_value={'sha512': '0' * 128}), \
                mock.patch.object(M.subprocess, 'check_output', side_effect=AssertionError('no source query')), \
                mock.patch.object(Path, 'mkdir', side_effect=AssertionError('no output write')):
            with self.assertRaisesRegex(ValueError, 'archive bytes differ'):
                M.main()


if __name__ == '__main__':
    unittest.main()
