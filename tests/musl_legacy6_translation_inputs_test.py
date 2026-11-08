"""SDK6 resource inputs cannot inherit another SDK or hide executable payloads."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_translation_test', ROOT / 'scripts/musl_legacy6_translation_inputs.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)


class SDK6TranslationBoundary(unittest.TestCase):
    def test_wrong_sdk_is_rejected_before_archive_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'not-the-reviewed-sdk.tar.gz'; path.write_bytes(b'unreviewed')
            with mock.patch.object(T.tarfile, 'open', side_effect=AssertionError('Wrong SDK reached archive parser')):
                with self.assertRaisesRegex(ValueError, 'comparison archive identity differs'):
                    T.comparison_sdk_inventory(path, dict(sdkVersion='7.0.120', architecture='aarch64'), set())

    def test_untrusted_same_sdk_archive_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'substituted.tar.gz'; path.write_bytes(b'unreviewed')
            with mock.patch.object(T.tarfile, 'open', side_effect=AssertionError('Unpinned SDK reached archive parser')):
                with self.assertRaisesRegex(ValueError, 'comparison archive identity differs'):
                    T.comparison_sdk_inventory(path, dict(sdkVersion=T.SDK, architecture='aarch64'), set())

    def test_unknown_import_origin_is_rejected_before_index_walk(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); directory = release / 'reports/build/nuget-translation-data'
            directory.mkdir(parents=True); (directory / 'origin.json').write_text(json.dumps(dict(schemaVersion=1,
                kind='imported-official-nuget-translation-data', sdkVersion=T.SDK, architecture='aarch64', sourceCommit='0' * 40)))
            with self.assertRaisesRegex(ValueError, 'resource-only NuGet product translation input identity'):
                T.validate_translation_data(release, dict(sdkVersion=T.SDK, architecture='aarch64'), {})


if __name__ == '__main__': unittest.main()
