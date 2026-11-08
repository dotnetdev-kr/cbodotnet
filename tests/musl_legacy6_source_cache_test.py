"""Real PackageDownload priming is closed to SDK6's own exact component set."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_source_cache_test', ROOT / 'scripts/musl_legacy6_source_cache.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


class SDK6SourceCacheBoundary(unittest.TestCase):
    def fixture(self, cache):
        rows = []
        for index, (identity, version) in enumerate(C.PACKAGES.items()):
            directory = cache / identity / version; directory.mkdir(parents=True)
            package = directory / (identity + '.' + version + '.nupkg'); package.write_bytes(('actual-restored-' + str(index)).encode())
            row = dict(id=identity, version=version, file=package.name, **C.fingerprint(package)); rows.append(row)
            content = base64.b64encode(bytes.fromhex(row['sha512'])).decode()
            (directory / '.nupkg.metadata').write_text(json.dumps(dict(version=2, source='/work/inputs/bootstrap-feed', contentHash=content)))
            (directory / (package.name + '.sha512')).write_text(content)
        return rows

    def test_replaced_metadata_source_or_checksum_is_rejected(self):
        for field in ('source', 'contentHash', 'checksum'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                cache = Path(temporary); rows = self.fixture(cache); C.validate(cache, rows)
                path = cache / rows[0]['id'] / rows[0]['version']; metadata_path = path / '.nupkg.metadata'
                if field == 'checksum': (path / (rows[0]['file'] + '.sha512')).write_text('forged')
                else:
                    metadata = json.loads(metadata_path.read_text()); metadata[field] = 'https://unreviewed.example/feed'
                    metadata_path.write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, 'origin or content hash differs'):
                    C.validate(cache, rows)

    def test_same_version_package_bytes_must_match_actual_source_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary); rows = self.fixture(cache)
            package = cache / rows[0]['id'] / rows[0]['version'] / rows[0]['file']; package.write_bytes(b'other-same-version-payload')
            with self.assertRaisesRegex(ValueError, 'different same-version package bytes'):
                C.validate(cache, rows)

    def test_missing_duplicate_or_unreviewed_component_cannot_use_twenty_two_as_a_waiver(self):
        rows = [dict(id=identity, version=version) for identity, version in C.PACKAGES.items()]
        changed = copy.deepcopy(rows); changed[0]['id'] = 'Unreviewed.Component'
        wrong_version = copy.deepcopy(rows); wrong_version[0]['version'] = '7.0.0'
        for selected in (rows[:-1], rows[:-1] + [rows[-2]], changed, wrong_version):
            with self.subTest(rows=selected[:1]), self.assertRaisesRegex(ValueError, 'component/source set required'):
                C.validate(ROOT / 'not-a-cache', selected)


if __name__ == '__main__': unittest.main()
