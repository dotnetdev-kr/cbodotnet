"""Reject incomplete, changed or architecture-dependent common RPM evidence."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('rpm_common_ci', ROOT / 'scripts/rpm-common-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class RpmCommonCiTests(unittest.TestCase):
    def matrix(self, directory):
        for arch in ('x64', 'aarch64'):
            output = directory / arch
            output.mkdir()
            rows = []
            for variant in CI.RPM.BASES:
                target = output / variant
                target.mkdir()
                package = target / ('cbodotnet-host-1.0.0-1.cbot.' + variant.replace('-', '') + '.noarch.rpm')
                package.write_bytes(b'fixture-rpm-' + variant.encode())
                (target / 'header.xml').write_bytes(b'fixture-header')
                (target / 'lead.bin').write_bytes(b'fixture-lead')
                rows.append(dict(variant=variant, architecture=arch, package=CI.descriptor(package),
                    headerSha256=CI.digest(b'fixture-header'), leadSha256=CI.digest(b'fixture-lead'),
                    cpioSha256=CI.digest(b'fixture-cpio'), baseImage=CI.RPM.BASES[variant][arch]))
            CI.save(output / 'native-common.json', dict(schemaVersion=1, status='passed',
                sourceCommit='a' * 40, architecture=arch, packages=rows))

    def test_complete_identical_native_matrix_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.matrix(directory)
            result = CI.aggregate(directory, directory / 'comparison.json', 'a' * 40)
            self.assertEqual('passed', result['status'])
            self.assertEqual(4, len(result['packages']))

    def test_changed_uploaded_package_and_wrong_source_commit_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.matrix(directory)
            with self.assertRaisesRegex(ValueError, 'provenance'):
                CI.aggregate(directory, directory / 'comparison.json', 'b' * 40)
            next((directory / 'x64').rglob('*.rpm')).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'evidence changed'):
                CI.aggregate(directory, directory / 'comparison.json', 'a' * 40)

    def test_different_but_internally_consistent_native_bytes_fail_and_retain_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.matrix(directory)
            path = directory / 'x64/native-common.json'
            report = json.loads(path.read_bytes())
            first = report['packages'][0]
            package = path.parent / first['variant'] / first['package']['name']
            package.write_bytes(b'different-native-header')
            first['package'] = CI.descriptor(package)
            CI.save(path, report)
            output = directory / 'comparison.json'
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                CI.aggregate(directory, output, 'a' * 40)
            self.assertEqual([first['variant']], json.loads(output.read_bytes())['differences'])

    def test_duplicate_variant_cannot_replace_a_missing_native_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.matrix(directory)
            path = directory / 'x64/native-common.json'
            report = json.loads(path.read_bytes())
            report['packages'][1] = report['packages'][0]
            CI.save(path, report)
            with self.assertRaisesRegex(ValueError, 'matrix differs'):
                CI.aggregate(directory, directory / 'comparison.json', 'a' * 40)


if __name__ == '__main__':
    unittest.main()
