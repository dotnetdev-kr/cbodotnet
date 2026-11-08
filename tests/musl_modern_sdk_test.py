"""Version-specific native source routes and modern musl admission boundaries."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_version_routes as R
SPEC = importlib.util.spec_from_file_location('modern_musl_sdk_tests', ROOT / 'scripts/musl-modern-sdk.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class NativeRoutes(unittest.TestCase):
    def test_all_four_routes_use_exact_native_bootstrap_and_stock_dependencies(self):
        for sdk in R.VERSIONS:
            for arch in R.ARCHITECTURES:
                with self.subTest(sdk=sdk, arch=arch):
                    value = R.profile(sdk, arch)
                    original = json.loads((ROOT / 'profiles' / ('dotnet-10.0.403-linux-musl-' + arch + '.json')).read_text())
                    self.assertEqual(value['container'], original['container'])
                    self.assertEqual(value['apkIndexes'], original['apkIndexes'])
                    self.assertEqual(value['buildPackages'], original['buildPackages'])
                    self.assertEqual(value['runtimePackages'], original['runtimePackages'])
                    self.assertFalse(value['build']['crossBuild'])
                    self.assertEqual('pending', value['qualification']['status'])
                    self.assertEqual(1, value['qualification']['producerRevision'])
                    self.assertFalse(value['qualification']['securityMaintenanceBeyondUpstreamEol'])

    def test_version_specific_commands_keep_real_native_musl_graph(self):
        for sdk in R.VERSIONS:
            for arch, identity in R.ARCHITECTURES.items():
                command = R.build_command(sdk, arch)
                self.assertIn('CrossBuild=false', command)
                self.assertIn('/p:CrossBuild=false', command)
                self.assertIn('/p:PortableBuild=true', command)
                self.assertNotIn('--clean-while-building', command)
                self.assertFalse(any('xenial' in item or item.startswith('ROOTFS_DIR=') for item in command))
                self.assertFalse(any('NuGetAudit' in item for item in command))
                if sdk.startswith('9.'):
                    self.assertIn(identity['rid'], command)
                    self.assertIn('/p:TargetOS=linux-musl', command)
                    self.assertNotIn('--arch', command)
                else:
                    self.assertIn('/p:TargetRid=' + identity['rid'], command)
                    self.assertIn('/p:Platform=' + identity['upstream'], command)
                    self.assertIn('--online', command)
                    self.assertNotIn('--source-only', command)
                    self.assertEqual(['--with-sdk', '/vmr/.dotnet'], command[command.index('--with-sdk'):command.index('--with-sdk') + 2])

    def test_upstream_baseline_is_explicit_and_does_not_become_the_built_sdk(self):
        for sdk in R.VERSIONS:
            for arch in R.ARCHITECTURES:
                with self.assertRaisesRegex(ValueError, 'comparison archive'):
                    R.build_command(sdk, arch, True, '/inputs/glibc-sdk.tar.gz')
                command = R.build_command(sdk, arch, True, '/inputs/official-sdk.tar.gz')
                self.assertIn('--test' if sdk.startswith('9.') else '--run-smoke-test', command)
                record = M.upstream_sdk_record(sdk, arch)
                self.assertIn(R.ARCHITECTURES[arch]['rid'], record['url'])
                self.assertEqual(128, len(record['sha512']))


class SourceAndArchiveSafety(unittest.TestCase):
    def test_feed_adjustment_accepts_only_canonical_git_crlf_and_records_exact_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            original = b'<configuration>\n<packageSources><clear /></packageSources>\n</configuration>\n'
            (source / 'NuGet.config').write_bytes(original.replace(b'\n', b'\r\n'))
            def process(command):
                return original if 'show' in command else b'diff\n'
            with mock.patch.object(M, 'git', return_value=R.VERSIONS['9.0.123']['source']), mock.patch.object(M.subprocess, 'check_output', side_effect=process):
                M.configure_feeds(source, Path(temporary) / 'reports', '9.0.123')
                record = json.loads((Path(temporary) / 'reports/feed-adjustments.json').read_text())
                self.assertFalse(record['packageVersionsChanged'])
                self.assertIn(b'maxHttpRequestsPerSource', (source / 'NuGet.config').read_bytes())
                (source / 'NuGet.config').write_bytes(original + b'<!-- unreviewed -->')
                with self.assertRaisesRegex(ValueError, 'preexisting'):
                    M.configure_feeds(source, Path(temporary) / 'other', '9.0.123')

    def archive(self, path, entries):
        with tarfile.open(path, 'w:gz') as stream:
            for name, value in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                stream.addfile(entry, io.BytesIO(value))

    def test_complete_framework_byte_comparison_detects_changed_or_missing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = 'shared/Microsoft.NETCore.App/9.0.22/'
            self.archive(root / 'a.tar.gz', [(prefix + 'core.dll', b'original'), (prefix + 'other.dll', b'other')])
            self.archive(root / 'b.tar.gz', [(prefix + 'core.dll', b'changed'), (prefix + 'other.dll', b'other')])
            self.assertNotEqual(M.archive_files(root / 'a.tar.gz', prefix), M.archive_files(root / 'b.tar.gz', prefix))
            self.archive(root / 'unsafe.tar.gz', [(prefix + '../outside', b'escape')])
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                M.archive_files(root / 'unsafe.tar.gz', prefix)

    def test_diagnostic_or_incomplete_modern_evidence_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for marker in ({}, {'diagnosticPtrace': True}, {'diagnosticPtrace': 0}):
                (root / 'producer-validation.json').write_text(json.dumps(marker))
                with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'Diagnostic'):
                    M.validate(root)


class OriginalTestGraph(unittest.TestCase):
    def test_net8_missing_tests_or_new_skips_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            trx = Path(temporary) / 'test.trx'
            ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
            root = ET.Element('{' + ns + '}TestRun')
            rows = ET.SubElement(root, '{' + ns + '}Results')
            for index in range(44):
                ET.SubElement(rows, '{' + ns + '}UnitTestResult', executionId=str(index), testName='Test.' + str(index), outcome='Passed')
            for index, name in enumerate(('LicenseScanTests.ScanForLicenses', 'PoisonTests.VerifyUsage'), 44):
                ET.SubElement(rows, '{' + ns + '}UnitTestResult', executionId=str(index), testName=name, outcome='NotExecuted')
            summary = ET.SubElement(root, '{' + ns + '}ResultSummary')
            ET.SubElement(summary, '{' + ns + '}Counters', total='46', executed='44', passed='44', failed='0')
            ET.ElementTree(root).write(trx)
            self.assertEqual(44, R.parse_upstream_results('8.0.133', 'x64', trx)['passed'])
            rows.remove(rows[0])
            ET.ElementTree(root).write(trx)
            with self.assertRaises(ValueError):
                R.parse_upstream_results('8.0.133', 'x64', trx)


if __name__ == '__main__':
    unittest.main()
