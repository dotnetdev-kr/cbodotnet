#!/usr/bin/env python3
"""Regression tests for the native CI image-manifest selection contract."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = (ROOT / 'scripts/ci-net10.sh').read_text(encoding='utf-8')

# Minimal unchanged fields from reports/ci/ubuntu22-base-image.json in the
# completed native ARM64 run 41186712404, artifact 13038945772. Podman records
# the inspected platform manifest and the multi-platform index simultaneously.
ACTUAL = {
    'Id': '5649198dfcca9dd6955ee455fdd6ba60734f28da600de2919a2f53da113a707c',
    'Digest': 'sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11',
    'RepoDigests': [
        'docker.io/library/ubuntu@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11',
        'docker.io/library/ubuntu@sha256:a8fb2ba88181746111cbbe2969826d6546b71226785b196c93d2c3445a25000d',
    ],
    'Architecture': 'arm64',
    'Os': 'linux',
}


def embedded_python(anchor):
    start = DRIVER.index("<<'PY'\n", DRIVER.index(anchor)) + len("<<'PY'\n")
    return DRIVER[start:DRIVER.index('\nPY\n', start)]


class NativeManifestSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cbodotnet-ci-digest-test.')
        self.addCleanup(self.temporary.cleanup)
        self.inspection = Path(self.temporary.name) / 'inspection.json'

    def invoke(self, rows, anchor='pinned=$(python3', distribution='ubuntu', arch='arm64'):
        self.inspection.write_text(json.dumps(rows), encoding='utf-8')
        selection = {'arm64': 'arm64', 'x64': 'amd64'}[arch] if anchor == 'inspect_image() {' else distribution
        return subprocess.run([sys.executable, '-', str(self.inspection), selection],
                              input=embedded_python(anchor), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_actual_platform_and_index_choose_inspected_manifest(self):
        for references in [ACTUAL['RepoDigests'], list(reversed(ACTUAL['RepoDigests'])),
                           [ACTUAL['RepoDigests'][0]]]:
            with self.subTest(references=references):
                row = copy.deepcopy(ACTUAL); row['RepoDigests'] = references
                result = self.invoke([row])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), ACTUAL['RepoDigests'][0])

    def test_missing_malformed_or_unbound_inspected_digest_is_rejected(self):
        for digest in [None, '', 'sha256:' + 'g'*64, 'sha256:' + 'a'*63,
                       'sha512:' + 'a'*128, 'sha256:' + 'A'*64, 'sha256:' + 'a'*64]:
            with self.subTest(digest=digest):
                row = copy.deepcopy(ACTUAL); row['Digest'] = digest
                self.assertNotEqual(self.invoke([row]).returncode, 0)
        row = copy.deepcopy(ACTUAL); del row['Digest']
        self.assertNotEqual(self.invoke([row]).returncode, 0)

    def test_absent_mismatched_or_ambiguous_repository_binding_is_rejected(self):
        expected = ACTUAL['RepoDigests'][0]
        for references in [None, [], [ACTUAL['RepoDigests'][1]], [expected, expected],
                           expected, ['mirror.example/ubuntu@' + ACTUAL['Digest']]]:
            with self.subTest(references=references):
                row = copy.deepcopy(ACTUAL); row['RepoDigests'] = references
                self.assertNotEqual(self.invoke([row]).returncode, 0)
        row = copy.deepcopy(ACTUAL); del row['RepoDigests']
        self.assertNotEqual(self.invoke([row]).returncode, 0)
        self.assertNotEqual(self.invoke([ACTUAL], distribution='debian').returncode, 0)

    def test_inspection_requires_one_native_linux_arm64_image(self):
        result = self.invoke([ACTUAL], anchor='inspect_image() {')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), ACTUAL['Id'])
        for key, value in [('Architecture', 'amd64'), ('Os', 'windows'), ('Id', 'short')]:
            with self.subTest(key=key):
                row = copy.deepcopy(ACTUAL); row[key] = value
                self.assertNotEqual(self.invoke([row], anchor='inspect_image() {').returncode, 0)
        for rows in [[], [ACTUAL, ACTUAL]]:
            with self.subTest(rows=len(rows)):
                self.assertNotEqual(self.invoke(rows, anchor='inspect_image() {').returncode, 0)

    def test_x64_inspection_requires_amd64_and_rejects_cross_architecture(self):
        row = copy.deepcopy(ACTUAL); row['Architecture'] = 'amd64'
        result = self.invoke([row], anchor='inspect_image() {', arch='x64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), row['Id'])
        self.assertNotEqual(self.invoke([ACTUAL], anchor='inspect_image() {', arch='x64').returncode, 0)
        self.assertNotEqual(self.invoke([row], anchor='inspect_image() {', arch='arm64').returncode, 0)
        row['Os'] = 'windows'
        self.assertNotEqual(self.invoke([row], anchor='inspect_image() {', arch='x64').returncode, 0)


if __name__ == '__main__':
    unittest.main()
