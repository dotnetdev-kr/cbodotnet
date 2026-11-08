"""Reject incomplete or changed SDK8 implementation servicing provenance."""
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_version_routes as R


class Net8ServicingRegistry(unittest.TestCase):
    def test_native_profiles_bind_all_introduced_packages_to_exact_sources(self):
        left = R.profile('8.0.133', 'x64')['supplementalSourceGit']
        right = R.profile('8.0.133', 'aarch64')['supplementalSourceGit']
        self.assertEqual(left, right)
        self.assertEqual([5, 2, 1], [len(source['packages']) for source in left])
        packages = {package['id']: package['version'] for source in left for package in source['packages']}
        self.assertEqual({
            'microsoft.build': '17.8.43', 'microsoft.build.framework': '17.8.43',
            'microsoft.build.tasks.core': '17.8.43', 'microsoft.build.utilities.core': '17.8.43',
            'microsoft.net.stringtools': '17.8.43', 'system.security.cryptography.xml': '8.0.5',
            'system.security.cryptography.pkcs': '8.0.2', 'system.formats.asn1': '8.0.2',
        }, packages)

    def test_protected_profile_rejects_source_license_byte_or_coverage_changes(self):
        original = R.profile('8.0.133', 'aarch64')
        for mutation in ('source', 'license', 'bytes', 'coverage'):
            changed = copy.deepcopy(original)
            sources = changed['supplementalSourceGit']
            if mutation == 'source':
                sources[0]['commit'] = '0' * 40
            elif mutation == 'license':
                sources[1]['packages'][0]['license'] = 'Unlicense'
            elif mutation == 'bytes':
                sources[2]['packages'][0]['sha512'] = '0' * 128
            else:
                sources[0]['packages'].pop()
            with self.subTest(mutation=mutation), mock.patch.object(R.json, 'loads', return_value=changed):
                with self.assertRaisesRegex(ValueError, 'registry'):
                    R.profile('8.0.133', 'aarch64')


if __name__ == '__main__':
    unittest.main()
