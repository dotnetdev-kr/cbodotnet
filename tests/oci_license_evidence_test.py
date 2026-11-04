"""New image promotions must retain the project license for their added CLI."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import downstream_release as RELEASE
SPEC = importlib.util.spec_from_file_location('oci_license_ci', ROOT / 'scripts/distribution-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class OciLicenseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.descriptor = RELEASE.oci_wrapper_license()
        self.proof = dict(self.descriptor, ownership='0:0:644', status='passed')
        self.report = dict(checks={'image-wrapper-license': 'passed'},
                           imageFiles=dict(wrapperLicense=self.proof), imageUpgradeFiles=dict(wrapperLicense=self.proof))

    def test_both_tested_images_must_retain_exact_project_license_owned_as_ordinary_public_notice(self):
        RELEASE.validate_oci_wrapper_license(self.report, dict(channel='oci'))
        for key in ('imageFiles', 'imageUpgradeFiles'):
            for change in (dict(path='/opt/cbodotnet/10.0/LICENSE.txt'), dict(sha256='a' * 64),
                           dict(ownership='1654:1654:644'), dict(status='not-run')):
                report = copy.deepcopy(self.report)
                report[key]['wrapperLicense'].update(change)
                with self.subTest(key=key, change=change), self.assertRaisesRegex(ValueError, 'wrapper license'):
                    RELEASE.validate_oci_wrapper_license(report, dict(channel='oci'))
        for report in ({}, dict(self.report, checks={}), dict(self.report, imageUpgradeFiles={})):
            with self.subTest(report=report), self.assertRaises(ValueError):
                RELEASE.validate_oci_wrapper_license(report, dict(channel='oci'))

    def test_other_native_package_channels_keep_their_existing_license_ownership_policy(self):
        for channel in ('deb', 'rpm', 'aur'):
            RELEASE.validate_oci_wrapper_license({}, dict(channel=channel))

    def test_actual_image_file_read_requires_exact_sha_owner_mode_and_an_ordinary_file(self):
        output = '0:0:644\n' + self.descriptor['sha256'] + '  ' + self.descriptor['path'] + '\n'
        with mock.patch.object(CI, 'run', side_effect=['0:0:755\n' * 4, '', output]) as command:
            proof = CI.inspect_consumer_files('image@sha256:test', '/opt/cbodotnet/9.0', wrapper_license=self.descriptor)
            self.assertEqual(self.proof, proof['wrapperLicense'])
            args = command.call_args.args[0]
            self.assertIn('none', args)
            self.assertIn('test ! -L', args[-1])
        for wrong in (output.replace('0:0:644', '0:0:600'), output.replace(self.descriptor['sha256'], 'f' * 64)):
            with mock.patch.object(CI, 'run', side_effect=['0:0:755\n' * 4, '', wrong]):
                with self.assertRaisesRegex(ValueError, 'MIT license bytes'):
                    CI.inspect_consumer_files('image', '/opt/cbodotnet/9.0', wrapper_license=self.descriptor)

    def test_historical_sdk10_r1_r2_remain_readable_but_all_new_descriptors_bind_notice(self):
        for tag in ('10.0.403-debian13-r3', '9.0.123-debian13-r1', '3.0.103-debian13-r1'):
            version = tag.split('-debian13-')[0]
            expected = dict(architecture='amd64', metadataPolicyVersion=2, sdkRoot='/opt/cbodotnet/' + '.'.join(version.split('.')[:2]),
                            labels={'placeholder': 'labels'})
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, 'exact project wrapper license'):
                CI.validate_published_metadata(dict(tag=tag), expected)
        # The r1 public metadata policy remains unchanged. Existing r2 label
        # validation is exercised by distribution_ci_test without a notice field.
        self.assertIsNone(CI.validate_published_metadata(dict(tag='10.0.403-debian13-r1'), dict(architecture='amd64')))


if __name__ == '__main__':
    unittest.main()
