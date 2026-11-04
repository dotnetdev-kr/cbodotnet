"""Validate package-owned original notices in the native Arch runtime driver."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('aur_ci_notices', ROOT / 'scripts/aur-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class AurNativeNoticeTests(unittest.TestCase):
    def test_original_curl_notice_and_arch_copying_require_exact_bytes_and_package_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def local(value):
                return root / str(value).lstrip('/')
            provider = local(CI.legacy_curl.PROVIDER_ROOT)
            provider.mkdir(parents=True)
            (provider / 'LICENSE.curl.txt').write_bytes(b'original curl notice')
            (provider / 'NOTICE.txt').write_bytes(b'reviewed provider provenance')
            packaged = local('/usr/share/licenses') / CI.legacy_curl.PACKAGE_NAME / 'COPYING'
            packaged.parent.mkdir(parents=True)
            packaged.write_bytes(b'original curl notice')
            owner = mock.Mock(return_value=CI.legacy_curl.PACKAGE_NAME + '\n')
            with mock.patch.object(CI, 'Path', side_effect=local):
                CI.verify_native_http_notices(owner)
                self.assertEqual({provider / 'LICENSE.curl.txt', provider / 'NOTICE.txt', packaged},
                                 {call.args[0][-1] for call in owner.call_args_list})
                owner.return_value = 'unrelated-package\n'
                with self.assertRaisesRegex(ValueError, 'package ownership'):
                    CI.verify_native_http_notices(owner)
                owner.return_value = CI.legacy_curl.PACKAGE_NAME
                packaged.write_bytes(b'altered notice')
                with self.assertRaisesRegex(ValueError, 'notice bytes'):
                    CI.verify_native_http_notices(owner)
                packaged.unlink()
                with self.assertRaisesRegex(ValueError, 'notice bytes'):
                    CI.verify_native_http_notices(owner)


if __name__ == '__main__':
    unittest.main()
