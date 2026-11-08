"""NuGet6 source admission must reject another graph and unrelated changes."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nuget6_source_test', ROOT / 'scripts/musl_legacy6_nuget_source.py')
N = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(N)


class SourceBoundary(unittest.TestCase):
    def test_explicit_upstream_xml_crlf_still_requires_the_original_blob(self):
        raw = b'<Project>original</Project>\n'
        blob = N.hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        row = dict(path='nuget/build/common.props', mode='100644', baseline=dict(mode='100644', blob=blob))
        self.assertTrue(N.pristine_source(row, raw.replace(b'\n', b'\r\n')))
        self.assertFalse(N.pristine_source(row, b'<Project>retargeted</Project>\r\n'))
        self.assertFalse(N.pristine_source(row, raw + b'\r'))
        for name in ('nuget/src/code.cs', 'other-submodule/build/common.props'):
            row['path'] = name
            self.assertFalse(N.pristine_source(row, raw.replace(b'\n', b'\r\n')))
        row['path'] = 'original-common/Common.sln'
        selected = {'original-common/Common.sln'}
        self.assertTrue(N.pristine_source(row, raw.replace(b'\n', b'\r\n'), selected))
        self.assertFalse(N.pristine_source(row, b'<Project>changed</Project>\r\n', selected))
        row['path'] = 'original-common/Other.sln'
        self.assertFalse(N.pristine_source(row, raw.replace(b'\n', b'\r\n'), selected))

    def test_unreviewed_patch_cannot_reach_source_reversal(self):
        raw = (ROOT / N.PATCH).read_bytes()
        with patch.object(N.B, 'reverse_reviewed_patch', side_effect=AssertionError('Unpinned patch reached reversal')):
            for changed in (raw + b'\n', raw.replace(b'AND', b'OR', 1)):
                with self.subTest(changed=changed[-20:]), self.assertRaisesRegex(ValueError, 'three-condition'):
                    N.original_pack(b'anything', changed)

    def test_valid_patch_cannot_authorize_unrelated_product_source(self):
        with self.assertRaises(ValueError):
            N.original_pack(b'<Project>unrelated source</Project>\n', (ROOT / N.PATCH).read_bytes())

    def test_another_sdk_or_incomplete_compilation_is_rejected_before_worker_io(self):
        base = dict(sdkVersion=N.SDK, component='nuget', sourceCommit=N.COMMIT)
        for proof, count, imports in [(dict(base, sdkVersion='7.0.120'), 72, {}),
                                      (base, 71, {}), (base, 72, {'imported.dll': 'unknown'})]:
            validated = dict(proof=proof, members={str(i): {} for i in range(count)}, imports=imports)
            with self.subTest(proof=proof, count=count, imports=imports), patch.object(N, 'worker',
                    side_effect=AssertionError('Unvalidated compiler proof reached worker')):
                with self.assertRaisesRegex(ValueError, 'compiler-validated original NuGet6'):
                    N.validate(ROOT, {}, validated)


if __name__ == '__main__': unittest.main()
