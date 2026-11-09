import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('sdk6_closed_literal_checkouts', ROOT / 'scripts/musl_legacy6_literal_checkout_inputs.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ClosedPublisherCheckouts(unittest.TestCase):
    def setUp(self):
        self.closed = copy.deepcopy(M.checkout_policy())
        self.root = dict(name='aspnetcore', kind='git', commit=self.closed['commit'], tree=self.closed['tree'])

    def vector(self, name=None, attribute=False):
        name = self.closed['attribute']['path'] if attribute else name or next(iter(self.closed['representations']))
        expected = self.closed['attribute'] if attribute else self.closed['representations'][name]
        raw = base64.b64decode(expected['rawBase64'], validate=True)
        row = dict(path=self.root['name'] + '/' + name, mode='100644', **M.fingerprint(raw),
            baseline=dict(mode='100644', blob=expected['gitBlob'] if attribute else expected['canonicalGitBlob']))
        entry = tarfile.TarInfo(row['path'])
        entry.mode = 0o644
        entry.size = len(raw)
        return name, row, entry, raw

    def accept(self, vector, root=None, key='aspnetcore', closed=None):
        name, row, entry, raw = vector
        return M._checkout(root or self.root, key, name, row, entry, raw, closed or self.closed)

    def repin_diagnostic_raw(self, vector, raw):
        # A private diagnostic only: normal checkout_policy authenticates the
        # immutable policy before parsing, so callers cannot supply this copy.
        name, row, entry, _ = vector
        closed = copy.deepcopy(self.closed)
        expected = closed['representations'][name]
        expected['rawBase64'] = base64.b64encode(raw).decode()
        expected['fingerprint'] = M.fingerprint(raw)
        expected['rawGitBlob'] = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        row = dict(row, **M.fingerprint(raw))
        return (name, row, entry, raw), closed

    def test_all_ten_actual_retained_crlf_vectors_pass(self):
        self.assertEqual(len(self.closed['representations']), 10)
        for name in self.closed['representations']:
            with self.subTest(name=name):
                self.assertTrue(self.accept(self.vector(name)))

    def test_original_git_forms_still_pass_unchanged_original_blob_primitive(self):
        P = M.module('sdk6_checkout_test_original_git_primitive', 'package-used-source.py')
        for name in self.closed['representations']:
            _, row, _, raw = self.vector(name)
            canonical = raw.replace(b'\r\n', b'\n')
            row.update(M.fingerprint(canonical))
            blob = hashlib.sha1(b'blob ' + str(len(canonical)).encode() + b'\0' + canonical).hexdigest()
            with self.subTest(name=name):
                self.assertTrue(P.pristine_blob(row, blob, None))

    def test_wrong_relative_or_full_path_and_extra_css_case_reject(self):
        for name in ('elsewhere/site.css', next(iter(self.closed['representations'])) + '.extra'):
            vector = list(self.vector())
            vector[0] = name
            vector[1]['path'] = self.root['name'] + '/' + name
            vector[2].name = vector[1]['path']
            self.assertFalse(self.accept(vector))
        vector = self.vector()
        vector[2].name += '.substitution'
        self.assertFalse(self.accept(vector))

    def test_wrong_commit_tree_or_source_role_reject(self):
        for field in ('commit', 'tree'):
            root = dict(self.root)
            root[field] = '0' * 40
            self.assertFalse(self.accept(self.vector(), root=root))
        self.assertFalse(self.accept(self.vector(), key='spa'))

    def test_wrong_index_baseline_mode_archive_mode_or_symlink_reject(self):
        vector = self.vector()
        vector[1]['mode'] = '100755'
        self.assertFalse(self.accept(vector))
        vector = self.vector()
        vector[1]['baseline']['mode'] = '100755'
        self.assertFalse(self.accept(vector))
        for mode in (0o755, 0o4644):
            vector = self.vector()
            vector[2].mode = mode
            self.assertFalse(self.accept(vector))
        vector = self.vector()
        vector[2].type = tarfile.SYMTYPE
        self.assertFalse(self.accept(vector))

    def test_each_raw_fingerprint_field_is_bound(self):
        for field in M.FP:
            vector = self.vector()
            vector[1][field] = 0 if field == 'bytes' else '0' * len(vector[1][field])
            self.assertFalse(self.accept(vector))

    def test_changed_content_rejects_even_after_index_hashes_are_updated(self):
        name, row, entry, raw = self.vector()
        changed = b'X' + raw[1:]
        row.update(M.fingerprint(changed))
        self.assertFalse(self.accept((name, row, entry, changed)))

    def test_canonical_git_blob_cannot_be_relabelled(self):
        name, row, entry, raw = self.vector()
        closed = copy.deepcopy(self.closed)
        closed['representations'][name]['canonicalGitBlob'] = '0' * 40
        row['baseline']['blob'] = '0' * 40
        self.assertFalse(self.accept((name, row, entry, raw), closed=closed))

    def test_rehashed_diagnostic_policy_does_not_hide_content_change(self):
        vector = self.vector()
        changed, closed = self.repin_diagnostic_raw(vector, b'X' + vector[3][1:])
        self.assertFalse(self.accept(changed, closed=closed))

    def test_mixed_eol_and_bare_cr_reject_even_with_rehashed_raw_descriptors(self):
        vector = self.vector()
        for raw in (vector[3].replace(b'\r\n', b'\n', 1), vector[3].replace(b'\r\n', b'\r', 1)):
            changed, closed = self.repin_diagnostic_raw(vector, raw)
            self.assertFalse(self.accept(changed, closed=closed))

    def test_nul_cannot_be_treated_as_text_checkout(self):
        vector = self.vector()
        changed, closed = self.repin_diagnostic_raw(vector, vector[3] + b'\0')
        name, row, entry, raw = changed
        canonical = raw.replace(b'\r\n', b'\n')
        blob = hashlib.sha1(b'blob ' + str(len(canonical)).encode() + b'\0' + canonical).hexdigest()
        closed['representations'][name]['canonicalGitBlob'] = blob
        row['baseline']['blob'] = blob
        self.assertFalse(self.accept(changed, closed=closed))

    def test_exact_attribute_bytes_mode_namespace_and_commit_are_required(self):
        name, row, entry, raw = self.vector(attribute=True)
        proof = M._attribute(self.root, 'aspnetcore', name, row, entry, raw, self.closed)
        self.assertEqual(proof['fingerprint']['bytes'], 37)
        for alteration in ('raw', 'mode', 'namespace', 'commit', 'tree', 'baseline', 'fingerprint'):
            name, row, entry, raw = self.vector(attribute=True)
            root = dict(self.root)
            if alteration == 'raw':
                raw += b'\n'
                row.update(M.fingerprint(raw))
            elif alteration == 'mode':
                entry.mode = 0o755
            elif alteration == 'namespace':
                entry.name += '.changed'
            elif alteration in ('commit', 'tree'):
                root[alteration] = '0' * 40
            elif alteration == 'baseline':
                row['baseline']['blob'] = '0' * 40
            else:
                row['sha512'] = '0' * 128
            with self.subTest(alteration=alteration), self.assertRaisesRegex(ValueError, 'attribute bytes/mode/Git proof'):
                M._attribute(root, 'aspnetcore', name, row, entry, raw, self.closed)

    def test_missing_attribute_proof_cannot_return_a_positive(self):
        with self.assertRaisesRegex(ValueError, 'must complete before returning'):
            M._finish_attribute(None)

    def test_untrusted_checkout_policy_rejects_before_json_parse(self):
        M.checkout_policy.cache_clear()
        try:
            with mock.patch.object(M.Path, 'read_bytes', return_value=b'{}'), \
                    mock.patch.object(M.json, 'loads', side_effect=AssertionError('untrusted policy parsed')):
                with self.assertRaisesRegex(ValueError, 'policy differs'):
                    M.checkout_policy()
        finally:
            M.checkout_policy.cache_clear()

    def test_original_helper_is_authenticated_before_loading(self):
        M.original.cache_clear()
        try:
            with mock.patch.object(M.Path, 'read_bytes', return_value=b'changed'), \
                    mock.patch.object(M, 'module', side_effect=AssertionError('changed original helper loaded')):
                with self.assertRaisesRegex(ValueError, 'original SDK6 literal helper changed'):
                    M.original()
        finally:
            M.original.cache_clear()


if __name__ == '__main__':
    unittest.main()
