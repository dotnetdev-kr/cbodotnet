"""Keep historical-reference audit review separate from executable SDK content."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_reference_audit as M


def warning(row):
    return (M.PREFIX + row['project'] + ' : warning ' + row['code'] + ": Package '" + row['packageId']
            + "' " + row['packageVersion'] + ' has a known ' + row['severity']
            + ' severity vulnerability, ' + row['advisory'])


class ReferenceAuditBoundary(unittest.TestCase):
    def setUp(self):
        self.rows = M.policy()['records']
        self.log = '\n'.join(warning(row) for row in self.rows)

    def test_complete_visible_graph_is_accepted_but_not_errors_or_missing_warnings(self):
        self.assertEqual(15, len(M.warning_graph(self.log + '\n' + self.log)))
        for changed in ('', '\n'.join(self.log.splitlines()[1:]), self.log.replace(': warning ', ': error ', 1)):
            with self.subTest(changed=changed[:80]), self.assertRaises(ValueError):
                M.warning_graph(changed)

    def test_new_advisory_package_version_or_implementation_scope_is_rejected(self):
        changed = dict(self.rows[0])
        for field, value in (('advisory', 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc'),
                             ('packageVersion', '999.0.0'), ('project', 'src/implementation/Runtime.csproj')):
            mutation = dict(changed, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.warning_graph(self.log + '\n' + warning(mutation))

    def test_projectless_or_unavailable_audit_diagnostics_cannot_be_ignored(self):
        for extra in ("warning NU1903: Package 'Unreviewed' has a known vulnerability",
                      'prefix WARNING NU1900: Audit service unavailable'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                M.warning_graph(self.log + '\n' + extra)

    def inventory(self, members):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'sdk.tar.gz'
            with tarfile.open(archive, 'w:gz') as destination:
                for name, raw in members:
                    member = tarfile.TarInfo(name); member.size = len(raw)
                    destination.addfile(member, io.BytesIO(raw))
            return M.sdk_reference_inventory(archive)

    def test_reference_apis_may_ship_in_ref_pack_but_never_as_host_runtime_code(self):
        stub = b'MZ' + M.MARKER
        rows = self.inventory([('packs/Microsoft.NETCore.App.Ref/8.0.33/ref/net8.0/Test.dll', stub)])
        self.assertEqual('compilation-reference-api-only', rows[0]['disposition'])
        for name in ('sdk/8.0.133/System.Text.Json.dll', 'shared/Microsoft.NETCore.App/8.0.33/Test.dll',
                     'packs/Microsoft.NETCore.App.Runtime.linux-arm64/8.0.22/tools/ref/Runtime.dll',
                     'packs/Unreviewed.Ref/8.0.33/ref/net8.0/Test.dll'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'outside a compilation-reference'):
                self.inventory([(name, stub)])

    def test_runtime_stubs_cannot_be_hidden_in_nested_packages(self):
        for directory, accepted in (('ref/net8.0', True), ('lib/net8.0', False)):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                archive.writestr(directory + '/Test.dll', b'MZ' + M.MARKER)
            if accepted:
                self.assertEqual(1, len(self.inventory([('library-packs/Test.nupkg', buffer.getvalue())])))
            else:
                with self.assertRaisesRegex(ValueError, 'outside a compilation-reference'):
                    self.inventory([('library-packs/Test.nupkg', buffer.getvalue())])

    def test_archives_inside_archives_are_inspected_and_recursion_is_bounded(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w') as archive:
            archive.writestr('runtimes/Runtime.dll', b'MZ' + M.MARKER)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as archive:
            archive.writestr('tools/inner.zip', inner.getvalue())
        with self.assertRaisesRegex(ValueError, 'outside a compilation-reference'):
            self.inventory([('sdk/8.0.133/payload.zip', outer.getvalue())])
        raw = b''
        for _ in range(6):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                archive.writestr('inner.zip', raw)
            raw = buffer.getvalue()
        with self.assertRaisesRegex(ValueError, 'depth exceeds'):
            self.inventory([('deep.zip', raw)])

    def test_duplicate_or_escaping_payload_cannot_hide_a_reference_assembly(self):
        for members in ([('../escape.dll', b'MZ')], [('same.dll', b'MZ'), ('same.dll', b'MZ')]):
            with self.subTest(members=members), self.assertRaises(ValueError):
                self.inventory(members)


if __name__ == '__main__':
    unittest.main()
