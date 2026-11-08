import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('framework_il_inputs',
    Path(__file__).resolve().parents[1] / 'scripts/musl_legacy_framework_il_inputs.py')
F = importlib.util.module_from_spec(spec); spec.loader.exec_module(F)


class FrameworkImplementationSourceBoundaryTests(unittest.TestCase):
    def test_original_token_endianness_and_switch_continuations_are_preserved(self):
        methods = F.parse_il_methods(b''' .method /*06000001*/ public static void A() cil managed
// Method begins at RVA 0x2050
// Code size 15
.maxstack 8
IL_0000: /* 28 | (0A)000030 */ call void A()
IL_0005: /* 45 | 01000000 */ switch (
          /*    | 00000000 */ IL_000e)
IL_000e: /* 2A | */ ret
// end of method X::A
''')
        self.assertEqual(methods[0x06000001]['body'], bytes.fromhex('283000000a4501000000000000002a'))
        self.assertEqual(methods[0x06000001]['rva'], 0x2050)

    def test_duplicate_methods_and_instruction_gaps_are_rejected(self):
        for raw in [b'.method /*06000001*/ A\n.method /*06000001*/ B',
                    b'.method /*06000001*/ A\nIL_0002: /* 2A | */ ret\n// end of method A']:
            with self.assertRaises(ValueError): F.parse_il_methods(raw)

    def test_no_resource_deserialization_or_external_xml_entities(self):
        for raw in [b'opaque serialized binary',
                    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>']:
            with self.assertRaises(ValueError): F.resource_value(raw)
        value = b'<?xml version="1.0"?><Directives><Application><Type Name="Exact.Type" /></Application></Directives>'
        self.assertEqual(F.resource_value(value), dict(kind='xml', text=value.decode()))

    def test_closed_policy_keeps_real_implementations_separate_from_facades(self):
        p = F.policy()
        self.assertEqual(sum(row['methodBodies'] for row in p['layout']), 5289)
        self.assertEqual(sum(len(row['resources']) for row in p['layout']), 22)
        self.assertTrue(all(row['methodBodies'] > 0 for row in p['layout']))
        self.assertFalse(p['originalCSharpSourceRecovered'])
        self.assertFalse(p['localBuildClaimed'])


if __name__ == '__main__': unittest.main()
