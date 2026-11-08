"""Reject unbound or replaced local FROM parents before a derived image build."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from musl_local_image import bind_parent


class LocalParentBoundary(unittest.TestCase):
    def fixture(self, replacement=None):
        image = 'sha256:' + 'a' * 64
        calls = []
        def run(command, capture=False):
            calls.append(command)
            if capture:
                return json.dumps([dict(Id=replacement if len(calls) == 3 and replacement else image,
                                        Architecture='arm64', Os='linux')])
        return SimpleNamespace(args=SimpleNamespace(run_id='123', arch='aarch64'),
            engine=['docker'], id=dict(image='arm64'), run=run), image, calls

    def test_local_tag_resolves_the_same_id_and_execution_identity_stays_immutable(self):
        producer, image, calls = self.fixture()
        tag = bind_parent(producer, image, 'runtime')
        self.assertTrue(tag.startswith('localhost/cbodotnet-musl-parent:123-aarch64-runtime-'))
        self.assertEqual(['docker', 'image', 'tag', image, tag], calls[1])
        self.assertEqual(['docker', 'image', 'inspect', image], calls[0])
        self.assertEqual(['docker', 'image', 'inspect', tag], calls[2])

    def test_replaced_parent_tag_cannot_supply_a_different_image(self):
        producer, image, _ = self.fixture('sha256:' + 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'exact inspected immutable'):
            bind_parent(producer, image, 'builder')

    def test_external_names_and_unscoped_roles_are_rejected(self):
        for image, role in [('alpine:latest', 'builder'), ('sha256:' + 'a' * 64, '../builder')]:
            producer, _, calls = self.fixture()
            with self.assertRaises(ValueError):
                bind_parent(producer, image, role)
            self.assertEqual([], calls)
