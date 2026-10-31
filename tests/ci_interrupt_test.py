#!/usr/bin/env python3
"""An interrupted stage must never leave a passed receipt."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ci_interrupt_driver', ROOT / 'scripts/ci-net67.py')
DRIVER = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(DRIVER)


class InterruptionTests(unittest.TestCase):
    def test_keyboard_interrupt_retains_failed_receipt(self):
        run = SimpleNamespace(build=mock.Mock(side_effect=KeyboardInterrupt), finish=mock.Mock())
        arguments = ['ci-net67.py', '6', 'build', '--workspace', '/fixture/work', '--output-dir', '/fixture/release',
                     '--build-id', '20261031.1', '--build-revision', '123']
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(DRIVER, 'Run', return_value=run):
            with self.assertRaises(KeyboardInterrupt):
                DRIVER.main()
        run.finish.assert_called_once_with(1)

    def test_completed_stage_can_write_a_passed_receipt(self):
        run = SimpleNamespace(build=mock.Mock(), finish=mock.Mock())
        arguments = ['ci-net67.py', '6', 'build', '--workspace', '/fixture/work', '--output-dir', '/fixture/release',
                     '--build-id', '20261031.1', '--build-revision', '123']
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(DRIVER, 'Run', return_value=run):
            self.assertEqual(DRIVER.main(), 0)
        run.finish.assert_called_once_with(0)


if __name__ == '__main__': unittest.main()
