# SPDX-License-Identifier: BSD-3-Clause
"""Bounded actual C diagnostics under fixed interception, no host socket/signal."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InspectorDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='diagnostics-', dir=ROOT / '.tools'))
        cls.binary = cls.work / 'intercepted-diagnostics'
        cls.env = dict(os.environ, TMPDIR=str(cls.work))
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DAEG_NATIVE_TEST', '-DAEG_STORAGE_FIXTURE', '-DAEG_INSPECTOR_SOURCE',
            '-DAEG_DIAGNOSTIC_FIXTURE', '-include', str(ROOT / 'tools/tests/fixtures/inspector-native-ops.h'),
            '-I', str(ROOT / 'internal/inspectorowner'),
            *[str(ROOT / 'internal/inspectorowner' / n) for n in
              ['controller.c', 'control_frame.c', 'native_construction.c', 'native_openbsd.c']],
            str(ROOT / 'tools/tests/fixtures/inspector-diagnostics-harness.c'),
            '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=30, check=False, env=cls.env)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def run_mode(self, name):
        r = subprocess.run([str(self.binary), name], capture_output=True,
                           text=True, timeout=5, check=False, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr[:2048])
        self.assertFalse(r.stderr)
        self.assertLess(len(r.stdout), 4096)
        row = json.loads(r.stdout)
        self.assertEqual(row['bad'], 0)
        self.assertLessEqual(row['peak'], 6)
        self.assertLessEqual(row['receives'], 4)
        self.assertLessEqual(row['logs'], 4)
        return row

    def test_finite_delivery_validation_and_loss(self):
        for name in ['normal', 'gap', 'duplicate', 'idle', 'read-error', 'connect-error',
                     'log-error', 'log-short', 'magic', 'reserved', 'flags', 'result',
                     'prejob', 'zero', 'short', 'oversize']:
            with self.subTest(name=name):
                r = self.run_mode(name)
                self.assertEqual((r['close'], r['again'], r['known']), (0, 2, 0))
                self.assertEqual((r['close_reader'], r['close_log']), (1, 1))
                if name in ['normal', 'gap', 'log-error', 'log-short', 'connect-error']:
                    self.assertEqual(r['seq'], 6 if name == 'gap' else 4)
                    self.assertEqual(r['missing'], 2 if name == 'gap' else 0)
                    self.assertEqual(r['logs'], 0 if name == 'connect-error' else 4)
                    self.assertEqual(r['sink_lost'], 4 if name in ['connect-error', 'log-error', 'log-short'] else 0)
                elif name == 'duplicate':
                    self.assertEqual((r['seq'], r['invalid'], r['logs']), (1, 3, 1))
                elif name in ['idle', 'read-error']:
                    self.assertEqual((r['receives'], r['invalid'], r['logs']), (1, int(name == 'read-error'), 0))
                else:
                    self.assertEqual((r['seq'], r['invalid'], r['logs']), (0, 4, 0))

    def test_stop_terminal_loss_and_once_close_ownership(self):
        for name in ['stop', 'terminal', 'lost', 'close-reader', 'close-log']:
            with self.subTest(name=name):
                r = self.run_mode(name)
                if name in ['stop', 'terminal', 'lost']:
                    self.assertEqual((r['receives'], r['logs']), (0, 0))
                if name == 'lost':
                    self.assertEqual((r['close'], r['close_reader'], r['close_log']), (2, 0, 0))
                    self.assertEqual(r['known'], 3)
                elif name in ['close-reader', 'close-log']:
                    self.assertEqual((r['close'], r['again'], r['uncertain']), (4, 2, 1))
                    self.assertEqual((r['close_reader'], r['close_log']), (1, 1))
                    self.assertEqual(r['known'], 1)
                else:
                    self.assertEqual((r['close'], r['again'], r['known']), (0, 2, 0))


if __name__ == '__main__':
    unittest.main()
