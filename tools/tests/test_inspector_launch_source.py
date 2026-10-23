# SPDX-License-Identifier: BSD-3-Clause
"""Actual C source lifecycle under fixed interception; no product effects."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InspectorLaunchSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='inspector-source-', dir=ROOT / '.tools'))
        cls.binary = cls.work / 'intercepted-start'
        cls.env = dict(os.environ, TMPDIR=str(cls.work))
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DAEG_NATIVE_TEST', '-DAEG_STORAGE_FIXTURE', '-DAEG_INSPECTOR_SOURCE',
            '-include', str(ROOT / 'tools/tests/fixtures/inspector-native-ops.h'),
            '-I', str(ROOT / 'internal/inspectorowner'),
            str(ROOT / 'internal/inspectorowner/controller.c'),
            str(ROOT / 'internal/inspectorowner/control_frame.c'),
            str(ROOT / 'internal/inspectorowner/native_construction.c'),
            str(ROOT / 'internal/inspectorowner/native_openbsd.c'),
            str(ROOT / 'tools/tests/fixtures/inspector-launch-harness.c'),
            '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=30, check=False, env=cls.env)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def run_mode(self, name):
        r = subprocess.run([str(self.binary), 'source-'+name], capture_output=True,
                           text=True, timeout=5, check=False, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr[:2048])
        self.assertFalse(r.stderr)
        self.assertLess(len(r.stdout), 4096)
        row = json.loads(r.stdout)
        self.assertEqual(row['bad'], 0)
        self.assertEqual(row['forks'], 1)
        return row

    def test_same_child_lifecycle_and_retention(self):
        for name in ['normal', 'fragments', 'bad-start', 'short-stop', 'late-ack', 'close-error', 'missing', 'denied']:
            with self.subTest(name=name):
                row = self.run_mode(name)
                self.assertEqual(row['spawn'], 0)
                self.assertEqual(row['start'], 4 if name == 'bad-start' else 0)
                self.assertEqual(row['kills'], 1)
                self.assertEqual(row['signal_pid'], 321)
                self.assertEqual(row['signal_result'], 2 if name == 'missing' else 3 if name == 'denied' else 1)
                self.assertTrue(row['held_after_kill'])
                self.assertEqual(row['terminal'], 2)
                self.assertFalse(row['known'])
                if name == 'close-error':
                    self.assertEqual((row['close'], row['again'], row['held']), (4, 2, 1))
                    self.assertTrue(row['uncertain'])
                else:
                    self.assertEqual((row['close'], row['again'], row['held']), (0, 2, 0))
                    self.assertEqual(row['target'], 2)
                self.assertEqual(row['ack'], int(name in ('normal', 'fragments', 'close-error', 'missing', 'denied')))
                self.assertEqual(row['stop_sends'], 0 if name == 'bad-start' else 1)

    def test_no_child_clock_fault_identity_loss_and_child_exit(self):
        row = self.run_mode('fork-error')
        self.assertEqual((row['spawn'],row['close'],row['terminal'],row['held'],row['kills']), (3,0,1,0,0))
        row = self.run_mode('clock')
        self.assertEqual((row['spawn'],row['phase'],row['held'],row['known'],row['kills']), (4,2,1,1,1))
        for name in ['lost', 'wrong-pid']:
            row = self.run_mode(name)
            self.assertEqual((row['wait'],row['tick'],row['held'],row['known'],row['kills']), (4,2,1,0,0))
        row = self.run_mode('child')
        self.assertEqual((row['execs'],row['exits'],row['phase'],row['known'],row['kills']), (1,1,3,0,0))


if __name__ == '__main__':
    unittest.main()
