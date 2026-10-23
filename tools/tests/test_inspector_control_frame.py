# SPDX-License-Identifier: BSD-3-Clause
"""Eight bounded ordinary host codec traces, no inspector or native operations."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Independent pre-code literal, not output from a production encoder.
STOP = ("41474354524c310a0100000000000000"
        "3030303030303030303030303030303030303030303030303030303030303030"
        "00000000000000010000000000000000")


class InspectorControlFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fresh retained build fixtures; no historical file/directory is removed.
        cls.build = Path(tempfile.mkdtemp(prefix='control-frame-', dir=ROOT / '.tools'))
        cls.binary = cls.build / 'control-frame-harness'
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-I', str(ROOT / 'internal/inspectorowner'),
            str(ROOT / 'internal/inspectorowner/controller.c'),
            str(ROOT / 'internal/inspectorowner/control_frame.c'),
            str(ROOT / 'tools/tests/fixtures/inspector-control-frame-harness.c'),
            '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def test_fixed_literal_retirement_traces(self):
        # rc, acknowledgment, unsafe fault, clock fault, existing target enum.
        cases = {
            'valid99': (0, 1, 0, 0, 1),
            'late100': (2, 0, 1, 0, 1),
            'miss4000': (2, 0, 1, 0, 3),
            'backward': (2, 0, 1, 1, 4),
            'reserved': (1, 0, 1, 0, 1),
            'stale': (1, 0, 1, 0, 1),
            'priorAck': (2, 1, 0, 0, 1),
            'short': (1, 0, 1, 0, 1),
        }
        self.assertEqual(len(cases), 8)
        for mode, expected in cases.items():
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.binary), mode], capture_output=True,
                                        text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0, result.stderr[:8192])
                self.assertFalse(result.stderr)
                self.assertLess(len(result.stdout), 4096)
                row = json.loads(result.stdout)
                self.assertEqual([row[k] for k in ('pre', 'absent', 'nullout', 'first', 'second', 'zero')], [2, 2, 1, 0, 2, 1])
                self.assertEqual(row['stop'], STOP)
                self.assertEqual(tuple(row[k] for k in ('accepted', 'ack', 'unsafe', 'clock', 'target')), expected)
                self.assertEqual(row['duplicate'], 2)
                for name in ('ack', 'unsafe', 'clock', 'target'):
                    self.assertEqual(row['dup_' + name], row[name])
                self.assertEqual([row[k] for k in ('held', 'requests', 'sockets', 'known', 'terminal', 'closed')], [1, 4, 8, 1, 0, 0])
