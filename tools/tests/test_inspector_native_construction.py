# SPDX-License-Identifier: BSD-3-Clause
"""Fixed C OS-boundary interception: no true host descriptors/identity effects."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Independent pre-code literal trace: synthetic IDs123/456 are not service IDs.
PREPARE = ['pair', 'null', 'stat:1', 'high:0', 'close:0', 'high:3',
           'close:3', 'high:1', 'close:1']
CHILD = ['dup:5:3', 'dup:6:0', 'dup:6:1', 'dup:6:2', 'getfd:3', 'getfl:3',
         'closefrom:4', 'groups:0', 'gid:456', 'uid:123', 'getgroups', 'getgid', 'getuid']
PARENT = ['close:5', 'close:6']
BASELINE = PREPARE + CHILD


class InspectorNativeConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fresh fixtures retained in the permitted tree. All compiler temp I/O is
        # redirected here from the first attempt, never the denied system path.
        cls.build = Path(tempfile.mkdtemp(prefix='native-construction-', dir=ROOT / '.tools'))
        cls.binary = cls.build / 'native-construction-harness'
        import os
        cls.env = dict(os.environ, TMPDIR=str(cls.build))
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DAEG_NATIVE_TEST', '-include', str(ROOT / 'tools/tests/fixtures/inspector-native-ops.h'),
            '-I', str(ROOT / 'internal/inspectorowner'),
            str(ROOT / 'internal/inspectorowner/controller.c'),
            str(ROOT / 'internal/inspectorowner/native_construction.c'),
            str(ROOT / 'internal/inspectorowner/native_openbsd.c'),
            str(ROOT / 'tools/tests/fixtures/inspector-native-harness.c'),
            '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=30, check=False, env=cls.env)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def run_mode(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True,
                                text=True, timeout=5, check=False, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr[:8192])
        self.assertFalse(result.stderr)
        self.assertLess(len(result.stdout), 8192)
        row = json.loads(result.stdout)
        self.assertEqual(row['bad'], 0)
        self.assertEqual(row['duplicates'], [2, 2, 2])
        self.assertEqual(row['duplicate_calls'], 0)
        self.assertLessEqual(row['peak'], 7)
        self.assertTrue(row['attempted'])
        if mode in ('controller', 'unprepared'):
            self.assertEqual(row['owner'], [0, 0, 0, 0, 0, 0])
        else:
            self.assertEqual(row['owner'], [2, 1, 4, 8, 0, 0])
        return row

    def test_fixed_intercepted_modes(self):
        semantic = ['zero-uid', 'minus-uid', 'zero-gid', 'minus-gid',
                    'pair-negative', 'pair-alias', 'open-alias', 'dup-alias',
                    'dup-target', 'nonchar', 'cloexec', 'blocking', 'groups-nonzero',
                    'gid0', 'gid1', 'gid2', 'uid0', 'uid1', 'uid2',
                    'controller', 'unprepared', 'allocation2']
        modes = ['child', 'parent'] + [f'fail-{n}' for n in range(1, 23)] + semantic + ['parent-fail-10', 'parent-fail-11']
        self.assertEqual(len(modes), 48)
        for mode in modes:
            with self.subTest(mode=mode):
                row = self.run_mode(mode)
                trace = row['trace']
                if mode == 'child':
                    self.assertEqual(trace, BASELINE)
                    self.assertEqual((row['prepare'], row['branch'], row['phase'], row['identity'], row['known'], row['uncertain']), (0, 0, 3, 1, 4, 0))
                elif mode == 'parent':
                    self.assertEqual(trace, PREPARE + PARENT)
                    self.assertEqual((row['prepare'], row['branch'], row['phase'], row['identity'], row['known'], row['uncertain']), (0, 0, 2, 0, 1, 0))
                elif mode == 'allocation2':
                    self.assertEqual(trace, ['pair', 'null', 'stat:1', 'high:2', 'close:2', 'high:0', 'close:0', 'high:1', 'close:1'] + CHILD)
                    self.assertEqual((row['branch'], row['phase'], row['identity'], row['known']), (0, 3, 1, 4))
                elif mode.startswith('fail-'):
                    n = int(mode[5:])
                    self.assertEqual(trace[:n], BASELINE[:n])
                    if n >= 16 or n in (1, 5, 7, 9):
                        self.assertEqual(len(trace), n)
                    else:
                        # The only permitted post-fault calls close independently
                        # owned source receipts; fixed sets, no failed-FD retry.
                        owned = {2: {0, 3}, 3: {0, 3, 1}, 4: {0, 3, 1},
                                 6: {4, 3, 1}, 8: {4, 5, 1},
                                 10: {4, 5, 6}, 11: {4, 5, 6}, 12: {4, 5, 6},
                                 13: {4, 5, 6}, 14: {4, 5, 6}, 15: {4, 5, 6}}[n]
                        self.assertEqual(set(trace[n:]), {f'close:{fd}' for fd in owned})
                        self.assertEqual(len(trace[n:]), len(owned))
                    self.assertEqual(row['phase'], 4)
                    self.assertFalse(row['identity'])
                    self.assertIn(row['prepare'] if n <= 9 else row['branch'], (3, 4))
                elif mode in ('zero-uid', 'minus-uid', 'zero-gid', 'minus-gid'):
                    self.assertEqual(trace, PREPARE)
                    self.assertEqual((row['branch'], row['phase'], row['identity'], row['known']), (1, 4, 0, 3))
                elif mode in ('pair-negative', 'pair-alias'):
                    self.assertEqual(trace, ['pair'])
                    self.assertEqual((row['prepare'], row['phase'], row['uncertain']), (4, 4, 1))
                elif mode == 'open-alias':
                    self.assertEqual(trace, ['pair', 'null'])
                    self.assertEqual((row['prepare'], row['phase'], row['uncertain']), (4, 4, 1))
                elif mode == 'dup-alias':
                    self.assertEqual(trace, PREPARE[:4])
                    self.assertEqual((row['prepare'], row['phase'], row['uncertain']), (4, 4, 1))
                elif mode == 'dup-target':
                    self.assertEqual(trace, BASELINE[:10])
                    self.assertEqual((row['branch'], row['phase'], row['uncertain']), (4, 4, 1))
                elif mode == 'nonchar':
                    self.assertEqual(trace[:3], PREPARE[:3])
                    self.assertEqual(set(trace[3:]), {'close:0', 'close:3', 'close:1'})
                    self.assertEqual(len(trace), 6)
                    self.assertEqual(row['prepare'], 3)
                elif mode in ('cloexec', 'blocking'):
                    n = 14 if mode == 'cloexec' else 15
                    self.assertEqual(trace[:n], BASELINE[:n])
                    self.assertEqual(set(trace[n:]), {'close:4', 'close:5', 'close:6'})
                    self.assertEqual(row['branch'], 3)
                elif mode == 'groups-nonzero' or mode.startswith('gid') or mode.startswith('uid'):
                    n = 20 if mode == 'groups-nonzero' else (21 if mode.startswith('gid') else 22)
                    self.assertEqual(trace, BASELINE[:n])
                    self.assertEqual((row['branch'], row['phase'], row['identity'], row['uncertain'], row['known']), (4, 4, 0, 1, 4))
                elif mode in ('controller', 'unprepared'):
                    self.assertEqual(trace, [])
                    self.assertEqual(row['phase'], 4)
                else:
                    self.assertIn(mode, ('parent-fail-10', 'parent-fail-11'))
                    self.assertEqual(trace, PREPARE + PARENT)
                    self.assertEqual((row['branch'], row['phase'], row['identity'], row['uncertain']), (4, 4, 0, 1))
