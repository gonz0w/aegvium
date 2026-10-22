# SPDX-License-Identifier: BSD-3-Clause
"""Real source wrappers under fixed interception, no host subject operations."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Independent pre-code syscall/SHA order, not obtained from product execution.
STORAGE = ['root', 'stat:40', 'var:40', 'stat:41', 'close:40', 'db:41',
           'stat:42', 'close:41', 'aegvium:42', 'stat:43', 'close:42',
           'state:43', 'lock:44', 'stat:44', 'path-state:43', 'read:44:128',
           'sha-init', 'sha-update:48', 'sha-update:48', 'sha-final',
           'intent:43', 'stat:45', 'path-intent:43', 'read:45:33', 'close:45',
           'sha-init', 'sha-update:48', 'sha-update:48', 'sha-final',
           'write:44', 'sync:44', 'read:44:128', 'stat:44', 'path-state:43',
           'close:43', 'clock']
PAIR = ['pair', 'null', 'stat:1', 'high:0', 'close:0', 'high:3', 'close:3', 'high:1', 'close:1']
BASELINE = STORAGE + PAIR
# Reviewer-derived literal outputs; not computed with the production encoder/hash.
U1 = '4145474f574e310a55000000000000003030303030303030303030303030303030303030303030303030303030303031a93801f9a665510e0ca24b6ba66c79c618252890d9722850002fe1ef4eef86bb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
UFF = '4145474f574e310a55000000000000006666666666666666666666666666666666666666666666666666666666666666105c28a634df45fa0e2bf6d9b38cef5b64d493da5aaf9c504538199c18b47492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
# Every non-void OS edge on the success trace. SHA's base API is void: the
# separate mismatch case tests digest refusal; interception checks both48 inputs.
FAIL_EDGES = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,21,22,23,24,25,
              30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45]
CUTOFF = {
    'root-uid':2, 'dir-uid':4, 'dir-write':4, 'dir-type':4,
    'state-uid':14, 'state-gid':14, 'state-type':14, 'state-mode':14,
    'state-link':14, 'state-size':14, 'path-dev':15, 'path-inode':15, 'path-mode':15,
    'intent-uid':22, 'intent-gid':22, 'intent-type':22, 'intent-mode':22,
    'intent-link':22, 'intent-size':22, 'intent-dev':23,
    'magic':16, 'state-tag':16, 'reserved':16, 'uppercase':16, 'suffix':16,
    'digest':20, 'hash-mismatch':20, 'unclean':20, 'unclean-zero':16,
    'nowrap':20, 'update-unclean':20,
    'read-1':16, 'read0':16, 'read127':16, 'read129':16,
    'write-1':30, 'write0':30, 'write127':30, 'write129':30,
    'write-full-error':30, 'readback':32, 'post-inode':34,
    'intent-mismatch':24, 'intent-upper':24, 'intent-lf':24, 'intent-short':24,
    'root-invalid':1, 'dir-alias':3, 'state-alias':12, 'intent-alias':21,
    'clock-negative':36, 'clock-nsec':36, 'controller-late':36,
    'owner-prestate':0, 'native-prestate':0,
}


class InspectorLaunchStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = Path(tempfile.mkdtemp(prefix='launch-storage-', dir=ROOT / '.tools'))
        cls.binary = cls.build / 'launch-storage-harness'
        cls.env = dict(os.environ, TMPDIR=str(cls.build))
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DAEG_NATIVE_TEST', '-include', str(ROOT / 'tools/tests/fixtures/inspector-storage-ops.h'),
            '-I', str(ROOT / 'internal/inspectorowner'),
            str(ROOT / 'internal/inspectorowner/controller.c'),
            str(ROOT / 'internal/inspectorowner/native_construction.c'),
            str(ROOT / 'internal/inspectorowner/native_openbsd.c'),
            str(ROOT / 'internal/inspectorowner/launch_storage.c'),
            str(ROOT / 'internal/inspectorowner/storage_openbsd.c'),
            str(ROOT / 'tools/tests/fixtures/inspector-storage-harness.c'),
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
        self.assertEqual(row['duplicates'], [1,1])
        self.assertEqual(row['duplicate_calls'], 0)
        self.assertTrue(row['attempted'])
        self.assertLessEqual(row['known'], 3)
        return row

    def test_fixed_storage_and_construction(self):
        modes = ['launch', 'edge', 'update', 'reentrant'] + [f'fail-{n}' for n in FAIL_EDGES] + list(CUTOFF)
        self.assertEqual(len(modes), 96)
        for mode in modes:
            with self.subTest(mode=mode):
                r = self.run_mode(mode)
                trace = r['trace']
                if mode in ('launch','edge','reentrant'):
                    self.assertEqual(trace, BASELINE)
                    self.assertEqual((r['rc'],r['phase'],r['committed'],r['uncertain'],r['known'],r['owner'],r['native']), (0,2,1,0,1,2,1))
                    self.assertEqual(r['disk'], UFF if mode=='edge' else U1)
                    self.assertEqual(r['writes'],1)
                    self.assertEqual(r['reentrant'],1 if mode=='reentrant' else -1)
                elif mode=='update':
                    self.assertEqual(trace, STORAGE[:20]+['close:43'])
                    self.assertEqual((r['rc'],r['phase'],r['committed'],r['known'],r['owner'],r['native'],r['writes']), (0,3,0,1,0,0,0))
                elif mode.startswith('fail-'):
                    n=int(mode[5:])
                    self.assertEqual(trace[:n],BASELINE[:n])
                    if n in (38,39,40,42,44):
                        expected={38:{0,3},39:{0,3,1},40:{0,3,1},42:{4,3,1},44:{4,5,1}}[n]
                        self.assertEqual(set(trace[n:]),{f'close:{fd}' for fd in expected})
                        self.assertEqual(len(trace[n:]),len(expected))
                    else:
                        self.assertEqual(len(trace),n)
                    self.assertNotEqual(r['rc'],0)
                    self.assertEqual(r['phase'],1)
                    self.assertTrue(r['uncertain'])
                    self.assertEqual(r['committed'],n>=35)
                    self.assertEqual(r['owner'],2 if n>=37 else 0)
                    if n>=35:
                        self.assertEqual(r['disk'],U1)
                else:
                    self.assertEqual(trace, BASELINE[:CUTOFF[mode]])
                    self.assertNotEqual(r['rc'],0)
                    self.assertEqual(r['phase'],1)
                    self.assertTrue(r['uncertain'])
                    self.assertEqual(r['committed'],mode in ('clock-negative','clock-nsec','controller-late'))
                    self.assertEqual(r['owner'],2 if mode in ('owner-prestate','controller-late') else 0)
                    if mode=='write-full-error':
                        self.assertEqual(r['disk'],U1)
                        self.assertFalse(r['committed'])
                    if mode in ('clock-negative','clock-nsec','controller-late'):
                        self.assertEqual(r['disk'],U1)
                    self.assertEqual(r['native'],4 if mode=='native-prestate' else 0)
