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
# Frozen image prefix: append after original intentClose, before U encoding.
IMAGE_PREFIX = ['pin:43', 'stat:46', 'path-pin:43', 'read:46:65', 'stat:46',
                'path-pin:43', 'close:46', 'image-root', 'stat:47', 'usr:47',
                'stat:48', 'close:47', 'local:48', 'stat:49', 'close:48',
                'libexec:49', 'stat:50', 'close:49', 'image-dir:50', 'stat:51',
                'close:50', 'image:51', 'stat:52', 'path-image:51', 'sha-init',
                'image-read:0:4096', 'sha-update:4096', 'image-read:4096:17',
                'sha-update:17', 'image-read:4113:1', 'sha-final', 'stat:52',
                'path-image:51', 'close:52', 'close:51']
STORAGE = STORAGE[:25] + IMAGE_PREFIX + STORAGE[25:]
PAIR = ['pair', 'null', 'stat:1', 'high:0', 'close:0', 'high:3', 'close:3', 'high:1', 'close:1']
BASELINE = STORAGE + PAIR
# Reviewer-derived literal outputs; not computed with the production encoder/hash.
U1 = '4145474f574e310a55000000000000003030303030303030303030303030303030303030303030303030303030303031a93801f9a665510e0ca24b6ba66c79c618252890d9722850002fe1ef4eef86bb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
UFF = '4145474f574e310a55000000000000006666666666666666666666666666666666666666666666666666666666666666105c28a634df45fa0e2bf6d9b38cef5b64d493da5aaf9c504538199c18b47492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
# Every non-void OS edge on the success trace. SHA's base API is void: the
# separate mismatch case tests digest refusal; interception checks both48 inputs.
FAIL_EDGES = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,21,22,23,24,25,
              65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
              26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,
              45,46,47,48,49,51,53,55,57,58,59,60]
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
    'write-1':65, 'write0':65, 'write127':65, 'write129':65,
    'write-full-error':65, 'readback':67, 'post-inode':69,
    'intent-mismatch':24, 'intent-upper':24, 'intent-lf':24, 'intent-short':24,
    'root-invalid':1, 'dir-alias':3, 'state-alias':12, 'intent-alias':21,
    'clock-negative':71, 'clock-nsec':71, 'controller-late':71,
    'owner-prestate':0, 'native-prestate':0,
    'pin-uid':27, 'pin-gid':27, 'pin-type':27, 'pin-mode':27,
    'pin-link':27, 'pin-size':27, 'pin-alias':26, 'pin-path':28,
    'pin-zero':29, 'pin-short':29, 'pin-over':29, 'pin-upper':29,
    'pin-nonhex':29, 'pin-lf':29, 'pin-post-inode':31, 'pin-digest':56,
    'image-dir-uid':36, 'image-dir-write':36, 'image-dir-type':36,
    'image-dir-search':36, 'image-dir-alias':35,
    'image-uid':49, 'image-gid':49, 'image-type':49, 'image-mode':49,
    'image-link':49, 'image-size':49, 'image-cap':49, 'image-alias':47,
    'image-path':49, 'image-path-link':49, 'image-post-inode':58, 'image-post-size':58,
    'image-first-negative':51, 'image-first-zero':51, 'image-first-short':51,
    'image-first-over':51, 'image-tail-negative':53, 'image-tail-zero':53,
    'image-tail-short':53, 'image-tail-over':53,
    'image-eof-negative':55, 'image-eof-data':55, 'image-data':56, 'image-digest':56,
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
        self.assertLessEqual(row['known'], 4)
        return row

    def test_fixed_storage_and_construction(self):
        modes = ['launch', 'edge', 'update', 'reentrant'] + [f'fail-{n}' for n in FAIL_EDGES] + list(CUTOFF)
        self.assertEqual(len(modes), 172)
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
                    if n in (73,74,75,77,79):
                        expected={73:{0,3},74:{0,3,1},75:{0,3,1},77:{4,3,1},79:{4,5,1}}[n]
                        self.assertEqual(set(trace[n:]),{f'close:{fd}' for fd in expected})
                        self.assertEqual(len(trace[n:]),len(expected))
                    else:
                        self.assertEqual(len(trace),n)
                    self.assertNotEqual(r['rc'],0)
                    self.assertEqual(r['phase'],1)
                    self.assertTrue(r['uncertain'])
                    self.assertEqual(r['committed'],n>=70)
                    self.assertEqual(r['owner'],2 if n>=72 else 0)
                    if n>=70:
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
                    if mode.startswith(('pin-','image-')):
                        self.assertEqual((r['writes'],r['committed'],r['owner'],r['native']),(0,0,0,0))
                        self.assertTrue(r['lock'])
