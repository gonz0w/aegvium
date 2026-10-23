# SPDX-License-Identifier: BSD-3-Clause
"""Same-source wait/close -> same locked checkpoint; every subject effect faked."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tools/tests/fixtures'
VECTORS = json.loads((FIXTURES / 'inspector-normal-clean.json').read_text())['vectors']
# Frozen before test execution, independently of implementation-produced traces.
CLEAN = ['clean-root', 'stat:40', 'var:40', 'stat:41', 'close:40', 'db:41',
         'stat:42', 'close:41', 'aegvium:42', 'stat:43', 'close:42',
         'stat:44', 'path-state:43', 'read:44:128', 'stat:44', 'path-state:43',
         'sha-init', 'sha-update:48', 'sha-update:48', 'sha-final',
         'write:44', 'sync:44', 'read:44:128', 'stat:44', 'path-state:43', 'close:43']
FAIL_EDGES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
              21, 22, 23, 24, 25, 26]


class InspectorNormalCleanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='normal-clean-', dir=ROOT / '.tools'))
        cls.env = dict(os.environ, TMPDIR=str(cls.work))
        cls.binary = cls.work / 'normal-clean'
        cls.gate = cls.work / 'source-gate'
        common = ['/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                  '-DAEG_INSPECTOR_SOURCE', '-I', str(ROOT / 'internal/inspectorowner')]
        cls.compile(common + ['-DAEG_NATIVE_TEST', '-DAEG_STORAGE_FIXTURE', '-include',
                    str(FIXTURES / 'inspector-storage-ops.h'),
                    *[str(ROOT / 'internal/inspectorowner' / name) for name in
                      ['controller.c', 'control_frame.c', 'native_construction.c',
                       'native_openbsd.c', 'launch_storage.c', 'storage_openbsd.c']],
                    str(FIXTURES / 'inspector-normal-clean-harness.c'), '-o', str(cls.binary)])
        cls.compile(common + ['-D_POSIX_C_SOURCE=200809L',
                              str(FIXTURES / 'inspector-supervisor-gate.c'), '-o', str(cls.gate)])

    @classmethod
    def compile(cls, args):
        r = subprocess.run(args, capture_output=True, text=True, timeout=30,
                           check=False, env=cls.env)
        if r.returncode:
            raise AssertionError(r.stderr[:8192])

    def run_case(self, name):
        r = subprocess.run([str(self.binary), name], capture_output=True, text=True,
                           timeout=5, check=False, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr[:4096])
        self.assertFalse(r.stderr)
        self.assertLess(len(r.stdout), 8192)
        row = json.loads(r.stdout)
        self.assertEqual(row['bad'], 0)
        self.assertEqual(row['again'], 2)
        self.assertEqual(row['duplicate_calls'], 0)
        self.assertEqual(row['kills'], 0)
        self.assertLessEqual(row['known'], 4)
        return row

    def test_actual_terminal_closure_settles_same_burned_generation(self):
        for name, vector in zip(['vector-one', 'vector-nontrivial', 'vector-maximum'], VECTORS):
            with self.subTest(name=name):
                row = self.run_case(name)
                self.assertEqual((row['rc'], row['settled'], row['writes'], row['reads'],
                                  row['known'], row['uncertain']), (0, 1, 2, 4, 1, 0))
                self.assertEqual(row['trace'], CLEAN)
                self.assertEqual(row['disk'], vector['expected_C_same_generation_hex'])
                self.assertEqual(bytes.fromhex(row['disk'])[16:48].decode(), vector['generation'])
                self.assertEqual((row['forks'], row['waits'], row['closed']), (1, 1, 0))

    def test_physical_cleanup_is_independent_of_diagnostic_or_timing_success(self):
        for name, terminal, target in [('native-nochild', 1, 0), ('native-signaled', 3, 0),
                                       ('native-late', 2, 3), ('native-clock', 2, 4)]:
            with self.subTest(name=name):
                row = self.run_case(name)
                self.assertEqual((row['rc'], row['settled'], row['terminal'], row['target']),
                                 (0, 1, terminal, target))
                self.assertEqual(row['disk'], VECTORS[0]['expected_C_same_generation_hex'])
                self.assertEqual(row['trace'], CLEAN)
                if name == 'native-clock':
                    self.assertTrue(row['clock_fault'])
                    self.assertNotEqual(row['closed'], 0)

    def test_nonterminal_lost_or_uncertain_physical_ownership_never_calls_writer(self):
        for name in ['native-empty', 'native-view', 'native-pending', 'native-stopped',
                     'native-interrupt', 'native-lost', 'native-wrong',
                     'native-close-error', 'native-early']:
            with self.subTest(name=name):
                row = self.run_case(name)
                self.assertEqual((row['rc'], row['settled'], row['trace']), (2, 0, []))
                self.assertEqual(row['writes'], 0 if name == 'native-empty' else 1)
                if name != 'native-empty':
                    self.assertEqual(row['disk'], VECTORS[0]['known_U_hex'])

    def test_every_nonvoid_storage_failure_is_once_only_and_uncertain(self):
        for edge in FAIL_EDGES:
            with self.subTest(edge=edge):
                row = self.run_case(f'clean-fail-{edge}')
                self.assertEqual((row['rc'], row['settled'], row['uncertain']), (4, 0, 1))
                self.assertEqual(row['trace'], CLEAN[:edge])
                self.assertLessEqual(row['writes'], 2)
                if edge <= 21:
                    self.assertEqual(row['disk'], VECTORS[0]['known_U_hex'])
                else:
                    self.assertEqual(row['disk'], VECTORS[0]['expected_C_same_generation_hex'])

    def test_malformed_drift_and_partial_commit_never_become_known_clean(self):
        before_write = ['root-alias', 'root-uid', 'dir-uid', 'dir-write', 'dir-type',
                        'state-uid', 'state-gid', 'state-mode', 'state-type', 'state-link',
                        'state-size', 'path-dev', 'path-inode', 'path-mode', 'bytes',
                        'read-1', 'read0', 'read127', 'read129']
        after_attempt = ['write-1', 'write0', 'write127', 'write129', 'write-full-error',
                         'readback', 'post-inode', 'post-read-negative',
                         'post-read-short', 'post-read-over']
        for suffix in before_write + after_attempt:
            with self.subTest(suffix=suffix):
                row = self.run_case('clean-' + suffix)
                self.assertNotEqual(row['rc'], 0)
                self.assertEqual((row['settled'], row['uncertain']), (0, 1))
                self.assertEqual(row['writes'], 1 if suffix in before_write else 2)
                self.assertLessEqual(row['trace'].count('write:44'), 1)
                if suffix in ['write-1', 'write0', 'write127', 'write129', 'write-full-error']:
                    self.assertEqual(row['trace'][-1], 'write:44')

    def test_source_entry_refuses_before_every_effect(self):
        r = subprocess.run([str(self.gate)], capture_output=True, text=True, timeout=5,
                           check=False, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr[:1024])
        self.assertEqual(json.loads(r.stdout), {'rc': 77, 'effects': 0})
