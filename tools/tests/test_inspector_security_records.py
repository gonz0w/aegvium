# SPDX-License-Identifier: BSD-3-Clause
"""Connected required records and retention; every subject OS boundary faked."""
import json
import subprocess
import unittest

from tools.tests import test_inspector_launch_storage as launch
from tools.tests import test_inspector_normal_clean as clean

# Explicit order expected from the contract; checkpoint traces remain the
# original separately frozen literals. Records use no positive source provider.
ADMIT = ['open', 'stat', 'path', 'read-all', 'stat', 'path', 'write:0',
         'sync', 'readback', 'stat', 'path', 'close']
SETTLE = ['open', 'stat', 'path', 'read-all', 'stat', 'path', 'write:0',
          'sync', 'readback', 'stat', 'path', 'write:4096', 'sync', 'readback',
          'stat', 'path', 'close']


class InspectorSecurityRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        launch.InspectorLaunchStorageTests.setUpClass()
        clean.InspectorNormalCleanTests.setUpClass()

    def run_case(self, mode, settlement=False):
        owner = clean.InspectorNormalCleanTests if settlement else launch.InspectorLaunchStorageTests
        result = subprocess.run([str(owner.binary), mode], capture_output=True,
                                text=True, timeout=5, check=False, env=owner.env)
        self.assertEqual(result.returncode, 0, result.stderr[:2048])
        self.assertFalse(result.stderr)
        self.assertLess(len(result.stdout), 12288)
        r = json.loads(result.stdout)
        self.assertEqual(r['bad'], 0)
        self.assertEqual(r['duplicate_calls'], 0)
        self.assertLessEqual(r['known'], 4)
        self.assertLessEqual(r['records']['writes'], 3)
        return r

    def test_required_admission_record_precedes_U_without_retiring_history(self):
        r = self.run_case('record-normal')
        a = r['records']
        self.assertEqual((r['rc'], r['committed'], r['writes']), (0, 1, 1))
        self.assertEqual(a['trace'], ADMIT)
        self.assertEqual((a['counts'], a['states'], a['old_preserved']), ([29, 30], [65, 83], 1))
        self.assertEqual(a['at_checkpoint_calls'], [70])  # Before U encoding/write.
        self.assertEqual(a['offsets'], [0])
        record = bytes.fromhex(a['last_record'])
        self.assertEqual(record[:16], b'AEGREQ1\nU' + bytes(7))
        self.assertEqual(record[16:48], b'f' * 32)
        self.assertEqual(record[48:80].hex(), 'ff8d673e62bc6b956ad76b818bd785e2b3b6e9e80ae81582c55059f5a8671a71')
        self.assertEqual(record[80:112].hex(), 'd855ba636ffdfea364522538421fa585c1927fe5ef4d8065b89549c6bf744213')
        self.assertEqual(record[112:], b'\x01' + bytes(15))
        v2 = self.run_case('snapshot-v2')
        self.assertEqual(bytes.fromhex(v2['records']['last_record'])[112:], b'\x03' + bytes(15))

    def test_only_proved_cleanup_seals_and_rotates_the_oldest_segment(self):
        for name, offsets, counts, states in [
            ('record-normal', [0, 0, 4096], [30, 0], [83, 65]),
            ('record-first-rotate', [0, 0, 4096], [30, 0], [83, 65]),
            ('record-swapped', [4096, 4096, 0], [0, 30], [65, 83]),
        ]:
            with self.subTest(name=name):
                r = self.run_case(name, True)
                a = r['records']
                self.assertEqual((r['rc'], r['settled'], r['writes'], r['waits'], r['kills']), (0, 1, 2, 1, 0))
                expected = ADMIT + SETTLE
                if name == 'record-swapped':
                    expected = [s.replace('write:4096', 'write:X').replace('write:0', 'write:4096').replace('write:X', 'write:0') for s in expected]
                self.assertEqual(a['trace'], expected)
                self.assertEqual((a['offsets'], a['counts'], a['states'], a['closes']), (offsets, counts, states, 2))
                self.assertEqual(r['trace'], clean.CLEAN)
                self.assertEqual(bytes.fromhex(r['disk'])[8], ord('C'))
                # Both terminal-boundary writes precede C encoding/write.
                self.assertEqual(a['at_checkpoint_calls'][1:], [r['setup_calls'] + 16] * 2)

    def test_every_admission_IO_failure_prevents_U_and_child_admission(self):
        for edge in range(1, len(ADMIT) + 1):
            with self.subTest(edge=edge):
                r = self.run_case(f'record-admit-fail-{edge}')
                self.assertEqual(r['records']['trace'], ADMIT[:edge])
                self.assertEqual((r['committed'], r['writes'], r['send_calls'], r['owner']), (0, 0, 0, 0))
                self.assertNotEqual(r['rc'], 0)
                self.assertTrue(r['uncertain'])
                self.assertEqual(r['records']['old_preserved'], 1)

    def test_every_clean_IO_failure_preserves_checkpoint_U_and_no_retry(self):
        for edge in range(1, len(SETTLE) + 1):
            with self.subTest(edge=edge):
                r = self.run_case(f'record-clean-fail-{edge}', True)
                self.assertEqual(r['records']['trace'], ADMIT + SETTLE[:edge])
                self.assertEqual((r['rc'], r['settled'], r['uncertain'], r['writes']), (4, 0, 1, 1))
                self.assertEqual(bytes.fromhex(r['disk'])[8], ord('U'))
                if edge <= 12:
                    self.assertEqual(r['records']['old_preserved'], 1)

    def test_malformed_protected_history_and_uncertain_writes_fail_closed(self):
        modes = ['alias', 'uid', 'gid', 'type', 'mode', 'links', 'size', 'path-inode',
                 'magic', 'digest', 'reserved', 'tail', 'odd', 'full', 'double-active',
                 'newer-sealed', 'stale', 'pair-mismatch', 'bad-profile', 'gap',
                 'read-negative', 'read-short', 'read-over', 'write-negative',
                 'write-short', 'write-over', 'write-full-error', 'readback', 'inode-drift']
        for name in modes:
            with self.subTest(name=name):
                r = self.run_case('record-' + name)
                self.assertNotEqual(r['rc'], 0)
                self.assertEqual((r['committed'], r['writes'], r['send_calls']), (0, 0, 0))
                self.assertTrue(r['uncertain'])
                self.assertEqual(r['records']['old_preserved'], 1)
        for name in ['uid', 'gid', 'type', 'mode', 'links', 'size', 'path-inode',
                     'read-negative', 'read-short', 'read-over', 'write-negative',
                     'write-short', 'write-over', 'write-full-error', 'readback',
                     'inode-drift', 'bytes-drift']:
            with self.subTest(clean=name):
                r = self.run_case('record-clean-' + name, True)
                self.assertEqual((r['rc'], r['settled'], r['uncertain'], r['writes']), (4, 0, 1, 1))
                self.assertEqual(r['records']['old_preserved'], 1)

    def test_segment_sequence_never_wraps_or_retires_newest_history(self):
        r = self.run_case('record-sequence-max', True)
        self.assertEqual((r['rc'], r['settled'], r['uncertain'], r['writes']), (4, 0, 1, 1))
        self.assertEqual(r['records']['offsets'], [0, 0])
        self.assertEqual(r['records']['old_preserved'], 1)

    def test_stop_wait_and_unproved_cleanup_do_no_record_IO(self):
        for mode in ['native-view', 'native-pending', 'native-stopped', 'native-interrupt',
                     'native-lost', 'native-wrong', 'native-close-error', 'native-early']:
            with self.subTest(mode=mode):
                r = self.run_case(mode, True)
                self.assertEqual((r['rc'], r['settled'], r['records']['trace']), (2, 0, ADMIT))
        for mode in ['native-nochild', 'native-signaled', 'native-late', 'native-clock']:
            with self.subTest(mode=mode):
                r = self.run_case(mode, True)
                self.assertEqual((r['rc'], r['settled']), (0, 1))
                self.assertEqual(r['records']['trace'], ADMIT + SETTLE[:11] + ['close'])


if __name__ == '__main__':
    unittest.main()
