# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('native_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class RelaydContractTests(unittest.TestCase):
    def test_receipts_reject_missing_duplicate_wrong_verdict_uid_hash_cleanup(self):
        values = {'syntax': 'accepted', 'up': 'up', 'down': 'down', 'positive': 'up',
                  'signal': 'down', 'missing': 'down', 'checker': 'down', 'cleanup': 'verified',
                  'profile': 'a'*64, 'checker-sha': 'b'*64, 'script-uid': '89',
                  'relayd': 'c'*64, 'states-log': 'd'*64, 'syntax-log': 'e'*64, 'daemon-log': 'f'*64}
        original = '\n'.join(f'CONTRACT\t{k}\t{v}' for k, v in values.items())
        self.assertEqual(LAB.parse_contract(original, 'a'*64, 'b'*64)['positive'], 'up')
        for changed in (original.replace('CONTRACT\tpositive\tup\n', ''),
                        original+'\nCONTRACT\tup\tup', original.replace('positive\tup', 'positive\tdown'),
                        original.replace('script-uid\t89', 'script-uid\t0'), original.replace('c'*64, 'bad'),
                        original.replace('cleanup\tverified', 'cleanup\tassumed')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                LAB.parse_contract(changed, 'a'*64, 'b'*64)
