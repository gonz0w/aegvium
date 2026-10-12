# SPDX-License-Identifier: BSD-3-Clause
import hashlib
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('native_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class RelaydConfigTests(unittest.TestCase):
    def valid(self):
        values = {'valid': 'accepted', 'missing-protocol': 'rejected', 'bad-syntax': 'rejected',
                  'no-daemon': 'verified-before-after', 'no-listener': 'verified-before-after',
                  'no-control-socket': 'verified-before-after', 'uid': '0', 'profile': 'a' * 64,
                  'binary': 'b' * 64, 'valid-log': 'c' * 64, 'missing-log': 'd' * 64, 'bad-log': 'e' * 64}
        return '\n'.join(f'RELAYD\t{name}\t{value}' for name, value in values.items())

    def test_missing_duplicate_invalid_verdict_and_hash_refused(self):
        valid = self.valid()
        self.assertEqual(LAB.parse_relayd(valid, 'a' * 64)['valid'], 'accepted')
        for changed in (valid.replace('RELAYD\tuid\t0\n', ''), valid + '\nRELAYD\tuid\t0',
                        valid.replace('missing-protocol\trejected', 'missing-protocol\taccepted'),
                        valid.replace('uid\t0', 'uid\t32767'), valid.replace('b' * 64, 'oops'),
                        valid.replace('a' * 64, 'f' * 64), valid + '\nRELAYD\tunknown\taccepted',
                        valid.replace('no-listener\tverified-before-after', 'no-listener\tassumed')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                LAB.parse_relayd(changed, 'a' * 64)

    def test_fixed_profile_has_only_reviewed_target_and_variants(self):
        inputs = LAB.relayd_inputs()
        profile = inputs['ingress.conf'].decode()
        self.assertEqual(profile.count('forward to '), 1)
        self.assertEqual(profile.count('listen on '), 1)
        self.assertIn('forward to <inspection> port 18081 check http', profile)
        self.assertIn('listen on 127.0.0.1 port 18080', profile)
        self.assertIn('table <inspection> { 127.0.0.1 }', profile)
        self.assertNotIn('redirect ', profile)
        self.assertNotIn('fallback', profile)
        self.assertEqual(inputs['missing-protocol.conf'], inputs['ingress.conf'].replace(
            b'    protocol "inspection_ingress"', b'    protocol "missing"'))
        self.assertEqual(inputs['bad-syntax.conf'], inputs['ingress.conf'] + b'unsupported_aegvium_option\n')
        self.assertEqual(len({hashlib.sha256(data).hexdigest() for data in inputs.values()}), 3)
