# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('signals', Path(__file__).resolve().parents[1] / 'relayd-signals.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class SignalTests(unittest.TestCase):
    def test_classification_account_and_state_are_independent_gates(self):
        values = {'syntax': 'accepted', 'cleanup': 'verified', 'profile': 'a'*64,
                  'observer': 'b'*64, 'expected-uid': '89', 'relayd': 'c'*64, 'daemon-log': 'd'*64}
        for arm, kind, code in (('zero', 'exited', '0'), ('one', 'exited', '1'), ('two', 'exited', '2'),
                                ('term', 'signalled', '15'), ('kill', 'signalled', '9')):
            values['observe-'+arm] = '89|'+kind+'|'+code
            for role in ('plain', 'child'):
                values['uid-'+role+'-'+arm] = '89'
            for role in ('plain', 'observed'):
                values['state-'+role+'-'+arm] = 'up' if kind == 'exited' and int(code) > 0 else 'down'
        text = lambda d: '\n'.join('SIGNAL\t'+k+'\t'+v for k, v in d.items())
        self.assertEqual(LAB.admit(text(values), 'a'*64, 'b'*64)['state-plain-kill'], 'down')
        for key, value in (('uid-child-term', '0'), ('observe-kill', '89|exited|137'),
                           ('state-plain-term', 'up'), ('observe-term', '0|signalled|15'),
                           ('cleanup', 'assumed'), ('observer', 'e'*64)):
            changed = {**values, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                LAB.admit(text(changed), 'a'*64, 'b'*64)
        for changed in (text(values)+'\nSIGNAL\tsyntax\taccepted', text({k:v for k,v in values.items() if k!='observe-term'})):
            with self.assertRaises(ValueError):
                LAB.admit(changed, 'a'*64, 'b'*64)
        values.update({'observe-term':'89|exited|143', 'state-plain-term':'up', 'state-observed-term':'up'})
        self.assertEqual(LAB.admit(text(values), 'a'*64, 'b'*64)['observe-term'], '89|exited|143')
