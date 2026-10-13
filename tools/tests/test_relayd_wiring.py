# SPDX-License-Identifier: BSD-3-Clause
import copy
import importlib.util
import json
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('wiring', Path(__file__).resolve().parents[1] / 'relayd-wiring.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class WiringTests(unittest.TestCase):
    def test_connected_admission_rejects_stale_identity_and_false_forwarding(self):
        hashes = {'profile': 'a'*64, 'engine': 'b'*64, 'checker': 'c'*64}
        values = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0', **hashes,
                  'uid': '32767', 'relayd': 'd'*64, 'fixture-log': 'e'*64, 'daemon-log': 'f'*64, 'bare': ''}
        events = []
        for i, operation in enumerate(LAB.OPERATIONS):
            if i in (2, 4):
                events += [{'Phase': i, 'Request': 'benign', 'Role': 'sink', 'Status': 200},
                           {'Phase': i, 'Request': 'benign', 'Role': 'inspection', 'Status': 200},
                           {'Phase': i, 'Request': 'denied', 'Role': 'inspection', 'Status': 403}]
            ack = {'schema': 1, 'generation': '1'*32, 'uid': 32767, 'phase': i, 'operation': operation,
                   'ready': i in (2, 4), 'terminal': i >= 5, 'cleaned': i == 6, 'events': copy.deepcopy(events)}
            values['ack-'+str(i)] = json.dumps(ack)
            if i in range(1, 6):
                up = i in (2, 4)
                values['state-'+str(i)] = 'up' if up else 'down'
                values['polls-'+str(i)] = '1'
                values['direct-'+str(i)] = (f'HTTP/1.0 {200 if up else 503} fixture\r\nCache-Control: no-store\r\n\r\n').encode().hex()
                for name in ('benign', 'denied'):
                    status = 200 if name == 'benign' else 403
                    body = b'synthetic sink\n' if name == 'benign' else b''
                    values[f'request-{i}-{name}'] = (f'HTTP/1.1 {status} fixture\r\n\r\n'.encode()+body).hex() if up else ''
        values['final-ack'] = values['ack-6']
        text = lambda d: '\n'.join('WIRING\t'+k+'\t'+v for k, v in d.items())
        self.assertEqual(LAB.admit(text(values), hashes)['phase_count'], 5)
        for key, value in [('cleanup', 'assumed'), ('fixture-exit', '1'), ('uid', '0'),
                           ('checker', '0'*64), ('state-3', 'up'), ('bare', '00'),
                           ('request-1-benign', values['request-2-benign'])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                LAB.admit(text({**values, key: value}), hashes)
        for field, value in [('generation', '2'*32), ('phase', 1), ('uid', 0), ('ready', False), ('events', [])]:
            ack = json.loads(values['ack-2']); ack[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                LAB.admit(text({**values, 'ack-2': json.dumps(ack)}), hashes)
        for changed in (text(values)+'\nWIRING\tcleanup\tverified', text({k:v for k,v in values.items() if k!='ack-3'})):
            with self.assertRaises(ValueError):
                LAB.admit(changed, hashes)
