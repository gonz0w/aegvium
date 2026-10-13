# SPDX-License-Identifier: BSD-3-Clause
import copy
import importlib.util
import json
import tempfile
from types import SimpleNamespace
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

    def test_fault_admission_keeps_window_forwarding_and_rejects_post_down_success(self):
        hashes = {'profile': 'a'*64, 'engine': 'b'*64, 'checker': 'c'*64}
        values = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0', **hashes,
                  'uid': '32767', 'relayd': 'd'*64, 'fixture-log': 'e'*64, 'daemon-log': 'f'*64}
        events = []
        wire = lambda status, body=b'', headers='': (f'HTTP/1.0 {status} fixture\r\n{headers}\r\n'.encode()+body).hex()
        pair = lambda i, name: [{'Phase': i, 'Request': name, 'Role': role, 'Status': 200} for role in ('sink', 'inspection')]
        for i, operation in enumerate(LAB.FAULT_OPERATIONS):
            if 1 <= i <= 8:
                up = i % 2 == 1
                values[f'state-{i}'] = 'up' if up else 'down'
                values[f'polls-{i}'] = '1'
                values[f'checker-exit-{i}'] = '1' if up else '0'
                values[f'direct-{i}'] = wire(200, headers='Cache-Control: no-store\r\n') if up else {2: wire(503), 4: b'malformed health\r\n\r\n'.hex(), 6: wire(302, headers='Location: http://127.0.0.1:18085/ready\r\n'), 8: ''}[i]
                values[f'request-{i}-benign'] = wire(200, b'synthetic sink\n') if up else ''
                if up:
                    events += pair(i, 'benign')
                else:
                    values[f'window-before-{i}'] = 'up'
                    values[f'window-after-{i}'] = 'down'
                    values[f'request-{i}-window'] = wire(200, b'synthetic sink\n') if i == 2 else ''
                    if i == 2:
                        events += pair(i, 'window')
                    values[f'request-{i}-witness'] = wire(200, b'synthetic sink\n')
                    events += pair(i, 'witness')
            values[f'ack-{i}'] = json.dumps({'schema': 1, 'generation': '1'*32, 'uid': 32767,
                'phase': i, 'operation': operation, 'ready': 1 <= i <= 8, 'terminal': i == 9,
                'cleaned': i == 9, 'events': copy.deepcopy(events)})
        values['final-ack'] = values['ack-9']
        text = lambda d: '\n'.join('WIRING\t'+k+'\t'+v for k, v in d.items())
        admitted = LAB.admit_faults(text(values), hashes)
        self.assertEqual(admitted['fault_count'], 4)
        self.assertTrue(admitted['polling_windows'][0]['forwarded'])
        for key, value in [('cleanup', 'assumed'), ('fixture-exit', '1'), ('uid', '0'),
                           ('checker-exit-2', '1'), ('state-4', 'up'), ('request-2-witness', ''),
                           ('request-2-benign', values['request-1-benign']), ('direct-4', ''),
                           ('window-before-2', 'unknown')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                LAB.admit_faults(text({**values, key: value}), hashes)
        ack = json.loads(values['ack-2']); ack['events'].append(pair(2, 'benign')[0])
        with self.assertRaises(ValueError):
            LAB.admit_faults(text({**values, 'ack-2': json.dumps(ack)}), hashes)
        for changed in (text(values)+'\nWIRING\tcleanup\tverified', text({k:v for k,v in values.items() if k!='ack-4'})):
            with self.assertRaises(ValueError):
                LAB.admit_faults(changed, hashes)

    def test_replacement_admission_requires_actual_unsafe_forwarding_and_restoration(self):
        hashes = {'profile': 'a'*64, 'engine': 'b'*64, 'checker': 'c'*64, 'replacement': 'd'*64}
        values = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0', **hashes,
                  'uid': '32767', 'relayd': 'e'*64, 'fixture-log': 'f'*64, 'daemon-log': '0'*64,
                  'checker-restored': hashes['checker'], 'checker-restored-owner-mode': '0:555', 'expected-script-uid': '89', 'replacement-script-uid': '89'}
        wire = lambda status, body=b'', headers='': (f'HTTP/1.0 {status} fixture\r\n{headers}\r\n'.encode()+body).hex()
        events = []
        for i, operation in enumerate(LAB.REPLACEMENT_OPERATIONS):
            if 1 <= i <= 7:
                up, healthy = i in (1, 3, 5, 7), i in (1, 2, 3, 7)
                mode = LAB.REPLACEMENT_MODES[i]
                values[f'checker-mode-{i}'] = mode
                values[f'checker-path-{i}'] = 'absent' if mode == 'missing' else hashes['replacement' if mode == 'exit2' else 'checker']
                values[f'state-{i}'] = 'up' if up else 'down'
                values[f'polls-{i}'] = '1'
                values[f'checker-exit-{i}'] = '127' if mode == 'missing' else '2' if mode == 'exit2' else '1' if healthy else '0'
                values[f'original-exit-{i}'] = '1' if healthy else '0'
                values[f'checker-output-{i}'] = 'launch-error' if mode == 'missing' else 'silent'
                values[f'checker-log-{i}'] = '1'*64 if mode == 'missing' else LAB.hashlib.sha256(b'').hexdigest()
                values[f'direct-{i}'] = wire(200 if healthy else 503, headers='Cache-Control: no-store\r\n' if healthy else '')
                values[f'request-{i}-benign'] = wire(200, b'synthetic sink\n') if up else ''
                name = 'benign' if up else 'witness'
                if not up:
                    values[f'request-{i}-witness'] = wire(200, b'synthetic sink\n')
                events += [{'Phase': i, 'Request': name, 'Role': role, 'Status': 200} for role in ('sink', 'inspection')]
            values[f'ack-{i}'] = json.dumps({'schema': 1, 'generation': '1'*32, 'uid': 32767, 'phase': i,
                'operation': operation, 'ready': 1 <= i <= 7, 'terminal': i == 8, 'cleaned': i == 8,
                'events': copy.deepcopy(events)})
        values['final-ack'] = values['ack-8']
        text = lambda d: '\n'.join('WIRING\t'+k+'\t'+v for k, v in d.items())
        result = LAB.admit_replacements(text(values), hashes)
        self.assertTrue(result['unsafe_exit2_forwarding_observed'])
        self.assertTrue(result['missing_checker_down_observed'])
        for key, value in [('checker-restored', '0'*64), ('checker-restored-owner-mode', '0:777'), ('replacement-script-uid', '0'), ('expected-script-uid', '0'),
                           ('checker-path-5', hashes['checker']), ('checker-exit-2', '0'), ('original-exit-5', '1'),
                           ('checker-exit-5', '0'), ('state-5', 'down'), ('checker-output-2', 'silent'),
                           ('checker-log-2', LAB.hashlib.sha256(b'').hexdigest()), ('request-5-benign', ''),
                           ('request-2-benign', values['request-1-benign']), ('request-6-witness', ''),
                           ('cleanup', 'assumed'), ('fixture-exit', '1')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                LAB.admit_replacements(text({**values, key: value}), hashes)
        for field, value in [('generation', '2'*32), ('phase', 3), ('ready', False), ('events', [])]:
            ack = json.loads(values['ack-5']); ack[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                LAB.admit_replacements(text({**values, 'ack-5': json.dumps(ack)}), hashes)
        for changed in (text(values)+'\nWIRING\tcleanup\tverified', text({k:v for k,v in values.items() if k!='ack-5'})):
            with self.assertRaises(ValueError):
                LAB.admit_replacements(changed, hashes)


    def test_supervisor_failure_keeps_log_receipt_even_when_wire_receipts_are_invalid(self):
        class Guest:
            def require(self, *args, **kwargs):
                pass

            def call(self, *args, **kwargs):
                kwargs['output'].write(b'WIRING\tcleanup\tverified\nWIRING\tcleanup\tverified\n')
                return SimpleNamespace(returncode=1)

        with tempfile.TemporaryDirectory() as directory:
            result = LAB.guest_run(Guest(), Path(directory), 'a'*64, 'b'*64, replacements=True)
            self.assertFalse(result['admitted'])
            self.assertEqual(result['supervisor_exit'], 1)
            self.assertEqual(result['partial_receipts'], {})
            self.assertIn('duplicate', result['error'])
            self.assertEqual(result['log_sha256'], LAB.hashlib.sha256((Path(directory)/'relayd-wiring.log').read_bytes()).hexdigest())
