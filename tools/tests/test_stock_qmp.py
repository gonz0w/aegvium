# SPDX-License-Identifier: BSD-3-Clause
"""Deterministic host protocol faults; no socket, guest or credential is created."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('stock_qmp_lab', Path(__file__).resolve().parents[1] / 'stock-lab.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


def frame(value):
    return (json.dumps(value) + '\r\n').encode()


GREETING = frame({'QMP': {'version': {}, 'capabilities': []}})
CAPABILITIES = frame({'id': 'stock-lab-0', 'return': {}})
RESULT = frame({'id': 'stock-lab-1', 'return': {'status': 'paused'}})
EVENT = frame({'event': 'STOP', 'data': {}, 'timestamp': {}})


class FakeSocket:
    def __init__(self, chunks, clock, *, delays=(), connect_delay=0, send_delay=0, fault=None):
        self.chunks = list(chunks)
        self.clock = clock
        self.delays = iter(delays)
        self.connect_delay = connect_delay
        self.send_delay = send_delay
        self.fault = fault
        self.closed = False
        self.sent, self.timeouts, self.reads = [], [], 0

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        self.closed = True

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def connect(self, _path):
        self.clock[0] += self.connect_delay
        if self.fault == 'connect':
            raise OSError('private connect detail')

    def sendall(self, data):
        self.clock[0] += self.send_delay
        self.sent.append(json.loads(data))
        if self.fault == 'send':
            raise OSError('private send detail')

    def recv(self, count):
        self.reads += 1
        self.clock[0] += next(self.delays, 0)
        if self.fault == 'receive':
            raise OSError('private receive detail')
        if not self.chunks:
            return b''
        data = self.chunks.pop(0)
        if len(data) > count:
            self.chunks.insert(0, data[count:])
        return data[:count]


class StockQMPTests(unittest.TestCase):
    def call(self, chunks, **options):
        clock = [100.0]
        connection = FakeSocket(chunks, clock, **options)
        self.addCleanup(lambda: self.assertTrue(connection.closed))
        with patch.object(LAB.socket, 'socket', return_value=connection) as create, patch.object(LAB.time, 'monotonic', side_effect=lambda: clock[0]):
            self.connection = connection
            try:
                return LAB.qmp(Path('/owned-fixture/qmp.sock'), 'query-status')
            finally:
                self.assertEqual(create.call_args.args, (LAB.socket.AF_UNIX,))
                self.assertEqual(create.call_count, 1)

    def test_fragmented_frames_and_interleaved_events_keep_exact_request_ids(self):
        wire = GREETING + EVENT + CAPABILITIES + EVENT + RESULT
        self.assertEqual(self.call([wire[i:i+3] for i in range(0, len(wire), 3)]), {'status': 'paused'})
        self.assertEqual(self.connection.sent, [
            {'execute': 'qmp_capabilities', 'id': 'stock-lab-0'},
            {'execute': 'query-status', 'arguments': {}, 'id': 'stock-lab-1'}])

    def test_coalesced_frames_are_not_lost(self):
        self.assertEqual(self.call([GREETING + CAPABILITIES + RESULT]), {'status': 'paused'})

    def test_connect_and_send_time_share_the_original_wall(self):
        with self.assertRaisesRegex(TimeoutError, 'owned QEMU control deadline'):
            self.call([GREETING, CAPABILITIES, RESULT], connect_delay=5)
        self.assertEqual(self.connection.reads, 0)
        with self.assertRaisesRegex(TimeoutError, 'owned QEMU control deadline'):
            self.call([GREETING, CAPABILITIES, RESULT], send_delay=2.5)
        self.assertEqual(len(self.connection.sent), 2)
        self.assertEqual(self.connection.reads, 2)

    def test_slow_trickle_cannot_renew_the_read_deadline(self):
        with self.assertRaisesRegex(TimeoutError, 'owned QEMU control deadline'):
            self.call([bytes([byte]) for byte in GREETING], delays=[1] * len(GREETING))
        self.assertEqual(self.connection.reads, 5)
        self.assertEqual(self.connection.sent, [])

    def test_late_complete_reply_and_event_progress_do_not_extend_deadline(self):
        with self.assertRaisesRegex(TimeoutError, 'owned QEMU control deadline'):
            self.call([GREETING, CAPABILITIES, RESULT], delays=[1, 1, 3])
        with self.assertRaisesRegex(TimeoutError, 'owned QEMU control deadline'):
            self.call([GREETING] + [EVENT] * 10 + [CAPABILITIES, RESULT], delays=[0.5] * 13)
        self.assertEqual(len(self.connection.sent), 1)
        self.assertEqual(self.connection.timeouts, sorted(self.connection.timeouts, reverse=True))

    def test_event_count_is_bounded_across_both_replies(self):
        with self.assertRaisesRegex(RuntimeError, 'event bound'):
            self.call([GREETING, *([EVENT] * 16), CAPABILITIES, *([EVENT] * 17), RESULT])
        self.assertEqual(len(self.connection.sent), 2)
        self.assertEqual(self.call([GREETING, *([EVENT] * 16), CAPABILITIES, *([EVENT] * 16), RESULT]), {'status': 'paused'})

    def test_frame_and_aggregate_input_have_independent_bounds(self):
        for ending in (b'', b'\n'):
            with self.subTest(ending=ending), self.assertRaisesRegex(RuntimeError, 'frame bound'):
                self.call([b'x' * LAB.QMP_FRAME_BYTES + ending])
        large_event = frame({'event': 'STOP', 'data': {'owned': 'x' * 60000}})
        with self.assertRaisesRegex(RuntimeError, 'input bound'):
            self.call([GREETING, *([large_event] * 5), CAPABILITIES, RESULT])

    def test_exact_frame_and_total_input_boundaries_are_accepted(self):
        def sized(value, size):
            empty = frame(value)
            value['QMP' if 'QMP' in value else 'data']['padding'] += 'x' * (size - len(empty))
            result = frame(value)
            self.assertEqual(len(result), size)
            return result
        greeting = sized({'QMP': {'padding': ''}}, LAB.QMP_FRAME_BYTES)
        self.assertEqual(self.call([greeting, CAPABILITIES, RESULT]), {'status': 'paused'})
        large_event = sized({'event': 'STOP', 'data': {'padding': ''}}, LAB.QMP_FRAME_BYTES)
        last_size = LAB.QMP_INPUT_BYTES - len(GREETING + CAPABILITIES + RESULT) - 3 * len(large_event)
        last_event = sized({'event': 'STOP', 'data': {'padding': ''}}, last_size)
        self.assertEqual(self.call([GREETING, large_event, large_event, large_event,
                                   last_event, CAPABILITIES, RESULT]), {'status': 'paused'})

    def test_eof_malformed_duplicate_nonfinite_and_nonobject_frames_refuse(self):
        for bad in (b'', GREETING[:-1], b'not-json\n', b'[]\n', b'null\n',
                    b'{"QMP":{},"QMP":{}}\n', b'{"QMP":{"x":NaN}}\n',
                    b'{"QMP":{"x":1e999}}\n', b'{"QMP":{"x":-1e999}}\n', b'\xff\n',
                    b'[' * 2000 + b']' * 2000 + b'\n'):
            with self.subTest(frame_bytes=len(bad)), self.assertRaises(RuntimeError):
                self.call([bad])

    def test_invalid_greeting_cannot_send_a_command(self):
        for bad in ({'QMP': []}, {'return': {}}, {'QMP': {}, 'extra': True}):
            with self.subTest(shape=sorted(bad)), self.assertRaisesRegex(RuntimeError, 'greeting refused'):
                self.call([frame(bad)])
            self.assertEqual(self.connection.sent, [])

    def test_nonfinite_numbers_fail_before_capability_negotiation(self):
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1e999', b'-1e999'):
            greeting = b'{"QMP":{"nested":[{"value":' + number + b'}]}}\n'
            with self.subTest(number=number), self.assertRaisesRegex(RuntimeError, 'malformed frame'):
                self.call([greeting, CAPABILITIES, RESULT])
            self.assertEqual(self.connection.sent, [])

    def test_wrong_missing_ambiguous_and_replayed_reply_ids_refuse(self):
        for reply in ({'return': {}}, {'id': 'wrong', 'return': {}},
                      {'id': 'stock-lab-0', 'return': {}, 'error': {}},
                      {'id': 'stock-lab-0', 'return': {}, 'extra': True},
                      {'id': 'stock-lab-0', 'event': 'STOP'}):
            with self.subTest(shape=sorted(reply)), self.assertRaises(RuntimeError):
                self.call([GREETING, frame(reply), RESULT])
        with self.assertRaisesRegex(RuntimeError, 'reply refused'):
            self.call([GREETING, CAPABILITIES, CAPABILITIES])

    def test_peer_error_and_transport_faults_never_expose_details(self):
        with self.assertRaisesRegex(RuntimeError, '^owned QEMU control refused$'):
            self.call([GREETING, frame({'id': 'stock-lab-0', 'error': {'desc': 'private peer detail'}})])
        for fault in ('connect', 'send', 'receive'):
            with self.subTest(fault=fault), self.assertRaisesRegex(RuntimeError, '^owned QEMU control transport failed$'):
                self.call([GREETING, CAPABILITIES, RESULT], fault=fault)


if __name__ == '__main__':
    unittest.main()
