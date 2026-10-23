# SPDX-License-Identifier: BSD-3-Clause
"""Replay independently frozen literals against an isolated C11 state core.

No native inspector, supervisor binding, process subject, signal, credentials,
IPC or engine. Fresh ordinary host harness processes exit normally; a bounded
subprocess timeout owns only that test invocation. This is not native proof.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tools/tests/fixtures'
FLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic']


class InspectorControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='aeg-controller-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / 'controller-harness'
        result = subprocess.run([
            '/usr/bin/cc', *FLAGS, '-I', str(ROOT / 'internal/inspectorowner'),
            str(ROOT / 'internal/inspectorowner/controller.c'),
            str(FIXTURES / 'inspector-controller-harness.c'), '-o', str(cls.binary),
        ], text=True, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def test_frozen_contract_and_literal_packet(self):
        frozen = json.loads((ROOT / 'docs/milestones/M2/SUPERVISOR-CONTROLLER-FREEZE.json').read_text())
        self.assertTrue(frozen['root_verified_product_c_absent'])
        for name, expected_hash in frozen['files'].items():
            with self.subTest(frozen_path=name):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected_hash)

    def command(self, step):
        op = step['op']
        if op == 'prepare':
            generation = step['generation']
            self.assertTrue(generation is None or
                            (0 < len(generation) <= 64 and generation.isascii() and generation.isalnum()))
            self.assertIs(type(step['length']), int)
            self.assertTrue(0 <= step['length'] <= 64)
            command = f"P {step['now']} {step['length']} {int(generation is None)} {generation or '-'}\n"
        elif op == 'step':
            self.assertIs(type(step['event']), int)
            self.assertTrue(-100 <= step['event'] <= 100)
            seed = step.get('out_seed', 2)
            self.assertIn(seed, (0, 1, 2))
            command = f"S {step['event']} {step['now']} {int(step.get('null_out', False))} {seed}\n"
        else:
            self.assertIn(op, ('view', 'mutate_view'))
            command = 'V\n' if op == 'view' else 'M\n'
        if 'now' in step:
            self.assertIs(type(step['now']), int)
            self.assertTrue(-(1 << 63) <= step['now'] < (1 << 63))
        self.assertLess(len(command.encode('ascii')), 128)
        return command

    def test_independent_literal_traces(self):
        paths = sorted(FIXTURES.glob('inspector-controller-[1-4].json'))
        self.assertEqual(len(paths), 4)
        traces = []
        for path in paths:
            self.assertLess(path.stat().st_size, 256 * 1024)
            packet = json.loads(path.read_text())
            self.assertEqual(packet['schema'], 'aeg-inspector-owner-controller-independent-v1')
            traces.extend(packet['traces'])
        self.assertEqual(len(traces), 32)
        self.assertEqual(len({trace['name'] for trace in traces}), 32)
        self.assertEqual(sum(len(trace['steps']) for trace in traces), 289)
        for trace in traces:
            self.replay(trace)

    def test_postimplementation_independent_regression(self):
        path = FIXTURES / 'inspector-controller-review-addendum.json'
        self.assertLess(path.stat().st_size, 16 * 1024)
        packet = json.loads(path.read_text())
        self.assertEqual(packet['packet_role'], 'postimplementation_regression')
        self.assertEqual(len(packet['traces']), 1)
        self.assertEqual(len(packet['traces'][0]['steps']), 13)
        self.replay(packet['traces'][0])

    def replay(self, trace):
        with self.subTest(trace=trace['name']):
            steps = trace['steps']
            self.assertTrue(0 < len(steps) <= 64)
            commands = ''.join(self.command(step) for step in steps)
            result = subprocess.run([str(self.binary)], input=commands,
                                    text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr[:8192])
            self.assertFalse(result.stderr)
            self.assertLess(len(result.stdout), 128 * 1024)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(rows), len(steps))
            for index, (step, row) in enumerate(zip(steps, rows)):
                with self.subTest(operation=index):
                    for field in ('rc', 'intent'):
                        if field in step:
                            self.assertEqual(row[field], step[field], field)
                    for field, expected in step['expect'].items():
                        self.assertIs(type(row[field]), type(expected), field)
                        self.assertEqual(row[field], expected, field)
                    self.assertEqual(row['request_envelope'], 4 if row['held'] else 0)
                    self.assertEqual(row['socket_envelope'], 8 if row['held'] else 0)
                    if row['phase'] == 7:
                        self.assertFalse(row['known_child'])
                        self.assertFalse(row['held'])
                        self.assertTrue(row['protocol_closed'])
                        self.assertNotEqual(row['terminal'], 0)
                    if row['identity_fault']:
                        self.assertFalse(row['known_child'])
                        # Input failures deliberately leave the supplied seed.
                        if step['op'] == 'step' and row['rc'] != 1:
                            self.assertEqual(row['intent'], 0)
