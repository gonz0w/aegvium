# SPDX-License-Identifier: BSD-3-Clause
"""Failure injection never launches a process or sends a real signal."""
import errno
import importlib.util
import os
from pathlib import Path
import signal
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ordinary_owner_test_subject', Path(__file__).parents[1]/'lab-supervisor.py')
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


class Interrupted(BaseException):
    pass


class OrdinaryOwnerTests(unittest.TestCase):
    def run_owner(self, fault=None, *, reservation_lost=False, signal_error=None, absent=True, wait_error=False, status=0, clock_error=False, late=False, observed_exit=True, stop=False, tick=1.0, eof=False, signal_at_eof=False, transient_probe=False, signal_at_exit=False):
        child = types.SimpleNamespace(pid=424242, returncode=None)
        calls, records = [], {}
        def observe(*args):
            calls.append('observe')
            if reservation_lost:
                raise ChildProcessError(errno.ECHILD, 'synthetic lost reservation')
            if signal_at_exit: latch.setdefault('reason', 'signal')
            return types.SimpleNamespace(si_pid=child.pid) if observed_exit else None
        def wait(pid, flags):
            calls.append('wait')
            self.assertEqual(pid, 424242)
            if wait_error:
                raise ChildProcessError(errno.ECHILD, 'synthetic consumed wait')
            return pid, status
        def group(pid, number):
            calls.append(('signal', number))
            self.assertNotIn('wait', calls)
            self.assertEqual(pid, 424242)
            if signal_error:
                raise PermissionError(signal_error, 'synthetic denied signal')
        probed = set()
        probe_number = [100]
        def observation(pid, number):
            self.assertEqual(number, 0)
            calls.append(('absent', pid))
            if fault == 'probe-denied': raise PermissionError(errno.EPERM, 'synthetic repeated denial')
            if fault == 'probe-overflow':
                probe_number[0] += 1
                raise OSError(probe_number[0], 'synthetic distinct error')
            if fault == 'probe-eintr': raise InterruptedError()
            if fault == 'probe-base': raise Interrupted()
            if transient_probe and pid not in probed:
                probed.add(pid)
                raise PermissionError(errno.EPERM, 'synthetic uncertain observation')
            if absent:
                raise ProcessLookupError
        def started(path):
            if fault == 'body':
                raise Interrupted()
        def saved(path, value):
            calls.append(('save', path.name))
            records[path.name] = value
            if fault == 'final' and path.name == 'result.json':
                raise Interrupted()
        ticks = [tick]
        def clock():
            if clock_error: raise Interrupted()
            return ticks[0]
        original_saved = saved
        def saved(path, value):
            original_saved(path, value)
            if late and path.name == 'result.ownership.json': ticks[0] = 11.0
        latch = {}
        def selected(**_):
            if signal_at_eof: latch.setdefault('reason', 'signal')
            return eof
        selector = types.SimpleNamespace(register=lambda *_: None, close=lambda: None, select=selected)
        if fault == 'close':
            def close(): raise Interrupted()
            selector.close = close
        with patch.object(OWNER.os, 'waitid', observe), patch.object(OWNER.os, 'waitpid', wait), \
             patch.object(OWNER.os, 'read', return_value=b''), patch.object(OWNER.os, 'killpg', group), patch.object(OWNER.os, 'kill', observation), \
             patch.object(OWNER.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(OWNER.time, 'monotonic', clock), patch.object(OWNER.time, 'sleep'):
            try:
                code = OWNER.own_ordinary(child, Path('result.json'), 0, 5, 10, 5,
                                           lambda: stop, started, saved, latch)
            except Interrupted:
                code = 'original-interruption'
        return code, calls, records

    def test_finalizer_interruption_cannot_skip_sole_wait_or_independent_receipt(self):
        for fault in ('body', 'close', 'final'):
            with self.subTest(fault=fault):
                code, calls, records = self.run_owner(fault)
                self.assertEqual(calls.count('wait'), 1)
                self.assertIn(('signal', signal.SIGKILL), calls)
                self.assertIn('result.ownership.json', records)
                self.assertTrue(records['result.ownership.json']['child_reaped'])
                self.assertNotEqual(code, 0)

    def test_unknown_wait_reservation_never_grants_signal_or_wait(self):
        code, calls, records = self.run_owner(reservation_lost=True)
        self.assertNotEqual(code, 0)
        self.assertFalse(any(isinstance(c, tuple) and c[0]=='signal' for c in calls))
        self.assertNotIn('wait', calls)
        self.assertFalse(records['result.ownership.json']['child_reaped'])

    def test_permission_error_is_retained_and_only_redundant_with_real_terminal_proof(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                code, calls, records = self.run_owner(signal_error=errno.EPERM, absent=complete)
                audit = records['result.ownership.json']
                self.assertEqual(audit['signals'][0]['errno'], errno.EPERM)
                self.assertEqual(sum(isinstance(c, tuple) and c[0]=='signal' for c in calls), 1)
                self.assertEqual(code == 0, complete)
                self.assertEqual(audit['pid_absent'] and audit['group_absent'], complete)

    def test_consumed_wait_is_not_fabricated_as_success(self):
        code, calls, records = self.run_owner(wait_error=True)
        self.assertNotEqual(code, 0)
        audit = records['result.ownership.json']
        self.assertFalse(audit['child_reaped'])
        self.assertIsNone(audit['raw_wait_status'])
        self.assertEqual(calls.count('wait'), 1)

    def test_clock_failure_still_attempts_signal_wait_and_both_absence_checks(self):
        code, calls, records = self.run_owner(clock_error=True)
        self.assertNotEqual(code, 0)
        self.assertIn(('signal', signal.SIGKILL), calls)
        self.assertIn('wait', calls)
        self.assertIn(('absent', 424242), calls)
        self.assertIn(('absent', -424242), calls)
        self.assertFalse(records['result.ownership.json']['deadline_met'])

    def test_nonterminal_wait_is_not_terminal_proof(self):
        code, _, records = self.run_owner(status=0x7f)
        self.assertNotEqual(code, 0)
        self.assertFalse(records['result.ownership.json']['child_reaped'])

    def test_late_publication_cannot_return_success(self):
        code, _, _ = self.run_owner(late=True)
        self.assertNotEqual(code, 0)

    def test_permission_error_without_prior_exit_is_never_redundant(self):
        code, _, records = self.run_owner(signal_error=errno.EPERM, observed_exit=False, stop=True)
        self.assertNotEqual(code, 0)
        self.assertFalse(records['result.ownership.json']['signals'][0]['exit_observed_before'])

    def test_deadline_is_sticky_and_eof_is_not_overwritten(self):
        code, _, records = self.run_owner(observed_exit=False, tick=6.0)
        self.assertEqual(records['result.json']['reason'], 'deadline')
        self.assertTrue(records['result.ownership.json']['expired'])
        code, _, records = self.run_owner(observed_exit=False, eof=True)
        self.assertEqual(records['result.json']['reason'], 'controller-eof')
        self.assertFalse(records['result.ownership.json']['expired'])

    def test_signal_recorded_during_select_beats_simultaneous_eof(self):
        _, _, records = self.run_owner(observed_exit=False, eof=True, signal_at_eof=True)
        self.assertEqual(records['result.json']['reason'], 'signal')

    def test_uncertain_probe_is_retained_and_cannot_itself_prove_absence(self):
        code, _, records = self.run_owner(transient_probe=True)
        audit = records['result.ownership.json']
        self.assertEqual(code, 0)
        self.assertTrue(audit['pid_absent'] and audit['group_absent'])
        self.assertEqual([v['errno'] for v in audit['absence_errors']], [errno.EPERM, errno.EPERM])
        code, _, records = self.run_owner(transient_probe=True, absent=False)
        self.assertNotEqual(code, 0)
        self.assertFalse(records['result.ownership.json']['pid_absent'])

    def test_probe_interruptions_are_sticky_and_no_post_wait_signal_occurs(self):
        for fault in ('probe-eintr', 'probe-base'):
            with self.subTest(fault=fault):
                code, calls, records = self.run_owner(fault)
                self.assertNotEqual(code, 0)
                self.assertTrue(records['result.ownership.json']['errors'])
                self.assertEqual(calls.count('wait'), 1)
                tail = calls[calls.index('wait')+1:]
                self.assertFalse(any(isinstance(c, tuple) and c[0]=='signal' for c in tail))

    def test_repeated_denial_counts_and_summary_overflow_cannot_admit(self):
        code, _, records = self.run_owner('probe-denied')
        self.assertNotEqual(code, 0)
        audit = records['result.ownership.json']
        self.assertEqual(len(audit['absence_errors']), 2)
        self.assertEqual([v['count'] for v in audit['absence_errors']], [251, 251])
        code, _, records = self.run_owner('probe-overflow')
        self.assertNotEqual(code, 0)
        audit = records['result.ownership.json']
        self.assertEqual(len(audit['absence_errors']), 16)
        self.assertEqual(len(audit['errors']), 1)
        self.assertLess(len(__import__('json').dumps(audit).encode()), 4096)

    def test_signal_recorded_during_final_exit_observation_is_retained(self):
        _, _, records = self.run_owner(signal_at_exit=True)
        self.assertEqual(records['result.json']['reason'], 'signal')

    def test_capability_failure_happens_before_child_birth(self):
        # Pre-birth guard requires the actual capability name, not a fake waiter.
        with patch.object(OWNER, 'os', types.SimpleNamespace()):
            with self.assertRaises(RuntimeError): OWNER.require_wait_reservation()
