# SPDX-License-Identifier: BSD-3-Clause
"""Owned host receipt/finalization faults; no guest or application execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('native_cleanup', Path(__file__).resolve().parents[1] / 'native-cleanup.py')
CLEANUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANUP)


class CleanupTests(unittest.TestCase):
    def receipts(self, work):
        started = work / 'teardown.started.json'
        final = work / 'teardown.json'
        started.write_text(json.dumps({'pid': 24680}))
        final.write_text(json.dumps({'pid': 24680, 'returncode': 0, 'reason': 'controller-eof',
                                    'deadline_seconds': 900, 'escalated': False, 'teardown_verified': True}))
        return started, final

    def test_receipts_require_exact_identity_schema_and_independent_absence(self):
        cases = ('valid', 'missing-start', 'missing-final', 'malformed', 'partial', 'unknown',
                 'pid-mismatch', 'invalid-pid', 'duration', 'boolean-duration', 'boolean-returncode',
                 'reason', 'negative', 'nonboolean', 'duplicate', 'oversized', 'symlink',
                 'live-process', 'live-group', 'supervisor-failed')
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            for case in cases:
                with self.subTest(case=case):
                    for path in work.iterdir(): path.unlink()
                    started, final = self.receipts(work)
                    value = json.loads(final.read_text())
                    if case == 'missing-start': started.unlink()
                    elif case == 'missing-final': final.unlink()
                    elif case == 'malformed': final.write_text('{')
                    elif case == 'duplicate': final.write_text('{"pid":24680,"pid":24680}')
                    elif case == 'oversized': final.write_bytes(b' ' * 4097)
                    elif case == 'symlink':
                        target = work / 'target'; final.rename(target); final.symlink_to(target)
                    else:
                        if case == 'partial': value.pop('returncode')
                        elif case == 'unknown': value['unknown'] = True
                        elif case == 'pid-mismatch': value['pid'] += 1
                        elif case == 'invalid-pid':
                            started.write_text('{"pid":1}'); value['pid'] = 1
                        elif case == 'duration': value['deadline_seconds'] = 1800
                        elif case == 'boolean-duration': value['deadline_seconds'] = True
                        elif case == 'boolean-returncode': value['returncode'] = False
                        elif case == 'reason': value['reason'] = 'unknown'
                        elif case == 'negative': value['teardown_verified'] = False
                        elif case == 'nonboolean': value['escalated'] = 0
                        final.write_text(json.dumps(value))
                    supervisor = Mock(returncode=1 if case == 'supervisor-failed' else 0)
                    with patch.object(CLEANUP, 'process_absent', side_effect=lambda pid, group=False:
                            not (case == 'live-group' and group or case == 'live-process' and not group)):
                        result = CLEANUP.stop_supervisor(supervisor, work, 900)
                    self.assertEqual(result['teardown_verified'], case == 'valid')
                    supervisor.communicate.assert_called_once_with(timeout=25)
                    supervisor.terminate.assert_not_called()
                    supervisor.kill.assert_not_called()
                    if case == 'valid':
                        self.assertEqual(result['receipt_status'], 'valid')
                        self.assertEqual(result['receipt_sha256'], hashlib.sha256(final.read_bytes()).hexdigest())
                        self.assertTrue(result['independent_process_absent'])
                        self.assertTrue(result['independent_group_absent'])

    def test_cleanup_io_timeout_and_signal_failure_still_admit_receipt_separately(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve(); self.receipts(work)
            for kind in ('timeout', 'io', 'signal-failure', 'recovered'):
                with self.subTest(kind=kind):
                    error = subprocess.TimeoutExpired(['owned-supervisor'], 25) if kind == 'timeout' else OSError('owned failure')
                    supervisor = Mock(returncode=0)
                    supervisor.communicate.side_effect = [error, None if kind == 'recovered' else error]
                    if kind == 'signal-failure': supervisor.terminate.side_effect = OSError('owned failure')
                    with patch.object(CLEANUP, 'process_absent', return_value=True):
                        result = CLEANUP.stop_supervisor(supervisor, work, 900)
                    self.assertEqual(result['teardown_verified'], kind == 'recovered')
                    self.assertEqual(result['receipt_status'], 'valid')
                    self.assertEqual(result['supervisor_status'], 'completed' if kind == 'recovered' else 'unacknowledged')
                    self.assertEqual(supervisor.communicate.call_count, 2)
                    self.assertTrue(all(c.kwargs == {'timeout': 25} for c in supervisor.communicate.call_args_list))
                    supervisor.terminate.assert_called_once_with()
                    supervisor.kill.assert_not_called()

    def test_missing_supervisor_cannot_claim_cleanup(self):
        result = CLEANUP.stop_supervisor(None, Path('/unused-owned-run'), 900)
        self.assertFalse(result['teardown_verified'])
        self.assertEqual(result['receipt_status'], 'not-read')

    def test_absence_observation_never_sends_terminating_signals(self):
        for group in (False, True):
            for state in ('absent', 'present', 'unknown'):
                with self.subTest(group=group, state=state):
                    effect = ProcessLookupError() if state == 'absent' else PermissionError() if state == 'unknown' else None
                    with patch.object(os, 'kill', side_effect=effect) as process, patch.object(os, 'killpg', side_effect=effect) as process_group:
                        self.assertEqual(CLEANUP.process_absent(24680, group), state == 'absent')
                    selected, other = (process_group, process) if group else (process, process_group)
                    selected.assert_called_once_with(24680, 0)
                    other.assert_not_called()

    def test_integrity_changes_and_unavailable_sources_do_not_short_circuit(self):
        report = {'commit': 'a' * 40}
        visited = []
        def digest(path):
            visited.append(path.name)
            if path.name == 'unavailable': raise OSError('owned failure')
            return 'changed' if path.name in ('base', 'first') else 'expected'
        CLEANUP.integrity(report, Path('base'), 'expected',
            {'first': 'expected', 'unavailable': 'expected', 'last': 'expected'}, Path('owned'),
            digest, lambda *args: 'a' * 40 if args[0] == 'rev-parse' else 'changed worktree')
        self.assertEqual(visited, ['base', 'first', 'unavailable', 'last'])
        self.assertFalse(report['baseline_unchanged'])
        self.assertFalse(report['source_unchanged'])
        self.assertFalse(report['worktree_clean'])
        self.assertTrue(report['head_unchanged'])
        self.assertEqual(report['integrity']['changed_source_count'], 1)
        self.assertEqual(report['integrity']['unreadable_source_count'], 1)
