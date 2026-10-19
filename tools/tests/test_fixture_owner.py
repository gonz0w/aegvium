# SPDX-License-Identifier: BSD-3-Clause
"""No-process failures in the independent portable fixture owner."""
from pathlib import Path
import signal
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import ordinary_fixture as FIXTURE


class FixtureOwnerTests(unittest.TestCase):
    def test_close_failure_cannot_skip_kill_raw_wait_or_terminal_ledger(self):
        with tempfile.TemporaryDirectory() as folder:
            owner = FIXTURE.SupervisorFixture.__new__(FIXTURE.SupervisorFixture)
            owner.record = Path(folder)/'result.json'
            owner.pid, owner.reserved, owner.reaped = 424243, True, False
            owner.process = types.SimpleNamespace(returncode=None)
            owner.errors, owner.signals = [], []
            owner.stdin = types.SimpleNamespace(close=Mock(side_effect=OSError('synthetic close')))
            owner.output, owner.error, owner.event = Mock(), Mock(), Mock()
            calls = []
            def kill(pid, number):
                calls.append((pid, number))
                if number == 0: raise ProcessLookupError
            def wait(pid, flags):
                calls.append('wait')
                return pid, 0
            with patch.object(FIXTURE.os, 'waitid', return_value=object()), \
                 patch.object(FIXTURE.os, 'waitpid', wait), patch.object(FIXTURE.os, 'kill', kill):
                with self.assertRaises(AssertionError): owner.__exit__(None, None, None)
            self.assertTrue(owner.reaped)
            self.assertIn((424243, signal.SIGKILL), calls)
            self.assertEqual(calls.count('wait'), 1)
            self.assertLess(calls.index((424243, signal.SIGKILL)), calls.index('wait'))
            owner.event.assert_called_once()
            self.assertEqual(owner.event.call_args.args[0], 'terminal')
            self.assertTrue(all(v['pid_absent'] and v['group_absent']
                                for v in owner.event.call_args.kwargs['observations']))
