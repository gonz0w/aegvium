# SPDX-License-Identifier: BSD-3-Clause
"""Intercepted owner failures only: no files, images, children or signals."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / 'commission-owner.py'
SPEC = importlib.util.spec_from_file_location('commission_owner_source', SOURCE)
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


class CommissionOwnerTests(unittest.TestCase):
    def test_fixed_supervisor_source_closure(self):
        expected = {
            'main.c', 'controller.c', 'controller.h', 'control_frame.c', 'control_frame.h',
            'launch_storage.c', 'launch_storage.h', 'storage_openbsd.c', 'storage_os.h',
            'native_construction.c', 'native_construction.h', 'native_openbsd.c',
            'native_os.h', 'launch_source.inc', 'launch_source_openbsd.c', 'launch_source_os.h',
        }
        self.assertEqual(len(OWNER.SUPERVISOR_INPUTS), 16)
        self.assertEqual({Path(p).name for p in OWNER.SUPERVISOR_INPUTS}, expected)
        self.assertEqual(sum(p.endswith('.c') for p in OWNER.SUPERVISOR_INPUTS), 8)
        for name in OWNER.SUPERVISOR_INPUTS:
            self.assertFalse(Path(name).is_absolute())
            self.assertNotIn('..', Path(name).parts)

    def test_default_entry_and_supplied_owner_have_no_effects(self):
        code = compile(SOURCE.read_bytes(), str(SOURCE), 'exec')
        with patch.object(OWNER.tempfile, 'mkdtemp') as create, \
                patch.object(OWNER.subprocess, 'Popen') as launch, \
                patch.object(OWNER.os, 'open') as opened:
            with self.assertRaises(SystemExit):
                exec(code, {'__name__': '__main__', '__file__': str(SOURCE)})
            with self.assertRaises(OWNER.Incomplete):
                OWNER._Owner()
            create.assert_not_called()
            launch.assert_not_called()
            opened.assert_not_called()

    def test_failed_candidate_retains_owner_and_never_creates_target(self):
        before = len(OWNER._ACTIVE)
        with patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=1000, st_mode=0o40700)), \
                patch.object(OWNER.tempfile, 'mkdtemp', return_value='/not-created'), \
                patch.object(OWNER.os, 'open', return_value=71), \
                patch.object(OWNER.os, 'getuid', return_value=1000), \
                patch.object(OWNER.os, 'fstat', return_value=SimpleNamespace(st_uid=1000, st_mode=0o40700)), \
                patch.object(OWNER.os, 'close') as close, \
                patch.object(OWNER._Owner, '_candidate', side_effect=OWNER.Incomplete('missing real inspector')), \
                patch.object(OWNER._Owner, '_target_and_vm') as target, \
                patch.object(OWNER.subprocess, 'Popen') as launch:
            with self.assertRaises(OWNER.Incomplete):
                OWNER._Owner._create()
            target.assert_not_called()
            launch.assert_not_called()
            close.assert_not_called()
        self.assertEqual(len(OWNER._ACTIVE), before + 1)
        retained = OWNER._ACTIVE[-1]
        self.assertTrue(retained.failed)
        self.assertFalse(retained.prepared)
        self.assertEqual(retained.fds, [71])

    def test_tool_wait_failure_keeps_exact_child_for_owner_cleanup(self):
        owner = object.__new__(OWNER._Owner)
        owner.tools, owner.work = [], Path('/not-created')
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired('intercepted', 2)
        with patch.object(OWNER.subprocess, 'Popen', return_value=child) as launch:
            with self.assertRaises(subprocess.TimeoutExpired):
                owner._command(['/unexecuted/fixed-tool'], seconds=2)
        self.assertEqual(owner.tools, [child])
        launch.assert_called_once()
        self.assertTrue(launch.call_args.kwargs['close_fds'])
        child.wait.assert_called_once_with(timeout=2)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_stop_request_never_substitutes_for_terminal_wait(self):
        owner = object.__new__(OWNER._Owner)
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('intercepted', 5),
                                  subprocess.TimeoutExpired('intercepted', 5)]
        owner.child, owner.tools = child, []
        with self.assertRaises(subprocess.TimeoutExpired):
            owner._stop_owned()
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)
        self.assertIs(owner.child, child)
        self.assertEqual(child.method_calls,
                         [('poll', (), {}), ('terminate', (), {}),
                          ('wait', (), {'timeout': 5}), ('kill', (), {}),
                          ('wait', (), {'timeout': 5})])

    def test_failed_close_is_retained_and_not_retried(self):
        owner = object.__new__(OWNER._Owner)
        owner.fds, owner.close_tried = [71], set()
        with patch.object(OWNER.os, 'close', side_effect=OSError('intercepted')) as close:
            with self.assertRaises(OSError):
                owner._close(71)
            with self.assertRaises(OWNER.Incomplete):
                owner._close(71)
            close.assert_called_once_with(71)
        self.assertEqual(owner.fds, [71])

    def test_input_growth_and_size_bound_refuse_without_unbounded_read(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_size=3)
        with patch.object(OWNER.os, 'fstat', return_value=info), \
                patch.object(OWNER.os, 'pread', side_effect=[b'abc', b'x']):
            with self.assertRaises(OWNER.Incomplete):
                OWNER._digest(71)
        huge = SimpleNamespace(st_size=1024**3 + 1)
        with patch.object(OWNER.os, 'fstat', return_value=huge), \
                patch.object(OWNER.os, 'pread') as read:
            with self.assertRaises(OWNER.Incomplete):
                OWNER._digest(71)
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
