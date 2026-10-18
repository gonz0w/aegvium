# SPDX-License-Identifier: BSD-3-Clause
"""Exercise actual process ownership and teardown, without a VM."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SUPERVISOR = Path(__file__).resolve().parents[1] / 'lab-supervisor.py'


class SupervisorTests(unittest.TestCase):
    def exercise(self, code, duration=30, eof=False, stop_signal=False):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            child = subprocess.Popen(
                [sys.executable, str(SUPERVISOR), str(result), str(duration),
                 '--', sys.executable, '-c', code.replace('READY_PATH', repr(str(Path(folder) / 'ready')))], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready = Path(folder) / 'ready'
                # Child readiness is explicit, avoiding a signal-handler race.
                if eof or stop_signal:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        if child.poll() is not None:
                            self.fail('supervisor exited before child readiness')
                        time.sleep(0.02)
                    self.assertTrue(ready.exists())
                    if eof:
                        child.stdin.close()
                        child.stdin = None
                    else:
                        child.terminate()
                if not eof and not stop_signal:
                    child.wait(timeout=20)  # Keep controller stdin open until exit.
                stdout, stderr = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, (stdout, stderr))
                receipt = json.loads(result.read_text())
                self.assertTrue(receipt['teardown_verified'])
                started = result.with_suffix('.started.json')
                self.assertEqual(json.loads(started.read_text())['pid'], receipt['pid'])
                for path in (started, result): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(list(Path(folder).glob('.teardown*')), [])
                with self.assertRaises(ProcessLookupError): os.kill(receipt['pid'], 0)
                with self.assertRaises(ProcessLookupError): os.killpg(receipt['pid'], 0)
                return receipt
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.communicate(timeout=20)

    def test_controller_eof(self):
        self.assertEqual(self.run_ready(False)['reason'], 'controller-eof')

    def run_ready(self, resistant):
        # exercise substitutes this placeholder with its owned temporary path.
        code = "import signal,time; from pathlib import Path; "
        if resistant:
            code += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        code += "Path(READY_PATH).touch(); time.sleep(60)"
        return self.exercise(code, eof=True)

    def test_deadline(self):
        receipt = self.exercise('import time; time.sleep(60)', duration=1)
        self.assertEqual(receipt['reason'], 'deadline')

    def test_term_resistant_child(self):
        receipt = self.run_ready(True)
        self.assertTrue(receipt['escalated'])

    def test_normal_child_exit(self):
        receipt = self.exercise('pass')
        self.assertEqual(receipt['reason'], 'child-exit')
        self.assertEqual(receipt['returncode'], 0)

    def test_supervisor_signal_stops_owned_child(self):
        code = 'import time; from pathlib import Path; Path(READY_PATH).touch(); time.sleep(60)'
        receipt = self.exercise(code, stop_signal=True)
        self.assertEqual(receipt['reason'], 'signal')

    def test_leader_exit_does_not_leave_term_resistant_descendant(self):
        code = ('import subprocess,sys,time; from pathlib import Path; '
                'subprocess.Popen([sys.executable,"-c", '
                '"import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM, signal.SIG_IGN); "'
                '+ "Path(" + repr(READY_PATH) + ").touch(); time.sleep(60)"]); '
                '\nwhile not Path(READY_PATH).exists(): time.sleep(0.01)')
        receipt = self.exercise(code)
        self.assertEqual(receipt['reason'], 'child-exit')
        self.assertTrue(receipt['escalated'])

    def test_connector_profile_maximum_is_bounded_and_reaped(self):
        receipt = self.exercise('pass', duration=3600)
        self.assertEqual(receipt['deadline_seconds'], 3600)
        self.assertFalse(receipt['escalated'])

    def test_unbounded_deadline_rejected(self):
        result = subprocess.run([sys.executable, str(SUPERVISOR), '/tmp/unused',
                                 '3601', '--', sys.executable, '-c', 'pass'],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_startup_receipt_failure_still_reaps_owned_child(self):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            result.with_suffix('.started.json').mkdir()  # Force a real I/O failure.
            child = subprocess.Popen(
                [sys.executable, str(SUPERVISOR), str(result), '30', '--',
                 sys.executable, '-c', 'import time; time.sleep(60)'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = child.communicate(timeout=20)
            self.assertNotEqual(child.returncode, 0, (stdout, stderr))
            self.assertTrue(json.loads(result.read_text())['teardown_verified'])

    def test_final_receipt_failure_cannot_succeed_and_still_reaps_child(self):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            code = ('import importlib.util,sys; from pathlib import Path\n'
                    f's=importlib.util.spec_from_file_location("supervisor",{str(SUPERVISOR)!r})\n'
                    'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
                    'original=m.PROGRESS.atomic_json\n'
                    'def save(path,value):\n'
                    ' if path.name=="teardown.json": raise OSError("owned write failure")\n'
                    ' return original(path,value)\n'
                    'm.PROGRESS.atomic_json=save\n'
                    f'sys.argv=["supervisor",{str(result)!r},"30","--",sys.executable,"-c","pass"]\n'
                    'sys.exit(m.main())\n')
            child = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.communicate(timeout=20)
            self.assertNotEqual(child.returncode, 0)
            self.assertFalse(result.exists())
            pid = json.loads(result.with_suffix('.started.json').read_text())['pid']
            with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
            with self.assertRaises(ProcessLookupError): os.killpg(pid, 0)
