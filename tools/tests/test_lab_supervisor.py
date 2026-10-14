# SPDX-License-Identifier: BSD-3-Clause
"""Exercise actual process ownership and teardown, without a VM."""
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SUPERVISOR = Path(__file__).resolve().parents[1] / 'lab-supervisor.py'


class SupervisorTests(unittest.TestCase):
    def exercise(self, code, duration=30, eof=False):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            child = subprocess.Popen(
                [sys.executable, str(SUPERVISOR), str(result), str(duration),
                 '--', sys.executable, '-c', code.replace('READY_PATH', repr(str(Path(folder) / 'ready')))], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready = Path(folder) / 'ready'
                # Child readiness is explicit, avoiding a signal-handler race.
                if eof:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        if child.poll() is not None:
                            self.fail('supervisor exited before child readiness')
                        time.sleep(0.02)
                    self.assertTrue(ready.exists())
                    child.stdin.close()
                    child.stdin = None
                if not eof:
                    child.wait(timeout=20)  # Keep controller stdin open until exit.
                stdout, stderr = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, (stdout, stderr))
                receipt = json.loads(result.read_text())
                self.assertTrue(receipt['teardown_verified'])
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
