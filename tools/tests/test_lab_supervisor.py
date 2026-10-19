# SPDX-License-Identifier: BSD-3-Clause
"""Exercise actual process ownership and teardown, without a VM."""
import json
import signal
import uuid
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from ordinary_fixture import SupervisorFixture

SUPERVISOR = Path(__file__).resolve().parents[1] / 'lab-supervisor.py'


class SupervisorTests(unittest.TestCase):
    def exercise(self, code, duration=30, eof=False, stop_signal=False):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            with SupervisorFixture(
                [sys.executable, str(SUPERVISOR), str(result), str(duration),
                 '--', sys.executable, '-c', code.replace('READY_PATH', repr(str(Path(folder) / 'ready')))], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, record=result) as child:
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
                    audit = json.loads(result.with_suffix('.ownership.json').read_text())
                    self.assertTrue(audit['child_reaped'])
                    self.assertIsInstance(audit['raw_wait_status'], int)
                    self.assertTrue(audit['pid_absent'] and audit['group_absent'])
                    self.assertIn(signal.SIGKILL, [entry['signal'] for entry in audit['signals']])
                    for path in (started, result, result.with_suffix('.ownership.json')): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(list(Path(folder).glob('.teardown*')), [])
                    with self.assertRaises(ProcessLookupError): os.kill(receipt['pid'], 0)
                    with self.assertRaises(ProcessLookupError): os.killpg(receipt['pid'], 0)
                    descendant = int(ready.read_text()) if ready.exists() and ready.read_text().isdigit() else None
                    if descendant:
                        deadline = time.monotonic()+3
                        while time.monotonic() < deadline:
                            try: os.kill(descendant, 0)
                            except ProcessLookupError: break
                            time.sleep(.02)
                        with self.assertRaises(ProcessLookupError): os.kill(descendant, 0)
                    evidence = os.environ.get('SUITE_OWNERSHIP_EVIDENCE')
                    if evidence:
                        proof = dict(owner=audit, supervisor_pid=child.pid, supervisor_returncode=child.returncode,
                                     independent_pid_absent=True, independent_group_absent=True,
                                     descendant_pid=descendant, independent_descendant_absent=bool(descendant))
                        path = Path(evidence)/('python-'+uuid.uuid4().hex+'.json')
                        with path.open('x') as stream: json.dump(proof, stream, sort_keys=True)
                    return receipt
                finally:
                    pass  # SupervisorFixture independently owns terminal cleanup.

    def test_controller_eof(self):
        self.assertEqual(self.run_ready(False)['reason'], 'controller-eof')

    def run_ready(self, resistant):
        # exercise substitutes this placeholder with its owned temporary path.
        code = "import signal,time; from pathlib import Path; "
        if resistant:
            code += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        code += "Path(READY_PATH).touch(); time.sleep(10)"
        return self.exercise(code, eof=True)

    def test_deadline(self):
        receipt = self.exercise('import time; time.sleep(10)', duration=1)
        self.assertEqual(receipt['reason'], 'deadline')

    def test_term_resistant_child(self):
        receipt = self.run_ready(True)
        self.assertTrue(receipt['escalated'])

    def test_normal_child_exit(self):
        receipt = self.exercise('pass')
        self.assertEqual(receipt['reason'], 'child-exit')
        self.assertEqual(receipt['returncode'], 0)

    def test_supervisor_signal_stops_owned_child(self):
        code = 'import time; from pathlib import Path; Path(READY_PATH).touch(); time.sleep(10)'
        receipt = self.exercise(code, stop_signal=True)
        self.assertEqual(receipt['reason'], 'signal')

    def test_leader_exit_does_not_leave_term_resistant_descendant(self):
        code = ('import subprocess,sys,time; from pathlib import Path; '
                'subprocess.Popen([sys.executable,"-c", '
                '"import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM, signal.SIG_IGN); "'
                '+ "Path(" + repr(READY_PATH) + ").write_text(str(os.getpid())); time.sleep(10)"]); '
                'end=time.monotonic()+3\n'
                'while not Path(READY_PATH).exists() and time.monotonic()<end: time.sleep(0.01)\n'
                'assert Path(READY_PATH).exists()')
        receipt = self.exercise(code)
        self.assertEqual(receipt['reason'], 'child-exit')
        # The leader already exited; the retained ownership audit proves the
        # final group KILL and external observations prove descendant absence.
        self.assertFalse(receipt['escalated'])

    def test_connector_profile_maximum_is_bounded_and_reaped(self):
        receipt = self.exercise('pass', duration=3600)
        self.assertEqual(receipt['deadline_seconds'], 3600)
        self.assertFalse(receipt['escalated'])

    def test_unbounded_deadline_rejected(self):
        result = subprocess.run([sys.executable, str(SUPERVISOR), '/tmp/unused',
                                 '3601', '--', sys.executable, '-c', 'pass'],
                                capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)

    def test_startup_receipt_failure_still_reaps_owned_child(self):
        with tempfile.TemporaryDirectory() as folder:
            result = Path(folder) / 'teardown.json'
            result.with_suffix('.started.json').mkdir()  # Force a real I/O failure.
            with SupervisorFixture(
                [sys.executable, str(SUPERVISOR), str(result), '30', '--',
                 sys.executable, '-c', 'import time; time.sleep(10)'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, record=result) as child:
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
            with SupervisorFixture([sys.executable, '-c', code], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, record=result) as child:
                child.communicate(timeout=20)
                self.assertNotEqual(child.returncode, 0)
                self.assertFalse(result.exists())
                pid = json.loads(result.with_suffix('.started.json').read_text())['pid']
                with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
                with self.assertRaises(ProcessLookupError): os.killpg(pid, 0)
