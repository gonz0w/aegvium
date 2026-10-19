# SPDX-License-Identifier: BSD-3-Clause
"""Independent finite direct-supervisor owner for portable regression fixtures."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


class SupervisorFixture:
    def __init__(self, command, *, record, **unused):
        self.record = record
        self.reserved, self.reaped = False, False
        self.errors, self.signals = [], []
        evidence = Path(os.environ.get('SUITE_OWNERSHIP_EVIDENCE', record.parent))
        self.ledger = evidence/('fixture-'+uuid.uuid4().hex+'.jsonl')
        self.output, self.error = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.event('intent', command_kind='finite portable supervisor')
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                            stdout=self.output, stderr=self.error)
        except BaseException:
            self.output.close(); self.error.close()
            raise
        self.pid = self.process.pid
        self.stdin = self.process.stdin
        self.reserved = True
        try:
            self.event('birth', pid=self.pid)
        except BaseException:
            self.__exit__(None, None, None)
            raise

    @property
    def returncode(self):
        return self.process.returncode

    def event(self, kind, **value):
        fd = os.open(self.ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a') as stream:
            stream.write(json.dumps(dict(event=kind, **value), sort_keys=True)+'\n')

    def poll(self):
        if self.reaped:
            return self.returncode
        if not self.reserved:
            return None
        try:
            state = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            return 0 if state else None  # Readiness only; never a terminal receipt.
        except InterruptedError:
            return None
        except BaseException as error:
            self.reserved = False
            self.errors.append(type(error).__name__)
            return None

    def send(self, number):
        if not self.reserved:
            return
        entry = dict(signal=number, errno=None)
        try:
            os.kill(self.pid, number)
        except BaseException as error:
            entry['errno'] = getattr(error, 'errno', None)
            entry['type'] = type(error).__name__
        self.signals.append(entry)

    def terminate(self):
        self.send(signal.SIGTERM)

    def wait(self, timeout):
        if self.reaped:
            return self.returncode
        try:
            until = time.monotonic()+timeout
            while self.reserved and self.poll() is None and time.monotonic() < until:
                time.sleep(.02)
        except BaseException as error:
            self.errors.append(type(error).__name__)
        # Last positive signal before any consuming wait. An exited zombie can
        # refuse it on Darwin; raw wait and independent absence remain required.
        self.send(signal.SIGKILL)
        until = time.monotonic()+5
        while self.reserved:
            try:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
            except InterruptedError:
                if time.monotonic() >= until: break
                continue
            except BaseException as error:
                self.reserved = False
                self.errors.append(type(error).__name__)
                break
            if waited == self.pid:
                self.reserved = False
                self.reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
                self.process.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() >= until: break
            time.sleep(.02)
        if not self.reaped:
            raise RuntimeError('finite fixture supervisor terminal wait unproven')
        return self.returncode

    def communicate(self, timeout):
        if self.stdin is not None:
            self.stdin.close()
            self.stdin = None
        self.wait(timeout)
        self.output.seek(0); self.error.seek(0)
        return self.output.read(1<<20), self.error.read(1<<20)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        try:
            if self.stdin is not None:
                self.stdin.close()
                self.stdin = None
        except BaseException as error:
            self.errors.append(type(error).__name__)
        try:
            if not self.reaped:
                self.terminate()
                self.wait(1)
        except BaseException as error:
            self.errors.append(type(error).__name__)
        finally:
            # All receipt-derived operations below are observations, never
            # authority for a late signal. Include known targets even on failure.
            targets = {self.pid}
            for path in (self.record, self.record.with_suffix('.started.json'),
                         self.record.with_suffix('.ownership.json')):
                try:
                    value = json.loads(path.read_text())
                    if type(value.get('pid')) is int and value['pid'] > 1:
                        targets.add(value['pid'])
                except (OSError, ValueError): pass
            ready = self.record.parent/'ready'
            try:
                if ready.read_text().isdigit(): targets.add(int(ready.read_text()))
            except OSError: pass
            def absent(target):
                try: os.kill(target, 0)
                except ProcessLookupError: return True
                except OSError: return False
                return False
            until = time.monotonic()+12  # Fixed child sleep10 TTL plus observation.
            while True:
                observations = [dict(pid=pid, pid_absent=absent(pid),
                                     group_absent=absent(-pid)) for pid in sorted(targets)]
                if all(v['pid_absent'] and v['group_absent'] for v in observations) or time.monotonic() >= until:
                    break
                time.sleep(.02)
            try:
                self.event('terminal', pid=self.pid, reaped=self.reaped,
                       returncode=self.returncode, signals=self.signals,
                       errors=self.errors, observations=observations,
                       scope='Known direct supervisor, original child group and finite recorded descendant; no detached/native proof.')
            finally:
                self.output.close(); self.error.close()
        if _exc[0] is None and (not self.reaped or self.errors or not all(v['pid_absent'] and v['group_absent'] for v in observations)):
            raise AssertionError('finite fixture ownership/absence proof failed')
        return False
