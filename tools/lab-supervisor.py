# SPDX-License-Identifier: BSD-3-Clause
"""Own a disposable process group; controller EOF and a bounded deadline initiate teardown.

Adapted from Nomvium tools/lab-supervisor.py (BSD-3-Clause)."""
import importlib.util
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('supervisor_progress', Path(__file__).with_name('native-progress.py'))
PROGRESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROGRESS)


def main():
    record = Path(sys.argv[1])
    duration = int(sys.argv[2])
    command = sys.argv[4:]
    if not 1 <= duration <= 3600 or sys.argv[3] != '--' or not command:
        raise ValueError('expected result path deadline-seconds (1..3600) -- command')
    expires = time.monotonic() + duration
    reason = 'child-exit'
    stopping = False

    def request_stop(why):
        nonlocal stopping, reason
        if not stopping:
            reason = why
            stopping = True

    def stop(_number, _frame):
        request_stop('signal')

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    selector = selectors.DefaultSelector()
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
    escalated = False
    try:
        PROGRESS.atomic_json(record.with_suffix('.started.json'), {'pid': child.pid})
        selector.register(sys.stdin, selectors.EVENT_READ)
        while child.poll() is None and not stopping:
            if time.monotonic() >= expires:
                request_stop('deadline')
            elif selector.select(timeout=min(0.2, max(0, expires - time.monotonic()))):
                if not os.read(sys.stdin.fileno(), 1024):
                    request_stop('controller-eof')
    finally:
        stopping = True  # Freeze the observed cause before cleanup can receive more signals.
        selector.close()
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            escalated = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        # A parent can exit while a descendant ignores TERM. Own the whole group.
        deadline = time.monotonic() + 5
        while True:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                escalated = True
                os.killpg(child.pid, signal.SIGKILL)
                break
            time.sleep(0.05)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        try:
            os.killpg(child.pid, 0)
            verified = False
        except ProcessLookupError:
            verified = True
        PROGRESS.atomic_json(record, {'pid': child.pid, 'returncode': child.returncode,
                                     'reason': reason, 'deadline_seconds': duration,
                                     'escalated': escalated,
                                     'teardown_verified': verified})
    return 0 if verified else 1


if __name__ == '__main__':
    sys.exit(main())
