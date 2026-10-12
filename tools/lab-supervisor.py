# SPDX-License-Identifier: BSD-3-Clause
"""Own a disposable process group; controller EOF and a bounded deadline initiate teardown.

Adapted from Nomvium tools/lab-supervisor.py (BSD-3-Clause)."""
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path


def main():
    record = Path(sys.argv[1])
    duration = int(sys.argv[2])
    command = sys.argv[4:]
    if not 1 <= duration <= 900 or sys.argv[3] != '--' or not command:
        raise ValueError('expected result path deadline-seconds (1..900) -- command')
    expires = time.monotonic() + duration
    reason = 'child-exit'
    stopping = False

    def stop(_number, _frame):
        nonlocal stopping, reason
        stopping = True
        reason = 'signal'

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
    record.with_suffix('.started.json').write_text(json.dumps({'pid': child.pid}) + '\n')
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin, selectors.EVENT_READ)
    escalated = False
    try:
        while child.poll() is None and not stopping:
            if time.monotonic() >= expires:
                reason = 'deadline'
                stopping = True
            elif selector.select(timeout=min(0.2, max(0, expires - time.monotonic()))):
                if not os.read(sys.stdin.fileno(), 1024):
                    reason = 'controller-eof'
                    stopping = True
    finally:
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
        record.write_text(json.dumps({'pid': child.pid, 'returncode': child.returncode,
                                     'reason': reason, 'deadline_seconds': duration,
                                     'escalated': escalated,
                                     'teardown_verified': verified}) + '\n')
    return 0 if verified else 1


if __name__ == '__main__':
    sys.exit(main())
