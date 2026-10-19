# SPDX-License-Identifier: BSD-3-Clause
"""Own a disposable process group; controller EOF and a bounded deadline initiate teardown.

Adapted from Nomvium tools/lab-supervisor.py (BSD-3-Clause)."""
import errno
import importlib.util
import math
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


def own_ordinary(child, record, created, work_end, total_end, duration, stopped, write_started, write_final, triggers=None):
    """Own only this born PID/group; WNOWAIT reserves it through the last signal."""
    triggers = {} if triggers is None else triggers
    def choose(value):
        # The signal handler shares this latch. setdefault makes one fixed
        # dictionary operation choose the first observed trigger.
        if stopped():
            triggers.setdefault('reason', 'signal')
        return triggers.setdefault('reason', value)

    pid = child.pid
    reserved, exited, reaped = True, False, False
    reason, primary, selector = 'child-exit', None, None
    errors, signals = [], []
    raw_status = None
    escalated, expired = False, False
    no_more_signals = False
    last_time, clock_failed = created, False

    def failed(phase, error):
        errors.append({'phase': phase, 'type': type(error).__name__,
                       'errno': getattr(error, 'errno', None)})

    def now():
        nonlocal last_time, clock_failed
        if clock_failed:
            return total_end
        try:
            value = time.monotonic()
            if not math.isfinite(value) or value < last_time:
                raise RuntimeError('invalid monotonic clock')
            last_time = value
            return value
        except BaseException as error:
            clock_failed = True
            failed('clock', error)
            return total_end  # No new time budget; later stages still try once.

    def observe():
        nonlocal reserved, exited
        if not reserved:
            return False
        if child.pid != pid:
            reserved = False
            failed('ownership', RuntimeError('changed born process binding'))
            return False
        try:
            state = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            exited = state is not None
        except InterruptedError:
            return False  # WNOWAIT did not consume the reservation.
        except BaseException as error:
            reserved = False  # ECHILD/unknown never grants a new signal or wait.
            failed('observe', error)
        return exited

    def send(number):
        nonlocal no_more_signals
        if not reserved or no_more_signals:
            return
        entry = {'signal': number, 'exit_observed_before': exited, 'errno': None}
        try:
            os.killpg(pid, number)
        except ProcessLookupError:
            entry['errno'] = errno.ESRCH  # ESRCH remains a real, redundant signal outcome.
        except BaseException as error:
            entry['errno'] = getattr(error, 'errno', None)
            entry['type'] = type(error).__name__
            no_more_signals = True
        signals.append(entry)

    try:
        write_started(record.with_suffix('.started.json'))
        selector = selectors.DefaultSelector()
        selector.register(sys.stdin, selectors.EVENT_READ)
        while reserved:
            if stopped():
                reason = choose('signal')
                break
            if observe() or not reserved:
                break
            if now() >= work_end:
                reason = choose('deadline')
                expired = reason == 'deadline'
                break
            if selector.select(timeout=min(.2, max(0, work_end-now()))):
                if not os.read(sys.stdin.fileno(), 1024):
                    reason = choose('controller-eof')
                    break
    except BaseException as error:
        primary = error
        failed('body', error)
    finally:
        # Each stage is independent: a close/observer/signal error cannot skip
        # the later safe stages. Signal handlers only set a flag.
        try:
            if selector is not None:
                selector.close()
        except BaseException as error:
            failed('selector-close', error)
        try:
            observe()
            if reserved and not exited:
                send(signal.SIGTERM)
                until = min(now()+5, total_end-5)
                for _ in range(101):
                    if not reserved or observe() or now() >= until:
                        break
                    time.sleep(min(.05, max(0, until-now())))
        except BaseException as error:
            failed('terminate', error)
        finally:
            escalated = reserved and not exited
            send(signal.SIGKILL)  # Last positive signal; leader is still unreaped.
        try:
            until = min(now()+5, total_end)
            for _ in range(251):
                if not reserved:
                    break
                try:
                    waited, status = os.waitpid(pid, os.WNOHANG)
                except InterruptedError:
                    if now() >= until:
                        break
                    continue  # EINTR consumed no wait or custody; original budget only.
                if waited == pid:
                    reserved, raw_status = False, status
                    if not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                        failed('wait-status', RuntimeError('nonterminal wait'))
                        break
                    reaped = True
                    child.returncode = os.waitstatus_to_exitcode(status)
                    break
                if now() >= until:
                    break
                time.sleep(min(.02, max(0, until-now())))
        except BaseException as error:
            reserved = False
            failed('wait', error)

    # Never positively signal after the sole terminal wait (including ECHILD).
    def absent(target):
        try:
            os.kill(target, 0)
        except ProcessLookupError:
            return True
        except BaseException as error:
            failed('absence', error)
            return False
        return False
    pid_absent = group_absent = False
    until = min(now()+5, total_end)
    for _ in range(251):
        pid_absent, group_absent = absent(pid), absent(-pid)
        if pid_absent and group_absent or now() >= until:
            break
        try:
            time.sleep(min(.02, max(0, until-now())))
        except BaseException as error:
            failed('absence-sleep', error)
            break
    verified = reaped and pid_absent and group_absent
    # Darwin can refuse signaling a zombie-only group. Preserve the errno; it
    # is redundant only with earlier WNOWAIT exit, actual wait, and dual absence.
    signal_failure = any(e.get('type') and not (
        e.get('errno') == errno.EPERM and e['exit_observed_before'] and verified)
        for e in signals)
    deadline_met = not clock_failed and now() < total_end
    audit = {'pid': pid, 'group': pid, 'raw_wait_status': raw_status,
             'child_reaped': reaped, 'pid_absent': pid_absent, 'group_absent': group_absent,
             'signals': signals, 'errors': errors, 'expired': expired, 'deadline_met': deadline_met,
             'created_monotonic': created, 'deadline_monotonic': total_end,
             'scope': 'Original direct child and its process group only; detached sessions are not covered.'}
    try:
        write_final(record, {'pid': pid, 'returncode': child.returncode,
                            'reason': reason, 'deadline_seconds': duration,
                            'escalated': escalated, 'teardown_verified': verified})
    except BaseException as error:
        failed('final-receipt', error)
    try:
        # Keep the exact older final receipt shape; detailed ownership is separate.
        write_final(record.with_suffix('.ownership.json'), audit)
    except BaseException as error:
        failed('ownership-receipt', error)
    publication_met = now() < total_end and not clock_failed
    if primary is not None:
        raise primary
    return 0 if verified and deadline_met and publication_met and not errors and not signal_failure else 1


def require_wait_reservation():
    if not all(hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'P_PID', 'WNOHANG', 'WEXITED')):
        raise RuntimeError('WNOWAIT ownership unavailable')
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError('default SIGCHLD disposition unavailable')


def main():
    record = Path(sys.argv[1])
    duration = int(sys.argv[2])
    command = sys.argv[4:]
    if not 1 <= duration <= 3600 or sys.argv[3] != '--' or not command:
        raise ValueError('expected result path deadline-seconds (1..3600) -- command')
    stopping = False
    triggers = {}
    def stop(_number, _frame):
        nonlocal stopping
        stopping = True
        triggers.setdefault('reason', 'signal')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    require_wait_reservation()
    created = time.monotonic()
    if not math.isfinite(created) or created < 0 or not math.isfinite(created+duration+20):
        raise RuntimeError('invalid initial monotonic deadline')
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
    return own_ordinary(child, record, created, created+duration, created+duration+20,
                        duration, lambda: stopping,
                        lambda path: PROGRESS.atomic_json(path, {'pid': child.pid}),
                        PROGRESS.atomic_json, triggers)


if __name__ == '__main__':
    sys.exit(main())
