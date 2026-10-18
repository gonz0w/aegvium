# SPDX-License-Identifier: BSD-3-Clause
"""Independent host finalization gates for an owned native run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

SPEC = importlib.util.spec_from_file_location('cleanup_image', Path(__file__).with_name('native-image.py'))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)


def process_absent(pid, group=False):
    """Observe with signal zero; never terminate an identity obtained from a receipt."""
    try:
        (os.killpg if group else os.kill)(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def receipt(path):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate receipt field')
            result[key] = value
        return result

    with os.fdopen(IMAGE.regular_fd(path), 'rb') as stream:
        data = stream.read(4097)
    if len(data) > 4096:
        raise ValueError('receipt size bound')
    value = json.loads(data, object_pairs_hook=object_pairs)
    if not isinstance(value, dict):
        raise ValueError('receipt object required')
    return value, hashlib.sha256(data).hexdigest()


def stop_supervisor(supervisor, work, duration):
    result = {'teardown_verified': False, 'supervisor_status': 'not-started',
              'receipt_status': 'not-read', 'independent_process_absent': False,
              'independent_group_absent': False}
    if supervisor is None:
        return result
    try:
        supervisor.communicate(timeout=25)  # Controller EOF requests owned group cleanup.
    except (OSError, subprocess.TimeoutExpired):
        try:
            supervisor.terminate()  # Signal the known supervisor handle, never a receipt PID.
        except OSError:
            pass
        try:
            supervisor.communicate(timeout=25)
        except (OSError, subprocess.TimeoutExpired):
            result['supervisor_status'] = 'unacknowledged'
    if result['supervisor_status'] != 'unacknowledged':
        result['supervisor_status'] = 'completed' if type(supervisor.returncode) is int and supervisor.returncode == 0 else 'failed'
    try:
        started, result['started_receipt_sha256'] = receipt(work / 'teardown.started.json')
        final, result['receipt_sha256'] = receipt(work / 'teardown.json')
        if (set(started) != {'pid'} or type(started['pid']) is not int or started['pid'] <= 1
                or set(final) != {'pid', 'returncode', 'reason', 'deadline_seconds', 'escalated', 'teardown_verified'}
                or type(final['pid']) is not int or final['pid'] != started['pid']
                or type(final['returncode']) is not int or type(final['deadline_seconds']) is not int
                or final['deadline_seconds'] != duration
                or final['reason'] not in ('child-exit', 'controller-eof', 'deadline', 'signal')
                or type(final['escalated']) is not bool or type(final['teardown_verified']) is not bool):
            raise ValueError('invalid teardown receipt')
        result.update(final)
        result['reported_teardown_verified'] = final['teardown_verified']
        result['receipt_status'] = 'valid'
        result['independent_process_absent'] = process_absent(final['pid'])
        result['independent_group_absent'] = process_absent(final['pid'], group=True)
        result['teardown_verified'] = bool(final['teardown_verified']
            and result['supervisor_status'] == 'completed'
            and result['independent_process_absent'] and result['independent_group_absent'])
    except FileNotFoundError:
        result['receipt_status'] = 'missing'
    except OSError:
        result['receipt_status'] = 'unreadable'
    except (ValueError, TypeError):
        result['receipt_status'] = 'invalid'
    return result


def integrity(report, image, expected, source, root, digest, git):
    """Attempt every independent gate even when another gate cannot be read."""
    states = {}
    checks = {
        'baseline_unchanged': lambda: digest(image) == expected,
        'head_unchanged': lambda: report['commit'] == git('rev-parse', 'HEAD'),
        'worktree_clean': lambda: not git('status', '--porcelain'),
    }
    for name, check in checks.items():
        try:
            report[name] = bool(check())
            states[name] = 'passed' if report[name] else 'failed'
        except (Exception, KeyboardInterrupt):
            report[name], states[name] = False, 'unavailable'
    changed = unreadable = 0
    for name, expected_hash in source.items():
        try:
            changed += digest(root / name) != expected_hash
        except (Exception, KeyboardInterrupt):
            unreadable += 1
    report['source_unchanged'] = not (changed or unreadable)
    states['source_unchanged'] = 'unavailable' if unreadable else 'failed' if changed else 'passed'
    report['integrity'] = {'gates': states, 'source_file_count': len(source),
                           'changed_source_count': changed, 'unreadable_source_count': unreadable}
