# SPDX-License-Identifier: BSD-3-Clause
"""Exact ordinary lifecycle units; never WAF/traffic/profile admission."""
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = {
    'TestLabGenerationDrain', 'TestLabReloadRetirementFailure',
    'TestLabShutdownConcurrentClose', 'TestLabShutdownDrainedServeFailure',
    'TestLabShutdownErrorOwnership', 'TestLabShutdownLeaseRetirement',
    'TestLabShutdownMissingJoin', 'TestLabShutdownReloadErrorCause',
    'TestLabSupervisionCloseExitRace', 'TestLabSupervisionCompletion',
    'TestLabSupervisionConcurrentFailureCleanup', 'TestLabSupervisionExpectedShutdown',
}
CONTROL = {
    'TestLabControlCleanupError', 'TestLabControlFailureDuringClose',
    'TestLabControlFailureDuringReload', 'TestLabControlReload',
    'TestLabControlServerFailure', 'TestLabControlStopPriority',
}
LIBRARY_CHILDREN = {
    'TestLabShutdownErrorOwnership/' + name for name in
    ('drained-retirement-errors', 'failed-drain-retains-generation', 'normal-serve-completions')
} | {'TestLabShutdownMissingJoin/' + name for name in ('absent', 'closed', 'stalled')}
CONTROL_CHILDREN = {
    'TestLabControlReload/' + name for name in ('accepted', 'config-error', 'reload-error', 'retirement-error')
} | {'TestLabControlFailureDuringReload/' + name for name in ('read', 'reload')}


def selection(names):
    return '^(' + '|'.join(sorted(names)) + ')$'


def admitted_suite(text, expected):
    passed = re.findall(r'^\s*--- PASS: (\S+) \([0-9.]+s\)$', text, re.M)
    if (len(passed) != len(expected) or set(passed) != expected
            or re.search(r'--- (?:FAIL|SKIP):', text)
            or len(re.findall(r'^PASS$', text, re.M)) != 1
            or re.search(r'^FAIL(?:\s|$)', text, re.M)):
        raise ValueError('lifecycle test set incomplete')
    return len(passed)


def admit(text, hashes):
    if len(text) > 1024 * 1024:
        raise ValueError('lifecycle evidence oversized')
    receipts, bodies, active = {}, {}, None
    for line in text.splitlines():
        if line.startswith('LIFECYCLE\t'):
            parts = line.split('\t')
            if active is not None or len(parts) != 3 or parts[1] in receipts:
                raise ValueError('lifecycle receipt invalid')
            if parts[1] == 'complete' and set(bodies) != {'library', 'control'}:
                raise ValueError('premature lifecycle completion')
            receipts[parts[1]] = parts[2]
        elif line.startswith('LIFECYCLE-BEGIN '):
            name = line.removeprefix('LIFECYCLE-BEGIN ')
            if active is not None or name not in ('library', 'control') or name in bodies or (name == 'control' and 'library' not in bodies):
                raise ValueError('lifecycle suite order invalid')
            active = name
            bodies[name] = []
        elif line.startswith('LIFECYCLE-END '):
            if active is None or line != 'LIFECYCLE-END ' + active:
                raise ValueError('lifecycle suite end invalid')
            active = None
        elif active is not None:
            bodies[active].append(line)
        elif line.lstrip().startswith(('=== ', '--- ', 'PASS', 'FAIL')):
            raise ValueError('test output outside lifecycle suite')
    wanted = {**hashes, 'os': 'OpenBSD 7.9 amd64', 'uid': '32767',
              'scope': 'ordinary-components', 'complete': 'verified'}
    if active is not None or set(bodies) != {'library', 'control'} or receipts != wanted:
        raise ValueError('lifecycle identity/suite incomplete')
    if set(hashes) != {'library', 'control'} or any(not re.fullmatch('[0-9a-f]{64}', h) for h in hashes.values()):
        raise ValueError('lifecycle input hash invalid')
    library = admitted_suite('\n'.join(bodies['library']), LIBRARY | LIBRARY_CHILDREN)
    control = admitted_suite('\n'.join(bodies['control']), CONTROL | CONTROL_CHILDREN)
    return {'admitted': True, 'scope': 'ordinary-components-only',
            'parent_count': len(LIBRARY) + len(CONTROL), 'subtest_count': len(LIBRARY_CHILDREN) + len(CONTROL_CHILDREN),
            'pass_count': library + control, 'receipts': receipts,
            'native_source_build': False, 'complete_profile_qualified': False}


def guest_run(guest, work, library, library_hash, control, control_hash):
    inputs = {'library': (library, library_hash), 'control': (control, control_hash)}
    for path, wanted in inputs.values():
        if not re.fullmatch('[0-9a-f]{64}', wanted) or hashlib.sha256(path.read_bytes()).hexdigest() != wanted:
            raise ValueError('lifecycle cross-build changed before transfer')
    guest.require('set -eu; mkdir /var/aegvium-lifecycle; chmod 755 /var/aegvium-lifecycle')
    hashes = {name: pair[1] for name, pair in inputs.items()}
    for name, (path, wanted) in inputs.items():
        with path.open('rb') as stream:
            result = guest.call('set -eu; cat > /var/aegvium-lifecycle/' + name + '.test; chmod 555 /var/aegvium-lifecycle/' + name + '.test', stream=stream, seconds=120)
        if result.returncode:
            raise RuntimeError('lifecycle binary transfer failed')
        guest.require('test "$(sha256 -q /var/aegvium-lifecycle/' + name + '.test)" = "' + wanted + '"')
    script = (ROOT / 'tools/native/lifecycle-components.sh').read_bytes()
    for token, value in {'LIBRARY_SHA256': library_hash, 'CONTROL_SHA256': control_hash,
                         'LIBRARY_SELECTION': selection(LIBRARY), 'CONTROL_SELECTION': selection(CONTROL)}.items():
        script = script.replace(token.encode(), value.encode())
    log = work / 'lifecycle-components.log'
    code, error_class = None, 'none'
    with log.open('wb') as output:
        try:
            code = guest.call('sh -s', data=script, seconds=120, output=output).returncode
        except (TimeoutError, subprocess.TimeoutExpired):
            error_class = 'timeout'
        except OSError:
            error_class = 'io'
    text = log.read_text(errors='replace')
    result = {'admitted': False, 'hashes': hashes, 'execution_returncode': code,
              'execution_error_class': error_class, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
              'observed_pass_count': len(re.findall(r'^\s*--- PASS:', text, re.M))}
    try:
        result.update(admit(text, hashes))
    except ValueError:
        result['admission_error'] = 'incomplete-or-invalid-lifecycle-evidence'
    if code != 0 or error_class != 'none':
        result['admitted'] = False
    return result
