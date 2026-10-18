# SPDX-License-Identifier: BSD-3-Clause
"""Exact ordinary lifecycle units; never WAF/traffic/profile admission."""
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD_SECONDS = 1200
POST_BUILD_SECONDS = 180
GUEST_SECONDS = 2400
BUILD_STEPS = ('inputs-verified', 'library-started', 'library-compiled',
               'control-started', 'control-compiled', 'outputs-verified')
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

FILE_INPUTS = {'TestLabFileRegular', 'TestLabFileSpecial', 'TestLabFileDescriptor',
               'TestLabFileLimits', 'TestLabFileOpenFailure'}
FILE_CHILDREN = {'TestLabFileRegular/' + name for name in ('empty', 'below', 'exact', 'above')}
FILE_CHILDREN |= {'TestLabFileSpecial/' + name for name in ('missing', 'symlink', 'directory', 'fifo')}
FILE_CHILDREN |= {'TestLabFileDescriptor/' + name for name in
                  ('regular', 'nonregular', 'oversized-stat', 'stat-error', 'read-error', 'close-error', 'joined-errors', 'growth')}
FILE_CHILDREN |= {'TestLabFileLimits/' + name for name in ('negative', 'zero', 'overflow')}
SUITES = {'library': LIBRARY | LIBRARY_CHILDREN, 'control': CONTROL | CONTROL_CHILDREN,
          'files': FILE_INPUTS | FILE_CHILDREN}


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
            if parts[1] == 'complete' and set(bodies) != set(SUITES):
                raise ValueError('premature lifecycle completion')
            receipts[parts[1]] = parts[2]
        elif line.startswith('LIFECYCLE-BEGIN '):
            name = line.removeprefix('LIFECYCLE-BEGIN ')
            if active is not None or len(bodies) >= len(SUITES) or name != tuple(SUITES)[len(bodies)]:
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
    if active is not None or set(bodies) != set(SUITES) or receipts != wanted:
        raise ValueError('lifecycle identity/suite incomplete')
    if set(hashes) != {'library', 'control'} or any(not re.fullmatch('[0-9a-f]{64}', h) for h in hashes.values()):
        raise ValueError('lifecycle input hash invalid')
    counts = {name: admitted_suite('\n'.join(bodies[name]), expected) for name, expected in SUITES.items()}
    return {'admitted': True, 'scope': 'ordinary-components-only',
            'parent_count': len(LIBRARY) + len(CONTROL) + len(FILE_INPUTS),
            'subtest_count': len(LIBRARY_CHILDREN) + len(CONTROL_CHILDREN) + len(FILE_CHILDREN),
            'retained_lifecycle': {'parent_count': len(LIBRARY) + len(CONTROL),
                                   'subtest_count': len(LIBRARY_CHILDREN) + len(CONTROL_CHILDREN)},
            'file_inputs': {'parent_count': len(FILE_INPUTS), 'subtest_count': len(FILE_CHILDREN)},
            'suite_pass_counts': counts, 'pass_count': sum(counts.values()), 'receipts': receipts,
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
    return execute_guest(guest, work, hashes)


def execute_guest(guest, work, hashes):
    library_hash, control_hash = hashes['library'], hashes['control']
    script = (ROOT / 'tools/native/lifecycle-components.sh').read_bytes()
    for token, value in {'LIBRARY_SHA256': library_hash, 'CONTROL_SHA256': control_hash,
                         'LIBRARY_SELECTION': selection(LIBRARY), 'CONTROL_SELECTION': selection(CONTROL),
                         'FILE_SELECTION': selection(FILE_INPUTS)}.items():
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


def build_progress(text):
    if len(text) > 1024 * 1024:
        return {'valid': False, 'observed_steps': 0, 'last_step': None, 'complete': False}
    steps = [line.removeprefix('LCSTEP ') for line in text.splitlines()
             if line.startswith('LCSTEP')]
    valid = len(steps) <= len(BUILD_STEPS) and tuple(steps) == BUILD_STEPS[:len(steps)]
    return {'valid': valid, 'observed_steps': len(steps),
            'last_step': steps[-1] if valid and steps else None,
            'complete': valid and tuple(steps) == BUILD_STEPS}


def parse_build(text, inputs):
    if len(text) > 1024 * 1024:
        raise ValueError('lifecycle build evidence oversized')
    receipts = {}
    for line in text.splitlines():
        if line.startswith('LCBUILD\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('lifecycle build receipt invalid')
            receipts[parts[1]] = parts[2]
    expected = {'os': 'OpenBSD 7.9 amd64', 'version': 'go1.27.2', 'uid': '32767',
                'compiler': inputs['compiler_executable_sha256'], 'source': inputs['source_sha256']}
    if (not build_progress(text)['complete']
            or text.splitlines()[-1:] != ['LCSTEP outputs-verified']
            or set(receipts) != set(expected) | {'library', 'control'}
            or any(receipts.get(key) != value for key, value in expected.items())
            or any(not re.fullmatch('[0-9a-f]{64}', receipts.get(key, ''))
                   for key in ('compiler', 'source', 'library', 'control'))):
        raise ValueError('lifecycle build identity incomplete')
    return receipts


def build_guest(guest, work, inputs):
    # Verify both host assets again before transferring either. No cross-build
    # executable is accepted by this path, including after a partial build.
    for name in ('compiler', 'source'):
        with inputs[name].open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != inputs[name + '_sha256']:
                raise ValueError('lifecycle native build input changed')
    guest.require('set -eu; mkdir /var/aegvium-lifecycle-build; chmod 755 /var/aegvium-lifecycle-build')
    for name, filename in (('compiler', 'go.tar.gz'), ('source', 'source.tar.gz')):
        with inputs[name].open('rb') as stream:
            response = guest.call('set -eu; cat > /var/aegvium-lifecycle-build/' + filename,
                                  stream=stream, seconds=180)
        if response.returncode:
            raise RuntimeError('lifecycle native build transfer failed')
    script = (ROOT / 'tools/native/lifecycle-build.sh').read_bytes()
    for token, key in (('COMPILER_SHA256', 'compiler_sha256'), ('SOURCE_SHA256', 'source_sha256'),
                       ('EXECUTABLE_SHA256', 'compiler_executable_sha256')):
        if not re.fullmatch('[0-9a-f]{64}', inputs[key]):
            raise ValueError('lifecycle native build hash invalid')
        script = script.replace(token.encode(), inputs[key].encode())
    log = work / 'lifecycle-build.log'
    code, error_class = None, 'none'
    required = BUILD_SECONDS + POST_BUILD_SECONDS
    # Source transfer precedes this check. Never silently shorten compilation
    # because setup consumed the shared guest deadline.
    log.write_bytes(b'')
    try:
        reserved = guest.remaining(required) >= required
    except TimeoutError:
        reserved = False
    if not reserved:
        return {'admitted': False, 'execution_returncode': None,
                'execution_error_class': 'budget', 'budget_reserved_before_launch': False,
                'required_remaining_seconds': required,
                'build_log_sha256': hashlib.sha256(b'').hexdigest(),
                'progress': build_progress('')}
    with log.open('wb') as output:
        try:
            code = guest.call('sh -s', data=script, seconds=BUILD_SECONDS, output=output).returncode
        except (TimeoutError, subprocess.TimeoutExpired):
            error_class = 'timeout'
        except OSError:
            error_class = 'io'
    text = log.read_text(errors='replace')
    result = {'admitted': False, 'execution_returncode': code, 'execution_error_class': error_class,
              'budget_reserved_before_launch': True, 'required_remaining_seconds': required,
              'build_log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
              'progress': build_progress(text)}
    try:
        receipts = parse_build(text, inputs)
    except ValueError:
        result['admission_error'] = 'incomplete-or-invalid-lifecycle-build'
        return result
    result['receipts'] = receipts
    if code != 0 or error_class != 'none':
        return result
    hashes = {name: receipts[name] for name in ('library', 'control')}
    guest.require('set -eu; mkdir /var/aegvium-lifecycle; chmod 755 /var/aegvium-lifecycle')
    for name, wanted in hashes.items():
        guest.require('set -eu; cp /var/aegvium-lifecycle-build/output/' + name + '.test /var/aegvium-lifecycle/' + name + '.test; '
                      'chown root:wheel /var/aegvium-lifecycle/' + name + '.test; chmod 555 /var/aegvium-lifecycle/' + name + '.test; '
                      'test "$(sha256 -q /var/aegvium-lifecycle/' + name + '.test)" = "' + wanted + '"')
    return {**result, 'admitted': True, 'hashes': hashes, 'installed_verified': True}
