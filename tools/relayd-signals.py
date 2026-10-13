# SPDX-License-Identifier: BSD-3-Clause
"""Source-bound controls and exact admission for the disposable signal study."""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARMS = ('zero', 'one', 'two', 'term', 'kill')


def inputs():
    result = {'profile.conf': (ROOT / 'research/relayd/signal-comparison.conf').read_bytes()}
    actions = {'zero': 'exit 0', 'one': 'exit 1', 'two': 'exit 2', 'term': 'kill -TERM $$', 'kill': 'kill -KILL $$'}
    for arm in ARMS:
        for kind in ('plain', 'child'):
            name = 'plain-' + arm if kind == 'plain' else arm
            result[name + '.sh'] = ('#!/bin/sh\n# SPDX-License-Identifier: BSD-3-Clause\n'
                'id -u > /var/aegvium-signal/evidence/' + kind + '-' + arm + '.uid\n' + actions[arm] + '\n').encode()
        result['observed-' + arm + '.sh'] = ('#!/bin/sh\n# SPDX-License-Identifier: BSD-3-Clause\n'
            'exec /var/aegvium-sigobs ' + arm + ' "$@"\n').encode()
    return result


def receipts(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('SIGNAL\t'):
            fields = line.split('\t')
            if len(fields) != 3 or fields[1] in result:
                raise ValueError('malformed/duplicate signal receipt')
            result[fields[1]] = fields[2]
    return result


def admit(text, profile_hash, observer_hash):
    values = receipts(text)
    expected = {'syntax': 'accepted', 'cleanup': 'verified', 'profile': profile_hash, 'observer': observer_hash}
    uid = values.get('expected-uid', '')
    keys = set(expected) | {'expected-uid', 'relayd', 'daemon-log'}
    keys |= {kind + '-' + arm for kind in ('uid-plain', 'uid-child', 'observe', 'state-plain', 'state-observed') for arm in ARMS}
    if (set(values) != keys or not re.fullmatch('[1-9][0-9]*', uid)
            or any(values.get(k) != v for k, v in expected.items())
            or any(not re.fullmatch('[0-9a-f]{64}', values[k]) for k in ('relayd', 'daemon-log'))):
        raise ValueError('incomplete signal gates')
    for arm in ARMS:
        if any(values['uid-' + kind + '-' + arm] != uid for kind in ('plain', 'child')):
            raise ValueError('script account mismatch')
        observation = values['observe-' + arm].split('|')
        if len(observation) != 3 or observation[0] != uid:
            raise ValueError('observer account/status mismatch')
        kind, code = observation[1:]
        if arm in ('zero', 'one', 'two'):
            if (kind, code) != ('exited', str(('zero', 'one', 'two').index(arm))):
                raise ValueError('exit control mismatch')
        elif arm == 'kill':
            if (kind, code) != ('signalled', '9'):
                raise ValueError('KILL control mismatch')
        elif not ((kind == 'signalled' and code == '15') or (kind == 'exited' and re.fullmatch('[0-9]{1,3}', code) and int(code) <= 255)):
            raise ValueError('TERM classification mismatch')
        state = 'up' if kind == 'exited' and int(code) > 0 else 'down'
        if any(values['state-' + role + '-' + arm] != state for role in ('plain', 'observed')):
            raise ValueError('plain/instrumented state divergence')
    return values


def guest_run(guest, work, observer, observer_hash):
    data = inputs()
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in data.items()}
    guest.require('set -eu; umask 022; mkdir /var/aegvium-signal; chmod 755 /var/aegvium-signal')
    for name, value in data.items():
        guest.require('set -eu; cat > /var/aegvium-signal/' + name, data=value)
        if name.endswith('.sh'):
            guest.require('chmod 555 /var/aegvium-signal/' + name)
    with observer.open('rb') as stream:
        response = guest.call('set -eu; cat > /var/aegvium-sigobs; chmod 555 /var/aegvium-sigobs', stream=stream, seconds=120)
    if response.returncode:
        raise RuntimeError('signal observer transfer failed')
    guest.require('test "$(sha256 -q /var/aegvium-sigobs)" = "' + observer_hash + '"')
    script = (ROOT / 'tools/native/relayd-signals.sh').read_bytes()
    script = script.replace(b'PROFILE_SHA256', hashes['profile.conf'].encode()).replace(b'OBSERVER_SHA256', observer_hash.encode())
    log = work / 'relayd-signals.log'
    with log.open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=180, output=output)
    result = {'input_sha256': hashes, 'observer_sha256': observer_hash, 'transfer_verified': True,
              'host_cross_built': True, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
              'partial_receipts': receipts(log.read_text()), 'supervisor_exit': response.returncode, 'admitted': False}
    try:
        result['receipts'] = admit(log.read_text(), hashes['profile.conf'], observer_hash)
        if response.returncode:
            raise ValueError('signal supervisor failed')
        result['admitted'] = True
    except ValueError as error:
        result['error'] = str(error)
    return result
