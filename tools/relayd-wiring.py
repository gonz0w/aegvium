# SPDX-License-Identifier: BSD-3-Clause
"""Exact connected readiness/forwarding admission for the owned native fixture."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ('startup', 'down', 'ready', 'down', 'ready', 'close', 'stop')


def receipts(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('WIRING\t'):
            fields = line.split('\t')
            if len(fields) != 3 or fields[1] in result:
                raise ValueError('malformed/duplicate wiring receipt')
            result[fields[1]] = fields[2]
    return result


def response(hexadecimal):
    if len(hexadecimal) > 16384 or not re.fullmatch('(?:[0-9a-f]{2})*', hexadecimal):
        raise ValueError('invalid/oversized response witness')
    raw = bytes.fromhex(hexadecimal)
    if not raw:
        return None, {}, b''
    head, separator, body = raw.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    if not separator or not re.fullmatch(b'HTTP/1\\.[01] [0-9]{3}(?: [^\r\n]*)?', lines[0]):
        raise ValueError('malformed HTTP witness')
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b':')
        if not sep or key.lower() in headers:
            raise ValueError('malformed/duplicate response header')
        headers[key.lower()] = value.strip()
    return int(lines[0].split()[1]), headers, body


def admit(text, hashes):
    values = receipts(text)
    expected = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0', **hashes}
    keys = set(expected) | {'uid', 'relayd', 'fixture-log', 'daemon-log', 'final-ack', 'bare'}
    keys |= {'ack-' + str(i) for i in range(7)}
    keys |= {kind + '-' + str(i) for kind in ('state', 'polls', 'direct') for i in range(1, 6)}
    keys |= {'request-' + str(i) + '-' + name for i in range(1, 6) for name in ('benign', 'denied')}
    if set(values) != keys or any(values.get(k) != v for k, v in expected.items()):
        raise ValueError('missing/unknown/mismatched wiring gates')
    if not re.fullmatch('[1-9][0-9]*', values['uid']) or any(not re.fullmatch('[0-9a-f]{64}', values[k]) for k in ('relayd', 'fixture-log', 'daemon-log')):
        raise ValueError('invalid identity/hash')
    acks = [json.loads(values['ack-' + str(i)]) for i in range(7)]
    generation = acks[0].get('generation', '')
    if not re.fullmatch('[0-9a-f]{32}', generation):
        raise ValueError('invalid generation')
    events = []
    for i, ack in enumerate(acks):
        if set(ack) != {'schema', 'generation', 'uid', 'phase', 'operation', 'ready', 'terminal', 'cleaned', 'events'}:
            raise ValueError('ack schema mismatch')
        if (type(ack['schema']) is not int or ack['schema'] != 1 or ack['generation'] != generation
                or type(ack['uid']) is not int or ack['uid'] != int(values['uid'])
                or type(ack['phase']) is not int or ack['phase'] != i or ack['operation'] != OPERATIONS[i]
                or ack['ready'] is not (i in (2, 4)) or ack['terminal'] is not (i >= 5)
                or ack['cleaned'] is not (i == 6)):
            raise ValueError('stale/incorrect phase acknowledgement')
        if i in (2, 4):
            events += [{'Phase': i, 'Request': 'benign', 'Role': 'sink', 'Status': 200},
                       {'Phase': i, 'Request': 'benign', 'Role': 'inspection', 'Status': 200},
                       {'Phase': i, 'Request': 'denied', 'Role': 'inspection', 'Status': 403}]
        if (ack['events'] or []) != events:
            raise ValueError('inspection/sink phase delta mismatch')
        if i in range(1, 6):
            up = i in (2, 4)
            if values['state-' + str(i)] != ('up' if up else 'down') or not re.fullmatch('[0-9]|[12][0-9]', values['polls-' + str(i)]):
                raise ValueError('host state/poll mismatch')
            status, headers, body = response(values['direct-' + str(i)])
            if status != (200 if up else 503) or body or headers.get(b'cache-control') != b'no-store':
                raise ValueError('direct health mismatch')
            for name, wanted in (('benign', 200), ('denied', 403)):
                status, _, body = response(values['request-' + str(i) + '-' + name])
                if up and (status != wanted or (name == 'benign' and body != b'synthetic sink\n')):
                    raise ValueError('ready forwarding/denial witness mismatch')
                if not up and (status == 200 or b'synthetic sink' in body):
                    raise ValueError('successful forwarding while down')
    if values['bare'] or json.loads(values['final-ack']) != acks[6]:
        raise ValueError('bare data accepted or terminal acknowledgement changed')
    return {'receipts': values, 'generation': generation, 'phases': acks, 'phase_count': 5}


def guest_run(guest, work, binary_hash, checker_hash, faults=False):
    profile = (ROOT / 'research/relayd/readiness-wiring.conf').read_bytes()
    hashes = {'profile': hashlib.sha256(profile).hexdigest(), 'engine': binary_hash, 'checker': checker_hash}
    guest.require('set -eu; umask 022; mkdir /var/aegvium-wiring; chmod 755 /var/aegvium-wiring; cat > /var/aegvium-wiring/profile.conf', data=profile)
    script = (ROOT / ('tools/native/relayd-health-faults.sh' if faults else 'tools/native/relayd-wiring.sh')).read_bytes()
    for token, key in ((b'PROFILE_SHA256', 'profile'), (b'ENGINE_SHA256', 'engine'), (b'CHECKER_SHA256', 'checker')):
        script = script.replace(token, hashes[key].encode())
    log = work / 'relayd-wiring.log'
    with log.open('wb') as output:
        reply = guest.call('sh -s', data=script, seconds=420 if faults else 300, output=output)
    result = {'hashes': hashes, 'supervisor_exit': reply.returncode, 'admitted': False,
              'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(), 'partial_receipts': receipts(log.read_text())}
    try:
        result.update((admit_faults if faults else admit)(log.read_text(), hashes))
        if reply.returncode:
            raise ValueError('owned supervisor failed')
        result['admitted'] = True
    except (ValueError, TypeError, KeyError) as error:
        result['error'] = str(error)
    return result


FAULT_OPERATIONS = ('startup', 'ready', 'health-silent', 'ready', 'health-malformed',
                    'ready', 'health-redirect', 'ready', 'health-refused', 'stop')


def admit_faults(text, hashes):
    values = receipts(text)
    fixed = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0', **hashes}
    keys = set(fixed) | {'uid', 'relayd', 'fixture-log', 'daemon-log', 'final-ack'}
    keys |= {'ack-'+str(i) for i in range(10)}
    keys |= {f'{kind}-{i}' for kind in ('state', 'polls', 'direct', 'checker-exit') for i in range(1, 9)}
    keys |= {f'request-{i}-benign' for i in range(1, 9)}
    keys |= {f'{kind}-{i}' for kind in ('window-before', 'window-after') for i in (2, 4, 6, 8)}
    keys |= {f'request-{i}-{name}' for i in (2, 4, 6, 8) for name in ('window', 'witness')}
    if set(values) != keys or any(values.get(k) != v for k, v in fixed.items()):
        raise ValueError('missing/unknown/mismatched fault gates')
    if not re.fullmatch('[1-9][0-9]*', values['uid']) or any(not re.fullmatch('[0-9a-f]{64}', values[k]) for k in ('relayd', 'fixture-log', 'daemon-log')):
        raise ValueError('invalid fault identity/hash')
    acks = [json.loads(values[f'ack-{i}']) for i in range(10)]
    generation = acks[0].get('generation', '')
    if not re.fullmatch('[0-9a-f]{32}', generation):
        raise ValueError('invalid fault generation')
    events, windows = [], []
    for i, ack in enumerate(acks):
        if set(ack) != {'schema', 'generation', 'uid', 'phase', 'operation', 'ready', 'terminal', 'cleaned', 'events'}:
            raise ValueError('fault ack schema mismatch')
        if (type(ack['schema']) is not int or ack['schema'] != 1 or ack['generation'] != generation
                or type(ack['uid']) is not int or ack['uid'] != int(values['uid'])
                or type(ack['phase']) is not int or ack['phase'] != i or ack['operation'] != FAULT_OPERATIONS[i]
                or ack['ready'] is not (1 <= i <= 8) or ack['terminal'] is not (i == 9)
                or ack['cleaned'] is not (i == 9)):
            raise ValueError('incorrect fault phase acknowledgement')
        if 1 <= i <= 8:
            up = i % 2 == 1
            if values[f'state-{i}'] != ('up' if up else 'down') or not re.fullmatch('[0-9]|[12][0-9]', values[f'polls-{i}']):
                raise ValueError('fault table/poll mismatch')
            if values[f'checker-exit-{i}'] != ('1' if up else '0'):
                raise ValueError('unchanged checker fault result mismatch')
            hexadecimal = values[f'direct-{i}']
            if len(hexadecimal) > 16384 or not re.fullmatch('(?:[0-9a-f]{2})*', hexadecimal):
                raise ValueError('invalid fault health encoding')
            raw = bytes.fromhex(hexadecimal)
            if i == 4:
                if raw != b'malformed health\r\n\r\n':
                    raise ValueError('malformed peer witness mismatch')
            else:
                status, headers, body = response(values[f'direct-{i}'])
                wanted = {2: 503, 6: 302, 8: None}.get(i, 200)
                if status != wanted or body or (up and headers.get(b'cache-control') != b'no-store'):
                    raise ValueError('fault health witness mismatch')
                if i == 6 and headers.get(b'location') != b'http://127.0.0.1:18085/ready':
                    raise ValueError('redirect target mismatch')
            def pair(name):
                return [{'Phase': i, 'Request': name, 'Role': role, 'Status': 200} for role in ('sink', 'inspection')]
            if not up:
                before, after = values[f'window-before-{i}'], values[f'window-after-{i}']
                if before not in ('up', 'down') or after not in ('up', 'down'):
                    raise ValueError('missing polling-window states')
                status, _, body = response(values[f'request-{i}-window'])
                if status == 200:
                    if body != b'synthetic sink\n':
                        raise ValueError('window sentinel mismatch')
                    events += pair('window')
                elif status is not None or body:
                    raise ValueError('unexpected window response')
                windows.append({'phase': i, 'before': before, 'after': after, 'forwarded': status == 200})
            status, _, body = response(values[f'request-{i}-benign'])
            if up:
                if status != 200 or body != b'synthetic sink\n':
                    raise ValueError('recovery forwarding mismatch')
                events += pair('benign')
            elif status is not None or body:
                raise ValueError('post-DOWN ingress produced bytes')
            if not up:
                status, _, body = response(values[f'request-{i}-witness'])
                if status != 200 or body != b'synthetic sink\n':
                    raise ValueError('independent data-ready witness mismatch')
                events += pair('witness')
        if (ack['events'] or []) != events:
            raise ValueError('fault inspection/sink delta mismatch')
    if json.loads(values['final-ack']) != acks[9]:
        raise ValueError('fault cleanup acknowledgement mismatch')
    return {'receipts': values, 'generation': generation, 'phases': acks,
            'phase_count': 8, 'fault_count': 4, 'polling_windows': windows}
