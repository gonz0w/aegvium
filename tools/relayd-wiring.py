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


def guest_run(guest, work, binary_hash, checker_hash, faults=False, replacements=False, generations=False):
    profile = (ROOT / 'research/relayd/readiness-wiring.conf').read_bytes()
    hashes = {'profile': hashlib.sha256(profile).hexdigest(), 'engine': binary_hash, 'checker': checker_hash}
    if sum((faults, replacements, generations)) > 1:
        raise ValueError('select one connected wiring study')
    if replacements:
        replacement = (ROOT / 'research/relayd/checker-exit2.sh').read_bytes()
        hashes['replacement'] = hashlib.sha256(replacement).hexdigest()
    guest.require('set -eu; umask 022; mkdir /var/aegvium-wiring; chmod 755 /var/aegvium-wiring; cat > /var/aegvium-wiring/profile.conf', data=profile)
    if replacements:
        guest.require('set -eu; cat > /var/aegvium-wiring/exit2.sh; chmod 555 /var/aegvium-wiring/exit2.sh', data=replacement)
    script = (ROOT / ('tools/native/relayd-generations.sh' if generations else 'tools/native/relayd-checker-replacement.sh' if replacements else 'tools/native/relayd-health-faults.sh' if faults else 'tools/native/relayd-wiring.sh')).read_bytes()
    tokens = [(b'PROFILE_SHA256', 'profile'), (b'ENGINE_SHA256', 'engine'), (b'CHECKER_SHA256', 'checker')]
    if replacements:
        tokens.append((b'REPLACEMENT_SHA256', 'replacement'))
    for token, key in tokens:
        script = script.replace(token, hashes[key].encode())
    log = work / 'relayd-wiring.log'
    with log.open('wb') as output:
        reply = guest.call('sh -s', data=script, seconds=420 if faults or replacements or generations else 300, output=output)
    result = {'hashes': hashes, 'supervisor_exit': reply.returncode, 'admitted': False,
              'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(), 'partial_receipts': {}}
    try:
        result['partial_receipts'] = receipts(log.read_text())
        result.update((admit_generations if generations else admit_replacements if replacements else admit_faults if faults else admit)(log.read_text(), hashes))
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


REPLACEMENT_OPERATIONS = ('startup', 'ready', 'ready', 'ready', 'health-silent',
                          'health-silent', 'health-silent', 'ready', 'stop')
REPLACEMENT_MODES = {i: ('missing' if i == 2 else 'exit2' if i == 5 else 'original') for i in range(1, 8)}


def admit_replacements(text, hashes):
    values = receipts(text)
    fixed = {'syntax': 'accepted', 'cleanup': 'verified', 'fixture-exit': '0',
             'checker-restored': hashes['checker'], 'checker-restored-owner-mode': '0:555', **hashes}
    keys = set(fixed) | {'uid', 'relayd', 'fixture-log', 'daemon-log', 'final-ack',
                        'expected-script-uid', 'replacement-script-uid'}
    keys |= {f'ack-{i}' for i in range(9)}
    keys |= {f'{kind}-{i}' for kind in ('state', 'polls', 'direct', 'checker-exit', 'original-exit',
                                      'checker-mode', 'checker-path', 'checker-output', 'checker-log') for i in range(1, 8)}
    keys |= {f'request-{i}-benign' for i in range(1, 8)}
    keys |= {f'request-{i}-witness' for i in (2, 4, 6)}
    if set(values) != keys or any(values.get(k) != v for k, v in fixed.items()):
        raise ValueError('missing/unknown/mismatched replacement gates')
    if (any(not re.fullmatch('[1-9][0-9]*', values[k]) for k in ('uid', 'expected-script-uid'))
            or values['replacement-script-uid'] != values['expected-script-uid']
            or any(not re.fullmatch('[0-9a-f]{64}', values[k]) for k in ('relayd', 'fixture-log', 'daemon-log'))):
        raise ValueError('replacement identity/hash mismatch')
    acks = [json.loads(values[f'ack-{i}']) for i in range(9)]
    generation = acks[0].get('generation', '')
    if not re.fullmatch('[0-9a-f]{32}', generation):
        raise ValueError('invalid replacement generation')
    events = []
    empty_hash = hashlib.sha256(b'').hexdigest()
    for i, ack in enumerate(acks):
        if set(ack) != {'schema', 'generation', 'uid', 'phase', 'operation', 'ready', 'terminal', 'cleaned', 'events'}:
            raise ValueError('replacement acknowledgement schema mismatch')
        if (type(ack['schema']) is not int or ack['schema'] != 1 or ack['generation'] != generation
                or type(ack['uid']) is not int or ack['uid'] != int(values['uid'])
                or type(ack['phase']) is not int or ack['phase'] != i or ack['operation'] != REPLACEMENT_OPERATIONS[i]
                or ack['ready'] is not (1 <= i <= 7) or ack['terminal'] is not (i == 8)
                or ack['cleaned'] is not (i == 8)):
            raise ValueError('incorrect replacement phase acknowledgement')
        if 1 <= i <= 7:
            up = i in (1, 3, 5, 7)
            healthy = i in (1, 2, 3, 7)
            mode = REPLACEMENT_MODES[i]
            path = 'absent' if mode == 'missing' else hashes['replacement' if mode == 'exit2' else 'checker']
            if values[f'checker-mode-{i}'] != mode or values[f'checker-path-{i}'] != path:
                raise ValueError('checker replacement provenance mismatch')
            if values[f'state-{i}'] != ('up' if up else 'down') or not re.fullmatch('[0-9]|[12][0-9]', values[f'polls-{i}']):
                raise ValueError('replacement table/poll mismatch')
            expected_exit = '127' if mode == 'missing' else '2' if mode == 'exit2' else '1' if healthy else '0'
            if values[f'checker-exit-{i}'] != expected_exit or values[f'original-exit-{i}'] != ('1' if healthy else '0'):
                raise ValueError('checker launch/original exit mismatch')
            log_hash = values[f'checker-log-{i}']
            if (not re.fullmatch('[0-9a-f]{64}', log_hash)
                    or values[f'checker-output-{i}'] != ('launch-error' if mode == 'missing' else 'silent')
                    or (log_hash != empty_hash) is not (mode == 'missing')):
                raise ValueError('checker output mismatch')
            status, headers, body = response(values[f'direct-{i}'])
            if status != (200 if healthy else 503) or body or (healthy and headers.get(b'cache-control') != b'no-store'):
                raise ValueError('independent health response mismatch')
            status, _, body = response(values[f'request-{i}-benign'])
            if up:
                if status != 200 or body != b'synthetic sink\n':
                    raise ValueError('replacement forwarding witness mismatch')
                name = 'benign'
            else:
                if status is not None or body:
                    raise ValueError('post-DOWN replacement ingress produced bytes')
                status, _, body = response(values[f'request-{i}-witness'])
                if status != 200 or body != b'synthetic sink\n':
                    raise ValueError('replacement data-ready control mismatch')
                name = 'witness'
            events += [{'Phase': i, 'Request': name, 'Role': role, 'Status': 200} for role in ('sink', 'inspection')]
        if (ack['events'] or []) != events:
            raise ValueError('replacement inspection/sink delta mismatch')
    if json.loads(values['final-ack']) != acks[8]:
        raise ValueError('replacement final cleanup mismatch')
    return {'receipts': values, 'generation': generation, 'phases': acks, 'phase_count': 7,
            'unsafe_exit2_forwarding_observed': True, 'missing_checker_down_observed': True}


def admit_generations(text, hashes):
    """Admit three fresh generations, including an intentionally interrupted child."""
    values = receipts(text)
    expected = {'syntax': 'accepted', 'cleanup': 'verified', 'daemon-continuity': 'verified',
                'fixture-exit-1': '0', 'fixture-exit-3': '0',
                'crash-owned-2': 'verified', 'crash-injection-2': 'SIGKILL', **hashes}
    expected.update({'fixture-absence-' + str(g): 'verified' for g in (1, 2, 3)})
    operations = {1: ('startup', 'ready', 'health-refused', 'stop'),
                  2: ('startup', 'ready'), 3: ('startup', 'ready', 'stop')}
    labels = {f'{g}-{p}': ('up' if p == 1 else 'down')
              for g in operations for p in range(len(operations[g])) if operations[g][p] != 'stop'}
    labels.update({'gap-1': 'down', 'gap-2': 'down'})
    keys = set(expected) | {'uid', 'relayd', 'daemon-log', 'final-ack', 'crash-wait-2',
                           'crash-victim-uid-2', 'before-crash-2', 'after-crash-2', 'gap-ack-1', 'gap-ack-2'}
    keys |= {f'fixture-log-{g}' for g in operations}
    keys |= {f'ack-{g}-{p}' for g, ops in operations.items() for p in range(len(ops))}
    keys |= {f'{kind}-{label}' for label in labels for kind in ('state', 'polls', 'checker-exit', 'direct')}
    keys |= {f'request-{label}-{name}' for label in labels
             for name in (('benign', 'denied') if label.endswith('-1') and not label.startswith('gap') or label == '1-2' else ('benign',))}
    if set(values) != keys or any(values.get(k) != v for k, v in expected.items()):
        raise ValueError('missing/unknown/mismatched generation gates')
    if (not re.fullmatch('[1-9][0-9]*', values['uid']) or values['crash-victim-uid-2'] != values['uid']
            or any(not re.fullmatch('[0-9a-f]{64}', values[k]) for k in ('relayd', 'daemon-log', 'fixture-log-1', 'fixture-log-2', 'fixture-log-3'))):
        raise ValueError('invalid generation identity/hash')
    wait = values['crash-wait-2']
    if not re.fullmatch('[1-9][0-9]{0,2}', wait) or int(wait) > 255 or int(wait) == 127:
        raise ValueError('injected crash did not produce an admitted shell wait result')
    phases = {}
    generations = []
    wanted_events = [{'Phase': 1, 'Request': 'benign', 'Role': 'sink', 'Status': 200},
                     {'Phase': 1, 'Request': 'benign', 'Role': 'inspection', 'Status': 200},
                     {'Phase': 1, 'Request': 'denied', 'Role': 'inspection', 'Status': 403}]
    for g, ops in operations.items():
        acks = [json.loads(values[f'ack-{g}-{p}']) for p in range(len(ops))]
        generation = acks[0].get('generation', '')
        if not re.fullmatch('[0-9a-f]{32}', generation) or generation in generations:
            raise ValueError('invalid/reused fixture generation')
        generations.append(generation)
        for p, (ack, operation) in enumerate(zip(acks, ops)):
            if set(ack) != {'schema', 'generation', 'uid', 'phase', 'operation', 'ready', 'terminal', 'cleaned', 'events'}:
                raise ValueError('generation acknowledgement schema mismatch')
            if (type(ack['schema']) is not int or ack['schema'] != 1 or ack['generation'] != generation
                    or type(ack['uid']) is not int or ack['uid'] != int(values['uid'])
                    or type(ack['phase']) is not int or ack['phase'] != p or ack['operation'] != operation
                    or ack['ready'] is not (operation in ('ready', 'health-refused'))
                    or ack['terminal'] is not (operation == 'stop') or ack['cleaned'] is not (operation == 'stop')):
                raise ValueError('incorrect generation acknowledgement')
            if (ack['events'] is not None and not isinstance(ack['events'], list)) or (ack['events'] or []) != ([] if p == 0 else wanted_events):
                raise ValueError('generation counters were stale or forwarding delta mismatched')
        phases[str(g)] = acks
    for key, wanted in (('gap-ack-1', phases['1'][3]), ('before-crash-2', phases['2'][1]),
                        ('after-crash-2', phases['2'][1]), ('gap-ack-2', phases['2'][1]), ('final-ack', phases['3'][2])):
        if json.loads(values[key]) != wanted:
            raise ValueError('stale crash/stop receipt unexpectedly changed')
    for label, state in labels.items():
        up = state == 'up'
        if values['state-' + label] != state or not re.fullmatch('[0-9]|[12][0-9]', values['polls-' + label]) or values['checker-exit-' + label] != ('1' if up else '0'):
            raise ValueError('generation state/checker mismatch')
        status, headers, body = response(values['direct-' + label])
        absent = label.startswith('gap') or label == '1-2'
        if absent:
            if values['direct-' + label]:
                raise ValueError('closed health listener returned bytes')
        elif status != (200 if up else 503) or body or headers.get(b'cache-control') != b'no-store':
            raise ValueError('generation direct health mismatch')
        for name in ('benign', 'denied') if up or label == '1-2' else ('benign',):
            witness = values[f'request-{label}-{name}']
            status, _, body = response(witness)
            if up and (status != (200 if name == 'benign' else 403) or name == 'benign' and body != b'synthetic sink\n'):
                raise ValueError('fresh generation forwarding/denial mismatch')
            if not up and witness:
                raise ValueError('startup/gap/down returned ingress bytes')
    return {'receipts': values, 'generations': generations, 'phases': phases,
            'generation_count': 3, 'graceful_generation_count': 2, 'injected_crash_count': 1,
            'crash_shell_wait': int(wait)}
