# SPDX-License-Identifier: BSD-3-Clause
"""Admit the owned configured Caddy server separately from connector API tests."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASES = {'initial', 'invalid-rejected', 'replaced', 'rollback', 'strict-enabled'}


def expectations():
    return json.loads((ROOT / 'research/connector/server-expectations.json').read_text())


def admit(text, binary_hash):
    wanted = expectations()
    expected = {r['case']: r for r in wanted['rows']}
    rows, configs, receipts, cleanup, order = {}, {}, {}, {}, []
    for line in text.splitlines():
        if line.startswith('CONFIGURED\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('duplicate/malformed configured receipt')
            receipts[parts[1]] = parts[2]
        if line.startswith('SERVER '):
            row = json.loads(line[7:])
            kind = row.get('kind')
            order.append([kind, row.get('case', row.get('phase', ''))])
            if kind == 'case':
                name = row.get('case')
                if (name not in expected or name in rows or row != expected[name] or
                        any(type(row[k]) is not int for k in ('status', 'backend')) or
                        any(type(row[k]) is not bool for k in ('headers_clean', 'client_error', 'response_leaked'))):
                    raise ValueError('configured input/authority/effect/outcome mismatch')
                rows[name] = row
            elif kind == 'config':
                phase = row.get('phase')
                if (set(row) != {'kind', 'phase', 'sha256', 'strict'} or phase not in PHASES or phase in configs or
                        row['strict'] is not (phase == 'strict-enabled') or
                        not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
                    raise ValueError('configuration transition malformed')
                configs[phase] = row
            elif kind in ('server-cleanup', 'process-cleanup'):
                fields = {'caddy_stopped', 'backends_joined', 'listeners_absent', 'autosave_absent'} if kind == 'server-cleanup' else {'child_exited', 'assets_removed', 'raw_log_sha256'}
                if set(row) != fields | {'kind'} or kind in cleanup:
                    raise ValueError('duplicate/malformed configured cleanup')
                for key in fields:
                    if key == 'raw_log_sha256':
                        if not isinstance(row[key], str) or not re.fullmatch('[0-9a-f]{64}', row[key]):
                            raise ValueError('child log identity missing')
                    elif row[key] is not True:
                        raise ValueError('configured cleanup incomplete')
                cleanup[kind] = row
            else:
                raise ValueError('unknown configured event')
        if '--- FAIL:' in line or '--- SKIP:' in line:
            raise ValueError('failed/skipped configured fixture')
    if (receipts != {'os': 'OpenBSD 7.9 amd64', 'binary': binary_hash, 'uid': '32767', 'cleanup': 'verified'} or
            set(rows) != set(expected) or set(configs) != PHASES or
            set(cleanup) != {'server-cleanup', 'process-cleanup'} or order != wanted['event_order'] or
            re.findall(r'^--- PASS: (\S+) \([0-9.]+s\)$', text, re.M) != ['TestConfiguredCaddyTLS'] or
            text.splitlines().count('PASS') != 1):
        raise ValueError('incomplete configured-server run')
    if (configs['rollback']['sha256'] != configs['initial']['sha256'] or
            len({r['sha256'] for r in configs.values()}) != 4):
        raise ValueError('replacement/rollback identity mismatch')
    return {'admitted': True, 'case_count': len(rows), 'configuration_count': len(configs),
            'cases': [rows[k] for k in sorted(rows)], 'configurations': configs,
            'cleanup': cleanup, 'receipts': receipts}


def guest_run(guest, work, binary_hash, native_binary):
    if not re.fullmatch('[0-9a-f]{64}', binary_hash):
        raise ValueError('invalid configured binary hash')
    guest.require('test "$(sha256 -q /var/aegvium-connector/compare.test)" = "' + binary_hash + '"')
    script = (ROOT / 'tools/native/configured-caddy.sh').read_bytes().replace(b'BINARY_SHA256', binary_hash.encode())
    log = work / 'configured-caddy.log'
    with log.open('wb') as output:
        reply = guest.call('sh -s', data=script, seconds=180, output=output)
    if reply.returncode:
        raise RuntimeError('configured Caddy failed; partial owned logs retained')
    return {**admit(log.read_text(), binary_hash), 'native_binary': native_binary,
            'build': 'offline native source build' if native_binary else 'host cross-build; native execution only',
            'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
