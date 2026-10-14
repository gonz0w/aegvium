# SPDX-License-Identifier: BSD-3-Clause
"""Strict admission for the isolated connector API comparison, not Caddy server adoption."""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'research/connector'
PROFILES = ('engine', 'caddy')
PHASES = ('initial', 'same-configuration', 'changed-configuration', 'known-good', 'rollback')


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        item, end = decoder.raw_decode(text.lstrip())
        yield item
        text = text.lstrip()[end:]


def verify_graph():
    env = {**os.environ, 'GOOS': 'openbsd', 'GOARCH': 'amd64', 'CGO_ENABLED': '0', 'GOPROXY': 'off', 'GOSUMDB': 'off'}
    subprocess.run([str(ROOT / 'tools/run-research-go.sh'), 'mod', 'verify'], cwd=MODULE, env=env, check=True, timeout=120)
    output = subprocess.check_output([str(ROOT / 'tools/run-research-go.sh'), 'list', '-mod=readonly', '-test', '-deps', '-json', '.'], cwd=MODULE, env=env, text=True, timeout=120)
    loaded = {p['Module']['Path']: p['Module'] for p in objects(output) if p.get('Module') and not p['Module'].get('Main')}
    reviewed = json.loads((ROOT / 'research/coraza/connector-dependencies.json').read_text())
    expected = {r['path']: r for r in reviewed['modules']}
    if set(loaded) != set(expected):
        raise ValueError('connector loaded module set differs from reviewed graph')
    for name, module in loaded.items():
        row = expected[name]
        if module.get('Version') != row['version'] or module.get('Sum') != row['sum'] or module.get('GoModSum') != row['go_mod_sum'] or module.get('Replace'):
            raise ValueError('connector module identity differs from review: ' + name)
        for item in row['legal_files']:
            path = Path(module['Dir']) / item['path']
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('connector legal file differs from review: ' + name)
    print(f'Reviewed target graph and legal-file hashes verified: {len(loaded)} third-party modules')
    return loaded


def expected_wire():
    return json.loads((MODULE / 'wire-expectations.json').read_text())['rows']


def expected_passes():
    return ({'TestConnectorWire', 'TestConnectorRuleReload'} |
            {'TestConnectorWire/' + p for p in PROFILES} |
            {'TestConnectorRuleReload/' + p for p in PROFILES} |
            {'TestConnectorWire/' + r['profile'] + '/' + r['case'] for r in expected_wire()})


def admit(text, binary_hash, uid='32767'):
    receipts, rows, reloads, cleanups, passed = {}, {}, {}, set(), set()
    expected = {(r['profile'], r['case']): r for r in expected_wire()}
    for line in text.splitlines():
        if line.startswith('COMPARISON\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('duplicate/malformed connector receipt')
            receipts[parts[1]] = parts[2]
        if 'CONNECTOR ' in line:
            match = re.fullmatch(r'\s*comparison_test.go:[0-9]+: CONNECTOR (\{.*\})', line)
            if not match:
                raise ValueError('malformed connector observation')
            row = json.loads(match[1])
            if 'input_sha256' in row:
                key = (row.get('profile'), row.get('case'))
                if key not in expected or key in rows or row != expected[key] or any(type(row[k]) is not int for k in ('status', 'backend', 'source_closed')) or type(row['spoof_preserved']) is not bool:
                    raise ValueError('connector wire identity/outcome/backend/closure mismatch')
                rows[key] = row
            elif 'cleanup' in row:
                profile = row.get('profile')
                if set(row) != {'profile', 'cleanup'} or profile not in PROFILES or profile in cleanups or row['cleanup'] != 'verified':
                    raise ValueError('connector listener/task cleanup missing')
                cleanups.add(profile)
            elif row.get('phase') == 'invalid-rejected':
                key = (row.get('profile'), 'invalid-rejected', '')
                if set(row) != {'profile', 'phase'} or key[0] not in PROFILES or key in reloads:
                    raise ValueError('invalid rule rejection malformed')
                reloads[key] = row
            else:
                key = (row.get('profile'), row.get('phase'), row.get('case'))
                if set(row) != {'profile', 'phase', 'case', 'status'} or key[0] not in PROFILES or key[1] not in PHASES or key[2] not in ('old', 'new') or key in reloads or type(row['status']) is not int:
                    raise ValueError('connector reload observation malformed')
                old = key[1] in ('initial', 'rollback') or key[0] == 'caddy' and key[1] in ('same-configuration', 'known-good')
                wanted = 403 if (key[2] == 'old') == old else 200
                if row['status'] != wanted:
                    raise ValueError('connector rule reuse/activation mismatch')
                reloads[key] = row
        match = re.fullmatch(r'\s*--- PASS: (\S+) \([0-9.]+s\)', line)
        if match:
            name = match[1]
            if name in passed or name not in expected_passes():
                raise ValueError('unknown/duplicate connector PASS')
            passed.add(name)
        if '--- FAIL:' in line or '--- SKIP:' in line or re.search(r'\[ERROR\].*cleanup', line):
            raise ValueError('connector failed/skipped/unclean fixture')
    wanted_receipts = {'binary': binary_hash, 'uid': uid, 'os': 'OpenBSD 7.9 amd64', 'cleanup': 'verified'}
    if receipts != wanted_receipts or set(rows) != set(expected) or len(reloads) != 22 or cleanups != set(PROFILES) or passed != expected_passes() or text.splitlines().count('PASS') != 1:
        raise ValueError('incomplete connector execution/admission')
    return {'admitted': True, 'build': 'host cross-build; native execution only', 'receipts': receipts,
            'wire_count': len(rows), 'reload_count': len(reloads), 'go_pass_count': len(passed),
            'wire': [rows[k] for k in sorted(rows)], 'reload': [reloads[k] for k in sorted(reloads)]}


def guest_run(guest, work, native_binary=None, require_native=False):
    if require_native and native_binary is None:
        raise ValueError('native connector output required; host fallback prohibited')
    if native_binary is None:
        binary = ROOT / '.tools/research/connector-openbsd-amd64.test'
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        guest.require('set -eu; umask 022; mkdir /var/aegvium-connector; chmod 755 /var/aegvium-connector')
        with binary.open('rb') as stream:
            result = guest.call('set -eu; cat > /var/aegvium-connector/compare.test; chmod 555 /var/aegvium-connector/compare.test', stream=stream, seconds=120)
        if result.returncode:
            raise RuntimeError('connector binary transfer failed')
    else:
        if not re.fullmatch('[0-9a-f]{64}', native_binary):
            raise ValueError('invalid native connector output hash')
        binary_hash = native_binary
        guest.require('test "$(sha256 -q /var/aegvium-connector/compare.test)" = "' + binary_hash + '"')
    script = (ROOT / 'tools/native/connector-comparison.sh').read_bytes().replace(b'BINARY_SHA256', binary_hash.encode())
    log = work / 'connector-comparison.log'
    with log.open('wb') as output:
        result = guest.call('sh -s', data=script, seconds=180, output=output)
    if result.returncode:
        raise RuntimeError('connector comparison failed; partial native log retained')
    result = admit(log.read_text(), binary_hash)
    result['build'] = 'offline native source build' if native_binary is not None else result['build']
    return {**result, 'native_binary': native_binary is not None, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}


if __name__ == '__main__':
    verify_graph()
