# SPDX-License-Identifier: BSD-3-Clause
"""Strict native admission for the separate relayd TLS passthrough profile."""
import hashlib
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
EXPECTED = json.loads((ROOT/'research/coraza/tls-path-expectations.json').read_text())
FINAL = 'TLS-FINAL reload_accepted=2 reload_rejected=1 companion_stopped=true backends_alive_at_stop=true listeners_absent=true assets_removed=true'
STARTUP = 'TLS-STARTUP checked=1 rejected=4 listeners_absent=true'


def admit(text, hashes, request_wire=False):
    if type(request_wire) is not bool: raise ValueError("invalid TLS wire mode")
    test_name = "TestLabRequestWireNative" if request_wire else "TestLabTLSPassthrough"
    wire_names = ["wire-"+r["mode"]+"-"+r["case"] for r in json.loads((ROOT/"research/coraza/request-wire-expectations.json").read_text())] if request_wire else []
    rows, receipts, assets = [], {}, []
    for line in text.splitlines():
        if 'TLS-PATH ' in line:
            row = json.loads(line.split('TLS-PATH ', 1)[1])
            if not isinstance(row, dict) or set(row) != set(EXPECTED[0]):
                raise ValueError('TLS path schema drift')
            if any(type(row[k]) is not int for k in ('status', 'backend')) or any(type(row[k]) is not bool for k in ('headers_clean', 'client_error', 'verified_tls')):
                raise ValueError('TLS path type drift')
            rows.append(row)
        if line.startswith('TLSLAB\t'):
            _, name, value = line.split('\t')
            if name in receipts:
                raise ValueError('duplicate TLS receipt')
            receipts[name] = value
        if 'TLS-ASSETS ' in line:
            match = re.fullmatch(r'cert_sha256=([0-9a-f]{64}) config_sha256=([0-9a-f]{64})', line.split('TLS-ASSETS ', 1)[1])
            if match is None:
                raise ValueError('TLS public asset hashes malformed')
            assets.append({'cert_sha256': match[1], 'config_sha256': match[2]})
    if rows != EXPECTED:
        raise ValueError('TLS authority/forwarding/input outcome mismatch')
    wanted = {**hashes, 'uid': '32767', 'syntax': 'accepted', 'cleanup': 'verified'}
    if set(receipts) != set(wanted)|{'relayd', 'daemon-log'} or any(receipts.get(k) != v for k, v in wanted.items()) or any(not re.fullmatch('[0-9a-f]{64}', receipts[k]) for k in (*hashes, 'relayd', 'daemon-log')):
        raise ValueError('TLS identity/cleanup incomplete')
    passed = re.findall(r'^\s*--- PASS: '+test_name+r'/([^ ]+) ', text, re.M)
    parent = re.findall(r'^--- PASS: '+test_name+r' \(', text, re.M)
    if passed != [r['case'] for r in EXPECTED[:-1]]+wire_names+[EXPECTED[-1]['case']] or len(parent) != 1 or len(assets) != 1 or text.count(STARTUP) != 1 or text.count(FINAL) != 1 or not re.search(r'^PASS$', text, re.M) or '--- FAIL:' in text or '--- SKIP:' in text:
        raise ValueError('TLS process/startup/test gates incomplete')
    return {'admitted': True, 'case_count': len(rows), 'cases': rows, 'receipts': receipts, 'public_assets': assets[0], 'startup_rejects': 4, 'reload_accepted': 2, 'reload_rejected': 1}


def guest_run(guest, work, binary, checker, program):
    # Native output required: this mode has no program-transfer or host fallback.
    if any(not re.fullmatch('[0-9a-f]{64}', h) for h in (binary, checker, program)):
        raise ValueError('invalid native TLS program identities')
    guest.require('test "$(sha256 -q /var/aegvium-lab-proxy)" = "'+program+'"')
    profile = (ROOT/'research/relayd/lab-tls-passthrough.conf').read_bytes()
    hashes = {'engine': binary, 'checker': checker, 'program': program, 'profile': hashlib.sha256(profile).hexdigest()}
    guest.require('set -eu; mkdir /var/aegvium-lab-tls; chmod 755 /var/aegvium-lab-tls; cat > /var/aegvium-lab-tls/profile.conf', data=profile)
    script = (ROOT/'tools/native/lab-tls.sh').read_bytes()
    for token, key in [('ENGINE','engine'),('CHECKER','checker'),('PROGRAM','program'),('PROFILE','profile')]:
        script = script.replace((token+'_SHA256').encode(), hashes[key].encode())
    log = work/'lab-tls.log'
    with log.open('wb') as output:
        reply = guest.call('sh -s', data=script, seconds=180, output=output)
    result = {'admitted': False, 'hashes': hashes, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(), 'supervisor_exit': reply.returncode, 'native_program': True}
    try:
        result.update(admit(log.read_text(), hashes))
    except (ValueError, KeyError, TypeError) as error:
        result['admission_error'] = str(error)
    if reply.returncode:
        result['admitted'] = False
    return result
