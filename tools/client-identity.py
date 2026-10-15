# SPDX-License-Identifier: BSD-3-Clause
"""Admit explicit PROXY identity component evidence, separate from CLI/PF."""
import hashlib
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXPECTED=json.loads((ROOT/'research/coraza/client-identity-expectations.json').read_text())
COMPONENT_TESTS={
    'TestLabClientIdentityWire':[r['case'] for r in EXPECTED],
    'TestLabClientIdentityContext':['missing','wrong-type','wrong-destination','zero-port','ipv6','valid'],
    'TestLabBodyTransport':['writer-after-transaction-close','read','close','oversize','length'],
    'TestLabBufferedResponse':['healthy','cancelled-eof','expired-unnotified','missing-request','read-error','oversize'],
}


def admit(text,binary,program):
    rows=[]
    for line in text.splitlines():
        if 'CLIENT-IDENTITY ' in line:
            row=json.loads(line.split('CLIENT-IDENTITY ',1)[1])
            if not isinstance(row,dict) or set(row)!=set(EXPECTED[0]) or any(type(row[k]) is not int for k in ('status','backend')) or any(type(row[k]) is not bool for k in ('enabled','headers_clean','verified_tls')):
                raise ValueError('client identity row schema/type drift')
            rows.append(row)
    if rows!=EXPECTED:
        raise ValueError('client identity Coraza input/status/effects differ')
    receipts=re.findall(r'^CLIENT-RECEIPT\t(\w+)\t([^\n]+)$',text,re.M)
    if receipts!=[('binary',binary),('program',program),('uid','32767')]:
        raise ValueError('client identity native output/UID mismatch')
    if re.findall(r'CLIENT-STARTUP tls=(true|false) no_bind=true',text)!=['false','true']:
        raise ValueError('client identity native startup checks incomplete')
    if text.count('CLIENT-FINAL companion_stopped=true backend_alive_at_stop=true assets_removed=true')!=1:
        raise ValueError('client identity cleanup incomplete')
    for name,cases in COMPONENT_TESTS.items():
        if re.findall(r'^\s*--- PASS: '+name+r'/([^ ]+) ',text,re.M)!=cases or len(re.findall(r'^--- PASS: '+name+r' \(',text,re.M))!=1:
            raise ValueError('client identity component execution incomplete')
    if set(re.findall(r'^--- PASS: ([^ /]+) \(',text,re.M))!=set(COMPONENT_TESTS) or text.splitlines().count('PASS')!=1 or '--- FAIL:' in text or '--- SKIP:' in text:
        raise ValueError('client identity component execution incomplete')
    return {'admitted':True,'case_count':len(rows),'cases':rows,'native_built':True,'receipts':dict(receipts),'startup_checks':2,'context_cases':6,'body_lifetime_cases':5,'response_boundary_cases':6,'scope':'Direct uncontained TLS component server with test-only REMOTE_ADDR/REMOTE_PORT rules and internal route replacement. Separate from the normal-CRS actual CLI/PF matrix.'}


def guest_run(guest,work,binary,program):
    if any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in (binary,program)):
        raise ValueError('client identity native hash invalid')
    controller='''set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'BINARY_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-proxy)" = 'PROGRAM_SHA256' ]
printf 'CLIENT-RECEIPT\tbinary\tBINARY_SHA256\nCLIENT-RECEIPT\tprogram\tPROGRAM_SHA256\n'
su -m nobody -c 'set -eu; [ "$(id -u)" -eq 32767 ]; printf "CLIENT-RECEIPT\tuid\t32767\n"; cd /var/aegvium-lab; export AEGVIUM_CLIENT_IDENTITY=owned-guest; exec ./engine.test -test.v -test.timeout=90s -test.run="^(TestLabClientIdentityWire|TestLabClientIdentityContext|TestLabBodyTransport|TestLabBufferedResponse)$"'
'''.replace('BINARY_SHA256',binary).replace('PROGRAM_SHA256',program).encode()
    log=work/'client-identity-component.log'
    with log.open('wb') as output:
        reply=guest.call('sh -s',data=controller,seconds=120,output=output)
    result={'admitted':False,'supervisor_exit':reply.returncode,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
    try:
        result.update(admit(log.read_text(),binary,program))
    except (ValueError,KeyError,TypeError) as error:
        result['admission_error']=str(error)
    if reply.returncode:result['admitted']=False
    return result
