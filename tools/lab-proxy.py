# SPDX-License-Identifier: BSD-3-Clause
"""Admit actual lab executable/TLS/inspection/backend composition separately."""
import hashlib
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXPECTED={'get':(200,1),'json':(200,1),'sql':(403,0),'script':(403,0),'unknown':(421,0),'oversize':(413,0),'media':(415,0),'upgrade':(501,0),'spoof':(200,1),'untrusted-cert':(0,0),'wrong-name':(0,0),'bare-data':(0,0),'backend-down':(502,0),'backend-recovery':(200,1),'companion-stop':(None,0)}

def admit(text,hashes):
    rows,receipts={},{}
    for line in text.splitlines():
        if 'LAB-PATH {' in line:
            row=json.loads(line.split('LAB-PATH ',1)[1]);name=row['case']
            if name in rows:raise ValueError('duplicate path case')
            rows[name]=row
        if line.startswith('LAB\t'):
            _,name,value=line.split('\t')
            if name in receipts:raise ValueError('duplicate lab receipt')
            receipts[name]=value
    if set(rows)!=set(EXPECTED):raise ValueError('incomplete lab path')
    wanted={**hashes,'uid':'32767','syntax':'accepted','cleanup':'verified','tls-cleanup':'verified'}
    if set(receipts)!=set(wanted)|{'relayd','daemon-log'} or any(receipts.get(k)!=v for k,v in wanted.items()):raise ValueError('identity/cleanup mismatch')
    if any(not re.fullmatch('[0-9a-f]{64}',receipts[k]) for k in (*hashes,'relayd','daemon-log')):raise ValueError('hash malformed')
    passed=re.findall(r'^\s*--- PASS: TestLabCompanionPath/([^ ]+) ',text,re.M)
    if len(passed)!=15 or set(passed)!=set(EXPECTED) or '\nPASS\n' not in text or '--- FAIL:' in text or 'LAB-FINAL companion-stopped backend-stopped listeners-absent' not in text:raise ValueError('Go/process gates incomplete')
    for name,row in rows.items():
        if set(row)!={'case','status','backend','body_sha256','headers_clean','client_error'}:raise ValueError('path schema drift')
        if type(row['status'])is not int or type(row['backend'])is not int or type(row['client_error'])is not bool or row['headers_clean'] is not True:raise ValueError('path type/header violation')
        status,count=EXPECTED[name]
        if row['backend']!=count or (status is not None and row['status']!=status):raise ValueError('false forwarding/response')
        if name=='companion-stop' and row['status']!=0 and not 400<=row['status']<=599:raise ValueError('companion stop succeeded')
        if row['client_error']!=(row['status']==0):raise ValueError('response error hidden')
        expected_hash=hashlib.sha256(b'{"payload":"ordinary"}' if name=='json' else b'').hexdigest() if count else ''
        if row['body_sha256']!=expected_hash:raise ValueError('backend bytes mismatch')
    return {'admitted':True,'case_count':15,'cases':[rows[n] for n in sorted(rows)],'receipts':receipts}

def guest_run(guest,work,binary,checker):
    program=ROOT/'.tools/research/labproxy-openbsd-amd64';profile=(ROOT/'research/relayd/lab-proxy.conf').read_bytes()
    hashes={'program':hashlib.sha256(program.read_bytes()).hexdigest(),'profile':hashlib.sha256(profile).hexdigest(),'engine':binary,'checker':checker}
    with program.open('rb') as stream:reply=guest.call('set -eu; cat > /var/aegvium-lab-proxy; chmod 555 /var/aegvium-lab-proxy',stream=stream,seconds=120)
    if reply.returncode:raise RuntimeError('lab program transfer failed')
    guest.require('set -eu; mkdir /var/aegvium-lab-path; chmod 755 /var/aegvium-lab-path; cat > /var/aegvium-lab-path/profile.conf',data=profile)
    script=(ROOT/'tools/native/lab-proxy.sh').read_bytes()
    for token,key in [('PROGRAM','program'),('PROFILE','profile'),('ENGINE','engine'),('CHECKER','checker')]:script=script.replace((token+'_SHA256').encode(),hashes[key].encode())
    log=work/'lab-proxy.log'
    with log.open('wb') as output:reply=guest.call('sh -s',data=script,seconds=180,output=output)
    result={'hashes':hashes,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_exit':reply.returncode,'admitted':False}
    try:result.update(admit(log.read_text(),hashes))
    except (ValueError,KeyError,TypeError) as error:result['admission_error']=str(error)
    if reply.returncode:result['admitted']=False
    return result
