# SPDX-License-Identifier: BSD-3-Clause
"""Owned direct/relayd body comparison, separately admitted from ordinary leaves."""
import hashlib
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
ARMS = ('direct', 'http', 'tcp')
CASES = ('fixed-json', 'json-script', 'form-sql', 'fixed-over', 'chunked-json', 'chunked-over', 'short-fixed', 'bad-chunk', 'invalid-json', 'text-media', 'conflicting-cl', 'identical-cl', 'cl-te', 'unsupported-te', 'stalled-chunked', 'fixed-json-halfclose', 'chunked-json-halfclose', 'json-script-halfclose', 'fixed-over-halfclose', 'chunked-over-halfclose', 'conflicting-cl-halfclose', 'short-open')


def admit(text, binary, profile):
    rows, errors, receipts, lifecycle = {}, {}, {}, {}
    for line in text.splitlines():
        if 'RELAYD-BODY {' in line:
            row = json.loads(line.split('RELAYD-BODY ', 1)[1]); name = row['case']
            if name in rows: raise ValueError('duplicate body row')
            rows[name] = row
        if 'RELAYD-BODY-LIFECYCLE {' in line:
            value=json.loads(line.split('RELAYD-BODY-LIFECYCLE ',1)[1]); name=value['case']
            if name in lifecycle: raise ValueError('duplicate lifecycle row')
            lifecycle[name]=value
        if 'RELAYD-BODY-ERROR ' in line:
            name, error = line.split('RELAYD-BODY-ERROR ', 1)[1].split()
            if name in errors: raise ValueError('duplicate response error')
            errors[name] = error
        if line.startswith('BODY\t'):
            _, name, value = line.split('\t')
            if name in receipts: raise ValueError('duplicate daemon receipt')
            receipts[name] = value
    names = {arm+'/'+case for arm in ARMS for case in CASES}
    if set(rows)!=names or set(errors)!=names or set(lifecycle)!=names: raise ValueError('incomplete body matrix')
    if receipts.keys()!= {'binary','profile','relayd','uid','cleanup','daemon-log'} or receipts['binary']!=binary or receipts['profile']!=profile or receipts['uid']!='32767' or receipts['cleanup']!='verified': raise ValueError('daemon identity/cleanup missing')
    if any(not re.fullmatch('[0-9a-f]{64}',receipts[k]) for k in ('binary','profile','relayd','daemon-log')): raise ValueError('receipt hash malformed')
    passed = re.findall(r'^\s*--- PASS: TestRelaydBodyComparison/([^ ]+) ',text,re.M)
    if set(passed)!=names or len(passed)!=66 or '\nPASS\n' not in text or '--- FAIL:' in text: raise ValueError('Go leaves incomplete/failed')
    keys={'case','status','handler','backend','content_length','transfer_encoding','header_lengths','source_read','source_closed','source_close_error','wire_read','request_bytes','request_sha256','body_sha256','rules','phases','connection_closed','server_joined','listener_absent'}
    body_hash=hashlib.sha256(b'{"payload":"ordinary"}').hexdigest()
    for name,row in rows.items():
        arm,case=name.split('/')
        baseline={'fixed-json':(200,1,1,22),'json-script':(403,1,0,39),'form-sql':(403,1,0,22),'fixed-over':(413,1,0,0),'chunked-json':(200,1,1,22),'chunked-over':(413,1,0,129),'short-fixed':(500,1,0,22),'bad-chunk':(500,1,0,0),'invalid-json':(400,1,0,11),'text-media':(415,1,0,0),'conflicting-cl':(400,0,0,0),'identical-cl':(200,1,1,22),'cl-te':(200,1,1,22),'unsupported-te':(501,0,0,0),'stalled-chunked':(413,1,0,129)}
        base_case=case.removesuffix('-halfclose') if case.endswith('-halfclose') else 'short-fixed' if case=='short-open' else case
        life=lifecycle[name]
        if set(life)!={'case','write_shutdown','bytes_sent'} or type(life['write_shutdown'])is not bool or life['write_shutdown']!=(case=='short-fixed' or case.endswith('-halfclose')) or type(life['bytes_sent'])is not int or life['bytes_sent']!=row['request_bytes']: raise ValueError('lifecycle witness drift')
        if arm=='direct' and tuple(row[k] for k in ('status','handler','backend','source_read'))!=baseline[base_case]: raise ValueError('direct baseline drift')
        if set(row)!=keys: raise ValueError('body schema drift')
        for k in ('status','handler','backend','source_read','source_closed','wire_read','request_bytes'):
            if type(row[k]) is not int or row[k]<0: raise ValueError('body integer type')
        if row['handler'] not in (0,1) or row['backend'] not in (0,1) or row['source_closed']!=row['handler'] or row['source_read']>129 or row['wire_read']>4096 or not 0<row['request_bytes']<=4096: raise ValueError('body ownership/bounds')
        if not re.fullmatch('[0-9a-f]{64}',row['request_sha256']): raise ValueError('body request hash')
        if errors[name] not in ('none','eof','timeout','other') or (row['status']==0)!=(errors[name]!='none'): raise ValueError('response error concealed')
        if row['status'] and not 200<=row['status']<=599: raise ValueError('invalid response status')
        if any(row[k] is not True for k in ('connection_closed','server_joined','listener_absent')): raise ValueError('body cleanup missing')
        if row['source_close_error'] not in ('none','timeout','other'): raise ValueError('source Close class')
        if row['handler'] and not row['wire_read']: raise ValueError('handler without accepted connection')
        if not row['handler'] and row['source_close_error']!='none': raise ValueError('invented Close error')
        if row['handler']==0:
            if row['content_length'] is not None or row['transfer_encoding'] is not None or row['header_lengths'] is not None or row['source_read'] or row['backend']: raise ValueError('rejected parser invented handler')
        elif type(row['content_length']) is not int or row['content_length'] < -1 or not isinstance(row['transfer_encoding'],list) or not isinstance(row['header_lengths'],list) or any(type(v)is not str for v in row['transfer_encoding']+row['header_lengths']): raise ValueError('normalized request type')
        for key in ('rules','phases'):
            values=row[key]
            if not isinstance(values,list) or any(type(v)is not int for v in values) or values!=(sorted(set(values)) if key=='rules' else sorted(values)): raise ValueError('rule/phase type')
        if len(row['rules'])!=len(row['phases']): raise ValueError('rule/phase count')
        if any(not 100000<=v<=999999 for v in row['rules']) or any(not 1<=v<=5 for v in row['phases']): raise ValueError('rule/phase range')
        if case in ('fixed-json','chunked-json') and (row['status'],row['backend'])!=(200,1): raise ValueError('benign forwarding missing')
        if row['backend']:
            if case not in ('fixed-json','chunked-json','identical-cl','cl-te','fixed-json-halfclose','chunked-json-halfclose') or row['status']!=200 or row['body_sha256']!=body_hash: raise ValueError('uninspected/bad body forwarded')
        elif row['body_sha256'] or 200<=row['status']<300: raise ValueError('false rejection receipt')
        if case in ('json-script','json-script-halfclose','form-sql') and row['handler']:
            family=941 if case.startswith('json-script') else 942
            if not any(v//1000==family for v in row['rules']) or row['status']!=403: raise ValueError('attack denial missing')
    for case in CASES:
        if len({rows[a+'/'+case]['request_sha256'] for a in ARMS})!=1: raise ValueError('arms sent different inputs')
    for arm in ARMS:
        for case in CASES:
            if case.endswith('-halfclose') or case=='short-open':
                base=case.removesuffix('-halfclose') if case.endswith('-halfclose') else 'short-fixed'
                if any(rows[arm+'/'+case][k]!=rows[arm+'/'+base][k] for k in ('request_sha256','request_bytes')): raise ValueError('lifecycle pair input drift')
    return {'cases':[rows[n] for n in sorted(rows)],'response_errors':errors,'receipts':receipts,'case_count':66,'lifecycle':lifecycle,'admitted':True}


def guest_run(guest, work, binary):
    profile=(ROOT/'research/relayd/body-comparison.conf').read_bytes(); ph=hashlib.sha256(profile).hexdigest()
    guest.require('set -eu; mkdir /var/aegvium-body; chmod 755 /var/aegvium-body')
    guest.require('cat > /var/aegvium-body/profile.conf',data=profile)
    script=(ROOT/'tools/native/relayd-body.sh').read_bytes().replace(b'PROFILE_SHA256',ph.encode()).replace(b'BINARY_SHA256',binary.encode())
    log=work/'relayd-body.log'
    with log.open('wb') as output: result=guest.call('sh -s',data=script,seconds=180,output=output)
    receipt={'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'exit_code':result.returncode,'admitted':False}
    try: receipt.update(admit(log.read_text(),binary,ph))
    except (ValueError,KeyError,TypeError,json.JSONDecodeError) as error: receipt['admission_error']=str(error)
    if result.returncode: receipt['admitted']=False
    return receipt
