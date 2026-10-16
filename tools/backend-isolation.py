# SPDX-License-Identifier: BSD-3-Clause
"""Separate owned PF backend boundary; never normalize foreign evidence into baseline."""
import hashlib
import importlib.util
import json
import re
import uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('backend_sender',ROOT/'tools/sender-containment.py')
S=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(S)
BODY='{"payload":"<script>alert(1)</script>"}'
BODY_SHA=hashlib.sha256(BODY.encode()).hexdigest()


def input_sha(name):
    host='api.test' if name=='api' else 'app.test'
    request=f'POST / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(BODY)}\r\n\r\n{BODY}'
    return hashlib.sha256((name+'\0'+request).encode()).hexdigest()


def inputs(relay_uid,marker):
    if type(relay_uid) is not int or relay_uid in (0,1,32767) or not 0<relay_uid<65535:
        raise ValueError('unsafe backend relay UID')
    opened=(ROOT/'research/relayd/backend-open.pf').read_bytes()
    protected=(ROOT/'research/relayd/backend-protected.pf').read_bytes().replace(b'RELAY_UID',str(relay_uid).encode())
    profile=(ROOT/'research/relayd/lab-backend.conf').read_bytes()
    assets={'open.pf':opened,'protected.pf':protected,'profile.conf':profile,'.owned':marker}
    hashes={k:hashlib.sha256(v).hexdigest() for k,v in {'open':opened,'protected':protected,'profile':profile,'marker':marker}.items()}
    return assets,hashes


def script(hashes,relay_uid):
    if type(relay_uid) is not int or relay_uid in (0,1,32767) or not 0<relay_uid<65535 or any(not isinstance(v,str) or not S.SHA.fullmatch(v) for v in hashes.values()):
        raise ValueError('backend controller identity invalid')
    content=(ROOT/'tools/native/backend-isolation.sh').read_bytes()
    for name in ('marker','open','protected','profile','engine','program','checker'):
        content=content.replace((name.upper()+'_SHA256').encode(),hashes.get(name,'0'*64).encode())
    return content.replace(b'RELAY_UID',str(relay_uid).encode())


def prepare_guest(guest,work):
    uid=guest.require('id -u _relayd').decode().strip()
    if not re.fullmatch(r'[1-9][0-9]{0,4}',uid) or guest.require('id -u daemon').decode().strip()!='1':
        raise ValueError('backend principals unavailable')
    uid=int(uid);assets,hashes=inputs(uid,uuid.uuid4().hex.encode())
    guest.require('set -eu; mkdir /var/aegvium-lab-backend; chmod 700 /var/aegvium-lab-backend')
    for name,data in assets.items():
        guest.require('set -eu; cat > /var/aegvium-lab-backend/'+name+'; chmod 400 /var/aegvium-lab-backend/'+name,data=data)
    log=work/'backend-preflight.log'
    with log.open('wb') as output:
        reply=guest.call('AEGVIUM_SENDER_STAGE=preflight sh -s',data=script(hashes,uid),seconds=60,output=output)
    text=log.read_text()
    if reply.returncode or re.findall(r'^BACKEND-PREFLIGHT\t(\S+)\t(\S+)$',text,re.M)!=[('probe-uid','1'),('fixture-uid','32767')]:
        raise RuntimeError('backend PF/principal preflight failed')
    return {'hashes':hashes,'relay_uid':uid,'probe_uid':1,'preflight':S.admit_preflight(text,hashes,uid),'preflight_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}


def admit(text,hashes,prepared):
    if type(prepared.get('probe_uid')) is not int or prepared['probe_uid']!=1:
        raise ValueError('backend foreign UID missing')
    result=S.admit(text,hashes,prepared,client_identity=True,backend_isolation=True)
    groups=[];pending=[];public=[];public_hashes=[];effects=[];rows=[];principals=[];counters=[];events=[]
    for line in text.splitlines():
        if line.startswith('BACKEND-FOREIGN '):
            pending.append(line[len('BACKEND-FOREIGN '):])
        elif line.startswith('BACKEND-PROBE-LOG\t'):
            _,phase,digest=line.split('\t')
            raw='\n'.join(pending)+'\n'
            if not pending or hashlib.sha256(raw.encode()).hexdigest()!=digest:
                raise ValueError('backend foreign log substituted')
            groups.append((phase,raw,digest));pending=[]
        elif line.startswith('BACKEND-PUBLIC '):public.append(line[len('BACKEND-PUBLIC '):])
        elif line.startswith('BACKEND-PUBLIC-LOG\t'):public_hashes.append(line.split('\t')[1])
        if 'BACKEND-EFFECT ' in line:
            row=json.loads(line.split('BACKEND-EFFECT ',1)[1]);effects.append(row);events.append(('effect',row.get('phase'),row.get('case')))
        elif line.startswith('BACKEND-SYNC\t'):
            _,phase,state=line.split('\t');events.append(('sync',phase,state))
        elif line.startswith('BACKEND-COUNTER\t'):
            parts=line.split('\t')
            if len(parts)!=11 or not all(re.fullmatch('[0-9]+',v) for v in parts[3:]):raise ValueError('backend counter malformed')
            row={'phase':parts[1],'label':parts[2],'values':list(map(int,parts[3:]))};counters.append(row)
    public_text='\n'.join(public)+'\n'
    if pending or public_hashes!=[hashlib.sha256(public_text.encode()).hexdigest()] or len(re.findall(r'^--- PASS: TestLabBackendPublicFiles \(',public_text,re.M))!=1 or public_text.splitlines().count('PASS')!=1 or set(re.findall(r'^--- PASS: ([^ /]+) \(',public_text,re.M))!={'TestLabBackendPublicFiles'} or '--- FAIL:' in text or '--- SKIP:' in text:
        raise ValueError('backend public file execution incomplete')
    if [g[0] for g in groups]!=list(S.PHASES):raise ValueError('backend probe phase incomplete')
    for phase,raw,_ in groups:
        principal=re.findall(r'BACKEND-PRINCIPAL phase=(\w+) uid=(\d+) euid=(\d+) binary=([0-9a-f]{64}) ca_sha256=([0-9a-f]{64})',raw)
        ca=result['public_assets'][phase]['cert_sha256']
        if principal!=[(phase,'1','1',hashes['engine'],ca)]:raise ValueError('backend foreign principal/CA mismatch')
        principals.append({'phase':phase,'uid':1,'euid':1,'binary':hashes['engine'],'ca_sha256':ca})
        if re.findall(r'^\s*--- PASS: TestLabBackendProbe/([^ ]+) ',raw,re.M)!=['plain','api'] or len(re.findall(r'^--- PASS: TestLabBackendProbe \(',raw,re.M))!=1 or raw.splitlines().count('PASS')!=1 or set(re.findall(r'^--- PASS: ([^ /]+) \(',raw,re.M))!={'TestLabBackendProbe'}:
            raise ValueError('backend foreign Go execution incomplete')
        observed=[json.loads(line.split('BACKEND-PROBE ',1)[1]) for line in raw.splitlines() if 'BACKEND-PROBE ' in line]
        expected=[];protected=phase in ('protected','reprotected')
        for name in ('plain','api'):
            expected.append({'phase':phase,'case':name,'input_sha256':input_sha(name),'ca_sha256':ca,'connected':not protected,'verified_tls':not protected and name=='api','status':0 if protected else 200,'error':'denied' if protected else ''})
        if observed!=expected or any(type(r.get('status')) is not int or any(type(r.get(k)) is not bool for k in ('connected','verified_tls')) for r in observed):
            raise ValueError('backend bypass outcome/input/TLS drift')
        rows+=observed
    expected_effects=[];expected_events=[];expected_counters=[]
    for phase in S.PHASES:
        protected=phase in ('protected','reprotected')
        for name in ('plain','api'):
            expected_effects.append({'phase':phase,'case':name,'backend':0 if protected else 1,'authority':'' if protected else 'api.test' if name=='api' else 'app.test','body_sha256':'' if protected else BODY_SHA})
            expected_events.append(('effect',phase,name))
        expected_events.append(('sync',phase,'removed'))
        for suffix in (('allow','deny') if protected else ('open',)):expected_counters.append((phase,'aegvium-backend-'+suffix))
    if effects!=expected_effects or any(type(r.get('backend')) is not int for r in effects) or events!=expected_events:
        raise ValueError('backend independent effects or synchronization incomplete')
    if [(r['phase'],r['label']) for r in counters]!=expected_counters:raise ValueError('backend counters missing/duplicated')
    for row in counters:
        evaluations,packets,bytes_,incoming,inbytes,outgoing,outbytes,states=row['values']
        if min(evaluations,packets,bytes_)<=0 or incoming+outgoing!=packets or inbytes+outbytes!=bytes_:raise ValueError('backend counter accounting invalid')
        if row['label'].endswith('deny'):
            if states!=0 or min(outgoing,outbytes)<=0:raise ValueError('backend rejection not witnessed')
        elif states<2:raise ValueError('backend positive state control absent')
    if re.findall(r'BACKEND-FIXTURE phase=(\w+) public_assets_removed=true',text)!=list(S.PHASES) or text.splitlines().count('BACKEND-CLEANUP\tpublic-sync\tremoved')!=1:
        raise ValueError('backend public asset cleanup incomplete')
    result.update({'backend_isolation':True,'foreign_probe_count':8,'independent_effect_count':8,'foreign_probes':rows,'backend_effects':effects,'foreign_principals':principals,'foreign_log_sha256':{phase:h for phase,_,h in groups},'backend_counters':counters,'public_file_tests':1,'public_file_log_sha256':public_hashes[0],'public_sync_removed':True})
    return result


def guest_run(guest,work,binary,checker,program,prepared):
    hashes={**prepared['hashes'],'engine':binary,'checker':checker,'program':program}
    if not prepared['preflight']['admitted'] or type(prepared.get('probe_uid')) is not int or prepared['probe_uid']!=1 or any(not isinstance(v,str) or not S.SHA.fullmatch(v) for v in hashes.values()):raise ValueError('backend preparation not admitted')
    guest.require('test "$(sha256 -q /var/aegvium-lab-proxy)" = "'+program+'"')
    log=work/'backend-isolation.log'
    with log.open('wb') as output:
        reply=guest.call('AEGVIUM_SENDER_STAGE=run sh -s',data=script(hashes,prepared['relay_uid']),seconds=360,output=output)
    result={'admitted':False,'hashes':hashes,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_exit':reply.returncode}
    try:result.update(admit(log.read_text(),hashes,prepared))
    except (ValueError,KeyError,TypeError) as error:result['admission_error']=str(error)
    if reply.returncode:result['admitted']=False
    return result
