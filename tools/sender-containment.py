# SPDX-License-Identifier: BSD-3-Clause
"""Admit owned OpenBSD PF socket-UID containment, with separate rollback proof."""
import copy
import hashlib
import json
import re
import uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PHASES = ('baseline', 'protected', 'rollback', 'reprotected')
VIEWS = ('rules', 'interfaces', 'timeouts', 'memory', 'anchors', 'tables', 'config', 'enabled')
BASELINE = json.loads((ROOT/'research/coraza/sender-path-expectations.json').read_text())
SHA = re.compile(r'[0-9a-f]{64}')


def inputs(relay_uid, marker):
    if type(relay_uid) is not int or not 0 < relay_uid < 65535 or relay_uid == 32767:
        raise ValueError('unsafe relay UID')
    opened = (ROOT/'research/relayd/sender-open.pf').read_bytes()
    protected = (ROOT/'research/relayd/sender-protected.pf').read_bytes().replace(b'RELAY_UID', str(relay_uid).encode())
    profile = (ROOT/'research/relayd/lab-sender.conf').read_bytes()
    assets = {'open.pf': opened, 'protected.pf': protected, 'profile.conf': profile, '.owned': marker}
    return assets, {k: hashlib.sha256(v).hexdigest() for k, v in {'open':opened, 'protected':protected, 'profile':profile, 'marker':marker}.items()}


def script(hashes, relay_uid):
    content = (ROOT/'tools/native/sender-containment.sh').read_bytes()
    for name in ('marker', 'open', 'protected', 'profile', 'engine', 'program', 'checker'):
        content = content.replace((name.upper()+'_SHA256').encode(), hashes.get(name, '0'*64).encode())
    return content.replace(b'RELAY_UID', str(relay_uid).encode())


def admit_preflight(text, hashes, relay_uid):
    receipts, views = {}, {}
    for line in text.splitlines():
        if line.startswith('SENDER-PREFLIGHT\t') or line.startswith('SENDER-BEFORE\t'):
            kind, key, value = line.split('\t')
            target = receipts if kind == 'SENDER-PREFLIGHT' else views
            if key in target:
                raise ValueError('duplicate sender preflight receipt')
            target[key] = value
    wanted = {'uid':str(relay_uid), 'syntax':'accepted', 'unchanged':'verified', **{k:hashes[k] for k in ('open','protected','profile')}}
    if set(receipts) != set(wanted)|{'restore','open-loaded','protected-loaded'} or any(receipts.get(k)!=v for k,v in wanted.items()) or set(views)!=set(VIEWS):
        raise ValueError('sender preflight identity/snapshot incomplete')
    if any(not SHA.fullmatch(v) for v in (*views.values(), *(receipts[k] for k in ('restore','open-loaded','protected-loaded')))):
        raise ValueError('sender snapshot hash malformed')
    if views['enabled'] not in [hashlib.sha256((v+'\n').encode()).hexdigest() for v in ('Enabled','Disabled')]:
        raise ValueError('initial PF state invalid')
    return {'admitted':True, 'receipts':receipts, 'before_views':views}


def prepare_guest(guest, work):
    uid_text = guest.require('id -u _relayd').decode().strip()
    if not re.fullmatch(r'[1-9][0-9]{0,4}', uid_text):
        raise ValueError('relay account lookup failed')
    uid = int(uid_text)
    assets, hashes = inputs(uid, uuid.uuid4().hex.encode())
    guest.require('set -eu; mkdir /var/aegvium-lab-sender; chmod 700 /var/aegvium-lab-sender')
    for name, data in assets.items():
        guest.require('set -eu; cat > /var/aegvium-lab-sender/'+name+'; chmod 400 /var/aegvium-lab-sender/'+name, data=data)
    log = work/'sender-preflight.log'
    with log.open('wb') as output:
        reply = guest.call('AEGVIUM_SENDER_STAGE=preflight sh -s', data=script(hashes, uid), seconds=60, output=output)
    if reply.returncode:
        raise RuntimeError('sender PF syntax/snapshot preflight failed; see sender-preflight.log')
    return {'hashes':hashes, 'relay_uid':uid, 'preflight':admit_preflight(log.read_text(), hashes, uid), 'preflight_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}


def expected_rows():
    result = []
    for phase in PHASES:
        for original in BASELINE:
            row = copy.deepcopy(original)
            row['phase'] = phase
            if phase in ('protected','reprotected') and row['case'].startswith('direct-'):
                row.update(status=0, backend=0, authority='', body_sha256='', connected=False, verified_tls=False, error='denied')
            result.append(row)
    return result


def admit(text, hashes, prepared, client_identity=False, backend_isolation=False):
    if type(client_identity) is not bool or type(backend_isolation) is not bool or (backend_isolation and not client_identity):
        raise ValueError('invalid sender identity mode')
    test_name='TestLabBackendIsolation' if backend_isolation else 'TestLabSenderClientIdentity' if client_identity else 'TestLabSenderContainment'
    modes=re.findall(r'SENDER-CLIENT-IDENTITY phase=(\w+) enabled=true',text)
    if modes != (list(PHASES) if client_identity else []):
        raise ValueError('sender client identity mode incomplete or substituted')
    rows, receipts, phases, counters, stops, daemons, assets, finals, restored = [], {}, [], {}, {}, {}, {}, {}, {}
    events, invalid = [], None
    for line in text.splitlines():
        if 'SENDER-PATH ' in line:
            row = json.loads(line.split('SENDER-PATH ',1)[1])
            if not isinstance(row,dict) or set(row)!=set(BASELINE[0]) or any(type(row[k]) is not int for k in ('status','backend')) or any(type(row[k]) is not bool for k in ('headers_clean','connected','verified_tls')):
                raise ValueError('sender row schema/type drift')
            rows.append(row)
            events.append(('row',row['phase'],row['case']))
        elif 'SENDER-CLIENT-IDENTITY ' in line:
            m=re.fullmatch(r'phase=(\w+) enabled=true',line.split('SENDER-CLIENT-IDENTITY ',1)[1])
            if not client_identity or m is None:
                raise ValueError('sender identity mode malformed or unexpected')
            events.append(('mode',m[1]))
        elif 'SENDER-ASSETS ' in line:
            m = re.fullmatch(r'phase=(\w+) cert_sha256=([0-9a-f]{64}) config_sha256=([0-9a-f]{64})',line.split('SENDER-ASSETS ',1)[1])
            if m is None or m[1] in assets:
                raise ValueError('sender public assets incomplete/duplicate')
            events.append(('assets',m[1]))
            assets[m[1]] = {'cert_sha256':m[2], 'config_sha256':m[3]}
        elif 'SENDER-FINAL ' in line:
            m = re.fullmatch(r'phase=(\w+) companion_stopped=true backends_alive_at_stop=true listeners_absent=true assets_removed=true',line.split('SENDER-FINAL ',1)[1])
            if m is None or m[1] in finals:
                raise ValueError('sender fixture cleanup incomplete')
            finals[m[1]] = True
            events.append(('final',m[1]))
        elif line.startswith('SENDER-PHASE\t'):
            fields = line.split('\t')
            if len(fields)!=5:
                raise ValueError('sender PF phase schema drift')
            _, phase, policy, policy_hash, loaded_hash = fields
            phases.append(phase)
            events.append(('phase',phase))
            wanted = 'protected' if phase in ('protected','reprotected') else 'open'
            if phase not in PHASES or policy!=wanted or policy_hash!=hashes[wanted] or loaded_hash!=prepared['preflight']['receipts'][wanted+'-loaded']:
                raise ValueError('sender PF policy mismatch')
        elif line.startswith('SENDER-INVALID\t'):
            fields = line.split('\t')
            if len(fields)!=4 or fields[1]!='protected' or invalid is not None or fields[2]!=prepared['preflight']['receipts']['protected-loaded'] or not SHA.fullmatch(fields[3]):
                raise ValueError('sender invalid policy did not preserve known good')
            invalid = {'phase':fields[1],'active_sha256':fields[2],'log_sha256':fields[3]}
            events.append(('invalid',fields[1]))
        elif line.startswith('SENDER-COUNTER\t'):
            fields = line.split('\t')
            if len(fields)!=11 or not all(re.fullmatch('[0-9]+',v) for v in fields[3:]):
                raise ValueError('sender PF counters malformed')
            _, phase, label, *values = fields
            key = (phase,label)
            events.append(('counter',phase,label))
            if key in counters:
                raise ValueError('duplicate sender PF counter')
            counters[key] = dict(zip(('evaluations','packets','bytes','packets_in','bytes_in','packets_out','bytes_out','states'),map(int,values)))
        elif line.startswith(('SENDER\t','SENDER-STOP\t','SENDER-DAEMON\t','SENDER-RESTORE\t')):
            kind,key,value = line.split('\t')
            target = {'SENDER':receipts,'SENDER-STOP':stops,'SENDER-DAEMON':daemons,'SENDER-RESTORE':restored}[kind]
            if key in target:
                raise ValueError('duplicate sender identity/cleanup receipt')
            target[key] = value
            if kind in ('SENDER-STOP','SENDER-DAEMON'):
                events.append(('stop' if kind=='SENDER-STOP' else 'daemon',key))
    expected_events = []
    for phase in PHASES:
        expected_events.append(('phase',phase))
        if phase=='protected': expected_events.append(('invalid',phase))
        if client_identity: expected_events.append(('mode',phase))
        expected_events.append(('assets',phase))
        expected_events += [('row',phase,r['case']) for r in BASELINE]
        expected_events.append(('final',phase))
        expected_events += [('counter',phase,'aegvium-sender-'+suffix) for suffix in (('allow','deny') if phase in ('protected','reprotected') else ('open',))]
        expected_events += [('daemon',phase),('stop',phase)]
    if events!=expected_events or invalid is None:
        raise ValueError('sender policy/application event order drift')
    if rows!=expected_rows() or phases!=list(PHASES):
        raise ValueError('sender policy/forwarding/phase outcomes mismatch')
    wanted = {**{k:hashes[k] for k in ('engine','program','checker','profile','open','protected')}, 'relay-uid':str(prepared['relay_uid']), 'uid':'32767', 'cleanup':'verified', 'pf-restored':'verified'}
    if set(receipts)!=set(wanted)|{'relayd'} or any(receipts.get(k)!=v for k,v in wanted.items()) or not SHA.fullmatch(receipts['relayd']):
        raise ValueError('sender native identities/rollback incomplete')
    if set(stops)!=set(PHASES) or any(v!='verified' for v in stops.values()) or set(daemons)!=set(PHASES) or any(not SHA.fullmatch(v) for v in daemons.values()) or set(assets)!=set(PHASES) or set(finals)!=set(PHASES) or restored!=prepared['preflight']['before_views']:
        raise ValueError('sender assets/daemon/PF restoration incomplete')
    expected_counters = {(p,'aegvium-sender-'+suffix) for p in PHASES for suffix in (('allow','deny') if p in ('protected','reprotected') else ('open',))}
    if set(counters)!=expected_counters:
        raise ValueError('sender PF counter set drift')
    for (phase,label),counter in counters.items():
        if counter['evaluations']<1 or counter['packets']<1 or counter['bytes']<1 or counter['packets']!=counter['packets_in']+counter['packets_out'] or counter['bytes']!=counter['bytes_in']+counter['bytes_out']:
            raise ValueError('sender PF filter bypassed or counters inconsistent')
        if label.endswith('deny'):
            if counter['packets']<4 or counter['states']!=0:
                raise ValueError('sender PF denial not witnessed')
        elif counter['states']<(7 if label.endswith('allow') else 11):
            raise ValueError('sender allowed socket UID/control not witnessed')
    passed = re.findall(r'^\s*--- PASS: '+test_name+r'/([^ ]+) ',text,re.M)
    parents = re.findall(r'^--- PASS: '+test_name+r' \(',text,re.M)
    if passed!=[row['case'] for row in expected_rows()] or len(parents)!=4 or len(re.findall('^PASS$',text,re.M))!=4 or '--- FAIL:' in text or '--- SKIP:' in text:
        raise ValueError('sender Go phase execution incomplete')
    return {'admitted':True,'client_identity':client_identity,'mode_phases':modes,'go_test':test_name,'case_count':len(rows),'cases':rows,'phase_order':phases,'native_program':True,'receipts':receipts,'public_assets':assets,'daemon_log_sha256':daemons,'restored_views':restored,'invalid_policy':invalid,'counters':[{'phase':p,'label':l,**v} for (p,l),v in counters.items()]}


def guest_run(guest,work,binary,checker,program,prepared,client_identity=False):
    if type(client_identity) is not bool:
        raise ValueError('invalid sender identity mode')
    hashes = {**prepared['hashes'],'engine':binary,'checker':checker,'program':program}
    if any(not isinstance(v,str) or not SHA.fullmatch(v) for v in hashes.values()) or not prepared['preflight']['admitted']:
        raise ValueError('native sender identity/preflight invalid')
    guest.require('test "$(sha256 -q /var/aegvium-lab-proxy)" = "'+program+'"')
    log = work/('client-identity-pf.log' if client_identity else 'sender-containment.log')
    controller=script(hashes,prepared['relay_uid'])
    if client_identity:
        controller=controller.replace(b'TestLabSenderContainment',b'TestLabSenderClientIdentity')
    with log.open('wb') as output:
        reply = guest.call('AEGVIUM_SENDER_STAGE=run sh -s',data=controller,seconds=360,output=output)
    result = {'admitted':False,'hashes':hashes,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_exit':reply.returncode}
    try:
        result.update(admit(log.read_text(),hashes,prepared,client_identity))
    except (ValueError,KeyError,TypeError) as error:
        result['admission_error'] = str(error)
    if reply.returncode:
        result['admitted'] = False
    return result
