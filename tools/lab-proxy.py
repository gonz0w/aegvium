# SPDX-License-Identifier: BSD-3-Clause
"""Admit actual lab executable/TLS/inspection/backend composition separately."""
import hashlib
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXPECTED={'get':(200,1),'json':(200,1),'sql':(403,0),'script':(403,0),'unknown':(421,0),'oversize':(413,0),'media':(415,0),'upgrade':(501,0),'spoof':(200,1),'untrusted-cert':(0,0),'wrong-name':(0,0),'bare-data':(0,0),'backend-down':(502,0),'backend-recovery':(200,1),'companion-stop':(None,0),'api-get':(200,1),'api-json':(200,1),'api-port':(200,1),'api-wrong-port':(421,0),'api-sql':(403,0),'api-wrong-cert':(502,0),'api-untrusted-cert':(502,0),'api-tls-recovery':(200,1),'api-large':(502,1),'api-stall':(502,1),'api-after-stall':(200,1),'api-cleartext':(502,0),'api-cleartext-recovery':(200,1),'api-reload-version':(200,1),'api-reload-duplicate':(200,1),'api-reload-ca':(200,1),'alt-reload-get':(200,1),'alt-reload-json':(200,1),'alt-reload-sql':(403,0),'reload-removed-api':(421,0),'reload-app-during':(200,1),'api-reload-restored':(200,1),'reload-alt-removed':(421,0),'alt-load-available':(200,1),'load-api-removed':(421,0),'api-load-restored':(200,1),'load-alt-removed':(421,0)}

LOAD_PHASES={'saturation','mixed','inflight-reload'}

def admit_load(row):
    if not isinstance(row,dict) or set(row)!={'phase','statuses','backend','peak','active_after','effects','health','reload_accepted','ack_before_release','limit'}:raise ValueError('load schema drift')
    phase=row['phase']
    statuses,count,peak,reload={'saturation':([200,200,200,200,503],4,4,0),'mixed':([200,200,403,403],2,2,0),'inflight-reload':([200],1,1,1)}[phase]
    if not isinstance(row['statuses'],list) or any(type(x)is not int for x in row['statuses']) or sorted(row['statuses'])!=statuses or any(type(row[k])is not int for k in ('backend','peak','active_after','health','reload_accepted','limit')) or (row['backend'],row['peak'],row['active_after'],row['health'],row['reload_accepted'],row['limit'])!=(count,peak,0,200,reload,4) or row['ack_before_release'] is not False:raise ValueError('load outcome mismatch')
    if not isinstance(row['effects'],list) or len(row['effects'])!=count:raise ValueError('load effects incomplete')
    digest=hashlib.sha256(b'{"payload":"ordinary"}' if phase=='mixed' else b'').hexdigest()
    targets=['app.test','app.test','api.test','api.test'] if phase=='saturation' else ['app.test','api.test'] if phase=='mixed' else ['api.test']
    observed=[]
    for effect in row['effects']:
        if not isinstance(effect,dict) or set(effect)!={'backend_host','authority','body_sha256','headers_clean'} or effect['headers_clean'] is not True or effect['body_sha256']!=digest or effect['authority']!=effect['backend_host']:raise ValueError('load bytes/authority/metadata changed')
        observed.append(effect['backend_host'])
    if sorted(observed)!=sorted(targets):raise ValueError('load backend mismatch')
    return row

TRACE_CLASSES={'none','body-limit','cancelled','deadline','refused','reset','broken-pipe','unreachable','unexpected-eof','eof','closed','tls-certificate','tls-protocol','dns','timeout','other'}
TRACE_KEYS={'id','case','start_ms','duration_ms','status','stage','class','health_samples','health_age_ms'}


def transport_diagnostics(text, complete=False):
    """Separate observations, never sufficient to admit composition success."""
    rows=[]
    for line in text.splitlines():
        if 'LAB-TRANSPORT {' not in line:continue
        row=json.loads(line.split('LAB-TRANSPORT ',1)[1])
        if not isinstance(row,dict) or set(row)!=TRACE_KEYS:raise ValueError('transport diagnostic schema drift')
        integers=('id','start_ms','duration_ms','status','health_samples','health_age_ms')
        if any(type(row[k])is not int for k in integers) or any(not isinstance(row[k],str) for k in ('case','stage','class')):raise ValueError('transport diagnostic type drift')
        if not 1<=row['id']<=200 or not 0<=row['start_ms']<=120000 or not 0<=row['duration_ms']<=120000 or row['start_ms']+row['duration_ms']>120000 or not 0<=row['health_samples']<=2000:raise ValueError('transport diagnostic bounds')
        if row['case'] not in (set(EXPECTED)-{'bare-data'})|{'readiness','load'} or row['stage'] not in ('roundtrip','body','complete') or row['class'] not in TRACE_CLASSES:raise ValueError('transport diagnostic label/stage/class')
        if row['stage']=='roundtrip':
            if row['status']!=0 or row['class']=='none':raise ValueError('transport failure disguised')
        elif not 100<=row['status']<=599 or (row['stage']=='complete')!=(row['class']=='none'):raise ValueError('transport completion inconsistent')
        if row['health_samples']==0:
            if row['health_age_ms']!=-1:raise ValueError('unsampled health given age')
        elif not 0<=row['health_age_ms']<=row['start_ms']+row['duration_ms']+1:raise ValueError('transport health age invalid')
        rows.append(row)
        if len(rows)>200:raise ValueError('too many transport diagnostics')
    ids=[r['id'] for r in rows]
    if len(set(ids))!=len(ids):raise ValueError('duplicate transport call')
    finals=re.findall(r'^.*LAB-TRANSPORT-FINAL calls=([0-9]+) raw_errors=false$',text,re.M)
    if len(finals)>1:raise ValueError('duplicate transport final')
    final=bool(finals)
    if final and (int(finals[0])!=len(rows) or sorted(ids)!=list(range(1,len(rows)+1))):raise ValueError('transport calls missing')
    if complete and (not final or not rows):raise ValueError('transport diagnostics incomplete')
    return {'valid':True,'complete':final,'call_count':len(rows),'rows':sorted(rows,key=lambda r:r['id'])}


def admit(text,hashes):
    rows,receipts={},{}
    loads={}
    config=None
    reload=None
    for line in text.splitlines():
        if 'LAB-LOAD {' in line:
            row=json.loads(line.split('LAB-LOAD ',1)[1]);phase=row['phase']
            if phase not in LOAD_PHASES or phase in loads:raise ValueError('unknown/duplicate load phase')
            loads[phase]=admit_load(row)
        if 'LAB-RELOAD {' in line:
            if reload is not None:raise ValueError('duplicate reload receipt')
            reload=json.loads(line.split('LAB-RELOAD ',1)[1])
        if 'LAB-CONFIG {' in line:
            if config is not None:raise ValueError('duplicate config receipt')
            config=json.loads(line.split('LAB-CONFIG ',1)[1])
        if 'LAB-PATH {' in line:
            row=json.loads(line.split('LAB-PATH ',1)[1]);name=row['case']
            if name in rows:raise ValueError('duplicate path case')
            rows[name]=row
        if line.startswith('LAB\t'):
            _,name,value=line.split('\t')
            if name in receipts:raise ValueError('duplicate lab receipt')
            receipts[name]=value
    if set(loads)!=LOAD_PHASES:raise ValueError('incomplete load phases')
    if set(rows)!=set(EXPECTED):raise ValueError('incomplete lab path')
    if not isinstance(config,dict) or set(config)!={'checked','invalid_rejected','listeners_absent','config_sha256','ca_sha256'} or config['checked'] is not True or config['listeners_absent'] is not True or type(config['invalid_rejected']) is not int or config['invalid_rejected']!=7 or any(not isinstance(config[k],str) or not re.fullmatch('[0-9a-f]{64}',config[k]) for k in ('config_sha256','ca_sha256')):raise ValueError('config startup gates incomplete')
    if not isinstance(reload,dict) or set(reload)!={'accepted','rejected','health_samples','health_connection_preserved','same_process','restored_config_sha256','replacement_config_sha256'} or type(reload['accepted']) is not int or reload['accepted']!=2 or type(reload['rejected']) is not int or reload['rejected']!=3 or type(reload['health_samples']) is not int or reload['health_samples']<5 or reload['health_connection_preserved'] is not True or reload['same_process'] is not True or reload['restored_config_sha256']!=config['config_sha256'] or not isinstance(reload['replacement_config_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',reload['replacement_config_sha256']) or reload['replacement_config_sha256']==config['config_sha256']:raise ValueError('reload lifecycle gates incomplete')
    wanted={**hashes,'uid':'32767','syntax':'accepted','cleanup':'verified','tls-cleanup':'verified'}
    if set(receipts)!=set(wanted)|{'relayd','daemon-log'} or any(receipts.get(k)!=v for k,v in wanted.items()):raise ValueError('identity/cleanup mismatch')
    if any(not re.fullmatch('[0-9a-f]{64}',receipts[k]) for k in (*hashes,'relayd','daemon-log')):raise ValueError('hash malformed')
    passed=re.findall(r'^\s*--- PASS: TestLabCompanionPath/([^ ]+) ',text,re.M)
    if len(passed)!=len(EXPECTED)+len(LOAD_PHASES) or set(passed)!=set(EXPECTED)|LOAD_PHASES or '\nPASS\n' not in text or '--- FAIL:' in text or 'LAB-FINAL companion-stopped backend-stopped listeners-absent' not in text:raise ValueError('Go/process gates incomplete')
    for name,row in rows.items():
        if set(row)!={'case','status','backend','body_sha256','headers_clean','client_error','backend_host','backend_authority'}:raise ValueError('path schema drift')
        if type(row['status'])is not int or type(row['backend'])is not int or type(row['client_error'])is not bool or row['headers_clean'] is not True:raise ValueError('path type/header violation')
        status,count=EXPECTED[name]
        if row['backend']!=count or (status is not None and row['status']!=status):raise ValueError('false forwarding/response')
        if name=='companion-stop' and row['status']!=0 and not 400<=row['status']<=599:raise ValueError('companion stop succeeded')
        if row['client_error']!=(row['status']==0):raise ValueError('response error hidden')
        expected_hash=hashlib.sha256(b'{"payload":"ordinary"}' if name in ('json','api-json','alt-reload-json') else b'').hexdigest() if count else ''
        expected_host=('api.test' if name.startswith(('api-','alt-')) else 'app.test') if count else ''
        expected_authority=('alt.test' if name.startswith('alt-') else expected_host) if count else ''
        if row['backend_authority']!=expected_authority:raise ValueError('wrong backend authority')
        if row['backend_host']!=expected_host:raise ValueError('wrong backend route')
        if row['body_sha256']!=expected_hash:raise ValueError('backend bytes mismatch')
    diagnostics=transport_diagnostics(text,complete=True)
    named={}
    for row in diagnostics['rows']:
        if row['case'] in EXPECTED:
            if row['case'] in named:raise ValueError('repeated named transport call')
            named[row['case']]=row
    if set(named)!=set(EXPECTED)-{'bare-data'}:raise ValueError('named transport coverage incomplete')
    for name,row in named.items():
        if row['status']!=rows[name]['status'] or row['stage']=='body':raise ValueError('transport/path outcomes disagree')
    readiness=[r for r in diagnostics['rows'] if r['case']=='readiness']
    load=[r for r in diagnostics['rows'] if r['case']=='load']
    if not readiness or readiness[-1]['status']!=421 or len(load)!=10 or sorted(r['status'] for r in load)!=[200]*7+[403]*2+[503]:raise ValueError('transport readiness/load coverage incomplete')
    return {'admitted':True,'case_count':len(EXPECTED), 'load_case_count':len(LOAD_PHASES),'loads':[loads[p] for p in sorted(loads)],'config':config,'reload':reload,'cases':[rows[n] for n in sorted(rows)],'receipts':receipts,'transport_diagnostics':diagnostics}

def guest_run(guest,work,binary,checker,native_program=None):
    program=ROOT/'.tools/research/labproxy-openbsd-amd64';profile=(ROOT/'research/relayd/lab-proxy.conf').read_bytes()
    program_hash=native_program or hashlib.sha256(program.read_bytes()).hexdigest()
    if not re.fullmatch('[0-9a-f]{64}',program_hash):raise ValueError('invalid lab program hash')
    hashes={'program':program_hash,'profile':hashlib.sha256(profile).hexdigest(),'engine':binary,'checker':checker}
    if native_program is None:
        with program.open('rb') as stream:reply=guest.call('set -eu; cat > /var/aegvium-lab-proxy; chmod 555 /var/aegvium-lab-proxy',stream=stream,seconds=120)
        if reply.returncode:raise RuntimeError('lab program transfer failed')
    else:
        guest.require('test "$(sha256 -q /var/aegvium-lab-proxy)" = "'+program_hash+'"')
    guest.require('set -eu; mkdir /var/aegvium-lab-path; chmod 755 /var/aegvium-lab-path; cat > /var/aegvium-lab-path/profile.conf',data=profile)
    script=(ROOT/'tools/native/lab-proxy.sh').read_bytes()
    for token,key in [('PROGRAM','program'),('PROFILE','profile'),('ENGINE','engine'),('CHECKER','checker')]:script=script.replace((token+'_SHA256').encode(),hashes[key].encode())
    log=work/'lab-proxy.log'
    with log.open('wb') as output:reply=guest.call('sh -s',data=script,seconds=180,output=output)
    result={'hashes':hashes,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_exit':reply.returncode,'admitted':False,'native_program':native_program is not None}
    try:result['transport_diagnostics']=transport_diagnostics(log.read_text())
    except (ValueError,KeyError,TypeError) as error:result['transport_diagnostics']={'valid':False,'complete':False,'error':str(error)}
    try:result.update(admit(log.read_text(),hashes))
    except (ValueError,KeyError,TypeError) as error:result['admission_error']=str(error)
    if reply.returncode:result['admitted']=False
    return result
