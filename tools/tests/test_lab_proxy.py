# SPDX-License-Identifier: BSD-3-Clause
"""Reject fake lab executable/TLS/no-bypass receipts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
SPEC=importlib.util.spec_from_file_location('lab_proxy',Path(__file__).resolve().parents[1]/'lab-proxy.py');LAB=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(LAB)
class LabProxyTests(unittest.TestCase):
    hashes={'program':'a'*64,'profile':'b'*64,'engine':'c'*64,'checker':'d'*64}
    def rows(self):
        result=[]
        for name,(status,count) in LAB.EXPECTED.items():
            status=502 if status is None else status
            digest=hashlib.sha256(b'{"payload":"ordinary"}' if name in ('json','api-json','alt-reload-json') else b'').hexdigest() if count else ''
            result.append({'case':name,'status':status,'backend':count,'body_sha256':digest,'headers_clean':True,'client_error':status==0,'backend_host':('api.test' if name.startswith(('api-','alt-')) else 'app.test') if count else '', 'backend_authority':('alt.test' if name.startswith('alt-') else 'api.test' if name.startswith('api-') else 'app.test') if count else ''})
        return result
    def loads(self):
        result=[]
        for phase,codes,targets,peak,reload in [('saturation',[200,200,200,200,503],['app.test','app.test','api.test','api.test'],4,0),('mixed',[200,200,403,403],['app.test','api.test'],2,0),('inflight-reload',[200],['api.test'],1,1)]:
            digest=hashlib.sha256(b'{"payload":"ordinary"}' if phase=='mixed' else b'').hexdigest()
            result.append({'phase':phase,'statuses':codes,'backend':len(targets),'peak':peak,'active_after':0,'effects':[{'backend_host':name,'authority':name,'body_sha256':digest,'headers_clean':True} for name in targets],'health':200,'reload_accepted':reload,'ack_before_release':False,'limit':4})
        return result
    def log(self,rows):
        receipts={**self.hashes,'uid':'32767','syntax':'accepted','cleanup':'verified','tls-cleanup':'verified','relayd':'e'*64,'daemon-log':'f'*64}
        traces=[]
        for row in rows:
            if row['case']=='bare-data':continue
            traces.append({'id':len(traces)+1,'case':row['case'],'start_ms':1,'duration_ms':1,'status':row['status'],'stage':'roundtrip' if row['status']==0 else 'complete','class':'eof' if row['status']==0 else 'none','health_samples':1,'health_age_ms':0})
        for name,status in [('readiness',421)]+[('load',200)]*7+[('load',403)]*2+[('load',503)]:
            traces.append({'id':len(traces)+1,'case':name,'start_ms':1,'duration_ms':1,'status':status,'stage':'complete','class':'none','health_samples':0,'health_age_ms':-1})
        diagnostics=['LAB-TRANSPORT '+json.dumps(r) for r in traces]+['LAB-TRANSPORT-FINAL calls='+str(len(traces))+' raw_errors=false']
        return '\n'.join(diagnostics+['LAB-CONFIG '+json.dumps({'checked':True,'invalid_rejected':7,'listeners_absent':True,'config_sha256':'1'*64,'ca_sha256':'2'*64})]+['LAB-RELOAD '+json.dumps({'accepted':2,'rejected':3,'health_samples':10,'health_connection_preserved':True,'same_process':True,'restored_config_sha256':'1'*64,'replacement_config_sha256':'3'*64})]+['LAB-PATH '+json.dumps(r) for r in rows]+['--- PASS: TestLabCompanionPath/'+r['case']+' (0.01s)' for r in rows]+['LAB-LOAD '+json.dumps(row) for row in self.loads()]+['--- PASS: TestLabCompanionPath/'+row['phase']+' (0.01s)' for row in self.loads()]+['LAB-FINAL companion-stopped backend-stopped listeners-absent']+['LAB\t'+k+'\t'+v for k,v in receipts.items()]+['PASS',''])
    def test_exact_composition(self):self.assertEqual(LAB.admit(self.log(self.rows()),self.hashes)['case_count'],len(LAB.EXPECTED))
    def test_rejects_false_forwarding_tls_identity_and_cleanup(self):
        for name,key,value in [('sql','backend',1),('sql','status',200),('json','body_sha256','0'*64),('spoof','headers_clean',False),('untrusted-cert','client_error',False),('wrong-name','status',200),('companion-stop','status',200),('get','backend',True),('api-get','backend_host','app.test'),('api-wrong-cert','backend',1),('api-untrusted-cert','status',200),('api-cleartext','status',200),('api-stall','backend',0),('alt-reload-get','backend_authority','api.test'),('reload-removed-api','backend',1),('api-reload-ca','backend',0)]:
            rows=self.rows();next(r for r in rows if r['case']==name)[key]=value
            with self.subTest(name=name,key=key),self.assertRaises(ValueError):LAB.admit(self.log(rows),self.hashes)
        text=self.log(self.rows())
        for bad in [self.log(self.rows()[:-1]),self.log(self.rows()+[self.rows()[0]]),text.replace('LAB\tuid\t32767','LAB\tuid\t0'),text.replace('LAB\tcleanup\tverified','LAB\tcleanup\tfailed'),text.replace('LAB\tprogram\t'+'a'*64,'LAB\tprogram\t'+'0'*64),text.replace('LAB-FINAL companion-stopped backend-stopped listeners-absent',''),text.replace('\"invalid_rejected\": 7','\"invalid_rejected\": 6'),text.replace('\"listeners_absent\": true','\"listeners_absent\": false'),text.replace('\"accepted\": 2','\"accepted\": 1'),text.replace('\"rejected\": 3','\"rejected\": 2'),text.replace('\"health_connection_preserved\": true','\"health_connection_preserved\": false'),text.replace('\"same_process\": true','\"same_process\": false'),text.replace('--- PASS: TestLabCompanionPath/json','--- FAIL: TestLabCompanionPath/json')]:
            with self.assertRaises(ValueError):LAB.admit(bad,self.hashes)

    def test_load_mutations_reject_overflow_hidden_effects_and_early_retirement(self):
        for key,value in [('backend',5),('peak',5),('active_after',1),('health',503),('limit',8),('ack_before_release',True),('statuses',[200]*5)]:
            row=self.loads()[0];row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):LAB.admit_load(row)
        row=self.loads()[1];row['effects'][0]['body_sha256']='0'*64
        with self.assertRaises(ValueError):LAB.admit_load(row)
        row=self.loads()[2];row['effects'][0]['authority']='alt.test'
        with self.assertRaises(ValueError):LAB.admit_load(row)

    def test_native_program_is_verified_and_never_replaced_by_host_transfer(self):
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)
            class Guest:
                def __init__(self):self.commands=[]
                def require(self,command,**kwargs):self.commands.append(command)
                def call(self,command,**kwargs):self.commands.append(command);kwargs['output'].write(b'owned log');return subprocess.CompletedProcess([],0)
            guest=Guest()
            with patch.object(LAB,'admit',return_value={'admitted':True}):result=LAB.guest_run(guest,work,'c'*64,'d'*64,native_program='a'*64)
            self.assertTrue(result['native_program']);self.assertEqual(result['hashes']['program'],'a'*64)
            self.assertTrue(any('sha256 -q /var/aegvium-lab-proxy' in c for c in guest.commands))
            self.assertFalse(any('cat > /var/aegvium-lab-proxy' in c for c in guest.commands))
