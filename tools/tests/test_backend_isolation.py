# SPDX-License-Identifier: BSD-3-Clause
"""Reject false local backend isolation and substituted foreign-user evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_sender_containment as baseline
SPEC=importlib.util.spec_from_file_location('backend',Path(__file__).resolve().parents[1]/'backend-isolation.py')
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)


class BackendTests(unittest.TestCase):
    def prepared(self):
        p=baseline.SenderTests().prepared();p['probe_uid']=1;return p

    def log(self):
        text=baseline.SenderTests().log().replace('TestLabSenderContainment','TestLabBackendIsolation')
        public='=== RUN   TestLabBackendPublicFiles\n--- PASS: TestLabBackendPublicFiles (0.01s)\nPASS\n'
        text=''.join('BACKEND-PUBLIC '+l+'\n' for l in public.splitlines())+'BACKEND-PUBLIC-LOG\t'+hashlib.sha256(public.encode()).hexdigest()+'\n'+text
        for phase in B.S.PHASES:
            text=text.replace('SENDER-ASSETS phase='+phase,'SENDER-CLIENT-IDENTITY phase='+phase+' enabled=true\nSENDER-ASSETS phase='+phase)
            protected=phase in ('protected','reprotected');effects=[];rows=[]
            for name in ('plain','api'):
                effects.append({'phase':phase,'case':name,'backend':0 if protected else 1,'authority':'' if protected else 'api.test' if name=='api' else 'app.test','body_sha256':'' if protected else B.BODY_SHA})
                rows.append({'phase':phase,'case':name,'input_sha256':B.input_sha(name),'ca_sha256':'4'*64,'connected':not protected,'verified_tls':not protected and name=='api','status':0 if protected else 200,'error':'denied' if protected else ''})
            marker='SENDER-FINAL phase='+phase
            additions=''.join('BACKEND-EFFECT '+json.dumps(e)+'\n' for e in effects)+'BACKEND-FIXTURE phase='+phase+' public_assets_removed=true\n'
            text=text.replace(marker,additions+marker)
            raw='BACKEND-PRINCIPAL phase='+phase+' uid=1 euid=1 binary='+'a'*64+' ca_sha256='+'4'*64+'\n'
            raw+=''.join('BACKEND-PROBE '+json.dumps(r)+'\n' for r in rows)
            raw+='--- PASS: TestLabBackendProbe/plain (0.01s)\n--- PASS: TestLabBackendProbe/api (0.01s)\n--- PASS: TestLabBackendProbe (0.03s)\nPASS\n'
            foreign=''.join('BACKEND-FOREIGN '+l+'\n' for l in raw.splitlines())+'BACKEND-PROBE-LOG\t'+phase+'\t'+hashlib.sha256(raw.encode()).hexdigest()+'\nBACKEND-SYNC\t'+phase+'\tremoved\n'
            for suffix in (('allow','deny') if protected else ('open',)):
                values=[40,20,4000,5,1000,15,3000,0 if suffix=='deny' else 11]
                foreign+='\t'.join(['BACKEND-COUNTER',phase,'aegvium-backend-'+suffix]+list(map(str,values)))+'\n'
            text=text.replace('SENDER-DAEMON\t'+phase,foreign+'SENDER-DAEMON\t'+phase)
        return text+'BACKEND-CLEANUP\tpublic-sync\tremoved\n'

    def rehash(self,text):
        lines=text.splitlines();pending=[];out=[]
        for line in lines:
            if line.startswith('BACKEND-FOREIGN '):pending.append(line[len('BACKEND-FOREIGN '):])
            elif line.startswith('BACKEND-PROBE-LOG\t'):
                fields=line.split('\t');fields[2]=hashlib.sha256(('\n'.join(pending)+'\n').encode()).hexdigest();line='\t'.join(fields);pending=[]
            out.append(line)
        return '\n'.join(out)+'\n'

    def test_complete_separate_foreign_and_independent_effects(self):
        r=B.admit(self.log(),baseline.SenderTests.hashes,self.prepared())
        self.assertEqual((r['case_count'],r['foreign_probe_count'],r['independent_effect_count']),(44,8,8))
        self.assertEqual(r['foreign_principals'][0]['uid'],1)

    def test_rejects_forged_effect_identity_tls_input_and_cleanup(self):
        text=self.log()
        changes=[('uid=1 euid=1','uid=0 euid=0'),('uid=1 euid=1','uid=32767 euid=32767'),('"status": 0','"status": 200'),('"connected": false','"connected": true'),('"error": "denied"','"error": "timeout"'),('"verified_tls": true','"verified_tls": false'),('"backend": 0','"backend": 1'),('"backend": 0','"backend": false'),('"status": 0','"status": false'),(B.BODY_SHA,'0'*64),(B.input_sha('api'),'0'*64),('binary='+'a'*64,'binary='+'b'*64),('public_assets_removed=true','public_assets_removed=false'),('BACKEND-CLEANUP\tpublic-sync\tremoved','BACKEND-CLEANUP\tpublic-sync\tfailed'),('--- PASS: TestLabBackendProbe/api','--- SKIP: TestLabBackendProbe/api'),('TestLabBackendIsolation','TestLabSenderClientIdentity')]
        for old,new in changes:
            with self.subTest(change=old),self.assertRaises(ValueError):B.admit(self.rehash(text.replace(old,new,1)),baseline.SenderTests.hashes,self.prepared())

    def test_rejects_missing_duplicate_reordered_or_zero_counter_evidence(self):
        text=self.log();lines=text.splitlines()
        for marker in ('BACKEND-PROBE-LOG','BACKEND-PUBLIC-LOG','BACKEND-EFFECT','BACKEND-SYNC','BACKEND-COUNTER','BACKEND-CLEANUP'):
            line=next(l for l in lines if l.startswith(marker))
            for bad in (text.replace(line+'\n','',1),text+line+'\n'):
                with self.subTest(marker=marker),self.assertRaises(ValueError):B.admit(bad,baseline.SenderTests.hashes,self.prepared())
        line=next(l for l in lines if l.startswith('BACKEND-COUNTER\tprotected\taegvium-backend-deny'))
        values=line.split('\t')
        for index,value in ((3,'0'),(4,'0'),(10,'1'),(9,'1')):
            changed=values[:];changed[index]=value
            with self.assertRaises(ValueError):B.admit(text.replace(line,'\t'.join(changed)),baseline.SenderTests.hashes,self.prepared())
        with self.assertRaises(ValueError):B.admit(text.replace('BACKEND-FOREIGN PASS','BACKEND-FOREIGN FAIL',1),baseline.SenderTests.hashes,self.prepared())

    def test_fixed_policy_controller_and_failed_supervisor(self):
        reply=subprocess.run(['python3',str(B.ROOT/'tools/native-engine.py'),'--backend-isolation'],capture_output=True,text=True)
        self.assertEqual(reply.returncode,2);self.assertIn('requires client-identity',reply.stderr)
        for uid in (0,1,32767,65535,True):
            with self.assertRaises(ValueError):B.inputs(uid,b'owned')
        assets,hashes=B.inputs(89,b'owned');self.assertIn(b'user 32767',assets['protected.pf']);self.assertIn(b'18086:18087',assets['protected.pf']);self.assertNotIn(b'/var/aegvium-lab-sender',assets['profile.conf'])
        controller=B.script({**hashes,**{k:'a'*64 for k in ('engine','program','checker')}},89)
        self.assertIn(b'su -m daemon',controller);self.assertIn(b'TestLabBackendIsolation',controller);self.assertNotIn(b'RELAY_UID',controller);self.assertNotIn(b'MARKER_SHA256',controller)
        class Guest:
            def require(self,command):pass
            def call(self,command,**kwargs):kwargs['output'].write(b'partial');return subprocess.CompletedProcess([],1)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(B,'admit',return_value={'admitted':True}):self.assertFalse(B.guest_run(Guest(),Path(directory),'a'*64,'c'*64,'b'*64,self.prepared())['admitted'])
