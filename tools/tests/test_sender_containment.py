# SPDX-License-Identifier: BSD-3-Clause
"""Reject simulated sender/PF bypass and incomplete restoration evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('sender',Path(__file__).resolve().parents[1]/'sender-containment.py')
S=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(S)


class SenderTests(unittest.TestCase):
    hashes={k:c*64 for k,c in zip(('engine','program','checker','profile','open','protected','marker'),'abcdef0')}

    def prepared(self):
        views={k:'1'*64 for k in S.VIEWS};views['enabled']=hashlib.sha256(b'Enabled\n').hexdigest()
        return {'relay_uid':89,'hashes':self.hashes,'preflight':{'admitted':True,'before_views':views,'receipts':{'open-loaded':'2'*64,'protected-loaded':'3'*64}}}

    def log(self, rows=None):
        result=[];rows=S.expected_rows() if rows is None else rows
        for phase in S.PHASES:
            policy='protected' if phase in ('protected','reprotected') else 'open'
            result.append('\t'.join(('SENDER-PHASE',phase,policy,self.hashes[policy],self.prepared()['preflight']['receipts'][policy+'-loaded'])))
            if phase=='protected':result.append('SENDER-INVALID\tprotected\t'+'3'*64+'\t'+'8'*64)
            result.append('SENDER-ASSETS phase='+phase+' cert_sha256='+'4'*64+' config_sha256='+'5'*64)
            for row in rows:
                if row['phase']==phase: result.append('SENDER-PATH '+json.dumps(row))
            result += ['--- PASS: TestLabSenderContainment/'+r['case']+' (0.01s)' for r in rows if r['phase']==phase]
            result += ['--- PASS: TestLabSenderContainment (1.00s)','PASS']
            result.append('SENDER-FINAL phase='+phase+' companion_stopped=true backends_alive_at_stop=true listeners_absent=true assets_removed=true')
            for suffix in (('allow','deny') if policy=='protected' else ('open',)):
                # evaluations, total packets/bytes, in packets/bytes, out packets/bytes, state creations
                values=[40,20,4000,5,1000,15,3000,0 if suffix=='deny' else 11]
                result.append('\t'.join(['SENDER-COUNTER',phase,'aegvium-sender-'+suffix]+list(map(str,values))))
            result += ['SENDER-DAEMON\t'+phase+'\t'+'6'*64,'SENDER-STOP\t'+phase+'\tverified']
        receipts={**{k:self.hashes[k] for k in ('engine','program','checker','profile','open','protected')},'uid':'32767','relay-uid':'89','relayd':'7'*64,'cleanup':'verified','pf-restored':'verified'}
        result += ['SENDER\t'+k+'\t'+v for k,v in receipts.items()]
        result += ['SENDER-RESTORE\t'+k+'\t'+v for k,v in self.prepared()['preflight']['before_views'].items()]
        return '\n'.join(result)+'\n'

    def test_complete_four_phase_matrix(self):
        r=S.admit(self.log(),self.hashes,self.prepared())
        self.assertEqual(r['case_count'],44)
        self.assertEqual(r['phase_order'],list(S.PHASES))

    def test_rejects_forgery_tls_effect_and_typed_drift(self):
        for phase,name,key,value in [('protected','direct-app','connected',True),('protected','direct-app','error','tls'),('protected','direct-api','backend',1),('baseline','direct-app','backend',0),('reprotected','direct-plain','error','timeout'),('rollback','ingress-json','body_sha256','0'*64),('protected','ingress-api','verified_tls',False),('baseline','ingress-app','backend',True),('protected','cross-host','status',200),('protected','ingress-app','input_sha256','0'*64)]:
            rows=S.expected_rows();next(r for r in rows if r['phase']==phase and r['case']==name)[key]=value
            with self.subTest(case=name,key=key),self.assertRaises(ValueError):S.admit(self.log(rows),self.hashes,self.prepared())

    def test_rejects_missing_counter_policy_identity_restore_or_test(self):
        text=self.log();lines=text.splitlines()
        mutations=[text.replace('SENDER\tuid\t32767','SENDER\tuid\t0'),text.replace('SENDER\tpf-restored\tverified','SENDER\tpf-restored\tfailed'),text.replace('SENDER-RESTORE\trules\t'+'1'*64,'SENDER-RESTORE\trules\t'+'0'*64),text.replace('--- PASS: TestLabSenderContainment (','--- SKIP: TestLabSenderContainment ('),text.replace('SENDER-PHASE\tprotected\tprotected','SENDER-PHASE\tprotected\topen'),text.replace('assets_removed=true','assets_removed=false'),text.replace('SENDER\tprogram\t'+'b'*64,'SENDER\tprogram\t'+'0'*64)]
        for tag in ('SENDER-INVALID','SENDER-PHASE','SENDER-COUNTER','SENDER-STOP','SENDER-RESTORE','SENDER-FINAL','SENDER-ASSETS'):
            first=next(l for l in lines if l.startswith(tag))
            mutations += [text.replace(first+'\n','',1),text+first+'\n']
        counter=next(l for l in lines if l.startswith('SENDER-COUNTER\tprotected\taegvium-sender-deny'))
        parts=counter.split('\t')
        for index,value in ((3,'0'),(4,'0'),(10,'1'),(5,'1')):
            changed=parts[:];changed[index]=value;mutations.append(text.replace(counter,'\t'.join(changed)))
        phase_line=next(l for l in lines if l.startswith('SENDER-PHASE\tprotected'))
        mutations.append(phase_line+'\n'+text.replace(phase_line+'\n','',1))
        for bad in mutations:
            with self.assertRaises(ValueError):S.admit(bad,self.hashes,self.prepared())

    def test_preflight_syntax_only_and_failed_run_never_admitted(self):
        for bad in (0,True,32767,65535):
            with self.assertRaises(ValueError):S.inputs(bad,b'marker')
        assets,hashes=S.inputs(89,b'marker');self.assertIn(b'user 89',assets['protected.pf']);self.assertNotIn(b'RELAY_UID',assets['protected.pf'])
        prepared=self.prepared()
        receipts={'uid':'89','syntax':'accepted','unchanged':'verified',**{k:self.hashes[k] for k in ('open','protected','profile')},'restore':'9'*64,'open-loaded':'2'*64,'protected-loaded':'3'*64}
        preflight='\n'.join(['SENDER-PREFLIGHT\t'+k+'\t'+v for k,v in receipts.items()]+['SENDER-BEFORE\t'+k+'\t'+v for k,v in prepared['preflight']['before_views'].items()])
        self.assertTrue(S.admit_preflight(preflight,self.hashes,89)['admitted'])
        for bad in (preflight.replace('unchanged\tverified','unchanged\tfailed'),preflight+'\nSENDER-PREFLIGHT\tuid\t89',preflight.replace('SENDER-BEFORE\trules','SENDER-BEFORE\tunknown')):
            with self.assertRaises(ValueError):S.admit_preflight(bad,self.hashes,89)
        class Guest:
            def __init__(self):self.commands=[]
            def require(self,command,**kwargs):self.commands.append(command)
            def call(self,command,**kwargs):self.commands.append(command);kwargs['output'].write(b'partial');return subprocess.CompletedProcess([],1)
        with tempfile.TemporaryDirectory() as d:
            guest=Guest()
            with patch.object(S,'admit',return_value={'admitted':True}):r=S.guest_run(guest,Path(d),'a'*64,'c'*64,'b'*64,prepared)
            self.assertFalse(r['admitted']);self.assertFalse(any('cat > /var/aegvium-lab-proxy' in c for c in guest.commands))

    def test_loopback_group_guard_rejects_extra_missing_or_duplicate_members(self):
        controller=(S.ROOT/'tools/native/sender-containment.sh').read_text()
        function=controller.split('sole_loopback() {',1)[1].split('\n}',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'status'
            for text, accepted in [('lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 32768\n\tgroups: lo\n\tinet 127.0.0.1 netmask 0xff000000\n',True),('lo0: flags=8049\nlo1: flags=8049\n',False),('lo1: flags=8049\n',False),('',False),('lo: carp demote count 0\n',False),('lo0: flags=8049\nlo0: flags=8049\n',False)]:
                path.write_text(text)
                reply=subprocess.run(['sh','-c','sole_loopback() {'+function+'\n}\nsole_loopback "$1"','guard',str(path)],capture_output=True)
                self.assertEqual(reply.returncode==0,accepted,text)

    def test_client_identity_requires_named_test_and_one_ordered_mode_per_phase(self):
        original=self.log()
        changed=original.replace('TestLabSenderContainment','TestLabSenderClientIdentity')
        for phase in S.PHASES:
            changed=changed.replace('SENDER-ASSETS phase='+phase,'SENDER-CLIENT-IDENTITY phase='+phase+' enabled=true\nSENDER-ASSETS phase='+phase)
        self.assertEqual(S.admit(changed,self.hashes,self.prepared(),True)['case_count'],44)
        bad=[original,changed.replace('enabled=true','enabled=false'),changed.replace('TestLabSenderClientIdentity','TestLabSenderContainment'),changed.replace('SENDER-CLIENT-IDENTITY phase=protected enabled=true\n',''),changed+'SENDER-CLIENT-IDENTITY phase=protected enabled=true\n']
        marker='SENDER-CLIENT-IDENTITY phase=protected enabled=true\n'
        bad.append(changed.replace(marker,'')+marker)
        for text in bad:
            with self.assertRaises(ValueError):S.admit(text,self.hashes,self.prepared(),True)
        with self.assertRaises(ValueError):S.admit(changed,self.hashes,self.prepared())
        with self.assertRaises(ValueError):S.admit(changed,self.hashes,self.prepared(),'yes')
