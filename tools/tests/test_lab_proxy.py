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
            digest=hashlib.sha256(b'{"payload":"ordinary"}' if name=='json' else b'').hexdigest() if count else ''
            result.append({'case':name,'status':status,'backend':count,'body_sha256':digest,'headers_clean':True,'client_error':status==0})
        return result
    def log(self,rows):
        receipts={**self.hashes,'uid':'32767','syntax':'accepted','cleanup':'verified','tls-cleanup':'verified','relayd':'e'*64,'daemon-log':'f'*64}
        return '\n'.join(['LAB-PATH '+json.dumps(r) for r in rows]+['--- PASS: TestLabCompanionPath/'+r['case']+' (0.01s)' for r in rows]+['LAB-FINAL companion-stopped backend-stopped listeners-absent']+['LAB\t'+k+'\t'+v for k,v in receipts.items()]+['PASS',''])
    def test_exact_composition(self):self.assertEqual(LAB.admit(self.log(self.rows()),self.hashes)['case_count'],15)
    def test_rejects_false_forwarding_tls_identity_and_cleanup(self):
        for name,key,value in [('sql','backend',1),('sql','status',200),('json','body_sha256','0'*64),('spoof','headers_clean',False),('untrusted-cert','client_error',False),('wrong-name','status',200),('companion-stop','status',200),('get','backend',True)]:
            rows=self.rows();next(r for r in rows if r['case']==name)[key]=value
            with self.subTest(name=name,key=key),self.assertRaises(ValueError):LAB.admit(self.log(rows),self.hashes)
        text=self.log(self.rows())
        for bad in [self.log(self.rows()[:-1]),self.log(self.rows()+[self.rows()[0]]),text.replace('LAB\tuid\t32767','LAB\tuid\t0'),text.replace('LAB\tcleanup\tverified','LAB\tcleanup\tfailed'),text.replace('LAB\tprogram\t'+'a'*64,'LAB\tprogram\t'+'0'*64),text.replace('LAB-FINAL companion-stopped backend-stopped listeners-absent',''),text.replace('--- PASS: TestLabCompanionPath/json','--- FAIL: TestLabCompanionPath/json')]:
            with self.assertRaises(ValueError):LAB.admit(bad,self.hashes)
