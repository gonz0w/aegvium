# SPDX-License-Identifier: BSD-3-Clause
"""Reject hidden wire effects, extra responses and incomplete native ownership."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_lab_tls as baseline
SPEC=importlib.util.spec_from_file_location('request_wire',Path(__file__).resolve().parents[1]/'request-wire.py')
W=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(W)


class RequestWireTests(unittest.TestCase):
    hashes=baseline.LabTLSTests.hashes

    def log(self,rows=None):
        rows=W.EXPECTED if rows is None else rows
        text=baseline.LabTLSTests().log().replace('TestLabTLSPassthrough','TestLabRequestWireNative')
        anchor='--- PASS: TestLabRequestWireNative/companion-stop'
        extra='\n'.join(['REQUEST-WIRE '+json.dumps(r) for r in rows]+['--- PASS: TestLabRequestWireNative/wire-'+r['mode']+'-'+r['case']+' (0.01s)' for r in rows]+[W.FINAL,W.MODE])+'\n'
        return text.replace(anchor,extra+anchor,1)

    def test_complete_matrix_and_identical_transport_inputs(self):
        r=W.admit(self.log(),self.hashes)
        self.assertEqual((r['case_count'],r['wire_case_count']),(29,52))
        self.assertEqual([{k:v for k,v in r.items() if k!='mode'} for r in W.EXPECTED[:26]],[{k:v for k,v in r.items() if k!='mode'} for r in W.EXPECTED[26:]])

    def test_rejects_effect_framing_eof_tls_identity_and_type_drift(self):
        for case,key,value in [('declared-trailer','backend',1),('undeclared-trailer','status',200),('pipeline-attack','backend',2),('json','body_sha256','0'*64),('get','input_sha256','0'*64),('json','sent',1),('json','trailers',1),('get','server_closed',False),('json','verified_tls',False),('get','responses',2),('get','additional_byte',True),('get','backend',True),('get','server_closed',1),('json','headers_clean',False),('json','authority','api.test'),('json','path','/second')]:
            rows=copy.deepcopy(W.EXPECTED);next(r for r in rows if r['case']==case)[key]=value
            with self.subTest(case=case,key=key),self.assertRaises(ValueError):W.admit(self.log(rows),self.hashes)

    def test_rejects_missing_duplicate_substituted_and_cleanup(self):
        text=self.log()
        for bad in (self.log(W.EXPECTED[:-1]),self.log(W.EXPECTED+[W.EXPECTED[0]]),self.log(list(reversed(W.EXPECTED))),text.replace(W.FINAL,''),text+'\n'+W.FINAL,text.replace(W.MODE,''),text.replace('TLSLAB\tuid\t32767','TLSLAB\tuid\t0'),text.replace(W.TLS.FINAL,''),text.replace('TestLabRequestWireNative','TestLabTLSPassthrough'),text.replace('--- PASS: TestLabRequestWireNative/wire-relayd-json','--- SKIP: TestLabRequestWireNative/wire-relayd-json'),text.replace('TLSLAB\tcleanup\tverified','TLSLAB\tcleanup\tfailed')):
            with self.assertRaises(ValueError):W.admit(bad,self.hashes)

    def test_profile_native_build_and_failed_supervisor(self):
        reply=subprocess.run(['python3',str(W.ROOT/'tools/native-engine.py'),'--request-wire'],capture_output=True,text=True)
        self.assertEqual(reply.returncode,2);self.assertIn('requires backend-isolation',reply.stderr)
        self.assertIn('/var/aegvium-lab-request-wire/control.sock',(W.ROOT/'research/relayd/lab-request-wire.conf').read_text())
        class Guest:
            def require(self,command,**kwargs):pass
            def call(self,command,**kwargs):kwargs['output'].write(b'partial');return subprocess.CompletedProcess([],1)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(W,'admit',return_value={'admitted':True}):self.assertFalse(W.guest_run(Guest(),Path(directory),'a'*64,'b'*64,'c'*64)['admitted'])
            with self.assertRaises(ValueError):W.guest_run(Guest(),Path(directory),'a'*64,'b'*64,'')
