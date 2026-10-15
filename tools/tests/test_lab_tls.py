# SPDX-License-Identifier: BSD-3-Clause
"""Reject hidden effects, authority drift and incomplete native TLS lifecycle."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
SPEC = importlib.util.spec_from_file_location('lab_tls', Path(__file__).resolve().parents[1]/'lab-tls.py')
TLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TLS)


class LabTLSTests(unittest.TestCase):
    hashes = {'engine':'a'*64, 'checker':'b'*64, 'program':'c'*64, 'profile':'d'*64}

    def log(self, rows=None):
        rows = TLS.EXPECTED if rows is None else rows
        receipts = {**self.hashes, 'uid':'32767', 'syntax':'accepted', 'cleanup':'verified', 'relayd':'e'*64, 'daemon-log':'f'*64}
        return '\n'.join(['TLS-ASSETS cert_sha256='+'1'*64+' config_sha256='+'2'*64, TLS.STARTUP] + ['TLS-PATH '+json.dumps(r) for r in rows] + ['--- PASS: TestLabTLSPassthrough/'+r['case']+' (0.01s)' for r in rows] + ['--- PASS: TestLabTLSPassthrough (2.00s)', TLS.FINAL] + ['TLSLAB\t'+k+'\t'+v for k,v in receipts.items()] + ['PASS', ''])

    def test_complete_native_matrix(self):
        self.assertEqual(TLS.admit(self.log(), self.hashes)['case_count'], 29)

    def test_rejects_authority_effect_trust_and_type_drift(self):
        for name, key, value in [('cross-app-api','backend',1), ('cross-app-api','status',200), ('unknown-sni','verified_tls',True), ('api-match','authority','app.test'), ('json','body_sha256','0'*64), ('app-match','headers_clean',False), ('app-match','backend',True), ('app-match','input_sha256','0'*64), ('slow-tls','client_error',False), ('forged-local-prefix','backend',0)]:
            rows = copy.deepcopy(TLS.EXPECTED)
            next(r for r in rows if r['case']==name)[key] = value
            with self.subTest(case=name, key=key), self.assertRaises(ValueError):
                TLS.admit(self.log(rows), self.hashes)

    def test_rejects_missing_duplicate_failed_root_and_cleanup(self):
        text = self.log()
        for bad in [self.log(TLS.EXPECTED[:-1]), self.log(TLS.EXPECTED+[TLS.EXPECTED[0]]), self.log(list(reversed(TLS.EXPECTED))), text.replace(TLS.FINAL,''), text.replace(TLS.STARTUP,''), text.replace('TLSLAB\tuid\t32767','TLSLAB\tuid\t0'), text.replace('TLSLAB\tcleanup\tverified','TLSLAB\tcleanup\tfailed'), text.replace('--- PASS: TestLabTLSPassthrough (','--- SKIP: TestLabTLSPassthrough ('), text.replace('--- PASS: TestLabTLSPassthrough/json','--- FAIL: TestLabTLSPassthrough/json'), text.replace('TLS-ASSETS cert_sha256=','TLS-ASSETS cert_sha256=wrong'), text+'\nTLSLAB\tuid\t32767', text+'\n'+TLS.FINAL]:
            with self.assertRaises(ValueError):
                TLS.admit(bad,self.hashes)

    def test_native_identity_required_no_host_fallback_and_failure_retained(self):
        class Guest:
            def __init__(self,code): self.commands=[];self.code=code
            def require(self,command,**kwargs): self.commands.append(command)
            def call(self,command,**kwargs):
                self.commands.append(command);kwargs['output'].write(b'partial failure');return subprocess.CompletedProcess([],self.code)
        with tempfile.TemporaryDirectory() as d:
            guest=Guest(1)
            with patch.object(TLS,'admit',return_value={'admitted':True}):
                result=TLS.guest_run(guest,Path(d),'a'*64,'b'*64,'c'*64)
            self.assertFalse(result['admitted'])
            self.assertEqual(result['supervisor_exit'],1)
            self.assertTrue(any('sha256 -q /var/aegvium-lab-proxy' in c for c in guest.commands))
            self.assertFalse(any('cat > /var/aegvium-lab-proxy' in c for c in guest.commands))
            with self.assertRaises(ValueError): TLS.guest_run(guest,Path(d),'a'*64,'b'*64,'')
