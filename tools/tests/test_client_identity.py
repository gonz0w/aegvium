# SPDX-License-Identifier: BSD-3-Clause
"""Reject substituted identity/Coraza/component/native cleanup evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('client_identity',Path(__file__).resolve().parents[1]/'client-identity.py')
C=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(C)


class ClientIdentityTests(unittest.TestCase):
    def log(self,rows=None):
        rows=C.EXPECTED if rows is None else rows
        return '\n'.join(['CLIENT-RECEIPT\tbinary\t'+'a'*64,'CLIENT-RECEIPT\tprogram\t'+'b'*64,'CLIENT-RECEIPT\tuid\t32767','CLIENT-STARTUP tls=false no_bind=true','CLIENT-STARTUP tls=true no_bind=true']+['CLIENT-IDENTITY '+json.dumps(r) for r in rows]+['CLIENT-FINAL companion_stopped=true backend_alive_at_stop=true assets_removed=true']+['--- PASS: TestLabClientIdentityWire/'+r['case']+' (0.01s)' for r in rows]+['--- PASS: TestLabClientIdentityWire (1.00s)','PASS'])+'\n'

    def test_complete_component_is_separate_from_cli_pf(self):
        result=C.admit(self.log(),'a'*64,'b'*64)
        self.assertEqual(result['case_count'],10)
        self.assertEqual(result['startup_checks'],2)

    def test_rejects_identity_rules_header_effect_tls_and_test_substitution(self):
        original=self.log()
        for index,key,value in ((1,'status',200),(1,'backend',1),(2,'status',451),(3,'status',451),(3,'headers_clean',False),(4,'body_sha256','0'*64),(7,'enabled',False),(8,'rules_sha256','0'*64),(9,'verified_tls',False),(0,'backend',True)):
            rows=copy.deepcopy(C.EXPECTED);rows[index][key]=value
            with self.subTest(key=key,index=index),self.assertRaises(ValueError):C.admit(self.log(rows),'a'*64,'b'*64)
        for bad in (original.replace('uid\t32767','uid\t0'),original.replace('tls=false no_bind=true','tls=false no_bind=false'),original.replace('assets_removed=true','assets_removed=false'),original.replace('--- PASS:','--- SKIP:'),original.replace('program\t'+'b'*64,'program\t'+'c'*64),original+original.splitlines()[0]+'\n',original.replace('CLIENT-STARTUP tls=true no_bind=true\n','')):
            with self.assertRaises(ValueError):C.admit(bad,'a'*64,'b'*64)

    def test_failed_supervisor_never_admitted(self):
        class Guest:
            def call(self,command,**kwargs):
                kwargs['output'].write(b'partial');return subprocess.CompletedProcess([],1)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(C,'admit',return_value={'admitted':True}):
                self.assertFalse(C.guest_run(Guest(),Path(directory),'a'*64,'b'*64)['admitted'])
