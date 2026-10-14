# SPDX-License-Identifier: BSD-3-Clause
"""Reject concealed forwarding, incomplete comparisons and false cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('relayd_body',ROOT/'tools/relayd-body.py')
BODY=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BODY)

class RelaydBodyTests(unittest.TestCase):
    def rows(self):
        prior=json.loads((ROOT/'research/native/body-http-observations.json').read_text())['native']['body_http']
        return [{**copy.deepcopy(row),'case':arm+'/'+row['case']} for arm in BODY.ARMS for row in prior]

    def log(self,rows):
        text='\n'.join('RELAYD-BODY '+json.dumps(r)+'\nRELAYD-BODY-ERROR '+r['case']+' none\n--- PASS: TestRelaydBodyComparison/'+r['case']+' (0.01s)' for r in rows)
        receipts={'binary':'a'*64,'profile':'b'*64,'relayd':'c'*64,'daemon-log':'d'*64,'uid':'32767','cleanup':'verified'}
        return text+'\n'+'\n'.join('BODY\t'+k+'\t'+v for k,v in receipts.items())+'\nPASS\n'

    def test_complete_comparison_and_safe_normalization_rejection(self):
        rows=self.rows();self.assertEqual(BODY.admit(self.log(rows),'a'*64,'b'*64)['case_count'],45)
        row=next(r for r in rows if r['case']=='http/cl-te')
        row.update(status=400,backend=0,handler=0,content_length=None,transfer_encoding=None,header_lengths=None,source_closed=0,source_read=0,wire_read=0,body_sha256='')
        self.assertTrue(BODY.admit(self.log(rows),'a'*64,'b'*64)['admitted'])

    def test_admission_rejects_false_backend_cleanup_identity_and_missing_cases(self):
        for field,value in [('backend',1),('status',200),('source_read',130),('source_closed',0),('source_read',True),('server_joined',False),('listener_absent',False),('rules',[]),('request_sha256','0'*64)]:
            rows=self.rows();row=next(r for r in rows if r['case']=='tcp/form-sql');row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):BODY.admit(self.log(rows),'a'*64,'b'*64)
        rows=self.rows()
        for text in [self.log(rows[:-1]),self.log(rows+[rows[0]]),self.log(rows).replace('BODY\tcleanup\tverified','BODY\tcleanup\tfailed'),self.log(rows).replace('BODY\tuid\t32767','BODY\tuid\t0'),self.log(rows).replace('--- PASS: TestRelaydBodyComparison/tcp/fixed-json','--- FAIL: TestRelaydBodyComparison/tcp/fixed-json'),self.log(rows).replace('RELAYD-BODY-ERROR tcp/fixed-json none','RELAYD-BODY-ERROR tcp/fixed-json timeout')]:
            with self.assertRaises(ValueError):BODY.admit(text,'a'*64,'b'*64)
