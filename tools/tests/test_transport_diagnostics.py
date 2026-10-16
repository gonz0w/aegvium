# SPDX-License-Identifier: BSD-3-Clause
"""Diagnostic observations cannot convert failed composition into acceptance."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_lab_proxy as baseline
LAB=baseline.LAB


class TransportDiagnosticsTests(unittest.TestCase):
    def text(self):return baseline.LabProxyTests().log(baseline.LabProxyTests().rows())

    def mutate(self,key,value):
        lines=self.text().splitlines()
        index=next(i for i,l in enumerate(lines) if l.startswith('LAB-TRANSPORT '))
        row=json.loads(lines[index].split(' ',1)[1]);row[key]=value;lines[index]='LAB-TRANSPORT '+json.dumps(row)
        return '\n'.join(lines)+'\n'

    def test_complete_names_correlate_with_original_outcomes(self):
        result=LAB.admit(self.text(),baseline.LabProxyTests.hashes)
        diagnostic=result['transport_diagnostics']
        self.assertTrue(diagnostic['valid']);self.assertTrue(diagnostic['complete']);self.assertEqual(diagnostic['call_count'],52)
        self.assertEqual(result['case_count'],42)

    def test_rejects_raw_fields_invalid_classes_types_times_and_health(self):
        for key,value in [('raw_error','private marker'),('class','private marker'),('case','http://private.invalid'),('case',[]),('stage','tls-guessed'),('id',True),('id',0),('start_ms',-1),('duration_ms',120001),('status',0),('health_samples',-1),('health_samples',0),('health_age_ms',-1),('health_age_ms',10000)]:
            with self.subTest(key=key),self.assertRaises(ValueError):LAB.transport_diagnostics(self.mutate(key,value))
        bad=self.mutate('stage','roundtrip')
        with self.assertRaises(ValueError):LAB.transport_diagnostics(bad)
        bad=self.mutate('class','reset')
        with self.assertRaises(ValueError):LAB.transport_diagnostics(bad)

    def test_rejects_missing_duplicate_incomplete_or_disagreed_success(self):
        text=self.text();line=next(l for l in text.splitlines() if l.startswith('LAB-TRANSPORT '))
        final=next(l for l in text.splitlines() if l.startswith('LAB-TRANSPORT-FINAL '))
        for bad in (text.replace(line+'\n','',1),text+line+'\n',text.replace(final,'',1),text+final+'\n',self.mutate('status',421),self.mutate('case','bare-data')):
            with self.assertRaises(ValueError):LAB.admit(bad,baseline.LabProxyTests.hashes)

    def test_partial_failure_observed_without_success_or_retry(self):
        row={'id':1,'case':'reload-app-during','start_ms':100,'duration_ms':1,'status':0,'stage':'roundtrip','class':'reset','health_samples':3,'health_age_ms':10}
        text='LAB-TRANSPORT '+json.dumps(row)+'\n--- FAIL: TestLabCompanionPath (1.0s)\nFAIL\n'
        observed=LAB.transport_diagnostics(text)
        self.assertTrue(observed['valid']);self.assertFalse(observed['complete']);self.assertEqual(observed['rows'],[row])
        with self.assertRaises(ValueError):LAB.transport_diagnostics(text,complete=True)
        with self.assertRaises(ValueError):LAB.admit(text,baseline.LabProxyTests.hashes)
        class Guest:
            def require(self,command,**kwargs):pass
            def call(self,command,**kwargs):kwargs['output'].write(text.encode());return subprocess.CompletedProcess([],1)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(LAB,'admit',return_value={'admitted':True}):
                result=LAB.guest_run(Guest(),Path(directory),'c'*64,'d'*64,native_program='a'*64)
        self.assertFalse(result['admitted']);self.assertEqual(result['transport_diagnostics']['rows'],[row])
        full=self.text().splitlines()
        index=next(i for i,line in enumerate(full) if line.startswith('LAB-TRANSPORT '))
        body=json.loads(full[index].split(' ',1)[1]);body['stage']='body';body['class']='unexpected-eof'
        full[index]='LAB-TRANSPORT '+json.dumps(body)
        with self.assertRaises(ValueError):LAB.admit('\n'.join(full)+'\n',baseline.LabProxyTests.hashes)
        old=LAB.transport_diagnostics('historical fixture with no transport namespace\n')
        self.assertEqual(old['rows'],[]);self.assertFalse(old['complete'])
