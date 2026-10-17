# SPDX-License-Identifier: BSD-3-Clause
"""Ordinary component admission cannot become engine/traffic qualification."""
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_native_progress as progress

ENGINE = progress.ENGINE
LAB = ENGINE.LIFECYCLE


class LifecycleComponentsTests(unittest.TestCase):
    hashes = {'library': 'a'*64, 'control': 'b'*64}

    def log(self, hashes=None):
        hashes = hashes or self.hashes
        receipts = {**hashes, 'os': 'OpenBSD 7.9 amd64', 'uid': '32767', 'scope': 'ordinary-components'}
        lines = ['LIFECYCLE\t'+key+'\t'+value for key, value in receipts.items()]
        for name, expected in (('library', LAB.LIBRARY | LAB.LIBRARY_CHILDREN), ('control', LAB.CONTROL | LAB.CONTROL_CHILDREN)):
            lines += ['LIFECYCLE-BEGIN '+name]
            lines += ['--- PASS: '+test+' (0.00s)' for test in sorted(expected)]
            lines += ['PASS', 'LIFECYCLE-END '+name]
        return '\n'.join(lines + ['LIFECYCLE\tcomplete\tverified'])+'\n'

    def test_exact_component_counts_and_selection(self):
        result = LAB.admit(self.log(), self.hashes)
        self.assertEqual((result['parent_count'], result['subtest_count'], result['pass_count']), (18, 12, 30))
        self.assertFalse(result['native_source_build'])
        self.assertFalse(result['complete_profile_qualified'])
        for names in (LAB.LIBRARY, LAB.CONTROL):
            selected = LAB.selection(names)
            for name in names:
                self.assertRegex(name, selected)
                self.assertNotRegex(name+'FutureCase', selected)
        self.assertNotRegex('TestEnforcementCorpus', LAB.selection(LAB.LIBRARY))

    def test_missing_duplicate_unknown_failed_skipped_and_mixed_tests_reject(self):
        original = self.log()
        row = '--- PASS: TestLabSupervisionCompletion (0.00s)'
        child = '--- PASS: TestLabControlReload/accepted (0.00s)'
        for text in (original.replace(row+'\n',''), original.replace(row,row+'\n'+row),
                     original.replace(row,row.replace('PASS','FAIL')),
                     original.replace(row,row.replace('PASS','SKIP')),
                     original.replace(child,child.replace('accepted','unknown')),
                     original+'    --- PASS: unknown (0.00s)\n',
                     original.replace(row,'--- PASS: TestLabControlCleanupError (0.00s)'),
                     original.replace('\nPASS\n','\n',1)):
            with self.assertRaises(ValueError):LAB.admit(text,self.hashes)

    def test_identity_boundaries_premature_and_malformed_receipts_reject(self):
        original = self.log()
        for text in (original.replace('uid\t32767','uid\t0'),
                     original.replace('OpenBSD 7.9','OpenBSD 7.8'),
                     original.replace('a'*64,'c'*64),
                     original.replace('scope\tordinary-components','scope\tcomplete-profile'),
                     original+'LIFECYCLE\tuid\t32767\n',
                     original.replace('LIFECYCLE-END library\n',''),
                     original.replace('LIFECYCLE-BEGIN control','LIFECYCLE-BEGIN library'),
                     original.replace('LIFECYCLE\tcomplete\tverified\n',''),
                     'LIFECYCLE\tcomplete\tverified\n'+original.replace('LIFECYCLE\tcomplete\tverified\n',''),
                     'x'*(1024*1024+1)):
            with self.assertRaises(ValueError):LAB.admit(text,self.hashes)

    def test_transfer_hash_mismatch_and_transfer_failure_never_execute(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);binary=work/'binary';binary.write_bytes(b'ordinary fixture')
            actual=hashlib.sha256(binary.read_bytes()).hexdigest()
            class Guest:
                def __init__(self):self.calls=[]
                def require(self,*args,**kwargs):pass
                def call(self,command,**kwargs):self.calls.append(command);return subprocess.CompletedProcess([],1)
            guest=Guest()
            with self.assertRaises(ValueError):LAB.guest_run(guest,work,binary,'a'*64,binary,actual)
            self.assertEqual(guest.calls,[])
            with self.assertRaises(RuntimeError):LAB.guest_run(guest,work,binary,actual,binary,actual)
            self.assertEqual(len(guest.calls),1)
            self.assertNotEqual(guest.calls[0],'sh -s')

    def test_failed_or_timed_out_execution_keeps_counts_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);binary=work/'binary';binary.write_bytes(b'ordinary fixture')
            digest=hashlib.sha256(binary.read_bytes()).hexdigest()
            hashes={'library':digest,'control':digest};text=self.log(hashes)
            for outcome in (0,1,'timeout'):
                class Guest:
                    def require(self,*args,**kwargs):pass
                    def call(self,command,**kwargs):
                        if command=='sh -s':
                            script=kwargs['data'].decode()
                            self_script=LAB.selection(LAB.LIBRARY)
                            assert self_script in script and LAB.selection(LAB.CONTROL) in script
                            kwargs['output'].write(text.encode())
                            if outcome=='timeout':raise subprocess.TimeoutExpired(['private marker'],120)
                            return subprocess.CompletedProcess([],outcome)
                        return subprocess.CompletedProcess([],0)
                result=LAB.guest_run(Guest(),work,binary,digest,binary,digest)
                self.assertEqual(result['admitted'],outcome==0)
                self.assertEqual(result['observed_pass_count'],30)
                self.assertNotIn('private marker',json.dumps(result))

    def test_exclusive_mode_rejects_every_other_option_before_preflight(self):
        for mode in ('--lifecycle-components', '--lifecycle-source-build'):
            other = '--lifecycle-components' if mode == '--lifecycle-source-build' else '--lifecycle-source-build'
            for option in (other, '--source-build', '--lab-proxy', '--lab-tls', '--request-wire',
                           '--relayd-config', '--relayd-traffic', '--connector-comparison', '--inject-failure'):
                extra = [option, 'boot'] if option == '--inject-failure' else [option]
                with patch.object(sys, 'argv', ['native-engine.py', mode, *extra]), patch.object(ENGINE, 'git') as git, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:ENGINE.run()
                    self.assertEqual(error.exception.code, 2)
                    git.assert_not_called()
