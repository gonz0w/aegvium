# SPDX-License-Identifier: BSD-3-Clause
"""Offline ordinary build admission and no-fallback boundaries; no guest traffic."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_native_progress as progress

LAB = progress.ENGINE.LIFECYCLE


class LifecycleBuildTests(unittest.TestCase):
    def inputs(self, work):
        asset = work / 'archive'; asset.write_bytes(b'owned offline input')
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        return {'compiler': asset, 'source': asset, 'compiler_sha256': digest,
                'source_sha256': digest, 'compiler_executable_sha256': 'c'*64}

    def log(self, inputs):
        receipts = {'os': 'OpenBSD 7.9 amd64', 'version': 'go1.27.2', 'uid': '32767',
                    'compiler': inputs['compiler_executable_sha256'], 'source': inputs['source_sha256'],
                    'library': 'a'*64, 'control': 'b'*64}
        return '\n'.join('LCBUILD\t'+key+'\t'+value for key,value in receipts.items())+'\n'

    def guest(self, log, outcome=0, transfer_error=False, install_error=False):
        class Guest:
            def __init__(self):self.commands=[];self.builds=0
            def require(self, command):
                self.commands.append(command)
                if install_error and 'cp /var/' in command:raise RuntimeError('installation mismatch')
            def call(self, command, **kwargs):
                self.commands.append(command)
                if command=='sh -s':
                    self.builds += 1
                    self.script=kwargs['data'].decode();self.timeout=kwargs['seconds']
                    kwargs['output'].write(log.encode())
                    if isinstance(outcome, BaseException):raise outcome
                    return subprocess.CompletedProcess([],outcome)
                assert 'stream' in kwargs
                return subprocess.CompletedProcess([],int(transfer_error))
        return Guest()

    def test_build_receipts_require_both_outputs_and_exact_input_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs=self.inputs(Path(folder));original=self.log(inputs)
            self.assertEqual(LAB.parse_build(original,inputs)['control'],'b'*64)
            for key,value in (('os','OpenBSD 7.9 amd64'),('version','go1.27.2'),('uid','32767'),
                              ('compiler','c'*64),('source',inputs['source_sha256']),('library','a'*64),('control','b'*64)):
                row='LCBUILD\t'+key+'\t'+value+'\n'
                for bad in (original.replace(row,''),original+row,original.replace(row,'LCBUILD\t'+key+'\twrong\n')):
                    with self.subTest(key=key),self.assertRaises(ValueError):LAB.parse_build(bad,inputs)
            for bad in (original+'LCBUILD\textra\tvalue\n','x'*(1024*1024+1)):
                with self.assertRaises(ValueError):LAB.parse_build(bad,inputs)

    def test_changed_input_and_transfer_failure_never_compile_or_install(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);inputs=self.inputs(work);guest=self.guest(self.log(inputs))
            inputs['source_sha256']='d'*64
            with self.assertRaises(ValueError):LAB.build_guest(guest,work,inputs)
            self.assertEqual(guest.commands,[])
            inputs=self.inputs(work);guest=self.guest(self.log(inputs),transfer_error=True)
            with self.assertRaises(RuntimeError):LAB.build_guest(guest,work,inputs)
            self.assertEqual(guest.builds,0)
            self.assertFalse(any('cp /var/' in c for c in guest.commands))

    def test_nonzero_timeout_io_and_incomplete_builds_never_install(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);inputs=self.inputs(work);complete=self.log(inputs)
            for log,outcome in ((complete,1),(complete,subprocess.TimeoutExpired(['private marker'],1200)),
                                (complete,OSError('private marker')),(complete.rsplit('LCBUILD',1)[0],0)):
                guest=self.guest(log,outcome);result=LAB.build_guest(guest,work,inputs)
                self.assertFalse(result['admitted'])
                self.assertEqual(result['build_log_sha256'],hashlib.sha256(log.encode()).hexdigest())
                self.assertFalse(any('cp /var/' in c for c in guest.commands))
                self.assertEqual(guest.builds,1)
                self.assertNotIn('private marker',str(result))

    def test_install_uses_only_native_receipts_and_mismatch_aborts(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);inputs=self.inputs(work);guest=self.guest(self.log(inputs))
            result=LAB.build_guest(guest,work,inputs)
            self.assertTrue(result['admitted']);self.assertTrue(result['installed_verified'])
            self.assertEqual(result['hashes'],{'library':'a'*64,'control':'b'*64})
            installs=[c for c in guest.commands if 'cp /var/' in c]
            self.assertEqual(len(installs),2)
            for name,digest in result['hashes'].items():
                command=next(c for c in installs if '/output/'+name+'.test' in c)
                self.assertIn(digest,command);self.assertIn('chown root:wheel',command);self.assertIn('chmod 555',command)
            self.assertEqual(guest.timeout,1200)
            self.assertIn('go test -mod=vendor -p=2 -c',guest.script)
            self.assertNotIn('-test.run',guest.script)
            self.assertNotIn('engine-repeat',guest.script)
            with self.assertRaises(RuntimeError):LAB.build_guest(self.guest(self.log(inputs),install_error=True),work,inputs)

    def test_native_build_failure_skips_execution_and_still_tears_down(self):
        runner=progress.RunnerProgressTests()
        status,report,journal=runner.exercise(['--lifecycle-source-build'],lifecycle_build_failure=True)
        self.assertEqual(status,1);self.assertFalse(report['passed']);self.assertFalse(report['native_build'])
        self.assertEqual(next(s['state'] for s in journal['stages'] if s['name']=='lifecycle_build'),'failed')
        self.assertEqual(next(s['state'] for s in journal['stages'] if s['name']=='native'),'not-run')
        self.assertTrue(report['teardown']['teardown_verified'])
