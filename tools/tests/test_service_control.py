# SPDX-License-Identifier: BSD-3-Clause
"""Bounded pure C protocol/native-source fixture; every subject OS call faked."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ServiceControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='service-control-', dir=ROOT / '.tools'))
        cls.env = dict(os.environ, TMPDIR=str(cls.work))
        cls.binary = cls.work / 'service-control'
        result = subprocess.run([
            '/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DAEG_SERVICE_FIXTURE', '-I', str(ROOT / 'internal/inspectorowner'),
            '-I', str(ROOT / 'tools/tests/fixtures'),
            str(ROOT / 'internal/inspectorowner/service_control.c'),
            str(ROOT / 'tools/tests/fixtures/service-control-harness.c'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=30, check=False, env=cls.env)
        if result.returncode:
            raise AssertionError(result.stderr[:8192])

    def test_fixed_owner_endpoint_boundaries(self):
        for case in ('normal', 'status', 'fragment', 'ancestor', 'stale', 'nonroot',
                     'peer', 'prefix', 'trailing', 'oversize', 'timeout', 'close',
                     'drift', 'clock', 'unlink', 'low-listener', 'low-client', 'low-close',
                     'shared', 'future', 'epoch-zero', 'epoch-max'):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True,
                                        text=True, timeout=5, check=False, env=self.env)
                self.assertEqual(result.returncode, 0, result.stderr[:1024])
                self.assertEqual(result.stdout, 'PASS\n')
                self.assertFalse(result.stderr)
