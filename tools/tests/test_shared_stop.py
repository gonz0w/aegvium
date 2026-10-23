# SPDX-License-Identifier: BSD-3-Clause
"""Pure existing controller with frozen epochs; no subject OS operation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
class SharedStopTests(unittest.TestCase):
    def test_shared_epoch_and_late_physical_cleanup(self):
        work=Path(tempfile.mkdtemp(prefix='shared-stop-',dir=ROOT/'.tools'))
        env=dict(os.environ,TMPDIR=str(work));binary=work/'shared-stop'
        built=subprocess.run(['/usr/bin/cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-I',str(ROOT/'internal/inspectorowner'),str(ROOT/'internal/inspectorowner/controller.c'),str(ROOT/'tools/tests/fixtures/shared-stop-harness.c'),'-o',str(binary)],capture_output=True,text=True,timeout=30,env=env,check=False)
        self.assertEqual(built.returncode,0,built.stderr[:8192])
        data=json.loads((ROOT/'tools/tests/fixtures/shared-stop.json').read_text())
        for row in data['controller']:
            with self.subTest(case=row['name']):
                run=subprocess.run([str(binary),row['name']],capture_output=True,text=True,timeout=5,env=env,check=False)
                self.assertEqual(run.returncode,0,run.stderr[:1024]);self.assertEqual(run.stdout,'PASS\n');self.assertFalse(run.stderr)
