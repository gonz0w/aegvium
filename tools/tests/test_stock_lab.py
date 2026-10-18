# SPDX-License-Identifier: BSD-3-Clause
"""Prelaunch ownership refusals; no guest starts in host tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location('stock_lab', Path(__file__).resolve().parents[1] / 'stock-lab.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class StockLabTests(unittest.TestCase):
    def test_dirty_source_or_unowned_media_never_creates_or_launches(self):
        with patch.object(LAB.subprocess, 'Popen') as launch, patch.object(LAB.MEDIA, 'verify') as verify:
            with patch.object(LAB, 'git', return_value='changed'):
                with self.assertRaises(ValueError): LAB.create(Path('/unused'))
            with patch.object(LAB, 'git', return_value=''):
                with self.assertRaises(ValueError): LAB.create(Path('/unused'))
            verify.assert_not_called(); launch.assert_not_called()

    def test_wrong_virtual_disk_or_backing_chain_prevents_guest_launch(self):
        for info in ({'format': 'raw', 'virtual-size': 8 * 1024**3},
                     {'format': 'qcow2', 'virtual-size': 1024},
                     {'format': 'qcow2', 'virtual-size': 8 * 1024**3, 'backing-filename': 'unowned'}):
            with self.subTest(info=info), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve(); media = root / '.tools/official-media' / str(uuid.uuid4())
                with patch.object(LAB, 'ROOT', root), patch.object(LAB, 'git', return_value=''), patch.object(LAB.MEDIA, 'verify', return_value={}), patch.object(LAB.subprocess, 'run'), patch.object(LAB.subprocess, 'check_output', return_value=json.dumps(info)), patch.object(LAB.subprocess, 'Popen') as launch:
                    with self.assertRaises(ValueError): LAB.create(media)
                    launch.assert_not_called()
                created = list((root / '.tools/native-stock').glob('*/disk.qcow2'))
                self.assertEqual(len(created), 1)
                self.assertEqual(created[0].stat().st_nlink, 1)
                self.assertEqual(created[0].stat().st_mode & 0o777, 0o600)
