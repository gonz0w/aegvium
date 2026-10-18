# SPDX-License-Identifier: BSD-3-Clause
"""Owned file/command controls for fixed release input authentication."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('official_media', Path(__file__).resolve().parents[1] / 'official-media.py')
MEDIA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEDIA)


class OfficialMediaTests(unittest.TestCase):
    def fixture(self, root):
        pins = copy.deepcopy(MEDIA.PINS)
        verifier = root / 'verifier'; verifier.write_bytes(b'owned executable fixture')
        pins['verifier']['executable_sha256'] = hashlib.sha256(verifier.read_bytes()).hexdigest()
        for name, pin in pins['assets'].items():
            data = name.encode(); (root / name).write_bytes(data)
            pin['sha256'] = hashlib.sha256(data).hexdigest()
            if 'size' in pin: pin['size'] = len(data)
        return verifier, pins

    def test_real_verifier_command_and_complete_result_are_both_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); verifier, pins = self.fixture(root)
            for code, output in ((0, b'Signature Verified\ninstall79.iso: OK\n'),
                                 (1, b'Signature Verified\ninstall79.iso: OK\n'),
                                 (0, b'install79.iso: OK\n'), (0, b'Signature Verified\n'),
                                 (0, b'Signature Verified\nother.iso: OK\n')):
                with self.subTest(code=code, output_hash=hashlib.sha256(output).hexdigest()), patch.object(MEDIA, 'PINS', pins), patch.object(MEDIA.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, output)) as command:
                    if code == 0 and output == b'Signature Verified\ninstall79.iso: OK\n':
                        receipt = MEDIA.verify(root, verifier)
                        self.assertTrue(receipt['signature_verified'])
                        self.assertEqual(receipt['assets_sha256'], {n: p['sha256'] for n, p in pins['assets'].items()})
                    else:
                        with self.assertRaises(ValueError): MEDIA.verify(root, verifier)
                    self.assertEqual(command.call_args.args[0], [str(verifier), '-C', '-p', 'openbsd-79-base.pub', '-x', 'SHA256.sig', 'install79.iso'])
                    self.assertEqual(command.call_args.kwargs['timeout'], 60)
                    self.assertEqual(command.call_args.kwargs['cwd'], root)

    def test_input_drift_and_nonregular_files_prevent_verifier_execution(self):
        for name in ('verifier', 'openbsd-79-base.pub', 'SHA256.sig', 'install79.iso'):
            for kind in ('changed', 'missing', 'symlink', 'directory'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder).resolve(); verifier, pins = self.fixture(root)
                    path = root / name; data = path.read_bytes(); path.unlink()
                    if kind == 'changed': path.write_bytes(b'changed owned data')
                    elif kind == 'symlink':
                        target = root / 'target'; target.write_bytes(data); path.symlink_to(target)
                    elif kind == 'directory': path.mkdir()
                    with patch.object(MEDIA, 'PINS', pins), patch.object(MEDIA.subprocess, 'run') as command:
                        with self.assertRaises((ValueError, OSError)): MEDIA.verify(root, verifier)
                        command.assert_not_called()

    def test_verifier_timeout_or_io_failure_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); verifier, pins = self.fixture(root)
            for error in (OSError('owned failure'), subprocess.TimeoutExpired(['owned verifier'], 60)):
                with patch.object(MEDIA, 'PINS', pins), patch.object(MEDIA.subprocess, 'run', side_effect=error):
                    with self.assertRaises(type(error)): MEDIA.verify(root, verifier)
                self.assertFalse((root / 'verification.json').exists())

    def test_input_change_during_verifier_prevents_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); verifier, pins = self.fixture(root)
            def verify(*args, **kwargs):
                (root / 'install79.iso').write_bytes(b'changed owned input')
                return subprocess.CompletedProcess([], 0, b'Signature Verified\ninstall79.iso: OK\n')
            with patch.object(MEDIA, 'PINS', pins), patch.object(MEDIA.subprocess, 'run', side_effect=verify):
                with self.assertRaises(ValueError): MEDIA.verify(root, verifier)
