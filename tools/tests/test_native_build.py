# SPDX-License-Identifier: BSD-3-Clause
import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD = load('native-build')
LAB = load('native-engine')


class NativeBuildTests(unittest.TestCase):
    def test_compiler_corruption_size_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder).resolve()
            asset = cache / 'go-openbsd-amd64.tar.gz'
            original = b'compiler fixture'
            pin = {'size': len(original), 'sha256': hashlib.sha256(original).hexdigest()}
            asset.write_bytes(original)
            with patch.object(BUILD, 'CACHE', cache), patch.object(BUILD, 'compiler_pin', return_value=pin):
                BUILD.compiler()
                asset.write_bytes(b'x' * len(original))
                with self.assertRaises(ValueError): BUILD.compiler()
                asset.write_bytes(b'x')
                with self.assertRaises(ValueError): BUILD.compiler()
                asset.unlink()
                (cache / 'target').write_bytes(original)
                asset.symlink_to(cache / 'target')
                with self.assertRaises(ValueError): BUILD.compiler()

    def test_native_build_receipts_fail_closed(self):
        valid = '\n'.join(('BUILD\tuid\t32767', 'BUILD\tcompiler\t' + 'a' * 64,
                           'BUILD\tsource\t' + 'b' * 64, 'BUILD\tbinary\t' + 'c' * 64, 'BUILD\tchecker\t' + 'e' * 64))
        self.assertEqual(LAB.parse_build(valid, 'b' * 64)['uid'], '32767')
        for text in (valid.replace('32767', '0'), valid + '\nBUILD\tuid\t32767',
                     valid.replace('c' * 64, 'oops'), valid.replace('binary', 'unknown'),
                     valid.replace('b' * 64, 'd' * 64), valid.replace('e' * 64, 'oops'),
                     valid.replace('BUILD\tchecker\t' + 'e' * 64, ''), valid + '\nBUILD\tchecker\t' + 'e' * 64):
            with self.assertRaises(ValueError): LAB.parse_build(text, 'b' * 64)

    def test_transfer_or_compile_failure_never_reaches_test(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            asset = work / 'asset'
            asset.write_bytes(b'fixture')
            inputs = {'compiler': asset, 'source': asset,
                      'compiler_sha256': 'a' * 64, 'source_sha256': 'b' * 64}
            for codes in ((1,), (0, 0, 1)):
                class Guest:
                    def __init__(self): self.codes = iter(codes); self.commands = []
                    def require(self, command): self.commands.append(command)
                    def call(self, command, **kwargs):
                        self.commands.append(command)
                        return subprocess.CompletedProcess([], next(self.codes))
                guest = Guest()
                with self.assertRaises(RuntimeError): LAB.source_build_guest(guest, work, inputs)
                self.assertFalse(any('/var/aegvium-lab' in command for command in guest.commands))

    def test_native_checker_install_uses_build_receipt_and_rejects_legacy_output(self):
        valid = '\n'.join(('BUILD\tuid\t32767', 'BUILD\tcompiler\t' + 'a'*64,
                           'BUILD\tsource\t' + 'b'*64, 'BUILD\tbinary\t' + 'c'*64,
                           'BUILD\tchecker\t' + 'e'*64))
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            asset = work / 'asset'; asset.write_bytes(b'fixture')
            inputs = {'compiler': asset, 'source': asset, 'compiler_sha256': 'a'*64, 'source_sha256': 'b'*64}
            for complete in (True, False):
                class Guest:
                    def __init__(self): self.commands = []; self.count = 0
                    def require(self, command): self.commands.append(command)
                    def call(self, command, **kwargs):
                        self.commands.append(command); self.count += 1
                        if self.count == 3:
                            kwargs['output'].write((valid if complete else valid.rsplit('\n', 1)[0]).encode())
                        return subprocess.CompletedProcess([], 0)
                guest = Guest()
                with patch.object(LAB, 'parse_native', return_value={'receipts': {'binary': 'c'*64, 'uid': '32767'}}):
                    if complete:
                        result = LAB.source_build_guest(guest, work, inputs)
                        self.assertEqual(result['build_receipts']['checker'], 'e'*64)
                        install = next(c for c in guest.commands if 'cp /var/aegvium-build/output/readycheck' in c)
                        self.assertIn('sha256 -q /var/aegvium-lab-readycheck', install)
                        self.assertIn('e'*64, install)
                        self.assertEqual(guest.count, 4)
                        with patch.object(LAB, 'parse_native', return_value={'receipts': {'binary': 'c'*64, 'uid': '89'}}):
                            with self.assertRaisesRegex(ValueError, 'UID mismatch'):
                                LAB.source_build_guest(Guest(), work, inputs)
                    else:
                        with self.assertRaises(ValueError): LAB.source_build_guest(guest, work, inputs)
                        self.assertFalse(any('cp /var/aegvium-build/output/readycheck' in c for c in guest.commands))

    def test_fetch_preserves_unowned_staging_file(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder).resolve()
            stage = cache / 'go.download'
            stage.write_bytes(b'owned elsewhere')
            with patch.object(BUILD, 'CACHE', cache), self.assertRaises(FileExistsError):
                BUILD.fetch()
            self.assertEqual(stage.read_bytes(), b'owned elsewhere')
