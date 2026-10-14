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

    def test_native_program_receipt_and_install_required_without_fallback(self):
        valid='\n'.join(('BUILD\tuid\t32767','BUILD\tcompiler\t'+'a'*64,'BUILD\tsource\t'+'b'*64,'BUILD\tbinary\t'+'c'*64,'BUILD\tchecker\t'+'e'*64,'BUILD\tprogram\t'+'f'*64))
        self.assertEqual(LAB.parse_build(valid,'b'*64,program=True)['program'],'f'*64)
        for bad in (valid.rsplit('\n',1)[0],valid.replace('f'*64,'oops'),valid+'\nBUILD\tprogram\t'+'f'*64):
            with self.assertRaises(ValueError):LAB.parse_build(bad,'b'*64,program=True)
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder).resolve();asset=work/'asset';asset.write_bytes(b'fixture')
            inputs={'compiler':asset,'source':asset,'compiler_sha256':'a'*64,'source_sha256':'b'*64}
            class Guest:
                def __init__(self):self.commands=[];self.count=0
                def require(self,command):self.commands.append(command)
                def call(self,command,**kwargs):
                    self.commands.append(command);self.count+=1
                    if self.count==3:kwargs['output'].write(valid.encode())
                    return subprocess.CompletedProcess([],0)
            guest=Guest()
            with patch.object(LAB,'parse_native',return_value={'receipts':{'binary':'c'*64,'uid':'32767'}}):result=LAB.source_build_guest(guest,work,inputs,program=True)
            self.assertEqual(result['build_receipts']['program'],'f'*64)
            install=next(c for c in guest.commands if 'cp /var/aegvium-build/output/labproxy' in c)
            self.assertIn('sha256 -q /var/aegvium-lab-proxy',install);self.assertIn('f'*64,install)

    def test_connector_receipts_bind_source_compiler_target_and_identity(self):
        valid = '\n'.join(('CBUILD\tos\tOpenBSD 7.9 amd64', 'CBUILD\tversion\tgo1.27.2',
                           'CBUILD\tcompiler\t'+'a'*64, 'CBUILD\tsource\t'+'b'*64,
                           'CBUILD\tuid\t32767', 'CBUILD\tbinary\t'+'c'*64))
        self.assertEqual(LAB.parse_connector_build(valid, 'b'*64, 'a'*64)['binary'], 'c'*64)
        for bad in (valid.replace('32767','0'),valid.replace('32767','88'),valid.replace('amd64','arm64'),
                    valid.replace('go1.27.2','go1.27.0'),valid.replace('a'*64,'d'*64),valid.replace('b'*64,'d'*64),
                    valid.replace('c'*64,'oops'),valid.rsplit('\n',1)[0],valid+'\nCBUILD\tuid\t32767'):
            with self.assertRaises(ValueError):LAB.parse_connector_build(bad,'b'*64,'a'*64)

    def test_connector_transfer_compile_and_missing_output_fail_before_install(self):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder).resolve();asset=work/'asset';asset.write_bytes(b'fixture')
            inputs={'compiler':asset,'source':asset,'compiler_sha256':'a'*64,'source_sha256':'b'*64,'compiler_executable_sha256':'a'*64}
            for codes in ((1,), (0,0,1), (0,0,0)):
                class Guest:
                    def __init__(self):self.commands=[];self.codes=iter(codes)
                    def require(self,c,**kw):self.commands.append(c)
                    def call(self,c,**kw):self.commands.append(c);return subprocess.CompletedProcess([],next(self.codes))
                guest=Guest()
                with self.assertRaises((ValueError,RuntimeError)):LAB.connector_build_guest(guest,work,inputs)
                self.assertFalse(any('cp /var/' in c for c in guest.commands))

    def test_connector_install_uses_only_admitted_native_output(self):
        valid='\n'.join(('CBUILD\tos\tOpenBSD 7.9 amd64','CBUILD\tversion\tgo1.27.2','CBUILD\tcompiler\t'+'a'*64,'CBUILD\tsource\t'+'b'*64,'CBUILD\tuid\t32767','CBUILD\tbinary\t'+'c'*64))
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder).resolve();asset=work/'asset';asset.write_bytes(b'fixture')
            inputs={'compiler':asset,'source':asset,'compiler_sha256':'a'*64,'source_sha256':'b'*64,'compiler_executable_sha256':'a'*64}
            class Guest:
                def __init__(self):self.commands=[];self.calls=0
                def require(self,c,**kw):self.commands.append(c)
                def call(self,c,**kw):
                    self.commands.append(c);self.calls+=1
                    if self.calls==3:kw['output'].write(valid.encode())
                    return subprocess.CompletedProcess([],0)
            guest=Guest();result=LAB.connector_build_guest(guest,work,inputs)
            self.assertTrue(result['installed_verified']);self.assertEqual(result['receipts']['binary'],'c'*64)
            self.assertIn('seconds',result)
            install=next(c for c in guest.commands if 'cp /var/' in c)
            self.assertIn('/var/aegvium-connector-build/output/compare.test',install)
            self.assertIn('sha256 -q /var/aegvium-connector/compare.test',install);self.assertIn('c'*64,install)

    def test_source_archive_manifest_rejects_changed_missing_duplicate_and_link_members(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as folder:
            bundle=Path(folder)/'source.tar.gz'
            manifest={'go.mod':hashlib.sha256(b'fixture').hexdigest()}
            for mode in ('valid','changed','missing','duplicate','symlink','outside'):
                with tarfile.open(bundle,'w:gz') as archive:
                    if mode!='missing':
                        item=tarfile.TarInfo('src/go.mod' if mode!='outside' else '../go.mod')
                        if mode=='symlink':item.type=tarfile.SYMTYPE;item.linkname='/tmp/other';archive.addfile(item)
                        else:
                            data=b'bad' if mode=='changed' else b'fixture';item.size=len(data);archive.addfile(item,io.BytesIO(data))
                            if mode=='duplicate':archive.addfile(item,io.BytesIO(data))
                if mode=='valid':BUILD.verify_source_bundle(bundle,manifest)
                else:
                    with self.subTest(mode=mode),self.assertRaises(ValueError):BUILD.verify_source_bundle(bundle,manifest)
