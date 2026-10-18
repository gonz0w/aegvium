# SPDX-License-Identifier: BSD-3-Clause
"""Reject patch provenance drift before any native installation."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('patches', TOOLS / 'openbsd-patches.py')
PATCHES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCHES)


class PatchTests(unittest.TestCase):
    def test_native_trust_pins_match_host_reviewed_manifest(self):
        script = (TOOLS / 'native/patch-openbsd.sh').read_text()
        for value in (PATCHES.PINS['manifest_sha256'], PATCHES.PINS['public_key_sha256']):
            self.assertIn(value, script)
        numbers = [name.split('-')[1].split('_')[0] for name in PATCHES.PINS['assets']]
        self.assertEqual(numbers, [f'{number:03d}' for number in range(1, 35)])

    def test_manifest_rejects_path_escape_duplicate_and_malformed_hash(self):
        entry = 'SHA256 (syspatch79-001_fixture.tgz) = ' + 'a' * 64
        header = 'untrusted comment: fixture\nsignature\n'
        self.assertEqual(PATCHES.parse_manifest(header + entry),
                         {'syspatch79-001_fixture.tgz': 'a' * 64})
        for body in (entry + '\n' + entry, entry.replace('syspatch79-', '../'),
                     entry.replace('a' * 64, 'oops'), ''):
            with self.assertRaises(ValueError):
                PATCHES.parse_manifest(header + body)

    def test_modified_or_symlinked_patches_cannot_be_transferred(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary).resolve()
            package = b'fixture archive'
            checksum = hashlib.sha256(package).hexdigest()
            name = 'syspatch79-001_fixture.tgz'
            signature = ('untrusted comment: fixture\nsignature\n'
                         f'SHA256 ({name}) = {checksum}\n').encode()
            key = b'public fixture key'
            pins = {'assets': {name: checksum},
                    'manifest_sha256': hashlib.sha256(signature).hexdigest(),
                    'public_key_sha256': hashlib.sha256(key).hexdigest()}
            (cache / name).write_bytes(package)
            (cache / 'SHA256.sig').write_bytes(signature)
            (cache / 'openbsd-79-syspatch.pub').write_bytes(key)
            with patch.object(PATCHES, 'PINS', pins):
                PATCHES.verify(cache)
                (cache / name).write_bytes(b'tampered')
                with self.assertRaises(ValueError):
                    PATCHES.verify(cache)
                (cache / name).unlink()
                (cache / 'target').write_bytes(package)
                (cache / name).symlink_to(cache / 'target')
                with self.assertRaises(ValueError):
                    PATCHES.verify(cache)

    def test_legacy_script_is_byte_identical_without_stock_applicability(self):
        with patch.object(PATCHES, 'stock_applicability') as stock:
            script, result = PATCHES.guest_script()
            self.assertEqual(script, (TOOLS / 'native/patch-openbsd.sh').read_bytes())
            self.assertIsNone(result); stock.assert_not_called()

    def stock_fixture(self, cache, kind='valid'):
        import copy, io, tarfile
        pins = copy.deepcopy(PATCHES.PINS)
        for name in PATCHES.STOCK_INAPPLICABLE:
            path = cache / ('syspatch79-' + name + '.tgz')
            with tarfile.open(path, 'w:gz') as archive:
                target = ('usr/X11R6/bin/fixture' if kind == 'valid' else
                          'usr/X11R6/../escape' if kind == 'traversal' else
                          'usr/sbin/ordinary' if kind == 'foreign' else 'usr/X11R6/bin/fixture')
                member = tarfile.TarInfo(target); member.size = 1
                if kind == 'link': member.type = tarfile.SYMTYPE; member.linkname = 'fixture'; member.size = 0
                archive.addfile(member, io.BytesIO(b'x') if member.isfile() else None)
                if kind != 'missing-signature':
                    member = tarfile.TarInfo('var/syspatch/79-' + name + '/' + name + '.patch.sig');member.size = 1
                    archive.addfile(member, io.BytesIO(b'x'))
            pins['assets'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return pins

    def test_stock_exact_cohort_retains_full_authentication_and_absence_gates(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder).resolve(); pins = self.stock_fixture(cache)
            with patch.object(PATCHES, 'PINS', pins): script, result = PATCHES.guest_script(True, cache)
            self.assertEqual(result['inapplicable'], list(PATCHES.STOCK_INAPPLICABLE))
            self.assertEqual(result['target_count'], 6)
            self.assertIn(b'cd "$mirror" && sha256 -c SHA256', script)
            self.assertIn(b'PATCH\\tinstalled\\t31', script)
            self.assertIn(b'PATCH\\tinapplicable\\t3', script)
            self.assertIn(b'cmp -s /var/aegvium-lab-patches-expected /var/aegvium-lab-patches-installed', script)
            self.assertEqual(script.count(b'[ ! -e /usr/X11R6 ] && [ ! -L /usr/X11R6 ]'), 2)
            for name in PATCHES.STOCK_INAPPLICABLE:
                self.assertEqual(script.count(('[ ! -e /var/syspatch/79-' + name + ' ]').encode()), 2)
            expected = [n.removeprefix('syspatch79-').removesuffix('.tgz') for n in pins['assets']
                        if not any(n == 'syspatch79-' + skip + '.tgz' for skip in PATCHES.STOCK_INAPPLICABLE)]
            self.assertEqual(len(expected), 31)
            self.assertIn((' '.join(expected) + ' > /var/aegvium-lab-patches-expected').encode(), script)

    def test_stock_unreviewed_targets_or_drift_never_render(self):
        for kind in ('foreign', 'traversal', 'link', 'missing-signature', 'drift'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                cache = Path(folder).resolve(); pins = self.stock_fixture(cache, kind if kind != 'drift' else 'valid')
                if kind == 'drift': (cache / 'syspatch79-001_xserver.tgz').write_bytes(b'changed')
                with patch.object(PATCHES, 'PINS', pins):
                    with self.assertRaises(ValueError): PATCHES.guest_script(True, cache)
