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
