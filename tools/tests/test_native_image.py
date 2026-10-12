# SPDX-License-Identifier: BSD-3-Clause
import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('native_image', Path(__file__).resolve().parents[1] / 'native-image.py')
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)


class ImageAdmissionTests(unittest.TestCase):
    def test_matching_bytes_private_copy_and_preserved_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            source, output = root / 'source', root / 'output'
            source.write_bytes(b'fixture-image')
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(IMAGE.copy_verified(source, output, expected), expected)
            self.assertEqual(source.read_bytes(), output.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o400)

    def test_digest_failure_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            source, output = root / 'source', root / 'output'
            source.write_bytes(b'changed-image')
            with self.assertRaises(ValueError):
                IMAGE.copy_verified(source, output, '0' * 64)
            self.assertFalse(output.exists())

    def test_existing_output_is_never_removed_or_overwritten(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            source, output = root / 'source', root / 'output'
            source.write_bytes(b'new')
            output.write_bytes(b'owned-elsewhere')
            with self.assertRaises(FileExistsError):
                IMAGE.copy_verified(source, output, '0' * 64)
            self.assertEqual(output.read_bytes(), b'owned-elsewhere')

    def test_symlink_asset_and_parent_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            source = root / 'source'
            source.write_bytes(b'image')
            link = root / 'link'
            link.symlink_to(source)
            parent = root / 'parent'
            parent.symlink_to(root, target_is_directory=True)
            for path in (link, parent / 'source'):
                with self.assertRaises(ValueError):
                    IMAGE.regular_fd(path)

    def test_fifo_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as name:
            fifo = Path(name).resolve() / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                IMAGE.regular_fd(fifo)
