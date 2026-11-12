# SPDX-License-Identifier: BSD-3-Clause
"""Tiny offline limits; never allocate a real image or purge cache data."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('storage_preflight', Path(__file__).resolve().parents[1] / 'storage_preflight.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StoragePreflight(unittest.TestCase):
    def check(self, used, free, image=False):
        with tempfile.TemporaryDirectory() as td, patch.object(module._guard, 'allocated_bytes', return_value=used), patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=free, total=2_000_000_000_000)):
            return module.preflight([Path(td)], image, 80_000_000_000 if image else None, 20_000_000_000 if image else None)

    def test_ordinary_peak_counts(self):
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.check(19_000_000_000, 500_000_000_000)

    def test_reserve_after_peak(self):
        with self.assertRaisesRegex(ValueError, 'reserve'):
            self.check(0, 201_000_000_000)

    def test_exact_ordinary_boundary(self):
        self.check(18_000_000_000, 202_000_000_000)

    def test_image_boundary(self):
        self.check(60_000_000_000, 220_000_000_000, True)
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.check(61_000_000_000, 500_000_000_000, True)

    def test_missing_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(OSError):
                module.preflight([Path(td) / 'absent'])

    def test_git_artifact_policy(self):
        self.assertIsNotNone(module._guard.blob_problem('test.img', 1, 100, set()))
        self.assertIsNotNone(module._guard.blob_problem('evidence.bin', 101, 100, set()))
        self.assertIsNone(module._guard.blob_problem('source.go', 100, 100, set()))

    def test_image_requires_explicit_profile(self):
        with tempfile.TemporaryDirectory() as td, patch.object(module._guard, 'allocated_bytes', return_value=0), patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=500_000_000_000, total=2_000_000_000_000)):
            with self.assertRaisesRegex(ValueError, 'explicit reviewed'):
                module.preflight([Path(td)], True)

    def test_small_filesystem_reserve_scales(self):
        with tempfile.TemporaryDirectory() as td, patch.object(module._guard, 'allocated_bytes', return_value=0), patch.object(module.shutil, 'disk_usage', return_value=SimpleNamespace(free=6_000_000_000, total=40_000_000_000)):
            module.preflight([Path(td)])
