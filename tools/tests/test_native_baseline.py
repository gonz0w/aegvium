# SPDX-License-Identifier: BSD-3-Clause
"""Explicit baseline provenance and credential boundaries; no guest execution."""
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('baseline_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
ENGINE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ENGINE)
BASE = ENGINE.BASELINES


class BaselineTests(unittest.TestCase):
    def fixture(self, root):
        pin = json.loads((ENGINE.ROOT / 'research/native/official-image-pin.json').read_text())
        directory = root / '.tools/native/base-7.9-official'; directory.mkdir(parents=True)
        metadata = root / 'research/native'; metadata.mkdir(parents=True)
        (metadata / 'official-image-pin.json').write_text(json.dumps(pin))
        admission = {**pin, 'clean_halt_observed': True, 'installed_files_match': True, 'disk_independent': True}
        (directory / 'admission.json').write_text(json.dumps(admission))
        return pin, admission, directory

    def test_explicit_origins_missing_official_never_falls_back(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); legacy = {'qcow2_sha256': 'a'*64, 'assets': {'openbsd-7.9-host.id_rsa': {'sha256': 'b'*64}}}
            old = BASE.select(root, legacy)
            self.assertEqual(old['kind'], 'inherited-reference')
            with self.assertRaises(FileNotFoundError): BASE.select(root, legacy, True)
            pin, _, directory = self.fixture(root)
            selected = BASE.select(root, legacy, True)
            self.assertEqual(selected['image'], directory / 'base.qcow2')
            self.assertEqual(selected['image_sha256'], pin['image_sha256'])
            self.assertNotIn('bootstrap_private_sha256', selected)

    def test_stale_incomplete_and_nonregular_metadata_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); pin, admission, directory = self.fixture(root)
            for key, value in [('clean_halt_observed', False), ('installed_files_match', False),
                               ('disk_independent', False), ('image_sha256', '0'*64),
                               ('provision_source_commit', '0'*40), ('provision_run_id', 'wrong')]:
                (directory / 'admission.json').write_text(json.dumps({**admission, key: value}))
                with self.assertRaises(ValueError): BASE.select(root, {}, True)
            (directory / 'admission.json').write_text(json.dumps(admission))
            path = root / 'research/native/official-image-pin.json'
            for value in ([], {**pin, 'qualified_mode': 'all'}, {**pin, 'provision_run_id': 'wrong'},
                          {**pin, 'image_sha256': 4}, {**pin, 'extra': True}):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): BASE.select(root, {}, True)
            path.write_text(' ' * 16385)
            with self.assertRaises(ValueError): BASE.select(root, {}, True)
            path.unlink(); path.symlink_to(directory / 'admission.json')
            with self.assertRaises(ValueError): BASE.select(root, {}, True)

    def test_public_identity_permissions_links_and_command_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder).resolve() / 'key'; key.write_bytes(b'owned synthetic key'); key.chmod(0o600)
            public = b'ssh-ed25519 cHVibGlj\n'
            baseline = {'kind': 'authenticated-stock-install', 'bootstrap': key,
                        'bootstrap_public_sha256': hashlib.sha256(public).hexdigest()}
            with patch.object(BASE.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, public, b'')) as run:
                BASE.verify_bootstrap(baseline, None)
                self.assertEqual(run.call_args.args[0], ['ssh-keygen', '-y', '-f', str(key)])
                key.chmod(0o644)
                with self.assertRaises(ValueError): BASE.verify_bootstrap(baseline, None)
                key.chmod(0o600); os.link(key, Path(folder).resolve() / 'alias')
                with self.assertRaises(ValueError): BASE.verify_bootstrap(baseline, None)
            (Path(folder).resolve() / 'alias').unlink()
            for result in (subprocess.CompletedProcess([], 1, public, b''),
                           subprocess.CompletedProcess([], 0, b'ssh-rsa wrong', b''),
                           subprocess.CompletedProcess([], 0, b'ssh-ed25519 wrong', b'')):
                with patch.object(BASE.subprocess, 'run', return_value=result):
                    with self.assertRaises(ValueError): BASE.verify_bootstrap(baseline, None)
            with patch.object(BASE.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 15)):
                with self.assertRaises(subprocess.TimeoutExpired): BASE.verify_bootstrap(baseline, None)

    def test_unsupported_official_profiles_fail_before_preflight(self):
        for flags in ([], ['--lifecycle-source-build'], ['--source-build'], ['--lifecycle-components', '--relayd-config']):
            with self.subTest(flags=flags), patch.object(sys, 'argv', ['native-engine.py', '--official-baseline', *flags]), patch.object(ENGINE, 'git') as git, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): ENGINE.run()
                git.assert_not_called()
