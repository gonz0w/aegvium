# SPDX-License-Identifier: BSD-3-Clause
"""Fail closed on misleading guest results, auth failures and elapsed budgets."""
import importlib.util
import hashlib
import json
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class NativeEngineTests(unittest.TestCase):
    def valid(self):
        receipts = {'os': 'OpenBSD 7.9 amd64', 'uid': '32767', 'binary': 'a' * 64,
                    'kernel': 'GENERIC.MP native receipt', 'kernel_sha256': 'b' * 64,
                    'patches': ','.join(name.removeprefix('syspatch79-').removesuffix('.tgz')
                                       for name in LAB.PATCHES.PINS['assets'])}
        return '\n'.join([f'RECEIPT\t{k}\t{v}' for k, v in receipts.items()]
                         + [f'--- PASS: {name} (0.01s)' for name in sorted(LAB.EXPECTED | LAB.GROUPS)]
                         + ['    crs_corpus_test.go:1: CRS-INPUTS '+hashlib.sha256((LAB.ROOT / 'research/coraza/crs-inputs.json').read_bytes()).hexdigest()]
                         + [self.corpus_line(*key) for key in sorted(LAB.CORPUS_KEYS)]
                         + [self.body_line(*key) for key in sorted(LAB.BODY_KEYS)] + ['PASS'])

    def corpus_line(self, mode, role, kind):
        denied = kind != 'benign' and mode == 'On'
        rules = [] if kind == 'benign' else [942100 if kind == 'sql' else 941100]
        item = {'mode': mode, 'role': role, 'kind': kind, 'status': 403 if denied else 200,
                'backend': 0 if denied else 1, 'rules': rules, 'phases': [2] if rules else []}
        return '    crs_corpus_test.go:1: CRS-CORPUS ' + json.dumps(item)

    def test_crs_receipts_reject_false_enforcement_missing_matches_and_stale_vectors(self):
        original = self.valid()
        line = self.corpus_line('On', 'json', 'sql')
        item = json.loads(line.split('CRS-CORPUS ', 1)[1])
        for field, value in [('status', 200), ('backend', 1), ('backend', False), ('rules', []),
                             ('rules', [941100]), ('phases', [0]), ('phases', [True]), ('role', 'header')]:
            changed = {**item, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                LAB.parse_native(original.replace(line, '    crs_corpus_test.go:1: CRS-CORPUS '+json.dumps(changed)), 'a'*64)
        pin = hashlib.sha256((LAB.ROOT / 'research/coraza/crs-inputs.json').read_bytes()).hexdigest()
        for changed in (original.replace(line+'\n',''), original.replace(line,line+'\n'+line),
                        original.replace(pin,'0'*64), original.replace('    crs_corpus_test.go:1: CRS-INPUTS '+pin+'\n','')):
            with self.assertRaises(ValueError): LAB.parse_native(changed,'a'*64)

    def body_line(self, profile, name):
        gated = profile == 'gated'
        status, backend = LAB.BODY_CASES[name][int(gated)]
        rules = [942100] if name == 'form-sql' else [941100] if name == 'json-script' else [200002] if name == 'invalid-json' else []
        read = 129 if name in ('unknown-over', 'understated-over') else 16 if name == 'partial-read-error' else 0
        item = {'profile': profile, 'case': name, 'status': status, 'backend': backend,
                'read': read, 'closed': int(gated), 'rules': rules, 'phases': [2] if rules else []}
        return '    body_admission_test.go:1: BODY-ADMISSION '+json.dumps(item)

    def test_body_receipts_reject_false_limits_forwarding_and_ownership(self):
        original = self.valid()
        line = self.body_line('gated', 'unknown-over')
        item = json.loads(line.split('BODY-ADMISSION ', 1)[1])
        for field, value in [('status', 200), ('backend', 1), ('read', 130), ('read', 0), ('closed', 0), ('closed', True), ('rules', [942100]), ('case', 'unknown')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                LAB.parse_native(original.replace(line, '    body_admission_test.go:1: BODY-ADMISSION '+json.dumps({**item,field:value})), 'a'*64)
        for changed in (original.replace(line+'\n',''), original.replace(line,line+'\n'+line)):
            with self.assertRaises(ValueError): LAB.parse_native(changed,'a'*64)

    def test_complete_native_receipts_and_cases(self):
        self.assertEqual(LAB.parse_native(self.valid(), 'a' * 64)['case_count'], 148)

    def test_missing_duplicate_skipped_unknown_and_root_results_rejected(self):
        original = self.valid()
        for changed in (
            original.replace('--- PASS: TestBodyReadFailure (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyV1Rejected/overlong (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyV1TCP/timeout (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyV1Listener/close-undelivered (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyV1ListenerTCP/bare-head (0.01s)\n', ''),
            original.replace('--- PASS: TestReadyCheckerTCP/transitions (0.01s)\n', ''),
            original.replace('--- PASS: TestReadyProbe/oversized (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyReady/close (0.01s)\n', ''),
            original.replace('--- PASS: TestProxyReadyTCP/accept-failure (0.01s)\n', ''),
            original.replace('--- PASS: TestExplicitInspectionError/partial-read-error (0.01s)\n', ''),
            original.replace('\nPASS', '\n--- PASS: TestBodyReadFailure (0.01s)\nPASS'),
            original.replace('\nPASS', '\n--- SKIP: future (0.00s)\nPASS'),
            original.replace('\nPASS', '\n--- FAIL: future (0.00s)\nPASS'),
            original.replace('\nPASS', '\n--- PASS: unknown (0.00s)\nPASS'),
            original.replace('uid\t32767', 'uid\t0'),
            original.replace('os\tOpenBSD 7.9 amd64', 'os\tOpenBSD 7.8 amd64'),
            original.replace('binary\t' + 'a' * 64, 'binary\t' + 'c' * 64),
            original.replace('kernel_sha256\t' + 'b' * 64, 'kernel_sha256\tinvalid'),
            original + '\nRECEIPT\tuid\t32767',
        ):
            with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                LAB.parse_native(changed, 'a' * 64)

    def test_connection_failure_is_not_key_revocation(self):
        for code, error in ((255, b'Connection refused'), (0, b''), (1, b'Permission denied (publickey)')):
            with self.assertRaises(RuntimeError):
                LAB.verify_rejection(subprocess.CompletedProcess([], code, b'', error))
        LAB.verify_rejection(subprocess.CompletedProcess([], 255, b'', b'Permission denied (publickey).'))

    def test_expired_budget_never_launches_ssh(self):
        guest = LAB.Guest(Path('/unused'), time.monotonic() - 1)
        with patch.object(LAB.subprocess, 'run') as run, self.assertRaises(TimeoutError):
            guest.call('true')
        run.assert_not_called()

    def test_ssh_call_is_clamped_and_endpoint_is_fixed(self):
        guest = LAB.Guest(Path('/private/config'), time.monotonic() + 2)
        with patch.object(LAB.subprocess, 'run') as run:
            guest.call('true', seconds=600)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ['ssh', '-F', '/private/config', 'fixture', 'true'])
        self.assertLessEqual(run.call_args.kwargs['timeout'], 2)

    def test_restricted_loopback_only_qemu_profile(self):
        argv = LAB.qemu_command(Path('/owned/base'), 12345, Path('/owned/run'))
        network = argv[argv.index('-netdev') + 1]
        self.assertIn('restrict=on', network)
        self.assertIn('hostfwd=tcp:127.0.0.1:12345-192.168.122.254:22', network)
        self.assertIn('-snapshot', argv)
        self.assertNotIn('-virtfs', argv)
