# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('native_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class RelaydTrafficTests(unittest.TestCase):
    def valid(self):
        receipts = {'relayd': 'a' * 64, 'profile': 'b' * 64, 'binary': 'c' * 64,
                    'uid': '32767', 'cleanup': 'verified', 'daemon-log': 'd' * 64}
        return '\n'.join([f'TRAFFIC\t{k}\t{v}' for k, v in receipts.items()]
                         + [f'--- PASS: {name} (0.01s)' for name in sorted(LAB.TRAFFIC_CASES | {'TestRelaydTraffic'})]
                         + ['PASS'])

    def test_incomplete_failed_skipped_root_and_unverified_traffic_rejected(self):
        original = self.valid()
        self.assertEqual(LAB.parse_traffic(original, 'c' * 64, 'b' * 64, 'a' * 64)['case_count'], 34)
        for changed in (
            original.replace('--- PASS: TestRelaydTraffic/inspection-loss (0.01s)\n', ''),
            original.replace('--- PASS: TestRelaydTraffic/relayd-mixed-framing-attack (0.01s)\n', ''),
            original.replace('--- PASS: TestRelaydTraffic/relayd-serialized-denied-benign (0.01s)\n', ''),
            original.replace('--- PASS: TestRelaydTraffic/relayd-longidle-pipeline-benign-benign (0.01s)\n', ''),
            original.replace('--- PASS: TestRelaydTraffic/relayd-wake-pipeline-benign-benign (0.01s)\n', ''),
            original + '\n--- PASS: TestRelaydTraffic/recovery (0.01s)',
            original + '\n--- SKIP: TestRelaydTraffic (0.01s)',
            original + '\n--- FAIL: TestRelaydTraffic (0.01s)',
            original + '\n--- PASS: unknown (0.01s)',
            original.replace('uid\t32767', 'uid\t0'),
            original.replace('cleanup\tverified', 'cleanup\tassumed'),
            original.replace('c' * 64, 'e' * 64), original.replace('a' * 64, 'e' * 64),
            original.replace('b' * 64, 'e' * 64), original.replace('d' * 64, 'oops'),
            original + '\nTRAFFIC\tuid\t32767', original.removesuffix('PASS'), original + '\nPASS',
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                LAB.parse_traffic(changed, 'c' * 64, 'b' * 64, 'a' * 64)

    def test_failed_native_command_never_admitted(self):
        class Guest:
            def require(self, *args, **kwargs): pass
            def call(self, *args, **kwargs): return subprocess.CompletedProcess([], 1)
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(RuntimeError):
            LAB.relayd_traffic_guest(Guest(), Path(folder), 'c' * 64, 'a' * 64)

    def test_traffic_profile_matches_reviewed_syntax_except_mode_comment(self):
        syntax = (LAB.ROOT / 'research/relayd/ingress.conf').read_text()
        traffic = (LAB.ROOT / 'research/relayd/traffic.conf').read_text()
        self.assertEqual(traffic, syntax.replace('# Syntax-only research fixture; no daemon is started.',
                                                '# Foreground traffic research fixture; owned disposable guest only.'))
