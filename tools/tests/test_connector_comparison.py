# SPDX-License-Identifier: BSD-3-Clause
"""Reject incomplete or forged native connector comparisons."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('connector_comparison', Path(__file__).resolve().parents[1] / 'connector-comparison.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ConnectorAdmissionTests(unittest.TestCase):
    def rows(self):
        rows = copy.deepcopy(C.expected_wire())
        for profile in C.PROFILES:
            rows.append({'profile': profile, 'cleanup': 'verified'})
            rows.append({'profile': profile, 'phase': 'invalid-rejected'})
            for phase in C.PHASES:
                old = phase in ('initial', 'rollback') or profile == 'caddy' and phase in ('same-configuration', 'known-good')
                for case in ('old', 'new'):
                    rows.append({'profile': profile, 'phase': phase, 'case': case, 'status': 403 if (case == 'old') == old else 200})
        return rows

    def log(self, rows):
        return '\n'.join(['comparison_test.go:1: CONNECTOR ' + json.dumps(r) for r in rows] +
                         ['--- PASS: ' + p + ' (0.01s)' for p in sorted(C.expected_passes())] +
                         ['PASS', 'COMPARISON\tbinary\t' + 'a' * 64, 'COMPARISON\tuid\t32767',
                          'COMPARISON\tos\tOpenBSD 7.9 amd64', 'COMPARISON\tcleanup\tverified', ''])

    def test_complete_comparison(self):
        result = C.admit(self.log(self.rows()), 'a' * 64)
        self.assertEqual((result['wire_count'], result['reload_count'], result['go_pass_count']), (40, 22, 46))

    def test_rejects_changed_inputs_effects_errors_and_source_ownership(self):
        for key, value in [('backend', 0), ('backend', True), ('status', 403), ('input_sha256', '0' * 64),
                           ('body_sha256', '0' * 64), ('response_sha256', '0' * 64), ('source_closed', 0),
                           ('host', 'other.test'), ('spoof_preserved', True), ('unexpected', 1)]:
            rows = self.rows()
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.admit(self.log(rows), 'a' * 64)
        rows = self.rows()
        next(r for r in rows if r.get('profile') == 'caddy' and r.get('phase') == 'same-configuration' and r.get('case') == 'new')['status'] = 403
        with self.assertRaises(ValueError):
            C.admit(self.log(rows), 'a' * 64)

    def test_rejects_missing_duplicate_skipped_failed_and_root_execution(self):
        text = self.log(self.rows())
        for bad in [self.log(self.rows()[:-1]), self.log(self.rows() + [self.rows()[0]]),
                    text.replace('COMPARISON\tuid\t32767', 'COMPARISON\tuid\t0'),
                    text.replace('COMPARISON\tcleanup\tverified', 'COMPARISON\tcleanup\tfailed'),
                    text.replace('--- PASS:', '--- SKIP:', 1), text.replace('--- PASS:', '--- FAIL:', 1),
                    text.replace('PASS\nCOMPARISON', 'COMPARISON'), text + '\n[ERROR] waf cleanup: failed',
                    text.replace('COMPARISON\tbinary\t' + 'a' * 64, 'COMPARISON\tbinary\t' + 'b' * 64)]:
            with self.assertRaises(ValueError):
                C.admit(bad, 'a' * 64)
