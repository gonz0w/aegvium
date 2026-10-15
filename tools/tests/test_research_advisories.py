# SPDX-License-Identifier: BSD-3-Clause
"""Incomplete scans and newly reachable findings must never look clean."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile
import subprocess

SPEC = importlib.util.spec_from_file_location('research_advisories', Path(__file__).resolve().parents[1] / 'research-advisories.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


class AdvisoryTests(unittest.TestCase):
    expected = {'example.test/research': '', 'example.test/dependency': 'v1.2.3', 'stdlib': 'v1.27.2'}
    allowed = {'GO-TEST-1': {'module': 'example.test/dependency', 'version': 'v1.2.3', 'maximum_level': 1}}

    def messages(self):
        return [{'config': {'scanner_name': 'govulncheck', 'scanner_version': 'v1.9.0',
                            'scan_level': 'symbol', 'scan_mode': 'source', 'go_version': 'go1.27.2',
                            'db': 'https://vuln.go.dev', 'db_last_modified': '2026-10-08T22:31:09Z'}},
                {'SBOM': {'go_version': 'go1.27.2', 'roots': ['example.test/research'],
                          'modules': [{'path': p, 'version': v} for p, v in self.expected.items()]}},
                {'osv': {'id': 'GO-TEST-1'}},
                {'finding': {'osv': 'GO-TEST-1', 'trace': [{'module': 'example.test/dependency',
                                                         'version': 'v1.2.3', 'package': 'example.test/dependency/api'}]}}]

    def admit(self, rows):
        return A.admit('\n'.join(json.dumps(r) for r in rows), self.expected, self.allowed, '1.27.2')

    def test_complete_scoped_residual_and_clean_scans(self):
        report = self.admit(self.messages())
        self.assertEqual(report['package_ids'], ['GO-TEST-1'])
        self.assertEqual(report['symbol_ids'], [])
        self.assertEqual(self.admit(self.messages()[:2])['module_ids'], [])

    def test_rejects_empty_truncated_and_missing_graph_coverage(self):
        rows = self.messages()
        for broken in ([], rows[:1], rows + [rows[1]], rows[1:], rows + [{'error': 'failed'}]):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                self.admit(broken)
        for change in ('missing', 'duplicate', 'version', 'root'):
            broken = copy.deepcopy(rows)
            sbom = broken[1]['SBOM']
            if change == 'missing': sbom['modules'].pop()
            if change == 'duplicate': sbom['modules'].append(sbom['modules'][0])
            if change == 'version': sbom['modules'][1]['version'] = 'v1.2.2'
            if change == 'root': sbom['roots'] = []
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.admit(broken)
        with self.assertRaises(ValueError):
            A.admit('{', self.expected, self.allowed, '1.27.2')

    def test_rejects_weakened_scanner_and_finding_scope(self):
        for key, value in [('scan_level', 'module'), ('scan_mode', 'binary'), ('go_version', 'go1.27.0'),
                           ('scanner_version', 'v1.0.0'), ('db_last_modified', ''), ('db', 'https://example.test')]:
            rows = self.messages()
            rows[0]['config'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.admit(rows)
        for key, value in [('function', 'Unsafe'), ('version', 'v1.2.2'), ('module', 'stdlib')]:
            rows = self.messages()
            rows[-1]['finding']['trace'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.admit(rows)
        rows = self.messages()
        rows[-1]['finding']['osv'] = 'GO-NEW-2'
        rows.insert(2, {'osv': {'id': 'GO-NEW-2'}})
        with self.assertRaises(ValueError): self.admit(rows)
        rows = self.messages()
        rows.pop(2)
        with self.assertRaises(ValueError): self.admit(rows)

    def test_failed_scanner_cannot_admit_partial_output(self):
        packages = '\n'.join(json.dumps({'Module': {'Path': p, 'Version': v}})
                             for p, v in self.expected.items() if p != 'stdlib')
        with tempfile.TemporaryDirectory() as tmp, patch.object(A.subprocess, 'check_output', return_value=packages), \
                patch.object(A.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                patch.object(A, 'admit') as admission:
            with self.assertRaises(RuntimeError):
                A.scan('coraza', 'openbsd-amd64', {'coraza': {}}, Path(tmp), '1.27.2')
            admission.assert_not_called()
