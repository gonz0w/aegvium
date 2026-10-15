# SPDX-License-Identifier: BSD-3-Clause
"""Reject configured-server evidence with changed trust/effects or missing cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('configured_caddy', Path(__file__).resolve().parents[1] / 'configured-caddy.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ConfiguredTests(unittest.TestCase):
    def events(self):
        wanted = C.expectations()
        rows = {r['case']: r for r in wanted['rows']}
        events = []
        for kind, name in wanted['event_order']:
            if kind == 'case': events.append(copy.deepcopy(rows[name]))
            elif kind == 'config':
                digest = {'initial':'a','rollback':'a','invalid-rejected':'b','replaced':'c','strict-enabled':'d'}[name]
                events.append({'kind':kind,'phase':name,'sha256':digest*64,'strict':name=='strict-enabled'})
            elif kind == 'server-cleanup': events.append({'kind':kind,'caddy_stopped':True,'backends_joined':True,'listeners_absent':True,'autosave_absent':True})
            else: events.append({'kind':kind,'child_exited':True,'assets_removed':True,'raw_log_sha256':'e'*64})
        return events

    def log(self, events):
        return '\n'.join(['SERVER '+json.dumps(r) for r in events]+[
            '--- PASS: TestConfiguredCaddyTLS (0.01s)','PASS','CONFIGURED\tos\tOpenBSD 7.9 amd64',
            'CONFIGURED\tbinary\t'+'f'*64,'CONFIGURED\tuid\t32767','CONFIGURED\tcleanup\tverified',''])

    def test_complete_configured_run(self):
        result=C.admit(self.log(self.events()),'f'*64)
        self.assertEqual((result['case_count'],result['configuration_count']),(30,5))

    def test_rejects_changed_trust_effects_inputs_and_types(self):
        for key,value in [('status',200),('backend',1),('backend',False),('http_host','app.test'),
                          ('sni','api.test'),('input_sha256','0'*64),('headers_clean',False),
                          ('response_leaked',True),('client_error',True),('extra',1)]:
            events=self.events();row=next(r for r in events if r.get('case')=='strict-cross-host');row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.admit(self.log(events),'f'*64)

    def test_rejects_missing_duplicate_reordered_and_failed_runs(self):
        events=self.events()
        for broken in (events[:-1],events+[events[-1]],events[1:],list(reversed(events))):
            with self.assertRaises(ValueError):C.admit(self.log(broken),'f'*64)
        for old,new in [('uid\t32767','uid\t0'),('PASS\nCONFIGURED','--- FAIL: child\nPASS\nCONFIGURED'),
                        ('--- PASS: TestConfiguredCaddyTLS','--- SKIP: TestConfiguredCaddyTLS')]:
            with self.assertRaises(ValueError):C.admit(self.log(events).replace(old,new),'f'*64)

    def test_rejects_unbound_rollback_strict_config_and_unclean_child(self):
        for phase,key,value in [('rollback','sha256','9'*64),('replaced','sha256','a'*64),('strict-enabled','strict',False)]:
            events=self.events();next(r for r in events if r.get('phase')==phase)[key]=value
            with self.assertRaises(ValueError):C.admit(self.log(events),'f'*64)
        for kind,key in [('server-cleanup','listeners_absent'),('server-cleanup','autosave_absent'),('process-cleanup','child_exited'),('process-cleanup','assets_removed')]:
            events=self.events();next(r for r in events if r['kind']==kind)[key]=False
            with self.assertRaises(ValueError):C.admit(self.log(events),'f'*64)
