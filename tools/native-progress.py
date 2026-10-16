# SPDX-License-Identifier: BSD-3-Clause
"""Private, atomic phase checkpoints; completion is not native acceptance."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


def plan(args):
    """Match native-engine's execution order after host preflight/export."""
    stages = ['guest_boot', 'fresh_access', 'patch_refresh']
    optional = [
        ('relayd_config', args.relayd_config or args.relayd_traffic),
        ('sender_preparation', args.sender_containment),
        ('backend_preparation', args.backend_isolation),
        ('native', True),
        ('relayd_wiring', any((args.relayd_wiring, args.relayd_health_faults,
                              args.relayd_checker_replacements, args.relayd_generations))),
        ('relayd_signals', args.relayd_signals),
        ('relayd_contract', args.relayd_contract),
        ('lab_proxy', args.lab_proxy), ('lab_tls', args.lab_tls),
        ('sender_containment', args.sender_containment),
        ('client_identity_component', args.client_identity),
        ('client_identity_pf', args.client_identity),
        ('backend_isolation', args.backend_isolation), ('request_wire', args.request_wire),
        ('relayd_body', args.relayd_body), ('relayd_traffic', args.relayd_traffic),
        ('connector_native_build', args.connector_source_build),
        ('connector_comparison', args.connector_comparison),
        ('configured_caddy', args.configured_caddy), ('subset_gate', True),
    ]
    return stages + [name for name, selected in optional if selected]


def atomic_json(path, value):
    """Readers see complete JSON, even if serialization/write/replace fails."""
    data = (json.dumps(value, indent=2) + '\n').encode()
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        # Flush the directory entry too, before allowing the next operation.
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def error_class(error):
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'interrupted'
    if isinstance(error, TimeoutError):
        return 'timeout'
    # subprocess.TimeoutExpired is deliberately handled without rendering argv/output.
    if isinstance(error, subprocess.TimeoutExpired):
        return 'timeout'
    return 'operation'


class Journal:
    def __init__(self, path, run_id, commit, tree, stages):
        if str(uuid.UUID(run_id)) != run_id or any(not re.fullmatch('[0-9a-f]{40}', x) for x in (commit, tree)):
            raise ValueError('invalid progress identity')
        if not stages or len(stages) > 32 or len(set(stages)) != len(stages) or any(not re.fullmatch('[a-z][a-z_]{0,39}', x) for x in stages):
            raise ValueError('invalid progress plan')
        self.path = Path(path)
        if self.path.exists():
            raise ValueError('progress checkpoint already exists')
        self.started = time.monotonic()
        self.state = {'schema': 1, 'run_id': run_id, 'commit': commit, 'tree': tree,
                      'sequence': 0, 'finished': False, 'result': 'incomplete',
                      'teardown_verified': None,
                      'stages': [{'name': name, 'state': 'pending', 'start_ms': None,
                                  'duration_ms': None, 'error_class': 'none'} for name in stages]}
        self._save()

    def _save(self):
        self.state['sequence'] += 1
        atomic_json(self.path, self.state)

    @contextmanager
    def stage(self, name):
        if self.state['finished'] or any(s['state'] in ('running', 'failed', 'interrupted') for s in self.state['stages']):
            raise ValueError('progress cannot advance')
        pending = next((s for s in self.state['stages'] if s['state'] == 'pending'), None)
        if pending is None or pending['name'] != name:
            raise ValueError('progress order mismatch')
        row = pending
        row['state'] = 'running'
        row['start_ms'] = int((time.monotonic() - self.started) * 1000)
        try:
            self._save()  # Never start guest work without its durable checkpoint.
        except OSError:
            row['state'], row['error_class'] = 'failed', 'checkpoint'
            raise
        print(f'Native phase: {name} running', flush=True)
        try:
            yield
        except BaseException as error:
            row['error_class'] = error_class(error)
            row['state'] = 'interrupted' if row['error_class'] == 'interrupted' else 'failed'
            raise
        else:
            row['state'] = 'completed'
        finally:
            row['duration_ms'] = max(0, int((time.monotonic() - self.started) * 1000) - row['start_ms'])
            try:
                self._save()
            except OSError:
                row['state'], row['error_class'] = 'failed', 'checkpoint'
                raise
            print(f"Native phase: {name} {row['state']}", flush=True)

    def finish(self, passed, teardown_verified):
        if type(passed) is not bool or type(teardown_verified) is not bool or self.state['finished']:
            raise ValueError('invalid progress finalization')
        stages = self.state['stages']
        if passed and (not teardown_verified or any(s['state'] != 'completed' for s in stages)):
            raise ValueError('incomplete progress cannot pass')
        for row in stages:
            if row['state'] == 'pending':
                row['state'] = 'not-run'
        self.state['finished'] = True
        self.state['result'] = 'passed' if passed else 'interrupted' if any(s['state'] == 'interrupted' for s in stages) else 'failed'
        self.state['teardown_verified'] = teardown_verified
        self._save()

    def summary(self):
        counts = {state: sum(row['state'] == state for row in self.state['stages'])
                  for state in ('pending', 'running', 'completed', 'failed', 'interrupted', 'not-run')}
        stopped = next((row for row in self.state['stages'] if row['state'] in ('running', 'failed', 'interrupted')), None)
        return {'result': self.state['result'], 'finished': self.state['finished'],
                'stage_counts': counts, 'sequence': self.state['sequence'],
                'stopped_stage': stopped['name'] if stopped else None,
                'error_class': stopped['error_class'] if stopped else 'none'}
