# SPDX-License-Identifier: BSD-3-Clause
"""Host-only checkpoint crashes/storage failures and mocked native orchestration."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import uuid

SPEC = importlib.util.spec_from_file_location('progress_engine', Path(__file__).resolve().parents[1] / 'native-engine.py')
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)
PROGRESS = ENGINE.PROGRESS


class ProgressTests(unittest.TestCase):
    def journal(self, path, stages=('first', 'second')):
        return PROGRESS.Journal(path, str(uuid.uuid4()), 'a'*40, 'b'*40, stages)

    def test_atomic_permissions_failure_and_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'progress.json'
            journal = self.journal(path)
            original = path.read_bytes()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch.object(PROGRESS.os, 'replace', side_effect=OSError('private marker')):
                with self.assertRaises(OSError), journal.stage('first'):
                    self.fail('work started despite checkpoint failure')
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(folder).iterdir()), [path])
            self.assertEqual(journal.state['stages'][0]['error_class'], 'checkpoint')
            journal.finish(False, True)
            self.assertEqual(json.loads(path.read_text())['stages'][1]['state'], 'not-run')
            with self.assertRaises(ValueError):self.journal(path)

    def test_failed_interrupted_timeout_and_later_work_never_succeeds(self):
        errors = [RuntimeError('private marker'), KeyboardInterrupt('private marker'),
                  subprocess.TimeoutExpired(['private marker'], 2, output=b'private marker')]
        for error in errors:
            with self.subTest(kind=type(error).__name__), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'progress.json'
                journal = self.journal(path)
                with self.assertRaises(type(error)), journal.stage('first'):
                    raise error
                with self.assertRaises(ValueError), journal.stage('second'):
                    self.fail('work advanced after failure')
                with self.assertRaises(ValueError):journal.finish(True, True)
                journal.finish(False, True)
                result = json.loads(path.read_text())
                self.assertNotIn('private marker', path.read_text())
                self.assertTrue(result['teardown_verified'])
                self.assertEqual(result['stages'][1]['state'], 'not-run')
                self.assertEqual(result['stages'][0]['error_class'], PROGRESS.error_class(error))

    def test_phase_order_and_teardown_are_independent_acceptance_gates(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = self.journal(Path(folder) / 'progress.json')
            with self.assertRaises(ValueError), journal.stage('second'):
                self.fail('out of order')
            for name in ('first', 'second'):
                with journal.stage(name):
                    running = json.loads(journal.path.read_text())
                    self.assertEqual(next(s for s in running['stages'] if s['name'] == name)['state'], 'running')
            with self.assertRaises(ValueError):journal.finish(True, False)
            journal.finish(False, False)
            self.assertEqual(journal.summary()['stage_counts']['completed'], 2)
            self.assertEqual(journal.summary()['result'], 'failed')
            with self.assertRaises(ValueError):journal.finish(True, True)

    def test_killed_controller_leaves_unfinished_running_checkpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            path, ready = Path(folder) / 'progress.json', Path(folder) / 'ready'
            code = ('import importlib.util,sys; from pathlib import Path\n'
                    f's=importlib.util.spec_from_file_location("progress",{str(Path(PROGRESS.__file__))!r})\n'
                    'p=importlib.util.module_from_spec(s);s.loader.exec_module(p)\n'
                    f'j=p.Journal({str(path)!r},{str(uuid.uuid4())!r},"a"*40,"b"*40,["first","second"])\n'
                    f'with j.stage("first"):\n Path({str(ready)!r}).touch()\n sys.stdin.buffer.read(1)\n')
            child = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                child.send_signal(signal.SIGKILL)
                child.communicate(timeout=5)
                state = json.loads(path.read_text())
                self.assertFalse(state['finished'])
                self.assertEqual(state['result'], 'incomplete')
                self.assertEqual([s['state'] for s in state['stages']], ['running', 'pending'])
            finally:
                if child.poll() is None:child.kill()
                child.communicate(timeout=5)


class RunnerProgressTests(unittest.TestCase):
    def exercise(self, flags, failure=None, checkpoint_failure=False, lifecycle_build_failure=False):
        """Run the actual orchestrator; every guest/process operation is replaced."""
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            for name in ('.tools/native/base-7.9-reviewed/base.qcow2', '.tools/native/bootstrap.key',
                         '.tools/research/readycheck-openbsd-amd64', 'tracked.txt'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'owned synthetic file')
            image = root / '.tools/native/base-7.9-reviewed/base.qcow2'
            image.chmod(0o400)
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            stack.enter_context(patch.object(ENGINE, 'ROOT', root))
            stack.enter_context(patch.object(ENGINE, 'PINS', {'qcow2_sha256': digest,
                'assets': {'openbsd-7.9-host.id_rsa': {'sha256': digest}}}))
            stack.enter_context(patch.object(ENGINE, 'git', side_effect=lambda *args:
                '' if args[0] == 'status' else 'tracked.txt' if args[0] == 'ls-files'
                else 'b'*40 if args[-1] == 'HEAD^{tree}' else 'a'*40))
            stack.enter_context(patch.object(ENGINE, 'digest', side_effect=lambda path:
                hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else digest))
            stack.enter_context(patch.object(ENGINE.PATCHES, 'verify'))
            stack.enter_context(patch.object(ENGINE.BUILD, 'package', return_value={'archive_sha256': digest}))
            stack.enter_context(patch.object(ENGINE.BUILD, 'connector_package', return_value={'archive_sha256': digest}))
            stack.enter_context(patch.object(ENGINE.subprocess, 'run'))
            stack.enter_context(patch.object(ENGINE.subprocess, 'check_output', return_value='synthetic version'))
            stack.enter_context(patch.object(ENGINE, 'qemu_command', return_value=[sys.executable]))
            stack.enter_context(patch.object(ENGINE, 'ssh_config'))
            socket_type = stack.enter_context(patch.object(ENGINE.socket, 'socket'))
            socket_type.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 12345)
            guest_type = stack.enter_context(patch.object(ENGINE, 'Guest'))
            guest_type.return_value.call.return_value.returncode = 0
            stack.enter_context(patch.object(ENGINE, 'rotate', return_value=True))
            stack.enter_context(patch.object(ENGINE, 'patch_guest', return_value={'admitted': True}))
            built = {'receipts': {'binary': digest, 'uid': '32767'},
                     'build_receipts': {'checker': digest, 'program': digest}}
            engine_calls = {}
            for name in ('source_build_guest', 'engine_guest'):
                engine_calls[name] = stack.enter_context(patch.object(ENGINE, name, return_value=built))
            for name in ('relayd_config_guest', 'relayd_contract_guest', 'relayd_traffic_guest', 'connector_build_guest'):
                stack.enter_context(patch.object(ENGINE, name, return_value={**built, 'admitted': True}))
            modules = [ENGINE.WIRING, ENGINE.SIGNALS, ENGINE.BODY, ENGINE.LAB_PROXY, ENGINE.LAB_TLS,
                       ENGINE.SENDER, ENGINE.CLIENT_IDENTITY, ENGINE.BACKEND_ISOLATION,
                       ENGINE.REQUEST_WIRE, ENGINE.CONNECTOR, ENGINE.CONFIGURED, ENGINE.LIFECYCLE]
            calls = {}
            for module in modules:
                calls[module.__name__] = stack.enter_context(patch.object(module, 'guest_run',
                    return_value={**built, 'admitted': True, 'native_binary': True}))
            for module in (ENGINE.SENDER, ENGINE.BACKEND_ISOLATION):
                stack.enter_context(patch.object(module, 'prepare_guest', return_value={'admitted': True}))
            lifecycle_builder = stack.enter_context(patch.object(ENGINE.LIFECYCLE, 'build_guest',
                return_value={'admitted': not lifecycle_build_failure, 'hashes': {'library': digest, 'control': digest}}))
            lifecycle_execution = stack.enter_context(patch.object(ENGINE.LIFECYCLE, 'execute_guest',
                return_value={**built, 'admitted': True}))
            if failure:
                calls[ENGINE.LAB_PROXY.__name__].side_effect = failure
            supervisor = Mock()
            def cleanup(**kwargs):
                work = next((root / '.tools/native-runs').iterdir())
                (work / 'teardown.json').write_text(json.dumps({'teardown_verified': True}))
            supervisor.communicate.side_effect = cleanup
            stack.enter_context(patch.object(ENGINE.subprocess, 'Popen', return_value=supervisor))
            if checkpoint_failure:
                real_save = PROGRESS.atomic_json
                def save(path, value):
                    if Path(path).name == 'progress.json' and (value['finished'] if checkpoint_failure == 'final' else any(s['name'] == 'lab_proxy' and s['state'] == 'running' for s in value['stages'])):
                        raise OSError('private checkpoint failure')
                    return real_save(path, value)
                stack.enter_context(patch.object(PROGRESS, 'atomic_json', side_effect=save))
            output = io.StringIO()
            stack.enter_context(patch.object(sys, 'argv', ['native-engine.py', *flags]))
            with redirect_stdout(output):
                status = ENGINE.run()
            work = next((root / '.tools/native-runs').iterdir())
            report = json.loads((work / 'report.json').read_text())
            self.assertEqual(supervisor.communicate.call_count, 1, report.get('error'))
            journal = json.loads((work / 'progress.json').read_text())
            if checkpoint_failure != 'final':
                self.assertEqual(report['progress']['sha256'], hashlib.sha256((work / 'progress.json').read_bytes()).hexdigest())
                self.assertEqual(report['progress']['result'], journal['result'])
            self.assertTrue(report['teardown']['teardown_verified'])
            if '--lifecycle-components' in flags or '--lifecycle-source-build' in flags:
                for call in engine_calls.values():call.assert_not_called()
                for name, call in calls.items():
                    if name != ENGINE.LIFECYCLE.__name__:call.assert_not_called()
                if '--lifecycle-source-build' in flags:
                    calls[ENGINE.LIFECYCLE.__name__].assert_not_called()
                    lifecycle_builder.assert_called_once()
                    if lifecycle_build_failure:lifecycle_execution.assert_not_called()
                    else:lifecycle_execution.assert_called_once()
                    self.assertEqual(report['scope'], 'ordinary-lifecycle-components-native-build')
                    self.assertEqual(report['native_build'], not lifecycle_build_failure)
                    self.assertEqual(report['profile']['deadline_seconds'], 2400)
                    self.assertEqual(report['profile']['post_build_reserve_seconds'], 180)
                    self.assertEqual(report['profile']['native_build_deadline_seconds'], 1200)
                else:
                    calls[ENGINE.LIFECYCLE.__name__].assert_called_once()
                    lifecycle_builder.assert_not_called();lifecycle_execution.assert_not_called()
                    self.assertEqual(report['scope'], 'ordinary-lifecycle-components')
                    self.assertFalse(report['native_build'])
            self.assertNotIn('private marker', output.getvalue())
            self.assertNotIn('private checkpoint failure', output.getvalue())
            self.assertNotIn('build_receipts', output.getvalue())
            if checkpoint_failure is True:
                calls[ENGINE.LAB_PROXY.__name__].assert_not_called()
            return status, report, journal

    wire = ['--source-build', '--lab-proxy', '--lab-tls', '--sender-containment',
            '--client-identity', '--backend-isolation', '--request-wire']

    def test_selected_profiles_complete_exact_plans_without_launching_guest(self):
        for flags in ([], ['--lifecycle-components'], ['--lifecycle-source-build'], self.wire,
                      ['--lab-proxy', '--connector-comparison', '--connector-source-build', '--configured-caddy'],
                      ['--relayd-traffic', '--relayd-generations', '--relayd-signals', '--relayd-contract', '--relayd-body']):
            with self.subTest(flags=flags):
                status, report, journal = self.exercise(flags)
                self.assertEqual(status, 0)
                self.assertTrue(report['passed'])
                self.assertTrue(all(s['state'] == 'completed' for s in journal['stages']))

    def test_failure_interrupt_timeout_skip_later_scopes_and_still_cleanup(self):
        for failure in (RuntimeError('private marker'), KeyboardInterrupt(),
                        subprocess.TimeoutExpired(['private marker'], 1)):
            with self.subTest(kind=type(failure).__name__):
                status, report, journal = self.exercise(self.wire, failure=failure)
                self.assertEqual(status, 1)
                self.assertFalse(report['passed'])
                index = next(i for i,s in enumerate(journal['stages']) if s['name'] == 'lab_proxy')
                self.assertTrue(all(s['state'] == 'completed' for s in journal['stages'][:index]))
                self.assertIn(journal['stages'][index]['state'], ('failed', 'interrupted'))
                self.assertTrue(all(s['state'] == 'not-run' for s in journal['stages'][index+1:]))

    def test_checkpoint_failure_prevents_operation_and_still_cleanup(self):
        status, report, journal = self.exercise(self.wire, checkpoint_failure=True)
        self.assertEqual(status, 1)
        row = next(s for s in journal['stages'] if s['name'] == 'lab_proxy')
        self.assertEqual((row['state'], row['error_class']), ('failed', 'checkpoint'))

    def test_injected_test_gate_failure_cannot_pass(self):
        status, report, journal = self.exercise(['--inject-failure', 'test'])
        self.assertEqual(status, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(journal['stages'][-1]['state'], 'failed')

    def test_final_checkpoint_failure_preserves_report_and_cannot_pass(self):
        status, report, journal = self.exercise(self.wire, checkpoint_failure='final')
        self.assertEqual(status, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(report['progress_error'], 'checkpoint-finalization-failed')
        self.assertNotIn('progress', report)
        self.assertFalse(journal['finished'])
