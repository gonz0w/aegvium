# SPDX-License-Identifier: BSD-3-Clause
"""Bounded Aegvium engine repeat. Generic QEMU/SSH setup adapted from Nomvium."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import resource
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

IMAGE = load('native-image')
PATCHES = load('openbsd-patches')
BUILD = load('native-build')
SIGNALS = load('relayd-signals')
WIRING = load('relayd-wiring')
PINS = json.loads((ROOT / 'research/native/image-pin.json').read_text())

SSH_HARDEN = b'''set -eu
umask 077
cat > /etc/ssh/sshd_config.aegvium-lab <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
AuthorizedKeysCommand none
AllowUsers root
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
EOF
sshd -t -f /etc/ssh/sshd_config.aegvium-lab
cp /etc/ssh/sshd_config.aegvium-lab /etc/ssh/sshd_config
rcctl reload sshd
rm -f /root/.ssh/id_rsa /root/.ssh/id_rsa.pub
'''


def qemu_command(image, port, work):
    return [shutil.which('qemu-system-x86_64') or 'qemu-system-x86_64',
            '-machine', 'pc,accel=tcg,hpet=off,smm=off', '-cpu', 'max',
            '-smp', '2', '-m', '2048', '-snapshot', '-display', 'none',
            '-monitor', 'none', '-serial', f'file:{work / "serial.log"}',
            '-rtc', 'base=utc,clock=host', '-netdev',
            'user,id=net0,net=192.168.122.0/24,host=192.168.122.1,'
            'dns=192.168.122.3,dhcpstart=192.168.122.254,ipv6=off,restrict=on,'
            f'hostfwd=tcp:127.0.0.1:{port}-192.168.122.254:22',
            '-device', 'virtio-net-pci,netdev=net0',
            '-device', 'virtio-balloon-pci', '-object', 'rng-builtin,id=rng0',
            '-device', 'virtio-rng-pci,rng=rng0',
            '-drive', f'file={image},format=qcow2,if=virtio']



def ssh_config(path, port, key, work):
    path.write_text(f'''Host fixture
    HostName 127.0.0.1
    User root
    Port {port}
    IdentityFile "{key}"
    IdentitiesOnly yes
    IdentityAgent none
    StrictHostKeyChecking accept-new
    UserKnownHostsFile "{work / 'known_hosts'}"
    BatchMode yes
    ConnectTimeout 5
    LogLevel ERROR
''')
    path.chmod(0o600)



def verify_rejection(response):
    if response.returncode != 255 or b'Permission denied (publickey)' not in response.stderr:
        raise RuntimeError('public bootstrap rejection not proven')


EXPECTED = {
    'TestPinnedCRSSmoke/' + name for name in
    ('benign-query', 'benign-post', 'sql-injection', 'script-injection')
} | {'TestRequestInterruption/' + name for name in
     ('benign-get', 'uri-denied', 'benign-post', 'body-denied', 'body-limit',
      'detection-uri', 'detection-body')} | {'TestInvalidRulesRejected', 'TestBodyReadFailure'} | {
    'TestExplicitInspectionError/' + name for name in
    ('empty-benign', 'benign-post', 'read-error', 'partial-read-error',
     'uri-denied', 'body-denied', 'detection-uri')}
EXPECTED |= {'TestProxyV1Accepted/' + name for name in ('coalesced', 'one-byte', 'two-requests', 'maximum')} | {
    'TestProxyV1Rejected/' + name for name in ('missing', 'truncated', 'overlong', 'bare-lf', 'magic', 'family',
    'unknown', 'v2', 'source', 'destination', 'leading-zero-address', 'mapped-ipv6', 'zero-port', 'overflow-port',
    'leading-zero-port', 'signed-port', 'duplicate-space', 'tab', 'extra-field', 'wrong-destination')} | {'TestProxyV1ReadFailure'}
EXPECTED |= {'TestProxyV1Conn/' + name for name in ('coalesced', 'deadline-cleared', 'timeout-silent', 'timeout-partial',
    'malformed', 'initial-deadline-failure', 'clear-deadline-failure', 'invalid-budget')} | {
    'TestProxyV1TCP/' + name for name in ('handoff', 'timeout')}
EXPECTED |= {'TestProxyV1Listener/' + name for name in ('progress', 'capacity', 'close-pending',
    'close-undelivered', 'engine-gate', 'accept-failure')} | {
    'TestProxyV1ListenerTCP/' + name for name in ('progress', 'bare-head')}
EXPECTED |= {'TestProxyReady/' + name for name in ('transitions', 'head', 'route', 'method', 'nil', 'close', 'accept-failure', 'server-bounds')} | {
    'TestProxyReadyTCP/' + name for name in ('lifecycle', 'accept-failure')}
EXPECTED |= {'TestReadyProbe/' + name for name in ('ready', 'unavailable', 'redirect', 'malformed', 'oversized', 'body', 'missing-no-store', 'keepalive', 'validation', 'dial-failure', 'silent-timeout')} | {
    'TestReadyCheckerTCP/' + name for name in ('transitions', 'refused', 'silent', 'malformed', 'invalid-argument', 'missing-executable')}
GROUPS = {'TestPinnedCRSSmoke', 'TestRequestInterruption', 'TestExplicitInspectionError', 'TestProxyV1Accepted', 'TestProxyV1Rejected', 'TestProxyV1Conn', 'TestProxyV1TCP', 'TestProxyV1Listener', 'TestProxyV1ListenerTCP', 'TestProxyReady', 'TestProxyReadyTCP', 'TestReadyProbe', 'TestReadyCheckerTCP'}


def digest(path):
    with os.fdopen(IMAGE.regular_fd(path), 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse_native(text, binary_hash):
    receipts, passed = {}, set()
    for line in text.splitlines():
        if line.startswith('RECEIPT\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('malformed/duplicate receipt')
            receipts[parts[1]] = parts[2]
        match = re.fullmatch(r'\s*--- PASS: (\S+) \([0-9.]+s\)', line)
        if match:
            if match[1] in passed or match[1] not in EXPECTED | GROUPS:
                raise ValueError('duplicate/unknown passed test')
            passed.add(match[1])
        if '--- SKIP:' in line or '--- FAIL:' in line:
            raise ValueError('native skipped/failed test')
    if (passed != EXPECTED | GROUPS or text.splitlines()[-1:] != ['PASS']
            or set(receipts) != {'os', 'uid', 'binary', 'kernel', 'kernel_sha256', 'patches'}
            or receipts['os'] != 'OpenBSD 7.9 amd64'
            or not re.fullmatch(r'[1-9][0-9]*', receipts['uid'])
            or receipts['binary'] != binary_hash
            or not re.fullmatch(r'[0-9a-f]{64}', receipts['kernel_sha256'])
            or not receipts['kernel']
            or receipts['patches'].split(',') != [name.removeprefix('syspatch79-').removesuffix('.tgz')
                                                  for name in PATCHES.PINS['assets']]):
        raise ValueError('incomplete/mismatched native receipts or test set')
    return {'receipts': receipts, 'cases': sorted(EXPECTED), 'case_count': len(EXPECTED)}


class Guest:
    def __init__(self, config, expires):
        self.config = config
        self.expires = expires

    def remaining(self, maximum):
        remaining = self.expires - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('total native deadline exhausted')
        return min(maximum, remaining)

    def call(self, command, data=None, seconds=15, output=None, stream=None):
        kwargs = {'timeout': self.remaining(seconds), 'stderr': subprocess.STDOUT if output else subprocess.PIPE,
                  'stdout': output if output else subprocess.PIPE}
        if stream:
            kwargs['stdin'] = stream
        else:
            kwargs['input'] = data
        return subprocess.run(['ssh', '-F', str(self.config), 'fixture', command], **kwargs)

    def require(self, command, data=None, seconds=15):
        response = self.call(command, data=data, seconds=seconds)
        if response.returncode:
            raise RuntimeError(f'guest command failed ({response.returncode}): {response.stderr.decode(errors="replace")}')
        return response.stdout

    def wait(self, command, predicate, seconds):
        deadline = min(self.expires, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            response = self.call(command, seconds=min(10, deadline - time.monotonic()))
            if response.returncode == 0 and predicate(response.stdout):
                return response.stdout
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise TimeoutError('native readiness deadline exhausted')


def rotate(guest, port, work, bootstrap):
    key = work / 'fixture.key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                   check=True, capture_output=True, timeout=guest.remaining(15))
    guest.require('set -eu; umask 077; mkdir -p /root/.ssh; cat > /root/.ssh/authorized_keys',
                  data=key.with_suffix('.key.pub').read_bytes())
    ssh_config(guest.config, port, key, work)
    guest.require('true')
    guest.require('sh -s', data=SSH_HARDEN)
    guest.wait('true', lambda _: True, 45)
    old = work / 'bootstrap-rejection.conf'
    ssh_config(old, port, bootstrap, work)
    verify_rejection(Guest(old, guest.expires).call('true'))
    guest.require('true')
    return True


def patch_guest(guest, work):
    cache = PATCHES.verify()
    archive = work / 'patch-mirror.tar'
    with tarfile.open(archive, 'w') as bundle:
        for name in PATCHES.expected_files():
            bundle.add(cache / name, arcname='syspatch/7.9/amd64/' + name, recursive=False)
    with archive.open('rb') as stream:
        response = guest.call('set -eu; mkdir /var/aegvium-lab-mirror; '
                              'chmod 755 /var/aegvium-lab-mirror; '
                              'tar -xpf - -C /var/aegvium-lab-mirror; '
                              'chmod -R a+rX /var/aegvium-lab-mirror', stream=stream, seconds=180)
    if response.returncode:
        raise RuntimeError('patch mirror transfer failed')
    archive.unlink()
    with (work / 'patch.log').open('wb') as output:
        response = guest.call('sh -s', data=(ROOT / 'tools/native/patch-openbsd.sh').read_bytes(),
                              seconds=600, output=output)
    if response.returncode or any(marker not in (work / 'patch.log').read_bytes() for marker in (
            b'PATCH\tsignature\tVERIFIED', b'PATCH\tinstalled\t34', b'PATCH\tpending\t0')):
        raise RuntimeError('native patch authentication/installation failed; see patch.log')
    before = guest.require('sysctl -n kern.boottime')
    guest.require("nohup sh -c 'sleep 2; reboot' >/var/aegvium-lab-reboot.log 2>&1 </dev/null &")
    after = guest.wait('sysctl -n kern.boottime', lambda value: value != before, 240)
    guest.require('test "$(uname -srm)" = "OpenBSD 7.9 amd64"')
    return {'signature_verified': True, 'installed': 34, 'pending': 0,
            'manifest_sha256': PATCHES.PINS['manifest_sha256'],
            'public_key_sha256': PATCHES.PINS['public_key_sha256'],
            'log_sha256': digest(work / 'patch.log'),
            'boot_before': before.decode().strip(), 'boot_after': after.decode().strip()}


def engine_guest(guest, work, binary, binary_hash):
    with binary.open('rb') as stream:
        transferred = guest.call('set -eu; mkdir /var/aegvium-lab; chmod 755 /var/aegvium-lab; '
                                 'cat > /var/aegvium-lab/engine.test; chmod 555 /var/aegvium-lab/engine.test',
                                 stream=stream, seconds=120)
    if transferred.returncode:
        raise RuntimeError('engine transfer failed')
    script = (ROOT / 'tools/native/engine-repeat.sh').read_bytes().replace(b'BINARY_SHA256', binary_hash.encode())
    with (work / 'native.log').open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=180, output=output)
    if response.returncode:
        raise RuntimeError(f'native engine test failed ({response.returncode}); see native.log')
    return {**parse_native((work / 'native.log').read_text(), binary_hash),
            'log_sha256': digest(work / 'native.log')}



def parse_build(text, source_hash):
    values = {}
    for line in text.splitlines():
        if line.startswith('BUILD\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in values:
                raise ValueError('invalid native build receipt')
            values[parts[1]] = parts[2]
    if (set(values) != {'compiler', 'source', 'uid', 'binary', 'checker'}
            or not re.fullmatch(r'[1-9][0-9]*', values['uid'])
            or any(not re.fullmatch('[0-9a-f]{64}', values[name]) for name in ('compiler', 'source', 'binary', 'checker'))
            or values['source'] != source_hash):
        raise ValueError('native source build receipts incomplete')
    return values


def source_build_guest(guest, work, inputs):
    guest.require('set -eu; mkdir /var/aegvium-build; chmod 755 /var/aegvium-build')
    for name, asset in (('go.tar.gz', inputs['compiler']), ('source.tar.gz', inputs['source'])):
        with asset.open('rb') as stream:
            response = guest.call('set -eu; cat > /var/aegvium-build/' + name,
                                  stream=stream, seconds=180)
        if response.returncode:
            raise RuntimeError('native build input transfer failed')
    script = (ROOT / 'tools/native/source-build.sh').read_bytes()
    script = script.replace(b'COMPILER_SHA256', inputs['compiler_sha256'].encode())
    script = script.replace(b'SOURCE_SHA256', inputs['source_sha256'].encode())
    log = work / 'build.log'
    with log.open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=1200, output=output)
    if response.returncode:
        raise RuntimeError(f'native source build failed ({response.returncode}); see build.log')
    values = parse_build(log.read_text(), inputs['source_sha256'])
    guest.require('set -eu; mkdir /var/aegvium-lab; chmod 755 /var/aegvium-lab; '
                  'cp /var/aegvium-build/output/engine.test /var/aegvium-lab/engine.test; '
                  'chmod 555 /var/aegvium-lab/engine.test; '
                  'cp /var/aegvium-build/output/readycheck /var/aegvium-lab-readycheck; '
                  'chmod 555 /var/aegvium-lab-readycheck; '
                  'test "$(sha256 -q /var/aegvium-lab/engine.test)" = "' + values['binary'] + '"; '
                  'test "$(sha256 -q /var/aegvium-lab-readycheck)" = "' + values['checker'] + '"')
    repeat = (ROOT / 'tools/native/engine-repeat.sh').read_bytes().replace(b'BINARY_SHA256', values['binary'].encode())
    with (work / 'native.log').open('wb') as output:
        response = guest.call('sh -s', data=repeat, seconds=180, output=output)
    if response.returncode:
        raise RuntimeError('native-built test execution failed; see native.log')
    native = parse_native((work / 'native.log').read_text(), values['binary'])
    if native['receipts']['uid'] != values['uid']:
        raise ValueError('native builder/execution UID mismatch')
    return {'build_receipts': values, 'build_log_sha256': digest(log),
            **native, 'log_sha256': digest(work / 'native.log')}


def relayd_inputs():
    profile = (ROOT / 'research/relayd/ingress.conf').read_bytes()
    reference = b'    protocol "inspection_ingress"'
    if profile.count(reference) != 1:
        raise ValueError('reviewed protocol reference mismatch')
    return {'ingress.conf': profile,
            'missing-protocol.conf': profile.replace(reference, b'    protocol "missing"'),
            'bad-syntax.conf': profile + b'unsupported_aegvium_option\n'}


def parse_relayd(text, profile_hash):
    receipts = {}
    for line in text.splitlines():
        if line.startswith('RELAYD\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('malformed/duplicate relayd receipt')
            receipts[parts[1]] = parts[2]
    expected = {'valid': 'accepted', 'missing-protocol': 'rejected', 'bad-syntax': 'rejected',
                'no-daemon': 'verified-before-after', 'no-listener': 'verified-before-after',
                'no-control-socket': 'verified-before-after', 'uid': '0', 'profile': profile_hash}
    hashes = {'binary', 'valid-log', 'missing-log', 'bad-log'}
    if (set(receipts) != set(expected) | hashes
            or any(receipts.get(name) != value for name, value in expected.items())
            or any(not re.fullmatch('[0-9a-f]{64}', receipts[name]) for name in hashes)):
        raise ValueError('incomplete/mismatched relayd configtest receipts')
    return receipts


def relayd_config_guest(guest, work):
    inputs = relayd_inputs()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()}
    guest.require('set -eu; umask 077; mkdir /var/aegvium-relayd')
    for name, data in inputs.items():
        guest.require('set -eu; cat > /var/aegvium-relayd/' + name, data=data)
    script = (ROOT / 'tools/native/relayd-config.sh').read_bytes()
    for token, name in ((b'PROFILE_SHA256', 'ingress.conf'), (b'MISSING_SHA256', 'missing-protocol.conf'),
                        (b'BAD_SHA256', 'bad-syntax.conf')):
        script = script.replace(token, hashes[name].encode())
    log = work / 'relayd-config.log'
    with log.open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=60, output=output)
    if response.returncode:
        raise RuntimeError('relayd configtest failed; see relayd-config.log')
    return {'mode': 'syntax-only; daemon never started', 'input_sha256': hashes,
            'receipts': parse_relayd(log.read_text(), hashes['ingress.conf']), 'log_sha256': digest(log)}


def contract_inputs():
    inputs = {'profile.conf': (ROOT / 'research/relayd/checker-contract.conf').read_bytes()}
    for name, action in (('up', 'exit 1'), ('down', 'exit 0'), ('positive', 'exit 2'), ('signal', 'kill -TERM $$')):
        inputs[name + '.sh'] = ('#!/bin/sh\n# SPDX-License-Identifier: BSD-3-Clause\n'
                               'id -u > /var/aegvium-contract/uid/' + name + '\n' + action + '\n').encode()
    return inputs


def parse_contract(text, profile_hash, checker_hash):
    receipts = {}
    for line in text.splitlines():
        if line.startswith('CONTRACT\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('malformed/duplicate contract receipt')
            receipts[parts[1]] = parts[2]
    expected = {'syntax': 'accepted', 'up': 'up', 'down': 'down', 'positive': 'up',
                'signal': 'down', 'missing': 'down', 'checker': 'down', 'cleanup': 'verified',
                'profile': profile_hash, 'checker-sha': checker_hash}
    hashes = {'relayd', 'states-log', 'syntax-log', 'daemon-log'}
    if (set(receipts) != set(expected) | hashes | {'script-uid'}
            or any(receipts.get(k) != v for k, v in expected.items())
            or not re.fullmatch('[1-9][0-9]*', receipts.get('script-uid', ''))
            or any(not re.fullmatch('[0-9a-f]{64}', receipts[k]) for k in hashes)):
        raise ValueError('incomplete/mismatched relayd checker contract receipts')
    return receipts


def relayd_contract_guest(guest, work, checker_hash):
    inputs = contract_inputs()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()}
    guest.require('set -eu; umask 022; mkdir /var/aegvium-contract; chmod 755 /var/aegvium-contract')
    for name, data in inputs.items():
        guest.require('set -eu; cat > /var/aegvium-contract/' + name, data=data)
        if name.endswith('.sh'):
            guest.require('chmod 555 /var/aegvium-contract/' + name)
    script = (ROOT / 'tools/native/relayd-checker-contract.sh').read_bytes()
    script = script.replace(b'CONTRACT_PROFILE_SHA256', hashes['profile.conf'].encode()).replace(b'CHECKER_SHA256', checker_hash.encode())
    log = work / 'relayd-contract.log'
    with log.open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=120, output=output)
    if response.returncode:
        raise RuntimeError('relayd checker contract failed; see relayd-contract.log')
    return {'scope': 'script contract only; no backend/health listener or application traffic',
            'input_sha256': hashes, 'receipts': parse_contract(log.read_text(), hashes['profile.conf'], checker_hash),
            'log_sha256': digest(log)}


TRAFFIC_CASES = {'TestRelaydTraffic/' + name for name in (
    'direct-benign-get', 'direct-benign-post', 'direct-uri-denied', 'direct-body-denied',
    'relayd-benign-get', 'relayd-benign-post', 'relayd-uri-denied', 'relayd-body-denied',
    'inspection-loss', 'recovery', 'tcp-inspection-loss', 'tcp-recovery')} | {
    'TestRelaydTraffic/tcp-' + name for name in ('benign-get', 'benign-post', 'uri-denied', 'body-denied')} | {
    'TestRelaydTraffic/' + arm + '-' + name for arm in ('direct', 'relayd', 'tcp') for name in
    ('chunked-benign', 'chunked-denied', 'conflicting-length', 'mixed-framing-attack', 'pipeline-denied-benign', 'pipeline-benign-benign', 'serialized-denied-benign')} | {
    'TestRelaydTraffic/' + arm + '-' + name for arm in ('direct-longidle', 'relayd-longidle')
    for name in ('pipeline-denied-benign', 'pipeline-benign-benign', 'serialized-denied-benign')} | {
    'TestRelaydTraffic/' + arm + '-' + name for arm in ('direct', 'relayd')
    for name in ('wake-pipeline-denied-benign', 'wake-pipeline-benign-benign')} | {
    'TestRelaydTraffic/' + arm + '-recovery-head-post-' + mode
    for arm in ('direct', 'relayd', 'tcp') for mode in ('reuse', 'fresh')} | {
    'TestRelaydTraffic/tls-' + name for name in ('benign-get', 'benign-post', 'uri-denied', 'body-denied',
    'pipeline-denied-benign', 'pipeline-benign-benign', 'inspection-loss', 'recovery', 'reject-untrusted', 'reject-wrong-name')}


def parse_traffic(text, binary_hash, profile_hash, relayd_hash):
    receipts, passed = {}, set()
    for line in text.splitlines():
        if line.startswith('TRAFFIC\t'):
            parts = line.split('\t')
            if len(parts) != 3 or parts[1] in receipts:
                raise ValueError('malformed/duplicate traffic receipt')
            receipts[parts[1]] = parts[2]
        match = re.fullmatch(r'\s*--- PASS: (\S+) \([0-9.]+s\)', line)
        if match:
            if match[1] in passed or match[1] not in TRAFFIC_CASES | {'TestRelaydTraffic'}:
                raise ValueError('unknown/duplicate traffic case')
            passed.add(match[1])
        if '--- SKIP:' in line or '--- FAIL:' in line:
            raise ValueError('traffic skipped/failed test')
    if (set(receipts) != {'relayd', 'profile', 'binary', 'uid', 'cleanup', 'daemon-log', 'tls-cert', 'tls-cleanup'}
            or receipts.get('relayd') != relayd_hash or receipts.get('profile') != profile_hash
            or receipts.get('binary') != binary_hash or receipts.get('cleanup') != 'verified'
            or not re.fullmatch(r'[1-9][0-9]*', receipts.get('uid', ''))
            or not re.fullmatch('[0-9a-f]{64}', receipts.get('daemon-log', ''))
            or receipts.get('tls-cleanup') != 'verified'
            or not re.fullmatch('[0-9a-f]{64}', receipts.get('tls-cert', ''))
            or re.findall(r'tls-certificate sha256=([0-9a-f]{64})', text) != [receipts.get('tls-cert')]
            or passed != TRAFFIC_CASES | {'TestRelaydTraffic'} or text.splitlines().count('PASS') != 1):
        raise ValueError('incomplete/mismatched traffic results')
    return {'receipts': receipts, 'cases': sorted(TRAFFIC_CASES), 'case_count': len(TRAFFIC_CASES)}


def relayd_traffic_guest(guest, work, binary_hash, relayd_hash):
    profile = (ROOT / 'research/relayd/traffic.conf').read_bytes()
    profile_hash = hashlib.sha256(profile).hexdigest()
    guest.require('set -eu; cat > /var/aegvium-relayd/traffic.conf', data=profile)
    script = (ROOT / 'tools/native/relayd-traffic.sh').read_bytes()
    script = script.replace(b'TRAFFIC_PROFILE_SHA256', profile_hash.encode()).replace(b'BINARY_SHA256', binary_hash.encode())
    log = work / 'relayd-traffic.log'
    with log.open('wb') as output:
        response = guest.call('sh -s', data=script, seconds=150, output=output)
    if response.returncode:
        raise RuntimeError('relayd traffic experiment failed; see relayd-traffic.log')
    return {**parse_traffic(log.read_text(), binary_hash, profile_hash, relayd_hash), 'log_sha256': digest(log)}

def bound_child_storage():
    # Applies to supervisor/QEMU only. The snapshot stays in the private run.
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**3, 4 * 1024**3))


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inject-failure', choices=('boot', 'ssh', 'auth', 'transfer', 'test'))
    parser.add_argument('--source-build', action='store_true')
    parser.add_argument('--relayd-config', action='store_true')
    parser.add_argument('--relayd-traffic', action='store_true')
    parser.add_argument('--relayd-contract', action='store_true')
    parser.add_argument('--relayd-signals', action='store_true')
    parser.add_argument('--relayd-generations', action='store_true')
    parser.add_argument('--relayd-checker-replacements', action='store_true')
    parser.add_argument('--relayd-health-faults', action='store_true')
    parser.add_argument('--relayd-wiring', action='store_true')
    args = parser.parse_args()
    if sum((args.relayd_wiring, args.relayd_health_faults, args.relayd_checker_replacements, args.relayd_generations)) > 1:
        parser.error('select one connected wiring study')
    os.umask(0o077)
    if git('status', '--porcelain'):
        raise ValueError('native evidence requires a clean committed candidate')
    image = ROOT / '.tools/native/base-7.9-reviewed/base.qcow2'
    if digest(image) != PINS['qcow2_sha256'] or image.stat().st_mode & 0o777 != 0o400:
        raise ValueError('independent base admission mismatch')
    bootstrap = ROOT / '.tools/native/bootstrap.key'
    if digest(bootstrap) != PINS['assets']['openbsd-7.9-host.id_rsa']['sha256']:
        raise ValueError('bootstrap key mismatch')
    bootstrap.chmod(0o600)
    PATCHES.verify()
    binary = ROOT / '.tools/research/coraza-openbsd-amd64.test'
    # Always derive the executable from this clean candidate, never stale cache.
    subprocess.run(['make', 'research-cross', 'research-readycheck-cross'], cwd=ROOT, check=True, timeout=180)
    if args.relayd_signals:
        subprocess.run(['make', 'research-signalobserve-cross'], cwd=ROOT, check=True, timeout=180)
    binary_hash = digest(binary)
    work = ROOT / '.tools/native-runs' / str(uuid.uuid4())
    work.mkdir(parents=True, mode=0o700)
    build_inputs = BUILD.package(work) if args.source_build else None
    source = {name: digest(ROOT / name) for name in git('ls-files').splitlines()}
    duration = 1800 if args.source_build else (1500 if args.relayd_health_faults or args.relayd_checker_replacements or args.relayd_generations else 1200 if args.relayd_wiring else 900)
    report = {'schema': 1, 'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
              'source': source, 'started': datetime.now(timezone.utc).isoformat(),
              'binary_sha256': binary_hash, 'native_build': False, 'native_build_requested': args.source_build, 'relayd_config_requested': args.relayd_config or args.relayd_traffic, 'relayd_traffic_requested': args.relayd_traffic, 'relayd_generations_requested': args.relayd_generations, 'relayd_checker_replacements_requested': args.relayd_checker_replacements, 'relayd_health_faults_requested': args.relayd_health_faults, 'relayd_wiring_requested': args.relayd_wiring, 'relayd_signals_requested': args.relayd_signals, 'relayd_contract_requested': args.relayd_contract, 'passed': False,
              'host_go': subprocess.check_output([str(ROOT / '.tools/go/bin/go'), 'version'], text=True).strip(),
              'image_sha256': PINS['qcow2_sha256'], 'injected_failure': args.inject_failure,
              'profile': {'cpu': 2, 'ram_mib': 2048, 'acceleration': 'TCG', 'deadline_seconds': duration,
                          'network': 'restrict=on; dynamic loopback-only SSH; no guest egress'}}
    if build_inputs:
        report['native_build_inputs'] = {key: value for key, value in build_inputs.items() if key not in ('compiler', 'source')}
    supervisor = None
    expires = time.monotonic() + duration
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = work / 'ssh.conf'
        ssh_config(config, port, bootstrap, work)
        command = qemu_command(image, port, work)
        report['qemu_version'] = subprocess.check_output([command[0], '--version'], text=True).splitlines()[0]
        report['qemu_sha256'] = digest(Path(command[0]).resolve())
        with (work / 'qemu.log').open('wb') as output:
            supervisor = subprocess.Popen([sys.executable, str(ROOT / 'tools/lab-supervisor.py'),
                                           str(work / 'teardown.json'), str(duration), '--', *command],
                                          stdin=subprocess.PIPE, stdout=output, stderr=output,
                                          env={**os.environ, 'TMPDIR': str(work)},
                                          preexec_fn=bound_child_storage)
        print(f'Native run: {work}\nWaiting for restricted guest boot...', flush=True)
        if args.inject_failure == 'boot':
            raise RuntimeError('injected boot failure after owned launch')
        guest = Guest(config, expires)
        guest.wait('uname -srm', lambda value: value.strip() == b'OpenBSD 7.9 amd64', 240)
        if args.inject_failure == 'ssh':
            raise RuntimeError('injected SSH failure after readiness')
        report['bootstrap_revoked'] = rotate(guest, port, work, bootstrap)
        print('Fresh access verified; public bootstrap authentication rejected.', flush=True)
        if args.inject_failure == 'auth':
            raise RuntimeError('injected authentication-stage failure')
        print('Authenticating and applying reviewed patch set in owned guest...', flush=True)
        report['patch_refresh'] = patch_guest(guest, work)
        if args.inject_failure == 'transfer':
            raise RuntimeError('injected transfer-stage failure')
        if args.relayd_config or args.relayd_traffic:
            print('Validating stock relayd configuration without starting daemon...', flush=True)
            report['relayd_config'] = relayd_config_guest(guest, work)
        if args.source_build:
            print('Offline unprivileged native compilation started.', flush=True)
            report['native'] = source_build_guest(guest, work, build_inputs)
            report['native_build'] = True
            checker_hash = report['native']['build_receipts']['checker']
            report['checker'] = {'sha256': checker_hash, 'installed_verified': True,
                                 'host_cross_built': False, 'native_built': True}
        else:
            checker = ROOT / '.tools/research/readycheck-openbsd-amd64'
            checker_hash = digest(checker)
            with checker.open('rb') as stream:
                response = guest.call('set -eu; cat > /var/aegvium-lab-readycheck; chmod 555 /var/aegvium-lab-readycheck', stream=stream, seconds=120)
            if response.returncode:
                raise RuntimeError('checker transfer failed')
            guest.require('test "$(sha256 -q /var/aegvium-lab-readycheck)" = "' + checker_hash + '"')
            report['checker'] = {'sha256': checker_hash, 'transfer_verified': True, 'host_cross_built': True}
            report['native'] = engine_guest(guest, work, binary, binary_hash)
        if args.relayd_wiring or args.relayd_health_faults or args.relayd_checker_replacements or args.relayd_generations:
            print('Running connected readiness/forwarding matrix...', flush=True)
            report['relayd_wiring'] = WIRING.guest_run(guest, work, report['native']['receipts']['binary'], checker_hash, faults=args.relayd_health_faults, replacements=args.relayd_checker_replacements, generations=args.relayd_generations)
            if not report['relayd_wiring']['admitted']:
                raise RuntimeError('connected wiring admission failed; partial receipts retained')
        if args.relayd_signals:
            print('Running isolated plain/instrumented signal comparison...', flush=True)
            observer = ROOT / '.tools/research/signalobserve-openbsd-amd64'
            report['relayd_signals'] = SIGNALS.guest_run(guest, work, observer, digest(observer))
            if not report['relayd_signals']['admitted']:
                raise RuntimeError('native signal comparison failed; partial receipts retained')
        if args.relayd_contract:
            print('Running isolated stock-relayd script contract controls...', flush=True)
            report['relayd_contract'] = relayd_contract_guest(guest, work, checker_hash)
        if args.relayd_traffic:
            print('Running guest-loopback stock relayd / Coraza traffic comparison...', flush=True)
            report['relayd_traffic'] = relayd_traffic_guest(guest, work, report['native']['receipts']['binary'],
                                                           report['relayd_config']['receipts']['binary'])
        if args.inject_failure == 'test':
            raise RuntimeError('injected test-stage failure')
        report['native_subset_passed'] = True
    except (Exception, KeyboardInterrupt) as error:
        report['error'] = str(error)
    finally:
        if supervisor is not None:
            try:
                supervisor.communicate(timeout=25)  # EOF requests group cleanup.
            except subprocess.TimeoutExpired:
                supervisor.terminate()
                try:
                    supervisor.communicate(timeout=25)
                except subprocess.TimeoutExpired:
                    report['cleanup_error'] = 'supervisor did not acknowledge teardown'
            teardown = work / 'teardown.json'
            report['teardown'] = json.loads(teardown.read_text()) if teardown.is_file() else {'teardown_verified': False}
        report['baseline_unchanged'] = digest(image) == PINS['qcow2_sha256']
        report['source_unchanged'] = source == {name: digest(ROOT / name) for name in source}
        report['passed'] = bool(report.get('native_subset_passed') and not report.get('error')
                                and report.get('teardown', {}).get('teardown_verified')
                                and report['baseline_unchanged'] and report['source_unchanged']
                                and report['commit'] == git('rev-parse', 'HEAD') and not git('status', '--porcelain'))
        report['finished'] = datetime.now(timezone.utc).isoformat()
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({key: value for key, value in report.items() if key != 'source'}, indent=2), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(run())
