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
      'detection-uri', 'detection-body')} | {'TestInvalidRulesRejected', 'TestBodyReadFailure'}
GROUPS = {'TestPinnedCRSSmoke', 'TestRequestInterruption'}


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


def bound_child_storage():
    # Applies to supervisor/QEMU only. The snapshot stays in the private run.
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**3, 4 * 1024**3))


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inject-failure', choices=('boot', 'ssh', 'auth', 'transfer', 'test'))
    args = parser.parse_args()
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
    subprocess.run(['make', 'research-cross'], cwd=ROOT, check=True, timeout=180)
    binary_hash = digest(binary)
    work = ROOT / '.tools/native-runs' / str(uuid.uuid4())
    work.mkdir(parents=True, mode=0o700)
    source = {name: digest(ROOT / name) for name in git('ls-files').splitlines()}
    report = {'schema': 1, 'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
              'source': source, 'started': datetime.now(timezone.utc).isoformat(),
              'binary_sha256': binary_hash, 'native_build': False, 'passed': False,
              'host_go': subprocess.check_output([str(ROOT / '.tools/go/bin/go'), 'version'], text=True).strip(),
              'image_sha256': PINS['qcow2_sha256'], 'injected_failure': args.inject_failure,
              'profile': {'cpu': 2, 'ram_mib': 2048, 'acceleration': 'TCG', 'deadline_seconds': 900,
                          'network': 'restrict=on; dynamic loopback-only SSH; no guest egress'}}
    supervisor = None
    expires = time.monotonic() + 900
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
                                           str(work / 'teardown.json'), '900', '--', *command],
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
        report['native'] = engine_guest(guest, work, binary, binary_hash)
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
