# SPDX-License-Identifier: BSD-3-Clause
"""Own one fresh, offline stock-installer research VM; no installer automation."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MEDIA, PROGRESS, CLEANUP = load('official-media'), load('native-progress'), load('native-cleanup')
DURATION = 3600
QMP_SECONDS = 5
QMP_FRAME_BYTES = 65536
QMP_INPUT_BYTES = 4 * QMP_FRAME_BYTES
QMP_EVENTS = 32


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def qmp(path, command, arguments=None):
    """One exchange with fixed wall, frame, aggregate-input and event bounds."""
    deadline = time.monotonic() + QMP_SECONDS
    try:
        return _qmp_exchange(path, command, arguments, deadline)
    except TimeoutError:
        raise TimeoutError('owned QEMU control deadline') from None
    except OSError:
        raise RuntimeError('owned QEMU control transport failed') from None


def _qmp_exchange(path, command, arguments, deadline):
    """Internal exchange; the public entry fixes one deadline before any I/O."""
    with socket.socket(socket.AF_UNIX) as connection:
        pending, received, events = b'', 0, 0

        def remaining():
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError('owned QEMU control deadline')
            connection.settimeout(seconds)

        def unique(fields):
            value = {}
            for name, item in fields:
                if name in value:
                    raise ValueError('duplicate field')
                value[name] = item
            return value

        def constant(_value):
            raise ValueError('nonfinite number')

        def finite(value):
            number = float(value)
            if not math.isfinite(number):
                raise ValueError('nonfinite number')
            return number

        def receive():
            nonlocal pending, received
            while True:
                remaining()
                if b'\n' in pending:
                    line, _, pending = pending.partition(b'\n')
                    try:
                        value = json.loads(line, object_pairs_hook=unique,
                                           parse_constant=constant, parse_float=finite)
                    except (ValueError, RecursionError):
                        raise RuntimeError('owned QEMU control malformed frame') from None
                    if type(value) is not dict:
                        raise RuntimeError('owned QEMU control malformed frame')
                    remaining()  # Parsing or a completed late read cannot renew the wall.
                    return value
                if len(pending) >= QMP_FRAME_BYTES:
                    raise RuntimeError('owned QEMU control frame bound')
                chunk = connection.recv(min(4096, QMP_FRAME_BYTES - len(pending),
                                            QMP_INPUT_BYTES - received + 1))
                if not chunk:
                    raise RuntimeError('owned QEMU control incomplete frame')
                received += len(chunk)
                if received > QMP_INPUT_BYTES:
                    raise RuntimeError('owned QEMU control input bound')
                pending += chunk

        remaining()
        connection.connect(str(path))
        greeting = receive()
        if set(greeting) != {'QMP'} or type(greeting['QMP']) is not dict:
            raise RuntimeError('owned QEMU control greeting refused')
        for number, request in enumerate(({'execute': 'qmp_capabilities'},
                                           {'execute': command, 'arguments': arguments or {}})):
            request['id'] = 'stock-lab-' + str(number)
            payload = (json.dumps(request) + '\n').encode()
            if len(payload) > QMP_FRAME_BYTES:
                raise ValueError('owned QEMU control request bound')
            remaining()
            connection.sendall(payload)
            while True:
                response = receive()
                if 'event' in response:
                    events += 1
                    if (events > QMP_EVENTS or type(response['event']) is not str or not response['event']
                            or not set(response) <= {'event', 'data', 'timestamp'}):
                        raise RuntimeError('owned QEMU control event bound or shape')
                    continue
                if (response.get('id') != request['id']
                        or set(response) not in ({'id', 'return'}, {'id', 'error'})):
                    raise RuntimeError('owned QEMU control reply refused')
                if 'error' in response:
                    raise RuntimeError('owned QEMU control refused')
                break
        return response['return']


def bounded_child():
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**3, 4 * 1024**3))


def create(media):
    if git('status', '--porcelain'):
        raise ValueError('stock research requires a clean signed candidate')
    # Only an Aegvium-created media directory, never an arbitrary image/device.
    if media.parent != ROOT / '.tools/official-media' or str(uuid.UUID(media.name)) != media.name:
        raise ValueError('unknown stock media directory')
    verified = MEDIA.verify(media, media / 'signify')
    os.umask(0o077)
    parent = ROOT / '.tools/native-stock'
    if any(p.is_symlink() for p in (parent, *parent.parents)):
        raise ValueError('symlinked stock fixture path refused')
    parent.mkdir(mode=0o700, exist_ok=True)
    work = parent / str(uuid.uuid4()); work.mkdir(mode=0o700)
    disk = work / 'disk.qcow2'
    # Exclusive creation precedes qemu-img; it may only format this owned empty inode.
    with disk.open('xb'): pass
    initial = disk.stat()
    subprocess.run([shutil.which('qemu-img') or 'qemu-img', 'create', '-f', 'qcow2', str(disk), '8G'],
                   check=True, stdout=subprocess.DEVNULL, timeout=30)
    info = json.loads(subprocess.check_output([shutil.which('qemu-img') or 'qemu-img', 'info', '--output=json', str(disk)], text=True, timeout=15))
    current = disk.stat()
    if (initial.st_ino != current.st_ino or initial.st_dev != current.st_dev or current.st_nlink != 1
            or current.st_mode & 0o777 != 0o600 or info.get('format') != 'qcow2'
            or info.get('virtual-size') != 8 * 1024**3 or 'backing-filename' in info):
        raise ValueError('fresh stock disk identity mismatch')
    source = {name: MEDIA.digest(ROOT / name) for name in git('ls-files').splitlines()}
    command = [shutil.which('qemu-system-x86_64') or 'qemu-system-x86_64', '-S',
               '-machine', 'pc-i440fx-11.1,accel=tcg,hpet=off,smm=off', '-cpu', 'max', '-smp', '2', '-m', '2048',
               '-display', 'none', '-vga', 'std', '-nic', 'none', '-rtc', 'base=utc,clock=host',
               '-qmp', f'unix:{work / "qmp.sock"},server=on,wait=off',
               '-serial', f'unix:{work / "serial.sock"},server=on,wait=off',
               '-drive', f'file={disk},format=qcow2,if=virtio',
               '-drive', f'file={media / "install79.iso"},format=raw,media=cdrom,readonly=on',
               '-boot', 'once=d,order=c']
    report = {'schema': 1, 'run_id': work.name, 'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
              'started': datetime.now(timezone.utc).isoformat(), 'source': source, 'media': verified,
              'qemu_sha256': MEDIA.digest(Path(command[0]).resolve()), 'command': command,
              'disk_initial_sha256': MEDIA.digest(disk), 'disk_device': current.st_dev, 'disk_inode': current.st_ino,
              'profile': {'deadline_seconds': DURATION, 'stop_new_work_seconds': 3000, 'cleanup_reserve_seconds': 600,
                          'cpu': 2, 'ram_mib': 2048, 'virtual_disk_bytes': 8 * 1024**3, 'file_ceiling_bytes': 4 * 1024**3,
                          'network': 'no NIC; private Unix control/serial sockets only'},
              'installation_complete': False, 'passed': False}
    PROGRESS.atomic_json(work / 'creation.json', report)
    supervisor = None
    stopped = False
    def stop(_number, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    try:
        with (work / 'qemu.log').open('wb') as output:
            supervisor = subprocess.Popen([sys.executable, str(ROOT / 'tools/lab-supervisor.py'),
                str(work / 'teardown.json'), str(DURATION), '--', *command], stdin=subprocess.PIPE,
                stdout=output, stderr=output, preexec_fn=bounded_child, env={**os.environ, 'TMPDIR': str(work)})
        print(json.dumps({'run_id': work.name, 'state': 'paused-for-owned-inventory'}), flush=True)
        while supervisor.poll() is None and not stopped:
            time.sleep(0.25)
    finally:
        report['teardown'] = CLEANUP.stop_supervisor(supervisor, work, DURATION)
        CLEANUP.integrity(report, media / 'install79.iso', MEDIA.PINS['assets']['install79.iso']['sha256'],
                          source, ROOT, MEDIA.digest, git)
        try:
            report['media_unchanged'] = verified['assets_sha256'] == {n: MEDIA.digest(media / n) for n in MEDIA.PINS['assets']}
        except (OSError, ValueError):
            report['media_unchanged'] = False
        try:
            final = disk.stat()
            report['disk_identity_unchanged'] = (final.st_dev, final.st_ino, final.st_nlink) == (current.st_dev, current.st_ino, 1)
            report['disk_final_sha256'] = MEDIA.digest(disk)
        except (OSError, ValueError):
            report['disk_identity_unchanged'] = False
            report['disk_final_sha256'] = None
        report['finished'] = datetime.now(timezone.utc).isoformat()
        # Installation/boot/lineage are independent manual postconditions, never inferred from QEMU exit.
        PROGRESS.atomic_json(work / 'stopped.json', report)
        print(json.dumps({'run_id': work.name, 'state': 'stopped', 'teardown_verified': report['teardown']['teardown_verified'],
                          'source_unchanged': report['source_unchanged'], 'media_unchanged': report['media_unchanged']}), flush=True)
    return 0 if (report['teardown']['teardown_verified'] and report['source_unchanged'] and report['media_unchanged']
                 and report['disk_identity_unchanged'] and report['head_unchanged'] and report['worktree_clean']) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', type=Path, required=True)
    args = parser.parse_args()
    sys.exit(create(args.media))
