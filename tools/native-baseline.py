# SPDX-License-Identifier: BSD-3-Clause
"""Select explicit laboratory inputs; never fall back between baseline origins."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

SPEC = importlib.util.spec_from_file_location('baseline_image', Path(__file__).with_name('native-image.py'))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)


def read_json(path):
    with os.fdopen(IMAGE.regular_fd(path), 'rb') as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError('baseline metadata bound')
    return json.loads(data)


def select(root, legacy, official=False):
    if not official:
        return {'kind': 'inherited-reference', 'image': root / '.tools/native/base-7.9-reviewed/base.qcow2',
                'bootstrap': root / '.tools/native/bootstrap.key', 'image_sha256': legacy['qcow2_sha256'],
                'bootstrap_private_sha256': legacy['assets']['openbsd-7.9-host.id_rsa']['sha256']}
    pin = read_json(root / 'research/native/official-image-pin.json')
    expected = {'release', 'architecture', 'origin', 'image_sha256', 'bootstrap_public_sha256',
                'provision_source_commit', 'provision_run_id', 'qualified_mode'}
    if (not isinstance(pin, dict) or set(pin) != expected or pin['release'] != '7.9' or pin['architecture'] != 'amd64'
            or pin['origin'] != 'authenticated-stock-install'
            or pin['qualified_mode'] != 'ordinary-lifecycle-components'
            or any(not isinstance(pin[k], str) or not re.fullmatch('[0-9a-f]{64}', pin[k]) for k in ('image_sha256', 'bootstrap_public_sha256'))
            or not isinstance(pin['provision_source_commit'], str)
            or not re.fullmatch('[0-9a-f]{40}', pin['provision_source_commit'])):
        raise ValueError('official baseline pin mismatch')
    if not isinstance(pin['provision_run_id'], str) or str(uuid.UUID(pin['provision_run_id'])) != pin['provision_run_id']:
        raise ValueError('official baseline run identity mismatch')
    directory = root / '.tools/native/base-7.9-official'
    admission = read_json(directory / 'admission.json')
    if (not isinstance(admission, dict) or admission.get('image_sha256') != pin['image_sha256']
            or admission.get('bootstrap_public_sha256') != pin['bootstrap_public_sha256']
            or admission.get('provision_source_commit') != pin['provision_source_commit']
            or admission.get('disk_independent') is not True
            or admission.get('provision_run_id') != pin['provision_run_id']
            or admission.get('clean_halt_observed') is not True
            or admission.get('installed_files_match') is not True):
        raise ValueError('official baseline admission mismatch')
    return {'kind': pin['origin'], 'image': directory / 'base.qcow2', 'bootstrap': directory / 'bootstrap.key',
            'image_sha256': pin['image_sha256'], 'bootstrap_public_sha256': pin['bootstrap_public_sha256'],
            'provision_source_commit': pin['provision_source_commit'], 'provision_run_id': pin['provision_run_id']}


def verify_bootstrap(baseline, digest):
    key = baseline['bootstrap']
    if baseline['kind'] == 'inherited-reference':
        if digest(key) != baseline['bootstrap_private_sha256']:
            raise ValueError('bootstrap key mismatch')
        key.chmod(0o600)
        return
    with os.fdopen(IMAGE.regular_fd(key), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if info.st_mode & 0o777 != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('official bootstrap ownership mismatch')
    result = subprocess.run(['ssh-keygen', '-y', '-f', str(key)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    parts = result.stdout.split()
    if result.returncode or len(result.stdout) > 1024 or len(parts) < 2 or parts[0] != b'ssh-ed25519':
        raise ValueError('official bootstrap public identity unavailable')
    if hashlib.sha256(b' '.join(parts[:2]) + b'\n').hexdigest() != baseline['bootstrap_public_sha256']:
        raise ValueError('official bootstrap public identity mismatch')
