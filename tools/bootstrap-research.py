#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Checksum-pinned host research toolchain; never installs system software."""
import hashlib
import io
import json
import os
import platform
import subprocess
import shutil
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
pins = json.loads((ROOT / 'tools/research-pins.json').read_text())
arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine())
artifact = pins['go']['artifacts'].get(platform.system().lower() + '_' + str(arch))
if artifact is None:
    raise SystemExit('No reviewed research toolchain for this host')
target = ROOT / '.tools/go'
if not target.exists():
    request = urllib.request.Request(artifact['url'], headers={'User-Agent': 'aegvium-research'})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != artifact['sha256']:
        raise SystemExit('Go archive checksum mismatch')
    stage = ROOT / '.tools/research-go-stage'
    stage.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            archive.extractall(stage, filter='data')
        (stage / 'go').rename(target)
    finally:
        shutil.rmtree(stage)
go = target / 'bin/go'
env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOBIN': str(ROOT / '.tools/research-bin'),
       'GOCACHE': str(ROOT / '.tools/go-cache')}
version = subprocess.check_output([str(go), 'env', 'GOVERSION'], env=env, text=True).strip()
if version != 'go' + pins['go']['version']:
    raise SystemExit('Installed research Go version does not match the pin')
subprocess.run([str(go), 'install', 'golang.org/x/vuln/cmd/govulncheck@' + pins['govulncheck']['version']], env=env, check=True)
print('Pinned host research toolchain ready; native qualification remains separate')
