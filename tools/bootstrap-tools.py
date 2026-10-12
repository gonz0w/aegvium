#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Install checksum-pinned development tools inside the ignored .tools directory."""
import hashlib
import io
import json
import platform
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if platform.python_version() != (ROOT / ".python-version").read_text().strip():
    raise SystemExit("Python does not match .python-version; use the pinned development interpreter")
pins = json.loads((ROOT / "tools/pins.json").read_text())
system = platform.system().lower()
machine = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
target = f"{system}_{machine}"
bindir = ROOT / ".tools/bin"
bindir.mkdir(parents=True, exist_ok=True)
for name, pin in pins.items():
    artifact = pin["artifacts"].get(target)
    if not artifact:
        raise SystemExit(f"No reviewed {name} binary for {target}; use a Linux/macOS development host")
    binary = bindir / name
    marker = bindir / f"{name}.sha256"
    pinfile = bindir / f"{name}.artifact"
    if binary.exists() and marker.exists() and pinfile.exists():
        if marker.read_text().strip() == hashlib.sha256(binary.read_bytes()).hexdigest() and pinfile.read_text().strip() == artifact["sha256"]:
            continue
    print(f"Downloading {name} {pin['version']} for {target}", flush=True)
    request = urllib.request.Request(artifact["url"], headers={"User-Agent": "aegvium-foundation-bootstrap"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise SystemExit(f"Checksum mismatch for {name}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        matches = [member for member in archive.getmembers() if Path(member.name).name == name and member.isfile()]
        if len(matches) != 1:
            raise SystemExit(f"Expected one executable named {name}")
        binary.write_bytes(archive.extractfile(matches[0]).read())
    binary.chmod(0o755)
    marker.write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + "\n")
    pinfile.write_text(artifact["sha256"] + "\n")
venv = ROOT / ".tools/venv"
if not (venv / "bin/python3").exists():
    subprocess.run(["python3", "-m", "venv", str(venv)], check=True)
subprocess.run([str(venv / "bin/python3"), "-m", "pip", "install", "--no-cache-dir", "--require-hashes",
                "--only-binary=:all:", "-r", str(ROOT / "tools/requirements-ci.txt")], check=True)
print("Pinned development tools ready")
