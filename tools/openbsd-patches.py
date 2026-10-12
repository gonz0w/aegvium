# SPDX-License-Identifier: BSD-3-Clause
"""Nomvium-derived pinned lab-only syspatches (BSD-3-Clause).
Native signify verification remains mandatory."""
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / 'tools/openbsd-patches.json').read_text())
CACHE = ROOT / '.tools/openbsd-patches'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse_manifest(text):
    lines = text.splitlines()
    if len(lines) < 3 or not lines[0].startswith('untrusted comment: '):
        raise ValueError('missing signed manifest header')
    entries = {}
    for line in lines[2:]:
        match = re.fullmatch(r'SHA256 \((syspatch79-[0-9]{3}_[a-z0-9_]+\.tgz)\) = ([0-9a-f]{64})', line)
        if not match or match[1] in entries:
            raise ValueError('malformed or duplicate patch name')
        entries[match[1]] = match[2]
    if not entries:
        raise ValueError('empty patch manifest')
    return entries


def expected_files():
    return {'SHA256.sig': PINS['manifest_sha256'],
            'openbsd-79-syspatch.pub': PINS['public_key_sha256'], **PINS['assets']}


def verify(cache=CACHE):
    if any(parent.is_symlink() for parent in (cache, *cache.parents)):
        raise ValueError('symlinked patch cache')
    for name, checksum in expected_files().items():
        path = cache / name
        if path.is_symlink() or not path.is_file() or digest(path) != checksum:
            raise ValueError(f'unverified patch asset: {name}')
    if parse_manifest((cache / 'SHA256.sig').read_text()) != PINS['assets']:
        raise ValueError('manifest does not match reviewed patch set')
    return cache


def fetch():
    os.umask(0o077)
    CACHE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CACHE.is_symlink():
        raise ValueError('symlinked patch cache')
    for name, checksum in expected_files().items():
        path = CACHE / name
        if path.is_symlink():
            raise ValueError('symlinked patch asset')
        if path.is_file() and digest(path) == checksum:
            continue
        url = PINS['public_key_url'] if name.endswith('.pub') else PINS['mirror'] + '/' + name
        temporary = CACHE / (name + '.download')
        if temporary.is_symlink():
            raise ValueError('symlinked download staging file')
        print('Fetching ' + name, flush=True)
        try:
            with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as output:
                count = 0
                while block := response.read(1024 * 1024):
                    count += len(block)
                    if count > 256 * 1024 * 1024:
                        raise ValueError('patch exceeds lab download bound')
                    output.write(block)
            if digest(temporary) != checksum:
                raise ValueError('patch checksum mismatch: ' + name)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    verify()
    print('Pinned patch mirror verified; guest signature verification required.', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['fetch']:
        fetch()
    elif sys.argv[1:] == ['verify']:
        verify()
        print('Patch cache digests match reviewed pins.')
    else:
        sys.exit('usage: openbsd-patches.py fetch|verify')
