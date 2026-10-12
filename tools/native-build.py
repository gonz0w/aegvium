# SPDX-License-Identifier: BSD-3-Clause
"""Prepare source and compiler for an offline disposable native build."""
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_image', ROOT / 'tools/native-image.py')
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
CACHE = ROOT / '.tools/native-build'


def digest(path):
    with os.fdopen(IMAGE.regular_fd(path), 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def compiler_pin():
    return json.loads((ROOT / 'tools/research-pins.json').read_text())['go']['artifacts']['openbsd_amd64']


def compiler():
    path = CACHE / 'go-openbsd-amd64.tar.gz'
    pin = compiler_pin()
    if path.stat().st_size != pin['size'] or digest(path) != pin['sha256']:
        raise ValueError('native compiler archive mismatch')
    return path


def fetch():
    os.umask(0o077)
    CACHE.mkdir(mode=0o700, exist_ok=True)
    if any(path.is_symlink() for path in (CACHE, *CACHE.parents)):
        raise ValueError('symlinked compiler cache refused')
    target = CACHE / 'go-openbsd-amd64.tar.gz'
    if target.is_symlink():
        raise ValueError('symlinked compiler asset refused')
    if target.exists():
        compiler()
        return
    pin = compiler_pin()
    temporary = CACHE / 'go.download'
    created = False
    try:
        with temporary.open('xb') as output:
            created = True
            with urllib.request.urlopen(pin['url'], timeout=60) as response:
                count = 0
                while block := response.read(1024 * 1024):
                    count += len(block)
                    if count > pin['size']:
                        raise ValueError('native compiler download exceeds pin size')
                    output.write(block)
        if count != pin['size'] or digest(temporary) != pin['sha256']:
            raise ValueError('native compiler download mismatch')
        temporary.rename(target)
        compiler()
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def package(work):
    archive = compiler()
    env = {**os.environ, 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOTOOLCHAIN': 'local'}
    module = ROOT / 'research/coraza'
    subprocess.run([str(ROOT / 'tools/run-research-go.sh'), 'mod', 'verify'],
                   cwd=module, env=env, check=True, timeout=120)
    with tempfile.TemporaryDirectory(prefix='build-source-', dir=work) as temporary:
        stage = Path(temporary)
        names = ('go.mod', 'go.sum', 'engine_test.go', 'crs_test.go', 'relayd_test.go', 'proxy_v1.go', 'proxy_v1_test.go', 'proxy_conn.go', 'proxy_conn_test.go')
        for name in names:
            IMAGE.copy_verified(module / name, stage / name, digest(module / name))
            # Go vendor can update go.mod; stage is independent, source stays untouched.
            (stage / name).chmod(0o600)
        subprocess.run([str(ROOT / 'tools/run-research-go.sh'), 'mod', 'vendor'],
                       cwd=stage, env=env, check=True, timeout=120)
        if any(digest(stage / name) != digest(module / name) for name in names):
            raise ValueError('vendoring changed admitted source inputs')
        files = sorted(path for path in stage.rglob('*') if not path.is_dir())
        hashes = {str(path.relative_to(stage)): digest(path) for path in files}
        bundle = work / 'engine-source.tar.gz'
        with tarfile.open(bundle, 'w:gz') as output:
            for path in files:
                # Regular-file checks precede export; never transfer symlink/device entries.
                item = output.gettarinfo(path, arcname='src/' + str(path.relative_to(stage)))
                if not item.isfile():
                    raise ValueError('nonregular source export refused')
                item.mode = 0o444
                with path.open('rb') as stream:
                    output.addfile(item, stream)
        return {'compiler': archive, 'source': bundle,
                'compiler_sha256': digest(archive), 'source_sha256': digest(bundle),
                'source_files': hashes}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fetch', 'verify'))
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch()
    else:
        compiler()
    print('Pinned OpenBSD compiler archive verified; not yet guest build evidence.')
