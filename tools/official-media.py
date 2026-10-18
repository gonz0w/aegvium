# SPDX-License-Identifier: BSD-3-Clause
"""Authenticate a private stock ISO copy before the OB laboratory experiment."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('official_media_image', ROOT / 'tools/native-image.py')
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
SPEC_PROGRESS = importlib.util.spec_from_file_location('official_media_progress', ROOT / 'tools/native-progress.py')
PROGRESS = importlib.util.module_from_spec(SPEC_PROGRESS)
SPEC_PROGRESS.loader.exec_module(PROGRESS)
PINS = json.loads((ROOT / 'research/native/official-release-pins.json').read_text())


def digest(path):
    with os.fdopen(IMAGE.regular_fd(path), 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(directory, verifier):
    if digest(verifier) != PINS['verifier']['executable_sha256']:
        raise ValueError('release verifier identity mismatch')
    for name, pin in PINS['assets'].items():
        path = directory / name
        if digest(path) != pin['sha256'] or ('size' in pin and path.stat().st_size != pin['size']):
            raise ValueError('release input identity mismatch')
    result = subprocess.run([str(verifier), '-C', '-p', 'openbsd-79-base.pub',
                             '-x', 'SHA256.sig', 'install79.iso'], cwd=directory,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    # These fixed receipts supplement a successful real verifier exit; never replace it.
    if result.returncode != 0 or result.stdout.splitlines() != [b'Signature Verified', b'install79.iso: OK']:
        raise ValueError('stock release authentication incomplete or failed')
    if (digest(verifier) != PINS['verifier']['executable_sha256'] or
            any(digest(directory / name) != pin['sha256'] for name, pin in PINS['assets'].items())):
        raise ValueError('release inputs changed during authentication')
    return {'signature_verified': True, 'image_verified': True,
            'verifier_sha256': digest(verifier),
            'assets_sha256': {name: digest(directory / name) for name in PINS['assets']},
            'image_bytes': (directory / 'install79.iso').stat().st_size,
            'verifier_output_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'trust': 'pinned official HTTPS release key; host-only verifier; not independent out-of-band authentication'}


def prepare(verifier, image, license_file):
    os.umask(0o077)
    cache = ROOT / '.tools/official-media'
    for path in (cache, *cache.parents):
        if path.is_symlink():
            raise ValueError('symlinked release cache refused')
    cache.mkdir(mode=0o700, exist_ok=True)
    work = cache / str(uuid.uuid4())
    work.mkdir(mode=0o700)
    try:
        IMAGE.copy_verified(verifier, work / 'signify', PINS['verifier']['executable_sha256'])
        (work / 'signify').chmod(0o500)
        IMAGE.copy_verified(license_file, work / 'LICENSE', PINS['verifier']['license_sha256'])
        if image.stat().st_size != PINS['assets']['install79.iso']['size']:
            raise ValueError('stock image size mismatch')
        IMAGE.copy_verified(image, work / 'install79.iso', PINS['assets']['install79.iso']['sha256'])
        for name in ('openbsd-79-base.pub', 'SHA256.sig'):
            pin = PINS['assets'][name]
            with urllib.request.urlopen(pin['url'], timeout=60) as response:
                data = response.read(pin['maximum_bytes'] + 1)
            if len(data) > pin['maximum_bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                raise ValueError('official release download mismatch')
            with (work / name).open('xb') as output:
                output.write(data)
            (work / name).chmod(0o400)
        receipt = verify(work, work / 'signify')
        PROGRESS.atomic_json(work / 'verification.json', receipt)
        return work, receipt
    except BaseException:
        # Retain the uniquely owned partial directory; no successful receipt is published.
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--license', type=Path, required=True)
    args = parser.parse_args()
    work, receipt = prepare(args.verifier, args.image, args.license)
    print(json.dumps({'directory': str(work), **receipt}, indent=2))
