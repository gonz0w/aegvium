# SPDX-License-Identifier: BSD-3-Clause
"""Admit an independent, pinned research base; never boot or modify the source."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def regular_fd(path):
    path = Path(path).absolute()
    # Reject symlinked parents as well as the asset itself.
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError(f'symlink refused: {parent}')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f'not a regular file: {path}')
    return fd


def copy_verified(source, destination, expected):
    """Exclusive output, bounded streaming, hash the actual copied bytes."""
    fd = regular_fd(source)
    created = False
    try:
        with os.fdopen(fd, 'rb') as incoming:
            with open(destination, 'xb') as output:
                created = True
                os.chmod(destination, 0o400)
                digest = hashlib.sha256()
                while block := incoming.read(1024 * 1024):
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        if digest.hexdigest() != expected:
            raise ValueError(f'image digest mismatch: {source}')
        return digest.hexdigest()
    except BaseException:
        if created:
            Path(destination).unlink(missing_ok=True)
        raise


def admit(source, destination, pins):
    destination = Path(destination).absolute()
    # Owned directory must be new, underneath the repository's private cache.
    private_root = ROOT / '.tools' / 'native'
    for parent in (private_root, *private_root.parents):
        if parent.is_symlink():
            raise ValueError('symlinked private cache refused')
    private_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(private_root, 0o700)
    if destination.parent != private_root or destination.name in ('', '.', '..'):
        raise ValueError('destination must be a new direct child of .tools/native')
    destination.mkdir(mode=0o700)
    try:
        digest = copy_verified(source, destination / 'base.qcow2', pins['qcow2_sha256'])
        receipt = {'release': pins['release'], 'builder': pins['builder'],
                   'base_sha256': digest, 'base_mode': '0400',
                   'source_modified': False, 'guest_executed': False,
                   'provenance': 'third-party builder; not signed official install media'}
        (destination / 'admission.json').write_text(json.dumps(receipt, indent=2) + '\n')
        os.chmod(destination / 'admission.json', 0o600)
        return receipt
    except BaseException:
        # copy_verified removes only output it exclusively created.
        (destination / 'admission.json').unlink(missing_ok=True)
        (destination / 'base.qcow2').unlink(missing_ok=True)
        destination.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('name', help='new private cache directory name')
    args = parser.parse_args()
    pins = json.loads((ROOT / 'research/native/image-pin.json').read_text())
    print(json.dumps(admit(args.source, ROOT / '.tools/native' / args.name, pins)))


if __name__ == '__main__':
    main()
