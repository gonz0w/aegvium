#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Agent Temper 1c9e9fb7e5e1152691dbc669d5f7222a7c0c377d; BSD-3-Clause.
"""Optional read-only capacity and staged-artifact checks. Never deletes output."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

DISK_SUFFIXES = ('.qcow', '.qcow2', '.vmdk', '.vdi', '.vhd', '.vhdx', '.raw', '.img', '.iso')


def check_capacity(used, free, peak, budget, reserve):
    if any(n < 0 for n in (used, free, peak, budget, reserve)) or budget == 0:
        raise ValueError('limits and measurements must be nonnegative; budget must be positive')
    problems = []
    if used + peak > budget:
        problems.append(f'output budget exceeded: {used} allocated + {peak} peak > {budget} bytes')
    if free - peak < reserve:
        problems.append(f'free-space reserve exceeded: {free} free - {peak} peak < {reserve} bytes')
    return problems


def allocated_bytes(roots):
    """Count allocated blocks once per inode. Do not follow symlinks or mount points."""
    seen = set()
    total = 0
    for root in roots:
        root = Path(root)
        root_stat = root.lstat()
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError(f'output root must be an existing real directory: {root}')
        pending = [root]
        while pending:
            path = pending.pop()
            info = path.lstat()
            identity = (info.st_dev, info.st_ino)
            if identity in seen:
                continue
            if info.st_dev != root_stat.st_dev:
                raise ValueError(f'cross-device output needs its own budget: {path}')
            seen.add(identity)
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
    return total


def blob_problem(name, size, maximum, allowed):
    if name in allowed:
        return None
    if name.lower().endswith(DISK_SUFFIXES):
        return f'{name!r}: generated disk/media extension requires a recorded asset exception'
    if size > maximum:
        return f'{name!r}: {size} bytes exceeds {maximum}-byte Git blob limit'
    return None


def git_output(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60).stdout


def check_staged(root, maximum, allowed):
    root = os.fsdecode(git_output(root, 'rev-parse', '--show-toplevel').rstrip(b'\n'))
    if maximum <= 0:
        raise ValueError('Git blob limit must be positive')
    # Inspect index objects, not working files: partially staged changes stay correct.
    changed = set(git_output(root, 'diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRT').split(b'\0'))
    problems = []
    for entry in git_output(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, oid, stage = metadata.split()
        if stage != b'0':
            problems.append(f'{os.fsdecode(name)!r}: unresolved index entry')
            continue
        if name not in changed or mode == b'160000':
            continue
        size = int(git_output(root, 'cat-file', '-s', oid.decode('ascii')))
        problem = blob_problem(os.fsdecode(name), size, maximum, allowed)
        if problem:
            problems.append(problem)
    return problems


def check_tree(root, maximum, allowed):
    root = os.fsdecode(git_output(root, 'rev-parse', '--show-toplevel').rstrip(b'\n'))
    if maximum <= 0:
        raise ValueError('Git blob limit must be positive')
    problems = []
    # Inspect the current committed tree only, not unreachable/history objects.
    for entry in git_output(root, 'ls-tree', '-rlz', 'HEAD').split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, oid, size = metadata.split()
        if kind != b'blob':
            continue
        problem = blob_problem(os.fsdecode(name), int(size), maximum, allowed)
        if problem:
            problems.append(problem)
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    capacity = commands.add_parser('preflight', help='read-only allocated-output and free-space check')
    capacity.add_argument('--output', type=Path, action='append', required=True)
    capacity.add_argument('--budget-bytes', type=int, required=True)
    capacity.add_argument('--reserve-bytes', type=int, required=True)
    capacity.add_argument('--peak-bytes', type=int, required=True)
    for name, help_text in [('staged', 'inspect new/changed index blobs'), ('tree', 'inspect the complete current HEAD tree for CI')]:
        check = commands.add_parser(name, help=help_text)
        check.add_argument('--repo', type=Path, default=Path('.'))
        check.add_argument('--max-blob-bytes', type=int, default=10 * 1024 * 1024)
        check.add_argument('--allow', action='append', default=[], help='exact repo-relative asset path, justified in local policy')
    args = parser.parse_args(argv)
    try:
        if args.command in ('staged', 'tree'):
            checker = check_staged if args.command == 'staged' else check_tree
            problems = checker(args.repo, args.max_blob_bytes, set(args.allow))
        else:
            # One filesystem per invocation makes the combined peak/reserve unambiguous.
            if len({p.stat().st_dev for p in args.output}) != 1:
                raise ValueError('use a separate preflight and peak estimate for each filesystem')
            used = allocated_bytes(args.output)
            free = shutil.disk_usage(args.output[0]).free
            problems = check_capacity(used, free, args.peak_bytes, args.budget_bytes, args.reserve_bytes)
            print(f'allocated_output_bytes={used} free_bytes={free} peak_bytes={args.peak_bytes} '
                  f'budget_bytes={args.budget_bytes} reserve_bytes={args.reserve_bytes}')
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'storage check unavailable: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
