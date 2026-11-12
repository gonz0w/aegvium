#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Local allocation gate; no deletion or native execution."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('local_storage_guard', Path(__file__).with_name('storage_guard.py'))
_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_guard)


def preflight(outputs, image=False, image_budget=None, image_peak=None):
    roots = [Path(p).resolve(strict=True) for p in outputs]
    if not roots or len({p.stat().st_dev for p in roots}) != 1:
        raise ValueError('list existing outputs on one filesystem per preflight')
    used = _guard.allocated_bytes(roots)
    capacity = shutil.disk_usage(roots[0])
    free = capacity.free
    reserve = min(200_000_000_000, capacity.total // 10)
    if image and (image_budget is None or image_peak is None or image_budget <= 0 or image_peak <= 0):
        raise ValueError("image generation requires an explicit reviewed budget and peak")
    peak, budget = (image_peak, image_budget) if image else (2_000_000_000, 20_000_000_000)
    problems = _guard.check_capacity(used, free, peak, budget, reserve)
    print(f'allocated_output_bytes={used} free_bytes={free} peak_bytes={peak} budget_bytes={budget}')
    if problems:
        raise ValueError('; '.join(problems))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', action='store_true')
    parser.add_argument('--image-budget-bytes', type=int)
    parser.add_argument('--image-peak-bytes', type=int)
    parser.add_argument('--output', type=Path, action='append', help='additional external output on the same filesystem')
    args = parser.parse_args(argv)
    try:
        output = ROOT / '.tools'
        output.mkdir(exist_ok=True)
        preflight([output, *(args.output or [])], args.image, args.image_budget_bytes, args.image_peak_bytes)
        return 0
    except (OSError, ValueError) as error:
        print(f'storage preflight refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
