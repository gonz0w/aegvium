#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Require the author identity's DCO trailer on every contributor commit."""
import re
import subprocess
import sys

if len(sys.argv) != 3:
    sys.exit("usage: check-dco.py BASE_SHA HEAD_SHA")
base, head = sys.argv[1:]
if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (base, head)):
    sys.exit("Commit ranges must be full SHA-1 object IDs")
commits = subprocess.check_output(["git", "rev-list", f"{base}..{head}"], text=True).splitlines()
if not commits:
    sys.exit("No contributor commits found in the PR range")
failed = []
for commit in commits:
    record = subprocess.check_output(["git", "show", "-s", "--format=%an <%ae>%n%B", commit], text=True)
    author, body = record.split("\n", 1)
    trailers = subprocess.check_output(["git", "interpret-trailers", "--parse"], input=body, text=True)
    signoffs = [line.split(":", 1)[1].strip().casefold() for line in trailers.splitlines()
                if line.casefold().startswith("signed-off-by:")]
    if author.casefold() not in signoffs:
        failed.append(commit)
if failed:
    sys.exit("Missing author DCO sign-off: " + ", ".join(failed))
print(f"DCO passed for {len(commits)} contributor commits")
