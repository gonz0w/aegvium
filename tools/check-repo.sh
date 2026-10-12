#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu

cd "$(dirname "$0")/.."
if [ -x .tools/venv/bin/python3 ]; then
    exec .tools/venv/bin/python3 tools/check-repo.py
fi
exec python3 tools/check-repo.py
