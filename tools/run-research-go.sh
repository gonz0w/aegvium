#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
export GOTOOLCHAIN=local
export GOCACHE="$root/.tools/go-cache"
expected="go$(cat "$root/.go-version")"
actual=$("$root/.tools/go/bin/go" env GOVERSION)
[ "$actual" = "$expected" ] || { echo 'Run make research-tools for the pinned Go version' >&2; exit 1; }
exec "$root/.tools/go/bin/go" "$@"
