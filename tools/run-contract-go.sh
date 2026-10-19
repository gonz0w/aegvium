#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
task_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
task_go="$task_root/.tools/go/bin/go"
expected="go$(cat "$task_root/.go-version")"
[ -x "$task_go" ] || { echo 'Run make research-tools for the existing pinned development toolchain.' >&2; exit 1; }
[ "$("$task_go" env GOVERSION)" = "$expected" ] || { echo 'Go toolchain pin mismatch.' >&2; exit 1; }
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOMAXPROCS=2 GOFLAGS=-mod=readonly
export GOPROXY=off GOSUMDB=off
export GOCACHE="$task_root/.tools/contract-go-cache"
export GOMODCACHE="$task_root/.tools/contract-mod-cache"
exec "$task_go" "$@"
