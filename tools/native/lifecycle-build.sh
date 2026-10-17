#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Offline compilation only, in the independently owned disposable guest.
set -eu
export GOTELEMETRY=off GOTOOLCHAIN=local GOENV=off GOWORK=off
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-lifecycle-build
[ "$(sha256 -q go.tar.gz)" = 'COMPILER_SHA256' ]
[ "$(sha256 -q source.tar.gz)" = 'SOURCE_SHA256' ]
tar -xzf go.tar.gz
tar -xzf source.tar.gz
chown -R root:wheel go src
chmod -R a+rX go src
[ "$(sha256 -q go/bin/go)" = 'EXECUTABLE_SHA256' ]
[ "$(go/bin/go env GOVERSION)" = 'go1.27.2' ]
[ "$(go/bin/go env GOOS)" = 'openbsd' ]
[ "$(go/bin/go env GOARCH)" = 'amd64' ]
mkdir output
chown nobody output
chmod 700 output
# -c compiles test executables without running any tests or application main.
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; umask 077; [ "$(id -u)" -eq 32767 ]; cd /var/aegvium-lifecycle-build/src; export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOMAXPROCS=2 GOOS=openbsd GOARCH=amd64 GOAMD64=v1; export GOFLAGS=""; export GOCACHE=/var/aegvium-lifecycle-build/output/cache GOPATH=/var/aegvium-lifecycle-build/output/gopath TMPDIR=/var/aegvium-lifecycle-build/output; printf "LCBUILD\tuid\t%s\n" "$(id -u)"; /var/aegvium-lifecycle-build/go/bin/go test -mod=vendor -p=2 -c -o /var/aegvium-lifecycle-build/output/library.test .; /var/aegvium-lifecycle-build/go/bin/go test -mod=vendor -p=2 -c -o /var/aegvium-lifecycle-build/output/control.test ./cmd/labproxy'
[ "$(sha256 -q go/bin/go)" = 'EXECUTABLE_SHA256' ]
[ "$(sha256 -q source.tar.gz)" = 'SOURCE_SHA256' ]
printf 'LCBUILD\tos\t%s\nLCBUILD\tversion\tgo1.27.2\n' "$(uname -srm)"
printf 'LCBUILD\tcompiler\t%s\nLCBUILD\tsource\t%s\n' "$(sha256 -q go/bin/go)" "$(sha256 -q source.tar.gz)"
printf 'LCBUILD\tlibrary\t%s\nLCBUILD\tcontrol\t%s\n' "$(sha256 -q output/library.test)" "$(sha256 -q output/control.test)"
