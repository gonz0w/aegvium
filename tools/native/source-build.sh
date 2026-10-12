#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Controller-owned disposable guest only.
set -eu
export GOTELEMETRY=off GOTOOLCHAIN=local GOENV=off GOWORK=off
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-build
[ "$(sha256 -q go.tar.gz)" = 'COMPILER_SHA256' ]
[ "$(sha256 -q source.tar.gz)" = 'SOURCE_SHA256' ]
tar -xzf go.tar.gz
tar -xzf source.tar.gz
chown -R root:wheel go src
chmod -R a+rX go src
mkdir output
chown nobody output
chmod 700 output
[ "$(go/bin/go env GOVERSION)" = 'go1.27.2' ]
[ "$(go/bin/go env GOOS)" = 'openbsd' ]
[ "$(go/bin/go env GOARCH)" = 'amd64' ]
printf 'BUILD\tcompiler\t%s\n' "$(sha256 -q go/bin/go)"
printf 'BUILD\tsource\t%s\n' "$(sha256 -q source.tar.gz)"
# Shell expansion and build identity checks run as the unprivileged user.
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; umask 077; [ "$(id -u)" -ne 0 ]; cd /var/aegvium-build/src; export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOMAXPROCS=2 GOOS=openbsd GOARCH=amd64 GOAMD64=v1; export GOFLAGS=""; export GOCACHE=/var/aegvium-build/output/cache GOPATH=/var/aegvium-build/output/gopath TMPDIR=/var/aegvium-build/output; printf "BUILD\tuid\t%s\n" "$(id -u)"; /var/aegvium-build/go/bin/go test -mod=vendor -p=2 -c -o /var/aegvium-build/output/engine.test'
printf 'BUILD\tbinary\t%s\n' "$(sha256 -q output/engine.test)"
