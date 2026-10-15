#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Controller-owned disposable guest only; the comparison remains research.
set -eu
export GOTELEMETRY=off GOTOOLCHAIN=local GOENV=off GOWORK=off
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-connector-build
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
printf 'CBUILD\tos\t%s\nCBUILD\tversion\t%s\nCBUILD\tcompiler\t%s\nCBUILD\tsource\t%s\n' "$(uname -srm)" "$(go/bin/go env GOVERSION)" "$(sha256 -q go/bin/go)" "$(sha256 -q source.tar.gz)"
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; umask 077; [ "$(id -u)" -eq 32767 ]; cd /var/aegvium-connector-build/src; export GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOMAXPROCS=2 GOOS=openbsd GOARCH=amd64 GOAMD64=v1; export GOFLAGS=""; export GOCACHE=/var/aegvium-connector-build/output/cache GOPATH=/var/aegvium-connector-build/output/gopath TMPDIR=/var/aegvium-connector-build/output; printf "CBUILD\tuid\t%s\n" "$(id -u)"; /var/aegvium-connector-build/go/bin/go test -mod=vendor -p=2 -c -o /var/aegvium-connector-build/output/compare.test'
printf 'CBUILD\tbinary\t%s\n' "$(sha256 -q output/compare.test)"
