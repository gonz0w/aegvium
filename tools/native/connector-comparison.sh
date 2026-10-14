#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
[ "$(sha256 -q /var/aegvium-connector/compare.test)" = 'BINARY_SHA256' ]
printf 'COMPARISON\tos\t%s\n' "$(uname -srm)"
printf 'COMPARISON\tbinary\t%s\n' "$(sha256 -q /var/aegvium-connector/compare.test)"
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -eq 32767 ]; printf "COMPARISON\tuid\t%s\n" "$(id -u)"; cd /var/aegvium-connector; export AEGVIUM_CONNECTOR_REPEAT=owned-guest; exec ./compare.test -test.v -test.timeout=120s -test.run="^TestConnector(Wire|RuleReload)$"'
printf 'COMPARISON\tcleanup\tverified\n'
