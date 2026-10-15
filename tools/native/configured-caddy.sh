#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
[ "$(sha256 -q /var/aegvium-connector/compare.test)" = 'BINARY_SHA256' ]
mkdir /var/aegvium-configured-caddy
chown nobody /var/aegvium-configured-caddy
chmod 700 /var/aegvium-configured-caddy
printf 'CONFIGURED\tos\t%s\nCONFIGURED\tbinary\t%s\n' "$(uname -srm)" "$(sha256 -q /var/aegvium-connector/compare.test)"
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -eq 32767 ]; printf "CONFIGURED\tuid\t%s\n" "$(id -u)"; cd /var/aegvium-configured-caddy; export AEGVIUM_CONNECTOR_REPEAT=owned-guest AEGVIUM_CADDY_LOG_DIR=/var/aegvium-configured-caddy; exec /var/aegvium-connector/compare.test -test.v -test.timeout=150s -test.run="^TestConfiguredCaddyTLS$"'
printf 'CONFIGURED\tcleanup\tverified\n'
