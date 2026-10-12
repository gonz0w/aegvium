#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Only the controller-owned disposable guest; no live host target.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'BINARY_SHA256' ]
[ "$(id -u nobody)" -ne 0 ]
printf 'RECEIPT\tos\t%s\n' "$(uname -srm)"
printf 'RECEIPT\tbinary\t%s\n' "$(sha256 -q /var/aegvium-lab/engine.test)"
printf 'RECEIPT\tkernel\t%s\n' "$(uname -v)"
printf 'RECEIPT\tkernel_sha256\t%s\n' "$(sha256 -q /bsd)"
printf 'RECEIPT\tpatches\t%s\n' "$(syspatch -l | paste -sd , -)"
# Expand identity checks inside the unprivileged shell.
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -ne 0 ]; printf "RECEIPT\tuid\t%s\n" "$(id -u)"; cd /var/aegvium-lab; exec ./engine.test -test.v -test.timeout=120s -test.run="^(TestPinnedCRSSmoke|TestRequestInterruption|TestInvalidRulesRejected|TestBodyReadFailure|TestExplicitInspectionError)$"'
