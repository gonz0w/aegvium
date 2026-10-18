#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-lifecycle
[ "$(sha256 -q library.test)" = 'LIBRARY_SHA256' ]
[ "$(sha256 -q control.test)" = 'CONTROL_SHA256' ]
printf 'LIFECYCLE\tos\t%s\nLIFECYCLE\tscope\tordinary-components\n' "$(uname -srm)"
printf 'LIFECYCLE\tlibrary\t%s\nLIFECYCLE\tcontrol\t%s\n' "$(sha256 -q library.test)" "$(sha256 -q control.test)"
# No application listener, actual companion CLI, relayd, PF or WAF suite is run.
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -eq 32767 ]; cd /var/aegvium-lifecycle; printf "LIFECYCLE\tuid\t%s\n" "$(id -u)"; printf "LIFECYCLE-BEGIN library\n"; ./library.test -test.v -test.timeout=30s -test.run="LIBRARY_SELECTION"; printf "LIFECYCLE-END library\nLIFECYCLE-BEGIN control\n"; ./control.test -test.v -test.timeout=30s -test.run="CONTROL_SELECTION"; printf "LIFECYCLE-END control\nLIFECYCLE-BEGIN files\n"; ./library.test -test.v -test.timeout=30s -test.run="FILE_SELECTION"; printf "LIFECYCLE-END files\n"'
[ "$(sha256 -q library.test)" = 'LIBRARY_SHA256' ]
[ "$(sha256 -q control.test)" = 'CONTROL_SHA256' ]
printf 'LIFECYCLE\tcomplete\tverified\n'
