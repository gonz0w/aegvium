#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Only inside the controller-owned disposable guest, never against a live host.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-relayd
[ "$(sha256 -q ingress.conf)" = 'PROFILE_SHA256' ]
[ "$(sha256 -q missing-protocol.conf)" = 'MISSING_SHA256' ]
[ "$(sha256 -q bad-syntax.conf)" = 'BAD_SHA256' ]
assert_absent() {
    if pgrep -x relayd >/dev/null; then
        echo 'unexpected relayd process' >&2
        exit 1
    else
        code=$?
        [ "$code" -eq 1 ]
    fi
    netstat -an -f inet > listeners.txt
    awk '$4 ~ /[.:]18080$/ && $NF == "LISTEN" { found=1 } END { exit found }' listeners.txt
    [ ! -e control.sock ]
}
assert_absent
if /usr/sbin/relayd -n -f ingress.conf > valid.log 2>&1; then
    cat valid.log
else
    code=$?
    cat valid.log
    exit "$code"
fi
printf 'RELAYD\tvalid\taccepted\n'
if /usr/sbin/relayd -n -f missing-protocol.conf > missing.log 2>&1; then
    echo 'missing protocol unexpectedly accepted' >&2
    exit 1
else
    code=$?
    cat missing.log
    [ "$code" -eq 1 ]
fi
printf 'RELAYD\tmissing-protocol\trejected\n'
if /usr/sbin/relayd -n -f bad-syntax.conf > bad.log 2>&1; then
    echo 'bad syntax unexpectedly accepted' >&2
    exit 1
else
    code=$?
    cat bad.log
    [ "$code" -eq 1 ]
fi
printf 'RELAYD\tbad-syntax\trejected\n'
assert_absent
printf 'RELAYD\tno-daemon\tverified-before-after\n'
printf 'RELAYD\tno-listener\tverified-before-after\n'
printf 'RELAYD\tno-control-socket\tverified-before-after\n'
printf 'RELAYD\tuid\t%s\n' "$(id -u)"
printf 'RELAYD\tbinary\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
printf 'RELAYD\tprofile\t%s\n' "$(sha256 -q ingress.conf)"
printf 'RELAYD\tvalid-log\t%s\n' "$(sha256 -q valid.log)"
printf 'RELAYD\tmissing-log\t%s\n' "$(sha256 -q missing.log)"
printf 'RELAYD\tbad-log\t%s\n' "$(sha256 -q bad.log)"
