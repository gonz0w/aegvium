#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-lab-request-wire
[ "$(sha256 -q profile.conf)" = 'PROFILE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'ENGINE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-proxy)" = 'PROGRAM_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-readycheck)" = 'CHECKER_SHA256' ]
if pgrep -x relayd >/dev/null; then exit 1; else [ "$?" -eq 1 ]; fi
netstat -an -f inet > before.txt
awk '$4 ~ /[.:](1808[4567]|18120)$/ && $NF == "LISTEN" {found=1} END {exit found}' before.txt
[ ! -e control.sock ]
[ ! -e /etc/ssl/private/aegvium-lab.key ]
[ ! -e /etc/ssl/aegvium-lab.crt ]
owned_pid=''
alive() { pgrep -x relayd | awk -v pid="$owned_pid" '$1 == pid {found=1} END {exit !found}'; }
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    if [ -n "$owned_pid" ]; then
        if alive; then kill -TERM "$owned_pid"; fi
        attempt=0
        while alive && [ "$attempt" -lt 10 ]; do attempt=$((attempt+1)); sleep 1; done
        if alive; then kill -KILL "$owned_pid"; prior=1; fi
        wait "$owned_pid" 2>/dev/null || true
    fi
    [ ! -e /etc/ssl/private/aegvium-lab.key ] && [ ! -e /etc/ssl/aegvium-lab.crt ] && [ ! -e tls.cnf ] || exit 1
    if pgrep -x relayd >/dev/null; then exit 1; else [ "$?" -eq 1 ]; fi
    netstat -an -f inet > after.txt
    awk '$4 ~ /[.:](1808[4567]|18120)$/ && $NF == "LISTEN" {found=1} END {exit found}' after.txt || exit 1
    rm -f control.sock
    [ ! -e control.sock ] || exit 1
    printf 'TLSLAB\tcleanup\tverified\n'
    printf 'TLSLAB\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    exit "$prior"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
/usr/sbin/relayd -n -f profile.conf
printf 'TLSLAB\tsyntax\taccepted\n'
/usr/sbin/relayd -d -f profile.conf > daemon.log 2>&1 &
owned_pid=$!
printf 'TLSLAB\tengine\t%s\n' "$(sha256 -q /var/aegvium-lab/engine.test)"
printf 'TLSLAB\tprogram\t%s\n' "$(sha256 -q /var/aegvium-lab-proxy)"
printf 'TLSLAB\tchecker\t%s\n' "$(sha256 -q /var/aegvium-lab-readycheck)"
printf 'TLSLAB\tprofile\t%s\n' "$(sha256 -q profile.conf)"
printf 'TLSLAB\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -eq 32767 ]; printf "TLSLAB\tuid\t%s\n" "$(id -u)"; cd /var/aegvium-lab; export AEGVIUM_LAB_REQUEST_WIRE=owned-guest; exec ./engine.test -test.v -test.timeout=120s -test.run="^TestLabRequestWireNative$"'
alive
