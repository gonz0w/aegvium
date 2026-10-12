#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Foreground process only inside the independently owned disposable VM.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-relayd
[ "$(sha256 -q traffic.conf)" = 'TRAFFIC_PROFILE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'BINARY_SHA256' ]
if pgrep -x relayd >/dev/null; then exit 1; else code=$?; [ "$code" -eq 1 ]; fi
netstat -an -f inet > before-listeners.txt
awk '$4 ~ /[.:]1808[012]$/ && $NF == "LISTEN" { found=1 } END { exit found }' before-listeners.txt
[ ! -e control.sock ]
/usr/sbin/relayd -n -f traffic.conf
owned_pid=''
owned_alive() {
    pgrep -x relayd | awk -v target="$owned_pid" '$1 == target { found=1 } END { exit !found }'
}
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    if [ -n "$owned_pid" ]; then
        if owned_alive; then kill -TERM "$owned_pid" 2>/dev/null || true; fi
        attempt=0
        while owned_alive && [ "$attempt" -lt 10 ]; do
            attempt=$((attempt + 1))
            sleep 1
        done
        if owned_alive; then
            kill -KILL "$owned_pid" 2>/dev/null || true
        fi
        wait "$owned_pid" 2>/dev/null || true
    fi
    if pgrep -x relayd >/dev/null; then exit 1; else code=$?; [ "$code" -eq 1 ] || exit 1; fi
    netstat -an -f inet > after-listeners.txt
    awk '$4 ~ /[.:]1808[012]$/ && $NF == "LISTEN" { found=1 } END { exit found }' after-listeners.txt || exit 1
    rm -f control.sock
    [ ! -e control.sock ] || exit 1
    cat daemon.log
    printf 'TRAFFIC\tcleanup\tverified\n'
    printf 'TRAFFIC\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    exit "$prior"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
/usr/sbin/relayd -d -f traffic.conf > daemon.log 2>&1 &
owned_pid=$!
printf 'TRAFFIC\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
printf 'TRAFFIC\tprofile\t%s\n' "$(sha256 -q traffic.conf)"
printf 'TRAFFIC\tbinary\t%s\n' "$(sha256 -q /var/aegvium-lab/engine.test)"
# Expand UID and environment checks inside the unprivileged fixture shell.
# shellcheck disable=SC2016
su -m nobody -c 'set -eu; [ "$(id -u)" -ne 0 ]; printf "TRAFFIC\tuid\t%s\n" "$(id -u)"; cd /var/aegvium-lab; export AEGVIUM_RELAYD_TRAFFIC=owned-guest; exec ./engine.test -test.v -test.timeout=90s -test.run="^TestRelaydTraffic$"'
owned_alive
