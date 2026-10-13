#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Root supervisor only inside the owned isolated guest; no application traffic.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-contract
[ "$(sha256 -q profile.conf)" = 'CONTRACT_PROFILE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-readycheck)" = 'CHECKER_SHA256' ]
assert_absent() {
    if pgrep -x relayd >/dev/null; then exit 1; else code=$?; [ "$code" -eq 1 ]; fi
    netstat -an -f inet > listeners.txt
    awk '$4 ~ /[.:](1808[456789]|1809[01])$/ && $NF == "LISTEN" { found=1 } END { exit found }' listeners.txt
    [ ! -e control.sock ]
}
assert_absent
[ ! -e missing.sh ]
expected_uid=$(id -u _relayd)
[ "$expected_uid" -ne 0 ]
mkdir uid
chown _relayd uid
chmod 700 uid
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
        while owned_alive && [ "$attempt" -lt 10 ]; do attempt=$((attempt + 1)); sleep 1; done
        if owned_alive; then kill -KILL "$owned_pid" 2>/dev/null || true; fi
        wait "$owned_pid" 2>/dev/null || true
    fi
    rm -f control.sock
    assert_absent || exit 1
    [ ! -e states.log ] || cat states.log
    [ ! -e syntax.log ] || cat syntax.log
    cat daemon.log
    printf 'CONTRACT\tcleanup\tverified\n'
    printf 'CONTRACT\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    exit "$prior"
}
: > daemon.log
trap cleanup EXIT
trap 'exit 1' INT TERM
/usr/sbin/relayd -n -f profile.conf > syntax.log 2>&1
printf 'CONTRACT\tsyntax\taccepted\n'
/usr/sbin/relayd -d -f profile.conf > daemon.log 2>&1 &
owned_pid=$!
attempt=0
while :; do
    owned_alive
    if /usr/sbin/relayctl -s control.sock show hosts > states.log 2>&1 && awk '
        $2 == "table" { split($3, parts, ":"); current=parts[1] }
        $2 == "host" { states[current]=$5 }
        END { exit !(states["up"]=="up" && states["down"]=="down" && states["positive"]=="up" && states["signal"]=="down" && states["missing"]=="down" && states["checker"]=="down") }
    ' states.log; then break; fi
    attempt=$((attempt + 1))
    [ "$attempt" -lt 30 ]
    sleep 1
done
[ -S control.sock ]
for name in up down positive signal; do
    [ "$(cat "uid/$name")" = "$expected_uid" ]
done
printf 'CONTRACT\tup\tup\n'
printf 'CONTRACT\tdown\tdown\n'
printf 'CONTRACT\tpositive\tup\n'
printf 'CONTRACT\tsignal\tdown\n'
printf 'CONTRACT\tmissing\tdown\n'
printf 'CONTRACT\tchecker\tdown\n'
printf 'CONTRACT\tscript-uid\t%s\n' "$expected_uid"
printf 'CONTRACT\tprofile\t%s\n' "$(sha256 -q profile.conf)"
printf 'CONTRACT\tchecker-sha\t%s\n' "$(sha256 -q /var/aegvium-lab-readycheck)"
printf 'CONTRACT\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
printf 'CONTRACT\tstates-log\t%s\n' "$(sha256 -q states.log)"
printf 'CONTRACT\tsyntax-log\t%s\n' "$(sha256 -q syntax.log)"
