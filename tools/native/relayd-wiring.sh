#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Owned isolated OpenBSD guest only; fixture traffic never leaves loopback.
set -eu
umask 022
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-wiring
[ "$(sha256 -q profile.conf)" = 'PROFILE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'ENGINE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-readycheck)" = 'CHECKER_SHA256' ]
absent() {
    for name in relayd engine.test; do
        if pgrep -x "$name" >/dev/null; then return 1; else code=$?; [ "$code" -eq 1 ]; fi
    done
    netstat -an -f inet > listeners.txt
    awk '$4 ~ /[.:](1808[45]|1812[01])$/ && $NF=="LISTEN" { found=1 } END { exit found }' listeners.txt
    [ ! -e control.sock ]
}
absent
mkdir control receipts
chmod 755 control
chown nobody receipts
chmod 700 receipts
fixture_pid=''
daemon_pid=''
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    # Only this fixture can own engine.test: preflight required its absence.
    printf '16\tstop\n' > control/phase.tmp
    mv control/phase.tmp control/phase
    if [ -n "$daemon_pid" ]; then kill -TERM "$daemon_pid" 2>/dev/null || true; fi
    attempt=0
    while { pgrep -x relayd >/dev/null || pgrep -x engine.test >/dev/null; } && [ "$attempt" -lt 10 ]; do attempt=$((attempt+1)); sleep 1; done
    for name in relayd engine.test; do
        if pgrep -x "$name" > remaining.pids; then
            while read -r pid; do kill -KILL "$pid" 2>/dev/null || true; done < remaining.pids
            prior=1
        fi
    done
    if [ -n "$daemon_pid" ]; then wait "$daemon_pid" 2>/dev/null || true; fi
    if [ -n "$fixture_pid" ]; then wait "$fixture_pid" 2>/dev/null || true; fi
    [ ! -f receipts/state.json ] || printf 'WIRING\tfinal-ack\t%s\n' "$(cat receipts/state.json)"
    [ ! -f states.log ] || cat states.log
    cat fixture.log daemon.log syntax.log
    printf 'WIRING\tfixture-log\t%s\n' "$(sha256 -q fixture.log)"
    printf 'WIRING\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    rm -f control.sock
    absent || exit 1
    printf 'WIRING\tcleanup\tverified\n'
    exit "$prior"
}
: > fixture.log
: > daemon.log
: > syntax.log
trap cleanup EXIT
trap 'exit 1' INT TERM
printf 'WIRING\tprofile\t%s\n' "$(sha256 -q profile.conf)"
printf 'WIRING\tengine\t%s\n' "$(sha256 -q /var/aegvium-lab/engine.test)"
printf 'WIRING\tchecker\t%s\n' "$(sha256 -q /var/aegvium-lab-readycheck)"
printf 'WIRING\tuid\t%s\n' "$(id -u nobody)"
printf 'WIRING\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
/usr/sbin/relayd -n -f profile.conf > syntax.log 2>&1
printf 'WIRING\tsyntax\taccepted\n'
# shellcheck disable=SC2016
su -m nobody -c 'cd /var/aegvium-lab; AEGVIUM_WIRING_FIXTURE=owned-guest; export AEGVIUM_WIRING_FIXTURE; exec ./engine.test -test.v -test.timeout=260s -test.run="^TestNativeWiringFixture$"' > fixture.log 2>&1 &
fixture_pid=$!
ack_wait() {
    phase=$1
    operation=$2
    attempt=0
    while :; do
        if [ "$phase" -ne 0 ]; then pgrep -x engine.test >/dev/null; else kill -0 "$fixture_pid"; fi
        if [ -f receipts/state.json ] && grep -F "\"phase\":$phase,\"operation\":\"$operation\"" receipts/state.json >/dev/null; then break; fi
        attempt=$((attempt+1)); [ "$attempt" -lt 30 ]; sleep 1
    done
}
ack_wait 0 startup
printf 'WIRING\tack-0\t%s\n' "$(cat receipts/state.json)"
/usr/sbin/relayd -d -f profile.conf > daemon.log 2>&1 &
daemon_pid=$!
for phase in 1 2 3 4 5; do
    case "$phase" in 1|3) operation=down; state=down;; 2|4) operation=ready; state=up;; 5) operation=close; state=down;; esac
    printf '%s\t%s\n' "$phase" "$operation" > control/phase.tmp
    mv control/phase.tmp control/phase
    ack_wait "$phase" "$operation"
    attempt=0
    while :; do
        kill -0 "$daemon_pid"
        pgrep -x engine.test >/dev/null
        if /usr/sbin/relayctl -s control.sock show hosts > states.log 2>&1 && awk -v expected="$state" '$2=="host" { count++; if ($5==expected) matched++ } END { exit !(count==1 && matched==1) }' states.log; then break; fi
        attempt=$((attempt+1)); [ "$attempt" -lt 30 ]; sleep 1
    done
    printf 'WIRING\tstate-%s\t%s\n' "$phase" "$state"
    printf 'WIRING\tpolls-%s\t%s\n' "$phase" "$attempt"
    printf 'HEAD /ready HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 18085 > "direct-$phase.response"
    printf 'WIRING\tdirect-%s\t%s\n' "$phase" "$(hexdump -v -e '1/1 "%02x"' "direct-$phase.response")"
    for request in benign denied; do
        case "$request" in benign) path=allowed;; denied) path=forbidden;; esac
        printf 'GET /%s HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: %s\r\nX-Aegvium-Request: %s\r\n\r\n' "$path" "$phase" "$request" | nc -w 3 127.0.0.1 18120 > "$phase-$request.response" 2> "$phase-$request.error" || true
        printf 'WIRING\trequest-%s-%s\t%s\n' "$phase" "$request" "$(hexdump -v -e '1/1 "%02x"' "$phase-$request.response")"
    done
    if [ "$phase" -eq 2 ]; then
        printf 'HEAD /ready HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 18084 > bare.response 2> bare.error || true
        printf 'WIRING\tbare\t%s\n' "$(hexdump -v -e '1/1 "%02x"' bare.response)"
    fi
    sleep 1
    ack_wait "$phase" "$operation"
    printf 'WIRING\tack-%s\t%s\n' "$phase" "$(cat receipts/state.json)"
done
printf '6\tstop\n' > control/phase.tmp
mv control/phase.tmp control/phase
attempt=0
while ! grep -F '"phase":6,"operation":"stop"' receipts/state.json >/dev/null; do attempt=$((attempt+1)); [ "$attempt" -lt 10 ]; sleep 1; done
wait "$fixture_pid"
fixture_pid=''
printf 'WIRING\tack-6\t%s\n' "$(cat receipts/state.json)"
printf 'WIRING\tfixture-exit\t0\n'
