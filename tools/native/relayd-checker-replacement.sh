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
mkdir control receipts checker-uid
chown _relayd checker-uid
chmod 700 checker-uid
cp /var/aegvium-lab-readycheck readycheck.saved
chmod 555 readycheck.saved
[ "$(sha256 -q exit2.sh)" = 'REPLACEMENT_SHA256' ]
expected_uid=$(id -u _relayd)
[ "$expected_uid" -ne 0 ]
chmod 755 control
chown nobody receipts
chmod 700 receipts
fixture_pid=''
daemon_pid=''
restore_checker() {
    cp readycheck.saved /var/aegvium-lab-readycheck.new || return 1
    chmod 555 /var/aegvium-lab-readycheck.new || return 1
    mv /var/aegvium-lab-readycheck.new /var/aegvium-lab-readycheck || return 1
    [ "$(stat -f '%u:%Lp' /var/aegvium-lab-readycheck)" = '0:555' ] || return 1
    [ "$(sha256 -q /var/aegvium-lab-readycheck)" = 'CHECKER_SHA256' ]
}
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    restore_checker || prior=1
    printf 'WIRING\tchecker-restored-owner-mode\t%s\n' "$(stat -f '%u:%Lp' /var/aegvium-lab-readycheck)"
    printf 'WIRING\tchecker-restored\t%s\n' "$(sha256 -q /var/aegvium-lab-readycheck)"
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
printf 'WIRING\treplacement\t%s\n' "$(sha256 -q exit2.sh)"
printf 'WIRING\texpected-script-uid\t%s\n' "$expected_uid"
printf 'WIRING\tuid\t%s\n' "$(id -u nobody)"
printf 'WIRING\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
/usr/sbin/relayd -n -f profile.conf > syntax.log 2>&1
printf 'WIRING\tsyntax\taccepted\n'
# shellcheck disable=SC2016
su -m nobody -c 'cd /var/aegvium-lab; AEGVIUM_WIRING_FIXTURE=owned-guest; AEGVIUM_WIRING_FAULTS=owned-guest; export AEGVIUM_WIRING_FIXTURE AEGVIUM_WIRING_FAULTS; exec ./engine.test -test.v -test.timeout=380s -test.run="^TestNativeWiringFixture$"' > fixture.log 2>&1 &
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
state_read() {
    /usr/sbin/relayctl -s control.sock show hosts > states.log 2>&1
    awk '$2=="host" { count++; state=$5 } END { if (count!=1 || (state!="up" && state!="down")) exit 1; print state }' states.log
}
request() {
    phase=$1; id=$2; port=$3
    if [ "$port" -eq 18084 ]; then prefix='PROXY TCP4 127.0.0.1 127.0.0.1 12345 18120'; else prefix=''; fi
    { [ -z "$prefix" ] || printf '%s\r\n' "$prefix"
      printf 'GET /allowed HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: %s\r\nX-Aegvium-Request: %s\r\n\r\n' "$phase" "$id"
    } | nc -w 3 127.0.0.1 "$port" > "$phase-$id.response" 2> "$phase-$id.error" || true
    printf 'WIRING\trequest-%s-%s\t%s\n' "$phase" "$id" "$(hexdump -v -e '1/1 "%02x"' "$phase-$id.response")"
}
for phase in 1 2 3 4 5 6 7; do
    case "$phase" in 1|3|7) operation=ready; state=up; mode=original;; 2) operation=ready; state=down; mode=missing;; 4|6) operation=health-silent; state=down; mode=original;; 5) operation=health-silent; state=up; mode=exit2;; esac
    case "$mode" in
        original) restore_checker; digest=$(sha256 -q /var/aegvium-lab-readycheck);;
        missing) rm /var/aegvium-lab-readycheck; [ ! -e /var/aegvium-lab-readycheck ]; digest=absent;;
        exit2) cp exit2.sh /var/aegvium-lab-readycheck.new; chmod 555 /var/aegvium-lab-readycheck.new; mv /var/aegvium-lab-readycheck.new /var/aegvium-lab-readycheck; digest=$(sha256 -q /var/aegvium-lab-readycheck); [ "$digest" = 'REPLACEMENT_SHA256' ];;
    esac
    if [ "$mode" != missing ]; then [ "$(stat -f '%u:%Lp' /var/aegvium-lab-readycheck)" = '0:555' ]; fi
    printf 'WIRING\tchecker-mode-%s\t%s\n' "$phase" "$mode"
    printf 'WIRING\tchecker-path-%s\t%s\n' "$phase" "$digest"
    printf '%s\t%s\n' "$phase" "$operation" > control/phase.tmp
    mv control/phase.tmp control/phase
    ack_wait "$phase" "$operation"
    attempt=0
    while :; do
        kill -0 "$daemon_pid"
        pgrep -x engine.test >/dev/null
        [ "$(state_read)" != "$state" ] || break
        attempt=$((attempt+1)); [ "$attempt" -lt 30 ]; sleep 1
    done
    printf 'WIRING\tstate-%s\t%s\n' "$phase" "$state"
    printf 'WIRING\tpolls-%s\t%s\n' "$phase" "$attempt"
    if [ "$mode" = exit2 ]; then
        # No direct control has invoked this script yet: this is the stock check's UID.
        [ "$(cat checker-uid/exit2)" = "$expected_uid" ]
        printf 'WIRING\treplacement-script-uid\t%s\n' "$(cat checker-uid/exit2)"
    fi
    checker_exit=0
    su -m _relayd -c '/var/aegvium-lab-readycheck 127.0.0.1' > "checker-$phase.log" 2>&1 || checker_exit=$?
    if [ "$mode" = missing ]; then [ -s "checker-$phase.log" ]; output=launch-error; else [ ! -s "checker-$phase.log" ]; output=silent; fi
    original_exit=0
    su -m _relayd -c '/var/aegvium-wiring/readycheck.saved 127.0.0.1' > "original-$phase.log" 2>&1 || original_exit=$?
    [ ! -s "original-$phase.log" ]
    printf 'WIRING\toriginal-exit-%s\t%s\n' "$phase" "$original_exit"
    printf 'WIRING\tchecker-exit-%s\t%s\n' "$phase" "$checker_exit"
    printf 'WIRING\tchecker-output-%s\t%s\n' "$phase" "$output"
    printf 'WIRING\tchecker-log-%s\t%s\n' "$phase" "$(sha256 -q "checker-$phase.log")"
    printf 'HEAD /ready HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 18085 > "direct-$phase.response" 2> "direct-$phase.error" || true
    printf 'WIRING\tdirect-%s\t%s\n' "$phase" "$(hexdump -v -e '1/1 "%02x"' "direct-$phase.response")"
    request "$phase" benign 18120
    if [ "$state" = down ]; then request "$phase" witness 18084; fi
    sleep 1
    ack_wait "$phase" "$operation"
    printf 'WIRING\tack-%s\t%s\n' "$phase" "$(cat receipts/state.json)"
done
printf '8\tstop\n' > control/phase.tmp
mv control/phase.tmp control/phase
attempt=0
while ! grep -F '"phase":8,"operation":"stop"' receipts/state.json >/dev/null; do attempt=$((attempt+1)); [ "$attempt" -lt 10 ]; sleep 1; done
wait "$fixture_pid"
fixture_pid=''
printf 'WIRING\tack-8\t%s\n' "$(cat receipts/state.json)"
printf 'WIRING\tfixture-exit\t0\n'
