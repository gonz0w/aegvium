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
    for index in 1 2 3; do
        if [ -f "fixture-$index.log" ]; then
            cat "fixture-$index.log"
            printf 'WIRING\tfixture-log-%s\t%s\n' "$index" "$(sha256 -q "fixture-$index.log")"
        fi
    done
    cat daemon.log syntax.log
    printf 'WIRING\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    rm -f control.sock
    absent || exit 1
    printf 'WIRING\tcleanup\tverified\n'
    exit "$prior"
}
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
fixtures_absent() {
    if pgrep -x engine.test >/dev/null; then return 1; else code=$?; [ "$code" -eq 1 ]; fi
    netstat -an -f inet > fixture-listeners.txt
    awk '$4 ~ /[.:](1808[45]|18121)$/ && $NF=="LISTEN" { found=1 } END { exit found }' fixture-listeners.txt
}
daemon_alive() { kill -0 "$daemon_pid"; }
ack_wait() {
    aw_phase=$1; aw_operation=$2; aw_attempt=0
    while :; do
        if [ "$aw_phase" -eq 0 ]; then kill -0 "$fixture_pid"; else pgrep -x engine.test >/dev/null; fi
        if [ -f receipts/state.json ] && grep -F "\"phase\":$aw_phase,\"operation\":\"$aw_operation\"" receipts/state.json >/dev/null; then break; fi
        aw_attempt=$((aw_attempt+1)); [ "$aw_attempt" -lt 30 ]; sleep 1
    done
}
emit_ack() { printf 'WIRING\tack-%s-%s\t%s\n' "$active_gen" "$1" "$(cat receipts/state.json)"; }
start_fixture() {
    active_gen=$1
    fixtures_absent
    rm -f control/phase receipts/state.json
    # shellcheck disable=SC2016
    su -m nobody -c 'cd /var/aegvium-lab; AEGVIUM_WIRING_FIXTURE=owned-guest; export AEGVIUM_WIRING_FIXTURE; exec ./engine.test -test.v -test.timeout=260s -test.run="^TestNativeWiringFixture$"' > "fixture-$active_gen.log" 2>&1 &
    fixture_pid=$!
    ack_wait 0 startup
}
state_wait() {
    sw_label=$1; sw_state=$2; sw_attempt=0
    while :; do
        daemon_alive
        if /usr/sbin/relayctl -s control.sock show hosts > states.log 2>&1 && awk -v expected="$sw_state" '$2=="host" { count++; if ($5==expected) matched++ } END { exit !(count==1 && matched==1) }' states.log; then break; fi
        sw_attempt=$((sw_attempt+1)); [ "$sw_attempt" -lt 30 ]; sleep 1
    done
    printf 'WIRING\tstate-%s\t%s\n' "$sw_label" "$sw_state"
    printf 'WIRING\tpolls-%s\t%s\n' "$sw_label" "$sw_attempt"
}
probe() {
    pr_label=$1; pr_exit=0
    su -m nobody -c '/var/aegvium-lab-readycheck 127.0.0.1' > "checker-$pr_label.log" 2>&1 || pr_exit=$?
    [ ! -s "checker-$pr_label.log" ]
    printf 'WIRING\tchecker-exit-%s\t%s\n' "$pr_label" "$pr_exit"
    printf 'HEAD /ready HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 18085 > "direct-$pr_label.response" 2> "direct-$pr_label.error" || true
    printf 'WIRING\tdirect-%s\t%s\n' "$pr_label" "$(hexdump -v -e '1/1 "%02x"' "direct-$pr_label.response")"
}
request() {
    rq_label=$1; rq_phase=$2; rq_id=$3
    case "$rq_id" in benign) rq_path=allowed;; denied) rq_path=forbidden;; *) return 1;; esac
    printf 'GET /%s HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nX-Aegvium-Phase: %s\r\nX-Aegvium-Request: %s\r\n\r\n' "$rq_path" "$rq_phase" "$rq_id" | nc -w 3 127.0.0.1 18120 > "$rq_label-$rq_id.response" 2> "$rq_label-$rq_id.error" || true
    printf 'WIRING\trequest-%s-%s\t%s\n' "$rq_label" "$rq_id" "$(hexdump -v -e '1/1 "%02x"' "$rq_label-$rq_id.response")"
}
startup() {
    st_label="$active_gen-0"
    state_wait "$st_label" down
    probe "$st_label"
    request "$st_label" 1 benign
    emit_ack 0
}
phase() {
    ph_phase=$1; ph_operation=$2; ph_state=$3; ph_label="$active_gen-$ph_phase"
    printf '%s\t%s\n' "$ph_phase" "$ph_operation" > control/phase.tmp
    mv control/phase.tmp control/phase
    ack_wait "$ph_phase" "$ph_operation"
    state_wait "$ph_label" "$ph_state"
    probe "$ph_label"
    request "$ph_label" "$ph_phase" benign
    request "$ph_label" "$ph_phase" denied
    sleep 1
    ack_wait "$ph_phase" "$ph_operation"
    emit_ack "$ph_phase"
}
stop_fixture() {
    sf_phase=$1
    printf '%s\tstop\n' "$sf_phase" > control/phase.tmp
    mv control/phase.tmp control/phase
    sf_attempt=0
    while ! grep -F "\"phase\":$sf_phase,\"operation\":\"stop\"" receipts/state.json >/dev/null; do sf_attempt=$((sf_attempt+1)); [ "$sf_attempt" -lt 10 ]; sleep 1; done
    wait "$fixture_pid"
    fixture_pid=''
    emit_ack "$sf_phase"
    fixtures_absent
    daemon_alive
    printf 'WIRING\tfixture-exit-%s\t0\n' "$active_gen"
    printf 'WIRING\tfixture-absence-%s\tverified\n' "$active_gen"
}
gap() {
    gp_label="gap-$active_gen"
    fixtures_absent
    state_wait "$gp_label" down
    probe "$gp_label"
    request "$gp_label" 1 benign
    printf 'WIRING\tgap-ack-%s\t%s\n' "$active_gen" "$(cat receipts/state.json)"
    daemon_alive
}
start_fixture 1
/usr/sbin/relayd -d -f profile.conf > daemon.log 2>&1 &
daemon_pid=$!
startup
phase 1 ready up
phase 2 health-refused down
stop_fixture 3
gap
start_fixture 2
startup
phase 1 ready up
cp receipts/state.json before-crash.json
pgrep -x engine.test > victim.pids
[ "$(wc -l < victim.pids | tr -d ' ')" -eq 1 ]
victim=$(cat victim.pids)
victim_uid=$(ps -o uid= -p "$victim" | tr -d ' ')
[ "$victim_uid" = "$(id -u nobody)" ]
# Bound ancestry to this exact launched fixture child before signaling it.
cursor=$victim
ancestry=0
while [ "$cursor" != "$fixture_pid" ]; do
    ancestry=$((ancestry+1)); [ "$ancestry" -le 4 ]
    cursor=$(ps -o ppid= -p "$cursor" | tr -d ' ')
    [ "$cursor" -gt 1 ]
done
printf 'WIRING\tcrash-owned-2\tverified\n'
printf 'WIRING\tcrash-victim-uid-2\t%s\n' "$victim_uid"
kill -KILL "$victim"
printf 'WIRING\tcrash-injection-2\tSIGKILL\n'
crash_wait=0
wait "$fixture_pid" || crash_wait=$?
fixture_pid=''
[ "$crash_wait" -gt 0 ] && [ "$crash_wait" -ne 127 ] && [ "$crash_wait" -le 255 ]
printf 'WIRING\tcrash-wait-2\t%s\n' "$crash_wait"
fixtures_absent
printf 'WIRING\tfixture-absence-2\tverified\n'
printf 'WIRING\tbefore-crash-2\t%s\n' "$(cat before-crash.json)"
printf 'WIRING\tafter-crash-2\t%s\n' "$(cat receipts/state.json)"
gap
start_fixture 3
startup
phase 1 ready up
stop_fixture 2
daemon_alive
printf 'WIRING\tdaemon-continuity\tverified\n'
