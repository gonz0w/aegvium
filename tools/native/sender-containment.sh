#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Nonce-bound, root-only controller for ONE disposable guest. Never a service.
set -eu
preflight_step=identity
preflight_exit() {
    preflight_status=$1
    if [ "$preflight_status" -ne 0 ]; then
        printf 'SENDER-PREFLIGHT-FAIL\t%s\t%s\n' "$preflight_step" "$preflight_status" >&2
    fi
    exit "$preflight_status"
}
trap 'preflight_exit $?' EXIT
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-lab-sender
[ "$(stat -f '%u:%Lp' .)" = '0:700' ]
[ ! -L .owned ] && [ "$(stat -f '%u:%Lp' .owned)" = '0:400' ]
[ "$(sha256 -q .owned)" = 'MARKER_SHA256' ]
[ "$(sha256 -q open.pf)" = 'OPEN_SHA256' ]
[ "$(sha256 -q protected.pf)" = 'PROTECTED_SHA256' ]
[ "$(sha256 -q profile.conf)" = 'PROFILE_SHA256' ]
[ "$(id -u _relayd)" = 'RELAY_UID' ]
[ "$(id -u nobody)" = 32767 ]
relay_uid='RELAY_UID'
[ "$relay_uid" -gt 0 ] && [ "$relay_uid" -ne 32767 ]
umask 077
snapshot() {
    destination=$1
    /sbin/pfctl -sr > "$destination.rules"
    /sbin/pfctl -s Interfaces -v > "$destination.interfaces"
    /sbin/pfctl -s timeouts > "$destination.timeouts"
    /sbin/pfctl -s memory > "$destination.memory"
    /sbin/pfctl -s Anchors > "$destination.anchors"
    /sbin/pfctl -s Tables > "$destination.tables"
    sha256 -q /etc/pf.conf > "$destination.config"
    /sbin/pfctl -s info | awk '$1 == "Status:" {print $2}' > "$destination.enabled"
    grep -Eq '^(Enabled|Disabled)$' "$destination.enabled"
}
compare() {
    for view in rules interfaces timeouts memory anchors tables config enabled; do
        cmp -s "before.$view" "$1.$view" || return 1
    done
}
case ${AEGVIUM_SENDER_STAGE:-} in
preflight)
    [ ! -e before.rules ]
    preflight_step=snapshot
    snapshot before
    preflight_step=initial-state
    [ ! -s before.anchors ] && [ ! -s before.tables ]
    awk '/\(skip\)/ && $1 != "lo0" && $1 != "lo" {bad=1} END {exit bad}' before.interfaces
    : > restore.pf
    skipped=$(awk '/\(skip\)/ {print $1}' before.interfaces)
    if printf '%s\n' "$skipped" | grep -qx lo; then
        ifconfig -g lo > loopback-members
        [ "$(cat loopback-members)" = lo0 ]
    fi
    if [ -n "$skipped" ]; then
        printf 'set skip on { %s }\n' "$(printf '%s\n' "$skipped" | tr '\n' ' ')" >> restore.pf
    fi
    cat before.rules >> restore.pf
    for policy in open protected; do
        preflight_step=syntax-$policy
        /sbin/pfctl -o none -nvf "$policy.pf" > "$policy.syntax-out" 2> "$policy.syntax-log"
        sed -n '/^pass /p; /^block /p' "$policy.syntax-out" > "$policy.expected"
    done
    preflight_step=canonical-rules
    [ "$(wc -l < open.expected | tr -d ' ')" = 2 ]
    [ "$(wc -l < protected.expected | tr -d ' ')" = 3 ]
    preflight_step=restore-syntax
    /sbin/pfctl -nf restore.pf
    preflight_step=relayd-syntax
    /usr/sbin/relayd -n -f profile.conf
    preflight_step=unchanged
    snapshot after-preflight
    compare after-preflight
    printf 'SENDER-PREFLIGHT\tuid\tRELAY_UID\nSENDER-PREFLIGHT\tsyntax\taccepted\nSENDER-PREFLIGHT\tunchanged\tverified\n'
    printf 'SENDER-PREFLIGHT\topen\tOPEN_SHA256\nSENDER-PREFLIGHT\tprotected\tPROTECTED_SHA256\nSENDER-PREFLIGHT\tprofile\tPROFILE_SHA256\n'
    printf 'SENDER-PREFLIGHT\topen-loaded\t%s\n' "$(sha256 -q open.expected)"
    printf 'SENDER-PREFLIGHT\tprotected-loaded\t%s\n' "$(sha256 -q protected.expected)"
    for view in rules interfaces timeouts memory anchors tables config enabled; do
        printf 'SENDER-BEFORE\t%s\t%s\n' "$view" "$(sha256 -q "before.$view")"
    done
    printf 'SENDER-PREFLIGHT\trestore\t%s\n' "$(sha256 -q restore.pf)"
    exit 0
    ;;
run) ;;
*) exit 2 ;;
esac
trap - EXIT
[ "$(sha256 -q /var/aegvium-lab/engine.test)" = 'ENGINE_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-proxy)" = 'PROGRAM_SHA256' ]
[ "$(sha256 -q /var/aegvium-lab-readycheck)" = 'CHECKER_SHA256' ]
snapshot before-run
compare before-run
if pgrep -x relayd >/dev/null; then exit 1; else [ "$?" -eq 1 ]; fi
owned_pid=''
pf_changed=0
pf_before=$(cat before.enabled)
alive() { pgrep -x relayd | awk -v pid="$owned_pid" '$1 == pid {found=1} END {exit !found}'; }
stop_relay() {
    if [ -n "$owned_pid" ]; then
        if alive; then kill -TERM "$owned_pid"; fi
        attempt=0
        while alive && [ "$attempt" -lt 10 ]; do attempt=$((attempt+1)); sleep 1; done
        if alive; then kill -KILL "$owned_pid"; return 1; fi
        wait "$owned_pid" 2>/dev/null || true
        owned_pid=''
    fi
    if pgrep -x relayd >/dev/null; then return 1; else [ "$?" -eq 1 ]; fi
    netstat -an -f inet > listeners.txt
    awk '$4 ~ /[.:](1808[4567]|18120)$/ && $NF == "LISTEN" {found=1} END {exit found}' listeners.txt
    rm -f control.sock
    [ ! -e control.sock ]
}
kill_owned_states() {
    /sbin/pfctl -k label -k aegvium-sender-open
    /sbin/pfctl -k label -k aegvium-sender-allow
}
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    stopped=1
    restored=1
    stop_relay || { prior=1; stopped=0; }
    if [ "$pf_changed" -eq 1 ]; then
        if ! kill_owned_states; then prior=1; stopped=0; fi
        if ! /sbin/pfctl -o none -f restore.pf; then prior=1; restored=0; fi
        if [ "$pf_before" = Disabled ]; then
            if ! /sbin/pfctl -d; then prior=1; restored=0; fi
        fi
        if ! snapshot after; then prior=1; restored=0; fi
        if ! compare after; then prior=1; restored=0; fi
        if [ "$restored" -eq 1 ]; then
            for view in rules interfaces timeouts memory anchors tables config enabled; do
                printf 'SENDER-RESTORE\t%s\t%s\n' "$view" "$(sha256 -q "after.$view")"
            done
            printf 'SENDER\tpf-restored\tverified\n'
        fi
    fi
    if [ "$stopped" -eq 1 ]; then printf 'SENDER\tcleanup\tverified\n'; fi
    exit "$prior"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
printf 'SENDER\tengine\tENGINE_SHA256\nSENDER\tprogram\tPROGRAM_SHA256\nSENDER\tchecker\tCHECKER_SHA256\nSENDER\tprofile\tPROFILE_SHA256\n'
printf 'SENDER\topen\tOPEN_SHA256\nSENDER\tprotected\tPROTECTED_SHA256\nSENDER\trelay-uid\tRELAY_UID\nSENDER\tuid\t32767\n'
printf 'SENDER\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
for phase in baseline protected rollback reprotected; do
    case $phase in baseline|rollback) policy=open ;; *) policy=protected ;; esac
    stop_relay
    kill_owned_states
    pf_changed=1
    /sbin/pfctl -o none -f "$policy.pf"
    /sbin/pfctl -sr > "$phase.loaded"
    cmp -s "$phase.loaded" "$policy.expected"
    /sbin/pfctl -s Interfaces -v -i lo0 > "$phase.lo0"
    if grep -q '(skip)' "$phase.lo0"; then exit 1; fi
    /sbin/pfctl -s info > "$phase.status"
    if grep -q '^Status: Disabled' "$phase.status"; then /sbin/pfctl -e; fi
    /sbin/pfctl -s info | grep -q '^Status: Enabled'
    if [ "$phase" = protected ]; then
        printf 'not-a-pf-rule\n' > invalid.pf
        if /sbin/pfctl -f invalid.pf > invalid.log 2>&1; then exit 1; else [ "$?" -eq 1 ]; fi
        /sbin/pfctl -sr > after-invalid.rules
        cmp -s "$phase.loaded" after-invalid.rules
        /sbin/pfctl -s Interfaces -v -i lo0 > after-invalid.lo0
        cmp -s "$phase.lo0" after-invalid.lo0
    fi
    /sbin/pfctl -z
    printf 'SENDER-PHASE\t%s\t%s\t%s\t%s\n' "$phase" "$policy" "$(sha256 -q "$policy.pf")" "$(sha256 -q "$phase.loaded")"
    if [ "$phase" = protected ]; then
        printf 'SENDER-INVALID\tprotected\t%s\t%s\n' "$(sha256 -q after-invalid.rules)" "$(sha256 -q invalid.log)"
    fi
    /usr/sbin/relayd -d -f profile.conf > "$phase.daemon-log" 2>&1 &
    owned_pid=$!
    # The fixed phase name is the only varying argument; no unprivileged PF control.
    # shellcheck disable=SC2016
    su -m nobody -c "set -eu; [ \"\$(id -u)\" -eq 32767 ]; cd /var/aegvium-lab; export AEGVIUM_LAB_SENDER=owned-guest AEGVIUM_SENDER_PHASE=$phase; exec ./engine.test -test.v -test.timeout=60s -test.run='^TestLabSenderContainment\$'"
    alive
    /sbin/pfctl -s labels > "$phase.counters"
    awk -v phase="$phase" '$1 ~ /^aegvium-sender-(open|allow|deny)$/ {printf "SENDER-COUNTER\t%s", phase; for (i=1;i<=NF;i++) printf "\t%s", $i; printf "\n"}' "$phase.counters"
    printf 'SENDER-DAEMON\t%s\t%s\n' "$phase" "$(sha256 -q "$phase.daemon-log")"
    stop_relay
    printf 'SENDER-STOP\t%s\tverified\n' "$phase"
done
