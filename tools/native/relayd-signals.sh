#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Root-owned disposable guest only; no application traffic.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
cd /var/aegvium-signal
[ "$(sha256 -q profile.conf)" = 'PROFILE_SHA256' ]
[ "$(sha256 -q /var/aegvium-sigobs)" = 'OBSERVER_SHA256' ]
absent() {
    if pgrep -x relayd >/dev/null; then return 1; else code=$?; [ "$code" -eq 1 ]; fi
    if pgrep -x aegvium-sigobs >/dev/null; then return 1; else code=$?; [ "$code" -eq 1 ]; fi
    netstat -an -f inet > listeners.txt
    awk '$4 ~ /[.:](1808[45]|1810[0-9])$/ && $NF == "LISTEN" { found=1 } END { exit found }' listeners.txt
    [ ! -e control.sock ]
}
absent
expected_uid=$(id -u _relayd)
[ "$expected_uid" -ne 0 ]
mkdir evidence
chown _relayd evidence
chmod 700 evidence
owned_pid=''
alive() { pgrep -x relayd | awk -v target="$owned_pid" '$1 == target { found=1 } END { exit !found }'; }
capture() {
    for arm in zero one two term kill; do
        for kind in plain child; do
            file="evidence/$kind-$arm.uid"
            if [ -f "$file" ]; then printf 'SIGNAL\tuid-%s-%s\t%s\n' "$kind" "$arm" "$(cat "$file")"; fi
        done
        if [ -f "evidence/$arm.observe" ]; then
            value=$(awk 'NR==1 && $1=="uid" { uid=$2 } NR==2 { kind=$1; value=$2 } END { if (NR!=2 || uid=="") exit 1; printf "%s|%s|%s", uid,kind,value }' "evidence/$arm.observe")
            printf 'SIGNAL\tobserve-%s\t%s\n' "$arm" "$value"
        fi
    done
    if [ -f states.log ]; then
        awk '$2=="table" { split($3,p,":"); table=p[1] } $2=="host" { gsub("_","-",table); printf "SIGNAL\tstate-%s\t%s\n",table,$5 }' states.log
    fi
}
cleanup() {
    prior=$?
    trap - EXIT INT TERM
    if [ -n "$owned_pid" ]; then
        if alive; then kill -TERM "$owned_pid" 2>/dev/null || true; fi
        attempt=0
        while alive && [ "$attempt" -lt 10 ]; do attempt=$((attempt+1)); sleep 1; done
        if alive; then kill -KILL "$owned_pid" 2>/dev/null || true; fi
        wait "$owned_pid" 2>/dev/null || true
    fi
    # Direct observers own/reap bounded children; wait for their deadline on shutdown.
    attempt=0
    while pgrep -x aegvium-sigobs >/dev/null && [ "$attempt" -lt 5 ]; do
        attempt=$((attempt+1)); sleep 1
    done
    capture || prior=1
    cat daemon.log
    printf 'SIGNAL\tdaemon-log\t%s\n' "$(sha256 -q daemon.log)"
    rm -f control.sock
    absent || exit 1
    printf 'SIGNAL\tcleanup\tverified\n'
    exit "$prior"
}
: > daemon.log
trap cleanup EXIT
trap 'exit 1' INT TERM
printf 'SIGNAL\texpected-uid\t%s\n' "$expected_uid"
printf 'SIGNAL\tprofile\t%s\n' "$(sha256 -q profile.conf)"
printf 'SIGNAL\tobserver\t%s\n' "$(sha256 -q /var/aegvium-sigobs)"
printf 'SIGNAL\trelayd\t%s\n' "$(sha256 -q /usr/sbin/relayd)"
/usr/sbin/relayd -n -f profile.conf > syntax.log 2>&1
printf 'SIGNAL\tsyntax\taccepted\n'
/usr/sbin/relayd -d -f profile.conf > daemon.log 2>&1 &
owned_pid=$!
attempt=0
while :; do
    alive
    complete=1
    # Account gates run before and independently of the host-state predicate.
    for arm in zero one two term kill; do
        for kind in plain child; do
            file="evidence/$kind-$arm.uid"
            if [ ! -f "$file" ]; then complete=0; else [ "$(cat "$file")" = "$expected_uid" ]; fi
        done
        [ -f "evidence/$arm.observe" ] || complete=0
    done
    if /usr/sbin/relayctl -s control.sock show hosts > states.log 2>&1 && [ "$complete" -eq 1 ] && awk '
        $2=="table" { split($3,p,":"); table=p[1] } $2=="host" { state[table]=$5 }
        END { for (s in state) if (state[s]!="up" && state[s]!="down") exit 1; exit !(length(state)==10 && state["plain_one"]=="up" && state["observed_one"]=="up" && state["plain_two"]=="up" && state["observed_two"]=="up") }
    ' states.log; then break; fi
    attempt=$((attempt+1))
    [ "$attempt" -lt 30 ]
    sleep 1
done
