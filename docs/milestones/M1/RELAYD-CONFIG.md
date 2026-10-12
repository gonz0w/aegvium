# Stock relayd ingress configuration research

Status: bounded research under continuing maintainer authorization. Configuration validity precedes a running companion proxy. No service, listener, PF rule or appliance configuration is installed/enabled.

## PRD

RC-01: validate one versioned HTTP ingress fixture using the installed OpenBSD 7.9 stock relayd configtest command. It has one loopback listener and one loopback inspection target, with no application target/fallback/redirection.

RC-02: record explicit rejection of an unknown protocol reference and invalid syntax; record the admitted configuration and installed binary hashes. Never infer policy enforcement from syntax acceptance.

RC-03: prove no relayd process, fixture-port IPv4 listener or control socket exists before and after configtest. Run only in the independently owned patched/rebooted VM with the shared 900-second budget, verified group teardown and unchanged source/base. Retain failures.

## EDD

The fixed research profile names loopback ports 18080 (future ingress) and 18081 (future inspection), an explicit HTTP protocol, bounded session inactivity, and an HTTP status readiness check with a synthetic Host. There is no target for an application. Settings are fixture choices, not measured product resource budgets.

Transfer a hash-checked copy into a new private guest directory. Root invokes only `/usr/sbin/relayd -n -f` for this profile and two generated negative variants; no arbitrary configuration/remote host is accepted. The variants replace the declared protocol reference or append an unsupported syntax token. Exit status must match each expected result. Keep private stdout/stderr hashes and structured shared receipts. Repeat the existing 20-case engine fixture nonroot in the same VM; this does not exercise a connected traffic path.

The [OpenBSD 7.9 relayd manual](https://man.openbsd.org/OpenBSD-7.9/relayd.8) defines `-n` as configtest mode. The [configuration manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) documents HTTP status checks, HTTP protocols, error responses and relay settings. The HTTP status check uses HEAD: a future readiness handler must answer HEAD, depend on inspected configuration readiness and remain distinct from forwarded application success. Neither that handler nor a health result exists in this slice.

A stock parser may accept a syntactically valid application fallback. Thus this experiment's single-target reviewed fixture is not a general no-bypass validator. Binary hash and release/patch receipts identify the installed executable; they do not prove exact upstream source lineage or reproduce its build. No TLS, client identity, parser agreement or security guarantee is inferred.

## Test Design

Host checks reject missing/duplicate/unknown receipts, wrong hashes, unexpected case verdicts, non-root configtest identity and claimed daemon/listener absence that does not match the required values. Host fixture checks assert the sole reviewed target/listener and no redirection/fallback. These are checks of the fixed fixture, not a relayd grammar or arbitrary policy validator.

Native postconditions: valid profile exits zero; missing protocol and bad syntax exit 1; no pre/post relayd process, ingress-port IPv4 TCP listener or control socket; complete 20-case engine repeat as nonroot; authenticated patch/reboot, bootstrap revocation, teardown and source/base invariance. No running relayd test is claimed. A failure in any configtest/gate prevents this profile from passing.

## Compatibility and recovery

Plain HTTP syntax only, OpenBSD 7.9 amd64 installed baseline. No TLS key/certificate dependency or configuration API is selected. Remove the ignored private run/input copies to undo preparation; the read-only base and source remain unchanged. A future foreground traffic experiment must separately scope daemon ownership, readiness behavior, identity and both parsers before publication or service adoption.

## Observed outcome

Runtime candidate `62a0f7e3be7bb191fd56b1c7e172c16659d6c439` passed valid/invalid configtest expectations and pre/post absence checks in the owned patched/rebooted guest. All 20 engine cases passed as nonroot; cleanup/source/base passed. [Source-bound receipts](../../../research/relayd/config-observations.json) retain installed relayd/config hashes and raw log/report hashes. Host checks passed 40 tests, lint and secret scan. No connected traffic, health behavior, relayd source-build reproduction or phase acceptance is claimed.
