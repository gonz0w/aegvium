# Bounded local sender containment

Status: authorized bounded research; native execution pending. Refs #15/#16/#21, WAF-03/05/06. No product policy or privilege identity adoption.

## PRD

SC-01: test whether stock OpenBSD PF can restrict fresh connections to the companion's IPv4 PROXY/TLS data listener to sockets opened by `_relayd`. Use only the controller-owned disposable VM; no host, EdgeWall, storage, application, public interface or persistent service changes. Keep all earlier uncontained baselines and failures immutable.

SC-02: compare identical logical requests in open, protected, rollback-open and protected-again phases using the same native-built executable. Normal verified TLS ingress, HTTP/HTTPS backends, body preservation, header removal, CRS denial and SNI/Host rejection must keep their expected independent backend effects. Direct forged-prefix clients must connect/forward in open controls and fail at connect with zero effects when protected. A client timeout or absent backend alone cannot satisfy containment.

SC-03: independently require active PF, loopback filtering, exact policy/program/UID identities, positive allow/block rule counters, fresh-state handling and verified restoration of prior main rules, skip flags, enabled state, limits/timeouts, anchors/tables and unchanged `/etc/pf.conf`. Teardown remains mandatory on every failure. Do not call UID containment cryptographic authentication; root/PF administrators and compromised allowed-UID processes remain trusted/out of scope.

## EDD

No companion/library dependency or protocol change. Add two fixed research PF templates for `127.0.0.1:18084` on `lo0`: an open positive control and an ordered protected policy allowing the numeric `_relayd` UID, then rejecting every other sender. Other traffic is passed without new state only inside this isolated guest, so its owned SSH, health, ingress and synthetic backends remain available. This is not an appliance firewall template.

A root-only, nonce-bound controller directory holds immutable policy inputs and private snapshots. Parse both policies with `pfctl -n` before expensive native compilation, without applying either. Reject pre-existing anchors/tables or skipped interfaces/groups other than lo0/lo (with lo0 as its sole member) rather than attempting a generic PF migration. Save canonical current main rules and the admitted loopback skip settings; build/parse an exact restoration input. Capture static PF configuration before mutation and compare after restoration; `/etc/pf.conf` is never edited. Do not use global state flushing or `-F all`/`-F Reset`. Only states carrying this experiment's two unique labels may be killed.

After unchanged ordinary, legacy and 29-case uncontained TLS controls, run four separate guarded nonroot fixture processes behind foreground stock relayd. Each phase creates fresh owned TLS/backend assets and starts the exact same CLI; root selects only the fixed policy/phase. No unprivileged policy-control channel or privileged command evaluator. Require no remaining test listeners before transition. Enable PF temporarily if initially disabled, and restore that state after stopping all owned peers. Fresh connections only; no promise of revoking already admitted application effects or stateful sessions.

## Test design

Host-check exact typed admission and mutations: false forwarding, bypassed direct connection, non-verified TLS, body/authority/header drift, missing/duplicate/reordered phases, wrong UID/hash/policy, zero allow/block counters, root execution, absent rule application, failed/skipped tests, missing restoration and nonzero supervisor. Host Go tests exercise the open fixture as tooling only; PF cases require OpenBSD and an owned marker.

Native compile fixture/checker/CLI offline as UID 32767 with exact output/install/execution hashes; repeat 163 ordinary +42 legacy paths/three loads/seven startup rejects +29 uncontained TLS paths/four TLS startup rejects. The new phase matrix separately admits verified app/API GET, JSON, CRS denial, cross-authority, health, direct forged app/API prefix, bare TLS and plain HTTP. Protected direct sockets must fail before TLS/HTTP without a timeout; open forged prefixes must reach exactly the expected inspected backend. Compare all phase input hashes and bind phase-specific PF rule counters to the run. An actual invalid PF replacement must exit with a parse error and preserve the active protected rules and loopback flags before that phase's traffic. Every phase must stop/join CLI/backends, prove backend availability at companion stop, remove keys/config and release listeners.

Retain any failed native attempt independently. Native tooling keeps the existing TLS study's 3600 guest/2400 build seconds, two CPUs/2 GiB and 4 GiB file ceiling; each phase has a 60-second Go ceiling and the four-phase root controller 360 seconds. No legacy expectation or traffic deadline changes, no host build fallback.

## Compatibility and rollback

Opt-in owned VM experiment only; uncontained modes remain unchanged. Restore saved main rules plus original lo0 skip flag and enabled state, compare static PF configuration, then destroy the VM with source/base invariance. This does not implement product startup ordering, production service accounts, certificate rotation, remote sender authentication, IPv6/v2 or persistent-session revocation. BootWeave remains responsible for its generic installer; no schema or deployed policy is added.

References: [PF user/skip semantics](https://man.openbsd.org/OpenBSD-7.9/pf.conf.5), [PF rule counters, label-specific state removal and replacement](https://man.openbsd.org/OpenBSD-7.9/pfctl.8), [retained uncontained TLS result](../../../research/native/tls-passthrough-observations.json).

## Initial preparation failure and scoped patch budget

The [first signed attempt](../../../research/native/sender-containment-initial-failure.json) exhausted the existing 600-second patch call before PF preflight, native compilation or traffic admission. Partial signature evidence is not complete patch/reboot admission. Source/base invariance and full VM teardown passed.

A fresh sender-only run permits 1200 patch-call seconds inside the unchanged 3600-second guest and 2400-second build ceilings. Legacy patch calls stay at 600 seconds. Manifest/signature, exact 34 installed/no pending patches, reboot/fresh access, all traffic assertions and teardown remain mandatory. This is a predeclared tooling budget for a fresh signed candidate, not a live deadline extension or fallback.

The fresh patch-budget attempt admitted the authenticated 34-patch/no-pending/reboot gates, then failed the non-mutating PF preflight before compilation or traffic. Its empty preflight log does not identify the failing guard. Static source review found canonical rules were read from stderr, while pfctl prints them to stdout. The corrected controller reads stdout and emits only a literal stage/exit diagnostic on preflight failure. Policies, rule counts, loaded-rule comparison and all traffic/restoration assertions remain mandatory; retain the failed receipt separately.

The next attempt's literal diagnostic rejected initial PF-state admission, still before syntax parsing, compilation or policy application. Source review found `ifconfig -g lo` returns group attributes, not members. Read the member interface headers from `ifconfig lo` instead and continue to require exactly `lo0`; no additional interface or group becomes admissible. Keep both preflight failures independently and add finer initial-state diagnostics.
