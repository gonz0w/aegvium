# Bounded local backend isolation

Status: observed bounded native research; product adoption pending. Refs #15/#16/#18/#21, WAF-03/05/06. No product policy or service identity adoption.

## PRD

BI-01: extend the disposable TCP/PROXY/TLS candidate with explicit PF socket-UID restriction of its two synthetic backend ports. The existing sender-only policies intentionally leave these ports reachable. Preserve them and their evidence unchanged.

BI-02: a different nonroot local principal must be unable to send a request directly to either backend when protected, while the actual identity-enabled CLI still forwards inspected benign HTTP/verified HTTPS and denies the existing CRS attack. Open and rollback controls must demonstrate the same direct attack requests reaching the uninspected synthetic backends. Require independent backend receipts, immediate connect rejection rather than timeout, and positive allow/deny counters.

BI-03: deliver policy, fixture/controller, abuse/recovery tests, native build/execution, restoration evidence and guidance in one capability PR. Repeat every admitted client-identity baseline; retain failures independently. No live network or persistent service.

## EDD

Add separate research policies for lo0 IPv4: preserve relayd-only access to data port 18084 and restrict backend ports 18086–18087 to socket UID 32767. Reject every other sender to those ports with return; pass other isolated lab traffic without state. These are fixed owned-guest ports, not application inventory or an appliance firewall. Root/PF administrators and compromise of the allowed companion/fixture UID remain outside this boundary. Remote backend isolation, IPv6, existing sessions and production accounts/startup ordering remain unqualified.

Reuse the existing native engine/checker/CLI build and the four-phase sender fixture, with identity enabled. A separate root-only nonce-bound controller owns policy selection, snapshots, invalid replacement, label-specific state removal and restoration. No unprivileged policy-control channel is introduced. The foreign probe runs as the existing daemon account only after native lookup proves UID 1, distinct from root, relayd and UID 32767. This is a test principal, not a selected service account.

Use two public synchronization directories per fixed phase beneath a root-owned parent: one writable by UID 32767, the other by UID 1. Publish bounded regular marker files atomically and validate phase/run token, ownership, mode and file identity. Share only the synthetic public CA; keep private keys in the fixture's private temporary directory. The probe waits for the fixture's fixed ready marker, sends two fixed direct POST attack requests (HTTP and verified HTTPS), publishes completion, then exits. The fixture independently checks exact backend deltas/body/authority and removes its public marker/CA. Root joins both children, removes the remaining public barrier assets and verifies absence before changing phase. Marker data cannot select commands, policy, targets or paths.

## Test design

Require four fixed phases: open, protected, rollback-open, protected-again. Preserve the original eleven sender cases per phase (44 identity-enabled actual CLI/relayd cases) and add two foreign-user attempts plus two independent backend-effect observations per phase. In open controls each bypass returns 200 with the exact attack bytes at its intended backend; when protected each connection fails immediately, before TLS/HTTP, and neither backend observes an effect. Verify HTTPS using the fixture's public CA, with exact hash binding. Probe UID/program hashes, named Go tests, full phase order, all typed rows, active policies, fresh allow/deny counters and complete child/asset/listener/daemon cleanup are mandatory. Reject missing, duplicate, reordered, forged, timed-out, failed or skipped receipts.

Preflight must parse both new policies before compilation, record eight static PF views and reject unsupported initial state without mutation. Invalid replacement must preserve known good. Restore rules, skip flags, enabled state, timeouts/limits, anchors/tables and unchanged /etc/pf.conf; no global state flushing. Keep the existing 3600 guest/2400 build/1200 patch seconds, 2 CPUs/2 GiB, 4 GiB file bound, no-egress networking, authenticated 34-patch/reboot/access and source/base/VM teardown gates. The new four-phase call is independently capped at 360 seconds; each fixture/probe has 60 seconds, synchronization waits 20 seconds.

Host checks cover synchronization-file validation and strict receipt mutations, plus full Go/vet/race/cross and make verify. Native compilation/execution is separate from host evidence and has no native race-instrumentation claim. All prior 163 ordinary/42 legacy/three load/seven startup/29 TLS/four startup/original 44 PF/27 identity components/two CLI startup/44 enabled-PF semantics must repeat unchanged.

## Compatibility and rollback

The new native option requires the complete client-identity profile. Existing policies, CLI arguments, non-test Go and dependencies remain unchanged. Rollback restores all eight captured static views, joins owned children, removes public synchronization and private TLS assets, then destroys the owned guest. Disabling or reloading these policies does not revoke past backend effects. BootWeave's generic contract remains untouched. Full product trust, backend network isolation, privilege/certificate/audit policy, resource/soak budgets and adoption remain separate gates.

Reference: [OpenBSD 7.9 PF semantics](https://man.openbsd.org/OpenBSD-7.9/pf.conf.5).

## Observed result

[Native evidence](../../../research/native/backend-isolation-observations.json) binds `7c1d07c0b3a76d94191f02ff67dc5dd7e7cc95b7` and run `2a672f8f-8ee3-42bb-9216-7ecf0eb611b1`. BI-01–03 pass within the four-phase distinct-user scope: eight direct attack attempts, eight independently observed effects, forty-four unchanged actual identity-enabled CLI cases and the public-file validation test. All previous native semantics repeat unchanged. Three PF matrices independently restore eight static views; offline native compile/install/execution hashes, UID separation, authenticated 34 patches/reboot/access, source/base invariance and complete teardown pass under unchanged limits. All 99 local checks and host Go/vet/race/cross/advisory policy pass.

The companion/checker native hashes match the preceding study, with no non-test Go or dependency changes. Root/PF administrators and allowed-UID compromise, production accounts/startup/backend network policy, IPv6/existing sessions and full protocol/resource/certificate/audit/lineage/adoption acceptance remain outside this result.
