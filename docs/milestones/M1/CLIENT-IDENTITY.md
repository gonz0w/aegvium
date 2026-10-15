# Bounded PROXY client identity

Status: authorized bounded research; native evidence pending. Refs #15/#16/#18/#21, WAF-05/06. Product trust policy remains proposed.

## PRD

CI-01: explicitly opt in to using validated PROXY v1 IPv4 source address/port as the Coraza request peer, preserving transport-peer behavior by default. Enable only with companion TLS and the separately qualified relayd-only PF sender boundary. Configuration is an operator assertion; the process does not authenticate PROXY or verify/install PF.

CI-02: never derive identity from HTTP forwarding headers. Reject missing, wrong-type, invalid or wrong-destination connection metadata before inspection/backend forwarding, without falling back to headers or transport identity. Preserve TLS/SNI authority checks, bounded admission, CRS, route reload and header removal.

CI-03: deliver implementation, actual Coraza address/port rule tests, CLI controls, native execution, rollback and guidance in one capability PR. Keep prior uncontained baselines and failures immutable.

## EDD

A startup-only LabProfile boolean and guarded CLI `-proxy-client-ip` option remain off by default. Refuse the option without frontend TLS before binding, including check-only. Capture immutable validated prefix metadata through the accepted TLS connection's NetConn in the data server's ConnContext. Require the expected destination and a loopback transport peer. A private typed context value carries the source; the application wrapper copies the request and sets only its RemoteAddr before the existing admission/route/Coraza path. The connection RemoteAddr remains the actual socket peer. Health is independent and receives no identity wrapper. No forwarding headers, address logs, identity response endpoint or backend identity header are added.

Do not add a rule-file CLI or synthetic production rule. Test-only directives passed through the existing internal constructor distinguish actual Coraza REMOTE_ADDR and REMOTE_PORT decisions. Those direct, uncontained component tests are separate from actual CLI/relayd/PF controls using the normal pinned CRS rules. This distinction is retained in evidence; neither component substitutes for the other.

## Test design

Host and native component wire tests compare default/off and opt-in/on with verified TLS, explicit source address/port prefixes, spoofed forwarding headers, exact rule-denial status/zero independent backend effects, benign bytes/header removal, post-denial recovery and SIGHUP-equivalent route replacement/rollback. Host and native context tests reject absent/wrong/invalid/wrong-destination metadata and refuse enabling without TLS. Missing metadata must return generic 503 before the handler; raw connections retain their transport peer.

Repeat 163 ordinary, 42 legacy path/three load/seven startup, 29 TLS/four startup and the original 44 PF cases unchanged. Separately repeat all four PF phases/44 actual CLI cases with the option enabled, requiring the fixed named Go test and one mode receipt per phase. Keep exact input/status/effect/TLS/UID/program/policy/counter/invalid-replacement and eight-view restoration gates. Reject substituted baseline-mode receipts, missing/reordered tests, nonzero supervisor or partial cleanup. Native CLI check-only must accept TLS+identity and reject identity without TLS without binding.

Use the existing owned OpenBSD profile: 3600 guest/2400 build/1200 patch seconds, two CPUs/2 GiB, 4 GiB file bound, restrictive no-egress network, authenticated 34-patch/reboot/access gates, offline UID-32767 build and exact installed/executed hashes. Component test call120s; each fixed four-phase PF call360s. Retain failed attempts separately and destroy the guest on every exit. Host/cross builds are tooling only.

## Compatibility and rollback

Legacy CLI and LabProfile behavior remain unchanged. Identity is startup-only and survives route replacement without becoming part of the route-file schema. Disable by stopping/restarting the lab CLI without the option; never claim live trust revocation. Restore temporary PF policy and all peers/keys/listeners before VM teardown. IPv6/v2, remote sender authentication, allowed-UID/root compromise, backend isolation, arbitrary persistent protocols, certificate operations, production startup ordering, logs and adoption remain separate gates. BootWeave's generic extension contract is unchanged.

## Host body-lifetime finding and bounded repair

The initial focused host race check fails: Coraza transaction cleanup resets its body buffer while Go's backend transport writer can still read that buffer after RoundTrip returns. The benign JSON identity case exposes the race; earlier passing race runs do not reclassify this failure. Retain the failed trace hash and source fingerprints separately.

Before native admission, detach at most 4096 inspected body bytes into a per-request transport-owned copy. Consume and close the middleware-provided body synchronously, clone the outbound request, remove its replay closure and preserve content length/transfer encoding. Read/close/limit failures must prevent calling the backend transport. No dependency/upstream patch or unbounded buffering. This repair applies to the lab backend path in both identity modes.

Require a deterministic delayed-writer regression that reads only after the source buffer is reset, exact body/metadata preservation, no backend on read/close/oversize errors, focused/full lab race checks, and all prior native semantics unchanged. Native OpenBSD race instrumentation is not claimed.

The component native call requires ten wire rows, six context, five body-lifetime/fault and six response-boundary subtests, plus both CLI check-only outcomes and independent cleanup. Normal-CRS CLI/PF cases remain a separately admitted 44-case/four-phase matrix.

The initial host failure's source fingerprints match signed candidate `ec1bca4cd4cb4ea45469418166e3fe05aac8957d`. The repaired working tree passes twenty focused race repetitions, the full lab race suite, full Go regression/vet/cross builds, 95 repository checks and four source-advisory scans. Companion scans have no findings; Caddy's existing non-symbol residuals remain. These are host/tooling outcomes; native qualification is still pending.

## Native stalled-response rejection finding

The first native attempt compiled all three outputs and passed 163 ordinary cases, then failed legacy api-stall: the owned HTTPS backend produced one inspected effect and the client received empty 200 instead of the required 502. No later TLS/PF/identity matrices ran; source/base invariance and teardown passed. Retain this failed result independently.

The response-buffer gate currently accepts clean EOF without independently checking the request context/deadline. Reject cancelled or expired context after bounded response buffering even if the body reader returns clean EOF. Keep the existing two-second request deadline and 502/one-effect expectation. Deterministic tests must cover EOF following cancellation, expired deadline before timer notification, missing request context, response read error/limit and healthy response preservation. Repeat all prior native semantics; do not promote a retry as proof of the first attempt.
