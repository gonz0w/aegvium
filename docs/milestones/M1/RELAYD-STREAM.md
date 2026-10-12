# Bounded inspection stream diagnostics

Status: authorized follow-up to [idle comparison](RELAYD-IDLE.md). Research only; no supported connector profile selected.

## PRD

RS-01: retain all thirty connected expectations and previous failures. Record bytes consumed at inspection's net.Conn.Read boundary, separately from handler arrivals, for the existing synthetic pipeline and serialized controls.

RS-02: correlate inspection read/state/handler observations with anonymous monotonically assigned connection IDs. Never record peer addresses, credentials or production data.

## EDD

Wrap only the inspection listener's accepted connections. Forward Read bytes/errors and all other net.Conn methods unchanged. Keep a bounded 8192-byte cumulative buffer per connection; emit byte length, SHA-256, overflow flag and counts of fixed synthetic request-line/Connection markers. Counts are byte markers, not a replacement HTTP parser. Retain private synthetic stream bytes only in ignored logs if needed; public receipts contain hashes and marker counts.

Use separate typed wire observations, capped at 1024 entries; mutex-protect buffers and collections. Overflow makes diagnostics incomplete and fails the test. Record at each positive Read before returning those same bytes to Go. Assign anonymous IDs at Accept; attach them via ConnContext and ConnState so health probes can be distinguished by marker/handler data without peer addresses. Existing event limits, timings, profile restarts, assertions and daemon/VM cleanup remain unchanged. Instrumentation is synchronous and may affect timing; no performance claim.

## Test Design

Host tests must prove normal reads preserve exact bytes across split reads and oversized reads preserve caller data while capping recorded storage and flagging overflow. Host connected tests still skip; native engine admission remains its separate twenty cases. Connected admission remains exactly thirty leaves and any failed case keeps it failed.

For each raw case, retain client bytes successfully written and wire hash, anonymous stream snapshots, connection events, handler arrivals, backend receipts and response failures. The six-second exchange deadline remains bounded; timeout is not admitted as rejection. Publish failures with source/binary/config/log identities and verified cleanup/source/base invariance. Keep prior missing/unqualified observations historical.

## Limits and rollback

A Read boundary is neither packet capture nor proof of everything relayd wrote: data may remain unread in a socket. Fixed marker counts do not prove standards parsing or supported connection reuse. No relayd source patch/configuration change, dependency, product adoption, live network, TLS/identity/full CRS or installed source-lineage claim. Use the same disposable guest and verified destruction for rollback. Any result requiring causal attribution beyond received bytes remains open.

## Observed result

Candidate `b603a6b14f52c7a0e3b114c19ba71265b5ef2324` executed inside the owned patched/rebooted OpenBSD 7.9 amd64 guest as UID 32767. The connected suite **failed** at 26/30, retaining the four original relayed pipeline failures in both idle profiles. All twenty separate engine cases and stock configtests passed. [Source-bound receipts](../../../research/relayd/stream-observations.json) preserve successful client write counts/hashes, correlated inspection read/state/arrival observations, named outcomes and native log/report hashes. No recorder overflow occurred in the observed slices or terminal guard.

| Sequence (same outcome at one-/three-second idle) | Client bytes written | Direct consumed bytes / handler arrivals | Relayed consumed bytes / handler arrivals |
|---|---|---|---|
| Denied/benign pipeline | 111 in one write | 111 / 2 | 47 / 1 |
| Benign/benign pipeline | 109 in one write | 109 / 2 | 45 / 1 |
| Serialized denied/benign | 47 then 64 | 111 cumulative / 2 | 111 cumulative / 2 |

Direct pipeline read hashes match the entire submitted stream. Failed relayed pipeline read hashes match the first request only: no second request marker was recorded on their application connections before snapshots. Serialized relayed streams recorded both request markers and one Connection: close marker. Their final hash differs from the direct input despite equal length. Offline reconstruction of the fixed synthetic stream matches that recorded hash in both profiles when the second request’s Connection header precedes Host instead of following it. Receipts include the exact harmless reconstructed bytes and SHA-256. This corroborates header reordering in these samples; it does not claim general byte preservation, header trust or normalization safety. Healthy probe connections are separable from application connections by anonymous IDs and marker/arrival data.

The transport observations place the visible failure before a second request reaches inspection's Read boundary, rather than showing both requests consumed there followed by one ignored handler. They do not prove what remained buffered in relayd or a socket, or establish exact installed parser behavior. All twenty raw snapshots recorded zero hostile URI receipts; failed denied pipeline counted zero backend receipts and failed benign pipeline one. These remain failed observations, not admission or proof against later forwarding.

Inspection loss returned 500/502/502 with zero forwards and recovery passed. Foreground daemon/listener/control-socket cleanup, authenticated 34 patches/reboot, bootstrap rejection, VM teardown and unchanged source/base verified. Native execution is a host cross-build; the two recorder subcases passed on the host only and are excluded from the separate twenty-case native engine admission. Instrumentation can affect timing.

Next bounded research should use the stock relayd source corresponding to the installed release/patch baseline or guest-only client-side stream evidence to locate the buffered second request, before selecting an ingress profile; the observed serialized header-order difference is hash-corroborated only for the fixed sample. No relayd source/configuration, support policy or original expectation changed. Exact lineage, TLS/identity, broader parser corpus, full CRS and connector adoption remain open.
