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
