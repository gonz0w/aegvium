# Configured Caddy server/TLS comparison

Bounded M1-01/03 research under #13/#14/#15/#16/#21. Read [PRD](PRD.md), [EDD](EDD.md), [Test Design](TDD.md) and [ADR-0004](../../architecture/adr-0004-configured-caddy-comparison.md). This is an executable comparison, not product adoption.

| ID | Required observation |
| --- | --- |
| CS-01 | Exact reviewed graph/legal delta precedes the reverse-proxy import. Child initialization uses owned XDG paths, admin/persistence/automatic HTTPS disabled, HTTP/1.1 only, positive deadlines and loopback-only ingress/backends. No existing dependency version changes. |
| CS-02 | Actual configured Caddy TLS/server/router/WAF/reverse-proxy handles benign GET/JSON, SQL/script, oversized body, unknown authority, spoofed metadata and response phases with exact independent backend effects/bytes/authority and no denied response leak. Bad frontend trust/name and bad backend name/CA/cleartext fail with zero uninspected effect, followed by healthy recovery. |
| CS-03 | Real Load rejects invalid configuration and preserves old service; valid replacement activates/removes routes, and rollback restores them. Explicit strict SNI/Host enables matched verified TLS and rejects cross-authority requests. Retain the permissive baseline and compare it to the unchanged relayd companion api-get case using app.test SNI. Differences are findings, not weakened expectations. |
| CS-04 | Complete typed observations, exact PASS set, output/UID/build identities, child/asset/listener cleanup and source/base/VM teardown. Native-built extended fixture runs beside unchanged 163 ordinary, 42 companion/3 load/7 startup and 40 API wire/22 pool controls. Native compilation and cross-built controls remain separate. |

Use the existing cold 3000-second build/3600-second guest profile, fixed before launch, with unchanged CPU/RAM/egress/storage bounds. No benchmark/soak or full CRS claim. Run make verify, Go tests/vet/race/cross, complete advisory coverage, signatures and author DCO. Preserve every prior native/relayd non-Markdown observation. Host setup failures stay separate from native admission; never change a denied zero-effect assertion to admit forwarding.

Rollback restores the previous module files/reviewed inventory, removes the optional full-server fixture/mode and rebuilds the original matrices in the owned lab. Preserve new and historical evidence. No live deployment, release, product schema or BootWeave contract is implied.
