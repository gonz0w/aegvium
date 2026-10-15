# ADR 0007: Explicit PROXY identity for Coraza research

Status: bounded research decision; product adoption pending.

The sender study restricts fresh local data sockets to relayd's UID, but Coraza still sees the companion's transport peer. Test explicit propagation of validated source address/port through TLS connection context to Request.RemoteAddr, the pinned middleware's ProcessConnection input. Preserve raw socket identity, default-off compatibility and forwarding-header removal.

The opt-in requires companion TLS and an externally maintained sender boundary. It does not establish or verify that boundary. Fail closed on missing/invalid connection metadata. A private typed context avoids HTTP-header selection; startup-only selection persists across route replacement. No new dependency, rule-file interface, address logging or backend identity header is introduced.

Actual test-only Coraza rules establish address/port behavior separately from the normal-CRS CLI/relayd/PF matrix. Both are required, with unchanged prior controls and complete rollback. Root/PF administrators and allowed-UID compromise remain outside this local boundary. Product privilege/startup/certificate policy and any future reusable relayd control-plane API remain unadopted. See the [PRD/EDD/test design](../milestones/M1/CLIENT-IDENTITY.md).

The [native result](../../research/native/client-identity-observations.json) now observes the separate component/CLI scopes with unchanged prior controls and complete restoration. The adapter body-lifetime race discovered during this study is retained and repaired with bounded independent forwarding bytes. This is component qualification; the product adoption status above is unchanged.
