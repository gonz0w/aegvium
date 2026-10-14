# Consolidated relayd body parser comparison

Authorized bounded research under existing #16 (not full issue acceptance or runtime adoption).

## PRD / EDD

RB-01 (WAF-03/04, M1-03): compare the same fifteen synthetic HTTP body/framing inputs directly and through stock relayd HTTP and TCP modes, with the unchanged test-only body gate and pinned CRS. Use only owned loopback listeners in the disposable patched guest. No TLS, trust, persistent/pipelined traffic or upstream application.

RB-02: fresh inspection server and WAF per case, Connection: close and fixed read/write/shutdown guards; existing 128-byte gate, dependencies and rules unchanged. Foreground relayd has HTTP/TCP listeners and no health checks, isolating parsing from polling. Explicitly record parser-level absence of handler entry, normalized inspection view, source reads/Close errors, bytes/digest, rules and independent cleanup. HTTP rejection may yield a status or EOF; absence of response is characterization and must never hide a backend effect. Record bounded timeout distinctly from EOF. Socket byte counts are observational and do not define a transport body budget.

## Test Design / acceptance

RB-03: fifteen controls in three arms (45 connected cases). Benign controls must forward exactly one expected body; script/SQL must never reach backend; size/media/malformed controls must never reach backend. Retain parser normalization/close differences and raw outcomes. Every entered handler must invoke original source Close once with application consumption at most 129 bytes. Require server join/listener absence and foreground daemon/control-socket/three-listener/VM cleanup. Direct baseline must retain original outcomes. Preserve any failed case before fixing fixture or expectations; no weaker backend acceptance. Strict typed receipt admission/mutations and export cover the new study separately from the unchanged 163 ordinary leaves.

RB-04: execute a signed clean candidate on OpenBSD as UID 32767; authenticated patch/reboot/bootstrap/source/base checks; host tests/vet/race/advisory/cross/export and make verify are tooling evidence. Deliver implementation, tests, findings and a concrete mode compatibility assessment together on one PR. Keep original connected pipeline failures, image/daemon lineage, Host/SNI/trust and broader #16/#15 criteria open. Rollback removes this test-only comparison/profile/controller path while preserving receipts. No new dependency, service or installer changes.
