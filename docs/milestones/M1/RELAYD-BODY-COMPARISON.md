# Consolidated relayd body parser comparison

Authorized bounded research under existing #16 (not full issue acceptance or runtime adoption).

## PRD / EDD

RB-01 (WAF-03/04, M1-03): compare the same fifteen synthetic HTTP body/framing inputs directly and through stock relayd HTTP and TCP modes, with the unchanged test-only body gate and pinned CRS. Use only owned loopback listeners in the disposable patched guest. No TLS, trust, persistent/pipelined traffic or upstream application.

RB-02: fresh inspection server and WAF per case, Connection: close and fixed read/write/shutdown guards; existing 128-byte gate, dependencies and rules unchanged. Foreground relayd has HTTP/TCP listeners and no health checks, isolating parsing from polling. Explicitly record parser-level absence of handler entry, normalized inspection view, source reads/Close errors, bytes/digest, rules and independent cleanup. HTTP rejection may yield a status or EOF; absence of response is characterization and must never hide a backend effect. Record bounded timeout distinctly from EOF. Socket byte counts are observational and do not define a transport body budget.

## Test Design / acceptance

RB-03: fifteen controls in three arms (45 connected cases). Benign controls must forward exactly one expected body; script/SQL must never reach backend; size/media/malformed controls must never reach backend. Retain parser normalization/close differences and raw outcomes. Every entered handler must invoke original source Close once with application consumption at most 129 bytes. Require server join/listener absence and foreground daemon/control-socket/three-listener/VM cleanup. Direct baseline must retain original outcomes. Preserve any failed case before fixing fixture or expectations; no weaker backend acceptance. Strict typed receipt admission/mutations and export cover the new study separately from the unchanged 163 ordinary leaves.

RB-04: execute a signed clean candidate on OpenBSD as UID 32767; authenticated patch/reboot/bootstrap/source/base checks; host tests/vet/race/advisory/cross/export and make verify are tooling evidence. Deliver implementation, tests, findings and a concrete mode compatibility assessment together on one PR. Keep original connected pipeline failures, image/daemon lineage, Host/SNI/trust and broader #16/#15 criteria open. Rollback removes this test-only comparison/profile/controller path while preserving receipts. No new dependency, service or installer changes.

## Native findings and compatibility decision

[Curated receipts](../../../research/relayd/body-comparison-observations.json) bind runtime `529e6970984592bd5ac01ceae549a71ecd7996fa`, tree `0b65e7b9c84e3aeff7b7f598918284e28d6b55e6` and run `2b754d69-b703-4f99-ae22-e4c1a5fac313`, with 73 fingerprints. All 163 ordinary leaves and 45 separately admitted comparison cases passed as UID 32767 on patched/rebooted OpenBSD 7.9 amd64. Host test/vet/race/advisory/cross/export and 56 local checks passed. Bootstrap rejection, source/base invariance and owned server/listener/foreground daemon/control-socket/VM teardown passed. This run executes a host cross-build; earlier native source builds retain their original scope.

Each arm forwarded exactly four benign/normalization controls with the same 22-byte body digest. Six total SQL/script cases returned 403 with expected rules and no backend. Oversize, malformed JSON and media denials had no backend; source consumption never exceeded 129 bytes. Identical CL and CL+TE were accepted in all arms, with identical normalized inspection view. Acceptance is characterization, not anti-smuggling policy approval.

| Input | Direct | HTTP relay | TCP relay |
|---|---|---|---|
| Malformed chunk | 500, handler entered | No response, `other`, no handler | Same as direct |
| Conflicting CL | 400, no handler | No response before client deadline, no handler | Same as direct |
| Truncated fixed body | 500, handler entered | No response, `other`, no handler | No response, `other`, no handler |
| Unsupported coding | 501, no handler | 400, no handler | Same as direct |

These four inputs have zero backend receipts in every arm. The timeout is retained; it does not satisfy bounded appliance rejection. `other` is a normalized response-error class and does not attribute an internal relayd mechanism. Malformed-source Close `other` and stalled-source Close `timeout` remain separate from successful network/server cleanup. Parser rejection may create no inspection connection; cleanup assertions cover any owned accepted connection plus joined server/unavailable listener.

Prefer TCP mode as the candidate for further transport qualification: complete-input outcomes matched the direct arm in this corpus, and TCP mode avoids a second HTTP parser. This is a research direction, not adopted connector architecture. The truncated-body difference still requires qualification; relayd TLS/routing/readiness boundaries, trusted identity and persistent/concurrent traffic remain open. HTTP mode requires resolving or explicitly defining its differing rejection behavior before selection. The study isolates parsing from health polling and does not fix historical pipeline failures. No connector split, deploy or installer change.

Initial uncommitted host checks found an unused import and an admission assumption that phases were unique. Removing the import and retaining one valid phase per matched rule corrected the checks without weaker forwarding/cleanup assertions. The initial verify log was overwritten during follow-up; only captured diagnostics remain, without signed source attribution. Final host/native receipts are source-bound; that retention limitation remains explicit.
