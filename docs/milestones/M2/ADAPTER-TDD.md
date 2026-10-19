# M2-A01 adapter Test Design

Status: **Proposed; no executed adapter, security or native evidence.**
Date: 2026-10-19. [Engineering design](ADAPTER-EDD.md),
[selected M2-H1/1](FRONTEND-INSPECTOR-CONTRACT.md). Refs #19–24.
WAF-01–08, selected D2/D3 and M2-C01 fidelity/lifetime obligations.

## Portable A01a acceptance

Implementation fixtures must use isolated synthetic identities and owned finite
I/O. No existing application, public key, production credential, native VM or
engine policy is a fixture. The A01a dependency graph contains no application-dial
capability and its recorder has no allow authority. Certificate fixture creation,
handshakes and security tests remain future scoped work; none executes here.

| ID | Input/fault | Independent expected observation |
|---|---|---|
| A-AUTH | Valid role; missing/foreign CA; expired/not-yet-valid cert; wrong EKU/DNS SAN/CN-only/wildcard/conflicting role; wrong ALPN | Only the actual fully verified HTTP/1.1 connection constructs the private role; every other case fails before context recording; headers/forged ConnectionState cannot construct it |
| A-PAIR | Exact canonical descriptor versus duplicate/unknown fields, byte/count cap+1, wrong generation/digest/route/pin | Exact pair matches; every mismatch remains unready. Golden bytes and digest come from an independent oracle, not the encoder under test |
| A-START | New token, reused token, rollback, interrupted/uncertain history write, unreadable history | Prepared facts require a successfully consumed fresh token; uncertainty/refusal never becomes serving-ready. Synthetic history tests do not prove durable native publication |
| A-CONTROL | Pair-preflight before data readiness, replayed success, wrong role, saturated control budget | No circular wait, no backend effect or transferable permission; data still requires current per-request identity/context/generation |
| A-FIDELITY | Original Host case/port, encoded slashes/query multiplicity, duplicate public header values and complete payload | Exactly one immutable recording with independently expected bytes; reserved/spoofable metadata is removed/rejected according to contract |
| A-BODY | Exact/cap+1, early EOF, stalled read, trailing fields, unsupported encoding or contradictory supplied framing | Complete bounded owned body or finite failure; zero recording on rejection. Supplied parsed tests carry no raw-wire claim |
| A-LIFE | Deterministic cancellation/retirement before inspection, during body/transaction and immediately before the attempt barrier | No late recording/attempt; transaction/body/lease closed once. Ordered after an attempt starts, outcome remains possibly effected |
| A-SLOTS | Four requests/eight accepted+outbound sockets, fifth request/ninth socket, other-generation contention, health contention | Shared fixed budgets, immediate finite rejection, no hidden queue; control isolation and numerical cap independently checked |
| A-STOP | Active lease, stuck consumer, failed transaction close, shutdown deadline | Readiness withdrawn; join precedes engine close; uncertainty remains failure and cannot free a live engine |
| A-NODIAL | Every accepted/rejected/error/cancelled state | Application dial/engine allow path is structurally absent; record success is never reported as inspection/enforcement |

Use deterministic barriers at each ownership transition, exact close/count
oracles and race testing. Fuzz only bounded parsers for the reviewed descriptor
grammar and parsed context. The future implementation chooses explicit finite
test/operation deadlines within original budgets; no sleep-based success or
retries. Run repository `make verify`, relevant race/fuzz and exact-source review.

## Later A01b qualification — not executed or waived

| Gate | Required independent proof before enablement |
|---|---|
| W-RAW | Exact package/original bytes: equal/conflicting duplicate lengths, CL+TE, unsupported TE, truncated bodies, headers/line cap boundaries and second/pipelined input. Pin rejection/close outcomes and zero second effect. Never infer original framing from parsed counts |
| W-INSPECT | Real pinned engine/CRS inspects all admitted fields/body before a fixed backend attempt; denial/error/timeout/cancel causes zero attempt and closes transaction once |
| W-BACKEND | Wrong/missing client/server roles/trust/expiry fail; direct frontend and management reachability denied independently. Backend effect recorder separate from client response; no fallback/retry/redirect |
| W-BYTES | Inspection input and backend request match exact method/Host/encoded target/query/header/body or explicitly admitted framing transformation; signed representation mismatch rejects |
| W-PAIR | Real immutable file/parent ownership and consumed-generation history, bilateral preflight, failed startup/rollback and trust/containment-loss detection at the selected bound |
| W-RUNTIME | Exact native package/ABI/source/image; identities, confinement and installed startup; bounded resources/health/shutdown; no-change/teardown and source preservation |
| W-FAIL | Engine absent/crashed, management absent, backend failure, response cap/timeouts and uncertain effects; none enables uninspected forwarding |

The raw-framing gate is independent of A01a's authentication/body/lifetime source
work. If a normalized-input alternative is reviewed, give it a distinct profile
and exact expected-wire oracles; retain failed strict-rejection evidence. Keep
all acceptance unchecked until the named gate actually runs under a fresh
authorized packet. Existing validation restrictions remain in force.

## Receipt and review boundary

Each receipt binds source/tree/base, toolchain/package/fixture hashes, fixed
selection/budgets, counts, original failures and owned teardown. Retain status,
counts/hashes and fixed error classes; omit raw requests, keys, query/header
values and private inventory. A portable pass is source evidence; it cannot
qualify native containment, raw framing, complete CRS or deployment.

Publish A01a as a draft until its scoped implementation/checks/independent review
pass; keep backend/required-WAF disabled regardless. A01b requires its own full
gate review. This documentation supplies a concrete recommendation and test
matrix; it supplies no execution result or changed requirement acceptance.
