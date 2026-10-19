# M2 Test Design: enforcement and recovery acceptance

Status: **M2-H1/1 source-contract Test Design selected; cases not executed by this
documentation change.** Broader M2/native acceptance remains proposed.
Owner: Cam (`@gonz0w`). Date: 2026-10-19. [PRD](PRD.md), [EDD](EDD.md).
Affected security/traffic/advisory validation is **paused/blocked**. This design
does not authorize execution, resume a blocked profile or provide a workaround.

## Requirement to acceptance mapping

The [selected ADR](../../architecture/adr-0010-frontend-key-mandatory-inspector.md)
and [M2-H1/1 contract](FRONTEND-INSPECTOR-CONTRACT.md) resolve D1 and scope the next
M2-C01 pure context/route admission component. Its independent bounded fake-I/O
cases are specified there; no implementation or runtime case passes by publishing
this design. Rows below still require remaining D2–D4 realization/proof before a
runtime acceptance packet. A skipped/blocked row is not passing.

| Requirement | Test ID | Fixture and level | Required observation | Gate |
|---|---|---|---|---|
| M2-01 | M2-A01 | Typed-route unit/contract; later native owned backends | Exact configured destination; duplicate/unknown/invalid route rejection; no default/fallback effect | #20, #24 |
| M2-02 | M2-A02 | TLS/authority contract; later independent native path | Selected name/port/SNI/trust and identity semantics, invalid trust/authority zero effects, fresh positive recovery | #21, #24 |
| M2-03 | M2-A03 | Body/engine contract; later complete actual ingress path | Complete supported representation inspected and admitted bytes preserved; rejection/error/unsupported input zero effects | #22, #24 |
| M2-04 | M2-A04 | Boundaries/fake I/O; later independent native resource measurement | Limit and cap+1 behavior, no overflow/unbounded queue, shared generation ceiling, stalled input bounded, resource caps met | #22, #23, #24 |
| M2-05 | M2-A05 | Privilege review; later distinct-principal native acceptance | Unauthorized direct inspection/backend access denied, positive ingress intact, management absent still enforces, no credential exposure | #21, #23, #24 |
| M2-06 | M2-A06 | Generation/ownership unit contracts; later native lifecycle | Prepublication reject preserves old; whole publication/drain/retirement; crash/startup/cleanup faults and known-good restoration | #23, #24 |
| M2-07 | M2-A07 | Redaction/outcome contract; later candidate receipt review | Client status, effect and completion distinct; fixed bounded errors; log exhaustion policy; no secret/raw-traffic evidence | #23, #24 |
| M2-08 | M2-A08 | Independent full native acceptance and cleanup readback | Exact complete expected matrix, source/build/runtime/fixture identity, resources, restore and owned absence; no hidden failed/skipped rows | #24, M2 #3 |

## Unit, component and independent contract tests

After implementation admission, test route bounds and whole-record validation;
request-to-generation binding; cap+1/overflow/short/error reads and exact close
ownership; admission release on all outcomes; retirement while handlers retain
leases; failed preparation versus postpublication failure; and bounded redaction.
Use synthetic data and fake transports for portable contracts where possible.
These checks cannot qualify OpenBSD parser, TLS, PF, process or resource behavior.

For M2-A03 the oracle must distinguish wire input, admitted inspection view and
independent backend bytes/authority/metadata. Include fixed/chunked bodies and
the unsupported rows in the PRD, including trailers and ambiguous framing. A
parser's normalization is evidence to classify, not proof that stricter wire
rejection occurred. Assert finite complete response/close where required; a
client deadline or absent response is not successful rejection.

Independent backend fixtures record exact admitted effects and zero effects on
pre-forwarding denial. Response failure after forwarding may retain an inspected
effect and must not pass a zero-effect assertion. DetectionOnly results stay
separate. No response-content protection or full CRS coverage is inferred.

## Native functional, failure and recovery tests

When separately admitted and permitted, the selected disposable OpenBSD profile
must exercise the actual compiled candidate and complete chosen ingress path,
not only an engine handler or host-cross-built substitute. Include startup-invalid
config/trust/rules; selected frontend/backend trust failures; unknown authority;
loss/recovery of inspection/backend service; invalid and valid whole-generation
replacement; held old-generation work; overload; drain/retirement failure; crash;
management absence; and validated known-good restoration.

M2-A05 needs independent positive controls and distinct unauthorized principals
at each selected sender/backend boundary. Existing PF/UID tests cover only their
fresh local IPv4 socket profile; they do not qualify remote networks, IPv6,
existing-state revocation or compromised allowed identities. Record those limits.
No live gateway, storage or applications are permitted by this design.

## Resources, compatibility and security

Bind each limit to EDD D4's approved numerical value, workload, hardware, interval
and measurement method. Record process/child CPU, memory, files/sockets, temporary
and audit storage, latency/completion and cleanup separately. Report peaks and
failure behavior as well as successful steady state. No acceptance until these
criteria exist; small lab bursts and host checks cannot establish product budgets.

Specifically qualify the EDD's proposed shared four-second shutdown target rather
than counting per-server deadlines as a total bound. Exercise a deadline already
expired before a later stage, cross-generation saturation, and configured parser
header limits versus actual wire admission. The proposed normalization policy
needs paired original-wire/inspection/backend witnesses; it cannot pass based on
handler-level normalized fields alone. Remaining startup/reload/retirement,
health-capacity and hard-resource gaps must be resolved before those gates run.

The selected engine/CRS and dependency/NOTICE graph need their own qualified scope.
Preserve benign/false-positive samples, unsupported application behavior and
known failed cases; never weaken a zero-effect assertion or retry until success.
Affected advisory and security checks remain blocked while their pause applies.
There is no management UI in M2, so UI/accessibility acceptance is not claimed;
M3 must supply its own design if it introduces one.

## Retained evidence and current blockers

The baseline for this paper packet is
`c080a869ac60b2844490e16532b5f3687f4e8b7e`. Existing reports are source-bound inputs:

| Evidence | What it establishes | What remains open |
|---|---|---|
| [TLS passthrough](../../../research/native/tls-passthrough-observations.json) | 29 scoped path cases at `433ca9c0f362d581a969104407d6a41ab7f9d0cc`; tested SNI/authority behavior | Product key/rotation/privilege/profile acceptance; initial build timeout remains retained |
| [Configured Caddy](../../../research/native/configured-caddy-observations.json) | 30 cases/five configuration observations at `fd1882d07e24dff7939863a2a789f076f5849cd8` | Complete comparable trust/resources/protocols and residual advisory adoption |
| [Backend isolation](../../../research/native/backend-isolation-observations.json) | Distinct-user effects and restoration in the scoped local fixture | Product identity/network/compromise boundary |
| [Request-wire failure](../../../research/native/request-wire-native-failure.json) | Native build and 163 ordinary cases passed at `cbc21ae71fb94c5da25580856729d518c48a874d`; legacy composition failed | Three post-reload response failures unexplained; later native matrices, including 52 wire rows, unexecuted |
| [Official baseline](../../../research/native/official-baseline-observations.json) | Selected installed-file lineage and ordinary component profile | No retrospective authentication of inherited-image traffic results or M2 qualification |

For the failed composition, zero backend effects do not satisfy the required
responses; the expected outcomes remain unchanged. The ordinary transport
diagnostic follow-up is host tooling, not a diagnosis or native repeat. See the
[full retained limitation](../M1/REQUEST-WIRE.md). Later ordinary component passes
do not upgrade this source or replace complete-profile validation. #18 remains
blocked by #16/#17, and #19 by M1 #2; document review closes none of these gates.

## Fixture safety, rollback and candidate evidence

Any future admitted run needs exact source/tree/base, build/runtime/dependency
and public fixture identities, release/architecture and command/outcome records.
Use private ephemeral test keys only under the then-reviewed custody procedure;
no private key or raw inventory enters Git/evidence. Fixed work/cleanup limits,
owned process/socket/file/policy restoration, independent absence and source/base
invariance must be specified before launch. This paper packet allocates none.

Preserve failed/skipped original reports and distinguish compile, execution,
runtime acceptance and teardown. Restore only the exact owned fixture state;
never reuse failed/live mutable fixtures or modify unrelated host/network state.
Rollback cannot undo application effects or turn an older unsafe profile into
an accepted product. No installer/service state is created by this proposal.
