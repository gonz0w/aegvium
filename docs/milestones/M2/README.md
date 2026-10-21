# M2 bounded inline enforcement design

Status: **Boundary and M2-H1/1 source contract selected for reviewed adoption;
runtime integration UNIMPLEMENTED/UNQUALIFIED.** Broader M2 remains proposed.
Owner: Cam (`@gonz0w`). Date: 2026-10-19.
Refs [#19](https://github.com/gonz0w/aegvium/issues/19),
[#18](https://github.com/gonz0w/aegvium/issues/18).

The proposed first outcome is an explicitly allowlisted application path behind
EdgeWall: complete bounded request inspection, verified authority/backend trust,
and no uninspected forwarding on rejection or failure. Read the [PRD](PRD.md),
[EDD](EDD.md), [Test Design](TDD.md) and [TLS ownership comparison](TLS-OWNERSHIP.md)
together. They refine [M2's existing roadmap](../ROADMAP.md); they neither select
a production topology nor turn the research CLI/configuration into a product.

The [selected boundary ADR](../../architecture/adr-0010-frontend-key-mandatory-inspector.md)
and [M2-H1/1 contract](FRONTEND-INSPECTOR-CONTRACT.md) resolve the direction under
delegated engineering authority: frontend custody of the public endpoint private
key and authenticated separate series inspection. The [earlier recommendation](SECURE-BOUNDARY-RECOMMENDATION.md)
remains evidence. Only M2-C01's pure source-contract component is specified as the
next implementation slice; no current connector or required-WAF enablement exists.

The [M2-C01 inert context component](M2-C01.md) is now implemented with portable
tests. Its success only records a context; it grants no allow verdict and has no
transport or backend call. The next runtime adapter still requires its scoped
design and all applicable framing/trust/inspection/containment/qualification gates.

The proposed [M2-A01 adapter EDD](ADAPTER-EDD.md) and [Test Design](ADAPTER-TDD.md)
now recommend concrete mTLS roles, paired startup facts and a single request/
transaction owner. Its first implementation slice is a no-dial receiver and
coordinator fixture; strict original-wire framing and backend enablement remain
separate blocking gates. This proposal is not current runtime behavior.

The separate [M2-C02 capacity owner](CAPACITY-OWNER.md) scopes ordinary effect-free
bookkeeping for A01a's shared request/socket reservations, retirement and explicit
release. It leaves the real peer, transport, attempt barrier, cancellation,
transaction and shutdown/join integration unimplemented. It neither adopts the
paused pair descriptor nor changes M2-H1/1 or the existing validation pause.

The [A01a body owner](BODY-OWNER.md) now binds private C02 reservations to actual
bounded Read/Close calls and detached memory-only body records. It retains charges
while either call is unfinished and stops admission on uncertain Close. Original
deadline/cancellation, retirement and Stop suppress late records. Real engine
transaction ownership, authenticated same-connection transport/framing and full
receiver/shutdown qualification remain separate; no application dial is present.

The maintainer selected [exclusive external inspector ownership](../../architecture/adr-0011-inspector-owner-containment.md)
for scoped source implementation. Its first [private C11 lifecycle controller](../../../internal/inspectorowner/README.md)
implements the [frozen contract](SUPERVISOR-CONTROLLER.md) with synthetic
ownership/clock observations and no native launcher, signal,
wait, credentials or runtime activation. Four-second shutdown remains mandatory
and unqualified; old reservations cannot be released merely because stop was
requested. Durable startup history and native containment remain separate gates.

This paper packet uses canonical source
`c080a869ac60b2844490e16532b5f3687f4e8b7e` and its linked historical receipts.
It creates no keys, runtime configuration, service, installer or execution packet.
Affected security, traffic and advisory validation remains **paused/blocked**.
No test procedure below authorizes a run, retry, access expansion or workaround.

## Sequence and acceptance ownership

1. M2-C01's bounded immutable context source is implemented; review/verification
   remains source-bound. Next scope the adapter design. Engineering owns framing/trust
   proofs, adapter design and remaining D2–D4 resource/lifecycle gaps; no further
   CTO key-location or ordinary mechanism/numerical choice is needed.
2. Keep [M1](../M1/README.md), its parser/CRS blockers and
   [ADR 0001](../../architecture/adr-0001-ingress-inspection.md) open. Issue #18
   depends on #16/#17; issue #19 depends on M1 gate #2. Drafting this packet does
   not satisfy those relationships or their candidate-specific acceptance.
3. The ADR/contract scope the next source component; later runtime slices still
   need their candidate-specific approved EDD/Test Design. Native enforcement and
   bypass acceptance belongs to #24 under M2 gate #3, separately from document
   review and each implementation issue #20–23.

Management/policy operations remain M3; distribution/BootWeave remains M4;
stability and personal-use acceptance remain M5. No delivery date is asserted.
GitHub owns live status and blockers; these links are not a second progress queue.

## Review choices

- **Product boundary:** retain the proposed narrow request-enforcement outcome;
  no management UI or additional protocol project is needed to describe it.
- **Key custody:** frontend-only custody of the public endpoint private key is
  selected; internal service keys remain separate. No live key or topology changes.
- **Engineering closure:** propose and review exact raw-wire/authority admission,
  production principals/containment, certificate operations and numerical hard
  budgets before runtime approval. M2-H1/1 selects fixed-length-only admission and
  paired startup snapshots, superseding the earlier preferred normalization option
  for this slice without claiming raw-wire enforcement. Engineering closes gaps;
  the maintainer need not invent mechanisms or numerical resource limits.

Document review checks links, requirement coverage and honest evidence boundaries.
The repository's local `make verify` requirement remains with the identified
publication candidate; no hosted CI or security-validation substitute is added.
