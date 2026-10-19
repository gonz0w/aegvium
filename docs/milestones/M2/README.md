# M2 bounded inline enforcement design

Status: **Proposed for review; implementation and architecture adoption withheld.**
Owner: Cam (`@gonz0w`). Date: 2026-10-19.
Refs [#19](https://github.com/gonz0w/aegvium/issues/19),
[#18](https://github.com/gonz0w/aegvium/issues/18).

The proposed first outcome is an explicitly allowlisted application path behind
EdgeWall: complete bounded request inspection, verified authority/backend trust,
and no uninspected forwarding on rejection or failure. Read the [PRD](PRD.md),
[EDD](EDD.md), [Test Design](TDD.md) and [TLS ownership comparison](TLS-OWNERSHIP.md)
together. They refine [M2's existing roadmap](../ROADMAP.md); they neither select
a production topology nor turn the research CLI/configuration into a product.

This paper packet uses canonical source
`c080a869ac60b2844490e16532b5f3687f4e8b7e` and its linked historical receipts.
It creates no keys, runtime configuration, service, installer or execution packet.
Affected security, traffic and advisory validation remains **paused/blocked**.
No test procedure below authorizes a run, retry, access expansion or workaround.

## Sequence and acceptance ownership

1. Review the narrow capability/profile and the two TLS ownership choices against
   the existing connector alternative. Resolve EDD decisions D1–D4 using the
   retained evidence; record missing evidence rather than inventing conclusions.
2. Keep [M1](../M1/README.md), its parser/CRS blockers and
   [ADR 0001](../../architecture/adr-0001-ingress-inspection.md) open. Issue #18
   depends on #16/#17; issue #19 depends on M1 gate #2. Drafting this packet does
   not satisfy those relationships or their candidate-specific acceptance.
3. Only an accepted candidate-specific architecture and approved scoped
   PRD/EDD/Test Design admit product implementation. Native enforcement and
   bypass acceptance belongs to #24 under M2 gate #3, separately from document
   review and each implementation issue #20–23.

Management/policy operations remain M3; distribution/BootWeave remains M4;
stability and personal-use acceptance remain M5. No delivery date is asserted.
GitHub owns live status and blockers; these links are not a second progress queue.

## Review choices

- **Product boundary:** retain the proposed narrow request-enforcement outcome;
  no management UI or additional protocol project is needed to describe it.
- **Key custody:** is companion access to TLS private keys acceptable to evaluate,
  or must ingress keys remain at relayd? Neither answer proves a safe topology.
- **Engineering closure:** propose and review exact raw-wire/authority admission,
  production principals/containment, certificate operations and numerical hard
  budgets before approval. The EDD supplies a concrete initial finite profile,
  separated-principal/startup-only certificate replacement proposal and preferred
  normalized-input policy. Engineering owns closing the remaining measured gaps;
  the maintainer need not invent mechanisms or numerical resource limits.

Document review checks links, requirement coverage and honest evidence boundaries.
The repository's local `make verify` requirement remains with the identified
publication candidate; no hosted CI or security-validation substitute is added.
