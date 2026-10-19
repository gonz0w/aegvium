# M2 paper comparison: TLS ownership

Status: **Proposed decision support; no production topology selected.**
Owner: Cam (`@gonz0w`). Date: 2026-10-19. [Packet](README.md), [EDD](EDD.md).
Source baseline: `c080a869ac60b2844490e16532b5f3687f4e8b7e`.
This preserves [ADR 0001](../../architecture/adr-0001-ingress-inspection.md) and
[ADR 0005](../../architecture/adr-0005-tls-passthrough-research.md); it does not
amend their adoption state. No key is created, moved or read by this paper work.

## Same outcome, different custody

| Choice | Documented advantage | Cost and unresolved contract |
|---|---|---|
| relayd owns TLS; companion inspects plaintext | Base-system TLS ingress and health-checked dispatch; TCP avoids a second HTTP parser in the proposed comparison | Companion cannot establish original SNI from stock PROXY v1 addresses; pinned v2 writer has no TLS TLVs. Need an independently authenticated authority-binding contract; client headers cannot repair it. |
| relayd forwards TCP; companion owns TLS after prefix parsing | Actual TLS state permits SNI/HTTP authority binding; retained 29-case profile addresses the tested cross-host gap without patching relayd | Companion gains private-key/certificate custody and replacement obligations. Prefix trust, product sender containment, startup, privilege and backend isolation remain separate. |
| Existing coraza-caddy connector | Existing request/error/replay/cleanup/reload/response integration; strict configured SNI/Host control rejects the tested mismatch | Broader dependency graph, residual CEL package-only/OpenPGP module-only adoption findings, differing Host-port/media policy and incomplete equivalent topology/resource qualification |

The observations above come from the [connector assessment](../M1/CONNECTOR-ASSESSMENT.md),
[configured comparison](../M1/CONFIGURED-CADDY.md),
[TLS profile](../M1/TLS-PASSTHROUGH.md) and ADRs. They do not show that more source
or dependencies consume more runtime resources. The configured Caddy comparison
is separate from its smaller API harness and from current companion qualification.

## Authority and key boundaries

For relayd-owned TLS, documented alternatives include a separately authenticated
metadata channel, a source patch, or per-name isolated listeners. None is selected
or qualified. Patches add upstream maintenance; per-name listeners complicate
route/certificate ownership. This packet creates no new protocol for them.

For companion-owned TLS, the retained experiment validates route certificate
coverage at startup/replacement and binds each request to actual SNI. Certificate
replacement required stop/start in that slice. It does not establish product
rotation, renewal, rollback, revocation, file custody or distribution. Product
owners must specify which principal can read keys and who can replace them, how
replacement is validated, and what remains ready on failure. Those are D1/D2
decisions, not permissions to manipulate credentials now.

Either composition must authenticate the local sender boundary before trusting
PROXY identity and must separately prevent direct backend bypass. Existing
conditional socket-UID PF evidence covers fresh local IPv4 connections only;
root/PF administrators and compromised allowed principals are outside it. TLS
authority correctness alone does not establish client identity or isolation.

## Recommendation and rejection criteria

Continue the documented TCP-first comparative decision; do not select production
architecture from this paper. Give companion-owned TLS explicit review attention
because its retained actual-SNI binding addresses a demonstrated gap. This is an
inference about which decision to examine, not a superseding adoption decision.
Keep relayd-owned TLS as a control and coraza-caddy as the existing alternative.

The maintainer need only state whether companion key custody is acceptable to
evaluate or whether key location is a firm product constraint. Engineering must
then propose the exact authority/privilege/certificate contracts and compare all
candidates against M2-01–08, including unsupported behaviors and measured costs.
Do not silently choose an authentication mechanism or add another approval gate.

Reject a candidate if it cannot bind the selected authority/client identity,
prevent uninspected access, preserve the admitted protocol/error/lifecycle
behavior, or meet the agreed resource and custody obligations. Retain the existing
alternative rather than hide failures with fallback or weaker expectations.
relayd must justify its independent operational role against the existing connector;
no two-process preference or Traefik/Caddy feature parity follows from this packet.

## Evidence needed and current limit

The [Test Design](TDD.md) maps the same acceptance outcomes to each chosen
composition. Complete current-source trust/protocol/CRS/resource and lifecycle
evidence remains missing; the legacy reload failure and later unexecuted wire
scope remain unchanged. The authenticated stock baseline qualified only its
selected ordinary component profile, not historical inherited-image traffic.
Affected security, traffic and advisory validation remains paused/blocked.
This paper comparison neither resumes it nor requests access expansion. No
implementation, native launch, installation, live network or service change occurs.
