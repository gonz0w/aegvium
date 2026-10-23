# ADR 0010: frontend public key custody and mandatory series inspection

Status: **Selected design for adoption through the normal reviewed PR gate.**
Date: 2026-10-19. Authority: the maintainer delegated secure best-practice design
and asked engineering to resolve ordinary integration choices rather than leave
[#119](https://github.com/gonz0w/aegvium/pull/119) indefinitely unadopted.
This decision selects a boundary and an implementation contract. It does not
claim an implemented, qualified, installed or released runtime.

## Decision

Select Vectivium's provisional HAProxy frontend as the eventual public TLS owner,
followed in series by a separately authenticated, unprivileged Aegvium inspector
and an explicitly allowlisted HTTPS application. Keep Aegvium on its separate VM
behind EdgeWall. Do not add relayd to the selected suite path or select a callout,
side-channel verdict protocol, same-host profile or Caddy runtime in this slice.
The existing relayd/companion/Caddy experiments remain immutable comparisons.

Only the frontend may read the **public endpoint private key**. The inspector
necessarily receives plaintext, and may hold distinct internal service keys for
its authenticated links. Public certificates are shareable. Neither the inspector
nor a health/management principal receives frontend routing/Runtime API authority,
certificate issuance authority or an uninspected application path. An operator
owns trust/configuration and containment; serving identities cannot replace them.

Use mutually authenticated HTTPS between frontend and inspector, with dedicated
internal certificates, explicit service identities and no CA-membership-only
authorization. The inspector alone forwards an allowed, completely inspected
request to its configured backend. Backend access must independently exclude
frontend and management identities. [M2-H1/1](../milestones/M2/FRONTEND-INSPECTOR-CONTRACT.md)
defines the selected semantic boundary, limits and failure ownership.

This chooses the design; it does not assert that Vectivium has a WAF connector.
At `acd5c337230eab11cc65e15b812c9f334e72b49b`, its preview deliberately rejects
every route except `inspection=none`. Preserve that rejection until a reviewed
implementation and its capability gates exist. Do not route around it.

## Scope and consequences

Maintainer clarification,2026-10-22: Vectivium/EdgeWall identify the selected
optional suite integration, not mandatory dependencies of Aegvium's core
function. Any independently configured frontend satisfying the explicit current
protocol, authentication, provenance, byte fidelity and ownership contract may
integrate. Keep the isolated OpenBSD inspector behind an operator-controlled
perimeter. No Vectivium binary, EdgeWall API or suite control plane is required.
Standalone installation and third-party conformance are required acceptance,
still undelivered/unqualified. An enabled WAF integration must fail closed;
"optional" permits deliberate feature selection, never silent bypass on failure.
Public-key custody and the series inspection boundary remain unchanged.

The first WAF contract is close-only HTTPS HTTP/1.1 with a complete bounded
fixed-length request. Chunked input, trailers, h2/h3, gRPC, upgrades, CONNECT and
streaming remain unavailable. This narrows the earlier proposed fixed/chunked
profile. It does not reduce Vectivium's separate h1/h2/gRPC/WebSocket product
obligations or qualify protocol translation. A future WAF-specific listener must
enforce this profile before translation/forwarding; a shared h2 listener is not
implicitly acceptable. No listener or service is created by this change.

The authenticated HTTPS request itself carries the request and its context;
inspection and forwarding share one owned context/generation/body. There is no
portable allow token to replay against another request. Public SNI and Host are
bound at the trusted frontend; internal TLS SNI names the inspector, not the
public application. This adds operational peer/trust identities and a second HTTP
parser, whose disagreement and failure behavior need exact-package evidence.
Key separation reduces authority exposure; it does not protect against a
compromised frontend or make plaintext safe from a compromised inspector.

## Decision ownership and actual blockers

| Item | Disposition and owner |
|---|---|
| Public key owner, series inspection, separate WAF VM, first bounded profile | Selected here under delegated engineering authority; no additional CTO choice is needed. |
| Peer identity, immutable route/generation binding, no bypass/retry, startup-only replacement | Selected contract; engineering implements and reviews exact admission and ownership. No service or credential is provisioned. |
| HAProxy metadata, public SNI/Host binding, raw framing and byte fidelity | Engineering proof gap. The exact 3.2.25 source normalizes equal lengths and CL+TE, so post-parser header counts cannot prove strict rejection. Qualify an existing admission boundary or openly review a normalized-input contract; do not invent options, native success or a custom parser. |
| Aegvium internal mTLS receiver and backend admission | Unimplemented. Existing companion TLS accepts public-edge custody in a different research profile; it is not this receiver. |
| Hard resource/lifecycle bounds, engine/CRS/dependency acceptance, retained reload failure | Engineering/qualification blockers, not values or mechanisms for the CTO to invent. M1 and M2 gates remain open. |
| Protocol expansion, fail-open, co-location or inability to meet this boundary | A consequential change to scope/security direction; return the concrete tradeoff to the maintainer instead of silently weakening this decision. None is required to prepare the next source slice. |

## Next implementation and acceptance

Authorize the narrowly specified **M2-C01 source-contract slice** in the linked
contract: bounded immutable context/route admission and a recording context
consumer, with pure portable tests and no listener, transport, renderer enabling
required WAF, keys, deployment or engine-policy execution. A separate PR must
carry its implementation/tests and independent review. This decision is not
blanket approval of M2 runtime implementation or execution.

Then specify and implement the authenticated receiver/forwarder and the matching
Vectivium adapter in their owning repositories against this version, keeping
required-WAF disabled until both exist. Exact-package/parser, trust, no-bypass,
failure/recovery, resource and native acceptance precede enablement. The current
security/traffic/advisory/native pause still applies; this document resumes none.

This ADR supersedes ADR 0001 and the #119 recommendation only for the selected
M2 suite boundary. Research conclusions and their narrower scopes remain intact.
M2 requirements outside this slice, management M3 and distribution M4 remain open.
Rollback revises this source decision/contract; no runtime state, key or migration
exists to undo. A future runtime rollback must preserve mandatory inspection.
