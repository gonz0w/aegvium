# M2 product requirements: bounded inline enforcement

Status: **M2-H1/1 boundary/source-contract scope selected; broader runtime
implementation and product acceptance remain unapproved.** Owner: Cam (`@gonz0w`).
Date: 2026-10-19. [EDD](EDD.md), [Test Design](TDD.md), [entry](README.md).
Authority: [WAF-01–06](../../product/PRD.md), [M1-05](../M1/PRD.md),
[#19](https://github.com/gonz0w/aegvium/issues/19).

The [boundary ADR](../../architecture/adr-0010-frontend-key-mandatory-inspector.md)
and [M2-H1/1](FRONTEND-INSPECTOR-CONTRACT.md) supersede the initial proposed
frontend/custody/compatibility choices below for the first source slice: separate
authenticated series inspection, fixed-length-only close-only HTTP/1.1 and no
seamless replacement. Only its M2-C01 pure context-admission component is next;
requirements and acceptance outside that scope remain proposed/unexecuted.

## Operator outcome and workflows

An operator declares a bounded allowlist of application authorities and explicit
backend destinations on a separate OpenBSD WAF VM behind EdgeWall. A request is
forwarded only after its authority, identity boundary, supported representation
and complete admitted input pass the selected inspection policy. Unknown routes
and inspection errors must never select an uninspected fallback.

The operator can validate a replacement without activation, retain a known-good
inspected configuration after rejection, and deliberately restore it after a
successful replacement. A client failure does not promise no application effect;
the system must distinguish failure before forwarding from response failure
after an inspected effect. No automatic replay or safe-retry promise is included.

## Requirements and acceptance IDs

All requirements below are proposed obligations, not observed product results.
Their matching acceptance IDs and evidence levels are in the Test Design.

| Requirement | Parent | Required outcome |
|---|---|---|
| M2-01 | WAF-01/03 | Typed, bounded, unique authority-to-backend routes; deny unknown authorities and invalid destinations; no default backend or bypass fallback. |
| M2-02 | WAF-03/05/06 | Bind frontend authority to the selected TLS/trusted-ingress contract; verify backend TLS name/trust; discard spoofable forwarding metadata; authenticate the sender boundary before trusting client identity. |
| M2-03 | WAF-02/03 | Inspect every admitted request field and complete bounded body under pinned engine/CRS policy before forwarding; deny inspection failure and unsupported input with zero backend effects. DetectionOnly is not enforcement acceptance. |
| M2-04 | WAF-04 | Bound configuration, headers, bodies, responses, data connections, in-flight work, time and storage; reject overload without bypass; qualify hard process/resource limits separately. |
| M2-05 | WAF-03/06 | Least-privilege data plane, protected keys/configuration and independent containment of inspection and backend access; management absence does not disable enforcement. |
| M2-06 | WAF-03/06 | Validate before ready; complete replacement preparation before publication; preserve old configuration on prepublication failure; bound drain/retirement and stop safely on postpublication ownership failure. |
| M2-07 | WAF-05/06 | Bounded redacted outcomes distinguish rejection, inspected forwarding and unknown/failed response completion; retain exact candidate evidence and failures without raw secrets or traffic. |
| M2-08 | WAF-01–06 | Independent disposable OpenBSD enforcement, bypass, failure, recovery and resource evidence for the exact candidate, with known-good restoration and complete owned teardown. |
| M2-09 | WAF-09 | Independently installed Aegvium with a conforming non-suite frontend and operator-controlled perimeter; no suite control-plane/runtime prerequisite. Explicit protocol configuration and conformance vectors; requested inspection failure never becomes bypass. Standalone and optional-suite integration scenarios both require acceptance. |

## Scope and compatibility profile

The **proposed first profile** is intentionally bounded by the existing
[lab interface](../../../research/coraza/LAB-PROXY.md), not an assertion that its
current or historical implementations satisfy every row. EDD D3 must close the
wire-admission details before implementation approval.

| Surface | Proposed admission | Deferred or rejected in this profile |
|---|---|---|
| Frontend | HTTPS; HTTP/1.1; one request per data connection, followed by close | Plaintext ingress, HTTP/2/3, keepalive/reuse, pipelining, upgrades/WebSocket and general streaming |
| Methods/media | GET/HEAD with no request body; POST with bounded JSON or form body, complete before forwarding | Other methods/media and compressed request content; no silent pass-through |
| Body framing | Bounded fixed-length or chunked body, complete EOF and no trailers | Declared/undeclared trailers, truncation and conflicting framing; exact duplicate-length/CL+TE admission is an unresolved raw-wire design gate, not a normalization safety claim |
| Authority | Exact configured DNS authority and explicit ingress-port policy; certificate coverage and selected SNI binding | Wildcards, implicit aliases, unknown names/ports; case/trailing-dot normalization must be specified in D3, not guessed |
| Backend | Explicit route target; verified HTTPS, or explicitly reviewed HTTP within the protected application boundary | Arbitrary client-directed destinations, redirects/retries that escape the selected route, unconstrained DNS or remote-backend trust |
| Responses | Bounded forwarding of the inspected request's response, with completion/error classified separately | Response-content WAF guarantees, streaming and safe-retry/transaction rollback claims |

Unsupported traffic must receive the selected bounded rejection/connection-close
behavior before backend forwarding; handshake failures need no HTTP response.
Naming a feature unsupported is not enough if its input can still reach a backend.
Existing parser normalizations and half-close findings remain qualification gaps.
Client write shutdown must never be interpreted as proof of cancellation.

The initial authority/network model is one separately owned appliance with a
reviewed local inspection boundary. Remote backend isolation and IPv6 must either
receive explicit acceptance in the chosen profile or remain unavailable; the
loopback IPv4 research controls do not qualify them. No production UID, listener,
route syntax, service name or installer extension schema is selected here.

## Quality, security and recovery

The EDD recommends an initial finite size/concurrency/deadline and shutdown
profile for review, grounded in retained source. Those proposed values are
unadopted and unmeasured as product limits; they are not accepted capacity.
Hard CPU/RSS/storage, health capacity, whole startup/reload/retirement and
latency/throughput criteria remain approval blockers for engineering to resolve.
Its preferred single-parser normalization policy is a paper option, not a claim
that ambiguous framing is currently supported or strictly rejected.

Protect keys, route integrity and backend isolation against the untrusted inputs
in the [threat model](../../security/threat-model.md). An allowed service principal
or root compromise is not covered by the existing socket-UID containment result.
Avoid secret-bearing body/header/query logging; error classes must not expose
private paths, certificates or configuration contents. M3 owns richer audit/health
operations; basic redacted failure evidence is required here.

Recovery restores a complete inspected generation after validation. It cannot
undo backend effects or revive failed mutable fixture state. Changes to keys or
containment require their own reviewed custody/restoration contract. No rollback
may route around the engine or substitute older evidence for a changed candidate.

## Dependencies and non-goals

M1 comparison, parser, pinned CRS, dependency/legal and adoption gates remain open.
The unexplained retained reload failure and unexecuted later wire matrix remain
blocked; see [TDD](TDD.md). Affected validation remains paused.

Excluded: M3 policy-update distribution, exclusions and management UI; M4 installer
and upgrades; M5 soak/release acceptance; CrowdSec and later protocol/response
inspection work. This packet makes no OWASP Top 10 coverage, real-application,
live-deployment or throughput claim. BootWeave's generic contract remains external.
