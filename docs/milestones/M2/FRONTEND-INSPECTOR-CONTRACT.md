# M2-H1/1: frontend to mandatory inspector contract

Status: **Selected source contract; runtime integration UNIMPLEMENTED and
UNQUALIFIED.** Date: 2026-10-19.
[Decision and delegated scope](../../architecture/adr-0010-frontend-key-mandatory-inspector.md),
[PRD](PRD.md), [EDD](EDD.md), [Test Design](TDD.md). Refs #19/#20–24.
This version is a design, not a current public API, JSON configuration, CLI,
HAProxy configuration or certificate provisioning procedure.

## Peers, routes and lifetime

The only data path is frontend → Aegvium → selected application. Both internal
links use verified HTTPS with client authentication and role-specific dedicated
internal keys. Validate chains, validity, intended client/server usage and exact
configured DNS service identities; CA membership alone grants no role. Explicit
peer allowlists and server names come from immutable operator configuration, never
from client metadata. Do not use the public endpoint key on either internal link.
No ambient proxy, redirect, service discovery, fallback or retry is allowed.

The application must authenticate/allow only the inspector data identity, with
independent network admission that denies direct frontend/management access.
An application lacking this boundary is unavailable in this initial profile;
do not silently substitute a plaintext or unrestricted backend. No existing
application is claimed to implement it. Health only reports this path's readiness;
it has no application-forwarding operation or allow authority.

One startup snapshot owns at most eight unique route IDs, exact public DNS names
and ports, permitted frontend peers, fixed numeric inspector/backend addresses,
their TLS names/trust, and an exact engine/CRS policy pin. No wildcard/default
route, request-selected destination or runtime policy download. Use a common
operator-assigned 32-lowercase-hex generation token in both snapshots. It identifies
a paired immutable configuration, not a content hash or proof that peers agree.
Use a fresh token for each paired startup/change/rollback; never revive an old
generation token or request context.
Startup must verify compatible route/policy/capability pins; mismatches stay unready.
The exact paired configuration representation and verification belong to the
later adapter design, not an invented existing Vectivium feature.

For this first integration, configuration, trust and certificate changes use a
deliberate stop/validate/start, with fresh connection/request state. No seamless
reload, automatic renewal or old-generation continuation is promised. This
narrows M2's broader replacement proposal; its remaining lifecycle contracts and
hard-resource measurements stay open before a runtime slice is admitted.

## Authenticated request context

Use the same mutually authenticated HTTP/1.1 request for metadata and application
input. Each internal connection carries one request and closes; no multiplexing
or connection reuse. A second/pipelined request is never admitted or forwarded;
this does not undo an effect from the one already admitted first request.
Do not expose a separate verdict endpoint or transferable allow token. The frontend must reject externally supplied `Aegvium-*` fields and
spoofable `Forwarded`, `X-Forwarded-*` or `X-Real-IP` fields before constructing
its own context. The inspector rejects missing, duplicate or unknown reserved
fields and removes all reserved fields before application forwarding.

The future carrier has exactly these single-value fields; names are
case-insensitive HTTP field names, values use the explicit bounds below:

| Field | Meaning and bound |
|---|---|
| `Aegvium-Contract` | Exact `M2-H1/1`; no version negotiation or downgrade. |
| `Aegvium-Route` | Configured `[a-z][a-z0-9_]{0,31}` route ID, never a URL or backend selector. |
| `Aegvium-Generation` | Exact configured 32-lowercase-hex snapshot token; missing/foreign generation rejects. |
| `Aegvium-Request` | Frontend-assigned 1–64 ASCII alphanumeric/underscore/hyphen correlation ID, unique within its serving instance; not client input, permission, replay protection or an exactly-once promise. |
| `Aegvium-SNI` | Actual public TLS SNI, canonical lowercase ASCII DNS, at most 253 bytes; no wildcard, IP literal, empty/trailing-dot name or inferred Host value. |
| `Aegvium-Client` | Actual frontend-observed canonical IPv4 source address; never a browser forwarding claim. IPv6 needs a later scoped contract. |

TLS authenticates the frontend; it does not independently prove what public SNI
it observed. That observation and rejection policy are frontend responsibilities
with their own tests. The inspector independently requires allowed peer + route +
generation + configured public SNI + external Host/port agreement. Hostname
comparison folds ASCII case only; preserve the original Host bytes for forwarding.
An absent Host port is valid only for configured port 443; an explicit decimal
port without leading zeros must match the configured ingress port. Reject aliases,
userinfo, IP authorities, trailing dots and absolute-form targets. Internal TLS
SNI/Host transport handling must never replace the external application Host.

Method, original Host, origin-form encoded target including query, headers and
complete body belong to this same authenticated request and immutable context.
Do not serialize context from one request around another's body or destination.
The inspector owns the complete body and engine transaction through its single
forwarding attempt; generation/lifetime must still be valid immediately before
that attempt. Cancelled/retired work cannot later forward. Correlation IDs alone
never authorize a request, detect duplicates or make replays safe.

## Initial admission, bounds and forwarding

Admit only HTTPS HTTP/1.1, GET/HEAD with no body and POST with JSON or URL-encoded
form content, one exact Content-Length and at most 4096 body bytes. No
Content-Encoding, Transfer-Encoding/chunking, trailers, Expect, pipelining, persistence,
upgrades, CONNECT, h2/h3, gRPC, signed streaming or general streaming. Reject
duplicate Content-Length, including equal duplicates, and CL+TE. GET/HEAD may have
no Content-Length or exactly zero. An absent/unknown capability never means pass.

These are required original-wire outcomes, **not claims that current HAProxy/Go
parsers expose or reject every form**. Parser normalization can hide original
fields. Exact-package wire evidence must prove enforcement before enablement;
if the selected parser cannot enforce it, report the limitation and review a
narrower supported subset or an existing qualified boundary. Do not add a custom
parser or reclassify normalization as rejection without a new reviewed design.
No h2 translation is admitted by the general frontend's h2 support.

A read-only check of the retained exact **3.2.25** release source makes this a
concrete blocker: `src/http.c`'s `http_parse_cont_len_header` collapses equal
length values; `src/h1.c` skips the duplicate field and removes Content-Length
when Transfer-Encoding is present. Post-parser header counts therefore cannot
establish original duplicate/CL+TE rejection. Keep strict rejection as an
unqualified requirement, not a claimed existing HAProxy feature. Before the
adapter is enabled, engineering must identify a qualified existing admission
boundary or openly review a named normalized-input alternative with independent
original-wire/inspection/backend and no-second-effect evidence. All transfer
encoding remains unsupported either way; changing the prose alone proves none
of this. No custom parser, package patch or CTO decision is selected by this
source observation. Pure M2-C01 is unaffected by this runtime proof blocker.

Keep 4096 bytes of public request line + headers, a 2048-byte encoded target and
1024 bytes of internal context fields as design ceilings. The internal request
header ceiling is 5120 bytes including the context; these are separate public and
internal bounds, not a widened public limit. Inspect complete admitted fields and
body before any application effect. Per inspector instance, at most four admitted requests and eight total data
connections, counting accepted and outbound sockets together; no application
queue. Admission is shared across that process's generations. The frontend also
needs finite matching admission; no distributed suite-global capacity is claimed.
Bound response bodies to 4096 bytes without claiming response-content inspection.
The EDD request clocks remain initial design targets, not measured product bounds;
health capacity, total startup/retirement, CPU/RSS/FD/storage limits still require
a separate runtime admission design. A parser setting is not a wire-byte proof.

Forward only the inspected representation to the fixed route. Preserve external
Host including an admitted explicit port, method, encoded path/repeated slashes,
query order/multiplicity, signed header values and payload bytes. Do not decode
and reconstruct targets, normalize S3 paths, re-sign with operator credentials or
drop signed fields to make the contract fit. Hop-by-hop/framing changes need an
explicit exact-byte oracle; reject a signed representation that cannot survive
them. Never silently convert streaming signatures to ordinary payloads.

Wrong TLS identity fails the handshake. Invalid context/input closes with a safe
400, unknown authority with 421, header/body limits with 431/413, inspection denial
with 403, and unavailable inspection/generation/capacity with 503. Handshake or
incomplete/invalid framing may require connection close without an HTTP response;
the adapter test design must pin each expected outcome, not count a timeout as
success. Backend/response failures use bounded 502/504 where a response can still
be sent. Once a backend attempt starts, effect may be unknown even if the client
receives an error. No automatic retry or assertion that an application effect was
reversed. Backend access is never enabled by a health result or failure handler.

## M2-C01: precise next source implementation

Implement a small internal, stdlib-only immutable request-context/route admission
component with an injected already-authenticated peer descriptor and a recording
context consumer. A transport adapter alone constructs that descriptor from
verified TLS; never accept a header/boolean as proof of authentication. Inputs
are bounded parsed values, an owned complete synthetic body and one snapshot.
Do not pretend that this component proves original-wire framing or actual TLS.

Portable tests must independently exercise exact bounds and cap+1, duplicate/
unknown/missing context, wrong peer/route/SNI/Host/port/generation, body ownership,
target/header/payload fidelity, and cancellation/retirement before forwarding.
The recorder must see exactly one intended immutable context for admission and
none for rejection; no late/stale context can select another route. Context
admission is not an allow verdict and never calls a backend. The future serving
consumer must still perform complete policy inspection before forwarding.
Use finite synthetic values and deterministic fake I/O/clock barriers, no listener,
key/certificate generation, real engine policy, HAProxy execution or native run.
No dependency or new service is needed. This is the only next source slice
specified/admitted here; it cannot enable a required-WAF route.

Subsequent receiver/forwarder and Vectivium renderer/configuration slices need
their own scoped EDD/TDD, signatures, independent review, portable evidence and
required-WAF rejection until the complete path is admitted. Current portable
`make verify` checks documentation/foundation integrity only. It does **not**
execute or pass the M2-C01 cases described here, TLS/framing/CRS behavior, no-bypass,
resources or native qualification. Keep only fixed bounded error classes and
counts in logs/receipts; never raw bodies, query/header values, keys or private
inventories. M1 failures and the validation pause remain.

## Source basis and acceptance limits

WAF base `a575e5aa36dcabb9cbcd9d38b8de553cd432b4a9` retains all historical studies.
Read-only Vectivium `acd5c337230eab11cc65e15b812c9f334e72b49b`:
[`plan.go`](https://github.com/gonz0w/vectivium/blob/acd5c337230eab11cc65e15b812c9f334e72b49b/internal/plan/plan.go)
rejects required inspection and renders general h2/http1.1 with HTTP/1.1 backends;
its [ADR 0003](https://github.com/gonz0w/vectivium/blob/acd5c337230eab11cc65e15b812c9f334e72b49b/docs/adr/0003-required-h1-h2-optional-h3.md)
retains broader protocol obligations. Neither source implements this contract.
The [HAProxy 3.2 manual](https://docs.haproxy.org/3.2/configuration.html)
documents SNI/verified peers and body-buffer limitations; it currently identifies
3.2.26, while Vectivium's proposed OpenBSD package is 3.2.25. Bundled exact-package
documentation/source and actual behavior remain prerequisites, not inferred from
the web manual. No runnable configuration is supplied or current option claimed.
The retained 3.2.25 source archive SHA-256 is
`d59a68d0daef7b5c596b019b742089788ff1748513ef96e71fe7b3943577866e`, matching
the [published release checksum](https://www.haproxy.org/download/3.2/src/haproxy-3.2.25.tar.gz.sha256).
`src/h1.c` SHA-256 is `30bda655a9944b25e4e754f8d596686d51f2cc3689782133eca06dcace084fef`;
`src/http.c` is `26cab35d003db929d9bdd99e1b7d1331c0e527fd630e6203c74a65d68a7bc8f5`.
This is a static source observation, not package/runtime rejection evidence.
