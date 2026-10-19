# M2-A01: mandatory inspector adapter design

Status: **Proposed for independent review; no runtime enablement.**
Date: 2026-10-19. Source basis: `25dfe3ef299f560bf29d2402ff7800271af09d1b`.
Refs #19–24, [M2-H1/1](FRONTEND-INSPECTOR-CONTRACT.md),
[M2-C01](M2-C01.md), [Test Design](ADAPTER-TDD.md).
ADR0010's frontend public-key custody and separate series inspector remain selected.

## Recommendation and bounded implementation order

Recommend a standard-library HTTP/1.1 mTLS receiver that owns one immutable paired
snapshot and one request from handshake through transaction cleanup. Use the
existing isolated Coraza dependency graph only after a separate source-bound
engine adoption review; M2-A01 does not import the research module into the root
module. No public endpoint key belongs to the inspector. No verdict endpoint,
transferable allow object, direct frontend backend route or management fallback.

Deliver **A01a first**: the real mTLS peer constructor, paired-descriptor comparison
and body/transaction/forwarder lifetime coordinator, exercised with owned portable
fixtures and a recording sink. It must be structurally incapable of an application
dial: no backend transport or allow-producing engine adapter is connected. This
can make progress while raw-wire qualification is blocked. A01b later connects
the reviewed engine and fixed backend only after the framing, pairing, containment,
resource and native gates below pass. A passing A01a never enables required WAF.

This design selects mechanisms to review; it does not describe current Vectivium
features or authorize affected security/traffic/advisory/native validation. The
existing validation pause remains. No certificate/key generation or live credential
use is part of this documentation change.

## Actual TLS authentication and role

Recommend TLS 1.3 with ALPN restricted to `http/1.1` on both internal links. Use
`RequireAndVerifyClientCert` at receivers and standard x509 chain/time/EKU/server
name validation at clients. Use explicit operator-owned trust pools and fixed
numeric dial addresses, with a distinct configured TLS DNS name; reject ambient
roots/proxies, discovery, redirects, automatic retries and verification bypass.
Dedicated internal client/server certificates must have the intended role usage.
The public endpoint certificate and private key are not internal credentials.

The role identity is one exact canonical configured DNS SAN, matched literally
after successful chain/usage validation. Do not use CN fallback, wildcards,
substring/suffix matches, reverse DNS, claimed headers, source IP or CA membership
as role authority. Reject a certificate with conflicting configured role SANs.
The frontend-to-inspector client identity and inspector-to-application client
identity have disjoint allowlists/trust configuration. Backend server DNS identity
is fixed by the route. Application authentication must allow only inspector data
identity; independent network containment also denies frontend/management access.

Only the receiver-owned completed `tls.Conn` handshake can construct the private
peer descriptor. Keep that constructor inaccessible to general callers; a supplied
`tls.ConnectionState`, boolean or fabricated certificate struct alone is not a
production authentication capability. A01a may place the private adapter next to
`requestctx.Peer` rather than expose a public "verified" constructor. The receiver
binds the authenticated role to the same connection/request, never a global
correlation-ID lookup. Reject resumed state unless the same validated identity
and current snapshot/trust binding are re-established; simplest first profile
disables session resumption/tickets on these close-only links.

Trust is fixed for one process lifetime. Bound each handshake and data connection
by the original request clocks. Before a new application attempt, enforce the
current snapshot, cancellation and connection identity again. Revocation/expiry
loss detection for long-running processes needs an explicit bounded checker and
native proof before enablement; startup verification alone is not that proof.

## Paired snapshots and readiness without allow authority

Recommend one operator-prepared **pair descriptor** shared verbatim by frontend
and inspector. It contains contract ID, fresh 32-hex generation, sorted unique
route IDs, exact external names/ports, frontend role identities, fixed inspector
address/server identity, policy/CRS capability pin and the fixed admission profile.
The inspector snapshot additionally contains its fixed backend address/name/trust
and data-client identity. Public certificates/trust references may be shared;
private keys are role-local files and never descriptor/evidence content.

Recommend this exact proposed private encoding, capped at 8192 total bytes. All
integers are unsigned big-endian; lengths count bytes and zero length rejects.
All text is canonical ASCII under M2-H1/1's existing grammar. No optional field,
padding, unknown trailing bytes or duplicated entry is permitted:

```text
8 bytes "AGPAIR1\n", 32 ASCII generation bytes, 7 bytes "M2-H1/1"
u8 route_count (1..8), routes sorted by route ID, each:
  u8 ID_length (1..32), ID
  u16 public_DNS_length (1..253), public_DNS, u16 public_port (1..65535)
  64 ASCII lowercase-hex policy/CRS pin bytes
  u8 frontend_peer_count (1..8), sorted unique peers, each:
    u16 DNS_length (1..253), exact frontend role DNS SAN
  u8 inspector_address_length (1..45), canonical numeric IP, u16 inspector_port
  u16 inspector_DNS_length (1..253), exact inspector server DNS SAN
  32 raw SHA-256 bytes of inspector-server trust-anchor DER
  32 raw SHA-256 bytes of frontend-client trust-anchor DER
fixed u32 public_headers=4096, internal_headers=5120, target=2048,
          request_body=4096, response_body=4096
fixed u8 requests=4, data_sockets=8
```

The common digest is SHA-256 of these complete bytes. Independently produced
golden vectors must cover the complete grammar before a parser is connected.
The global 8192-byte cap may dominate individual maxima and rejects as a whole;
it does not widen M2-C01's separate retained-text budget. Per-role private backend
and key configuration remains separate, fully validated immutable input. No
general configuration language or public JSON API is selected. Generation alone
is not a content digest, freshness proof or handshake.

The operator startup owner validates both complete snapshots and records each
fresh generation as consumed before serving. Recommend append-only operator-owned
per-pair generation history, unavailable to serving principals. A changed/startup/
rollback attempt always gets a new token; a crash or uncertain history write
burns the token and stays unready. Never reclaim it because startup failed.
This needs a reviewed local startup/history writer and durable ordering; the
data-plane HTTP handler never writes history. A01a uses synthetic immutable
prepared facts and cannot assert that this external history exists.

Recommend a separate, fixed **pair-preflight** operation on the inspector's
authenticated control surface, limited to two accepted control connections with
no queue, one-second handshake/read stages and a two-second total deadline. These
are proposed source bounds requiring later measurement. It is side-effect
free for application traffic: no body inspection, allow verdict or backend dial.
The frontend presents the common descriptor digest/generation/capability pin;
the inspector authenticates its allowed frontend role and compares with its own
prepared snapshot, returning only the matching local tuple or a fixed mismatch.
Both sides distinguish locally prepared, pair-matched, and serving-ready states;
preflight can report prepared facts while data readiness is false, avoiding a
circular readiness dependency. Recommend the private HTTP/1.1 operation
`POST /_aegvium/m2-h1-1/pair`, one request per connection, with exact Content-Length
104 and no other body representation. Its body is eight bytes `AGCHECK1`, 32 ASCII
generation bytes, 32 raw common-digest bytes and 32 raw SHA-256 bytes of the literal
`M2-H1/1`. Success returns 200 and the same 104-byte tuple constructed from local
facts; invalid input returns 400, mismatch 409, unprepared/capacity 503, all
close-only. Authentication failure is a TLS failure. Use a separate configured
fixed control listener; no application route shares it. This proposed control
grammar is not a deployed endpoint or raw application-framing proof, and its exact
portable golden vectors remain required.

A replayed success response cannot authorize traffic: each data request still
needs a current mTLS role, current generation and exact route/SNI/Host/policy
checks. Preflight does not prove backend containment, a future handshake or an
application effect. Missing history, stale pairing, trust loss or failed engine/
containment readiness withdraws admission. A01a has no serving-ready state.
No automatic cross-host atomic publication is claimed. Stop/validate/start remains
the only configuration/trust/key replacement procedure.

## Request, transaction and forwarding ownership

The receiver acquires from one process-wide budget shared across generations:
at most four admitted requests and eight total accepted/outbound data sockets,
with no application waiting queue. It reserves an outbound slot before accepting
an attempt that needs it; saturation rejects without waiting for another request
to release capacity. Health/control capacity is separate and must be numerically
specified/measured before A01b enablement. Leases contain one generation identity
and cannot be transferred to another request or generation.

One request follows these states, with no bypass edges:

1. Authenticate the actual connection and admit only the separately proved wire
   profile. Reject unknown role/route/context/authority/generation.
2. Own the complete bounded body and metadata from that same request. Require the
   selected fixed length, exactly the admitted bytes, valid end/framing and no
   trailers/encoding/extra request effect. Matching a slice length is insufficient.
3. Create one engine transaction against the immutable policy pin. Inspect every
   admitted request field and complete body. Interruption or any engine error
   closes the transaction and releases the lease without an application attempt.
4. Under the same owner, immediately recheck cancellation, generation validity,
   containment/trust readiness and admission before the single backend attempt.
   Inspection completion is internal state, never a reusable allow token.
5. Forward only the inspected byte representation to the fixed authenticated
   backend. Preserve Host, encoded target, header values and payload. Exact
   hop-by-hop/framing transformations need independent byte oracles. A representation
   that cannot preserve signed fields is rejected; no re-signing or streaming.
6. Bound/finish the response and close transaction/body/connection/lease exactly
   once. A failed response after an attempt may have application effects. No retry.

Retirement atomically prevents new leases and prevents an unstarted forwarding
attempt from crossing the attempt barrier. A cancellation/retirement ordered
after a begun attempt cannot revoke its possible effect; record it separately.
Shutdown withdraws readiness, cancels/drains owned requests under one deadline,
joins them, then closes the engine. Never free an engine with live leases or
label uncertain cleanup successful. Startup-only replacement avoids overlapping
generation publication; it does not waive bounded shutdown or resource proof.

Use the selected request/body/header limits and earliest applicable parent
deadline; stage clocks cannot reset an expired budget. Existing EDD timing values
remain design targets. Complete startup/shutdown/health/CPU/RSS/FD/storage bounds
need candidate-specific admission before a listener/backend slice is enabled.

## Strict original framing is a separate blocking gate

Retain M2-H1/1's rejection of equal duplicate Content-Length and CL+TE. Exact
HAProxy 3.2.25 source normalizes those forms, so a Go handler's parsed counts
cannot establish rejection. A01a tests may demonstrate normalized loss but must
not label it raw admission. No custom parser or package patch is recommended.

Recommend keeping required-WAF disabled while evaluating an **existing qualified
raw admission boundary** against the exact package. If none can satisfy the
selected contract, the alternative is a separately named normalized-input profile
with independent original-wire/inspection/backend byte and no-second-effect
evidence. That alternative changes the advertised rejection contract and requires
explicit review; it is not adopted here. TE/chunking stays unsupported either way.
No framing run is authorized by this plan or by the portable source tests.

## Vectivium dependency and remaining delivery gates

The other product owner needs this proposed interface dependency, not a patch from
Aegvium: verified inspector server/client TLS roles; the bounded common pair
descriptor/preflight; fresh startup generations; original public SNI/client and
Host/target/body fidelity; spoofable-header rejection; one-request close; and a
proved framing profile. Keep Vectivium's required-WAF rejection until all gates
pass. Its general h2 support grants no M2-H1/1 translation permission.

Review A01a's exact grammar/API/budget choices and implement only the no-dial
receiver/coordinator fixture first. A01b additionally requires engine provenance
and adoption, raw-wire proof, operator-history/paired startup, real backend role
and network isolation, certificate-loss detection, complete resource/lifecycle
limits, independent effect oracles and fresh native qualification. M1 failures,
CRS/advisory gates and #19–24 acceptance remain open. No key/certificate operation,
native run, service enablement or deployment is authorized by this design.
