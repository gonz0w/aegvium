# M2 secure connector and TLS boundary recommendation

Status: **Historical recommendation; selected M2 boundary now recorded by
[ADR 0010](../../architecture/adr-0010-frontend-key-mandatory-inspector.md) and
[M2-H1/1](FRONTEND-INSPECTOR-CONTRACT.md). Runtime integration remains unimplemented
and unqualified.** The source/evidence comparison below retains its original scope.
Date: 2026-10-19. Owner: Cam (`@gonz0w`). Baseline:
`ea84325a513a9584a1fda880c53aebff8e60fa1b`, merged proposal [#118](https://github.com/gonz0w/aegvium/pull/118).
[PRD](PRD.md), [EDD](EDD.md), [Test Design](TDD.md),
[previous comparison](TLS-OWNERSHIP.md). Refs #18/#19; closes neither.

The maintainer asked engineering to follow secure best practices rather than
choosing a key location. This authorizes a recommendation and source review,
not live key handling, deployment or an unresolved architecture implementation.
The recommendation and its tradeoffs were reported before any such implementation.

## Recommended division of authority

Keep the public service TLS private key exclusively in the frontend proxy.
For suite integration, the preferred eventual frontend is Vectivium's selected
HAProxy engine, without a redundant relayd layer. Run Aegvium inspection as a
distinct unprivileged service identity. Give it no public edge key, certificate
issuance account, routing administration, proxy Runtime API or general management
authority. Plaintext necessarily reaches the inspector: key separation reduces
the compromise consequence; it does not make the inspection process untrusted
with request data or eliminate the need for isolation.

Retain Aegvium's independent appliance outcome. A separate WAF VM behind EdgeWall
remains the current project boundary; same-host integration is a future alternative,
not permission to co-locate services. Between hosts require mutually authenticated
TLS, explicit peer service identities, names and dedicated internal certificates
distinct from the public service key. A private CA membership check alone is too
broad. If a later reviewed same-host profile uses Unix sockets, protect socket and
parent-directory replacement authority and verify the peer using the target OS's
actual supported credentials facility. Mode bits, loopback and PROXY prefixes
alone do not authenticate a peer. No new certificate or principal is provisioned.

Require the application-side boundary to admit only the inspected path, never a
frontend health/fallback route directly to the application. Prefer a series
inspection-and-forwarding path that retains complete admitted request ownership;
it fits the existing companion's role better than an invented HAProxy callout.
An out-of-band verdict design is an alternative only after its complete-body,
authenticated correlation, replay and forwarding ownership contract is reviewed.
This paper defines acceptance constraints, not a new protocol, schema or option.

## Comparison against the actual candidates

| Candidate | Evidence and advantage | Consequence / recommendation |
| --- | --- | --- |
| Stock relayd terminates TLS, TCP forwards plaintext to Go/Coraza | Base TLS and dispatch; keeps edge key from the engine. Existing local sender/backend containment studies are source-bound. | The pinned PROXY v1 and v2 writer do not convey authenticated original SNI. A client Host header cannot repair that. Retain as a control; no product admission until authority binding and containment are independently proved. |
| Stock relayd TCP passthrough, Go/Coraza owns TLS | The retained 29-case TLS study binds actual SNI to HTTP authority and covers the tested cross-host gap without patching relayd. | The parser/inspection process holds the public key. Do not prefer this as the product default when key separation is feasible. Keep the experiment immutable; it remains valuable evidence, not an adopted custody policy. |
| Pinned coraza-caddy v2.6.2 | Existing connector owns transaction/error/replay/response/reload integration. The configured native comparison has 30 cases/five configuration observations and a tested strict SNI/Host control. | Co-locates edge TLS and inspection authority, broadens the dependency graph and retains documented advisory/profile/resource gaps. Keep as the measured existing alternative; neither its marketing claim nor source size establishes security or resource superiority. |
| Vectivium frontend plus separate mandatory Aegvium inspector | Best matches separation of public TLS custody and inspection privileges, while keeping the frontend's engine choice coherent. | Recommended destination, **currently unavailable**: Vectivium's preview rejects required WAF, and no admitted complete-request/metadata interface or integrated native evidence exists. Do not enable, render around the rejection or invent a connector. |

The evidence basis remains [ADR 0001](../../architecture/adr-0001-ingress-inspection.md),
[ADR 0005](../../architecture/adr-0005-tls-passthrough-research.md),
[connector assessment](../M1/CONNECTOR-ASSESSMENT.md),
[configured Caddy](../M1/CONFIGURED-CADDY.md) and
[request-wire failure](../M1/REQUEST-WIRE.md). This recommendation refines the
next design direction; it does not amend those ADRs' adoption status or erase
the failed legacy reload responses, missing 52-row native wire matrix, CRS gate
or paused security/traffic/advisory validation.

## Mandatory request, trust and failure constraints

The frontend must validate the external SNI/authority relationship and pass an
authenticated binding to the exact accepted request. Bind method, external
authority, target, body and policy/generation/request identity under the reviewed
transport's semantics. Do not trust browser Forwarded, X-Forwarded-* or PROXY
metadata without proving the actual sender boundary. Connection identity alone
does not prove that a verdict belongs to this request and generation.

Complete bounded inspection precedes any application effect. Reject input that
cannot be inspected in its entirety within the admitted byte/time/resource caps;
no header-only or prefix-only verdict, inspection bypass on overload, automatic
fallback or fail-open mode. A missing, partial, stale, malformed or foreign verdict,
crash, timeout or lost authenticated peer denies new forwarding and withdraws
readiness. A late verdict cannot revive retired work. Separate client response,
application effect and completion: an already forwarded effect cannot be recalled.

HAProxy's `option http-buffer-request` can resume when its buffer fills. It is
therefore insufficient as a complete-body or correlated-verdict proof. The fetched
3.2 web manual identifies **3.2.26**; Vectivium's static package proposal names
**OpenBSD 7.9 HAProxy 3.2.25**, while its historical fixture used **3.2.15**.
Inspect the exact selected official port and its bundled documentation before
assuming an option or behavior. This task installs and runs none of them.

Start with an explicitly bounded HTTP/1.1 WAF profile. Vectivium's required h2
baseline does not qualify h2-to-h1 inspection translation; that path needs separate
framing/parser/authority tests before WAF-enabled h2 can be advertised. Ambiguous
framing must reject or satisfy an explicitly accepted normalized-input contract
with independent original-wire/inspection/backend witnesses; a handler's parsed
fields are insufficient. No custom parser or relayd patch is selected here.
Explicitly reject unsupported trailers, signed streaming, upgrades, gRPC,
CONNECT and other unadmitted representations. Never silently pass them through.

For AWS SigV4, preserve the signature's canonical semantics end to end: external
Host including the admitted port, encoded path, repeated slashes, query names,
values and multiplicity, signed headers and payload. Keep the external Host
separate from internal TLS SNI/name verification. Do not re-sign with an operator
credential or normalize S3 paths. Framing translation is admissible only if the
exact signed meaning and application bytes remain intact. Unsupported streaming
signatures must fail explicitly, not become an unsigned or partially checked body.

## Required future acceptance, not new execution

Extend M2-A02/A03/A05/A06/A08 only after the architecture/interface is accepted:

- Healthy complete request has the expected inspected application effect; denied
  or incomplete input has zero effect and a bounded complete response/close.
- Wrong peer, CA, name, internal certificate purpose or authority binding denies;
  correct identity restores healthy service. Public and internal keys are distinct.
- Missing/partial/stale/foreign verdict, WAF crash, stalled body, timeout and
  generation retirement cannot forward to an application or revive late work.
- Frontend/direct local/remote backend bypass attempts deny with independent
  positive controls; health/readiness/admin credentials grant no data-plane bypass.
- Original-wire and independent backend witnesses cover framing disagreement,
  h2 translation when admitted, encoded targets, repeated slashes, duplicate query
  names, signed Host/headers and payload fidelity. Unsupported representations
  reject without relaxation of expected outcomes.
- Measure complete buffers, CPU/RSS, descriptors, queue/storage ceilings and total
  lifecycle deadlines; correlate all receipts to source/build/package/profile.
  Test custody/rotation loss and known-good recovery without exposing key material.

Key separation costs an authenticated internal boundary and more operational
identities/certificates; plaintext exposure remains. Additional HTTP translation
can increase parser disagreement risk. An existing connector reduces custom
lifecycle code but does not remove those acceptance obligations. If the separate
path cannot satisfy them, report that concrete blocker and compare the retained
connector; do not quietly give the inspector the public key or weaken inspection.

## Primary sources and source limits

Retrieved 2026-10-19; references inform the recommendation, not native acceptance:

- [OpenBSD 7.9 relayd.conf](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5): TLS/keypair and PROXY boundaries; the pinned writer study remains the specific TLV evidence.
- [HAProxy 3.2 manual](https://docs.haproxy.org/3.2/configuration.html#4.2-option%20http-buffer-request): buffering limitation; exact package still needs its own contract.
- [AWS SigV4 canonical request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html) and [S3 signed payload rules](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html): signed request preservation, including S3's path exception.
- [Pinned coraza-caddy README](https://github.com/corazawaf/coraza-caddy/blob/v2.6.2/README.md): upstream connector identity; local measured evidence takes precedence over unqualified coverage claims.
- [Vectivium source checkpoint](https://github.com/gonz0w/vectivium/tree/acd5c337230eab11cc65e15b812c9f334e72b49b): README required-WAF rejection, ADR 0001 engine/package direction and source ledger. Read only; no Vectivium source/settings changed.

There is no persistent/runtime migration. Rollback withdraws/revises this
recommendation while retaining source-bound experiments and failures. No key,
credential, service, live traffic, package, VM, native run or deployment occurred.
