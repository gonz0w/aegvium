# M2 engineering design: proposed enforcement contracts

Status: **Proposed; architecture and implementation not adopted.**
Owner: Cam (`@gonz0w`). Date: 2026-10-19.
[PRD](PRD.md), [Test Design](TDD.md), [TLS comparison](TLS-OWNERSHIP.md).
Refs [#18](https://github.com/gonz0w/aegvium/issues/18) and
[#19](https://github.com/gonz0w/aegvium/issues/19).

## Component and trust boundaries

EdgeWall retains perimeter authority. The separate WAF VM admits traffic only to
the selected ingress/inspection composition and only inspected requests to an
allowlisted backend. No health table or recovery path may point directly at an
application. Management is a separate authority; losing it cannot convert the
data plane to DetectionOnly or forwarding without inspection.

Two relayd compositions remain under comparison: TLS termination at relayd with
a companion, or stock TCP passthrough with TLS termination inside the companion.
The existing coraza-caddy connector remains a full alternative. The
[paper comparison](TLS-OWNERSHIP.md) states their actual evidence and gaps.
No component selection, UID, PF rule, pledge/unveil policy or key move occurs here.

The privileged boundary must enforce startup ordering and sender/backend access;
the nonroot inspection process must not be able to request arbitrary privileged
actions. PROXY metadata and loopback are not authentication. Product credentials,
certificate ownership and remote application containment remain D1/D2 decisions.

## Typed routes and state authority

Propose a validated internal route record containing a unique route identity,
frontend DNS authority/port policy, explicit backend address/scheme, backend TLS
server name and trust reference when applicable, and an inspection-policy pin.
This is a semantic contract, **not** a public JSON schema, CLI, path convention or
new API. Do not promote the research `.test` JSON or fixed ports into the product.

Reject duplicates, unknown fields in any eventual external representation,
ambiguous authority normalization, credentials in destinations, unreviewed
destination resolution, and missing trust/inspection pins. Never select a backend
from client forwarding headers or an arbitrary request URL. Validate all routes,
certificate coverage and dependencies before any serving generation becomes ready.

The selected serving generation owns an immutable route/policy/trust snapshot.
Each admitted request uses one generation through inspection and forwarding;
configuration changes must not splice old authority checks onto a new destination.
The coordinator owns publication; request leases own in-flight lifetime; retirement
waits for the bounded drain and owns cleanup. Existing research implementations
provide design input, not a preselected product package or lifecycle API.

## Request admission and budgets

Proposed order: acquire bounded admission; verify trusted sender/TLS authority and
route; admit only the PRD profile; read the bounded complete body; validate final
input including trailers; inspect; forward to the fixed backend; classify response;
release all request ownership. Parser-level checks may necessarily precede handler
admission and must also have finite connection/header/deadline limits.

The inspection and forwarded representations must agree for every admitted field.
Strip spoofable forwarding metadata before setting any selected trusted identity.
Inspection-denied/error paths release transactions/body buffers and never invoke
the backend. A forwarding attempt does not become safe to retry because response
completion failed. No automatic upstream retry or redirect is proposed.

| Budget family | Existing research input | Required product decision and proof |
|---|---|---|
| Routes/configuration | 1–8 routes; 8192-byte lab config | Exact route/string/serialized bounds and parse rejection before allocation/publication |
| Request/response | 4096-byte lab guards; bounded headers/deadlines | Separate encoded/decoded body, headers, response and parser-prefix limits; cap+1, overflow and stalled-I/O outcomes |
| Concurrency | Four admitted requests, eight data connections, two prefix workers | Shared ceiling across all generations, no hidden waiting queue; health budget independent; saturation/recovery evidence |
| Lifecycle/time | Existing bounded load, drain and process teardown | Numerical handshake/read/write/forward/drain/start/reload/retire deadlines and total operation budget; clock/failure semantics |
| Hard resources | Small research workloads only | Approved CPU/RSS/file/socket/tmp/audit-storage caps, workload/hardware and latency/throughput criteria; independently measured peak/steady/failure behavior |

These are **unaccepted comparison inputs**, not accepted product capacity. The
recommended initial proposal below uses them without claiming measurements. D4
must approve the product values and close the remaining gaps before admission.
Do not silently widen a cap to obtain a passing result. Health success is not
proof of ingress table convergence, backend readiness or successful application
effects. No performance or resource result is supplied by this document.

## Failure, recovery and rollback

| Transition/fault | Proposed invariant |
|---|---|
| Startup validation or containment/key failure | No ready data path or uninspected fallback; report bounded redacted failure |
| Unknown authority, unsupported input, inspection error or saturation | Selected finite rejection/close before forwarding; zero backend effect; independent recovery control |
| Backend trust/connect failure | No verification bypass or alternate destination; classify any already attempted inspected effect separately |
| Response timeout/size failure | Bounded termination with an explicit response failure; never infer zero effect or safe retry |
| Replacement preparation fails | Current generation remains intact; reject the whole replacement without partial publication |
| Successful replacement | Prepare fully, drain old leases within the agreed bound, publish a whole new generation and retire the old owner; acknowledge the actual publication outcome |
| Drain/retirement or cleanup fails | Do not free an engine still owned by handlers; withdraw readiness and stop under reviewed ownership rules; do not label an already published generation as a rejected update |
| Crash or management absence | Inspection/bypass controls remain fail closed; recovery loads only a validated known-good generation, with fresh identities/state where required |
| Rollback | Validate and restore the entire known-good configuration/policy/trust set through the same publication contract; no automatic replay of requests or reversal of application effects |

Exact status codes, acknowledgement and drain-failure behavior must be finalized
with D3/D4 and tested at the selected composition. In-flight work may have effects;
readiness withdrawal does not instantly revoke already accepted connections.
The existing [unsafe checker characterization](../M1/READINESS-WIRING.md) cannot
be interpreted as a correct product readiness policy.

## Recommended engineering profile for review

These are concrete **proposals, unadopted and unmeasured as product limits**.
They constrain the first design rather than asking the maintainer to choose
implementation constants. Retained source is the reason to start here, not
evidence that the proposed complete profile passes.

- **Principals and lifetime:** propose separate ingress, inspection and
  management principals; no shared application UID. A privileged operator owns
  configuration/trust directories and containment changes; serving principals
  receive read-only inputs and cannot replace them. Only the selected TLS owner
  may read its private key. Backend listeners admit only the selected inspection
  principal/path. No new privileged helper API is proposed. Numeric UIDs, exact
  permissions and containment realization need D2 review, not laboratory UID 32767.
  Requests and generation leases live only in the current process; restart
  validates fresh state and never resumes previous in-flight requests.
- **Replacement:** propose route/trust replacement only, with complete staged
  validation, shared admission across generations, drain before whole-map
  publication, and explicit retirement. Retain the old map on preparation failure;
  fail closed on uncertain publication/ownership. Keep rules pinned and embedded
  for this slice. Propose startup-only frontend certificate/key loading and a
  deliberate stop/start for certificate replacement, as in the retained TLS
  profile; no seamless renewal/rotation promise. A stopped replacement that fails
  validation stays unready until the operator restores validated known good.
- **Size and concurrency:** propose at most eight routes, 8192 bytes of serialized
  configuration, 4096 bytes each of admitted request body and buffered response,
  four in-flight application requests, eight data connections and two prefix
  workers. Keep no application waiting queue and no upstream retry. Health has
  separate ownership and must not consume an application admission slot; its
  numerical capacity remains a budget gap to close before approval.
- **Request clocks:** propose the retained one-second prefix, header, upstream
  dial/TLS/response-header bounds, two-second request-read and forwarding-context
  bounds, and four-second response-write bound, with close-only connections.
  Use the earliest applicable deadline; stage timeouts must not restart an
  expired parent budget. The source's configured 4096-byte `MaxHeaderBytes` is
  only a parser setting, not proof of a strict wire-byte ceiling; define and
  measure the actual admitted header/request-line bound before approval.
- **Shutdown:** propose one shared three-second drain deadline and one additional
  second for joining owned server tasks, then process failure if ownership is
  uncertain. This deliberately tightens the retained per-server shutdown/join
  structure into a four-second total shutdown target; it is not an observed
  implementation result. Never free engines still leased by handlers. Whole
  startup, preparation/reload and retirement budgets need measured preparation
  costs and an explicit containment owner before a safe total can be approved.

The input anchors are [lab proxy limits](../../../research/coraza/lab_proxy.go),
[configuration admission](../../../research/coraza/lab_config.go),
[shutdown ownership](../../../research/coraza/lab_shutdown.go),
[body ownership](../../../research/coraza/lab_body_transport.go) and the
[TLS profile](../M1/TLS-PASSTHROUGH.md), at this packet's baseline revision.
Hard process CPU/RSS, descriptors, audit/tmp storage, health capacity and
performance goals are genuinely unmeasured gaps. Engineering must propose those
numbers and their measurement basis; no product claim is possible by copying the
research VM's resource envelope.

### Preferred wire policy and its alternative

Prefer a single HTTP parser and an explicit **normalized-input contract** over
adding a second custom parser. Propose allowing the selected Go parser's equal
duplicate Content-Length and CL+TE normalization only if independent exact-wire
tests demonstrate one bounded complete interpretation, inspection/backend byte
agreement, no trailers and no second request effect. Conflicting lengths,
truncation and unsupported final fields remain rejection cases. This retains the
existing research characterization without mislabelling it strict raw rejection.

The tradeoff is a narrower interoperability/security claim: this option does not
promise that every ambiguous-looking wire encoding is rejected. If the selected
threat/profile requirements require such rejection, D3 must instead identify a
qualified raw-wire admission boundary or a qualifying existing-connector policy;
do not invent a new parser, assume a handler sees discarded raw fields, or patch
relayd implicitly. Neither option is currently qualified. Until D3 selects and
proves its contract, ambiguous framing is outside advertised support and cannot
be enabled in a product profile by this proposal.

No product state migration exists yet. Paper rollback revises/withdraws this
proposal while preserving historical evidence. Future runtime rollback needs
the reviewed candidate's restoration/absence checks; it never restores a known
inspection bypass simply because that was an earlier laboratory profile.

## Privilege, secrets and evidence

Select distinct production principals and enumerate who can open each socket,
read/write each config/key/trust file, replace policy and change containment.
Keys are not evidence or repository content. Input admission must cover parent
directory and replacement authority as well as opened-file type/length; the
ordinary file helper's checks alone do not authenticate a concurrent writer.
M2 selects no credential-creation or certificate-automation procedure.

Unknown or lost sender/backend containment or key validity must deny new data
admission and withdraw readiness; retaining a listener is not permission to
forward. D2 must define the evidence and detection bound for those conditions.
Existing in-flight effects remain classified separately and drain only under the
reviewed ownership policy; neither readiness withdrawal nor a failed response
proves that those effects were revoked.

Retain bounded operation/generation identifiers, fixed error classes, counts,
candidate hashes and separate client/backend-effect observations. Omit raw
credentials, private keys, bodies, query values and private inventories.
Audit exhaustion must have a bounded specified outcome without disabling
inspection; richer operational retention/export remains M3.

## Unresolved decisions before implementation approval

| ID | Decision | Required closure |
|---|---|---|
| D1 | Maintainer product choice: scope and TLS key custody | Confirm the narrow first outcome and state any key-location constraint. Engineering supplies the comparison; candidate-specific adoption still needs the existing evidence. |
| D2 | Engineering proposal: authority/privilege | Start with the separated principals, read-only inputs, startup-only certificate replacement and fresh lifetimes above; specify exact identities/permissions/containment and prove loss detection. No implicit lab-policy adoption. |
| D3 | Engineering proposal: compatibility/admission | Prefer the single-parser normalized-input contract above; document its limits and compare stricter admission if required. Propose exact authority/port/case, TLS and error/replacement behavior for review; no raw rejection claim from normalization. |
| D4 | Engineering proposal: budgets/acceptance | Start with the finite profile above; measure and propose the remaining hard resources and total startup/reload/retirement bounds. Qualify the complete profile before claiming accepted limits. |

The recommended next work is resolving this bounded paper packet, not another
isolated experiment or a production selection based on source size. M1 blockers
and the paused validation remain authoritative. No new dependency, service,
framework, shared package or deployment contract is introduced.
