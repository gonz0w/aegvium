# ADR 0001: Proposed ingress and inspection boundary

Status: **Proposed for review; adoption withheld.** Date: 2026-10-14. Owns the M1 recommendation under #15 and M1-05, not a runnable appliance contract. [Scoped assessment](../milestones/M1/CONNECTOR-ASSESSMENT.md); [existing connector source comparison](../research/connector-comparison.md).

## Recommendation

Prioritize stock relayd TCP transport with TLS termination and a separate unprivileged Coraza inspection/forwarding companion as the next candidate for combined qualification. Keep coraza-caddy as the existing-connector comparison/control. Supersede the earlier HTTP-first prototype preference; do not select relayd HTTP mode as the default WAF ingress while its measured parser/pipeline/rejection gaps remain unresolved. This recommendation does not approve a supported transport profile, configuration schema, service, distribution or product implementation.

The proposed path is EdgeWall → dedicated WAF VM relayd TLS/TCP ingress → local inspection companion → explicitly allowlisted backend. relayd's intended independent role is base-system TLS ingress and health-checked dispatch to inspection nodes, with no table/fallback directly to applications. The Go process owns HTTP parsing, Coraza/CRS transactions and allowlisted forwarding. Removing relayd remains an alternative if combined native tests do not justify its cost or trust boundary. This direction supports the maintainer's future relayd proxy project without creating that project or promising Traefik/Caddy parity.

## Why this direction

The direct/HTTP/TCP body comparison preserved ordinary benign bytes and attack denial. HTTP mode changed four rejection outcomes and retained a client-deadline timeout on conflicting lengths. TCP mode reduced the complete-input differences in that corpus, avoiding a second HTTP parser. The lifecycle study also found absent responses and variable backend effects after client write shutdown; TCP is not generally half-close qualified. Historical HTTP pipeline failures remain failed. The proposed direction narrows the next comparison; it does not prove parser safety or remove those findings.

The pinned existing connector supplies Caddy integration for explicit errors, request replay, transaction cleanup, reload sharing and response interception. A custom companion must own equivalent lifecycle/error behavior or document and enforce a narrower supported profile. Caddy's declared graph is broader, but source counts do not prove a runtime resource disadvantage. A [bounded native connector API comparison](../../research/connector/README.md) now exercises request/error/response and pool/file-update behavior. It uses a standard-library harness around the real Caddy module, not a complete Caddy server. The [native connector fixture build](../../research/native/connector-native-build-observations.json) now passes the same API matrix. A subsequent [configured Caddy TLS/server comparison](../../research/native/configured-caddy-observations.json) now measures actual routing, verified upstreams and configuration replacement. Strict SNI/Host rejects the tested cross-authority request that the permissive relayd companion accepts; Host-port/media policy differences remain explicit. Equivalent full-topology/trust/resource comparison remains open; the [compatible dependency refresh](../../research/native/dependency-remediation-observations.json) removes the seven prior reachable advisory IDs while retaining CEL package-only and OpenPGP module-only findings as adoption blockers.

A patched relayd callout or in-process embedding remains a distinct toolchain/protocol/upstream-maintenance project under the existing feasibility study. No stable inspection callout API or reusable connector repository is selected. Keep those alternatives deferred while stock-process composition is unqualified.

## Ownership and privilege contract to qualify

| Boundary | Candidate responsibility | Current evidence / gap |
|---|---|---|
| EdgeWall | Perimeter authority and delivery to the separate WAF VM | No live network changes; appliance-local containment must not replace EdgeWall. |
| relayd | TLS ingress, inspection-node dispatch, fail-closed readiness; no direct application fallback | Separate TLS, TCP and readiness fixtures exist; their full composition is unqualified. Do not assume correct checker status handling from shell exit conventions. |
| Companion | Dedicated nonroot identity; bounded HTTP parsing/body/error policy, transactions, fixed routes and validated backend TLS | Research runs use UID 32767 as a lab account. That is not a selected service UID, pledge/unveil policy, production filesystem boundary or resource qualification. |
| Data versus health | Mandatory bounded ingress prefix and independent readiness contract | PROXY/address metadata and loopback are not sender authentication. Local sender containment and trusted TLS/Host/SNI responsibilities must be demonstrated. |
| Backend and audit | Only admitted requests may forward; exact backend effects and response availability are distinct observations | Client errors/CloseWrite do not prove cancellation or safe retry. Future logs must not infer allow/deny solely from client status. |
| Runtime lifecycle | Load/validate rules before ready; bounded in-flight work, drain, reload, cleanup and no stale-ready generation | Generation/health controls are separately scoped fixtures; no combined product lifecycle exists. |

No product configuration is generated by this ADR. Base rc.d/syslog/acme-client and sibling relayd/httpd management preferences remain design inputs; no service is installed/enabled. BootWeave owns the generic installer; Aegvium owns a future reviewed payload/policy. No extension schema is invented.

## Adoption gates and rejection criteria

1. **Comparative connector outcome (#15):** build the companion candidate and pinned existing connector from reviewed dependency/NOTICE graphs on the same disposable OpenBSD profile. Match request/error/body/response, TLS/authority/identity, reload/failure and resource cases. Include unsupported capabilities and failures; source review alone cannot satisfy this gate.
2. **Supported protocol and containment (#16 and M2 trust work):** define, enforce and qualify a specific protocol/upgrade/streaming/reuse/half-close policy; demonstrate same-VM unauthorized senders cannot inject trusted identity or reach an uninspected backend. Resolve or explicitly reject unsupported paths. Never assume absence of response proves no backend effects.
3. **Reproducible native ownership (#12/#14):** retain exact build/runtime/input/license lineage, original image/installed-daemon attribution, real configured privileges and verified rollback/teardown. Existing hashes and component builds do not complete image lineage or a connector distribution review.
4. **Limits and acceptance (#17/#18):** measure in-flight/body/storage/socket/file/memory limits and failure isolation under the combined path, then review the supported profile and scoped M2 design. No latency/throughput/OWASP coverage claim follows from current lab guards or attack strings.

Reject this direction if relayd cannot preserve the selected supported behavior, enforce the intended trust/no-bypass boundary, provide reliable readiness, or justify its measured operational cost against the single-process existing connector. Prefer the measured alternative rather than adding a workaround that conceals failed cases. No dates or feature parity promised.

## Review result and rollback

The decision remains proposed until the maintainer explicitly accepts a candidate-specific architecture and implementation scope. Merging this source/evidence assessment records the recommendation; it does not satisfy the gates above or turn research fixtures into adopted runtime. Keep #15, #16 and M1 open. Revisions can replace the recommendation while preserving all historical evidence; no deployed component needs rollback because this ADR changes none.

## TLS ownership follow-up

The [bounded passthrough ADR](adr-0005-tls-passthrough-research.md) adds a second research candidate: relayd performs stock health-checked TCP forwarding; the companion parses PROXY then terminates TLS and binds HTTP authority to actual SNI. [Native receipts](../../research/native/tls-passthrough-observations.json) pass 29 cases with unchanged legacy controls and offline fixture/checker/CLI compilation. This addresses the tested cross-host gap without a relayd patch, at the cost of companion key ownership and future certificate operations. A local forged-prefix request still reaches inspected service. The TLS-at-relayd control and strict Caddy results remain separate; no topology, product privilege policy or separate connector repository is adopted.

## Local sender follow-up

The [bounded PF ADR](adr-0006-owned-pf-sender-containment.md) and [native receipts](../../research/native/sender-containment-observations.json) add conditional local socket-UID containment to the TCP passthrough research path. Four phases retain open forged-prefix effects, demonstrate protected denial with positive relayd ingress/counters, reject an invalid replacement without changing known good, and restore selected static PF views. The companion and dependency inputs are unchanged; no product firewall, service identity, startup ordering, trusted client-IP propagation or architecture adoption is selected.

## Explicit client identity follow-up

[ADR 0007](adr-0007-proxy-client-identity-research.md) and [native evidence](../../research/native/client-identity-observations.json) add default-off PROXY source selection for Coraza behind the externally maintained sender boundary. Test-only direct component rules prove address/port decisions; a separate normal-CRS actual CLI/PF matrix verifies the option and containment controls. The process does not establish that boundary. A diagnosed inspected-body lifetime race is repaired by bounded detachment before backend transport; its original host failure remains retained. Production identity/startup/privilege/certificate/audit policy, backend isolation, full compatibility/resources and architecture adoption remain proposed.

## Local backend ownership follow-up

[ADR 0008](adr-0008-local-backend-isolation-research.md) and [native receipts](../../research/native/backend-isolation-observations.json) add separate PF policies restricting the owned backend ports to the lab companion/fixture UID. A different nonroot principal's direct attack requests reach HTTP/verified HTTPS backends in open/rollback controls and reject before TLS/HTTP with zero effects when protected. The actual identity-enabled CLI retains its inspected-traffic outcomes. This is conditional local socket ownership, not production service identity, remote application isolation, allowed-UID/root compromise protection or architecture adoption.
