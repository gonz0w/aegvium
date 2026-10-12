# relayd–Coraza integration feasibility

Status: bounded source and native research, 2026-10-12. The maintainer requested a reusable relayd–Coraza connector if relayd provides a justified role, with a separate project possible after feasibility. No separate repository, published connector or relayd patch is selected.

## Existing project reality

Inspection of /Users/cam/DNS README/design found Unbound/NSD research and no relayd integration. Arxwall's capability map places relayd in optional health-checked service publishing; its 2026-10-10 service-observation tests explicitly use synthetic accounting-name executables and do not enable real relayd. Reuse of base facilities is a useful preference, not evidence that a connector already exists in either sibling.

## Candidate roles and costs

| Integration | relayd's concrete role | Coraza boundary | Feasibility questions |
| --- | --- | --- | --- |
| TLS/HTTP ingress → companion HTTP inspection proxy → application | Base TLS listener, ingress policy and health checks of inspection nodes | Separate unprivileged Go process owns inspection and allowlisted upstream forwarding | Two parsers, trusted identity, body/framing normalization, failed-engine readiness, explicit error responses |
| TCP relay with TLS termination → plaintext companion | Base TLS termination and health-checked TCP dispatch without HTTP ingress parsing | Go service owns HTTP inspection and allowlisted forwarding | Mandatory PROXY identity, readiness separation, local sender containment and TLS/authority metadata limits |
| TCP/TLS pass-through → TLS inspection proxy | Health-checked TCP dispatch to inspection nodes | Go service owns TLS and HTTP | Fewer HTTP parsers, but prove native dispatch adds value for this appliance rather than unnecessary processes |
| In-process Coraza library | relayd owns HTTP and calls engine directly | C/Go shared-library boundary | Go 1.27.2 platform support excludes OpenBSD c-shared; no documented stock relayd plugin hook; significant upstream/toolchain work |
| New external inspection callout in relayd | relayd pauses forwarding pending a bounded engine verdict | New interprocess inspection protocol | Requires relayd source changes, bounded body buffering/backpressure, request identity, timeout/error/privilege/lifecycle design and upstream maintenance |

The first candidate is preferred for a bounded prototype because it uses stock relayd and a Go executable that already cross-compiles. This is an inference from source/tooling evidence, not a connector adoption decision. The companion is a proxy integration rather than a plugin loaded into relayd. Do not call an out-of-band log consumer an inline WAF connector.

relayd must provide an independently useful ingress/dispatch boundary in the selected profile. A single-process Coraza proxy is the control arm: compare both under identical request/error/framing tests, configured privileges and bounded resource measurements. If relayd adds no needed capability or its parser interactions cannot be made safe, retain the measured finding rather than force the architecture.

## Required research postconditions

- relayd has no route or health-check fallback directly to application backends. Failures of the engine, rules or companion cannot cause uninspected forwarding.
- Health probes distinguish inspection readiness from an open TCP socket. The current engine reader-error implicit-200 observation must not create a false healthy/allowed signal; the candidate integration must give explicit error responses.
- Forwarded identity is derived only at the trusted ingress, with spoofed headers removed; the companion accepts traffic only from its authorized local ingress. Define TLS/SNI/Host and backend verification responsibilities once.
- Check framing across both parsers: duplicate Content-Length/Transfer-Encoding, chunked bodies/trailers, normalization, encoded paths, reused connections and malformed requests. Backend byte/receipt assertions must accompany client status codes.
- Request and admitted response phases, body limits/storage/cleanup, timeout/backpressure and unsupported upgrades/streaming are explicit. No generic HTTP/2/3 or websocket support claim.
- Compare stock relayd availability/privilege separation with the companion's actual native privileges and resource costs. A base daemon does not automatically confine the Go engine.

## Planned sibling proxy

The maintainer plans an OpenBSD relayd-based reverse-proxy project with a role similar to Traefik or Caddy. A reusable Coraza integration could serve both that project and Aegvium. This gives relayd reuse a concrete product motivation; it does not establish feature parity or select a connector protocol. Keep generic ingress/routing orchestration in the future proxy, inspection integration in a possible connector, and appliance policy/CRS tuning in Aegvium. Native failure, identity and framing evidence still governs adoption. No sibling repository or API is created by this note.

## Reusable project boundary

Develop the first bounded fixture in Aegvium research. If the tested integration has a coherent reusable API/configuration boundary and supports stock relayd, a separate connector project can own the minimal Go adapter, native rc.d examples, versioned supported profiles and conformance tests. Aegvium keeps product routes, policy/CRS tuning, management and BootWeave payloads. Name, repository visibility/license/notices and any publication are selected after feasibility; this request is not evidence that upstream accepts a relayd patch.

## Source evidence and gaps

The [OpenBSD 7.9 relayd manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) describes TLS relays, HTTP rules, tables and health checks; no Coraza/SecLang/plugin callout is documented. The [Coraza connector list](https://www.coraza.io/connectors/) has no relayd entry. These are documentation observations, not proof about every private fork.

Pinned discovery source: [OpenBSD relay_http.c](https://github.com/openbsd/src/blob/78e1d99e9924d1948e4cb7b4f374f5ab4b53bb29/usr.sbin/relayd/relay_http.c). Its HTTP framing/body forwarding paths require comparative native tests. This is current-tree discovery and must not be represented as the exact OpenBSD 7.9 installed source; establish release/patch lineage before native conclusions.

The reviewed [Go 1.27.2 platform support source](https://github.com/golang/go/blob/go1.27.2/src/internal/platform/supported.go) does not list OpenBSD under c-shared. A custom toolchain/libcoraza port is therefore a distinct research effort, not a supported drop-in option. No patched relayd, parser safety or performance qualification has been demonstrated. The first connected stock-relayd observation below is limited to its admitted fixture. Follow #15/#16 and the [native packet](../milestones/M1/NATIVE-ENGINE.md).

## Explicit-error feasibility slice

The [completion-adapter experiment](../milestones/M1/ERROR-ADAPTER.md) records generic 500 responses and zero synthetic backend receipts for immediate/partial body-read errors, while retaining unmodified upstream behavior and allow/deny/DetectionOnly controls. All 20 fixture cases passed in an owned OpenBSD guest using a host cross-built binary. This addresses one prerequisite for a future companion; it does not provide a proxy API, readiness, relayd listener or cross-parser evidence.

## Stock relayd syntax observation

The [syntax-only ingress fixture](../../research/relayd/README.md) was accepted by the installed stock relayd in the owned patched OpenBSD guest. Unknown protocol and bad syntax were rejected; process/listener/control-socket absence and teardown/source/base were verified. It names a sole inspection target with HTTP status readiness checking and no application target. Configuration acceptance alone cannot prove no-bypass behavior; the next connected experiment must exercise readiness loss, actual backend receipts and both parsers. No daemon, TLS or companion proxy was started in this slice.

## Connected companion observation

The [first traffic fixture](../../research/relayd/README.md) passed ten plain-HTTP cases in the owned OpenBSD guest: identical direct/relayd benign and URI/body-denial controls, inspection-listener loss with the backend alive, and recovery. Stock relayd's health-check logs observed down/up transitions; loss returned 500/502/502 with zero backend forwards, and recovery preserved POST bytes. Foreground daemon/listener cleanup and VM teardown/source/base passed. This establishes a small companion-proxy path with stock relayd without modifying it, while leaving TLS, trust, both-parser malformed framing, existing-connector comparison and adoption open.

## Framing compatibility finding

The [bounded framing comparison](../milestones/M1/RELAYD-FRAMING.md) failed its denied-then-benign pipeline expectation through stock relayd: 403 then unexpected EOF, versus direct 403/200. Nineteen other connected cases passed, including exact benign chunked body bytes and zero backend receipts for the tested chunked attack, conflicting lengths and mixed framing attack. The failed pipeline stopped before checking backend receipts; it is not evidence of bypass or supported pipelining. Cleanup and the separate engine/configtest gates passed. Preserve the failure and investigate connection reuse with receipts on failed exchanges before selecting a connector support profile.

## Reuse diagnostic finding

The [reuse repeat](../milestones/M1/RELAYD-REUSE.md) observed serialized denied/benign reuse passing through relayd, while denied/benign and benign/benign pipelines returned only their first response. Failed pipeline cleanup snapshots recorded zero and one backend receipts respectively, with zero hostile URI receipts. Direct controls passed. The suite remains failed at 22/24, and an extra health transition plus short fixture timeouts prevent cause attribution. Isolate timing and connection events before selecting a connector reuse profile; neither general support nor general incompatibility is established.

## Idle-time comparison finding

The [one-variable idle comparison](../milestones/M1/RELAYD-IDLE.md) shifted relayd pipeline EOF from about one to three seconds without recording a second application arrival or changing backend counts. Serialized reuse and direct pipelines passed in both profiles; the suite remained failed at 26/30. A longer inspection idle timeout alone did not restore these sampled pipelines. Aggregate events narrow the observation but do not establish relayd's internal buffering mechanism; synthetic packet evidence or attributable source tracing is needed before selecting a connection profile.

## Inspection stream finding

The [correlated Read-boundary trace](../milestones/M1/RELAYD-STREAM.md) recorded only the first request's bytes for each failed relayd pipeline, although clients wrote both. Direct pipelines consumed both; serialized controls consumed both and passed in both idle profiles. This narrows the visible failure before inspection consumes a second request but does not locate relayd/socket buffers or establish exact installed source behavior. A serialized relayed stream hash matches a reconstruction with second-request Connection/Host headers reordered; full byte preservation and normalization safety remain unqualified. The suite remains failed at 26/30. Establish source/stream attribution before selecting a supported ingress profile.

## Buffered-read hypothesis control

The [post-response CRLF comparison](../milestones/M1/RELAYD-BUFFER.md) admitted the second request in both relayed pipeline samples with exact responses/backend counts, while all four original pipeline failures remained. The suite failed at 30/34. This supports the buffered-read hypothesis suggested by the pinned discovery callback guard; it does not establish installed-source attribution or select a safe repair. Investigate release/source lineage and bounded buffer-draining behavior, or compare a stock transport-only ingress profile, before adoption. Extra CRLF is a diagnostic stimulus, not a product workaround.

## Stock TCP/TLS identity direction

The [TLS study](../milestones/M1/RELAYD-TLS.md) passed ten added HTTPS leaves while the full comparison retained four HTTP pipeline failures (59/63). The [identity source study](../milestones/M1/RELAYD-IDENTITY.md) traces stock v1/v2 output in authenticated release source, giving TCP/TLS termination a concrete companion-address transport candidate. The inspected writer carries addresses without TLS/SNI TLVs, and its HTTP health check sends a bare HEAD independently of that writer. A mandatory bounded PROXY receiver, separate readiness and qualified local sender containment are next research gates. Loopback and an address prefix do not authenticate relayd. No connector, product policy or new native result is adopted by this source study.
