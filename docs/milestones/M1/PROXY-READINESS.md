# Separate PROXY receiver readiness research

Status: static feasibility and isolated endpoint research complete; helper/stock-relayd wiring proposed. No appliance runtime or service policy adopted.

## PRD

PH-01: provide a separate, contained HTTP readiness endpoint whose result follows the PROXY receiver lifecycle and explicit engine-ready signal. Never permit bare HTTP on the mandatory-prefix data listener. The endpoint must have no application forwarding, diagnostic details, mutable operation or readiness cache.

PH-02: establish stock relayd health wiring before describing this as an integration. Retain syntax acceptance separately from observed health transitions and data admission. This informs WAF-03/05/06 and issues #12/#15/#16/#21; their broad acceptance and blockers remain unchanged.

## Static feasibility and provenance

The [OpenBSD 7.9 manual](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5) documents table HTTP checks, host-parent state inheritance and external checks. [Source fingerprints](../../../research/relayd/readiness-source.json) pin four members of the previously authenticated release archive. The archive hash was recomputed; members matched ignored extracted copies and the three previously pinned identity-study members. check_script.c's ISC-style notice was inspected. Signature/key authentication is inherited from [release-source evidence](RELAYD-SOURCE.md), not newly repeated. No upstream code or dependency is added. Installed-binary source attribution remains unresolved.

In this inspected table-forwarding path, parse.y 752–779 stores the configured port in table.conf.port; relay.c 1404–1409 selects it for data output; check_tcp.c 58–66 uses it for TCP-based health checks. Changing the table port changes both destinations. No independent HTTP-check port option is established by this study. parse.y 912–930 creates a bare HEAD request, without a PROXY prefix. Thus adding an HTTP endpoint on another port alone does not establish stock HTTP-check wiring to it.

External check configuration is parsed at parse.y 1003–1013. check_script.c 129–146 drops to the relayd account, closes internal descriptors and executes the configured program with the host-name argument. Lines 149–156 establish a timer that kills the direct child. Descendant/process-group cleanup is not established. Lines 65–81 and 159–167 interpret zero as down, positive as up, negative as unknown; a signalled child produces zero. A conventional utility's nonzero failure exit can therefore falsely report health. Do not connect a generic curl/nc command directly to this contract.

Host-parent inheritance is another documented possibility, but parse.y 3001–3050 rejects unused tables and validates parent identifiers. A readiness-only parent table cannot simply be assumed usable without another consumer. Adding a helper relay creates another listener and lifetime. This alternative requires its own scoped syntax/topology study; no invented parent-table configuration is supplied here. A formatted PROXY probe on the data port is also separate: a fixed advertised address is not sender authentication, and a canned HTTP success must not reach an application.

## EDD: proposed staged experiment

First add a standard-library handler on a distinct owned loopback listener in research. Accept only exact /ready with no query and GET or HEAD; unknown paths/query return 404, other methods on that route return 405 with Allow. Return 200 only when the existing receiver Ready observation is true, otherwise 503. Set Cache-Control: no-store. Use fixed small bodies for GET, no body for HEAD, and no rule, address, version or error detail. Missing Host must work for relayd's HTTP/1.0 probe. This fixed health role does not select application routes or authenticate senders.

The signal remains the existing synthetic atomic engine flag in this first slice. It proves lifecycle coupling, not loaded-rule health. The HTTP server must have bounded header/read/write/idle timeouts and header size in an owned TCP fixture. Closing the data listener while the health listener survives must produce 503. Health and data shutdown/absence are asserted independently. There is no appliance startup, reload or service configuration in this stage.

A subsequent fixture-only external probe can target a fixed health address/port independently of the data table port. Prefer a single standard-library executable without shell children, redirects, proxy environment use, DNS resolution or retries. Validate the supplied host argument against the fixture's fixed literal address; do not turn it into an arbitrary destination. Only a validated exact 200 response is mapped to positive success (reserve exit 1). Every expected transport, HTTP, validation and deadline failure must map explicitly to exit 0. Unhandled exits/panics can still be positive, so review and native failure injection are required before adopting this checker. This is a research candidate, not a guarantee that arbitrary program failure is fail-closed.

Use an absolute helper path, reviewed ownership/mode and a probe deadline shorter than relayd's configured check timeout. Restrict the research program to one request and bounded response processing; no subprocesses. Syntax, executable permissions, privilege identity and timeout behavior need native receipts. No helper or relayd configuration is implemented in this endpoint slice.

## Test Design

Endpoint slice: verify ready/unready/recovered status, missing Host HTTP/1.0 HEAD, bodyless HEAD, constant GET body and no-store, unknown path/query, unsupported method, and zero application/backend receipts. Use the actual research receiver for engine transitions, underlying accept failure and Close while the health server remains reachable. Continue to reject bare HEAD on the data listener. Native tests use two distinct ephemeral guest-loopback ports; close both, join workers/server and require failed reconnection on each. Host TCP capability skips remain skips. Define exact admitted case names/count before changing the native controller.

Checker/wiring slice: retain relayd -n result before service execution in the disposable fixture. Verify ready -> down -> recovered health states and forwarding receipts independently, allowing documented polling delay rather than claiming instantaneous revocation. Cover 503, refused connection, silent timeout, malformed response, unexpected redirect, helper argument rejection, missing executable, signal termination and unexpected positive exit behavior. Record the relayd account used and require zero application forwarding by health probes. A deliberately positive failing checker must demonstrate the stock contract, without being adopted. Preserve failed cases rather than relaxing assertions.

Run make verify for the source study and endpoint slice. Source additions require local Go test/vet/race/cross-build/advisory and export checks, signed clean candidate, owned patched/rebooted OpenBSD repeat, nonroot/source/base/bootstrap and VM teardown gates. Do not edit tracked files during native execution. Syntax-only acceptance, host tooling and native wire behavior are different evidence.

## Compatibility, remaining gates and rollback

The source-only study added no native run; the endpoint repeat below extends ordinary native admission from 63 to 73. Stock-relayd connected evidence remains separately failed at 59/63 with four historical HTTP pipeline failures. No rule-health proof, full CRS/OWASP coverage, sender containment, identity-to-Coraza mapping, public health exposure, performance budget or reusable connector API is accepted.

Next bounded work is the separately identified checker/wiring slice. Sender authentication and application routing remain independent. Rollback removes this proposed packet and static receipts; no VM, service, dependency or installer state changed.

## Endpoint candidate admission

The endpoint slice selects eight host/native leaves under TestProxyReady (transitions, head, route, method, nil, close, accept-failure, server-bounds), plus two owned-guest TestProxyReadyTCP leaves (lifecycle, accept-failure). Ordinary native admission is 73 (prior 63 plus 10); connected relayd admission remains separately 63. TCP tests require bodyless bare HTTP/1.0 HEAD on the distinct health port, data-port rejection, engine recovery, 503 while health survives receiver shutdown/failure, server/worker joins and failed reconnection on both ports. No checker or stock relayd wiring is included.

## Observed endpoint execution

[Retained receipts](../../../research/native/proxy-readiness-observations.json) identify signed runtime `fb4d7e2ac065ccc86ad5b9804fbe8f57b3e8dce1`, tree `d803d46dd09cc4611ab8f4854c3a510fae9ba388`, and owned run `937c9dfe-14c3-45b4-92b8-44c5b3dade22`. All 73 ordinary native leaves passed as UID 32767 on patched/rebooted OpenBSD 7.9; no native skips. Eight handler leaves and two separate-port TCP leaves extend the prior 63. The TCP probes required bare HTTP/1.0 HEAD without Host, zero wire bytes after headers and peer EOF. Engine false/true/false/recovered transitions passed. Health remained reachable and returned 503 after receiver Close or underlying Accept failure. Bare HEAD was rejected on the data role. Both fixture servers joined and each pair of ports failed reconnection; two explicit cleanup receipts passed. No exact socket errno is claimed.

The endpoint has no application handler or forwarding fallback; synthetic handler cases asserted zero data-listener accepts. These are isolation controls, not a live backend or stock relayd forwarding test. Server bounds are configuration assertions; oversized headers, slow HTTP clients and resource/performance behavior need separate qualification. Readiness is a point-in-time observation with a synthetic engine flag, not a loaded-rules proof or an atomic guarantee for a later request. There is no relayd checker executable or connected health-state assertion yet.

Host tests/vet/race, OpenBSD cross-build, advisory review and offline source export passed. Host-native TCP and stock-relayd capabilities remained explicitly skipped. Clean make verify passed 43 tests. The initial unsigned local verify failure retained in the receipts was the stale admission-count assertion (63 versus 73); it was corrected with additional missing-endpoint rejection checks before signing. No native failure occurred. The guest authenticated 34 patches, reported zero pending and rebooted; bootstrap rejection, nonroot execution, unchanged source/base and VM teardown passed. Execution used a host cross-built binary, not a new native source compilation. All 31 curated runtime fingerprints match the tested commit; later docs/receipts are not another run. The separate stock-relayd connected result remains failed at 59/63.

Rollback removes proxy_ready.go/tests and its ordinary-admission/source-export extensions, preserving these receipts. No dependency, service, PF, installer or live application configuration changed.
