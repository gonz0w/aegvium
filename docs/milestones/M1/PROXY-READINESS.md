# Separate PROXY receiver readiness research

Status: static feasibility complete; endpoint/helper/native wiring proposed under bounded research authorization. No runtime or service policy adopted.

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

Use an absolute helper path, reviewed ownership/mode and a probe deadline shorter than relayd's configured check timeout. Restrict the research program to one request and bounded response processing; no subprocesses. Syntax, executable permissions, privilege identity and timeout behavior need native receipts. No helper or relayd configuration is implemented in this PR.

## Test Design

Endpoint slice: verify ready/unready/recovered status, missing Host HTTP/1.0 HEAD, bodyless HEAD, constant GET body and no-store, unknown path/query, unsupported method, and zero application/backend receipts. Use the actual research receiver for engine transitions, underlying accept failure and Close while the health server remains reachable. Continue to reject bare HEAD on the data listener. Native tests use two distinct ephemeral guest-loopback ports; close both, join workers/server and require failed reconnection on each. Host TCP capability skips remain skips. Define exact admitted case names/count before changing the native controller.

Checker/wiring slice: retain relayd -n result before service execution in the disposable fixture. Verify ready -> down -> recovered health states and forwarding receipts independently, allowing documented polling delay rather than claiming instantaneous revocation. Cover 503, refused connection, silent timeout, malformed response, unexpected redirect, helper argument rejection, missing executable, signal termination and unexpected positive exit behavior. Record the relayd account used and require zero application forwarding by health probes. A deliberately positive failing checker must demonstrate the stock contract, without being adopted. Preserve failed cases rather than relaxing assertions.

Run make verify for this documentation/source study. Subsequent source additions require local Go test/vet/race/cross-build/advisory and export checks, signed clean candidate, owned patched/rebooted OpenBSD repeat, nonroot/source/base/bootstrap and VM teardown gates. Do not edit tracked files during native execution. Syntax-only acceptance, host tooling and native wire behavior are different evidence.

## Compatibility, remaining gates and rollback

This study adds no native run; ordinary native admission remains 63 passed from the listener slice. Stock-relayd connected evidence remains separately failed at 59/63 with four historical HTTP pipeline failures. No rule-health proof, full CRS/OWASP coverage, sender containment, identity-to-Coraza mapping, public health exposure, performance budget or reusable connector API is accepted.

Next bounded work is the endpoint slice above, followed by separately identified checker/wiring receipts. Sender authentication and application routing remain independent. Rollback removes this proposed packet and static receipts; no VM, service, dependency or installer state changed.

## Endpoint candidate admission

The endpoint slice selects eight host/native leaves under TestProxyReady (transitions, head, route, method, nil, close, accept-failure, server-bounds), plus two owned-guest TestProxyReadyTCP leaves (lifecycle, accept-failure). Ordinary native admission is 73 (prior 63 plus 10); connected relayd admission remains separately 63. TCP tests require bodyless bare HTTP/1.0 HEAD on the distinct health port, data-port rejection, engine recovery, 503 while health survives receiver shutdown/failure, server/worker joins and failed reconnection on both ports. No checker or stock relayd wiring is included.
