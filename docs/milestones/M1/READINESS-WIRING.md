# Stock relayd readiness and forwarding research packet

Status: proposed bounded research; implementation follows review. WAF-03/05/06. This extends the [readiness packet](PROXY-READINESS.md) after the merged native signal comparison, without adopting a connector or health policy.

Tracking: [issue #73](https://github.com/gonz0w/aegvium/issues/73), native sub-issue of #15; M1/P1/Backlog pending design review. Signal attribution remains independently tracked in #69.

## PRD

RW-01: determine whether the unchanged fixed readycheck executable can drive stock relayd's data table through synthetic engine down, ready, down and recovered states. Observe health response, table/host state, fresh ingress outcome, inspection and application-sink events separately. A table UP result alone does not prove inspection or application availability. A denied ingress outcome alone does not prove that relayd detected the outage.

RW-02: keep all components in the owned isolated OpenBSD VM: relayd ingress 127.0.0.1:18120, mandatory-PROXY data listener :18084, bare-HTTP health listener :18085, and an owned synthetic application sink :18121. No route, bridge, PF modification, external application or sibling VM. All ports must be absent before startup and after cleanup. Base relayd plus Go standard library and already-reviewed Coraza dependencies only. BootWeave, production TLS and appliance service configuration are out of scope.

RW-03: retain the original six-arm failures and admitted ten-arm signal/account comparison independently. Conventional positive failing exits remain an unsafe stock contract. The observed TERM child's exit 143 does not directly establish the plain child's wait status. This packet authorizes only a bounded comparison design; it does not clear issue #69's remaining attribution question or any adoption gate. Historical connected evidence remains failed at 59/63.

## EDD

Use one table for the data receiver at 127.0.0.1:18084, consumed by a TCP relay listening on :18120 with proxy-protocol v1 and check script pointing directly to the unchanged `/var/aegvium-lab-readycheck`. Keep the health endpoint separate at the helper's fixed :18085. The receiver validates the advertised destination against ingress :18120, not its own :18084 transport address. No HTTP health probe may enter the mandatory-prefix data role. The helper accepts relayd's literal host argument and dials only its fixed health endpoint. Retain exact configuration and relayd -n outcome before starting a daemon; do not assume syntax from this prose.

Use interval 4 seconds and timeout 3000ms for the first fixture, with the helper's existing 200ms I/O budget. Native Go startup under TCG adds process time outside that budget; record unexpected timeout/state outcomes as failures rather than silently stretching limits. Poll at most thirty one-second attempts per phase. Observe actual states instead of assuming a fixed number of seconds proves DOWN or UP. These are fixture guards, not a latency or resource-capacity promise.

The Go fixture runs as nobody, using the existing receiver/readiness implementation and a bounded Coraza transaction path for a fixed benign GET and one existing deterministic denial control. A separate loopback sink records only synthetic request IDs and returns a fixed sentinel. Inspect before sending to the sink; health requests must never invoke the inspection/application path. This is a forwarding witness, not a full application proxy, CRS qualification or rule-readiness implementation. Readiness continues to use an explicit synthetic atomic engine flag.

A root supervisor owns foreground relayd and the unprivileged fixture process, the private control socket and a fixed phase-control directory. Root publishes a monotonic phase ID plus an allowlisted operation using atomic file replacement; the fixture acknowledges the same ID only after the requested local transition. No shell command, path or address comes from control contents. Only the test process consumes controls. Use a separate bounded receipt directory owned by nobody, with synthetic counters and no request bodies or private inventories. Account ownership must not give the fixture access to the root control socket or alter executables.

Before each phase, finish/join previous requests and snapshot inspection/sink counters. Require transition acknowledgement, direct health result, observed table/host state and then bounded fresh ingress requests with unique phase IDs. Keep successful benign receipt, denied request receipt and zero-delta assertions distinct. Do not reuse client connections across phases. Existing in-flight requests, persistent connections and instantaneous revocation are outside this first study; the current receiver's readiness gate does not establish their behavior.

Closing a receiver is terminal for that receiver object. The receiver-close phase leaves health alive and must return 503. It cannot be called recovered by toggling its engine flag. Any process/listener restart is a new generation with separate absence, ownership, startup and identity receipts. Likewise a health listener stopped for a fault phase is recovered only by a separately owned restart with explicit evidence.

The actual readycheck stays silent and unchanged. Existing native controls establish their own _relayd UID; that evidence and the authenticated release-source privilege trace do not directly measure the unchanged helper's UID. Keep this limitation explicit. New direct helper-account instrumentation, if needed, requires a separately scoped method and cannot be inferred from table state.

## Test Design

Run the existing ninety ordinary leaves separately before connected research. Native skips are failures for an admitted native group. Retain signed clean source/tree, fresh checker/test executable hashes, authenticated patches/zero pending/reboot, bootstrap rejection, nonroot fixture, unchanged source/base and all cleanup gates. No tracked edits during an owned native run.

First implementation slice:

1. Preflight every selected listener, daemon and socket absent; check exact profile/helper hashes; retain relayd -n; start owned sink/data/health fixtures and relayd with bounded startup acknowledgements.
2. Engine false at startup: direct health 503, table/host DOWN, fresh relay ingress cannot produce a successful sentinel or increase inspection/sink counters. A matching negative control without relayd must show the fixture itself is alive.
3. Engine true: direct health 200 with exact checker response contract, table/host UP, benign fresh ingress produces an inspection event plus exactly one sink sentinel. Deterministic denied ingress produces an inspection denial and zero additional sink events. Bare HEAD directly to the data role is rejected; a direct health request causes zero inspection/sink delta.
4. Engine false after ready: health 503 and eventual DOWN; after observed DOWN, fresh ingress has no inspection/sink delta. Engine true again must repeat UP and benign/denied witnesses with new IDs, not reuse prior counters or bytes.
5. Receiver Close while health survives: health 503, eventual DOWN, zero successful forwarding and zero inspection/sink delta for fresh ingress after DOWN. Record receiver/server joins and terminal generation; do not invent recovery of the closed object.
6. Stop/join daemon and every owned fixture server/worker/child; require observer/checker processes absent, all four ports unavailable and private socket absent; then require VM teardown. Preserve partial phase receipts on any error.

Later fault slices, each source-bound and independently admitted:

- Refused health while data remains ready: record the polling window separately, then require DOWN and zero sink events for fresh ingress after observed DOWN. Any traffic before DOWN is a measured stale-state outcome, not silently counted as a failure or a zero-forwarding guarantee.
- Silent health after complete HEAD, malformed response and unexpected redirect: require helper zero, eventual DOWN and post-DOWN no-forwarding witnesses. Cover each with an owned bounded peer and join evidence. Counterfeit health success and loaded-rule failure are separate trust-policy questions.
- Missing checker path and deliberate exit-2 replacement: preserve missing DOWN versus positive-error UP as unsafe contract observations. These replacements never become candidate policy. KILL/TERM controls reuse the separately retained study; do not relabel shell exits as kernel signals.
- Restart/new-generation health/data recovery, crash behavior, pending/keepalive requests and worker saturation require their own semantics and guards. They are not established by the fresh-request matrix.

Add local admission tests rejecting wrong phase IDs, stale receipts, missing/duplicate gates, wrong UID/hash, mismatched inspection/sink deltas, unknown/skipped cases and absent cleanup. Fault injection must demonstrate that a failed health/state/forwarding gate remains a failed connected result even if all ninety ordinary leaves pass. Host tests, vet/race, advisory review, cross-build and offline export are tooling evidence only. Record native cases, phase counters, polling observations and cleanup separately; no universal fail-closed, OWASP Top 10, full CRS, throughput or latency claim.

## Compatibility, tracking and rollback

No dependency changes, installer extension schema or connector API is introduced. The relayd/Coraza boundary remains research. Review the first connected slice before implementation, then retain failures before expanding faults. Broad M1 and sender/parser/lineage blockers stay intact. A successful fixture does not close #12/#15/#16/#21, accept M1 or authorize deployment.

Rollback removes only the new wiring profile, connected native test/controller/supervisor/control protocol, export/admission entries and target. Retain original signal failures, signal comparison and connected observations. Stop/reap all owned processes and remove the disposable VM through the existing supervisor. Never stop or alter live homelab services.
