# Bounded PROXY listener lifecycle

Status: authorized research; no service, stock-relayd health configuration or trust policy adopted.

## PRD

PL-01: wrap a dedicated net.Listener with a fixed worker count (1–16; tests use two), mandatory bounded prefix handoff, and no extra accepted-connection queue. A slow prefix may occupy one worker but must not serialize all accepts. Close must cancel accepting, preparing and undelivered connections, wake application Accept and join all workers.

PL-02: readiness requires an open listener lifecycle and an explicit engine-ready signal. Reject handoff when the engine is unavailable; readiness is not a TCP connect check, sender authentication or a guarantee against a later engine failure. Add six synthetic-listener leaves and two owned-guest TCP leaves to the prior 55 native cases (63 total). Stock-relayd connected admission remains a separate 63-case set with historical failures unchanged.

## EDD

Use Go standard library. Each fixed worker accepts one connection, records ownership, invokes the deadline adapter, and waits on an unbuffered successful-handoff channel before accepting another. No goroutine per incoming connection. At most the configured worker count can be accepted but undelivered; kernel backlog and application-owned connections are outside this bound and need future product limits.

Transfer ownership to the application only at Accept under the listener lifecycle lock, rechecking both closed state and engine readiness. Keep transport peer and advertised metadata separate. A worker rejects malformed prefixes and engine-unready handoffs and continues; any underlying Accept error stops this research listener. No temporary-error retry policy is selected.

Close cancels workers, closes the underlying listener and all still-owned connections, and joins workers. Application-owned connections remain the application's responsibility. Multiple Close calls are safe. Shutdown from an accept-error worker must not wait for itself. Constructor rejection leaves the supplied listener caller-owned. Accepted connections remain subject to the adapter's prefix time budget; application deadlines are separate.

The engine-ready signal is a synthetic atomic flag in this experiment. Ready observes lifecycle plus that flag; it does not probe installed rules or validate an upstream health endpoint. Readiness remains true during temporary capacity saturation. Do not add a plain HTTP exception to the strict data listener. Separate contained HTTP readiness/relayd check wiring is a subsequent design.

## Test Design

Six host/native leaves use net.Pipe and a synthetic listener: valid handoff progresses beside a stalled prefix; accepted/undelivered count never exceeds two and invalid constructor limits are rejected; Close aborts pending reads and wakes Accept; Close aborts a valid undelivered handoff; engine readiness gates transfer and recovers; underlying Accept failure removes readiness and terminates workers. Require bounded completion and peer EOF, exact bytes, transport peer preservation and explicit worker join. Test ownership after successful application handoff separately from listener-owned cleanup within the progress control.

Two TCP leaves require owned OpenBSD repeat mode: a valid connection progresses beside a silent one, and a bare HEAD readiness request is rejected without an application handoff. Use ephemeral guest-loopback listeners and no service/PF changes. Both require Close completion and refused connection after listener close. Host TCP skips remain skips. Exact native admission is 63 leaves; reject missing shutdown or TCP evidence.

Run local verify/research tests/vet/race/cross-build/advisory review and source export before a signed clean native repeat. Retain patch/reboot, nonroot, bootstrap rejection, source/base and VM teardown gates. No tracked edits during execution. Native execution uses a host cross-build unless a distinct source-build run is recorded.

## Remaining gates and rollback

This supplies a bounded listener lifecycle experiment, not complete appliance admission, HTTP readiness wiring or a trusted PROXY boundary. Rule readiness, reload/crash races, application connection limits, header/Coraza identity mapping, Host/SNI, stock relayd wire assertions and unauthorized-local-peer containment remain separate. Default error-stop behavior is intentionally narrow; broader compatibility requires native tests.

Rollback removes the research listener and admission extension; preserve prior receipts. No dependency, deployment, installer or live network/service change.
