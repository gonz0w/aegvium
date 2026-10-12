# Bounded PROXY connection handoff

Status: authorized research; no listener service, sender trust or connector adopted.

## PRD

PA-01: give the restricted [prefix parser](PROXY-PARSER.md) a net.Conn handoff that takes ownership of an accepted connection, imposes a positive prefix deadline no longer than three seconds, closes it on every rejected/error path and clears the prefix read deadline only after valid identity parsing. Preserve buffered application bytes and the actual transport peer address.

PA-02: test handoff, silent/partial timeouts, malformed input, deadline setter failures and invalid budgets. Repeat all 45 existing native leaves, add eight in-memory connection cases and two owned-guest TCP cases (55 total). Connected relayd admission stays 63 and historical failures stay unchanged.

## EDD

Use Go standard library and a private adapter in research/coraza. The adapter owns read-deadline state: callers provide a fresh connection with no earlier application deadline to preserve. It accepts a deadline budget in (0, 3s], installs it before prefix reads, and wraps the connection with the same bufio.Reader on success. A failed initial deadline, parse, or deadline clear returns no connection/identity and closes the input. Return advertised endpoints as separate metadata; delegate RemoteAddr to the original connection. Neither loopback nor a valid prefix authenticates relayd. Caller owns Close after success; write deadlines are unchanged.

This is a per-connection preparation function, not a listener Accept loop or concurrency/admission policy. It uses elapsed wall-clock deadlines, not bytes-per-second enforcement. The three-second ceiling is a research choice, not an appliance performance budget. TCP fixtures use loopback ephemeral listeners only inside the controller-owned OpenBSD guest, explicitly selected by AEGVIUM_NATIVE_REPEAT=1; host TCP tests skip. In-memory net.Pipe controls run on both host and guest.

## Test Design

Eight pipe leaves: coalesced stream preservation/transport peer/caller close; application read after the expired prefix budget; silent timeout; partial-prefix timeout; malformed prefix closes peer; initial deadline setter error; deadline-clear error; invalid zero/negative/over-ceiling budgets. Use 100ms timeout controls and a five-second upper test bound, retaining elapsed/error observations. Keep application read bounds separate from prefix bounds. Injected errors must survive errors.Is; failed adapters return nil and signal peer closure.

Two native TCP leaves: successful prefix/application handoff with exact bytes and actual peer retained, and silent timeout that closes the accepted TCP connection. Require listener/client/server cleanup and bounded goroutine completion. These are direct adapter fixtures, not relayd wire tests. Extend strict native admission to all 55 leaves; reject missing TCP or timeout results. Host skipped TCP is not native evidence.

Run make verify, research tests/vet/race/cross-build/advisory review and source export verification before signing a clean native candidate. Native gates retain authenticated patches/reboot, nonroot execution, bootstrap rejection, unchanged source/base and VM teardown. No tracked edits during active execution. Host cross-build execution is distinct from native source compilation.

## Readiness and remaining boundaries

A future listener must bound concurrent pending handshakes, avoid serial Accept starvation, propagate cancellation and coordinate readiness with engine/rules plus actual receiver state. It must not add a bare-HTTP exception to the strict data listener. Compare a separate contained health endpoint or explicit formatted probe in a subsequent scoped native design; neither is implemented here.

RemoteAddr intentionally remains the transport peer. Immutable connection context, Coraza REMOTE_ADDR mapping, forwarding-header sanitization, expected listener roles, Host/SNI policy and local sender containment remain separate work. No claimed no-bypass or authenticated client identity follows from these tests. IPv6/v2 and full PROXY compatibility remain excluded.

Rollback removes the experimental handoff and admission extension; retain previous receipts. No dependency, service, live network/PF, installer or relayd configuration change.

## Observed execution

[Retained observations](../../../research/native/proxy-adapter-observations.json) identify signed runtime `b8df83670ae07be83bc8d49e0e4b0e3c32d8920e`, tree `727f8e21ce601a095a18e4b9752f5530ac1c61b1`, and owned run `26f93dec-d4c3-4ba7-9af2-2e858397df34`. All 55 admitted native leaves passed as UID 32767 on patched/rebooted OpenBSD 7.9: 20 engine, 25 parser, eight pipe handoff and two direct TCP cases. No native skips. Silent/partial pipe timeouts observed 105/116 ms; TCP timeout observed 109 ms with the 100ms prefix budget, each followed by verified peer EOF. These elapsed samples do not establish hard real-time or appliance performance bounds.

Coalesced application bytes survived handoff. The application read after the prefix budget expired passed, as did initial/clear deadline failures, malformed input and invalid budget closure. The native TCP handoff preserved exact bytes and the real transport peer separately from advertised identity. Both temporary TCP listeners closed; connection tasks completed, fixture cleanup and owned VM teardown passed. No stock relayd PROXY wire path was tested.

The first unsigned host working-file run failed seven pipe closure controls because the helper required changing a deadline after the remote net.Pipe endpoint closed; that operation returns io.ErrClosedPipe. The corrected helper permits only that deadline setter outcome and still requires EOF from Read. The adapter implementation was unchanged. The original host log hash and diagnosis are retained separately from candidate-bound native evidence.

Corrected host research tests, vet, race, OpenBSD cross-build and advisory review passed; owned-guest TCP and connected relayd tests explicitly skipped on host. Source export included the adapter files without native compilation. Clean make verify passed 43 tests. The native guest authenticated all 34 patches, reported zero pending and rebooted; bootstrap-key rejection, nonroot execution, source/base invariance and teardown passed. Execution used a host cross-built binary. All 27 published runtime fingerprints match the signed tested candidate; later docs/receipts do not represent another native run.

This establishes a bounded per-connection handoff in the tested fixtures. A concurrency-bounded listener, cancellation/readiness coordination, actual relayd address assertions, immutable context/header sanitation and sender containment still require scoped design/native evidence. The existing 63-case relayd comparison remains separately failed at 59/63. No supported connector or product policy is adopted.
