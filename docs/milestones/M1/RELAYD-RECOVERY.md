# Bounded readiness-to-application recovery diagnostic

Status: authorized research; historical TCP recovery failure retained.

## PRD

RR-01: retain all forty-seven existing assertions and passively capture inspection events/reads plus backend counts around the existing recovery leaves. Include readiness arrivals as a separate event kind, never as application arrivals or backend forwards.

RR-02: add six raw recovery controls after the existing recovery sequence: direct/HTTP-relay/TCP-relay arms, each using a readiness HEAD followed by one benign POST on either the same connection or a fresh connection. Require 200/200, readiness zero backend receipts and one exact POST receipt. Current connected admission becomes fifty-three leaves; do not retry a failed POST or count later success as repairing an earlier failure.

## EDD

Keep the stock profiles, inspection restart, readiness polling, timeouts and all prior traffic unchanged. Wrap existing HTTP/TCP recovery subtests with a bounded diagnostic snapshot registered before exchange. Record HEAD arrival separately in the existing anonymous event collector. Snapshot event/read deltas, backend/hostile counts and timestamp without private endpoints, packet claims or extra protocol parser.

After both existing recovery leaves, run the six new controls exactly once. Raw same-connection controls send HEAD without Connection: close, consume its response, then send the POST with Connection: close. Fresh-connection controls send HEAD with Connection: close, consume its response and close the socket, then open a new socket for the same POST. These are deliberate connection/header profiles; differences cannot be attributed solely to reuse. Record each successful write's count/hash and use Go's response parser with the correct HEAD/POST method. Require full expected body bytes and bound responses to 4096 bytes. Keep six-second per-connection deadlines, one-second inspection idle timeout and existing event/capture caps.

Controls occur later than the original recovery POST and their order is fixed, so success cannot exclude a transient failure or explain its cause. Do not insert a delay, retry or health/configuration change to make an assertion pass. No relayd source patch, TLS, dependencies, live services or network changes.

## Test Design and rollback

Admission guards require all fifty-three leaves, rejecting missing/failed/skipped cases. Host Go connected skip remains a skip. Run local checks/vet/race/advisory review and cross-build before a signed clean candidate's owned patched/rebooted native repeat. Keep twenty engine cases separate, retain all failures, and require daemon/listener/socket cleanup, VM teardown and unchanged source/base. Diagnostics use synthetic markers and anonymous IDs; Read observations are not packet traces or installed-binary source attribution.

Discard the owned guest. A result scopes the next investigation; it adopts no supported profile or readiness contract.

## Fixture lifetime correction and retained diagnostic

Source review found that the original HTTP recovery subtest started the restored inspection server using its own testing.T. The start helper registered server.Close with that subtest's Cleanup, so the listener was closed when the HTTP recovery leaf ended, before TCP recovery and subsequent controls. The intended shared fixture lifetime requires ownership by the parent comparison test. This is a test-fixture correction, not a relayd repair or readiness retry; preserve every status and receipt assertion.

Candidate `74a9df89ab40c062ba7142dc73346848d1e43b2a`, owned run `fa698697-af43-4568-8a3c-10d369c2f3ce`, retained the lifetime bug with added diagnostics. All fifty-three leaves ran; forty-one passed and twelve failed. Besides four original HTTP pipelines and TCP recovery, the baseline HTTP serialized reuse and all six new raw controls failed. Both direct controls could not connect to inspection (connection refused), and the original TCP recovery had zero inspection events/reads and zero backend receipts. This supports the source-level cleanup explanation rather than an ingress-specific recovery defect. Separate twenty engine cases/configtests, authenticated patches/reboot, daemon/VM cleanup and source/base invariance passed.

RR-03: bind only the restored server to the parent testing.T and repeat the unchanged fifty-three assertions in a fresh owned guest. Keep the failed diagnostic and historical TCP comparison separate from the corrected candidate; successful repetition cannot retroactively turn either attempt into passing evidence.

## Corrected native repeat

Candidate `2933e7f8d47d996d83e5485ed3165093e534628e`, fresh owned run `b34a43f4-7e0b-4b17-a4cc-6e659d04b96b`, passed both original recovery leaves and all six new raw HEAD/POST controls as UID 32767. Each recovery leaf recorded exactly one backend receipt and zero hostile URI receipts. All six raw controls returned HEAD 200 with no body followed by POST 200 with the exact 18-byte synthetic response; readiness did not reach the backend. The original TCP recovery also recorded an inspection POST arrival/read, unlike the failed diagnostic's empty event/read snapshot.

The full connected suite **failed at 49/53** because the four existing HTTP-relay pipelines still failed. The extra HTTP serialized failure in the first diagnostic was not observed in the fresh corrected repeat; retain it as an unresolved observation rather than attributing it to the recovery correction, which occurs later. [Receipts](../../../research/relayd/recovery-observations.json) keep both signed candidates, exact source/tree/runtime inputs, actual named outcomes, anonymous exchange observations and log/report hashes. Historical 42/47 TCP comparison remains unchanged.

This differential result, the direct connection-refused controls and the registered cleanup path support attributing the historical post-HTTP-recovery TCP failure to fixture lifetime. It does not establish a general relayd readiness contract, recovery resilience under load or a product-ready connector. The corrected restored server remains parent-owned until comparison cleanup; no retry, timeout, status/receipt expectation, relayd source or configuration changed.

All thirty-nine captured exchanges in the corrected run recorded zero hostile URI receipts and no stream overflow. Separate twenty native engine cases/configtests, bootstrap rejection, authenticated patches/reboot, foreground daemon/listener/control-socket cleanup, owned VM teardown and source/base invariance passed. Execution used the host cross-build; native source compilation and broad TLS/identity/CRS qualification remain separate. Next research can assess the TCP ingress candidate's TLS/identity boundary while preserving unresolved HTTP parser/reuse observations and installed binary/image provenance limits.
