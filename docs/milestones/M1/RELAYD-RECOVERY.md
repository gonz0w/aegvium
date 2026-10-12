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
