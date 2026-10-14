# Direct HTTP body transport research

Status: authorized bounded M1 research under #16; no connector or body-policy adoption.

## PRD

BT-01 (M1-03, WAF-03/04): carry the existing test-only body gate onto fresh owned HTTP/1.1 connections. Qualify fixed/chunked accepted bytes and rejection, parser-level framing rejection, observed header normalization and actual connection/server/listener cleanup. Record source reads separately from wire reads; a body-reader cap is not a transport-byte budget.

## EDD

BT-02: fresh literal-loopback ephemeral listener, Go HTTP server and pinned On-mode CRS WAF per case. Raw client bytes are fixed synthetic fixtures. Use Connection: close; half-close client writes after complete fixtures, except one intentionally stalled chunked upload. Server ReadTimeout/ReadHeaderTimeout are one-second test guards, WriteTimeout three seconds, bounded client four seconds and shutdown/join guards. These are laboratory guards, not performance acceptance. No arbitrary target, upstream, TLS, service or live network.

Wrap the owned accepted connection to count total wire reads, and the handler's original body to count source reads/Close calls plus normalized Close-error class. Capture the request view before middleware: ContentLength, TransferEncoding and retained Content-Length values. Record status/handler/backend/body digest, matched rules/phases and independent closed-connection, joined-server and unavailable-listener gates. Keep wire read counts observational because prefetch/drain and TCP batching differ from application body consumption.

## Test Design

BT-03: fifteen exact cases: fixed and chunked benign JSON, JSON script/form SQL denial, fixed and chunked oversize, short fixed body, malformed chunked body, malformed JSON, unsupported media, conflicting Content-Length, identical duplicate Content-Length, CL+TE, unsupported transfer coding and a stalled chunked oversize upload. Preserve inherited 400/403 responses, explicit gate 413/415/500 and exact admitted body digests. Parser rejections must occur before handler/backend entry. Record normalization acceptance separately from desirable appliance policy; accepted identical CL and CL+TE controls are not a smuggling-safety claim.

BT-04: stalled chunked oversize must demonstrate the application cap while observing underlying Close behavior under the server read guard. Do not infer successful source closure from one invocation. Require independent network/server teardown even where a source Close reports an error. Add exact native admission/mutations and export, then execute prior 148 plus fifteen TCP leaves (163). Host test/vet/race/advisory/cross-build/export and make verify remain tooling evidence. Native source/tree/input hashes, nonroot/patch/reboot/bootstrap/source/base and VM teardown remain mandatory; retain failures.

## Compatibility and rollback

Existing body gate and pinned dependencies/rules remain unchanged. Remove the new direct-HTTP fixture/export/admission to roll back, retaining observations. Direct Go HTTP parsing is not relayd/inspection parser comparison, trusted sender qualification, persistent/pipelined behavior, transport performance or selected route policy. Connection: close and bounded synthetic peers do not qualify general stalled-client/concurrency behavior. Historical failures and native/cross-built results remain separately scoped.
