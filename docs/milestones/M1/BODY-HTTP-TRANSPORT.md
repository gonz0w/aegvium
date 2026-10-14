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

## Native findings

[Curated receipts](../../../research/native/body-http-observations.json) bind runtime `2d2b4b1b802aed3c505ed263d35f74279472e7d2`, tree `2d81486cf5a59982c248fcd50ecca99bc0963f7e`, run `99b570ef-e5c9-43a1-a3db-3bb6e82ee75f` and 68 runtime fingerprints. All 163 ordinary native leaves passed as UID 32767 on OpenBSD 7.9 amd64 after authenticated patches/reboot. Bootstrap rejection, source/base invariance and owned VM teardown passed. Host tests/vet/race/advisory/cross-build/export and 54 local checks passed. These binaries were host cross-built; prior native source-build receipts retain their original scope.

All fifteen direct HTTP observations agree semantically between host and native; connection read counts remain observational and are excluded from semantic comparison. Four benign controls forwarded the same 22-byte JSON digest. SQL/script requests returned 403 with phase-2 942/941 matches and no backend. Fixed/chunked/stalled oversize returned 413; malformed JSON 400, media 415 and short/malformed body 500, all without backend. Conflicting lengths (400) and unsupported transfer coding (501) never entered the handler. Identical lengths were collapsed and accepted; CL+TE removed Content-Length and accepted chunked input. That normalization is characterization, not an approved anti-smuggling policy.

Maximum application-source consumption was 129 bytes. Fixed declared oversize was rejected with zero source reads, while connection reads also included prefetched headers/body. Malformed chunk source Close reported `other`; stalled chunk source Close reported `timeout`. Every connection closed, server loop joined and listener was unavailable independently of those errors. The one-second read guard establishes bounded fixture execution, not appliance latency or general stalled-client acceptance. Prior twenty-six body comparisons, twenty-four CRS observations and pinned 51-file inputs remain unchanged. Persistent/pipelined traffic, relayd dual-parser comparison, concurrency, trusted sender and selected body policy remain open.

## Consolidated current native source-build packet

BT-05 (WAF-03/04, M1-01–03): reuse the existing offline native engine/checker build path to compile the current fifteen-case TCP fixture and all prior admitted leaves from the same signed source. No new dependencies, compiler pins, budgets or runtime policy. Keep this extension on PR #89 and existing #88/#14 tracking; no separate preparation PR or experiment issue.

Test Design: verified pinned SDK and canonical private vendor/source export; compile engine and checker as UID 32767 with CGO disabled, offline vendored modules and two workers. Preserve the 1200-second compilation-stage and 1800-second VM guards. Require native build output hashes to equal installed/executed hashes, exact 163-case admission including all fifteen HTTP rows, unchanged prior body/CRS observations, pinned input gate, authenticated patch/reboot/bootstrap rejection and independent source/base/VM teardown. Compare semantic HTTP rows with the earlier cross-built native run while excluding observational connection byte counts. Keep source compilation evidence separate from the cross-built run and earlier ninety-case native build. Compilation failure must remain failed evidence without fallback, changed expectations or a live budget extension. This qualifies current research compilation/execution only; connected relayd behavior, image/daemon lineage and appliance adoption remain open.

### Current native source-build result

[Separate native-build receipts](../../../research/native/body-http-native-build-observations.json) bind runtime `8832740a78860b062cf7b83159a3e685d181b2be`, tree `10161f207f9e97f162b014b1673ae80a6f0a75d9` and run `81122edb-ead4-4344-bc3a-5ec253907188`. The current engine and checker compiled offline as UID 32767; all 163 leaves then passed using the native engine output. Installed/executed engine SHA-256 `3bd3a168414a6d80fd621f666a673d957dfd9388011644663356aa0c60ac20ca` and installed checker `52932419021d857d0eda4e818e11a564d29cb617c75b1a1937f7fb076ffb8dd9` are verified in the machine receipts. The fifteen HTTP semantic rows agree with the earlier cross-built run; prior body/CRS rows and all 68 runtime inputs remain unchanged. The private export manifest/file count, compiler/source archives and compile log are hash-bound without publishing the private assets. Patch/reboot/bootstrap/source/base/VM teardown passed within unchanged guards; 54 local checks passed. Existing host Go/vet/race/advisory evidence remains attributable to unchanged inputs; no new host run is claimed.

BT-05 is complete pending review on the same PR #89 and issue #88. Current fixture compilation is now demonstrated on OpenBSD. This does not extend earlier connected generation evidence to current source, establish installed relayd/image lineage or adopt a body/transport policy. Original cross-built and historical native receipts remain immutable.
