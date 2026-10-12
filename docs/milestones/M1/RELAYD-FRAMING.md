# Bounded HTTP framing comparison

Status: research extension to the [connected fixture](RELAYD-TRAFFIC.md). No new listener, daemon, dependency, service, TLS material or live network change. The same owned guest, inspected proxy, synthetic backend and lifecycle budget apply.

## PRD

RF-01: valid chunked benign POST reaches the backend once with exact decoded bytes; chunked synthetic body attack reaches it zero times. Compare direct inspection and stock relayd ingress.

RF-02: conflicting Content-Length values and mixed Content-Length/Transfer-Encoding with a synthetic attack must not reach the backend. Record actual response/connection outcomes for each arm. A client timeout alone is inconclusive, not a passing rejection.

RF-03: on one connection, a denied URI request followed by a benign GET must produce ordered 403/200 responses and exactly one benign backend receipt, with no hostile receipt. This deliberately tests only this small pipeline sequence.

## EDD

Add five raw-wire cases to each arm of the existing guest-only test. Use standard-library TCP connections and explicit CRLF request bytes rather than a normalizing HTTP client. Apply a six-second connection deadline, cap responses at 4096 bytes, close every connection, and decode responses with the same pinned Go standard library. This does not supply an independent response parser or packet capture.

The [HTTP/1.1 framing specification](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) describes transfer-coding and length precedence, conflicting lengths and framing risks. Mixed length/coding is an attack-only sample here: this experiment asserts zero backend access, not universal rejection of every combined header or complete standards compliance. Do not infer a full request-smuggling corpus from five cases.

Requests are fixed synthetic data. Both arms use identical bytes. Preserve exact body/receipt assertions and observed statuses/errors in the private native log, bound by its published hash. No production request bytes, credentials or real hosts are used. Existing ten traffic and twenty engine cases remain separately identifiable; the current connected admission set expands to twenty named cases.

Unknown/duplicate/skipped/failed/missing results or unverified cleanup cannot pass. If the native framing conditions fail, retain the failure and its source/case/cleanup receipts; do not weaken expectations or relabel it as qualification. A failed framing observation is useful research, not an approved appliance path.

## Test Design

For each direct/relayd arm: chunked benign (200, one exact POST receipt), chunked body attack (403, zero receipts), conflicting lengths (error response or EOF/closed connection, zero receipts), mixed framing attack (error response or EOF/closed connection, zero receipts), denied-then-benign pipeline (403 then 200, exactly one benign receipt). Response timeouts or unrelated I/O errors fail the framing assertion. Malformed cases use a 250 ms observation interval before final receipt comparison; the six-second exchange deadline and fixture server/session limits remain bounds, not performance acceptance.

Host Go checks retain the connected skip. Native repeat must use the owned patched/rebooted VM, nonroot client/inspection/backend, foreground stock relayd, exact input/binary/config hashes, verified daemon/listener/socket cleanup, VM teardown and unchanged base/source. Keep original ten-case observations historical. Host guards must reject omission of a newly admitted framing case.

## Compatibility and limits

Plain HTTP/1.1 synthetic requests only. Duplicate transfer codings, trailer semantics, compression, encoded paths, alternate whitespace/line endings, longer smuggling/pipeline sequences, HTTP/2/3, TLS/SNI/Host policy, client identity, direct-access containment, responses, full CRS, performance and comprehensive resource/crash/reload coverage remain open. A passed sample does not accept #16 or any phase gate. Recovery remains the existing fixture cleanup and inspection-listener restart; no relayd source patch or product policy is selected.
