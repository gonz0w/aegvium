# Explicit inspection-error response research

Status: bounded research under the maintainer's continuing authorization. This packet covers an in-memory adapter experiment before relayd companion/proxy implementation. No listener, service, route, relayd configuration or reusable API is adopted.

## PRD

EA-01: the pinned middleware's silent body-read abort must return an explicit HTTP 500 and zero synthetic backend receipts, including a read that returns partial bytes with an error.

EA-02: preserve benign empty/POST bytes and status, explicit URI/body denial with zero backend receipts, and DetectionOnly's intentional forwarding and logged match. Retain the unmodified upstream implicit-200 characterization alongside the adapter result.

EA-03: record exact host and disposable OpenBSD runtime candidates, binary hashes, named results, failure/skips and cleanup separately. The native cross-built fixture repeat is not a new native source-build claim.

## EDD

Use a test-only per-request wrapper around pinned `corazahttp.WrapHandler`. Track whether middleware entered the backend and whether the response emitted a final status or body. If it returns without either backend admission or a final response, emit a generic 500 with no engine/request detail. State belongs to each request; it is not shared across requests. Preserve explicit middleware rejection responses and normal backend implicit-200 behavior. Informational 1xx responses do not count as final.

This experiment observes middleware completion only. It cannot prove all request phases completed, distinguish every internal error, undo partial responses, or supply readiness. It does not recover panics, inspect responses, buffer responses, forward requests, add resource limits or implement optional ResponseWriter interfaces. Those must be designed separately before a companion proxy exists. A successful probe or socket must never substitute for inspection readiness. Backend error handling and trusted ingress/parser tests remain separate.

## Test Design

Run seven named adapter cases: empty benign GET, benign POST with exact byte assertion, read failure before data, partial-data read failure, URI denial, body denial and logged DetectionOnly URI forwarding. Require exact status and backend count for every case. Both read failures require 500 and zero receipts; the original upstream reader-error test still expects implicit 200 and zero receipts.

Host tests, vet, race and audit are tooling evidence. Repeat the entire 20-case fixture in the independently owned patched OpenBSD guest as nonroot; admit the exact named set and verify teardown/source/base. Preserve the earlier 13-case build observations as historical. No full CRS, relayd parser, connector, appliance or OWASP Top 10 coverage claim.

## Observed outcome

Runtime candidate `3f6c03dc2e7ac9d12fa6ca0d451bfa0791970c18` passed the full 20-case fixture in the owned OpenBSD guest as UID 32767; explicit immediate/partial reader-error cases returned 500 and zero backend receipts. [Receipts](../../../research/native/error-adapter-observations.json) bind source/tree/binary/runtime hashes and verified teardown/source/base. Host tests, vet, race and advisory audit passed. Native evidence is cross-build execution only; source-build receipts for earlier candidates remain unchanged. No connector or phase gate is accepted.
