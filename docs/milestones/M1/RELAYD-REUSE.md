# Bounded connection-reuse diagnostics

Status: authorized research follow-up to [framing failure](RELAYD-FRAMING.md); no runtime adoption.

## PRD

RR-01: preserve backend observations even when raw response expectations fail. Never turn diagnostic observations into an admitted failing exchange.

RR-02: compare two benign pipelined GETs with a serialized denied GET followed by a benign GET on the same connection, in both direct and stock-relayd arms. Expect 200/200 and two exact benign receipts for the former; 403/200 and one exact benign receipt for the latter. Retain RF-03 unchanged.

## EDD

Extend the existing owned-guest fixture with four cases, expanding connected admission from twenty to twenty-four leaves. Serialize by writing the second request only after fully reading the first response. Reuse the existing six-second exchange deadline, bounded response reader, synthetic backend, patch/reboot and daemon/VM cleanup. Register a test cleanup callback to record statuses, read errors and a receipt snapshot even after Fatal; it must run after connection close. Compare aggregate receipt counts and any hostile URI receipt. These are bounded local snapshots, not packet capture or proof of no later forwarding.

No timeout is admitted as rejection, no expectation is relaxed, and no relayd policy/source change is made. If cases fail, retain source-bound failure receipts. Host checks explicitly skip connected execution; use a fresh signed clean candidate and disposable native run.

## Test Design

Keep the original twenty cases and add direct/relayd benign pipelines and serialized denied/benign exchanges. Existing backend assertions retain exact method/path/body checks. Diagnostic callback records every raw case including early response failure; failed case observations remain distinct from successful backend assertions. Check current admission guards reject missing new cases. Native source/base invariance, foreground daemon/listener/socket cleanup and VM teardown must verify independently of test success.

## Limits and rollback

HTTP/1.1 guest-loopback synthetic traffic only. No cause attribution without additional evidence, packet trace, independent parser, supported reuse profile, TLS/identity qualification or connector adoption. Existing image/source lineage gaps remain. Disposable guest destruction is rollback; do not install services or alter live networks. Keep historical framing evidence unchanged.
