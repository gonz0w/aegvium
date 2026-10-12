# Bounded inspection idle-time diagnostic

Status: authorized research follow-up to [reuse diagnostics](RELAYD-REUSE.md). No supported runtime profile selected.

## PRD

RI-01: retain all twenty-four baseline cases and their expectations. Compare denied/benign pipeline, benign/benign pipeline and serialized denied/benign reuse in each arm with inspection IdleTimeout changed from one to three seconds only. Current connected admission is thirty named leaves; any failed case keeps the suite failed.

RI-02: capture synthetic inspection request arrivals and connection state events before response assertion failures. Record monotonic elapsed milliseconds and bounded anonymous events; exclude peer addresses and headers. Diagnostics must not become passing assertions.

## EDD

Reuse the owned guest fixture. After baseline raw cases, close the inspection listener and restart it with three-second idle timeout. Go read/write/header and relayd session/health limits remain unchanged. Before inspection-loss testing restore the one-second baseline. All requests and responses retain previous byte/count/status expectations and six-second client deadline. No relayd configuration, dependency or product policy is changed.

Bound event storage to 1024 entries per test process, fail on overflow, protect collection with a mutex and copy snapshots. Capture all inspection ConnState transitions (including health probes) and application method/path arrivals before Coraza, with no remote addresses. Log each raw case's event slice in cleanup after client close. Health probes are excluded from application arrivals but can appear in aggregate connection events; this is not a correlated packet trace or an independent parser.

## Test Design

Retain baseline twenty-four and add exactly six long-idle cases. Both direct/relayd long-idle arms require pipeline 403/200 with one benign receipt, benign pipeline 200/200 with two receipts, serialized 403/200 with one receipt. Verify newly missing cases cannot be admitted. Failed observations preserve statuses, backend counts, hostile URI counts and elapsed event timing.

Native execution requires a signed clean candidate, local verification, patched/rebooted owned VM, nonroot fixture, foreground daemon cleanup, VM teardown and unchanged source/base. Host execution skips connected cases. If the result only shifts EOF timing, record that distinction without claiming proof about internal relayd behavior or complete pipeline safety.

## Limits and rollback

One variable and one repeat per profile; no performance acceptance, packet capture, per-connection correlation, exact installed relayd source lineage, full framing corpus, TLS/identity, full CRS or connector adoption. Previous failures remain unchanged. Dispose of the owned guest; never alter live services or networks.
