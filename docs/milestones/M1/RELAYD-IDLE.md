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

## Observed result

Candidate `dcc3ea8a7780bd323f00a6abdffe6cd0beae2a2d` ran in the owned patched/rebooted OpenBSD 7.9 amd64 guest as UID 32767. The connected suite **failed**: twenty-six of thirty cases passed. The separate twenty engine cases and stock configtests passed. [Source-bound observations](../../../research/relayd/idle-observations.json) preserve named outcomes, anonymous event slices and native log/report hashes.

| Relayed sequence | One-second idle | Three-second idle | Backend snapshot / application arrivals |
|---|---|---|---|
| Denied/benign pipeline | 403, EOF; 1.02 s | 403, EOF; 3.02 s | 0 receipts / 1 arrival in each profile |
| Benign/benign pipeline | 200, EOF; 1.03 s | 200, EOF; 3.03 s | 1 receipt / 1 arrival in each profile |
| Serialized denied/benign | 403, 200 | 403, 200 | 1 exact benign receipt / 2 arrivals in each profile |

All direct pipeline and serialized controls passed in both profiles. All twenty raw-case snapshots recorded zero hostile URI receipts. Failed snapshots remain observations, not passing backend assertions or proof against later forwarding. The failed relayed pipelines each recorded an application arrival, an idle transition and later connection closure; health-probe connections also appear in their aggregate state slices. No second application arrival was recorded before those snapshots. One-variable comparison shifted failure time by approximately two seconds without restoring the second request. Increasing inspection idle timeout alone does not solve these sampled pipelines. This is functional diagnostic timing under TCG, not performance acceptance.

The log showed initial unknown/down/up and later up/down/up health transitions, with no additional mid-comparison timeout transition like the prior run. Inspection loss returned 500/502/502 with zero backend forwards and recovery passed after restoring the baseline. Foreground daemon/listener/control-socket cleanup, authenticated 34 patches/reboot, bootstrap rejection, VM teardown and unchanged source/base verified.

No relayd setting or parser policy changed; original expectations and historical failed evidence remain. Exact internal relayd handling is not established by aggregate events. Next bounded research should distinguish requests buffered in the client-to-relayd stream from requests actually written toward inspection, using synthetic packet evidence or attributable source tracing before choosing a supported connection profile. TLS/identity, broader corpus, full CRS, installed relayd/image lineage and connector adoption remain open. Native execution is a host cross-build, not a new native source build.
