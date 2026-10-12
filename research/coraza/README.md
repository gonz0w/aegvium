# Coraza engine semantics spike

Authorized bounded research, begun 2026-10-11. The original engine slice has no listener or reverse proxy; the separately scoped connected fixture below uses guest-loopback listeners only. No appliance configuration or live network operation. The pinned upstream HTTP middleware and synthetic SecLang rules isolate URI/body interruption, DetectionOnly and engine validation. Coraza v3.8.1 is pinned in this isolated research module; it is not an adopted runtime dependency.

Run `make research-test`; `make research-cross` compiles the test binary for OpenBSD amd64 without running it. Run `make research-tools` first. Research Go 1.27.2 is checksum-pinned under ignored .tools; the earlier Go 1.27.0 evidence remains historical, not the current baseline. Cache/output stay under ignored .tools. Module integrity uses go.sum; dependency/advisory review remains separate from runtime adoption.

Tests assert synthetic backend receipt counts only after permitted engine results. The in-memory backend is not an appliance proxy. No CRS corpus, relayd framing, TLS, response phase, concurrency, streaming or native enforcement is qualified. Retain failures and source-bound PR results; the [native repeat](../native/README.md) records guest execution under the disposable lab design.

The additional CRS v4.25.0 embedded bundle is pinned to the Caddy comparison candidate. Four smoke cases test benign query/POST and SQL/script attack denial, with backend receipts/body preservation. This is not the full CRS corpus. See [dependency review](../../docs/research/dependency-review.md).

The [explicit-error adapter packet](../../docs/milestones/M1/ERROR-ADAPTER.md) adds a test-only completion wrapper and seven cases. It experiments with explicit failure for silent inspection aborts while preserving the original middleware characterization. It is not a companion proxy or readiness API. Current native admission requires all 20 named cases; earlier 13-case observations remain historical.

The [connected relayd packet](../../docs/milestones/M1/RELAYD-TRAFFIC.md) scopes guest-loopback inspection/proxy/backend listeners and a foreground stock relayd process inside the owned VM only. Host runs retain an explicit `TestRelaydTraffic` skip; that test is separately admitted by `make research-relayd-traffic`. Ordinary native engine repeats select their existing 20 cases. The [connected native observations](../relayd/traffic-observations.json) separately record the admitted comparison; no connector is adopted.

The [framing packet](../../docs/milestones/M1/RELAYD-FRAMING.md) extended guest-only connected admission to twenty cases. Raw TCP inputs preserve chunking, conflicting/mixed lengths and one denied-then-benign pipeline sequence; host skips remain skips.

The [reuse diagnostic packet](../../docs/milestones/M1/RELAYD-REUSE.md) expands current connected admission to twenty-four cases, retaining backend snapshots on response failure. Its failed native observations and historical framing failure remain separate; host connected skips are unchanged.
