# Coraza engine semantics spike

Authorized bounded research, 2026-10-11. No listener, reverse proxy, appliance configuration or live network operation. The pinned upstream HTTP middleware and synthetic SecLang rules isolate URI/body interruption, DetectionOnly and engine validation. Coraza v3.8.1 is pinned in this isolated research module; it is not an adopted runtime dependency.

Run `make research-test`; `make research-cross` compiles the test binary for OpenBSD amd64 without running it. Host Go 1.27.0 is a tooling baseline, not native qualification. Cache/output stay under ignored .tools. Module integrity uses go.sum; license/vulnerability review is a separate adoption gate.

Tests assert synthetic backend receipt counts only after permitted engine results. The in-memory backend is not an appliance proxy. No CRS corpus, relayd framing, TLS, response phase, concurrency, streaming or native enforcement is qualified. Retain failures and source-bound PR results; native execution needs the disposable lab design.
