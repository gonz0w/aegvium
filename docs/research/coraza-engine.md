# Pinned Coraza engine observations

Host-only bounded spike, 2026-10-11: Go 1.27.0, darwin/arm64, Coraza v3.8.1. See [code](../../research/coraza/engine_test.go), [retained observations](../../research/coraza/host-observations.json), [provenance](../../research/coraza/provenance.json) and [dependency inventory](../../research/coraza/dependency-inventory.json). The PR binds final checks to the clean candidate; earlier working-tree experiments retain their original identity and do not become native receipts.

The initial compile failed: current upstream docs mention Transaction.ProcessRequest, but v3.8.1 exposes phase methods and the public HTTP WrapHandler. The spike now tests that release's public middleware with an in-memory backend. No custom proxy is implemented.

The next run passed benign GET/POST, URI/body denial, body-limit rejection and invalid config; DetectionOnly URI callback observation failed. Pinned source invokes the callback only for rules with the log action. Explicit log actions on both synthetic rules made detection-mode match observations pass. This corrects the fixture assumption; it is not a Coraza patch or qualification of all default logging behavior. Both detection cases intentionally reach the backend; enforcement cases assert zero backend receipts and 403/413.

A subsequent body-reader error characterization observes zero backend receipts but an implicit HTTP 200: v3.8.1 middleware logs the read error and returns without writing an error status. This is an adoption constraint; production integration must define explicit bounded error responses rather than interpret a 200 as successful inspection. The test intentionally records existing behavior and is not product acceptance.

Final host suite: seven request cases plus invalid configuration and read-error cases passed. Benign and DetectionOnly POST payloads arrive byte-for-byte at the synthetic backend. OpenBSD amd64 CGO-disabled test cross-compilation passed. It has not run in an OpenBSD guest. No CRS corpus, relayd, TLS, network isolation, response-body inspection, streaming, concurrent load, vulnerability audit or appliance qualification is established.

Next: review the dependency graph and native lab profile, then native builds and connector/error/framing comparisons. Keep original failures; no runtime architecture ADR is accepted yet.
