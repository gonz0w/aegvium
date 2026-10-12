# First connected relayd–Coraza traffic experiment

Status: bounded research under the maintainer's continuing relayd integration request. This permits foreground processes and guest-loopback test listeners only inside the independently owned disposable VM. No rc.d service, live network, PF change, TLS material, public endpoint or appliance API is created.

## PRD

RT-01: send identical benign GET/POST and synthetic URI/body-denial requests through a direct inspection control and through stock relayd to the same inspection handler and synthetic HTTP backend. Assert status and exact backend receipt/body for each request.

RT-02: while the synthetic backend remains alive, close the inspection listener and prove relayed requests cannot reach it. Restore inspection and require health-assisted recovery before a benign request reaches the backend again. Readiness probes never count as application receipts.

RT-03: hash-bind the native relayd/config/Go test executable and exact named cases; retain failed/skipped results. Verify owned foreground relayd shutdown, removal of guest test listeners, VM group teardown and unchanged base/source under the existing 900-second deadline.

## EDD

Reuse the syntax-reviewed fixed loopback relayd fixture and HTTP HEAD readiness check. Stock relayd runs with `-d -f` in the guest, launched by the root controller script; no service is installed/enabled. The [OpenBSD manual](https://man.openbsd.org/OpenBSD-7.9/relayd.8) documents foreground mode. The inspection and backend servers plus test client run as nonroot using the host-cross-built fixture executable. A separate test invocation admits only the connected cases; the ordinary invocation explicitly selects its existing 20 engine cases.

Inspection binds only guest loopback 127.0.0.1:18081, ingress uses 18080 and the synthetic backend uses an independently acquired ephemeral loopback port. A Go standard-library ReverseProxy uses only the internally derived backend URL, no environment proxy and bounded dial/header timeouts. Server timeouts and header limits bound these fixture inputs; synthetic SecLang rules retain the 64-byte request limit. No new module dependency or runtime configuration syntax is added.

Create WAF configuration successfully before opening inspection. A dedicated HEAD readiness route returns 200 only with the constructed fixture available, never invokes the backend, and remains separate from middleware/application success. This is a fixture readiness contract, not an adopted health API or comprehensive phase self-test. Use the previous test-only explicit-error adapter for the inspection handler. No response inspection, panic containment, TLS/backend trust, streaming/upgrade support or persistent body storage is adopted.

A root shell owns the foreground relayd PID, installs cleanup traps before launching it, sends TERM and waits within a bound, then escalates if needed. After process exit, verify no relayd processes or fixture ingress/inspection IPv4 listeners remain. Control-socket unlink is recorded separately from daemon exit. The Go test closes its own servers/connections. An error or uncertain cleanup prevents pass; VM teardown remains an independent final backstop.

All listeners remain inside QEMU's restricted guest network with only the existing dynamic loopback SSH host forward. The inspection listener lacks a production peer-identity boundary: any local fixture peer can access it, and direct/backend traffic is intentionally available for control assertions. Therefore no direct-access prevention, trusted identity, client headers or network containment is qualified. Ports/timeouts are fixture choices, not measured appliance budgets. Exact upstream relayd source/build lineage is still unresolved.

## Test Design

Admit ten connected named cases: direct and relayed benign GET/POST plus URI/body denial (eight), inspection-listener loss with zero backend forwards, and recovery with one exact backend receipt. Initial/recovery readiness polling uses HEAD on the dedicated readiness path, with bounded attempts and zero backend receipts. After listener loss, allow only a transport error or non-success status, never backend access; test requests use fresh connections and the backend remains alive. Native evidence identifies the actual observed result rather than promising a particular relayd error status.

Run the existing 20 engine cases separately. Host Go checks must explicitly retain the connected-test skip on non-OpenBSD/non-admitted hosts; a host skip never supplies native evidence. Native parsing rejects unknown, skipped, duplicate, failed or incomplete connected case sets, missing cleanup and binary/config drift. Repeat in the patched/rebooted owned guest; retain raw logs privately and sanitized source-bound receipts.

This is the first stock-relayd versus direct-companion functional comparison. Existing connector/Caddy comparison, CRS corpus, malformed framing across both parsers, persistent connection transitions, TLS/SNI/Host policy, identity, privileges, performance and comprehensive crash/reload/timeout/resource testing remain separate #15/#16/#17/#18 gates. Do not infer no-bypass security from this small synthetic sample.
