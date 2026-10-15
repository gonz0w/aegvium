# Runnable owned lab proxy

The companion now reads a strict route allowlist and supports verified HTTPS backends under [LR-01–04](../../docs/milestones/M1/LAB-ROUTING.md), with transactional SIGHUP reload under [RL-01–04](../../docs/milestones/M1/LAB-RELOAD.md) and bounded work/native compilation under [LC-01–04](../../docs/milestones/M1/LAB-CONCURRENCY.md). This is bounded lab research with fixed loopback listeners, pinned Coraza/CRS, request/response limits, metadata stripping, separate readiness and graceful WAF cleanup. [LP-01–04](../../docs/milestones/M1/LAB-COMPANION.md) and its original fixed-route receipts retain their historical scope.

After preparing the existing [reviewed native profile](../../docs/milestones/M1/NATIVE-ENGINE.md):

```sh
make verify
make research-native-lab
```

The native target launches the isolated OpenBSD guest, applies verified patches/reboots and compiles the fixture, checker and actual CLI offline as UID 32767 from the pinned compiler/source export. It validates installed/output identities, runs ordinary cases, then starts two owned backends and the newly native-built executable behind foreground relayd TLS/TCP. `make research-lab-proxy` remains the separate host cross-build/execution control. Cold native compilation has a 1200-second build and 1800-second owned-VM ceiling; this is research tooling rather than an installer. It tests config rejection before startup, exact route/backend effects, CRS denials, TLS verification failures, oversized/stalled responses, live route replacement/rejection/rollback, saturation/mixed traffic, an in-flight old-generation response and recovery. It tears down the fixture/VM and retains ignored source-bound reports under `.tools/native-runs/`. No service is installed or enabled.

`make research-labproxy-cross` separately builds `.tools/research/labproxy-openbsd-amd64`. Inside the owned nonroot OpenBSD lab only:

```sh
AEGVIUM_LAB_PROXY=owned-guest ./labproxy -config routes.json -check
AEGVIUM_LAB_PROXY=owned-guest ./labproxy -config routes.json
```

`-check` reads and validates the route/CA inputs without binding listeners. Start also validates them before binding. The CLI refuses root, non-OpenBSD, missing marker and unsupported arguments. The native harness supplies all owned peer components. This versioned JSON is laboratory instrumentation, not the product or BootWeave contract.

Minimal owned HTTP example:

```json
{
  "version": 1,
  "routes": [{"host": "app.test", "backend": "http://127.0.0.1:18086"}]
}
```

Add an independently owned HTTPS route with a public fixture CA file:

```json
{
  "host": "api.test",
  "backend": "https://127.0.0.1:18087",
  "tls_server_name": "api.test",
  "tls_ca_file": "/var/owned-lab/public-ca.pem"
}
```

The legacy TLS-at-relayd fixture generates its CA/certificates in memory and stores only the temporary public CA/config needed by the child. Private backend keys never enter files or evidence. Ingress uses the prior root-owned temporary relayd key/cert and removes them at teardown.

Configuration accepts 1–8 unique lowercase `.test` hosts and at most 8192 bytes. Duplicate/folded/unknown fields, trailing JSON, incompatible version, wildcard/port-bearing hosts, nonloopback/DNS/privileged backend addresses, listener collisions and backend URL credentials/paths/queries/fragments are rejected. HTTPS requires a valid bounded regular public CA file and explicit `.test` name; it uses neither ambient trust nor verification bypass. No redirects are followed and no upstream request retry is configured. CA/config checks reject directly symlinked inputs; owned-file checks do not authenticate local senders or concurrent file replacement.

Fixed listeners and shared policy:

- relayd TLS/TCP ingress: `127.0.0.1:18120`; prefix receiver: `127.0.0.1:18084`; separate health: `127.0.0.1:18085`.
- Each configured host or that host with `:18120` maps to its explicit backend. Unknown hosts/ports return 421. The backend Host is the configured host; forwarded client metadata is removed.
- Four admitted application requests across all routes/generations; excess gets generic 503 before body/WAF/proxy work. No application waiting queue. Health remains separate. Existing eight data connections/two prefix workers still apply. These are laboratory ceilings, not production budgets.
- GET/HEAD/POST, JSON/form POST, 4096-byte request/response guards, close-only HTTP/1.1; upgrades/general streaming/reuse are unsupported.
- Wrong upstream name/CA, cleartext peer and unavailable/oversized/stalled upstream return generic 502. Oversized/stalled response cases can have an inspected backend effect despite 502; response failure is not a no-effect or safe-retry guarantee.

[Current concurrency/native-build receipts](../native/lab-concurrency-observations.json), [prior reload receipts](../native/lab-reload-observations.json), [prior routing receipts](../native/lab-routing-observations.json) and their native scopes are separate from the original [15-case lab result](../native/lab-proxy-observations.json). Prefix identity remains untrusted/unused; sender containment and frontend SNI/Host binding remain open. Authenticated rules updates, real application trust/tuning, full response parity, broader native in-flight/load/crash, hard resource/performance/security acceptance and native Caddy comparison remain gates. The new native-build result compiles and executes the actual CLI on OpenBSD; earlier cross-built receipts remain separate. Appliance adoption and original installed-image/relayd lineage remain open.

After atomically replacing the same owned config file, send SIGHUP to the original owned lab CLI process. It prints only `owned lab reload accepted` or `owned lab reload rejected`. Acceptance follows complete config/CA/transport/pinned-WAF preparation, whole-map activation after old request leases drain, and retired-generation cleanup. Invalid preparation keeps the existing map active; restore the known-good file and repeat SIGHUP for rollback. SIGTERM/SIGINT have a separate notification channel and take priority before another queued reload.

Data/health listeners remain owned by the same process. Existing handlers finish against their original generation; reload does not revoke their effects or promise cancellation/retry safety. New traffic can wait while old handlers drain within the existing laboratory deadlines. A cleanup failure after activation terminates the lab process with a generic error instead of misreporting an uncommitted rejection. The earlier reload fixture measured fresh data requests and one persistent health connection across five signals; host tests separately prove held-request drain/retirement and cleanup failure classification. Rules remain embedded/pinned; SIGHUP is route/trust-input replacement, not a rules-distribution system.

The current workload fixture holds four backend requests across both routes and verifies the fifth receives 503 without an application effect. A mixed burst preserves both benign JSON bodies while denying two SQL requests. A separate verified HTTPS response stays in flight across SIGHUP: no accepted acknowledgement appears during the 500ms hold; the old response completes, then new authority/removal and known-good rollback pass. Health returns sampled 200 in all three phases. Observed backend high-water counts are 4/2/1; these small workloads do not establish hard memory/CPU/disk limits, throughput, continuous availability or safe retries.

## Opt-in companion TLS behind stock TCP relayd

`make research-native-tls` repeats the native compile and legacy path, then runs the separate [passthrough profile](../relayd/lab-tls-passthrough.conf) and [29-case native matrix](../native/tls-passthrough-observations.json). The companion first validates the mandatory bounded PROXY v1 prefix and then performs TLS; stock relayd forwards TLS bytes and independently checks readiness. No relayd source patch or dependency is added. This TLS research target uses a predeclared 3600-second guest and 2400-second native build ceiling after a retained initial compilation timeout; the legacy target stays at 1800/1200 seconds.

Inside that owned nonroot guest, the opt-in command is:

```sh
AEGVIUM_LAB_PROXY=owned-guest ./labproxy -config routes.json -tls-cert frontend.pem -tls-key frontend.key -check
AEGVIUM_LAB_PROXY=owned-guest ./labproxy -config routes.json -tls-cert frontend.pem -tls-key frontend.key
```

The fixture writes ephemeral certificate/key files with mode 0600 and removes them after stopping the child; private key bytes/hashes never enter evidence. Both flags are required together. Startup/check-only rejects invalid keypairs or certificate-uncovered routes before binding. TLS >=1.2 and HTTP/1.1 ALPN are explicit, session tickets are disabled, empty/unknown SNI is rejected, and authority must exactly match SNI with optional `:18120`. Uppercase/trailing-dot/wrong-port authorities are deliberately outside this bounded profile. SIGHUP can replace certificate-covered routes transactionally; an uncovered route preserves known good. Certificate replacement requires stop/start; no automated rotation contract is selected.

A direct local sender can forge a valid prefix and still obtain inspected service with verified TLS. This is retained as a 200/one-effect control, not trusted identity. The flow does not qualify sender containment, persistent connection revocation, client certificate authentication, arbitrary streaming, broad protocol compatibility or appliance adoption. See [ADR 0005](../../docs/architecture/adr-0005-tls-passthrough-research.md).
