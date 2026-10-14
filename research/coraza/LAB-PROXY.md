# Runnable owned lab proxy

The companion now reads a strict route allowlist and supports verified HTTPS backends under [LR-01–04](../../docs/milestones/M1/LAB-ROUTING.md). This is bounded lab research with fixed loopback listeners, pinned Coraza/CRS, request/response limits, metadata stripping, separate readiness and graceful WAF cleanup. [LP-01–04](../../docs/milestones/M1/LAB-COMPANION.md) and its original fixed-route receipts retain their historical scope.

After preparing the existing [reviewed native profile](../../docs/milestones/M1/NATIVE-ENGINE.md):

```sh
make verify
make research-lab-proxy
```

The target rebuilds the engine test, checker and actual executable, launches the isolated OpenBSD guest, applies verified patches/reboots, runs the ordinary suite, then starts two owned backends and the executable behind foreground relayd TLS/TCP. It tests config rejection before startup, exact route/backend effects, CRS denials, TLS verification failures, oversized/stalled responses and recovery. It tears down the fixture/VM and retains ignored source-bound reports under `.tools/native-runs/`. No service is installed or enabled.

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

The native fixture generates its CA/certificates in memory and stores only the temporary public CA/config needed by the child. Private backend keys never enter files or evidence. Ingress uses the prior root-owned temporary relayd key/cert and removes them at teardown.

Configuration accepts 1–8 unique lowercase `.test` hosts and at most 8192 bytes. Duplicate/folded/unknown fields, trailing JSON, incompatible version, wildcard/port-bearing hosts, nonloopback/DNS/privileged backend addresses, listener collisions and backend URL credentials/paths/queries/fragments are rejected. HTTPS requires a valid bounded regular public CA file and explicit `.test` name; it uses neither ambient trust nor verification bypass. No redirects are followed and no upstream request retry is configured. CA/config checks reject directly symlinked inputs; owned-file checks do not authenticate local senders or concurrent file replacement.

Fixed listeners and shared policy:

- relayd TLS/TCP ingress: `127.0.0.1:18120`; prefix receiver: `127.0.0.1:18084`; separate health: `127.0.0.1:18085`.
- Each configured host or that host with `:18120` maps to its explicit backend. Unknown hosts/ports return 421. The backend Host is the configured host; forwarded client metadata is removed.
- GET/HEAD/POST, JSON/form POST, 4096-byte request/response guards, close-only HTTP/1.1; upgrades/general streaming/reuse are unsupported.
- Wrong upstream name/CA, cleartext peer and unavailable/oversized/stalled upstream return generic 502. Oversized/stalled response cases can have an inspected backend effect despite 502; response failure is not a no-effect or safe-retry guarantee.

[Native routing receipts](../native/lab-routing-observations.json) are separate from the original [15-case lab result](../native/lab-proxy-observations.json). Prefix identity remains untrusted/unused; sender containment and frontend SNI/Host binding remain open. Reload/rules updates, real application trust/tuning, full response parity, concurrency/resource/security acceptance and native Caddy comparison remain gates. The executable is host cross-built and executed on OpenBSD; this result does not claim native compilation of the CLI or appliance adoption.
