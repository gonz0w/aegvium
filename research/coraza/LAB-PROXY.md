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

## Opt-in PF sender experiment

`make research-native-sender` runs the native TLS controls and a separate [four-phase sender matrix](../native/sender-containment-observations.json). The [owned PF templates](../relayd/sender-protected.pf) allow fresh data sockets opened by relayd's numeric UID, then reject every other sender. Normal verified ingress remains inspected; direct forged prefixes work in open/rollback controls and are denied before TLS in protected/reprotected controls. Native allow/block counters and invalid-policy known-good preservation are separate gates.

The root controller is nonce-bound to one disposable guest. It parses policies before compilation, records/restores selected static PF views and enabled/loopback skip settings, leaves `/etc/pf.conf` untouched and kills only experiment-labeled data states. No unprivileged policy-control channel exists. Existing CLI arguments and non-test Go code remain unchanged; the program does not automatically install or verify this kernel policy.

These templates pass other isolated lab traffic, including backend/health access, for the harness. They are not an appliance firewall, existing-session revocation or cryptographic authentication. Socket-creation credentials define the local principal; root/PF administrators and compromised allowed-UID processes remain trusted/out of scope. Production startup ordering, a dedicated service identity, trusted address propagation and certificate operations need separate adoption review. [Scoped design](../../docs/milestones/M1/SENDER-CONTAINMENT.md), [ADR 0006](../../docs/architecture/adr-0006-owned-pf-sender-containment.md).

## Explicit PROXY client identity

The guarded owned-guest CLI accepts startup-only `-proxy-client-ip` alongside `-tls-cert`/`-tls-key`. It is off by default and rejects enabling without companion TLS, including check-only. Establish the external relayd-only PF sender boundary before enabling this experiment. The process neither authenticates a PROXY prefix nor installs/verifies PF; open controls still admit forged local assertions. Do not use the lab PF templates as an appliance policy.

Validated connection metadata passes through TLS into a private connection context. The application copies Request.RemoteAddr for Coraza while the raw connection retains its socket peer. Missing/invalid metadata fails closed with generic 503; HTTP forwarding headers never select identity and are still removed before inspection/backend forwarding. Health stays independent. Route replacement keeps the startup option; disabling requires stop/restart. No backend identity header, address response endpoint, rule-file CLI or product address logging is added.

[Native evidence](../native/client-identity-observations.json) separates ten direct test-only Coraza identity-rule wire rows, six context, five body-lifetime and six response-boundary subtests from forty-four actual CLI/relayd/PF cases using normal pinned CRS rules. Two CLI check-only outcomes also pass. The actual CLI has no injected identity-rule probe; do not collapse these component scopes into a product trust claim.

The new race tests exposed inspected-body cleanup overlapping the asynchronous backend writer. The adapter now copies at most 4096 inspected body bytes before RoundTrip, closes that reader synchronously, preserves framing metadata and rejects body read/close/limit/length faults before the backend. The [initial failed host observation](../native/client-identity-host-failure.json) remains separate from twenty passing focused race repetitions and the fresh native result. [CI-01–03 and rollback](../../docs/milestones/M1/CLIENT-IDENTITY.md), [ADR 0007](../../docs/architecture/adr-0007-proxy-client-identity-research.md). Production privileges/startup/certificates/audit policy, backend isolation, protocol/resource budgets and adoption remain open.

## Distinct-user backend isolation

`make research-native-backends` adds a separate owned-guest PF experiment after all client-identity controls. Its fixed policies preserve relayd-only access to the companion and allow fresh loopback IPv4 backend connections on ports 18086–18087 only from the lab companion/fixture UID 32767. The earlier sender-only templates remain unchanged and leave backends reachable.

A distinct nonroot test principal (the existing daemon account, verified UID/EUID 1) sends identical direct attack POSTs to HTTP and verified HTTPS backends. Open/rollback controls return 200 and independently record exact attack bytes and authority; protected/reprotected controls reject before TLS/HTTP without timeout and record zero effects. In the same phases the actual identity-enabled CLI retains all forty-four inspected-traffic controls. Backend allow/deny counters, invalid replacement preserving known good, child joins, public/private asset cleanup and eight-view PF restoration are required.

[Native evidence](../native/backend-isolation-observations.json) separates eight foreign client outcomes from eight independent backend-effect observations. Public phase/run markers and a synthetic CA synchronize the two test users; they cannot select root commands, targets or policy. Private keys remain in the fixture's private directory. No non-test Go, CLI option or dependency changes.

The allowed UID is a laboratory identity, not a production account. Root/PF administrators and allowed-UID compromise remain outside this boundary. Other lab traffic is passed; these templates are not an appliance firewall, remote backend isolation, IPv6 or existing-state revocation. [BI-01–03 design/rollback](../../docs/milestones/M1/BACKEND-ISOLATION.md), [ADR 0008](../../docs/architecture/adr-0008-local-backend-isolation-research.md).

## Request trailer repair: host observed, native qualification blocked

The lab handler now rejects unsupported trailer declarations/maps before reading and rechecks after bounded body EOF. The identity wrapper initializes the original request's trailer map before its shallow copy so undeclared EOF metadata remains visible. Host direct verified-TLS tests require 400 and zero backend effects for the scoped trailer cases. The [initial host forwarding and incomplete first repair](../native/request-wire-host-failure.json) remain failed observations; these were uncommitted source-hash-bound host runs, not signed/native candidates.

A separate candidate raw-wire profile defines twenty-six identical logical messages over direct verified TLS and stock TCP relayd, using the actual identity-enabled native CLI. It requires exact bytes/hash, one finite response declaring close, raw EOF with no extra byte before the client deadline, independent exact backend body/path/authority/no-trailer/clean-header effects, pipeline exclusion and recovery. Equal duplicate lengths and CL/TE normalization remain explicit admitted observations, not complete request-smuggling protection.

The [native attempt](../native/request-wire-native-failure.json) built the fixture/checker/CLI offline as UID 32767 and passed 163 engine cases. Legacy composition then failed three post-reload responses: alt-reload-sql, reload-removed-api and reload-app-during had no response and zero backend effects instead of the required 403/421/200 outcomes. Cause is unproven; the existing fixture collapsed client errors and retained no sufficient daemon-health diagnosis. The new 52-row wire matrix and all later scopes did not run. Cleanup/source/base invariance and VM teardown passed; that does not make qualification pass.

`make research-native-request-wire` is the candidate command. Keep this batch in draft until the legacy failure is diagnosed and the complete native profile passes without retrying away or weakening required responses. [RW-01–03 and rollback](../../docs/milestones/M1/REQUEST-WIRE.md). No production protocol/identity/privilege/resource/architecture adoption follows.

## Redacted transport diagnostics

The legacy application-path client now emits a separate LAB-TRANSPORT metadata row for each call: controlled case label, unique ID, monotonic start/duration, response status, fixed completion stage/error class and sampled persistent-health count/age. It records response-body failures before failing the original assertion. Requests, deadlines, route handling and expected response/backend outcomes remain unchanged; there is no retry, new network probe or privileged observer. Request construction errors also use a fixed message instead of printing the URL-bearing error.

Current admission requires correlated diagnostics for forty-one named HTTP cases, ten workload calls and initial readiness attempts. The raw-prefix case remains separately asserted. Unknown/raw fields, invalid class/stage/types, missing/duplicate calls, inconsistent times/health and mismatched path/load statuses reject admission. Partial observations remain separate when Go or the supervisor fails; diagnostic completeness is not composition success. Historical logs without this namespace are incomplete and are not backfilled or reclassified.

[Host tooling evidence](transport-diagnostic-observations.json) binds focused fake-client/helper/race, admission mutations, vet, 107 repository checks and OpenBSD compilation. No network calls occur in these helper tests. The full traffic/security suite and new native integration have not run. Health count/age are independently sampled, not an atomic pair or relayd table witness; classes do not prove a precise failing layer, and instrumentation can perturb timing. The retained native reload failure remains unexplained. [TD-01–03](../../docs/milestones/M1/REQUEST-WIRE.md#ordinary-transport-diagnostic-follow-up).

## Shutdown ownership follow-up

The [SD-01–04 repair](../../docs/milestones/M1/LAB-RELOAD.md#shutdown-ownership-repair) separates successful handler drain/Serve join from the errors those operations return. A drained generation is retired even after a Serve error, while every independent failure remains available through error chaining. Concurrent/repeated Close shares one completion; owner-close errors and post-activation retirement causes remain preserved. Failed drain or missing join still prevents engine retirement. The CLI retains its generic failure output and nonzero exit.

[Host-only evidence](shutdown-host-observations.json) retains the original failing regression plus focused no-network lifecycle/race checks, vet, compilation and source export. This changed runtime has no native qualification yet; affected validation remains paused, and the earlier reload response failure/new wire matrix remain unresolved/unexecuted. No change to traffic policy, CLI options, deadlines, dependencies or installed services.

## Server supervision follow-up

The [SV-01–04 follow-up](../../docs/milestones/M1/LAB-COMPANION.md#server-supervision-follow-up) notifies the lab CLI when either HTTP Serve loop terminates unexpectedly. It drops readiness before publishing a payload-free Failed notification and retains the original result for shutdown. The CLI leaves its signal wait, closes owned resources and exits nonzero with a generic message. Normal requested shutdown suppresses new notifications; a previously recorded failure remains visible. Library owners must observe Failed or explicitly Close; notification alone does not retire resources.

[Original host-only lifecycle evidence](supervision-host-observations.json) retains eighteen library/CLI parent tests with host race/vet/cross/export checks. [Later ordinary OpenBSD component execution](../native/lifecycle-component-observations.json) passes the same eighteen parents and twelve subtests using verified host-cross-built test binaries, separately from native compilation and complete profile qualification. No application/WAF/traffic/security suite was resumed. Classification follows observer order during a shutdown race; an already running reload or accepted handler may still finish. This adds no retry, restart, cancellation, immediate network/relayd revocation, runtime adoption or permission to resume paused validation.
