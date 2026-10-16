# Aegvium

Lean, auditable OpenBSD WAF research for a dedicated VM behind EdgeWall. BSD-3-Clause; independent of the OpenBSD project. Private repository: [gonz0w/aegvium](https://github.com/gonz0w/aegvium).

A runnable lab companion now forwards owned HTTP/HTTPS applications through pinned Coraza/OWASP CRS. It supports verified HTTPS backends, strict route allowlists, transactional SIGHUP route replacement and four-request admission. Stock relayd can terminate TLS in the retained control or pass TCP/TLS to the companion, where actual SNI/HTTP authority binding is enforced. Architecture and appliance adoption remain proposed; this is not an installable WAF.

The optional sender-containment experiment uses stock PF to restrict fresh connections to the companion's PROXY listener by relayd's socket UID. Open/protected/rollback/protected-again native controls retain exact effects and policy counters. These are disposable-guest templates: other lab traffic, including backend ports, remains reachable. They are not an appliance firewall or cryptographic sender authentication.

| Capability | Current evidence and limits |
| --- | --- |
| Actual companion, CRS, HTTP/verified HTTPS routing | [Lab guide](research/coraza/LAB-PROXY.md); [163 ordinary /42 path/three load/seven startup controls](research/native/lab-concurrency-observations.json). Small synthetic corpus, not full OWASP coverage. |
| TLS passthrough and SNI/Host binding | [29-case native matrix](research/native/tls-passthrough-observations.json), [scoped design](docs/milestones/M1/TLS-PASSTHROUGH.md). Close-only HTTP/1.1; startup-only certificate inputs. |
| Local sender containment | [44-case/four-phase native matrix](research/native/sender-containment-observations.json), [PF design and rollback](docs/milestones/M1/SENDER-CONTAINMENT.md). Conditional on active PF and loopback filtering; fresh IPv4 data connections only. |
| Explicit client identity and body ownership | [Native component/CLI receipts](research/native/client-identity-observations.json), [scoped design](docs/milestones/M1/CLIENT-IDENTITY.md). Default-off PROXY source selection requires companion TLS and an external PF sender boundary; inspected bodies are detached before asynchronous forwarding and expired responses reject with 502. |
| Local backend isolation | [Native distinct-user bypass/effect receipts](research/native/backend-isolation-observations.json), [scoped policy](docs/milestones/M1/BACKEND-ISOLATION.md). Separate PF policies restrict two owned backend ports to the lab companion UID; root/allowed-UID compromise and remote backend network policy remain outside scope. |
| Request trailer enforcement (native qualification blocked) | [Scoped repair and wire design](docs/milestones/M1/REQUEST-WIRE.md), [retained host failures](research/native/request-wire-host-failure.json), [failed native run](research/native/request-wire-native-failure.json). Host TLS checks pass; native build/163 engine cases pass, but three legacy post-reload responses fail before the new wire matrix executes. |
| Transport diagnostics (host tooling) | [Focused helper/admission checks](research/coraza/transport-diagnostic-observations.json). Fixed error classes, timings and sampled health counts preserve failure detail without raw request/error data. Native integration is unexecuted; the retained reload failure remains unexplained. |
| Existing connector comparison | [Configured Caddy TLS/server/reverse-proxy](research/native/configured-caddy-observations.json), [API/rule-pool findings](research/connector/README.md), [comparison](docs/research/connector-comparison.md). No complete parity or runtime selection. |
| Dependencies and advisories | [Review](docs/research/dependency-review.md), [compatible remediation](research/native/dependency-remediation-observations.json). Companion source scans have no findings; Caddy retains CEL package-only and deprecated OpenPGP module-only adoption blockers. |

## Build and verify

Read [CONTRIBUTING](CONTRIBUTING.md), [agent instructions](AGENTS.md) and the active [M1 PRD](docs/milestones/M1/PRD.md), [EDD](docs/milestones/M1/EDD.md) and [test design](docs/milestones/M1/TDD.md). Use signed Conventional Commits, author DCO sign-offs, `codex/` branches and open PRs. Checks run locally; GitHub Actions, runners and hosted success publishers are prohibited.

```sh
make tools hooks
make verify
make research-tools
make research-test research-cross
make research-advisories
```

Host checks and cross-builds are tooling evidence only. Disposable native experiments require the [reviewed OpenBSD profile](docs/milestones/M1/NATIVE-ENGINE.md):

| Command | Owned native experiment |
| --- | --- |
| `make research-native-lab` | Offline native fixture/checker/CLI compilation and legacy TLS-at-relayd routing/reload/load controls. |
| `make research-native-tls` | Native compilation, legacy controls and companion TLS passthrough/authority matrix. |
| `make research-native-sender` | All TLS controls plus PF UID containment, invalid replacement, rollback and verified static PF restoration. |
| `make research-native-identity` | Prior controls plus actual Coraza identity/context/body components and a separate enabled CLI/PF matrix. |
| `make research-native-backends` | Prior identity controls plus restricted backend ports, foreign-user attack attempts, independent effects and rollback. |
| `make research-native-request-wire` | Candidate complete prior profile plus direct/relayd wire tests; currently blocked by retained legacy composition failure. |
| `make research-configured-caddy` | Separate native connector compilation and configured Caddy comparison. |

Each experiment owns and tears down its VM, sockets, daemons and synthetic TLS assets. Never point it at a live gateway, storage or application. Raw keys, source/vendor inventories and logs stay ignored; shared observations retain source/tree/input/output hashes. [Native evidence index](research/native/README.md) preserves earlier scopes, failed HTTP pipelines, half-close effects, unsafe checker behavior and the initial cold-build timeout. Later passing profiles do not reclassify those results; plain-TERM attribution remains [#69](https://github.com/gonz0w/aegvium/issues/69).

## Adoption and project structure

Still open: selected trust/privilege/startup policy, product client-identity policy, certificate distribution/rotation, supported persistent/streaming protocols, full CRS/application tuning, measured resource/soak budgets, original image/daemon lineage and distribution obligations. Local UID containment excludes root/PF administrators and compromised allowed-UID processes. No live deployment, service enablement or release is implied by research.

[Proposed ingress ADR](docs/architecture/adr-0001-ingress-inspection.md) keeps relayd plus a companion and coraza-caddy under comparison. A future Traefik/Caddy-like relayd control plane may reuse the boundary; no reusable API or separate connector repository is selected. CrowdSec remains an optional later behavioral layer.

BootWeave owns the generic installation builder and its extension contract. Aegvium owns its future payload/runtime policy; no speculative installer schema is defined.

Track work in the [private Project](https://github.com/users/gonz0w/projects/5), [roadmap](docs/milestones/github-roadmap-index.md) and [GitHub workflow](docs/engineering/github-workflow.md). Start with [product requirements](docs/product/PRD.md), [baseline architecture](docs/architecture/baseline.md) and [stack research](docs/research/stack.md).
