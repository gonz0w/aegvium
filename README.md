# Aegvium

Lean, auditable OpenBSD WAF research for a dedicated VM behind an operator-controlled perimeter. EdgeWall is an optional suite integration. BSD-3-Clause; independent of the OpenBSD project. Private repository: [gonz0w/aegvium](https://github.com/gonz0w/aegvium).

A runnable lab companion now forwards owned HTTP/HTTPS applications through pinned Coraza/OWASP CRS. It supports verified HTTPS backends, strict route allowlists, transactional SIGHUP route replacement and four-request admission. Stock relayd can terminate TLS in the retained control or pass TCP/TLS to the companion, where actual SNI/HTTP authority binding is enforced. The [M2 boundary](docs/architecture/adr-0010-frontend-key-mandatory-inspector.md) is now selected for reviewed source adoption; runtime integration remains unimplemented/unqualified. This is not an installable WAF.

The optional sender-containment experiment uses stock PF to restrict fresh connections to the companion's PROXY listener by relayd's socket UID. Open/protected/rollback/protected-again native controls retain exact effects and policy counters. These are disposable-guest templates: other lab traffic, including backend ports, remains reachable. They are not an appliance firewall or cryptographic sender authentication.

| Capability | Current evidence and limits |
| --- | --- |
| Owned authenticated DATA source | [Source path](docs/milestones/M2/DATA-REQUEST-SOURCE.md): same-connection context/body, continuous Coraza transaction and C02 lease through one fixed backend exchange and terminal cleanup. Operational gate remains false; no live TLS, listener, engine or native qualification. Any conforming frontend can implement the explicit protocol; Vectivium is the optional suite adapter. |
| Inert M2-C01 context admission | [Source component](docs/milestones/M2/M2-C01.md): immutable bounded peer/route/generation/request recording with synthetic portable tests. No production peer constructor, actual TLS/inspection, allow verdict, backend call or required-WAF enablement. |
| Inert M2-C02 capacity ownership | [Source design](docs/milestones/M2/CAPACITY-OWNER.md): shared four-request/eight-socket reservation accounting across generations, including pre-authentication inbound slots. No actual socket, authentication, inspection or forwarding operation; full qualification remains open. |
| A01a body Read/Close ownership | [Body owner](docs/milestones/M2/BODY-OWNER.md): actual bounded body capture into detached memory records, private shared C02 leases, cancellation/retirement and retained charges while cleanup is incomplete or uncertain. No peer, raw-framing proof, engine transaction or dial/forward operation; Draft qualification remains open. |
| Normal stop/restart history source | [Durable normal settlement](docs/milestones/M2/NORMAL-CLEAN-SETTLEMENT.md) joins the same supervisor’s actual terminal/close path to C at the same burned generation. No automatic restart, supervisor-loss repair or timing pass; operational gates remain false. |
| External inspector ownership | [Selected architecture](docs/architecture/adr-0011-inspector-owner-containment.md) and [private C11 controller](internal/inspectorowner/README.md): retained whole-child envelope, once-claimed diagnostic intents and 32 independently frozen synthetic traces. Native launcher, privilege reduction, process/descriptor proof and mandatory four-second qualification remain absent; Draft126's validation pause stays. |
| Inherited Stop/retirement connection | [Private control source](docs/milestones/M2/CONTROL-RETIREMENT.md): canonical one-shot S Stop → actual bodyowner Stop/Retire → matching admission-only ACK. Failed/uncertain endpoints remain owned; no authenticated launch/channel constructor, process reclamation, ready/allow verdict or native timing proof. |
| Actual companion, CRS, HTTP/verified HTTPS routing | [Lab guide](research/coraza/LAB-PROXY.md); [163 ordinary /42 path/three load/seven startup controls](research/native/lab-concurrency-observations.json). Small synthetic corpus, not full OWASP coverage. |
| TLS passthrough and SNI/Host binding | [29-case native matrix](research/native/tls-passthrough-observations.json), [scoped design](docs/milestones/M1/TLS-PASSTHROUGH.md). Close-only HTTP/1.1; startup-only certificate inputs. |
| Local sender containment | [44-case/four-phase native matrix](research/native/sender-containment-observations.json), [PF design and rollback](docs/milestones/M1/SENDER-CONTAINMENT.md). Conditional on active PF and loopback filtering; fresh IPv4 data connections only. |
| Explicit client identity and body ownership | [Native component/CLI receipts](research/native/client-identity-observations.json), [scoped design](docs/milestones/M1/CLIENT-IDENTITY.md). Default-off PROXY source selection requires companion TLS and an external PF sender boundary; inspected bodies are detached before asynchronous forwarding and expired responses reject with 502. |
| Local backend isolation | [Native distinct-user bypass/effect receipts](research/native/backend-isolation-observations.json), [scoped policy](docs/milestones/M1/BACKEND-ISOLATION.md). Separate PF policies restrict two owned backend ports to the lab companion UID; root/allowed-UID compromise and remote backend network policy remain outside scope. |
| Request trailer enforcement (native qualification blocked) | [Scoped repair and wire design](docs/milestones/M1/REQUEST-WIRE.md), [retained host failures](research/native/request-wire-host-failure.json), [failed native run](research/native/request-wire-native-failure.json). Host TLS checks pass; native build/163 engine cases pass, but three legacy post-reload responses fail before the new wire matrix executes. |
| Transport diagnostics (host tooling) | [Focused helper/admission checks](research/coraza/transport-diagnostic-observations.json) and [durable phase checkpoints](docs/milestones/M1/NATIVE-ENGINE.md#ordinary-run-checkpoint-packet). Fixed error classes, timings, sampled health counts and run states preserve failure detail. Native integration is unexecuted; the retained reload failure remains unexplained. |
| Existing connector comparison | [Configured Caddy TLS/server/reverse-proxy](research/native/configured-caddy-observations.json), [API/rule-pool findings](research/connector/README.md), [comparison](docs/research/connector-comparison.md). No complete parity or runtime selection. |
| Dependencies and advisories | [Review](docs/research/dependency-review.md), [compatible remediation](research/native/dependency-remediation-observations.json). Companion source scans have no findings; Caddy retains CEL package-only and deprecated OpenPGP module-only adoption blockers. |

## Build and verify

The current [ordinary component build and execution](research/native/lab-file-input-observations.json) passes on OpenBSD: eighteen lifecycle parents/twelve subtests plus five owned-file input parents/nineteen subtests. Inputs are checked through the opened descriptor; invalid bounds and read/stat/close failures reject without usable bytes. Both binaries compile and run as UID 32767 with matching output/installed/executed hashes. Earlier [lifecycle build success](research/native/lifecycle-native-build-observations.json), [cross-built execution](research/native/lifecycle-component-observations.json) and [build timeout](research/native/lifecycle-native-build-failure.json) retain their original source and scope. Complete WAF/traffic/profile qualification remains pending for this changed runtime.

Read [CONTRIBUTING](CONTRIBUTING.md), [agent instructions](AGENTS.md) and the active [M1 PRD](docs/milestones/M1/PRD.md), [EDD](docs/milestones/M1/EDD.md) and [test design](docs/milestones/M1/TDD.md). Use signed Conventional Commits, author DCO sign-offs, `codex/` branches and open PRs. Checks run locally; GitHub Actions, runners and hosted success publishers are prohibited.

```sh
make tools hooks
make research-tools
make verify
make contract-race contract-fuzz
make research-test research-cross
make research-advisories
```

Private engine and connector source exports now use fixed tar/gzip metadata and verified atomic publication. [Host export receipts](research/native/source-export-host-observations.json) retain byte-identical independent exports of both modules; this does not establish reproducible executables or native qualification.

The [cleanup/finalization batch](research/native/cleanup-finalization-observations.json) adds atomic supervisor receipts, independent process/group and integrity checks, and failed-publication handling. All 146 local checks and one unchanged 54-record ordinary native repeat pass; host fault controls and native normal-exit evidence remain separate from full WAF qualification.

The [authenticated stock baseline](research/native/official-baseline-observations.json) was installed into a new owned disk from verified official media. Seven installed binary/key hashes match release-set bytes, and a fresh snapshot passes the same 54 ordinary records, offline patch applicability/reboot/access and teardown gates. All 159 host checks pass. This new lineage applies to the explicitly selected component profile; inherited evidence retains its original assumptions. See the [scoped design](docs/milestones/M1/OFFICIAL-BASELINE.md).

Host checks and cross-builds are tooling evidence only. Disposable native experiments require the [reviewed OpenBSD profile](docs/milestones/M1/NATIVE-ENGINE.md):

| Command | Owned native experiment |
| --- | --- |
| `make research-native-official-lifecycle` | Exclusive ordinary component repeat on the authenticated stock baseline; source-build and other official-baseline profiles are refused. |
| `make research-native-lifecycle` | Exclusive ordinary lifecycle component tests on owned OpenBSD; host-cross-built binaries, no application/WAF/traffic/PF execution. |
| `make research-native-lifecycle-build` | Exclusive offline native component build and exact ordinary test selection; reserved build/verification budget, no application/WAF/traffic/PF execution. |
| `make research-native-lab` | Offline native fixture/checker/CLI compilation and legacy TLS-at-relayd routing/reload/load controls. |
| `make research-native-tls` | Native compilation, legacy controls and companion TLS passthrough/authority matrix. |
| `make research-native-sender` | All TLS controls plus PF UID containment, invalid replacement, rollback and verified static PF restoration. |
| `make research-native-identity` | Prior controls plus actual Coraza identity/context/body components and a separate enabled CLI/PF matrix. |
| `make research-native-backends` | Prior identity controls plus restricted backend ports, foreign-user attack attempts, independent effects and rollback. |
| `make research-native-request-wire` | Candidate complete prior profile plus direct/relayd wire tests; currently blocked by retained legacy composition failure. |
| `make research-configured-caddy` | Separate native connector compilation and configured Caddy comparison. |

Each experiment owns and tears down its VM, sockets, daemons and synthetic TLS assets. Never point it at a live gateway, storage or application. Raw keys, source/vendor inventories and logs stay ignored; shared observations retain source/tree/input/output hashes. [Native evidence index](research/native/README.md) preserves earlier scopes, failed HTTP pipelines, half-close effects, unsafe checker behavior and the initial cold-build timeout. Later passing profiles do not reclassify those results; plain-TERM attribution remains [#69](https://github.com/gonz0w/aegvium/issues/69).

The [Bootweave appliance requirements](docs/milestones/M2/BOOTWEAVE-APPLIANCE-PROFILE.md) target prospective OpenBSD 8.0 installation, minimal setup and required logging/monitoring. Production installer integration is not delivered; the closed 7.9 private builder and historical evidence are retained.

## Adoption and project structure

Still open: selected trust/privilege/startup policy, product client-identity policy, certificate distribution/rotation, supported persistent/streaming protocols, full CRS/application tuning, measured resource/soak budgets, complete candidate provenance/acceptance and distribution obligations. The new stock baseline establishes selected installed-file lineage; historical inherited-image lineage remains unproven. Local UID containment excludes root/PF administrators and compromised allowed-UID processes. No live deployment, service enablement or release is implied by research.

[Selected M2 boundary](docs/architecture/adr-0010-frontend-key-mandatory-inspector.md) keeps public endpoint private-key custody at the Vectivium frontend and mandatory series inspection separate. [M2-H1/1](docs/milestones/M2/FRONTEND-INSPECTOR-CONTRACT.md) defines the first source contract; Vectivium still rejects required WAF until integration and acceptance exist. The [historical M1 ingress ADR](docs/architecture/adr-0001-ingress-inspection.md) retains relayd/companion/Caddy comparison evidence. A future Traefik/Caddy-like relayd control plane may reuse the boundary; no reusable API or separate connector repository is selected. CrowdSec remains an optional later behavioral layer.

BootWeave owns the generic installation builder and its extension contract. Aegvium owns its future payload/runtime policy; no speculative installer schema is defined.

Track work in the [private Project](https://github.com/users/gonz0w/projects/5), [roadmap](docs/milestones/github-roadmap-index.md) and [GitHub workflow](docs/engineering/github-workflow.md). Start with [product requirements](docs/product/PRD.md), [baseline architecture](docs/architecture/baseline.md) and [stack research](docs/research/stack.md).
