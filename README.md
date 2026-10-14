# Aegvium

Lean, auditable HTTP/HTTPS inspection appliance for a separate homelab VM behind EdgeWall. BSD-3-Clause; independent of the OpenBSD project.

Private repository: [gonz0w/aegvium](https://github.com/gonz0w/aegvium).

Status: repository foundation, proposed architecture and authorized engine research, native execution repeats, an offline native source build and a bounded connected relayd fixture. No WAF appliance, full native qualification or installer exists yet.

Current recommendation: [proposed TCP/TLS ingress and inspection ADR](docs/architecture/adr-0001-ingress-inspection.md), with a [pinned existing-connector source comparison](docs/research/connector-comparison.md). Native Caddy comparison, trusted sender/TLS authority, supported protocol/resources and lineage remain adoption gates; no runtime mode is selected.

Candidate flow: client → EdgeWall → relayd (TLS) → local Coraza inspection proxy with OWASP CRS → explicitly configured backend. The connector and body handling require native evidence before adoption. CrowdSec is an optional later behavioral layer, not the inline WAF engine.

BootWeave will build installation media when its generic extension contract is ready. This repository owns WAF payloads and runtime policy; no speculative installer schema is defined.

Start with [requirements](docs/product/PRD.md), [architecture](docs/architecture/baseline.md), [M1 design](docs/milestones/M1/EDD.md), [test design](docs/milestones/M1/TDD.md), [research](docs/research/stack.md), and [contributing](CONTRIBUTING.md).

Run `make tools hooks` then `make verify`. Checks run locally, with no GitHub Actions or runners. Host checks do not establish OpenBSD support.

Track work in the [private Project](https://github.com/users/gonz0w/projects/5), [roadmap index](docs/milestones/github-roadmap-index.md), and [GitHub workflow](docs/engineering/github-workflow.md). The [Coraza spike](research/coraza/README.md) exercises synthetic request semantics; `make research-test` and `make research-cross` are separate research gates.

The research module includes pinned CRS smoke tests and [dependency/advisory review](docs/research/dependency-review.md). Run `make research-tools` before research commands; `make research-audit` queries the Go advisory database. [Native engine design](docs/milestones/M1/NATIVE-ENGINE.md) and [observed execution receipts](research/native/README.md) include separate cross-build execution and native source-build observations; connector qualification remains open.

Offline native engine compilation is now observed: [native source-build receipts](research/native/build-observations.json) preserve the initial timeout and fresh successful build with all 13 smoke cases. Connector and appliance acceptance remain separate.

The first [connected relayd/Coraza experiment](research/relayd/README.md) passed ten plain-HTTP guest-only cases, including inspection loss/recovery and direct-control comparison. TLS, trust/parser qualification and connector adoption remain open.

The subsequent [framing comparison](docs/milestones/M1/RELAYD-FRAMING.md) retained a failed relayd pipeline expectation (403 then EOF versus direct 403/200). Nineteen other connected cases passed; pipelining and broader parser qualification remain unresolved.

The [reuse diagnostics](docs/milestones/M1/RELAYD-REUSE.md) observed serialized requests passing through relayd while both tested pipelines failed. Backend counts are retained on failure; the cause and supported connection profile remain unresolved.

The [idle-time comparison](docs/milestones/M1/RELAYD-IDLE.md) delayed pipeline EOF without restoring second-request arrivals. A longer inspection idle timeout alone did not fix the tested relayd pipelines.

The [inspection stream trace](docs/milestones/M1/RELAYD-STREAM.md) recorded only the first request's bytes in failed relayd pipelines, while direct pipelines and serialized controls consumed both. Socket buffering and exact relayd handling remain unresolved.

The [buffer wake control](docs/milestones/M1/RELAYD-BUFFER.md) let the second request through after extra client input. It supports a buffered-read hypothesis; baseline failures and safe repair/profile selection remain unresolved.

The [official release-source comparison](docs/milestones/M1/RELAYD-SOURCE.md) authenticates the 7.9 source archive and finds the same callback condition in its static control flow. Installed binary attribution and a safe repair remain separate gates.

The [stock TCP relay control](docs/milestones/M1/RELAYD-TCP.md) passed the tested pipelines without wake input, but its recovery POST failed after readiness. The full native comparison remains failed at 42/47; connector adoption remains open.

The [recovery follow-up](docs/milestones/M1/RELAYD-RECOVERY.md) traced the prior TCP recovery failure to premature inspection cleanup in the test fixture. Parent-owned inspection passed TCP recovery and six additional controls; the full native suite remains failed at 49/53 on existing HTTP pipelines.

The [stock TCP/TLS study](docs/milestones/M1/RELAYD-TLS.md) passed ten new HTTPS cases, including intact pipelines, strict client certificate checks and inspection loss/recovery. The complete native comparison remains failed at 59/63 on unchanged HTTP pipelines; trust policy and connector adoption remain open.

The [client-identity study](docs/milestones/M1/RELAYD-IDENTITY.md) identifies stock PROXY address output as a companion candidate, with separate readiness and sender-containment requirements. It adds source evidence and a proposed test matrix; receiver implementation and native trust qualification remain pending.

The [restricted PROXY v1 parser](docs/milestones/M1/PROXY-PARSER.md) passed 25 isolated parser cases alongside 20 engine cases on OpenBSD. Buffered application bytes were preserved; socket deadlines, sender trust and connected PROXY qualification remain pending.

The [PROXY connection adapter](docs/milestones/M1/PROXY-ADAPTER.md) passed deadline, closure and buffered-byte controls, including direct TCP in the owned OpenBSD guest (55 native cases total). Listener/readiness integration and sender authentication remain pending.

The [PROXY listener lifecycle](docs/milestones/M1/PROXY-LISTENER.md) passed bounded pending-handshake, shutdown, readiness-gating and direct TCP controls (63 ordinary native cases). HTTP health wiring, actual relayd PROXY identity and sender containment remain pending.

The [readiness and checker packet](docs/milestones/M1/PROXY-READINESS.md) records 90 ordinary native cases and the original failed stock-script contract: conventional positive error exits can report UP. The separate signal/account comparison is retained; plain TERM wait-status attribution remains open.

The [connected readiness study](docs/milestones/M1/READINESS-WIRING.md) now includes the first down/ready/recovery/receiver-close matrix and four health faults with a ready inspection path. Silent, malformed, redirect and refused health caused eventual table DOWN and blocked fresh post-DOWN ingress. All four requests sent during the observed UP polling windows still forwarded. Three health-mode recoveries passed; in-flight/keepalive behavior, sender containment, actual rule readiness and runtime adoption remain unqualified. Implementation, tests, native receipts and findings are delivered together.

The [checker-replacement study](docs/milestones/M1/READINESS-WIRING.md#native-checker-replacement-result) confirms that a controlled exit-2 replacement can mark silent health UP and permit inspected forwarding while the original helper returns 0. Missing checker produced DOWN; hash/owner/mode-verified restoration recovered the expected behavior. This is retained unsafe-contract evidence, not acceptance of that health policy.

[Fixture generation recovery](docs/milestones/M1/READINESS-WIRING.md#native-generation-recovery-result) now demonstrates fresh-request recovery after graceful Stop and an injected crash with relayd kept running. Three distinct processes started unready and recovered benign forwarding/denial; both process-absent DOWN gaps blocked fresh ingress. The crashed process retained a stale ready receipt. Persistent/in-flight behavior and runtime adoption remain open.

The [current native-build study](docs/milestones/M1/NATIVE-ENGINE.md#native-built-current-fixturechecker-result) compiled both the fixture and checker offline on OpenBSD, then passed ninety ordinary cases and the generation-recovery study with those exact outputs. Earlier cross-build and thirteen-case source-build evidence remains separate; connector distribution and appliance adoption remain open.

The [pinned CRS request corpus](docs/milestones/M1/CRS-REQUEST-CORPUS.md) now compares query, form, JSON and cookie inputs in enforcement and DetectionOnly. All twenty-four native samples matched host outcomes, alongside the prior ninety cases. The 51-file rule input hash gate passed. Full CRS regression, realistic application tuning and relayd wire comparison remain open.

The [bounded body admission experiment](docs/milestones/M1/BODY-ADMISSION.md) now compares a test-only size/media/encoding gate with pinned CRS middleware. Native body and header controls passed alongside the prior suite (148 cases total), including explicit read-error responses and preserved attack denial. The 128-byte cap is a research fixture choice; real transport and appliance policy remain open.

The [direct HTTP body transport experiment](docs/milestones/M1/BODY-HTTP-TRANSPORT.md) carries that unchanged gate onto fifteen owned HTTP/1.1 connections (163 native cases total). It records Go's length/coding normalization, parser rejection and source-Close errors separately from successful connection/server/listener cleanup. RelayD dual-parser comparison, persistent/concurrent traffic and appliance policy remain open.

That same outcome now includes [native OpenBSD compilation](research/native/body-http-native-build-observations.json) of the current engine and checker followed by all 163 passing cases. The earlier cross-built receipts remain separate; both runs agree on the fifteen HTTP semantic observations.

The [consolidated relayd body comparison](docs/milestones/M1/RELAYD-BODY-COMPARISON.md) now measures fifteen inputs in direct, HTTP relay and TCP relay arms (45 separate native cases plus the unchanged 163 ordinary leaves). Both relay modes preserved benign body bytes and blocked SQL/script forwarding. HTTP rejection behavior differed in four controls, including a conflicting-length client timeout; TCP differed only for the truncated-body control. TCP is the candidate for further research; no mode or appliance policy is adopted.

The [upload-lifecycle follow-up](docs/milestones/M1/RELAYD-UPLOAD-LIFECYCLE.md) preserves those 45 controls and adds 21 identical-input comparisons (66 connected cases plus 163 ordinary leaves). Successful client write shutdown changed relayd responses; one half-closed benign request reached the backend without a client response in the retained first run. The fresh run passed corrected admission, while original failure/native compilation and offline replay remain separate. Neither response absence nor write shutdown establishes rejection or safe retry; mode adoption remains open.
