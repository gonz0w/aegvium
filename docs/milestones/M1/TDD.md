# M1 Test Design

Status: full M1 qualification pending; bounded engine execution observations exist.

| Requirement | Required disposable native evidence |
| --- | --- |
| WAF-01/02 | TLS and benign GET/POST to synthetic backend; CRS attack corpus with backend receipt assertions |
| WAF-03 | Unknown Host/SNI, direct listener/backend access, engine crash, invalid rules and interrupted reload; zero uninspected forwards |
| WAF-04 | Oversized/chunked/compressed bodies, slow clients, malformed framing, concurrent load, disk/log exhaustion; bounded behavior |
| WAF-05 | Spoofed forwarding headers, trusted peer identity, redacted credentials/cookies/query data |
| WAF-06 | Privilege boundary, invalid config rejected, pinned build, rules update failure and known-good recovery |
| WAF-07/08 | Deferred until installer and behavioral integration designs exist |

Include response-phase inspection if supported, false-positive samples, rule exclusions and detection/enforcement distinction. Request smuggling tests must exercise both ingress and inspection parsers. Record exact candidate/base/tree, environment, commands, outcomes and limitations. Agree measured latency/throughput/memory budgets before performance acceptance. Cross-compilation is not native execution evidence.

## First engine slice (M1-02)

Host fixtures assert permitted backend receipt/body bytes, denied zero receipts with expected status, explicit-log DetectionOnly matches with intentional forwarding, invalid config rejection and reader-error zero receipts. Characterize response error status separately from desired appliance behavior. OpenBSD cross-build is tooling evidence only; repeat natively after lab admission. See retained [observations](../../research/coraza-engine.md).

## Native source-build slice

The [native packet](NATIVE-ENGINE.md) defines an offline native compile followed by all admitted engine/CRS cases. Host failures must reject compiler drift, incomplete/root build receipts and failed transfer/compile before any test admission. Native receipts identify the compiler, source archive, unprivileged compiler UID and newly built binary; guest deadline, patch/reboot, source/base and teardown gates remain mandatory. The cross-built binary is a separate control and cannot satisfy native build acceptance.

The [explicit-error adapter packet](ERROR-ADAPTER.md) scopes seven additional in-memory completion cases; current fixture admission requires 20 named cases. Older source-build and execution receipts retain their original 13-case scope.

The [connected relayd packet](RELAYD-TRAFFIC.md) separately admits ten guest-only traffic cases against a direct-inspection control, listener loss and recovery. Host skips remain skips; ordinary native admission still selects 20 engine cases. Connected results and source-build evidence remain distinct.

The [framing extension](RELAYD-FRAMING.md) adds ten raw-wire direct/relayd cases, expanding current connected admission to twenty. Its small matrix and historical ten-case happy-path comparison remain distinct from full #16 qualification.

The [reuse diagnostic packet](RELAYD-REUSE.md) added four cases (connected admission at that slice: twenty-four) and receipt observations retained on response failures. Historical twenty-case framing failure remains unchanged.

The [idle-time packet](RELAYD-IDLE.md) added six comparison cases (connected admission at that slice: thirty), retaining anonymous inspection events and unchanged baseline expectations.

The [stream diagnostic packet](RELAYD-STREAM.md) retains thirty connected leaves and adds bounded Read-boundary metrics correlated with anonymous inspection connections; host recorder tests do not qualify connected traffic.

The [buffered-request wake packet](RELAYD-BUFFER.md) adds four diagnostic controls (current connected admission: thirty-four); prior failed expectations remain unchanged and discovery-source inference is separate from installed provenance.

The [TCP control packet](RELAYD-TCP.md) adds thirteen leaves alongside unchanged HTTP expectations (current connected admission: forty-seven). It compares plaintext transport-only relayd and retains original failures.

The [recovery diagnostic](RELAYD-RECOVERY.md) adds six raw HEAD/POST controls and passive recovery snapshots (current connected admission: fifty-three), retaining all existing assertions.

The [TLS termination packet](RELAYD-TLS.md) adds ten guest-only HTTPS/client-verification leaves (current connected admission: sixty-three) and ephemeral public-certificate/cleanup admission; prior failures remain required.

The [identity feasibility study](RELAYD-IDENTITY.md) pins static source findings and proposes the next prefix/trust/readiness matrix. It adds no native cases; connected admission remains sixty-three. Receiver implementation requires a concrete bounded packet before execution.

The [prefix parser packet](PROXY-PARSER.md) extends ordinary native admission to 45 leaves (20 engine plus 25 isolated parser cases). Connected admission remains 63; no listener, deadline or trust boundary is implemented by the parser.

The [connection handoff packet](PROXY-ADAPTER.md) adds eight in-memory net.Conn and two owned-guest TCP leaves (ordinary native admission: 55). Host TCP skips remain skips; relayd-connected admission remains 63.

The [listener lifecycle packet](PROXY-LISTENER.md) adds six synthetic-listener and two owned-guest TCP leaves (ordinary native admission: 63). This set is distinct from the unchanged 63 stock-relayd connected leaves.

The [connected readiness packet](READINESS-WIRING.md) separately admits the five-phase readiness matrix and eight-phase/four-fault study, alongside ninety ordinary native leaves. Require exact generation/phase/UID/hash/counter gates, direct checker outcomes, table state, polling-window witnesses, post-DOWN zero-delta ingress and independent data-ready controls. Current observations include four forwarded UP-window requests; they do not establish instantaneous or existing-connection revocation. Broader parser/trust/rule and adoption gates remain open; fresh process recovery is measured separately below.

The same packet adds seven checker-replacement phases with a ready inspection path: missing launch error/DOWN, controlled positive-error UP plus actual forwarding despite original-helper zero, and verified original restoration/recovery. Admit these as unsafe-contract characterization, not correct health policy or uninspected bypass. Keep controlled-script UID, actual helper results, health, state, per-request deltas and restoration/cleanup gates independent.

The [generation recovery packet](READINESS-WIRING.md#fixture-generation-recovery-packet) separately admits three startup-unready generations with fresh nonces/counters, two process-absent DOWN gaps, recovery forwarding/denial and final cleanup. Stop/exit gates apply to two graceful generations; the intentionally SIGKILLed second fixture retains a stale ready/uncleaned receipt and actual shell wait without direct kernel-status attribution. Native ordinary admission remains ninety; the interrupted fixture is not a passing Go test. Host rebind and exact receipt mutation checks complement owned OpenBSD evidence. Existing connections and broad trust/rule/adoption gates remain open.

The [current native-build packet](NATIVE-ENGINE.md#current-native-built-fixture-and-checker-packet) requires offline unprivileged compilation of fixture plus checker, exact native output/installed/ordinary/connected hashes and builder/execution UID consistency before admitting ninety ordinary leaves and the existing generation study. Native compilation is observed separately from cross-build controls. Historical build attempts retain their original counts and outcomes; no broad connector/adoption completion follows.

The [CRS request corpus packet](CRS-REQUEST-CORPUS.md) expands current ordinary admission to 114 leaves, adding twenty-four query/form/JSON/cookie cases across On/DetectionOnly. Require exact native bundle-file hashes, matched attack-family IDs/phases, status/backend counts and admitted input preservation. The native matrix matches host observations; earlier ninety-case native-built and four-case smoke results retain their scopes. This small synthetic set is separate from upstream CRS regression, realistic false positives and relayd wire/response/trust qualification.

The [bounded body admission packet](BODY-ADMISSION.md) adds twenty-six baseline/gated observations plus eight header/length controls, expanding ordinary admission to 148 leaves. Require explicit no-backend gate rejection, actual-byte cap+1 witnesses, original-source Close-call counts and preserved admitted bytes; retain middleware's implicit-200 read-error characterization and inherited rule denials. Host/native matrices agree. Constructed requests do not qualify wire framing, stalled I/O, concurrency/Close-error behavior, transport cleanup or appliance body policy.

The [direct HTTP transport packet](BODY-HTTP-TRANSPORT.md) adds fifteen real owned loopback connections (163 ordinary native leaves total). Exact admission checks parser rejection, normalized lengths/coding, source reads and Close error class, attack/no-backend outcomes and independent connection/server/listener cleanup. Host/native semantic rows match with observational accepted-connection byte counts excluded. Identical CL and CL+TE acceptance, malformed-source Close error and stalled-source timeout remain explicit characterization. Fresh close-only connections and laboratory guards leave relayd dual parsing, persistent/concurrent traffic and policy adoption open.

The [consolidated relayd body comparison](RELAYD-BODY-COMPARISON.md) separately admits 45 direct/HTTP/TCP cases alongside the unchanged 163 ordinary leaves. Preserve exact direct baseline, sent-input identity, benign bytes, attack/no-backend outcomes, normalized inspection view, source ownership/error classes and server/daemon/VM cleanup. HTTP's conflicting-length client timeout is characterization, not successful bounded rejection; truncated-body differences remain open. Mode compatibility assessment, implementation/tests and receipts share one PR under existing #16. No persistent/TLS/trust or appliance acceptance is implied.
