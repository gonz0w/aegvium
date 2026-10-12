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
