# M1 Test Design

Status: proposed; no native results yet.

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
