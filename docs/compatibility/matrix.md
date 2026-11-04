# Compatibility and evidence

| Capability | Current evidence | Remaining gate |
| --- | --- | --- |
| Foundation tools | Host make verify | Does not qualify runtime |
| Coraza v3.8.1 synthetic engine | Authorized research spike | See source-bound PR result; native execution pending |
| relayd integration | Upstream documentation | Native connector/parser/TLS/identity comparison |
| OWASP CRS v4.25.0 | Four host-only smoke cases passed | Native full corpus and benign application regressions |
| CrowdSec | OpenBSD current ports source contains v1.8.1 | Chosen-release packages, remediation and privacy review |
| BootWeave install | Intended builder | Accepted external contract and disposable install evidence |
| Personal use | None | Combined native stability and explicit acceptance |

Research now requires pinned Go 1.27.2; prior Go 1.27.0 runs remain historical. See [dependency review](../research/dependency-review.md) for initial advisories and the fresh patched scan.


### Scoped in-memory model (2026-10-20)

[A01a-P/1](../milestones/M2/A01a-pair-model.md) implements only the inert AGPAIR1
binary grammar, detached bytes and structural equality. Ordinary portable codec
checks do not establish TLS identity, freshness, readiness or traffic behavior.
The advisory/security/traffic pause remains effective; those gates are unpassed.
