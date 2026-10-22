# ADR0012: connect bounded body ownership to the pinned transaction API

2026-10-22. Status: source-only private integration under ADR0011; no runtime
activation, policy qualification, authentication authority or native acceptance.

The bounded body owner previously released its private C02 lease when source
Read/Close joined. Consuming its detached Record and acquiring another lease would
leave an ownership gap. The private transaction continuation now retains that
same job and lease through connection/URI/SNI/header/body mapping, state/error
checks, serial logging and transaction Close. The existing standalone body API
is preserved. One private constructor binds one startup generation and factory;
there is no public/default provider, runtime caller or forwarding operation.

The contract is the independently reviewed coordinator lifetime proposal r3
(retained outside Git before implementation), now constrained by the adopted
[sole-root-owner architecture](adr-0011-inspector-owner-containment.md). Frozen
failure expectations are in [the source packet](../milestones/M2/TRANSACTION-LIFETIME.md).
Creation/transaction Close/cache Close share one gate; Close error poisons before
unlock because the real Coraza Close returns transactions to its pool even on
error. No failed object is inspected or retried. Canceled/retired/stopped work
retains its charge until actual cleanup joins; unknown cleanup remains charged.
Every getter also has a start barrier, and no engine call runs under owner.mu.

The root module now pins the already selected Coraza v3.8.1 API dependency.
Default code imports only types, collection and experimental plugintypes (and
their API-only dependencies); no constructor or package init runs an engine.
The Apache-2.0 upstream license/notices remain in the dependency, without copying
upstream implementation into this repository. Distribution must retain those
notices. Local comparison found all577 module source files byte-identical to the
retained archive; archive Hash1 equals the existing research go.sum/ziphash:
`h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=`. No fetch/install occurred.

| Pinned source | SHA256 |
| --- | --- |
| types/transaction.go | 8d61be09315fe4ff040cc77bc2ce75ab14284e983d82324a9c8225f262cef615 |
| experimental/plugins/plugintypes/transaction.go | fd42f4c5a729a2406d6a424ca73cfd66497f5ededaa9ef63c38939a3466b6f4a |
| collection/collection.go | feb956f549f4d3b6e3436ba75d2b427b4593d54f867b29ee430593705f0429f3 |
| waf.go | 94c273b6ae92d7d72933d38291a2d81d6955677cf253571d55dfcb2238faf3b6 |

The compile-only `aegvium_binding_compile` assertion checks the actual WAF and
experimental API using the retained research dependency graph; that tagged test
binary must never execute. It is outside ordinary fake-only test selection.
This does not approve the full product engine graph, fresh SBOM/advisory/license
qualification or distribution. No dependency is fetched to make a check pass.

`InspectionComplete` and `Recorded` are always false on the engine continuation.
Correct phase/zero-error observations alone cannot establish immutable On versus
DetectionOnly, exact CRS/processor policy, exclusive4097-byte engine limit for
outer4096-byte bodies, or bounded redacted audit writer ownership. Those profile
preparation/qualification steps remain necessary before a successful inspection
predicate can exist. Metadata bounds are parsed-input checks, not strict raw
framing proof. TLS sender authentication and backend isolation remain separate.

WAF.Close nil means cache release only. It is not engine/writer shutdown, OS
resource reclamation or the required four-second shutdown proof. Production
supervisor bindings, generation lineage/history, transport resource joins and
native containment qualification remain open. Draft126's affected validation
pause, all historical failures and the no-activation boundary remain unchanged.
