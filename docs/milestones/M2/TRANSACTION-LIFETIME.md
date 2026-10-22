# Aegvium connected transaction source slice — frozen expectations

2026-10-22. Base: Draft126 worktree `aegvium-no-dial-lifetime`,
`e26cafd040ce7eff516b88fbafd0ac30dc4f06c0`, initially clean.

Contract: retained `aegvium-coordinator-design-r3.md` sections 1–4 and Q01–Q22;
repository `docs/architecture/adr-0011-inspector-owner-containment.md` and
`docs/milestones/M2/ADAPTER-EDD.md`. R3's external-containment choice is resolved
by ADR0011, not by this implementation. Its exact four-second requirement remains
unqualified. This packet adopts no runtime policy or security authority.

## Concrete source connection

- Reuse bodyowner's actual bounded Read/Close and private C02 lease. Its existing
  standalone API and recording behavior remain compatible.
- A private engine-owner constructor binds one factory, one generation and the
  same ledger. It has no public/default provider or production bootstrap caller.
  A second generation always refuses, including after clean retirement.
- Private begin takes copied bounded connection/URI/SNI/header metadata; the
  body remains owned by the existing job. This input is data, never peer or
  framing authority. No socket, listener, transport, backend or forward operation.
  Metadata reuses C01 bounds: at most64 fields,128-byte token names,4096-byte
  ASCII/tab values and4096 aggregate public request-line/header bytes;
  origin-form target1..2048 bytes with valid percent triplets/no fragment;
  lowercase DNS SNI1..253, labels1..63; correlation ID1..64; canonical IPv4
  connection addresses and numeric1..65535 ports. HTTP/1.1 GET/HEAD/POST only.
  Host/length/media and stripped-metadata checks match C01 but prove no raw wire.
- Use the pinned real Coraza `types.Transaction` interface. Serially map
  ProcessConnection, ProcessURI (including query once), SetServerName, every
  supplied header including Host, ProcessRequestHeaders, WriteRequestBody and
  ProcessRequestBody. Require exact write count, no interruption, enabled body
  access, expected LastPhase and zero inbound/body/processor/URL/argument-error
  flags through the retained experimental TransactionVariables capability.
- Nil API errors do not establish policy effectiveness. InspectionComplete and
  Recorded remain false for this private engine path until the immutable On/
  Reject/CRS/4097-byte and bounded writer profile is prepared and qualified.
- Hold one private lease continuously through body, creation, every phase,
  ProcessLogging and transaction.Close. No detached body Record/reacquisition.
- Same-WAF creation, transaction.Close and WAF.Close share one exclusion gate.
  Creation TryLock refuses busy without queueing. Existing charged workers may
  wait for cleanup. Calls run outside the owner mutex. Close error poisons the
  engine before gate unlock; the returned/possibly pooled object is never reused.
- Global stop permits clean known transaction Close but no new phases/logging.
  Panic/nil factory means unsafe: no new engine API calls, charges retained.
  Cancellation/retirement prevent later commitments but never revoke calls
  already committed. Logging is at most once after an ordinarily returned phase
  in active mode, then serial Close. Cancellation alone does not skip that cleanup.
  Metadata setters are not a qualifying inspection phase. Only an ordinarily
  returned ProcessRequestHeaders/ProcessRequestBody call permits logging. Missing
  experimental capability/nil Variables before headers closes without logging.
- Retirement waits for all job/reference cleanup before one WAF.Close; its nil
  return means cache release only. Uncertainty blocks that Close and replacement.

## Frozen independent literal expectations (before implementation)

U is (request charges, slot charges). F/L/C/W are factory/log/txClose/WafClose
counts. Every fake transaction implements the actual pinned public interface;
embedding a nil interface for unused methods is acceptable only when the tests
assert those methods were not called. No generic closer-shaped engine substitute.

| ID | Controlled condition | Required observation |
| --- | --- | --- |
| E01 | Clean body, held request-body phase, then held Close | Phase U=(1,2), F=1,L=C=0. Close U=(1,2),F=L=C=1. After join U=(0,0), no recorded/inspection-complete/allow result. |
| E02 | Body Close held before engine | U=(1,2),F=L=C=0. Copied inbound.Close returns Transferred. No refund gap on transition to E01. |
| E03 | Cancel while phase held | Wait observer may return pending; U=(1,2),C=0. After release L=C=1, canceled/no record, U=(0,0). No concurrent Close. |
| E04 | Ordinary interruption, body write short/error, phase/variable error | Fixed bounded failure, no later inspection phase, no record; Active-mode L=C=1 and clean U=(0,0). |
| E05 | Factory held; another admitted job reaches creation | F stays1, second job reports EngineBusy without waiting/extra worker; only first U=(1,2) remains after second clean join. |
| E06 | Close held after simulated pool return, then returns error | During hold no later F. Poison before gate unlock; failed U=(1,2),C=1, no record, no later factory call or retry Close. |
| E07 | Body Close fixed error | F=L=C=0, stopped/uncertain, U=(1,2) retained even after read joins. |
| E08 | Nil/panic factory or phase/log/Close panic | Unsafe sticky, no subsequent engine API commitment, no record, U=(1,2) retained. All deliberately held fake calls are released/joined. |
| E09 | Retire before creation, and after factory commitment before first phase | First F=L=C=0. Second F=C=1,L=0. No new phase/record. Clean charge releases only after actual cleanup. |
| E10 | One generation active, retired, then cache released | Every second generation refuses. W=0 until all jobs joined and references zero; then W=1 maximum. Nil WAF.Close only cache-release marker. |
| E11 | Stop before cleanup logging commitment | No new factory/phase/log. Known serial Close can complete once and free only clean job. |
| E12 | Connection/URI/SNI/header/body mapping | Exact synthetic values and order, one URI pass, all fields once, same body bytes; LastPhase 1 then2 and all required flags checked. No errors/raw request content in outcomes. |

## Exact proposed check containment

No tests/builds run yet. Before executing, independent review must inspect the
finished fake fixture graph and confirm this scope. At most four owned job workers
and their existing bounded body workers; barriers have unconditional release plus
explicit join in cleanup. Tests use in-memory fixed synthetic values only, no
real engine constructors/methods, listeners/sockets, OS subprocess fixtures,
signals, credentials, security changes or native calls. Existing old Aervium
groups are not queried or acted upon. These fixtures need no shared-host clearance.

Use cached pinned source and retained known toolchain only, GOPROXY/GOSUMDB off,
GOTOOLCHAIN local, GOMAXPROCS=2, compilation -p=2. Focused fake-only bodyowner
tests have a 60-second Go deadline and selected race checks a separate 60-second
deadline; no full repository/research/native/advisory/security campaign.
Compile-only actual Coraza WAF compatibility assertion is never executed.
Module/cache provenance and license review precede adding exact checksum-pinned
API dependency; no network fetch or install. Any missing cache is a blocker,
not permission to download. No claimed passing make verify or native evidence.
