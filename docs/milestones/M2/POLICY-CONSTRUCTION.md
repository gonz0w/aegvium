# Aegvium private pinned policy construction — frozen source slice

Base ef17033a40e925bdfbc5c0e10f25031230c85dcc, initially clean. Source-only under
ADR0011/0012, coordinator R3 and M2 PRD/EDD/TDD. No actual engine execution,
adapter activation, credentials, networking, process signals or native effects.

M2 EDD requires bounded operation/generation IDs, fixed errors/counts/candidate
hashes and separate client/backend-effect observations. WAF-05 requires redacted
audit evidence and detection/enforcement distinction. This slice does not close
M2-07 or replace those obligations with a no-output logger: it constructs an
inert engine profile, preserves bounded correlation/generation/profile identity
in existing outcomes and marks the profile OnUnqualified/NoBackendAttempt.
Export/retention/exhaustion and actual forwarding/response effects remain open.
No rule message, URI, header, body, client address or MatchedRule text is logged.

## Connected implementation

- Add one private startup guard connected to a tagged real Coraza constructor.
  It attempts construction once per process; every failure burns that attempt.
  Returned partial factory/closer resources remain held, never closed speculatively
  or retried. External S owns eventual process reclamation; no shutdown proof.
- Constructor has no caller policy/FS/log path parameters. Use only the pinned
  embedded CRS4.25.0 FS and Coraza3.8.1 APIs; no research HTTP middleware.
- Fixed include order: recommended base, CRS setup, CRS rules, final explicit
  On, request-body access On, body/memory4097, Reject, response-body access Off,
  audit Off, private no-output writer and debug level0. Config also binds body
  access/limit/memory and debug Noop. Outer admitted-body4096 remains unchanged.
- Private no-output writer implements the actual AuditLogWriter API. Init/Write/
  Close are stateless no-I/O; never inspect payload/config/formatter or retain it.
  Real builder registers the fixed private writer once inside the startup guard.
  NewWAF always initializes a writer even with audit Off, hence this explicit
  resource-free writer instead of relying on defaults. Error callback is no-op.
- Require nonnil factory/closer and positive bounded rule count. Actual tagged
  builder binds the real WAFCloser/WAFWithRules capabilities. Generic startup
  guard is private; synthetic tests intercept construction, never NewWAF.
  RuleCount is uint32 diagnostic data, admitted range1..65535, never a memory
  or effective-policy proof. Error or panic consumes the attempt with one fixed
  error; known partial objects and unknown acquisition remain held for S.
- Successful private construction attaches a fixed profile digest (module pins
  plus exact directives), rule count and intended OnUnqualified identity to the
  existing engine owner. Every engine outcome preserves its bounded request ID,
  generation, profile identity and NoBackendAttempt; InspectionComplete and
  Recorded remain false. A digest is source identity, not effective-policy proof.
- Actual constructor file is behind an explicit source-build tag and compiled
  only with the retained graph. No production entrypoint/bootstrap calls it.
  Default tests retain API-only imports and never run actual Coraza/CRS init.
  The constructor additionally requires the supported `no_fs_access` build tag;
  embedded rules remain readable but Coraza's native temporary-directory probe
  is excluded. This is a source-build restriction, not a live security setting
  change or qualified resource/OS confinement claim.

## Frozen independent expectations, before code

| ID | Fixed condition | Required result |
| --- | --- | --- |
| P01 | Construct via fake once, then call again/copied guard | Builder count1; same sole owner is not returned again; later call refuses; no second ledger/WAF. |
| P02 | Fake returns error/nil factory/nil closer/zero or invalid count | No owner; bounded fixed error only; attempt consumed; supplied partial resources retained; no Close/retry or replacement. |
| P03 | Constructor blocks while second caller arrives | Second refuses, no queued constructor/second builder; explicit fake release and both callers join in cleanup. |
| P04 | Exact policy literals | Last overrides On/access4097/memory4097/Reject/responseOff/auditOff/private writer/debug0; no caller directives/FS/path injection or DetectionOnly-effective claim. |
| P05 | Audit payload/formatter/config contain access traps | Writer Init/Write/Close return with zero trap method calls, zero retained payload, no callbacks/I/O; nil payload accepted without dereference. |
| P06 | Prepared fake owner runs existing transaction lifecycle | Same lease/gate semantics; outcome request ID/generation/profile pin/rule count/OnUnqualified/NoBackendAttempt match fixed synthetic values; InspectionComplete=Recorded=false. No raw fields/payload added. |
| P07 | Failed startup after engine creation/capability mismatch | Partial engine reference stays in one startup slot; no speculative WAF.Close or cache/resource release claim. |
| P08 | Constructor panic before/after retaining a known partial | Fixed error/no panic text; one consumed attempt, no retry/Close; known partial still held, unknown acquisition not declared reclaimed. |
| P09 | Prepared owner receives missing/mismatched policy pin | Refuse before body transfer/factory; caller still owns inbound/source; no authentication claim from an equal pin. |

## Exact proposed checks

Independent review freezes this packet before code, then checks actual fixture
graph before execution. Memory-only fake/intercepted constructor, actual API
writer doubles and existing fake transaction tests only. Every held fake has
unconditional release plus explicit caller/job join; no test listeners, OS child
fixtures, signals, credentials, engine constructor or policy execution.

Focused default bodyowner tests and selected TestPolicy/TestEngine race, each
-count=1/-timeout60s, GOMAXPROCS2/-p2, known retained Go1.27.2, private build cache,
GOPROXY/GOSUMDB off/local toolchain. Vet root API-only packages. Real constructor
and binding compile-only using retained research modfile/cache; never execute
that binary. Mandatory make check secrets/commit source-hygiene hooks remain.
No full verify, advisory/security/native/engine/resource campaign. Missing cache
stops; no fetch/install/elevated retry. Old Aervium groups remain unresolved;
these fixtures require no census or global clearance.
