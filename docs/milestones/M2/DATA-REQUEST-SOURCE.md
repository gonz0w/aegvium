# Owned DATA request source path

2026-10-22; approved source implementation, base6d4ae5b. Actual network,
credential/TLS, engine/native, image/root and activation effects remain held.
Default entries refuse and the source network-qualification constant stays false.
This is the connected AGPAIR2/M2-H1/3 implementation, not a new profile or proof.

Standalone operation and optional integrations are required acceptance. This
source has no Vectivium/EdgeWall/Aervium import, process or API dependency. It
accepts explicitly configured authenticated frontend DNS roles through the same
documented protocol. Vectivium is one optional adapter; a third-party adapter
must meet the identical provenance/framing/security obligations. A general
plug-in framework is not introduced. Turnkey standalone installation and actual
non-suite adapter conformance remain undelivered/unqualified, not deferred polish.

## Concrete ownership

The fixed startup owner binds CONTROL and DATA exactly from its inherited common
descriptor, once. Listener construction is below the false qualification gate.
CONTROL keeps its separate two-seat ledger and Q104 operation. The engine owner
reserves a shared C02 inbound before DATA Accept and upgrades it to the same
four-request/eight-socket lease before handshake/read. No application queue.
The sole DATA accept actor reserves one of two prefix slots before Accept;
its existing job worker releases that slot only when authentication/read returns.
There are at most two concurrent prefix protocols, four jobs with their existing
two workers each, one DATA accept actor, one CONTROL actor and the inherited
Stop reader. Saturated acceptance waits without an accepted application or new
reservation; kernel backlog and library/runtime worker tails require qualification.

Only the actual startup-owned receiver creates a sealed per-connection session.
It performs TLS1.3/h1 authentication on its own connection, checks current exact
frontend/server roles, parses one bounded raw internal request, and binds G/P,
route/SNI/Host and four public connection facts. Internal raw duplicate CL/TE
rejection cannot prove original-public rejection before HAProxy normalization.
That independent strict original-wire gate remains mandatory on Vectivium.

The job receives copied metadata/body data from that same session; no supplied
Peer/state/boolean or detached record is an admission issuer. Only the private
job worker calls its bound session's one backend exchange after all Coraza
request phases and the immutable source-owned policy check. There is no public
allow/verdict object, backend callback or lease release/reacquisition.

The session retains inbound, actual dial-in-progress and returned backend handles
on every outcome. Actual fixed numeric TLS backend uses explicit roots/name,
no proxy/discovery/retry/redirect, one request and response. Reserved context
never enters backend bytes. Request method/target/public header values/body
remain byte-identical. Response is bounded, fixed-length and close-only; no
response-body inspection guarantee. Failure after the attempt barrier means
possibly effected, including response failure; never retry.

The existing two job workers now own DATA work and cancellation/Close. Network
work finishes, the Close protocol joins actual endpoint calls, then the SAME
transaction logs/closes serially, then the lease releases only on certain cleanup.
A stuck call/Close retains charges and a strong transaction reference. Close failure stops admission;
panic/unknown ownership is sticky unsafe: no new phase/dial/write or retry, and
unknown handles stay retained for S rather than receiving speculative cleanup.
Stop/retire blocks unstarted attempts;
an already committed attempt may have an effect. S alone owns process retirement.
No stop request, ACK, cancellation or returned worker is reclamation proof.
The job/cache wait also refuses retained pre-job failures; successful local
joining still cannot prove physical process/network reclamation.

## Bounded source clocks and inputs

Keep4096 public/5120 internal header bytes,64 total fields,4096 request/response
body bytes,2048 target bytes, four requests/eight DATA sockets and separate
two-seat CONTROL. No extra outbound connection or per-I/O watcher goroutine.
Read/handshake uses at most the original accepted-at+2s/read and+1s/handshake;
forwarding at most2s with1s dial/handshake/header stages; response-write at most4s.
The accepted-at+8s source parent bounds their sum; earlier stop/parent deadlines
win and no stage extends that parent. This is a conservative implementation
ceiling, not measured capacity or a change to the mandatory4s shutdown target.
Actual memory/CPU/FD/queue/tail and native timing remain unqualified.
The fixed child exec-surviving source promise set now includes inet for these
numeric operations, retaining no dns/proc/exec/id/fdpass after exec. No pledge
operation ran. Nonroot listener permissions, exact syscall compatibility,
independent backend isolation and all installed/native acceptance still gate use.

## Frozen failure expectations before implementation

All fixtures are public synthetic bytes and intercepted OS boundaries, with
unconditional barrier release and join. No actual TLS, keys, socket/listener,
engine constructor, subject process, signals or native operations are tested.

| Case | Required independent outcome |
| --- | --- |
| D01 | Phase held: U=(1,2), backend/log/Close0; backend held: same charge/tx, log/Close0. |
| D02 | Response/network Close held: same charge/tx, log/Close0; after certain join log/txClose1 then U=(0,0). |
| D03 | Denied/failed phase: backend0; certain network cleanup before serial transaction Close and release. |
| D04 | Cancel/retire before attempt: backend0. After attempt starts: possible effect; no second call. |
| D05 | Dial/read/write/Close failure, failed response after attempt: fixed outcomes, no retry; uncertain cleanup retains U=(1,2). |
| D06 | Panic/nil/invalid transport result: unsafe/retained, no new engine/network call; never refund uncertain handles. |
| D07 | During a stuck backend/cleanup, retirement never WAF.Close; one WAF.Close only after every actual job/reference joins. |
| D08 | Raw internal duplicate CL/CL+TE/folding/extra fields/length cap/truncation refuse before backend; parser counts preserved raw bytes. Fixed failure classes preserve400 syntax,413 body,421 authority,431 header,403 role and503 unavailable without echoing input. |
| D09 | Independent request bytes match engine inputs and sole backend bytes; reserved/forwarding fields never reach application. |
| D10 | H1/3 local socket8443 versus route443 stays distinct; no internal-hop/dummy substitution. |
| D11 | Four charged jobs fill eight slots; fifth refuses without queue/worker, copies cannot transfer/retry exchange. |
| D12 | Default/source qualification refusal invokes no listener, TLS, credential or engine construction. |

Use direct cached focused Go tests (60s), scoped vet/cross-builds and ordinary
repository hooks. Existing fixture or native grants are not reused. Actual
credential, frontend observation/raw-wire, backend containment, installed-custody,
resource and4s shutdown acceptance remain unrun; Draft126 stays Draft.
