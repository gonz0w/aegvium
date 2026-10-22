# Aegvium inherited stop/retirement connection — pre-code freeze

Base a0823c17a0840280f335578da425cd5efc648ed4, clean. ADR0011's sole S owner,
S01 controller and real bodyowner.Stop are existing adopted source contracts.
This finite slice connects them; it adds no positive launch/history/FD issuer,
listener, key, backend, request allow, native operation or automatic replacement.

## Canonical one-epoch wire format

One fixed64-byte frame. Bytes0..7 ASCII `AGCTRL1\n`; byte8 opcode Stop=1 or
RetiredAck=2; bytes9..15 zero; bytes16..47 exactly32 lowercase ASCII hex generation
bytes; bytes48..55 unsigned big-endian epoch1; bytes56..63 zero. No timestamps,
PIDs, commands, request data, descriptor passing or optional fields. Other length,
magic/opcode/reserved/generation/epoch rejects. The native S clock alone owns T0.
No duplicate frame can create another epoch, ACK, readiness or allow authority.

C producer takes the existing controller's once-claimed SendStop intent and
current detached generation, producing canonical bytes only. It creates no FD or
native identity. The future authenticated sole-launch constructor must own the
actual inherited channel; frame syntax never authenticates an FD or caller.

I's private Go handler claims one control attempt per actual owner before I/O.
A valid generation with nil endpoint consumes the attempt and stops/retires with
a fixed Input fault; invalid generation touches no endpoint or other owner.
Copies/repeated calls refuse before touching a second stream. It reads exactly
one fixed frame with bounded empty-read handling, verifies exact generation and
Stop/epoch1, marks the actual owner stopped and generation retired, then writes
one matching ACK. It never waits for transactions/body/WAF.Close to produce ACK.
An ACK means only admission retirement; it excludes process reclamation, clean
request completion, generation readiness and allow. Extra/duplicate frames are
never processed after this one-shot session; no claim of detecting unread bytes.

Malformed/stale/short/error/panic I/O stops admission and retires generation but
emits no success ACK. Partial writes never justify another ACK/retry. Actual
request/slot charges remain governed by their existing join rules, not control
I/O. S's whole external envelope stays held until its separate terminal+local
protocol-close proof. I endpoint.Close is not S closure or terminal evidence.

Read/Write/Close happen outside owner.mu. Invalid counts, non-EOF errors,
truncated input, 100 consecutive empty operations fail with fixed classes only.
Close once after ordinary return; error/panic retains endpoint uncertainty.
Any Read/Write panic retains endpoint without attempting later I/O/Close. Stuck
I/O stays owned; no artificial cancellation/completion. No internal worker or
timeout goroutine. Future raw os.File binding is private/unactivated and asserts
no authentication; it must receive the actual sole-launch-owned endpoint later.

## Independent pre-code expectations

| ID | Controlled case | Literal obligation |
| --- | --- | --- |
| C01 | Valid Stop generation000..000, epoch1 | Exact64-byte ACK opcode2, same gen/epoch, all reserved zero; owner ReserveInbound refuses Stopped before first ACK byte. |
| C02 | Engine phase held while valid Stop received | U=(1,2) before/after ACK; no concurrent tx.Close, InspectionComplete/Recorded false. Release phase then serial cleanup joins under existing protocol. ACK never claims reclamation. |
| C03 | Wrong magic/opcode/reserved/uppercase/stale gen/epoch0 or2 | Fixed Frame fault, owner stopped/retired, zero ACK writes; no refund/replacement. |
| C04 | EOF before64; invalid read count; ordinary read error | Fixed Read fault, stop/retire, one ordinary Close; no ACK. Read panic instead keeps endpoint held, no Close. |
| C05 | Valid partial read/write chunks | One total64-byte read/ACK write, exact bytes; no duplicate ACK or body/lease transfer. Zero-progress bound100, then fixed error. |
| C06 | Partial ACK write then error/invalid count/panic | Stop already effective; AckWritten=false; no retry/new epoch. Ordinary path closes once; panic keeps endpoint without later calls. |
| C07 | Close blocks/errors/panics after ACK write | Admission remains stopped; request charges/endpoint stay owned until actual completion. ACK may be written, but error/panic is uncertainty, no physical cleanup proof or second Close. Every synthetic blocker releases+joins. |
| C08 | Second/copy invocation after success/failure, including while first Read blocks | Refuses before all Read/Write/Close on second endpoint. One control attempt/ACK maximum; release first blocker and explicitly join caller. |
| C09 | C controller stop intent absent/already consumed | No frame returned, no second stop claim/epoch. C producer golden Stop matches independently frozen exact bytes; no native subject/signal/wait. |

## Exact check scope

Freeze independent golden Stop/ACK bytes and malformed/partial literals before
source. Independent reviewer checks actual fixture graph before execution.
Go fixtures are memory-only actual-interface fake I/O plus existing engine fake
barriers; no listeners/credentials/process fixtures/actual engine calls. Every
held operation releases unconditionally and its caller/job/cache protocol joins.
C uses existing bounded normally exiting host harness pattern only: compiler
and a finite scripted byte/controller harness, no fork/wait/signals/subjects;
at most8 harness invocations,5s each, fixed input/output caps. Old Aerv groups
are neither queried nor acted on; no global clearance inferred.

Focused fake-only bodyowner tests/race -count1/-timeout60s, GOMAXPROCS2/-p2,
API-only vet; existing retained compiler/source only, offline Go cache; C test
only after specific process containment review. Ordinary content/redacted-secret
hooks. No full verify, real engine/policy/security/advisory/native campaign or
activation. Four-second shutdown and native FD/descendant/history proof stay open.

## Independent literal clarification, frozen before source

Stop, generation all ASCII zero, exact eight8-byte hex rows:

```text
41474354524c310a 0100000000000000 3030303030303030 3030303030303030
3030303030303030 3030303030303030 0000000000000001 0000000000000000
```

ACK changes only the second row to0200000000000000. These literals were supplied
independently, not generated by either production encoder. Exact64+EOF succeeds;
any non-EOF read error refuses, including with64 bytes. Exactly100 empty calls
fault,99 then progress succeeds and resets. Write64+error is NOT AckWritten.
C NULL output refuses before consuming intent; absent/claimed/late/fault intent
zeros output and returns no frame. Failed ordinary endpoint remains retained
even if local Close succeeds. At the original C01–C09 freeze, no S ACK receive/parser binding was in scope;
the later parent-authorized C10 source consumer below supersedes that boundary.

## C10 — independently frozen S admission-ACK consumer

Parent added this connected receiver before its implementation. Eligibility
before mutation/time sampling: held+known child+stopped+StopClaimed+open protocol,
no KillClaimed/clock/identity/unsafe fault and no consumed ACKattempt. Ineligible
returns State unchanged, including null/invalid input. Eligible attempt consumes
once before parsing. Require exactly64 canonical ACK opcode2/current generation/
epoch1/reserved0. Null/wrong length/any wrong byte returns Input and samples the
existing ControlFault; second attempt returns State with no event/time sample.
Valid bytes use existing Ack sampling then readback: accepted at elapsed0..99,
not at100 or later/negative/backward clock. Nonacceptance returns State and
ControlFault preserving target/clock evidence; at100 target remains Pending,
at4000 remains Missed. Good/bad/late duplicate never samples again. External4/8
envelope held, terminal Unknown, protocolClosed false. Native FD authentication,
owned read/wait/close and durable lineage remain missing; syntax grants no trust.

## Production source boundary and remaining constructor

`control_frame.c` connects only existing S intent/ACK transitions to fixed bytes.
`bodyowner/control.go` connects the same bytes to actual owner Stop+Retire and a
matching admission-only ACK. The private *os.File wrapper has no caller; neither
byte equality nor supplying an FD authenticates it. No C01 peer constructor,
receiver listener, engine initialization, backend call or launch exists here.
All request/body/transaction charges retain their existing cleanup/join rules.
The whole S envelope still requires actual owned terminal plus S-local closure.

Next indispensable launch/history design recommendation (not adopted here): one
root-owned exclusive S lock plus bounded durable consumed-generation journal;
sync consumption before child creation, burn failed launches, and refuse a new S
when the previous generation lacks proved terminal/descriptor cleanup. A lock
released by S death does not prove I died. Reconcile uncertain history through an
explicit cold operator procedure, not guessed PID adoption. Local storage cannot
prove nonrollbackability after snapshot rollback/live cloning; supporting those
would require a separate external witness and availability/trust commitment.
The concrete storage/commit/recovery contract still needs review/adoption before
positive source construction. Fixed held executable and irreversible identity/FD
construction then need source implementation and native proof. This slice does
not select a journal path/schema, installer extension, witness or recovery power.

Post-code independent correction: a previously accepted direct controller ACK
also makes the new consumer ineligible. Otherwise its sticky retired_ack flag
could misclassify this consumer's later call as fresh timely acceptance. The
source guard and one of the eight fresh C traces cover this path; the original
pre-code freeze is retained separately rather than backdated.
