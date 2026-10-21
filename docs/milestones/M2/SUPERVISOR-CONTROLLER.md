# M2-S01/1: isolated Inspector Owner lifecycle controller

Status: Private source contract independently reviewed before C implementation.
The freeze manifest records its exact bytes and the independent literal tests;
later implementation evidence is tracked separately, without rewriting this
contract's pre-implementation history. Review was content-only; file hashes and
the absence of C at freeze are checked by the source owner.
2026-10-21; architecture selected by the maintainer at 10:38:37 UTC in reply
Sentinel_faa3228bb28c819191cf06592504efb2 to question
Sentinel_7eda926be3c88191b98371beaff7398a. The approved architecture is a small
privileged sole launcher/stopper/reaper of one unprivileged inspector, retained
reservations until proved cleanup and no replacement before fresh validated
paired startup. Four-second shutdown remains mandatory and unqualified.

This first source slice implements the private single-event-loop **controller**,
not the native launcher, signal sender, wait collector or authenticated IPC.
There is no executable entrypoint, syscall binding, PID, credential, file, socket,
engine graph, callback or runtime-ready/allow API. Inputs below are synthetic
trusted-adapter observations; production observation/launch constructors do not
exist. No test success proves a child, descriptor or generation actually owned.
The native adapter, no-descendant/no-export proof, fixed privilege drop, held
executable, private IPC and durable startup/history are separate mandatory gates.
Draft126's affected security/advisory/native validation pause stays unchanged.

## Private C API and storage

Use internal/inspectorowner/controller.h and controller.c, C11 standard library
types only. No heap, I/O, callback, thread, process or signal calls. The module
holds one private static state for the process. No reset/destroy/replacement
constructor; repeated prepare refuses even after failed prepare or reclamation.
Opaque state is never exposed; getter returns a detached value view. Copying or
mutating a view cannot copy/release the private envelope. Calls are serialized
by the future sole S event loop; this API makes no concurrent-caller guarantee.
All times, including last/T0 and the 100/3000/4000 boundaries, are integer
milliseconds. `stopped` means a stop was requested, never wait-stopped or dead.
Initially generation is empty, phase Empty, all flags/envelopes zero, terminal
Unknown, signal result None and target NotStopping. Invalid first prepare changes
only phase to Refused; valid prepare copies generation and sets Reserved/held
with envelopes 4/8, leaving every other initial field unchanged.

`int aeg_owner_prepare(const char *generation, size_t length, int64_t now_ms)`
claims the one initialization attempt first. First call requires nonnull exactly
32 lowercase ASCII hex bytes and nonnegative initial elapsed-ms time. It copies
the generation, reserves the whole 4-request / 8-data-socket envelope and enters
Reserved with no known child. Bad input commits Refused, no envelope, returns
Input; a second call returns State and changes nothing. Syntax does not prove
pair agreement, uniqueness, consumption or authority. No generation is generated.

`int aeg_owner_step(enum aeg_owner_event event, int64_t now_ms,
                    enum aeg_owner_intent *intent)` returns OK, Input or State.
Null intent or an out-of-range event returns Input before any state/clock change.
For a valid operation set *intent=None, check legal phase first, then sample the
supplied time and apply its trusted event. Illegal phase returns State unchanged.
Clock faults are recorded in the view while valid ownership observations still
apply; they are not a return error that can discard a real terminal receipt.
Only TakeStop/TakeKill may return a non-None intent. An intent is private once-
claimed diagnostic work for the missing native adapter, not a transferable OS
capability or caller-selected target. The source never executes it.

`struct aeg_owner_view aeg_owner_get_view(void)` returns the fields below.
Integer constants are frozen by the independent packet before C. No setter.

| View field | Meaning |
|---|---|
| phase | Empty, Refused, Reserved, Active, Stopping, TerminalHeld, UnknownHeld or Reclaimed |
| generation | Copied canonical32 bytes and trailing NUL, or empty if absent |
| held | Conservative external envelope; request_envelope=held?4:0 and socket_envelope=held?8:0 |
| known_child | Continuously owned unreaped direct-child slot; no PID exposed |
| stopped, stop_claimed, retired_ack, kill_claimed | One stop epoch, once-claimed control/escalation and qualified timely ack; no clean-completion meanings |
| protocol_closed | Trusted observation that S's own control protocol resources are actually closed, not remote EOF |
| terminal | Unknown, NoChildProved, NormalExit or SignalExit; NoChildProved is not a wait/reap receipt |
| clock_fault, identity_fault, unsafe_fault | Sticky fault classifications; none manufactures physical cleanup |
| signal_result | None, Sent, Missing or Denied; no result releases capacity or proves signal caused death |
| target | NotStopping, Pending, Met, Missed or Unverifiable; clock/identity failure cannot qualify elapsed time |

## Events and exact transitions

Events have these names, in this numeric order starting at1: Owned, NoChild,
LaunchUnknown, Stop, TakeStop, Ack, Tick, Unsafe, TakeKill, WaitNone,
WaitStopped, WaitInterrupted, WaitNormal, WaitSignal, WaitLost, WaitError,
SignalSent, SignalMissing, SignalDenied, Closed, ControlFault. Intent values are
None=0, SendStop=1, SendKill=2. Errors OK=0, Input=1, State=2. Phase/terminal/
target/signal-result enums use the order in their view rows, starting at0.

Legal phases: Owned/NoChild/LaunchUnknown only Reserved. Wait events only a known
child (Active/Stopping), except duplicate waits after terminal/reclaimed refuse
State. Ack requires known child, stopped, stop_claimed and not protocol_closed.
Signal result requires known child and kill_claimed with no prior signal result.
Closed is allowed in any initialized held phase, idempotently. TakeStop/TakeKill,
Stop/Tick/Unsafe/ControlFault are allowed in Reserved/Active/Stopping/UnknownHeld/
TerminalHeld. A Take intent without its predicate is OK/None. Empty/Refused refuse
every step. Reclaimed permits idempotent Stop/Tick only, OK/None and no clock or
view mutation; every other step refuses State. No operation resurrects held state.

| Event | Observation/action |
|---|---|
| Owned | Bind the already reserved slot to the missing adapter's proved own child; Active unless a stop/fault already exists, then Stopping. No actual creation/proof here. |
| NoChild | Missing adapter proved no child was created. Record NoChildProved, TerminalHeld until protocol closure. No fabricated wait receipt. |
| LaunchUnknown | Identity becomes permanently unknown; UnknownHeld, stopped, identity_fault, target Unverifiable unless already Missed. No later bind/NoChild/terminal repair. |
| Stop | First valid sample sets T0; repeated Stop never resets it. Known child becomes Stopping. Reserved remains Reserved, retaining any launch reservation. |
| TakeStop | Claim SendStop once only if stopped, known child, protocol open, not kill_claimed, no clock/identity fault and kill is not due. No duplicated sends. |
| Ack | Only elapsed<100ms, no clock/identity fault: retired_ack=true. Equality/late ack is OK but does not set it or undo due/claimed escalation. |
| Tick | Time/deadline evaluation only. |
| Unsafe or ControlFault | Sticky unsafe_fault; request Stop if absent and force escalation eligibility. ControlFault is not Closed or reclamation. |
| TakeKill | Claim SendKill once only if stopped, continuously known child, no identity fault, not already kill_claimed and escalation due. Lost wait identity forbids a target. |
| WaitNone/Stopped/Interrupted | Nonterminal; retain the known child and envelope. Never infer cleanup from a stopped process or interruption. |
| WaitNormal/WaitSignal | Consume one trusted terminal-child receipt, known_child=false, TerminalHeld; prevent every future signal. Preserve exact terminal kind even if escalation was requested. |
| WaitLost/WaitError | Without an owned terminal receipt, permanently identity_fault, known_child=false, UnknownHeld, stopped; target Unverifiable unless Missed. No signal/refund/replacement or later asserted terminal repair. |
| SignalSent/Missing/Denied | Store only the corresponding first result. No refund or automatic retry; Missing/Denied does not itself erase the continuously reserved child identity. |
| Closed | Record actual closure of S protocol resources. EOF alone must enter ControlFault instead. |

Sample valid nonnegative time under the sole state owner; require now>=last,
then update last. A negative/regressing value permanently sets clock_fault,
requests stop if absent (using last only as a diagnostic T0), and makes target
Unverifiable unless already Missed. Later good samples do not repair the fault.
When stopped and known child, escalation is due on unsafe_fault, clock_fault,
elapsed>=3000ms, or elapsed>=100ms without retired_ack. Use nonnegative checked
differences, never addition of deadlines; large int64 values must not overflow.
No clock can establish ownership. Identity faults permanently disable intents.
The clock sample precedes event application, including first Stop; a newly
requested Stop uses that accepted sample as T0. Deadline evaluation precedes
the event; reclamation evaluation follows it. No time is sampled on illegal
operations. Invalid event/null intent leaves the supplied intent untouched;
legal-enum operations set it to None even when phase refusal returns State.
LaunchUnknown/WaitLost/WaitError request Stop if absent using the same current
accepted sample (or retained last on clock failure), then classify identity loss.

For a valid clock and pending target, elapsed>=4000 makes Missed **before** the
current event; equality expires. Missed and Unverifiable cannot become Met later.
Clock/identity failure changes any non-Missed, non-final target to Unverifiable.
Stop without such a fault sets Pending. Engine/control unsafe alone does not
invalidate the clock; physical reclamation may still meet the time target.

After each accepted event, when terminal!=Unknown AND protocol_closed, set
held=false and phase=Reclaimed exactly once. If stopped and target Pending, mark
Met only when the good current elapsed<4000; otherwise retain Missed/Unverifiable.
If no Stop occurred, leave NotStopping. Known process reclamation is not tx.Close,
C02 Release, audit flush, successful inspection or clean request completion.
The dead child ledger is retired, not reset. Old backend effects remain possible.

## Required independent Test Design before C

An independent reviewer authors literal JSON operation traces and expected views/
intents/errors from this contract without importing/running product source. Freeze
and hash them with this contract before C. Include clean drain, ack99/100,
unacked escalation100, drain2999/3000, completion3999/4000, retained target miss,
wait stopped/interrupted/lost/error, signal success/missing/denied and no retry,
no signal after reap, early/unexpected terminal exit, Closed versus control EOF,
stop during Reserved, launch unknown versus proven NoChild, second prepare after
every terminal/failure, detached view mutation, invalid input/phase, clock poison
and near-INT64_MAX time arithmetic. Every scripted process has finite step/input/
output caps. Host test executables exit normally; no actual subjects, signals,
fork/wait/network/engine/credentials or native runs.
Each trace uses a fresh ordinary host harness invocation for fresh static state;
there is no product reset hook. The 128-byte input cap applies to each operation
command line, not the JSON expectations file. At most 64 operations per trace
and 32 traces are admitted by the replay test, with a five-second harness limit.

The root source will replay retained literals, add focused boundary properties,
compile the private C core on the connected Mac and run required ordinary repo
checks through the bounded owned runner. Compile options/compiler identity and
source/fixture hashes are evidence, not an OpenBSD binary or native acceptance.
No security/advisory/traffic/TLS/native campaign is run or bypassed. Keep Draft126.

Native parent/child construction, irreversible UID/GID drop, actual signal/wait/
descriptor/no-descendant proof, authenticated inherited control, exact fresh pair
history/launch exclusivity and the mandatory four-second operating-profile proof
remain absent. Stop requests and successful signals never become reclamation.
