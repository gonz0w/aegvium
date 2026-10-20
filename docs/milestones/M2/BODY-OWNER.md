# A01a body capture and Close ownership

Status: **Exact source design and Test Design for independent review.**
Date: 2026-10-20. Refs #19/#22/#23, A-BODY/A-LIFE/A-SLOTS/A-STOP/A-NODIAL.
This extends C02 with actual body I/O, not a complete A01a coordinator.
Draft #125 and affected security/advisory/native validation remain paused.

## Useful boundary

Implement internal/bodyowner using only the root module and Go standard library.
Own a supplied io.ReadCloser from successful admission through read/Close
completion; capture at most 4096 body bytes into a detached memory-only Record.
Use one private C02 capacity owner across generations: four admitted captures,
eight inbound-plus-reserved outbound slots, immediate refusal and no work queue.
An outbound slot is a reservation only; no socket is opened. Future process
integration must share one instance; independent New calls are independent.

There is no peer constructor, TLS, HTTP parser, engine/transaction, allow verdict,
backend, dial, retry or forwarding API. Record means only bytes read from the
supplied body. EOF and declared length do not prove original framing, trailing
headers, connection identity or authentication. No metadata authority is created.
The real engine API/adoption review and same-connection transport/framing binding
remain separate blockers for complete A01a. Do not invent a transaction interface.

## Public handles and admission

New() returns *Owner. Owner.NewGeneration(token) uses C02's exact token grammar;
Owner.ReserveInbound() charges before a future accept/authentication. Generation,
Inbound, Job and Owner are copyable handles to private shared state. Nil/zero
handles reject acquisition with ErrInput. Inbound.Close returns C02 errors and
releases only an untransferred reservation, including after Stop/Retire. All
public errors are fixed and contain no source error text or body bytes.

Generation.Begin(ctx, inbound, source, declaredLength) returns (*Job, error).
Require a non-nil context with an existing deadline, non-nil usable source,
length 0..4096 and an inbound from this owner. Invalid arguments return ErrInput
first; then check owner stopped, generation retired, ctx.Err, and finally C02's
closed/transferred/capacity acquisition rules. Every failure returns nil, invokes
neither Read nor Close and leaves source and inbound with the caller. The caller
must not use or close source after success; concurrent Read and Close must be
supported by that source. Typed nil implementations and panicking methods are
outside the io.ReadCloser implementation contract of this component.

Observe the original Context.Deadline, Done and Err outside the owner mutex;
these methods may execute caller code. Snapshot its absolute deadline and Done
channel. After successful admission, create a private standard-library deadline
context from context.Background at that same absolute deadline. The existing
Close worker observes the original Done channel as well as private cancellation
and read completion, so no extra watcher or caller AfterFunc is installed. Do
not propagate caller context Values, expose the private context or derive from
the caller parent (whose custom cancellation hooks could execute caller code).
Before each Read and at publication check the snapshotted Done channel, private
cancellation and absolute deadline, with no caller Context methods under a lock.

On success the private lease owns the inbound, one request and the reserved
outbound slot. Never extend the original deadline. At Begin, before each Read
and at publication compare it with the clock; expiry is DeadlineExceeded even
if ctx.Err's timer propagation has not yet caught up. This cannot prove provenance:
the future receiver must supply the original two-second request-read context
or its earlier parent deadline, not start a fresh budget at Begin. Requiring a
deadline bounds eligibility/observation, not arbitrary I/O completion.

## Actual reads, Close and bounded ownership

Each admitted capture owns two goroutines: one read worker and one Close worker,
at most eight unfinished I/O ownership protocols across four captures. A worker's
terminal signal/accounting precedes its final goroutine return instructions;
no finite total live-goroutine scheduling/stack bound is inferred from that tail.
Both unfinished protocols are retained by their
Job/Owner until their completion protocol finishes; no detached per-wait worker,
user callback under a mutex or periodic polling is used. Read and Close calls
run outside the owner mutex. No method assumes context cancellation interrupts
an arbitrary io.ReadCloser. A permanently stuck source can exhaust the owner.

The read worker allocates one 4097-byte buffer (cap+1), requests only its remaining
space and checks the derived context before each Read. Valid nonzero data with
EOF is accepted as data then EOF; other read errors are fixed ReadError. Negative
or too-large returned counts are ReadError. One hundred consecutive (0,nil)
returns are NoProgress; any progress resets that counter. More than 4096 bytes,
or EOF at a length different from declaredLength, is LengthError. Filling 4096
bytes alone is insufficient: observe EOF or a 4097th byte. No unlimited ReadAll,
retry, source-error formatting or supplied callback is used.
For a single Read return, precedence is invalid count, non-EOF ReadError,
cap/EOF LengthError, then NoProgress. Thus 4097 bytes plus a non-EOF error is
ReadError. EOF is the exact io.EOF sentinel, not an arbitrary wrapped error.
Stopping before a Read because the context/deadline is unavailable leaves
ReadFailure=None; Canceled carries that condition. A source-returned non-EOF
context error is ReadError. A completed CloseFailed job freezes Canceled=true
and Stopped=true because immediate owner Stop cancels its derived context.

The Close worker waits for read completion OR derived cancellation, then calls
source.Close exactly once. Thus cancellation attempts Close concurrently with a
blocked Read. Close may itself block or return before Read. It waits for read
completion before finalization. A fixed completion channel signals that both
I/O calls are finished and no worker performs further I/O/accounting work.
The read worker has no further work after its completion signal.

Under the owner mutex, finalization checks cancellation, retirement and Stop at
the only publication point, after both calls complete. A clean exact-length read,
successful Close and still-current context/generation/owner publish one private
Record{Generation, Body}. All other paths publish no record. Retirement/Stop
serialize with this point: after either returns, that generation/owner cannot
publish new records; earlier records remain inert historical bytes. Cancellation
cannot revoke a record published before it became observable to this component.

Only after both I/O calls complete AND Close succeeds does finalization release
the lease, even for failed reads/cancelled/retired/stopped captures. A blocked
Read or Close remains charged. A Close error is uncertain resource cleanup:
retain the source and lease permanently, stop the entire owner, cancel its other
jobs and reject all later admission. Do not retry Close or forget the failed job.
Store CloseFailed and stop/cancel immediately when Close returns an error, even
if Read is still blocked; pending Outcome then has CloseFailed=true, Joined=false.
Other jobs still release only on their own successful cleanup. No finite-cleanup,
engine-free, complete shutdown or process-memory qualification is claimed.

## Observation

Job.Outcome() returns a detached Outcome: Joined, Recorded, Canceled, Retired,
Stopped, CloseFailed booleans, ReadFailure (None, ReadError, LengthError or
NoProgress), and Record (zero unless Recorded). Joined means the Read/Close calls
and their ownership protocol completed, not that Close succeeded. All failure
flags survive together; one failure does not erase another. Before completion,
Joined and Recorded are false; cancellation/retirement/stop flags reflect the
current state. After completion flags are frozen. Body copies never alias owned
buffers; mutating returned records cannot change subsequent observations.

Job.Wait(observerContext) waits on the same completion channel, or returns the
current Outcome and observerContext.Err. A nil observer context/zero Job returns
ErrInput. Observer cancellation does not cancel the capture or release anything.
If completion is also ready, prefer the completed outcome. There is no implicit
deadline extension, worker creation or assertion that pending cleanup succeeded.

Generation.Retire and Owner.Stop are idempotent, mark state and collect the at
most four private cancellation functions under the mutex, then invoke them
outside it. The marks prevent later admission/publication even before cancellation
delivery. Close-error poisoning uses the same protocol. They do not wait for I/O
or release held slots. Owner.Usage delegates numeric C02 usage;
free inbound reservations remain caller-owned until explicitly closed. No Reset,
forced release or externally reachable capacity Lease exists. Completed clean
jobs leave the bounded active registry; caller-held historical Job records are
caller-owned memory, not an unbounded owner history. Close-failed jobs stay held.

## Independent vectors before Go

Freeze this design and independent finite literal vectors before implementation.
Cover exact lengths 0/1/4096 and cap+1, early EOF, bytes+EOF, read errors with data,
invalid counts, bounded no-progress/reset, exact length without EOF, Close error,
blocked Read/Close, cancellation/retirement/Stop at I/O/publication boundaries,
observer cancellation, retained charges and maximum cross-generation contention.
Test all public handle copies and nil/zero/foreign/invalid/unbounded contexts;
every acquisition failure preserves caller ownership. Independently supplied
barrier tests must release every synthetic blocking source before test exit.
Never leave a test goroutine blocked, use sleep-based success or real networking.

Use synthetic finite io.ReadCloser implementations, fixed error classes and
bounded contexts. No attack corpus, authentication, certificates or raw-framing
validation is added. Required ordinary checks: make verify, focused test/vet/race
and staticcheck for bodyowner plus capacity through the owned portable launcher
and this worktree's private caches. Preserve prior C02 reports and the complete
193-member manifest. New source/evidence reviews bind this extended snapshot;
old passing evidence does not qualify the new code. All affected qualification
gates remain unrun and Draft #126 remains Draft.
