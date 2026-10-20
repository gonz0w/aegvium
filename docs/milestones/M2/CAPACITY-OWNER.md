# M2-C02: inert shared capacity ownership

Status: **Proposed exact source design and Test Design for independent review.**
Date: 2026-10-20. Refs #19/#22/#23, M2-A01 A-SLOTS/A-LIFE/A-STOP/A-NODIAL.
This is a separate ordinary source prerequisite, not full A01a or runtime adoption.
The validation pause and paused pair-descriptor draft #125 remain unchanged.

## Requirements and boundary

One future process owner must share admission accounting across generations:
at most four request leases and eight accepted-plus-reserved outbound socket
slots, without a waiting queue. Account for incoming sockets before authentication,
then reserve the outbound slot and request slot together. Failed acquisition
cannot free, transfer or partially consume an existing reservation. Retirement
prevents new leases while keeping old resources charged until explicitly closed.

Implement internal/capacity as pure bookkeeping with standard-library errors,
strings and sync only. There is no socket, connection, context callback, TLS,
request parser, peer, engine, body, backend, route, allow verdict or forwarding
operation. A socket slot is only a numeric reservation, not an opened socket.
No lease or status is permission to inspect or forward. Later adapters must own
actual close/join/cancellation and the atomic attempt barrier independently.

This component does not prove that runtime code uses a single process-wide owner,
closes real sockets or obeys the accounting. The later startup owner must supply
one shared instance; separate New calls create separate inert models. Control/
health connections and their as-yet unmeasured budgets are not data slots here.
The four/eight limits are existing A01 source bounds, not measured capacity/RSS.

## Exact API and state

New() returns an initialized *Owner. Nil/zero owners are unavailable.
Owner.NewGeneration(token string) returns *Generation: exactly 32 lowercase hex
bytes are cloned; no history, uniqueness or freshness is inferred. No generation
map/history is retained. Invalid receiver/token returns ErrInput before checking
ErrStopped. NewGeneration on an otherwise valid stopped owner returns ErrStopped.
NewGeneration, ReserveInbound and TryRequest each return (pointer, error).

Owner.ReserveInbound() returns *Inbound after charging one of eight shared socket
slots. A stopped owner returns ErrStopped; full socket count returns ErrCapacity.
Nil/zero owner returns ErrInput before either state check.
This is a reservation before a future accept/handshake, never actual network I/O.
An actual accept failure would require the future caller to close its reservation.

Generation.TryRequest(in *Inbound) returns *Lease. The inbound must belong to the
same initialized owner. Under one owner mutex, evaluate: ErrStopped, ErrRetired,
ErrClosed for a closed inbound, ErrTransferred for an already leased inbound,
then ErrCapacity if four requests are held or no eighth socket slot remains.
Success transfers inbound ownership into the lease and charges one request plus
one reserved outbound socket together. No partial success; failure leaves the
inbound charged to its original owner. Invalid receiver/nil/zero/foreign-owner
arguments return ErrInput before locking or state evaluation. All errors are
fixed, contain no input, and every constructor/acquisition refusal returns nil.

Inbound.Close() returns error and is idempotent after closing a free reservation. A transferred
reservation returns ErrTransferred and stays charged; only its owning Lease can
release it. Nil/zero inbound returns ErrInput. This prevents accidental early
slot reuse when an old caller retains the inbound pointer.
After Lease.Close closes that inbound, Inbound.Close returns nil and TryRequest
returns ErrClosed; closed state is checked before transferred state.

Lease.Close() returns no value and is idempotent (including nil/zero): under the owner mutex it closes
the transferred inbound, releases exactly two socket slots and one request,
and decrements its generation's pending count exactly once. The reserved outbound
slot is private and cannot be independently released or transferred.

Generation.Retire() returns no value, is idempotent, has no callback or waiting loop and prevents
future TryRequest success after it returns. Existing leases remain charged; it
does not assert cancellation, connection revocation or absence of effects.
Owner.Stop() returns no value, is idempotent, prevents new generations/inbound slots/request leases
after return and leaves every existing reservation charged until explicit close.
Nil/zero Retire/Stop are inert. Close remains usable after Stop/Retire.

Owner.Usage() returns a value {Requests, Sockets int}; nil/zero returns zero.
Generation.Pending() returns the number of its outstanding request leases;
nil/zero returns zero. Lease.Generation() returns its cloned generation token
even after close, or empty on nil/zero. These are accounting observations, not
readiness, authentication, successful shutdown or a reusable permission check.
There is no Reset, restart, resize, arbitrary counter update or consumable token.

All methods are concurrent-safe. Mutex sections perform bounded local accounting
only, with no I/O, user callback or application wait queue. Caller-created
generation objects are not retained by Owner; live lease references remain
bounded by four and inbound reservations by eight. Runtime parent allocations,
real sockets and total process memory remain later integration obligations.

## Independent Test Design before source

An independent reviewer first supplies literal finite operation traces with
expected errors, request/socket totals and per-generation pending counts. Cover
four leases/eight slots, eight pre-auth inbound reservations, ninth-slot and
outbound-reservation refusal, shared contention across generations, foreign
owners, duplicate transfer, early inbound close, release after retirement/stop,
idempotent close, exact generation validation and nil/zero state.

Go tests replay each trace and compare every step, preserving counts on every
failed operation. Add deterministic concurrent acquisition barriers and repeated
close/retire/stop races; successes must never exceed four requests/eight sockets,
and after explicit closure all counts are zero. Test cloned generation strings,
value-copy observations and that no independent reset/release path exists.
Use bounded in-memory work only; no timer sleeps, listener or generated identity.

Run repository make verify plus focused go test/vet/race and ordinary staticcheck
for internal/capacity through the existing isolated Go wrapper and owned portable
check launcher. These are ordinary source/bookkeeping checks, not affected
security/traffic/native campaigns. The base requestctx ordinary tests remain in
make verify; paused pairmodel is absent. Do not invoke research, advisory, TLS or
attack suites. Required product security/advisory/native checks remain explicitly
unrun while their pause applies; the PR remains Draft until applicable gates can
be completed.
Do not bypass normal commit signing/DCO/hooks or change any security setting.
The normal unchanged pre-commit source secret-hygiene hook applies to this
isolated unpaused source worktree. It does not validate the paused draft or run
any affected traffic/advisory campaign; no scanner is run by this document.

## Remaining product work

Complete A01a still needs actual peer authentication, bounded body/transaction
ownership, original-deadline cancellation and a concrete recording coordinator.
Pair history/preflight, strict original-wire framing, engine/CRS adoption,
mandatory backend role/containment, loss detection and native/resource proof
remain open. No M2-H1/2 contract is adopted. Parsed header counts still cannot
prove strict raw admission. No traffic, deployment, credentials or services change.
