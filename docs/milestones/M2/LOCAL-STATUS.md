# Local redacted inspection status

This source slice implements M2-07 basic outcomes inside the existing DATA owner.
It adds no listener, descriptor, file, credential, OS call, worker or privileged
actor. It does not enable either installed entrypoint or change resource ceilings.

The same DATA worker records one terminal event after its existing cleanup path
has returned and its final ownership result is known. A returned uncertain cleanup
can retain its transaction without calling transaction Close and is recorded as uncertain and its reservations remain held. A stuck call has no
terminal event: current active/retained jobs, request/socket charges and transaction
references remain visible instead. Reporting never joins, cancels, closes, releases,
resets or grants inspection/backend authority.

Each owner retains the last sixteen events in a fixed ring (at most 64 additional
logical bytes). Old events are overwritten, with a saturating overwrite counter;
there is no queue, flush or audit durability claim. Fixed classifications distinguish
input rejection, policy rejection, inspection error, no forwarding, a written response
and unknown backend outcome. Independent bits preserve possible backend effect,
response-written, cleanup certainty and cancellation/retirement/stop. No request ID,
generation, route, address, URI/query, header/body, rule text, error string or private
material enters a record. Aggregate counters also saturate rather than wrap.

`Owner.OperationalReport` and the production source engine's `OperationalReportSource`
return a bounded text copy of this actual state. Reports are capped at 4096 bytes;
qualification is always zero. Snapshots copy bounded fields under the owner lock and format only after unlocking.
They distinguish absent/active-source/cleanup-only/
unsafe engine state, stopped/retired state, active versus retained jobs, charged
requests/sockets, outstanding transactions and cache cleanup. An active source is
not readiness, authentication, full network health or native shutdown evidence.
The production wrapper separately identifies retained pre-job DATA ownership.

This is an in-process read-only source interface, not a delivered external health
endpoint or persistent audit sink. The approved local delivery source below
connects these records without changing their authority. Control fd 3 stays
dedicated to bootstrap/stop/acknowledgment. No Bootweave interface is needed for
the records themselves.

## Focused acceptance before implementation

- A held backend or transaction Close shows one charged request/two sockets and an
  active job, with no terminal event. A clean return then records a written response
  only after cleanup and refunds only through the unchanged lifecycle.
- A returned failed/uncertain Close retains charges and appears as a retained job;
  its event preserves possible effect and uncertainty. Reading repeatedly changes
  neither events nor ownership.
- Policy/input rejection, engine-phase failure and backend failure remain distinct. Hostile synthetic
  request metadata and error text never occur in the report.
- Eighteen real intercepted DATA jobs retain exactly sixteen ordered events with
  two overwrites. Saturated counters stay saturated while the newest event still advances; text stays bounded, and copies
  cannot mutate private state. Stop/retirement/cache uncertainty are not health.

Tests use the existing transaction and DATA OS-boundary fakes only; no TLS, engine,
credential, socket, process or native operation is executed.

## Approved nonblocking local delivery source

The 2026-10-23 source approval connects a private nonblocking AF_UNIX datagram
pair in the actual source constructor. I inherits its writer as fd 2; fd 0–1
remain `/dev/null` and fd 3 remains bootstrap/Stop/ACK only. S keeps the reader
and, after the fork, creates one nonblocking connected datagram client to the
fixed base-logging endpoint `/dev/log`. I creates no Unix socket or destination
and gains no new pledge promise. No such OS operation ran in these checks.

The source constructor owns at most six private acquisition descriptors: the
two pairs, null, and one relocation scratch. Child dup-to-target overlap can
temporarily retain five source descriptors plus four targets, up to nine in
this subset; the child ultimately inherits four. S retains two additional steady
integration descriptors (audit reader and local log client). Storage, Go runtime,
DATA/CONTROL listeners and other process descriptors are separate; these counts
are not a complete FD or kernel-memory profile. The fixed offline source lists
include the new C implementation, but their installed entry remains closed.

The same DATA worker still only records bounded memory. A pending-slot bitmap
and loss counter keep the producer history within 64 logical bytes and remain
independent of saturated total/overwrite counters. The existing sole DATA accept
actor claims at most four oldest pending events per loop, releases the owner lock,
then performs one raw nonblocking send per event. Claimed failures are lost, never
retried. No request worker emits I/O after its refund, and no new worker/queue is
created. Once stop is observed, no send is started; one already committed send may
race Stop. There is no stop flush or final-delivery guarantee.

Each message is exactly 64 bytes: `AGDIAG1\n`, four big-endian u64 fields
(attempt sequence, prior delivery loss, overwritten events, total events), result
and flags bytes, one pre-job-uncertainty byte, then 21 zero bytes. Sequence starts
at one and advances on failed attempts; exhaustion disables further sends rather
than wrapping. Result/flags contain only existing fixed classifications, never
traffic, identifiers, addresses, route/rule strings, errors or credentials.

S consumes at most four messages per ordinary loop using a 65-byte sentinel;
short, oversized, malformed, zero/duplicate/reordered sequence messages refuse.
Sequence gaps, malformed messages and local-sink loss are saturating diagnostics.
Only validated numeric fields enter one bounded local syslog datagram, labeled
`inspector-reported`, `qualified=0`, alongside S's own phase/target observation.
S never polls, retries or flushes this sink and skips draining during stop,
terminal wait and lost ownership. Added S endpoints receive one close attempt
after actual terminal/no-child proof. A failed close retains uncertainty and
prevents normal U-to-C settlement; dropping diagnostics does not waive ownership.

The one-second idle Accept and full/stuck capacity can delay delivery, potentially
indefinitely. Stop can lose final events. Missing/stale logs are never health,
readiness, peer authentication or replacement authority. No periodic heartbeat,
queryable status endpoint, remote logger or new actor is supplied.

This is **best-effort operational diagnostics**, not complete forensic audit.
Required protected durable enrollment/configuration/policy/generation records
remain separate. The connected [bounded security-record source](SECURITY-RECORDS.md)
now covers existing launch and normal-clean transitions, alongside mandatory
current U/C ownership history. Remaining administrative actions are undelivered. An action
whose required record cannot commit must refuse; containment/stop/wait must not
wait for audit I/O. Native durable retention is still an appliance acceptance
gap. Periodic base-log rotation is not a hard disk ceiling. Exact native buffer,
FD/CPU/kernel-memory/storage/full-disk/retention and four-second scheduling proof
remain required; immutable source/default qualification gates stay false.


## Root-only owner-control source

Partial source delivery under #23/#31/#32 connects a fixed local endpoint inside
each existing owner: `/var/run/aegvium/inspector.sock` in S and
`/var/run/aegvium/frontend.sock` in the separate frontend owner. No additional
persistent actor, goroutine or remote interface is added. The directory is
root:wheel0700; endpoints are root:wheel0600. Protected nonsymlink ancestors are
validated before directory creation and on use. Existing endpoints refuse; there
is no stale-path disposal. Each accepted peer must be uid0/gid0 on that actual
connection. Listener, accepted and transient client descriptors below3 refuse
and receive one close attempt so they cannot become a later child's standard I/O.

`AGCTL1 STATUS`+LF and `AGCTL1 STOP`+LF require exact framing and EOF. Each owner
keeps one listener and at most one accepted client, backlog1, a33-byte request
sentinel, response at most64 bytes and a one-second client deadline. The C state
is below512 bytes; Go keeps the same bounded buffers but runtime/kernel overhead
is unqualified. The command keeps one transient FD and a65-byte reply sentinel.
These are explicit added subsets, not an admitted complete FD/RSS/kernel profile.
The source constructor/fork and loader transient closure still need native proof.

Each ordinary owner loop performs bounded nonblocking accept/read/send work.
Root STOP cancels only the existing same-child lifetime, never selects a PID or
resets a retirement deadline. S continues to use its dedicated inspector fd3 stop
channel. Stop/wait is independent of journal I/O. A retiring reply acknowledges
only cancellation; status always says `qualified=0`. Neither response supplies
frontend acceptance, original-wire fidelity, readiness or reaping proof.

After actual original-child terminal/no-birth proof, owned client/listener closure
and matching-inode unlink must complete before normal C/audit settlement. Failed
close or namespace identity uncertainty is sticky, retains ownership/path and
blocks settlement; cleanup is never retried using a pathname guess. The fixed
client similarly retains a failed transient close. Source checks do not prove
four-second scheduling, native endpoint behavior or qualified restart. A later rc process cannot adopt old wait authority from socket absence or parsed
C alone. The normal successor source below relies on the already required native-
qualified protected clean-history chain, not a replacement waiter. All installed
gates remain false; reload stays unsupported.

The S, frontend owner and service-client immutable native gates remain false.
Focused C checks replace every subject OS boundary; pure protocol tests and
OpenBSD compile-only checks execute no product listener, credential or child.


The rc stop dispatch bypasses rc.subr running-state prechecks, including partial
startup. `service stop-all` submits one-way notifications to both bundled owners
without reading replies, keeping at most one transient FD at a time. Known
notification failures still permit trying the other selected owner; an uncertain
close retains its FD and stops further allocation. Submission is not admission,
physical cleanup, Ready or timing proof. rc stop still returns pending/failure.
External mode selects only the local inspector owner; external restart is refused.

The fixed additional request is `AGCTL2 STOP <canonical-positive-ms>`+LF, maximum
32 bytes inside the existing33-byte sentinel. The scalar uses the same kernel
CLOCK_MONOTONIC basis as S, with overflow/future/noncanonical rejection. This
version is explicitly one-way: handlers close the accepted stream after exact
EOF and never attempt an ACK write. Legacy AGCTL1 status/single-stop request/reply
is unchanged. Existing root-only peer/path checks still apply. There is no new
actor, endpoint, nonce, identity or ownership receipt.

One T0 precedes both notifications. Their nonblocking retries share100ms rather
than one timeout each; a final immediate nonblocking attempt may still fail for
the second owner. No delivery guarantee is claimed. Both owners keep the earliest
valid T0. S measures its existing100ms retirement-ACK,3s escalation and strict4s
completion offsets from that common origin. The frontend conservatively maps the
same kernel epoch into its Go monotonic clock, so notification/processing time
never grants fresh TERM/KILL/wait grace. A missed target stays failed; the same
owner continues only actual original-child cleanup. Identity loss consumes its
signal/wait rights. Stop/wait stays independent of journal/audit I/O.

The [normal successor source](NORMAL-CLEAN-SETTLEMENT.md#shared-stop-and-rc-restart-source)
now joins the fixed bundled rc sequence. Qualified protected C provenance and
exclusive locks are required, not merely a parsed C or missing endpoint. Native
clock/IPC/scheduling/durability/FD/resource proof and the whole-appliance4s target
remain unqualified. Every installed/default qualification gate remains false.
