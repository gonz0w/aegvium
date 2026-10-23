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
endpoint or persistent audit sink. The current child standard descriptors remain
`/dev/null`; control fd 3 stays dedicated to bootstrap/stop/acknowledgment. Connecting
local logging/status must identify the transport, finite reader/storage budget and
failure/retention policy without putting I/O on stop/wait or reusing control as Ready.
No Bootweave interface is needed for the records themselves.

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
