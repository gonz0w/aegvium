# ADR 0011: exclusive external inspector ownership

Status: **Architecture selected for scoped source implementation; native
implementation and four-second qualification remain absent.** Date: 2026-10-21.
The maintainer approved the concrete proposal in reply
`Sentinel_faa3228bb28c819191cf06592504efb2` at 10:38:37 UTC to question
`Sentinel_7eda926be3c88191b98371beaff7398a`. This permits isolated source,
portable/synthetic lifecycle tests and independent review. It permits no live
termination, credentials, deployment, native campaign or adapter activation and
does not lift Draft126's affected validation pause.

## Decision

A small base-C privileged supervisor S exclusively launches, stops, signals and
reaps exactly one unprivileged inspector I on the separate Aegvium VM. S owns
the external reservation for I's whole four-request/eight-data-socket envelope
before launch and retains it until physical cleanup is proved. The child has a
finer private C02 ledger; this creates no additional request/socket capacity.
No replacement starts while old ownership or cleanup is uncertain.

S has no network listener, public TLS key, request data, engine or application
backend capability. It launches a fixed held executable, never a caller-selected
command or PID. The exact native construction must prove irreversible real,
effective and saved UID/GID reduction, cleared supplementary groups, no authority
descriptor in I and no data descriptor retained by S. I must be unable to create
descendants, export descriptors or leave another data writer. OpenBSD/Go/engine
compatibility with that restriction is a mandatory unproved gate.

S and I use a private inherited bounded nonblocking control channel. The future
codec must fit 64-byte frames; this ADR does not implement or authenticate it.
EOF is a control fault, never a terminal-process receipt or proof S closed its
own resources. There is one event loop and one exclusive child waiter. Auto-reap
and competing waiters are forbidden; identity loss blocks guessed-PID signals.

The first stop fixes a single monotonic T0. A retirement acknowledgment must
arrive before 100 ms to establish effective admission retirement; a request to
stop does not establish it. Absent that acknowledgment, or on unsafe ownership,
escalation becomes eligible immediately at the relevant boundary. A timely
acknowledgment permits drain only until T0+3000 ms. S claims a kill attempt once
against its still continuously owned unreaped child; a successful signal, ESRCH
or EPERM proves neither death nor reclamation. A terminal receipt consumes the
child slot and forbids every future signal to it. No operation resets T0.

Reclamation requires the owned terminal/no-child proof, actual S protocol
closure and native proof of the no-descendant/no-export construction. It retires
the dead ledger rather than manufacturing C02 release or clean transaction
Close. All in-flight inspections may be lost; an application operation that
already began may have effects. There is no automatic request retry.

The existing four-second shutdown target remains mandatory. Completion at
T0+4000 ms is late. A missed target or unverifiable clock/identity cannot later
become a pass. Reservations remain held until actual cleanup; the deadline never
refunds them. OpenBSD signal/wait APIs do not establish a universal four-second
reap bound, so exact operating-profile qualification remains unpassed. An outer
VM fence is only a possible separately authorized recovery mechanism, not an
implemented or automatic means of satisfying this target.

## Restart, accounting and consequences

There is no automatic restart. A replacement requires old-process cleanup and
validated fresh operator-paired generation, durable consumption/history and
exclusive launch ownership. A failed launch burns its generation. S failure,
missing history or ambiguous wait identity blocks a new S; no PID adoption or
in-memory reset repairs those facts. [ADR0014](adr-0014-launch-namespace-durable-admission.md) selects WAF-local
namespace/updater exclusion and durable admission for scoped source only. Its
minimum checkpoint connects local controller/pair preparation but adds no positive
launch/cleanup issuer; full native composition and S-loss recovery remain absent.

S's proposed logical source envelope is one child, eight descriptors and 16 KiB
of owned logical state, including 8192 bytes of metadata, control storage and a
32-entry redacted event ring. These are source obligations, not measured RSS
bounds; OpenBSD RLIMIT_RSS cannot establish the latter. The isolated controller
below occupies only a small part of this allowance, reserves no real descriptors
and does not establish the eventual S resource bound.

This adds a root-trusted component and may keep the service unavailable when
cleanup cannot be proved. The practical alternative is same-user supervision:
less privileged code, but weaker independence from a compromised inspector.
The maintainer selected privileged exclusive ownership, without adopting any
new live security operation or relaxing the availability target.

## First implementation and remaining proof

The [M2-S01/1 private controller contract](../milestones/M2/SUPERVISOR-CONTROLLER.md)
scopes the first source slice: one non-resettable process-local state, detached
views, synthetic trusted observations and once-claimed diagnostic intents. It
contains no native launch/signal/wait binding, credential handling, real IPC,
engine or executable entrypoint. Independently authored literal expectations
must be frozen before C implementation and reviewed against the resulting code.

The native parent/child constructor, privilege reduction, descriptor/descendant
proof, held executable provenance, authenticated control, paired startup/history,
transaction lifetime integration and four-second profile qualification remain
mandatory. No synthetic result enables required WAF or satisfies those gates.
ADR 0010's mandatory inspection and frontend key custody remain unchanged.

Primary references for the researched native limits are OpenBSD 7.9
[kill(2)](https://man.openbsd.org/OpenBSD-7.9/kill.2),
[waitpid(2)](https://man.openbsd.org/OpenBSD-7.9/waitpid.2),
[_exit(2)](https://man.openbsd.org/OpenBSD-7.9/_exit.2),
[pledge(2)](https://man.openbsd.org/OpenBSD-7.9/pledge.2) and
[setrlimit(2)](https://man.openbsd.org/OpenBSD-7.9/setrlimit.2), read 2026-10-21.
These support the design limits; no native operation was run to produce them.
