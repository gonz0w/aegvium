# ADR 0014: WAF-local launch exclusion and durable admission

Status: **Selected for scoped source implementation; operational entry closed.**
Date: 2026-10-22. Maintainer approval `Sentinel_040f29f2644881918ffb859e9105d40d`
responded to the concrete source-only question
`Sentinel_15f4362dbc7c81918e92709e47409aa3`. No live permissions, launch,
credentials, native effects or deployment follow. Draft126's validation pause
and mandatory, unqualified four-second target remain unchanged.

## Decision and consequence

Use a WAF-controlled executable namespace. Every supported updater participates
in exclusion through S lifetime and any unresolved I lifetime. A cooperating
updater must refuse activation and namespace mutation on unclean durable state,
even after S dies and its advisory lock becomes free. Entry/namespace changes
require planned cold maintenance after established physical retirement. This
can cause outages and delay upgrades; no update or recovery operation is
implemented or authorized here.

Use WAF-local serialized durable generation consumption, without a new service
or cross-product issuer. Generation pairing with the frontend still needs an
actual qualified provenance/binding; locally parsed intent is not that proof.
The previous fixed journal proposal's arbitrary256-attempt exhaustion is not a
requirement. A fixed bounded checkpoint is routine engineering within this
choice. See [normal admission](../milestones/M2/LAUNCH-STORAGE.md).

Unannounced VM rollback and live cloning are unsupported. Local counters/locks
cannot detect a restored image. An external nonrollbackable witness would add
new trust and availability dependence and is not adopted.

## Physical retirement is independent of bytes

A normal clean transition requires S's continuous exclusive terminal wait (or
qualified NoChild), actual S-local channel closure, and qualified no-descendant/
no-export construction. Stop, ACK, freeflock, process absence, operator assertion,
parsed checkpoints and hashes establish none of these facts. TerminalClean may
only follow actual physical cleanup; no journal I/O may delay active stop,
escalation or wait.

If S is lost without a surviving exclusive waiter, this architecture currently
has NO selected physical-cleanup mechanism. Launch, updater activation AND
authority repair remain blocked. No PID adoption/guessed termination, reboot,
hypervisor fence or new recovery actor is selected. A separately specified
physical-retirement mechanism is a prerequisite for any cold recovery effects.
This source slice therefore has **no U→C, reset, repair or TerminalClean writer**.

## Minimum source boundary

The private existing-file-only storage path owns a fixed protected namespace and
exclusive checkpoint descriptor, strictly consumes a clean generation to U,
then connects to the existing controller and actual private pair constructor.
Its local success is not launch admission, authenticated channel identity,
Ready, request allow or operational updater authorization. Trusted initial-C/
normal-clean provenance and all native/identity/held-image/leaf/pairing/resource
qualification remain missing; installed entrypoints keep refusing.

Only full U write + fsync + exact reread + same-inode verification under exclusive
lifetime ownership establishes known consumption. No child/ownership admission
may precede that boundary. Candidate API attempts before it are not admitted
generations: a failed write cannot prove durable burn or unchanged/reusable C.
Same-process attempts are always consumed and failures retain uncertainty.
After known commitment, even later construction failure leaves U burned. A valid
C after precommit S loss can only be considered with trusted C provenance and
the no-child-before-U invariant, not a free lock alone. Native durability remains
unqualified. No storage call is inserted into the controller's active lifecycle.
