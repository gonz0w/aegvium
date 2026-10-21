# Private Inspector Owner controller

This C11 component implements the state-only portion of the approved
[external ownership architecture](../../docs/architecture/adr-0011-inspector-owner-containment.md)
against the frozen [M2-S01/1 contract](../../docs/milestones/M2/SUPERVISOR-CONTROLLER.md).
It has no production caller, native binding or executable entrypoint. It cannot
launch, signal, wait for, authenticate or reclaim an actual inspector.

One private static owner claims initialization once. Detached views cannot reset
or release it. The four-request/eight-data-socket external envelope stays held
after stop, signal results, deadline misses and uncertain wait identity. Only
trusted terminal/no-child and actual protocol-close observations together retire
the envelope; the missing native adapter must prove those facts and the original
no-descendant/no-export construction. Synthetic inputs grant no native authority.

Time inputs are integer milliseconds. One stop epoch governs acknowledgment
before 100 ms, acknowledged drain before 3000 ms, and completion before 4000 ms.
The controller detects equality expiry and sticky clock/identity faults. A
successful signal is never a terminal receipt. The four-second operating-profile
requirement remains mandatory and unqualified.

The [pre-C manifest](../../docs/milestones/M2/SUPERVISOR-CONTROLLER-FREEZE.json)
records 32 independently authored literal traces / 289 operations, maximum 24 per
trace. Contract and literals were signed in commit
`86cac03860f71943d50845eb8a191d97354be257` before this C existed. Review was
content-only; file provenance/hashes were checked by the source owner. Original
expectations remain unchanged.
A separate independently authored post-implementation review regression adds one
13-operation trace for repeated stop claims and late acknowledgment after kill
claim. Total: 33 traces / 302 operations. It is not pre-C evidence and does not
rewrite the original packet or its fixed 32-trace replay limit.

`tools/tests/test_inspector_controller.py` compiles this core and the finite
ordinary host driver with `/usr/bin/cc -std=c11 -Wall -Wextra -Werror -pedantic`.
Each trace starts a fresh normally exiting host executable, with no product
reset hook; operation input, step count and lifetime are capped. The driver is
test-only and its grammar is unrelated to any future private control protocol.
`make verify` discovers these tests alongside the ordinary repository checks.
Host compiler identity/hashes belong in the candidate evidence; no OpenBSD
binary, signal/wait, resource, RSS, engine or native timing proof follows.

Missing before runtime integration: the sole native parent/child constructor,
irreversible UID/GID drop, held executable, descriptor/descendant containment,
authenticated inherited channel, durable fresh paired-generation consumption
and exclusive launch history, engine transaction ownership, and full native
four-second qualification. No storage/IPC codec or restart authority is silently
selected here. Draft126 remains a draft and affected validation remains paused.
