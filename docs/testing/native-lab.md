# Disposable native lab

Status: bounded native engine repeat observed; full lab admission and appliance qualification remain open.

Use independent owned VM images/snapshots, synthetic clients/backend and an isolated network. Never reuse live Nomvium/Arxwall/Horvium guests or configurations as fixtures. Pin signed OpenBSD media, patches, Go/packages, source/tree and input hashes. Record connectivity boundaries before any listener opens. No public listeners or production data.

Each run needs a unique ownership marker, bounded process/time/storage budgets, fresh backend receipt counters, collector/analyzer identity, retained failures/skips and verified process/network/VM teardown. Host engine tests and OpenBSD cross-compilation are separate from native evidence. Choose release/architecture and measured budgets explicitly during lab design; no current OS support is asserted.

The bounded controller follows the [native engine packet](../milestones/M1/NATIVE-ENGINE.md) and [image pin](../../research/native/image-pin.json). Two 13-case native smoke runs and boot/auth stage-abort cleanup observations are recorded in the [native research receipts](../../research/native/README.md). The corrected runtime candidate is identified there; source builds, signed official image provenance and broader failure coverage remain separate gates.

## Ordinary host owner custody

The supervisor retains its born group leader with WNOWAIT until the final group
signal, then consumes the actual terminal wait exactly once. Missing WNOWAIT or
non-default SIGCHLD fails before birth. ECHILD/unknown ownership is sticky and
never authorizes a new signal or wait. Selector, clock, signal, wait and receipt
failures cannot silently become success; the first observed trigger is retained.
The existing 1..3600-second work limit and 20-second cleanup allowance remain.

The original final receipt shape is retained. A separate private `.ownership.json`
records raw wait status, every signal errno, errors and direct PID/original group
absence. Darwin EPERM remains an actual error observation; it is redundant only
when WNOWAIT already proved direct exit, the real terminal wait succeeds and both
identities are independently absent. No positive signal follows the sole wait.
`escalated` means the direct leader had not exited before the final KILL; a leader
that exited can still require descendant group cleanup. The finite portable
regressions independently check PID/group and the recorded descendant's absence.
Detached sessions and native campaigns remain outside this proof.
