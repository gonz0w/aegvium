# Disposable native lab

Status: bounded native engine repeat observed; full lab admission and appliance qualification remain open.

Use independent owned VM images/snapshots, synthetic clients/backend and an isolated network. Never reuse live Nomvium/Arxwall/Horvium guests or configurations as fixtures. Pin signed OpenBSD media, patches, Go/packages, source/tree and input hashes. Record connectivity boundaries before any listener opens. No public listeners or production data.

Each run needs a unique ownership marker, bounded process/time/storage budgets, fresh backend receipt counters, collector/analyzer identity, retained failures/skips and verified process/network/VM teardown. Host engine tests and OpenBSD cross-compilation are separate from native evidence. Choose release/architecture and measured budgets explicitly during lab design; no current OS support is asserted.

The bounded controller follows the [native engine packet](../milestones/M1/NATIVE-ENGINE.md) and [image pin](../../research/native/image-pin.json). Two 13-case native smoke runs and boot/auth stage-abort cleanup observations are recorded in the [native research receipts](../../research/native/README.md). The corrected runtime candidate is identified there; source builds, signed official image provenance and broader failure coverage remain separate gates.
