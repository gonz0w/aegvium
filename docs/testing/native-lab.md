# Disposable native lab

Status: profile design pending. No Aegvium native run exists.

Use independent owned VM images/snapshots, synthetic clients/backend and an isolated network. Never reuse live Nomvium/Arxwall/Horvium guests or configurations as fixtures. Pin signed OpenBSD media, patches, Go/packages, source/tree and input hashes. Record connectivity boundaries before any listener opens. No public listeners or production data.

Each run needs a unique ownership marker, bounded process/time/storage budgets, fresh backend receipt counters, collector/analyzer identity, retained failures/skips and verified process/network/VM teardown. Host engine tests and OpenBSD cross-compilation are separate from native evidence. Choose release/architecture and measured budgets explicitly during lab design; no current OS support is asserted.
