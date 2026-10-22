# Private normal launch storage composition

The approved [ADR0014](../../architecture/adr-0014-launch-namespace-durable-admission.md)
selects local namespace/updater exclusion and durable no-reuse ownership. This
source connects protected storage to actual controller/pair preparation; it
has no operational caller or positive startup/history/cleanup issuer.

## Fixed production path

`launch_storage.{c,h}` is one private process/event-loop attempt shared by launch
and updater exclusion. It consumes the attempt before checking controller Empty
and native constructor unused. Duplicate/reentrant/invalid-order calls do no I/O.
`storage_openbsd.c` directly binds fixed base OpenBSD APIs; no runtime operation
table, supplied FD/path, profile Boolean or provider registration exists.

Traverse `/`, `var`, `db`, `aegvium` with DIRECTORY|NOFOLLOW|CLOEXEC and actual
root UID0/directory/non-group-or-other-writable checks. Superseded directories
close once; any acquisition/metadata/close error stops normal work. Open existing
`/var/db/aegvium/launch.state` RDWR|NOFOLLOW|CLOEXEC. Require regular, UID0/GID0
(root:wheel on OpenBSD), exact0600, nlink1, size128. Acquire flock(EX|NB), then
validate fstat against fstatat(NOFOLLOW) dev/ino plus both current metadata. No
create/truncate/rename/unlock/repair exists. The stable checkpoint inode carries
the lifetime exclusion; every updater must cooperate because flock is advisory.

Frame128: magic `AEGOWN1\n` bytes0..7, C/U byte8, zero9..15, lowercasehex32
watermark16..47, raw SHA256 digest48..79, zero80..127. Digest input is48-prefix
plus48-suffix (96 bytes, excluding stored digest). It detects corruption, never
authenticates ownership. U0 is malformed; every U blocks BOTH roles. C's trusted
initialization/normal-clean provenance is not established by parsing/root mode.

Launch increments the128-bit watermark with no wrap, then reads protected fixed
`launch.intent`: existing root UID0/GID0 regular0600/nlink1/size33, current inode
and path metadata matched, exact32 lowercasehex + LF and equality with next.
Intent is S-side operator equality data; it is not frontend pairing or identity.
Close intent once before any checkpoint write. The connected [image prefix](IMAGE-CUSTODY.md)
then verifies the fixed protected pin and executable file under the same EX and
closes its verification descriptors. Only after that, encode U(next), one exact128-byte
pwrite, one fsync, one exact128-byte pread with byte equality, and descriptor/path
metadata plus original-inode equality. No short-write continuation, fsync-error
readback, repair or retry. Base SHA256Init/Update/Final allocates no product buffer
outside its fixed stack context; actual target behavior remains unqualified.

Only after full commitment mark known consumed, close namespace handle once,
sample checked monotonic milliseconds, call existing `aeg_owner_prepare`, then
existing `aeg_native_pair_prepare`. The checkpoint EX descriptor remains held.
A namespace-close/clock/controller/pair failure after commitment retains U burned;
no clean rewrite. No storage calls occur after controller/pair preparation or
on stop/escalation/wait. Pair construction is local source only: no fork/exec,
Owned/Ready, native channel authentication, request allow or cleanup proof.

Updater validates EX + strict C, closes the namespace handle once and holds the
checkpoint exclusion. It does no intent read, write, reset, controller/pair or
actual update. Its local guard stage does not authorize operational mutation.
On ANY failure known references/exclusion and uncertainty remain; a failed close
is never retried. No raw descriptor/counter capability escapes the bounded view.

The source owner has at most4 overlapping known storage/image descriptors, at most1
after clean local preparation, <=128-byte static owner state and fixed stack
frames. These are local source accounting only, not whole-S FD/RSS or native
no-export proof. A future child closes inherited checkpoint copies, never
LOCK_UN (which would unlock the parent's shared flock). The actual fork/image/
leaf/wait/closure composition is still missing.

## Pre-code expectations and focused checks

External frozen packet SHA256ec65cfce6b75d352647cb9ad47366a9e73bd610fbf63d92cb5a173d2871f6d64
preceded implementation. Independent reviewer supplied C0/U1/Cfe/Uff/Cff frame
literals and failure-order expectations. Current source tests bind those literal
frames and an independently listed syscall/SHA trace, not production-generated
oracles. Every non-void acquisition/stat/path/close/lock/read/write/sync/clock
edge fails in a fixed mode. Base SHA API is void; separate digest mismatch tests
refusal and the fake validates exactly both48-byte inputs. Metadata, aliases,
invalid counts, U, nowrap, intent mismatch, prestate, reentry and postcommit
failure are explicit. 'Committed=false' means unestablished, never reusable C.

Only the new C module is compiled with ALL storage/SHA/clock and existing native
OS boundaries intercepted. The original96 storage cases remain as regression
expectations; the image prefix adds76 fixed cases (172 total), normal-exit under5s each, compiler
30s, fresh retained task-local TMPDIR. No host file/descriptor/socket/identity/
permission/launch/process/engine effects occur. Independent exact fixture/source
review precedes checks; ordinary source/secret hooks/signature/DCO remain.
No full verify, actual crypto/engine/security/native campaign or four-second
acceptance is claimed. Existing retained failures and validation pause remain.

## Retained target source and remaining gates

Read in place, no fetch/extraction: OpenBSD7.9 src.tar.gz archive
SHA256fb305c553059b48e8ee64539f392b783cb38a67865823f6f6a94f3b220a1268b.
Selected member hashes: flock.2 dc64346318989b6524f64b8083e84e867551e8880896debcc9278525fb97dc4e;
fsync.2 edeef7d3a9bf5949f0d63750f996b5c2439af6dfc2bc2593ca5f6326c4a48ad3;
include/sha2.h 533cc52fd2f35af94a46e80cbae6bc887c7e88e3eef5d11396d382f3da29306e.
Flock is advisory/shared across fork; fsync EIO can leave partial bytes and must
not be retried/read back as repair. Native filesystem/directory/file initial
installation, persistence/crypto, cooperative updater and namespace/image pinning,
actual paired generation provenance, leaf syscall closure, no descendants/FD
export, exclusive waiter/local closure and four-second/resource qualification
remain mandatory. No C initializer or clean writer is included. S-loss cleanup
has no selected mechanism; U blocks launch, updates and repair indefinitely.
