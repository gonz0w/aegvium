# Bounded required security records

Source slice for [#28](https://github.com/gonz0w/aegvium/issues/28), under the
2026-10-23 approved bounded-retention choice. Only the oldest sealed segment may
rotate at a verified clean/stopped boundary. This implements the existing launch
and normal-clean transition records; it does not deliver an administrative API,
complete enrollment/policy administration or accepted appliance retention.
Draft126 remains open and installed/default qualification gates remain false.

## Protected bounded source

The existing launch-storage owner opens existing
`/var/db/aegvium/security.records` under the same protected directory traversal
and uninterrupted `launch.state` EX lock. Require NOFOLLOW/CLOEXEC, regular
root:wheel0600, nlink1, exact8192 bytes, matching current descriptor/path metadata
and inode before/after reads and writes. This is two logical4096-byte segments,
with30 fixed128-byte records each. No directory scanning, path input, new lock,
broker, worker, remote sink, create, truncate, rename, unlink or recovery exists.
Historical development/native evidence and base syslog files are never opened.
Stock syslog's best-effort periodic rotation cannot supply required commit
ordering or a hard byte ceiling, so this narrow existing-owner source is needed.

Each header is128 bytes: `AEGSEC1\n` at0..7; A/S at8; count at9; zero10..15;
lowercasehex32 segment sequence16..47; raw SHA25648..79; predecessor-generation
anchor80..111; zero112..127. Hash input is the48-byte prefix and4016-byte suffix
of the entire4096-byte segment, excluding the stored digest. Unused bytes are
zero. This detects corruption, not authentication, trusted initialization or
rollback. Exactly one segment is active; the other is all zero or sealed with
30 records and the immediately preceding segment sequence. Sequence never wraps.

Each record is128 bytes: `AEGREQ1\n` at0..7; U/C at8; zero9..15; generation
lowercasehex32 at16..47; pair.snapshot SHA256 at48..79; verified executable pin
at80..111; selected profile1/3 at112; zero113..127. No credential, identifier,
route/address, traffic, error string or content is stored. U means admission
intent, not checkpoint commitment. C means the actual private terminal/close
boundary was proved, not a successful checkpoint-C write, timing pass or exit
receipt. Paired U/C records preserve identical metadata and consecutive
generations from the header anchor. The last recorded boundary must match the
current checkpoint watermark; records never supply its C/U or physical authority.

Before consuming U(next), the existing owner validates both segments and reserves
room for both that generation's records. It appends U, writes exactly one whole
segment, fsyncs once, reads back exact bytes, checks identity and closes once.
Only then may existing U checkpoint publication and constructor work proceed.
Short/error/oversized I/O, full/malformed history, metadata drift, uncertain close
or durability failure refuses. There is no write continuation, retry, sync-error
readback, record loss allowance or repair. A failed checkpoint write may leave an
unpaired intent; subsequent attempts refuse rather than silently discarding it.

After the same surviving S exclusively proves its actual child terminal (or
NoChild), closes all construction/channel handles and validates its exact saved
U under the original lock, it reopens the same record inode and compares all8192
bytes with its retained admission snapshot. Append C and durably commit it before
the existing same-generation checkpoint C. If this fills the active segment,
seal it in that same write, then durably initialize the other segment as active
at the next sequence and current generation anchor. The other segment must be
the original empty segment or the sole older sealed segment; the newest segment
is retained. Each separate write must fully commit before the next action.

Interrupted sealing/rotation, exhausted sequence or any required-record failure
keeps cleanup settlement unsuccessful and prevents this owner from writing C.
Partial bytes may have reached disk; no atomic whole-file transaction or repair
is claimed. All logging work occurs before child construction or after physical
terminal/closure. Active containment, Stop, escalation and wait contain no record
I/O, wait, flush or delivery guarantee. They retain their existing ownership rules.

The fixed source state bound becomes17408 bytes (including the retained8192-byte
record snapshot); clean comparison uses8192 stack bytes and commit readback4096
more, with bounded existing caller frames. The source still owns at most four
storage/image descriptors and one steady checkpoint descriptor. These are source
accounting, not accepted process RSS, disk allocation, FD or kernel-memory limits.

## Fresh payload connection and finite checks

The existing pure payload writer emits empty segments before initial C, anchored
to its watermark (the predecessor of the selected arbitrary nonzero first generation).
The existing fresh-image placement source requires exact initial-record bytes
before creating its fixed0600 file, then follows its ordinary sync/readback and
directory durability checks. This is staging equality, never a live initializer,
reset, migration, current-owner issuer or permission to alter an installed image.
Old payloads without the new fixed member refuse. No image operation ran here.

Focused Python tests compile actual C storage/native wrappers with every subject
filesystem/flock/SHA/clock/process/socket/signal/identity boundary intercepted.
Existing checkpoint literals/traces remain separately asserted; the new record
trace covers every nonvoid admission and clean edge, metadata/digest/malformed
history, short/partial/uncertain I/O, exact retained-byte drift, first and later
rotation, swapped segment order, sequence exhaustion and absent physical proof.
Record digest interception checks both SHA input lengths and intentionally does
not qualify OpenBSD SHA. Pure Go tests compare fresh headers to separately
prepared literal SHA values, exact archive member ordering and placement equality.

Required before operational entry: independent review, trusted initial/current C
and fresh-pair provenance; actual protected file/directory installation; native
filesystem persistence/crash/full-disk/torn-write behavior; same-child no-export/
leaf/descriptor proof; whole process/storage bounds; native shutdown scheduling
and mandatory four-second qualification; complete standalone install/start/use
and remaining enrollment/configuration/policy action records. Supervisor loss
and uncertain history remain blocked; no restart, live disposal or deployment is
authorized. Reverting this source requires restoring its matching payload and
placement code together; never reset an installed history to empty.
