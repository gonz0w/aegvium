# First-image payload and maintenance boundary

Status: **Selected for source/design implementation; no commissioning or launch.**
Maintainer approval `Sentinel_91966a78fb5c8191b94163b82a31ba5f` answered
`Sentinel_f4c4a07f4b2881919aa8721be42257b4`: stopped-service maintenance and
first commissioning only through an offline builder that creates and hands over
a fresh, never-started paired image. Existing-image reset/recovery stays outside
this MVP. No credentials, OS updates, native execution or deployment are approved.

## Connected payload producer

`cmd/aegvium-payload` is an offline staging assembler, not an image installer or
runtime entry. Its required source interface is `-pair` (public AGPAIR1 file),
`-inspector` (reviewed image artifact), `-sha256` (expected lowercase hex digest)
and `-output` (new archive). Inputs are opened nonblocking without following a
final symlink and must be regular files. The descriptor is bounded to8192 bytes;
the image is bounded to1..67108864 bytes. No actual assembler invocation or input
provisioning is included in this source check.

The producer reuses the actual `pairmodel.Parse` grammar. Generation zero refuses.
It detaches the parsed descriptor, streams the exact image into the same hash
and archive, requires exact EOF and expected digest equality, then emits these
fixed USTAR regular-file members in order:

| Path | Mode | Bytes |
|---|---|---|
| `usr/local/libexec/aegvium/inspector` | 0555 | Complete reviewed image bytes |
| `var/db/aegvium/inspector.pin` | 0600 | Lowercase expected SHA256 plus LF |
| `var/db/aegvium/pair.snapshot` | 0600 | Complete canonical common descriptor |
| `var/db/aegvium/launch.intent` | 0600 | Descriptor generation plus LF |
| `var/db/aegvium/launch.state` | 0600 | Existing128-byte C format, immediate predecessor of descriptor generation |

Member UID/GID are0/root:wheel, timestamps are fixed, and no link, directory,
extended header or extra path is emitted. In particular the archive never
rewrites shared system-directory metadata. The generic builder must create the
WAF-owned directories with protected ownership/modes and all required ancestors.
The resulting C/intent/snapshot/pin bytes feed the existing fixed runtime reader;
they do not change its U commitment, no-wrap or failure behavior.

Output is created O_EXCL0600, never truncated/replaced/extracted. An existing
output refuses. Only successful image validation, all member writes, archive
finalization, input closure, output fsync and output closure produce success.
Failures retain the incomplete or unadmitted output as-is; no retry, unlink,
rename, chown, target-root write or cleanup is attempted. O_EXCL and file fsync
are not an atomic/durable image-publication protocol; parent-directory durability
and whole-image admission remain builder obligations. A complete-looking archive
whose command failed is not admissible.

## Actual first commissioning still required

This archive is data, not a fresh-image receipt or launch capability. The actual
offline builder must own newly created image resources continuously, prevent
startup/export/duplication while constructing the pair, validate separate trusted
OS/inspector artifact provenance, install exact regular files with nlink1/modes/
ancestors, prove file/directory durability and hand over the paired frontend and
inspector snapshots without losing exclusive never-started lineage. Missing
files, C bytes, root metadata, hashes or an operator Boolean prove none of that.
No generic BootWeave extension schema or attestation format is invented here.

Existing-image initialization/reset, U→C, normal TerminalClean writing, snapshot
restore/live cloning and supervisor-loss cleanup are not supplied. Local counters
cannot detect unannounced rollback or clones. The installed launch path remains
closed pending the actual builder integration and native qualification.

## Ordinary maintenance, no OS-updater manager

The supported MVP sequence is stop → prove actual inspector retirement and
supervisor-local descriptor closure → ordinary OS/package maintenance → validate
the complete new execution closure → fresh start. Hot updates, in-place runtime
mutation, plugins/dlopen and reexec are unsupported. No custom controller is
added over administrator OS maintenance. Existing WAF executable namespace and
qualified-restart conditions remain unchanged.

Retained OpenBSD loader/VM source shows mapped objects retain vnode references;
stock syspatch uses install's temporary-file/rename behavior. A pathname change
does not itself retarget a live mapping. MAP_PRIVATE is not a backing-byte
snapshot, and later library loads are separate operations. The actual operational
inspector's ELF/interpreter/dependency/search-path/environment closure, no-late-load
behavior and same-child post-loader handshake remain unqualified. The existing
AGCHECK104 configuration match is not that handshake or supervisor identity.
Uncertain retirement blocks a qualified WAF restart, not administrator patching.

## Focused source evidence

Memory-only tests use the retained public descriptor, independently frozen C0/
Cg/Cfe reader literals and4113-byte image/digest. They inspect exact member bytes,
metadata, deterministic output and generation predecessor, reject malformed/
trailing/zero-generation descriptors and size violations, exercise truncation/
growth/read/hash/header/body/finalization failures, and check detached input
ownership. They create no payload file, credential, listener, image or process
under test. Command filesystem/sync/close behavior is source-reviewed and compiled,
not executed or fault-qualified. Ordinary source hygiene/review evidence remains
separate from full/native/engine, resource and mandatory four-second acceptance.
