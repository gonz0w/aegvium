# Signed stock-media laboratory baseline

Status: bounded M1 provenance research under #12/#14 and the maintainer's 2026-10-18 continuation. This does not adopt an appliance installer, service or runtime architecture.

## PRD

OB-01: replace the unexplained construction lineage of the inherited laboratory image with an independently created owned OpenBSD 7.9 amd64 baseline installed from authenticated stock media. Preserve all inherited-image results as historical observations; new lineage does not retroactively authenticate them.

OB-02: retain the official release/key/manifest identities, selected sets, actual stock installer effects, first installed boot, daemon byte comparison, locally generated bootstrap identity, clean shutdown and independent process/group absence. Then repeat the existing ordinary component selection on a fresh snapshot of the new immutable baseline. No WAF/traffic/security/advisory validation resumes.

## EDD and ownership

Use the pinned host-only verifier in [ADR 0009](../../architecture/adr-0009-host-release-verification.md). Verify its exact executable hash and the pinned official release key, signature and ISO before any boot. No custom signature implementation or checksum-only fallback. Public release material may be copied from a sibling cache only after independent Aegvium verification; never borrow its active VM, credentials, writable target or acceptance evidence.

Create one new private owned qcow2 file with an 8 GiB virtual capacity and no backing image in a fresh UUID directory below `.tools/native-stock`. Refuse existing destinations, devices and symlinked paths. Never attach a host block device or production file. Use two CPUs, 2 GiB RAM, TCG, no shared mount/passthrough, stock optical media read-only and private Unix console/control sockets. Install with no NIC, using the observed stock interactive installer; do not create an answer-file language or replacement installer. BootWeave continues to own the generic installation framework and future product extension contract.

The provisioning guest has a predeclared 3600-second host supervisor ceiling and 4 GiB per-file storage guard. Stop scheduling work after 3000 seconds, reserving 600 seconds for halt/cleanup. Observe prompts before each response; use a single-disk unencrypted stock MBR/automatic layout, base/compiler/manual sets and stock kernels, UTC, serial console, no X/game/site sets, no extra user and no network configuration. Credentials are fresh, private and absent from Git/shared evidence. On an unexpected prompt or failed check, stop dependent work and retain the actual state; no automatic retry, reinstall or deadline extension.

The stock ISO omits the embedded signature list. The installer may continue at that exact missing-list prompt only after independent host verification of the entire unchanged ISO, as described by the [official installation FAQ](https://www.openbsd.org/faq/faq4.html#Download). This does not allow failed-signature bypass or an unsigned alternate artifact.

After installed boot, compare selected installed base binaries/public release keys against bytes from the authenticated sets before patching. Configure only the laboratory bootstrap needed by the existing restricted-loopback SSH controller: public-key-only access and no password/forwarding authority. Locally generated private material stays in mode-0600 ignored storage. Halt and verify process/group disappearance before hashing and admitting a mode-0400 independent base copy. A new pinned baseline and public bootstrap-key fingerprint select it; private bootstrap keys never enter source or evidence. Keep the inherited profile available explicitly without silent fallback.

## Test Design

OB-T01: owned host tests reject altered/nonregular/missing verification inputs, incomplete or unsuccessful verifier results, partial publication, stale baseline/credential identities and failed source/base invariance. Verify actual official signature/ISO identities independently in Aegvium; no inherited test pass is substituted.

OB-T02: record exclusive file creation and effective QEMU storage/network inventory before continuation, observed installer choices, complete stock-set installation and a clean full installed-kernel boot. Compare installed daemon/key bytes against authenticated release-set bytes and retain mismatches instead of accepting a checksum-only provenance claim.

OB-T03: independently verify stopped image/source/media identities, fresh bootstrap identity, clean halt, no owned process/group or attached handles, and private permissions before baseline admission. Preserve failed attempts and partial state; do not accept a merely stopped installer as a completed installation.

OB-T04: from the clean signed candidate, run one fresh exclusive ordinary component repeat against the new baseline: 23 parents/31 subtests/54 PASS records with exact binary hashes and UID 32767; existing authenticated 34-patch/reboot/access/source/base/journal/strict teardown gates still apply. Its 900-second profile is unchanged. This is separate from native source compilation and the paused complete WAF profile.

## Compatibility and rollback

Only laboratory provisioning and input provenance change; Go/dependency/rules/runtime policy, live networks, services, installation payloads and BootWeave schemas do not. The new source-bound image replaces a third-party construction assumption for subsequent research, not a reproducible-image or hardware/firmware trust claim. Original installed lineage requirements and explicit maintainer acceptance are tracked independently. Retain the inherited image pin and every historical failure. Rollback selects the explicit inherited profile; never silently fall back after a new-baseline failure. Full controller/guest failure coverage, architecture/phase adoption and paused qualification remain open.
