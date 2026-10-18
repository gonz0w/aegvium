# Signed stock-media laboratory baseline

Status: bounded M1 provenance research under #12/#14 and the maintainer's 2026-10-18 continuation. This does not adopt an appliance installer, service or runtime architecture.

## PRD

OB-01: replace the unexplained construction lineage of the inherited laboratory image with an independently created owned OpenBSD 7.9 amd64 baseline installed from authenticated stock media. Preserve all inherited-image results as historical observations; new lineage does not retroactively authenticate them.

OB-02: retain the official release/key/manifest identities, selected sets, actual stock installer effects, first installed boot, daemon byte comparison, locally generated bootstrap identity, clean shutdown and independent process/group absence. Then repeat the existing ordinary component selection on a fresh snapshot of the new immutable baseline. No WAF/traffic/security/advisory validation resumes.

OB-04: select the new baseline explicitly for ordinary components only, reject unsupported modes or missing/stale identity inputs before execution, preserve the inherited profile without fallback, and keep BootWeave and product adoption separate.

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

OB-T04: from the clean signed candidate, run one fresh exclusive ordinary component repeat against the new baseline: 23 parents/31 subtests/54 PASS records with exact binary hashes and UID 32767; all 34 archive signatures/digests, exact applicable patch cohort, reboot/access/source/base/journal/strict teardown gates apply as specified below. Its 900-second profile is unchanged. This is separate from native source compilation and the paused complete WAF profile.

## Compatibility and rollback

Only laboratory provisioning and input provenance change; Go/dependency/rules/runtime policy, live networks, product services, appliance installation payloads and BootWeave schemas do not. The new source-bound image replaces a third-party construction assumption for subsequent explicitly selected ordinary component research, not a reproducible-image or hardware/firmware trust claim. Original installed lineage requirements and explicit maintainer acceptance are tracked independently. Retain the inherited image pin and every historical failure. Rollback selects the explicit inherited profile; never silently fall back after a new-baseline failure. Full controller/guest failure coverage, architecture/phase adoption and paused qualification remain open.

## Provisioning observation and explicit selection

The owned stock installation completed all seven selected installer entries (`bsd`, `bsd.mp`, `bsd.rd`, `base79.tgz`, `comp79.tgz`, `man79.tgz`, `BUILDINFO`) and booted the installed GENERIC.MP #449 kernel from sd0a. Seven installed file hashes match the independently authenticated base set. The effective prelaunch inventory had one writable owned target, one read-only ISO and no NIC. Empty removable device slots carried no media.

Two host observer corrections are retained privately: the initial inventory counted empty slots as media; the initial boot-prompt observer used the wrong screen row. Before any installer entry, the latter recovery checked the still-pristine disk, performed one deliberate supervised reset and found the exact prompt at row 208. It reused the same owned disk and absolute deadline. Neither correction is an installation retry or unqualified hardware acceptance. The stock ISO's exact missing-signature-list prompt was accepted only after whole-media authentication. First installed boot's online firmware and patch checks failed without a NIC/DNS; offline pinned patch admission remains a separate later gate.

The stock automatic layout gives about 1088 MiB to `/`, 3072 MiB to `/usr`, 2048 MiB to `/home` and 256 MiB swap. Native source-build capacity is unqualified. `make research-native-official-lifecycle` selects only the cross-built ordinary component profile via `--official-baseline --lifecycle-components`; all other official-baseline modes fail before preflight. Existing commands retain the inherited image. Missing or stale official inputs never fall back. The new baseline contains lab-only public-key SSH bootstrap configuration, a locked temporary root password and future virtio DHCP configuration; it carries no WAF service. Stock OS boot services did execute during first boot. No product service or PF-policy test is implied.

## Non-X stock patch applicability correction

The first source-bound ordinary run stopped after patch execution because the inherited controller requires 34 installed patch records. It retained 31 install messages and no final admission markers; component execution and later phases were not run. Strict teardown and all source/base/head/worktree gates passed. Preserve this failure rather than relabeling it a successful patch or component run.

OB-03: the pinned 34-archive manifest remains mandatory, including signature verification and every archive digest. Stock `syspatch` skips patches whose target files are absent. The authenticated release's `usr/sbin/syspatch` and the three pinned archives identify exactly `001_xserver`, `020_xserver` and `032_xserver` as the absent-X cohort. All 29 archive members are regular files below `usr/X11R6/` or their exact per-patch signature path. Before rendering, rehash those archives and reject foreign/traversal/link/duplicate/missing-signature targets. Before and after patch execution, require the entire `/usr/X11R6` tree and all three corresponding `/var/syspatch/79-*` paths to be absent, including symlinks. Then require the exact ordered other 31 installed IDs, zero pending applicable patches and an explicit three-inapplicable receipt. This is a separate declared non-X profile; it does not lower the inherited profile's 34-installed requirement or allow arbitrary missing patches. All other admission/budget gates stay fixed.

OB-T05: host controls keep the inherited script byte-identical, require the exact 31/3 cohort and twice-enforced absence checks, preserve full manifest verification, and reject altered archive/target identities. A fresh 900-second snapshot must establish applicability, reboot and all ordinary component gates together. The failed run's snapshot is not reused and its deadline is never extended. Native compilation capacity remains unqualified.

## Final ordinary observation

Signed correction source `ac107360fcd5f7f5352201d2e68909f837bafb4d` / tree `d388d32a800490f3481d0a822cb7c2c69bd1d313` produced fresh run `36dcddc2-468f-4008-92cc-3429d6cd4177`. All 159 host checks pass. All 34 patch archives authenticate; the exact 31 applicable patches install, the three fixed X-only patches meet before/after absence checks, and zero applicable patches remain pending. Reboot/access and the exact 23-parent/31-subtest/54-record ordinary component selection pass. All five journal phases, base/source/head/worktree gates and strict teardown pass. Post-run checks independently find both owned provisioning/component processes and groups absent, zero retained disk handles, separate baseline inode and private modes. The original failed run remains [separate evidence](../../../research/native/official-baseline-native-failure.json); [final receipts](../../../research/native/official-baseline-observations.json) do not reclassify it.
