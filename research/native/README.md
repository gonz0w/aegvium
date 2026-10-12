# Bounded native engine repeat

Status: observed research execution, not lab/stack/appliance acceptance. The [receipts](engine-observations.json) preserve exact candidate/tree, runtime input hashes, host Go/QEMU identity, binary/base/patch hashes, nonroot UID, named cases and cleanup. Raw private logs/reports remain in ignored `.tools/native-runs`; their hashes bind the shared observations.

The image pin is inherited from Nomvium’s `tools/openbsd-image.json`; this research uses an independently verified copy, never its active image or process.

| Runtime candidate | Actual observation |
| --- | --- |
| `632620ec23e9a59f8b4539371b338d6d559dd19e` | Boot-stage controlled abort: result failed as intended; group teardown and unchanged base/source verified |
| `632620ec23e9a59f8b4539371b338d6d559dd19e` | First native execution: all 13 admitted cases passed; patches/reboot/nonroot UID and teardown verified |
| `929ac75efaf93dca92ab82d6dd5a784e5c5b9985` | Corrected supervisor: fresh full repeat, all 13 cases passed; patches/reboot/nonroot UID and teardown verified |
| `929ac75efaf93dca92ab82d6dd5a784e5c5b9985` | Auth-stage controlled abort after successful rotation: result failed as intended; group teardown and unchanged base/source verified |

The supervisor correction moves startup-receipt writing and selector registration inside its cleanup boundary; a host regression forces real receipt I/O failure and verifies child reaping. Earlier native observations remain historical rather than being relabeled as tests of this correction. This documentation/evidence commit follows those runtime candidates; it does not represent a new native run. Runtime/build inputs must match the recorded hashes before reusing an observation.

Both full repeats ran the same host Go 1.27.2 CGO-disabled OpenBSD amd64 test binary on OpenBSD 7.9 as UID 32767. Native installed-key/signify checks authenticated the offline 34-patch baseline, and a changed boot time was observed before engine execution. The [official errata](https://www.openbsd.org/errata79.html) and [syspatch manual](https://man.openbsd.org/OpenBSD-7.9/syspatch.8) explain the patch mechanism; the dated pin is not a future latest-patch claim.

Seven engine request cases, four CRS smoke cases, invalid configuration and reader-error characterization passed with synthetic in-memory backend assertions. The reader-error case confirms the upstream implicit-200 behavior with zero backend receipts; an appliance integration still needs explicit error responses and inspection-aware readiness. No application HTTP listener, relayd, TLS, full CRS corpus or performance/stability qualification is claimed. The source-build observation below is separate from these earlier cross-build repeats. The image comes from a third-party builder; installed patch authentication does not prove its complete original build lineage.

## Repeating the fixture

Read the [PRD/EDD/Test Design](../../docs/milestones/M1/NATIVE-ENGINE.md) first. Run `make tools research-tools` and use the decoded image pinned by [image-pin.json](image-pin.json). `python3 tools/native-image.py SOURCE base-7.9-reviewed` creates a new independent read-only base. Do not reuse an active sibling checkpoint.

Prepare a private regular-file copy of the pinned builder bootstrap key at `.tools/native/bootstrap.key` (0600). Prepare the reviewed 36-file patch mirror in `.tools/openbsd-patches` (0700), using verified copies or `python3 tools/openbsd-patches.py fetch`; run its `verify` command. The controller independently verifies these hashes before launch. Public bootstrap material remains outside Git; fresh per-run keys are generated and the bootstrap access is revoked inside each guest.

Commit/sign the clean candidate, run `make verify`, then `make research-native`. QEMU, SSH and the reviewed host toolchain are prerequisites. The controller always rebuilds the test binary, derives its own loopback endpoint, restricts guest egress and enforces a shared 900-second guest budget. It retains failures and requires teardown/source/base receipts. `--inject-failure boot|ssh|auth|transfer|test` exercises controlled stage aborts, not every low-level failure.

Native SSH/transfer/test abort arms and comprehensive low-level failure coverage remain unobserved. Signed official image provenance, native connector builds and actual connector/CRS corpus qualification remain open in #12/#14/#15/#17. Nothing in this receipt closes a phase gate or authorizes service deployment.

## Offline native source build

[Source-build observations](build-observations.json) retain both attempts. Candidate `eb67c2d9aa0a92f82d18919747191728faa6f1a4` exhausted its shared 900-second deadline while compiling; it produced no completed binary or native test pass. Teardown and unchanged source/base passed. This failure remains evidence.

Fresh candidate `b57423a70f45f2256e68a355d6b426ef119313cb` used a separately bounded 1800-second cold-build profile with the same two CPUs, 2 GiB RAM, restricted network and storage limit. It compiled the vendored engine fixture offline on OpenBSD 7.9 amd64 with Go 1.27.2 as UID 32767, then passed all 13 admitted cases using the newly built binary. Its SHA-256 is `2e3ed433dbf6d91150128103068eaa4aad9864db859ae5d19b3a3472281956ae`; the host cross-build control remains separately recorded. Authenticated patches/reboot, bootstrap revocation, unchanged source/base and owned-group teardown passed.

Prepare the pinned SDK using `python3 tools/native-build.py fetch`; commit/sign the clean candidate, run `make verify`, then `make research-native-build`. Only four admitted module source files are vendored; the private archive contains 745 regular files including dependencies and licenses. Shared receipts bind the full private file manifest by a documented hash encoding. No SDK/vendor assets are appliance payloads. Compilation failure cannot fall back to the host binary.

These receipts belong to the exact runtime candidates above. Subsequent evidence/documentation commits do not claim another native run; runtime/build hashes must match before reusing a result. Engine source-build feasibility is observed, while connector builds, signed original image lineage, comprehensive failure coverage and phase gates remain open.
