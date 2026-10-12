# First native engine repeat packet

Status: proposed implementation packet for the next bounded research slice. The user authorized continued research on 2026-10-11 after merging PR #42. This does not accept a runtime connector or any production policy.

## PRD

NATIVE-01: repeat the pinned engine and CRS smoke tests inside an independently owned OpenBSD 7.9 amd64 disposable VM.
NATIVE-02: authenticate exact image/source/test input lineage; preserve all original failures and distinguish host build from guest execution.
NATIVE-03: isolate guest networking and credentials, bound runtime and storage, and prove teardown. No live gateway or application.

No native source-build claim: host Go 1.27.2 cross-compiles the CGO-disabled test binary. Native Go compilation and connector qualification belong to #14/#15. A passing native smoke test cannot close those issues or M1.

## EDD

- Use the [inherited image pin](../../../research/native/image-pin.json), SHA-256 verification before any boot, regular files only, no symlinked assets. The upstream is an anyvm builder, not signed official install media; installed OS/key provenance needs explicit native receipts.
- Make an independent private Aegvium base copy; never mutate a sibling cache/checkpoint. Hash the copied base before and after. Mode 0400 base, 0700 run directories, 0600 private keys. Record source/tree and compiled test SHA-256.
- QEMU TCG, 2 vCPU/2 GiB, one owned overlay, restrict=on user networking, one dynamically reserved loopback-only SSH forward, no bridge/host mount/LAN interface or guest egress. TCG timing is functional evidence only.
- Supervisor owns only its process group. Controller EOF or a 15-minute total deadline initiates TERM, bounded wait, then KILL if needed. Verify group disappearance; retain failed teardown rather than report success.
- The inherited public builder login is bootstrap-only. Generate fresh per-run keys, require public-key-only SSH, disable forwarding, revoke inherited authentication and prove old authentication is rejected while fresh access succeeds. Loopback target is derived from owned QEMU; no arbitrary remote SSH target is accepted.
- Pin a reviewed official syspatch set and key before boot, transfer the local mirror, authenticate native installed key against pinned official public material, verify native signify and patch hashes, apply only to the owned disposable image, reboot and record receipts. Guest egress stays disabled. Do not reuse a sibling's patched active guest. Patch pinning/provisioning is not implemented by this packet.
- Transfer only the hashed test executable and synthetic inputs into an owned guest path. Run with an unprivileged fixture user after setup, execute the engine and CRS smoke cases, capture exit/status/case counts and OS/patch receipts, then reap owned processes and stop the VM. No rc.d service is installed or enabled.

## Test Design

| ID | Observable postconditions |
| --- | --- |
| NATIVE-01 | Every admitted engine/CRS case executes on the guest, matching test input hashes; exit/status and skipped cases recorded |
| NATIVE-02 | Exact source/tree, host Go, binary SHA, image/patch/key receipts and unchanged independent base hash; no native-build claim |
| NATIVE-03 | Negative checks reject symlink/hash/target drift; inherited login fails, fresh login succeeds; loopback/restricted networking verified; timeout and controller EOF kill/reap owned group |

Failure injection must exercise boot/SSH/auth rotation/transfer/test failures and deadline/EOF teardown. Never treat a failed SSH attempt alone as credential revocation. Retain raw private logs locally and sanitize shared receipts. A gate remains failed if cleanup cannot be observed.

[Official OpenBSD release](https://www.openbsd.org/79.html), [errata](https://www.openbsd.org/errata79.html), and [QEMU networking documentation](https://www.qemu.org/docs/master/system/invocation.html) are primary references. Nomvium's independently reviewed harness is a pattern, not an adopted Aegvium harness or evidence of Aegvium execution.

## Implemented preparation

`tools/lab-supervisor.py` adapts the BSD-licensed Nomvium process-group supervisor with a mandatory 1–900 second deadline. Host regression tests exercise controller EOF, deadline expiry, normal child exit and TERM-resistant child escalation. These establish host lifecycle behavior only. Image admission, credential rotation, patch provisioning and the guest controller remain outstanding; no Aegvium VM execution is claimed.

### Independent image admission

`python3 tools/native-image.py SOURCE NAME` streams and checks the pinned decoded qcow2 into a new `.tools/native/NAME` directory. It rejects symlinked source paths, nonregular files, hash mismatches and existing destinations. The base is private/read-only; the receipt explicitly records third-party provenance and no guest execution. This admits decoded image bytes only: compressed archive, bootstrap credentials, patches and guest lifecycle are separate checks before any boot.
